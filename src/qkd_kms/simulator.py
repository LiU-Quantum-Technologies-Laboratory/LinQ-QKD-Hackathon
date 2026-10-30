#!/usr/bin/env python3
"""QKD KMS simulator with the original demo TCP protocol with an optional web control plane.

The TCP data plane deliberately retains the newline-delimited JSON protocol used
by :mod:`qkd_kms.client`. The optional FastAPI application only controls
the simulated key-generation source and observes its metrics.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import random
import socket
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


DEFAULT_SEED_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
MAX_BUFFER_CAPACITY_BYTES = 100 * 1024 * 1024


class Sha256CtrPrng:
    def __init__(self, seed: bytes):
        self.seed = seed
        self.counter = 0
        self.lock = threading.Lock()

    def read(self, n: int) -> bytes:
        out = bytearray()
        with self.lock:
            while len(out) < n:
                ctr_bytes = self.counter.to_bytes(8, "big", signed=False)
                block = hashlib.sha256(self.seed + ctr_bytes).digest()
                self.counter += 1
                out.extend(block[: n - len(out)])
        return bytes(out)


@dataclass(frozen=True)
class RateModelConfig:
    """Parameters for the simulated QKD key-generation rate.

    Rates are bytes per second. ``variation_percent`` is the standard
    deviation of each newly sampled target, relative to the average.
    ``smoothing`` is the fraction of the previous rate retained at each update.
    """

    average_rate_bytes_per_second: float = 10_000.0
    variation_percent: float = 0.0
    fluctuation_interval_seconds: float = 5.0
    smoothing: float = 0.65
    minimum_rate_bytes_per_second: float = 0.0
    dropout_chance_per_minute: float = 0.0
    dropout_duration_seconds: float = 5.0
    generation_enabled: bool = True

    def validate(self) -> "RateModelConfig":
        if not 0 <= self.average_rate_bytes_per_second <= 1_000_000_000:
            raise ValueError("average rate must be between 0 and 1,000,000,000 B/s")
        if not 0 <= self.variation_percent <= 300:
            raise ValueError("variation percent must be between 0 and 300")
        if not 0.1 <= self.fluctuation_interval_seconds <= 3_600:
            raise ValueError(
                "fluctuation interval must be between 0.1 and 3,600 seconds"
            )
        if not 0 <= self.smoothing <= 0.99:
            raise ValueError("smoothing must be between 0 and 0.99")
        if not 0 <= self.minimum_rate_bytes_per_second <= 1_000_000_000:
            raise ValueError("minimum rate must be between 0 and 1,000,000,000 B/s")
        if self.minimum_rate_bytes_per_second > self.average_rate_bytes_per_second:
            raise ValueError("minimum rate must not exceed the average rate")
        if not 0 <= self.dropout_chance_per_minute <= 1:
            raise ValueError("dropout chance per minute must be between 0 and 1")
        if not 0 <= self.dropout_duration_seconds <= 3_600:
            raise ValueError("dropout duration must be between 0 and 3,600 seconds")
        return self


class TokenBucket:
    """Thread-safe finite key buffer with a configurable generation model."""

    def __init__(
        self,
        rate_bps: float,
        capacity_bytes: int,
        *,
        initial_tokens: int = 0,
        rate_model: Optional[RateModelConfig] = None,
        random_seed: Optional[int] = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not 0 < capacity_bytes <= MAX_BUFFER_CAPACITY_BYTES:
            raise ValueError("buffer capacity must be between 1 byte and 100 MiB")
        self._clock = clock
        self._rng = random.Random(random_seed)
        self._condition = threading.Condition(threading.Lock())
        self.capacity = float(capacity_bytes)
        self.tokens = float(max(0, min(capacity_bytes, initial_tokens)))
        self.config = (
            rate_model or RateModelConfig(average_rate_bytes_per_second=float(rate_bps))
        ).validate()
        self.rate = float(self.config.average_rate_bytes_per_second)
        self._modeled_rate = self.rate
        self._in_dropout = False
        self._dropout_until = 0.0
        self.t_last = self._clock()
        self._next_fluctuation_at = (
            self.t_last + self.config.fluctuation_interval_seconds
        )
        self.total_consumed_bytes = 0
        self.blocked_consumers = 0

    @property
    def lock(self) -> threading.Lock:
        """Compatibility alias for callers that inspected the original lock."""
        return self._condition

    def _sample_rate_locked(self, now: float) -> None:
        cfg = self.config
        if now < self._next_fluctuation_at:
            return

        intervals = max(
            1,
            int((now - self._next_fluctuation_at) / cfg.fluctuation_interval_seconds)
            + 1,
        )
        sigma = cfg.average_rate_bytes_per_second * cfg.variation_percent / 100.0
        target = self._rng.gauss(cfg.average_rate_bytes_per_second, sigma)
        target = max(cfg.minimum_rate_bytes_per_second, target)
        retained = math.pow(cfg.smoothing, intervals)
        self._modeled_rate = max(
            cfg.minimum_rate_bytes_per_second,
            retained * self._modeled_rate + (1 - retained) * target,
        )

        interval_probability = 1 - math.pow(
            1 - cfg.dropout_chance_per_minute,
            cfg.fluctuation_interval_seconds * intervals / 60.0,
        )
        if (
            not self._in_dropout
            and cfg.dropout_duration_seconds > 0
            and self._rng.random() < interval_probability
        ):
            self._in_dropout = True
            self._dropout_until = now + cfg.dropout_duration_seconds

        self._next_fluctuation_at += intervals * cfg.fluctuation_interval_seconds

    def _effective_rate_locked(self, now: float) -> float:
        self._sample_rate_locked(now)
        cfg = self.config
        if self._in_dropout and now >= self._dropout_until:
            self._in_dropout = False
        if not self.config.generation_enabled or self._in_dropout:
            self.rate = 0.0
        else:
            self.rate = max(cfg.minimum_rate_bytes_per_second, self._modeled_rate)
        return self.rate

    def _refill_locked(self, now: float) -> None:
        dt = now - self.t_last
        if dt > 0:
            # The monitor normally samples this once per second.
            rate = self._effective_rate_locked(now)
            self.tokens = min(self.capacity, self.tokens + dt * rate)
            self.t_last = now

    def _refill(self, now: float) -> None:
        """Compatibility helper. The caller must hold ``lock``."""
        self._refill_locked(now)

    def consume_blocking(self, amount: int) -> None:
        """Block until ``amount`` bytes are available, then consume them."""
        if amount <= 0:
            return
        is_counted_as_blocked = False
        with self._condition:
            try:
                while True:
                    now = self._clock()
                    self._refill_locked(now)
                    if amount > self.capacity:
                        raise ValueError(
                            f"requested key ({amount} B) exceeds buffer capacity ({int(self.capacity)} B)"
                        )
                    if self.tokens >= amount:
                        self.tokens -= amount
                        self.total_consumed_bytes += amount
                        return
                    if not is_counted_as_blocked:
                        self.blocked_consumers += 1
                        is_counted_as_blocked = True
                    deficit = amount - self.tokens
                    wait_s = deficit / self.rate if self.rate > 0 else 0.5
                    # Wake regularly so live configuration changes affect
                    # already-waiting clients promptly.
                    self._condition.wait(timeout=max(0.02, min(wait_s, 0.5)))
            finally:
                if is_counted_as_blocked:
                    self.blocked_consumers -= 1

    def configure(
        self, config: RateModelConfig, *, capacity_bytes: Optional[int] = None
    ) -> None:
        config.validate()
        if (
            capacity_bytes is not None
            and not 0 < capacity_bytes <= MAX_BUFFER_CAPACITY_BYTES
        ):
            raise ValueError("buffer capacity must be between 1 byte and 100 MiB")
        with self._condition:
            now = self._clock()
            self._refill_locked(now)
            previous_average = self.config.average_rate_bytes_per_second
            self.config = config
            if capacity_bytes is not None:
                self.capacity = float(capacity_bytes)
                self.tokens = min(self.tokens, self.capacity)
            if previous_average != config.average_rate_bytes_per_second:
                self._modeled_rate = config.average_rate_bytes_per_second
            self._modeled_rate = max(
                config.minimum_rate_bytes_per_second, self._modeled_rate
            )
            self._next_fluctuation_at = now + config.fluctuation_interval_seconds
            if not config.generation_enabled:
                self.rate = 0.0
            self._condition.notify_all()

    def set_available_bytes(self, available_bytes: int) -> None:
        with self._condition:
            if not 0 <= available_bytes <= self.capacity:
                raise ValueError(
                    f"available bytes must be between 0 and {int(self.capacity)}"
                )
            self.tokens = float(available_bytes)
            self.t_last = self._clock()
            self._condition.notify_all()

    def snapshot(self) -> dict:
        with self._condition:
            now = self._clock()
            self._refill_locked(now)
            capacity = int(self.capacity)
            available = int(self.tokens)
            return {
                # Legacy fields used by the socket status response.
                "rate_bps": self.rate,
                "buffer_max_bytes": capacity,
                "buffer_available_bytes": available,
                # Richer fields used by the web dashboard.
                "current_rate_bytes_per_second": self.rate,
                "buffer_capacity_bytes": capacity,
                "buffer_fill_percent": 100.0 * available / capacity,
                "total_consumed_bytes": self.total_consumed_bytes,
                "blocked_consumers": self.blocked_consumers,
                "in_dropout": self._in_dropout,
                "configuration": asdict(self.config),
            }


def _fmt_buffer_state(buf: TokenBucket) -> str:
    snap = buf.snapshot()
    used = snap["buffer_available_bytes"]
    cap = snap["buffer_max_bytes"]
    return f"{used}/{cap} B ({100.0 * used / cap:5.1f}%)"


@dataclass
class KeyRecord:
    key_id: int
    key_bytes: bytes
    length: int
    issued_at: float = field(default_factory=time.time)
    delivered_to: Dict[str, bool] = field(default_factory=dict)


class LinkState:
    def __init__(self, prng: Sha256CtrPrng, sae_a: str, sae_b: str):
        self.prng = prng
        self.sae_a = sae_a
        self.sae_b = sae_b
        self.next_key_id = 1
        self.pending: Dict[int, KeyRecord] = {}
        self.total_keys_issued = 0
        self.total_key_bytes_issued = 0
        self.lock = threading.Lock()

    def _validate_sae(self, sae_id: str) -> None:
        if sae_id not in (self.sae_a, self.sae_b):
            raise ValueError(
                f"unknown SAE '{sae_id}' (expected '{self.sae_a}' or '{self.sae_b}')"
            )

    def try_get_pending_for_sae(self, sae_id: str, length: int) -> Optional[KeyRecord]:
        self._validate_sae(sae_id)
        with self.lock:
            for rec in sorted(self.pending.values(), key=lambda item: item.key_id):
                if rec.length == length and not rec.delivered_to.get(sae_id, False):
                    return rec
        return None

    def mark_delivered(self, sae_id: str, rec: KeyRecord) -> None:
        self._validate_sae(sae_id)
        peer = self.sae_b if sae_id == self.sae_a else self.sae_a
        with self.lock:
            stored = self.pending.get(rec.key_id)
            if stored is None:
                raise KeyError(f"unknown key_id={rec.key_id}")
            if stored.delivered_to.get(sae_id, False):
                raise ValueError(f"key_id={rec.key_id} already delivered to {sae_id}")
            stored.delivered_to[sae_id] = True
            if stored.delivered_to.get(peer, False):
                self.pending.pop(stored.key_id, None)

    def create_new(self, creator_sae: str, length: int) -> KeyRecord:
        self._validate_sae(creator_sae)
        peer = self.sae_b if creator_sae == self.sae_a else self.sae_a
        with self.lock:
            kid = self.next_key_id
            self.next_key_id += 1
            rec = KeyRecord(key_id=kid, key_bytes=self.prng.read(length), length=length)
            rec.delivered_to[creator_sae] = True
            rec.delivered_to.setdefault(peer, False)
            self.pending[kid] = rec
            self.total_keys_issued += 1
            self.total_key_bytes_issued += length
            return rec

    def fetch_by_id(self, sae_id: str, key_id: int, length: int) -> KeyRecord:
        self._validate_sae(sae_id)
        peer = self.sae_b if sae_id == self.sae_a else self.sae_a
        with self.lock:
            rec = self.pending.get(key_id)
            if rec is None:
                raise KeyError(f"unknown key_id={key_id}")
            if rec.delivered_to.get(sae_id, False):
                return rec  # Keep idempotent behavior expected by the demo apps.
            if rec.length != length:
                raise ValueError(
                    f"length mismatch for key_id={key_id}: expected {rec.length} got {length}"
                )
            rec.delivered_to[sae_id] = True
            if rec.delivered_to.get(peer, False):
                self.pending.pop(key_id, None)
            return rec

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "sae_a": self.sae_a,
                "sae_b": self.sae_b,
                "total_keys_issued": self.total_keys_issued,
                "total_key_bytes_issued": self.total_key_bytes_issued,
                "pending_keys": len(self.pending),
            }


def send_json_line(conn: socket.socket, obj: dict) -> None:
    conn.sendall((json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8"))


def recv_json_line(conn: socket.socket, max_bytes: int = 1_000_000) -> dict:
    buf = bytearray()
    while True:
        chunk = conn.recv(1)
        if not chunk:
            raise ConnectionError("client disconnected")
        if chunk == b"\n":
            break
        buf += chunk
        if len(buf) > max_bytes:
            raise ValueError("line too long")
    return json.loads(buf.decode("utf-8"))


def _encode_key_record(rec: KeyRecord) -> dict:
    return {
        "key_id": str(rec.key_id),
        "key_b64": base64.b64encode(rec.key_bytes).decode("ascii"),
        "length_bytes": rec.length,
        "issued_at": rec.issued_at,
    }


def handle_client(
    conn: socket.socket,
    addr: Tuple[str, int],
    link: LinkState | "MockKmsService",
    buffer: Optional[TokenBucket] = None,
) -> None:
    del addr
    try:
        msg = recv_json_line(conn)
        if msg.get("type") != "hello" or "sae_id" not in msg:
            send_json_line(
                conn, {"type": "error", "error": "expected hello with sae_id"}
            )
            return

        session_id = str(msg.get("session_id", "standalone"))
        if isinstance(link, MockKmsService):
            try:
                context = link.get_context(session_id)
            except ValueError as exc:
                send_json_line(conn, {"type": "error", "error": str(exc)})
                return
            active_link = context.link
            active_buffer = context.buffer
        else:
            active_link = link
            if buffer is None:
                raise RuntimeError("a token buffer is required with a LinkState")
            active_buffer = buffer

        sae_id = str(msg["sae_id"])
        try:
            active_link._validate_sae(sae_id)
        except Exception as exc:
            send_json_line(conn, {"type": "error", "error": str(exc)})
            return

        hello_ack = {
            "type": "hello_ack",
            "server": "mock-qkd-kms",
            "sae_id": sae_id,
        }
        if "session_id" in msg:
            hello_ack["session_id"] = session_id
        send_json_line(conn, hello_ack)

        while True:
            req = recv_json_line(conn)
            request_type = req.get("type")
            if request_type == "ping":
                send_json_line(conn, {"type": "pong", "t": time.time()})
                continue

            if request_type == "get_status":
                try:
                    backend_status = active_buffer.snapshot()
                except Exception as exc:
                    send_json_line(conn, {"type": "error", "error": str(exc)})
                    continue
                send_json_line(conn, {"type": "status", **backend_status})
                continue

            if request_type == "get_key":
                length = int(req.get("length_bytes", 0))
                if length <= 0 or length > 1_000_000:
                    send_json_line(
                        conn, {"type": "error", "error": "invalid length_bytes"}
                    )
                    continue
                try:
                    active_buffer.consume_blocking(length)
                    rec = active_link.create_new(sae_id, length)
                    encoded = [_encode_key_record(rec)]
                except Exception as exc:
                    send_json_line(conn, {"type": "error", "error": str(exc)})
                    continue
                send_json_line(conn, {"type": "keys", "keys": encoded})
                continue

            if request_type == "get_key_with_key_IDs":
                length = int(req.get("length_bytes", 0))
                if length <= 0 or length > 1_000_000:
                    send_json_line(
                        conn, {"type": "error", "error": "invalid length_bytes"}
                    )
                    continue
                key_ids = req.get("key_ids")
                if not isinstance(key_ids, list) or not key_ids:
                    send_json_line(
                        conn,
                        {"type": "error", "error": "key_ids must be a non-empty list"},
                    )
                    continue
                encoded_records: List[dict] = []
                for key_id_text in key_ids:
                    try:
                        key_id = int(str(key_id_text))
                        rec = active_link.fetch_by_id(
                            sae_id, key_id=key_id, length=length
                        )
                        encoded_records.append(_encode_key_record(rec))
                    except Exception as exc:
                        send_json_line(conn, {"type": "error", "error": str(exc)})
                        encoded_records = []
                        break
                if encoded_records:
                    send_json_line(conn, {"type": "keys", "keys": encoded_records})
                continue

            if request_type == "bye":
                send_json_line(conn, {"type": "bye_ack"})
                return

            send_json_line(
                conn,
                {"type": "error", "error": f"unknown request type={request_type}"},
            )
    except (ConnectionError, OSError, ValueError, json.JSONDecodeError):
        return
    finally:
        try:
            conn.close()
        except OSError:
            pass


class KmsSessionState:
    """Independent key link, buffer configuration, and telemetry for one table."""

    def __init__(
        self,
        *,
        session_id: str,
        seed: bytes,
        rate_bps: float,
        buffer_bytes: int,
        initial_bytes: int,
        sae_a: str,
        sae_b: str,
        rate_model: Optional[RateModelConfig],
        history_points: int,
    ) -> None:
        self.session_id = session_id
        self.started_at = time.time()
        self.link = LinkState(Sha256CtrPrng(seed), sae_a, sae_b)
        simulation_seed = int.from_bytes(
            hashlib.sha256(seed + b"rate-model").digest()[:8]
        )
        self.buffer = TokenBucket(
            rate_bps,
            buffer_bytes,
            initial_tokens=initial_bytes,
            rate_model=rate_model,
            random_seed=simulation_seed,
        )
        self._history = deque(maxlen=history_points)
        self._history_lock = threading.Lock()
        self._last_sample_time = time.time()
        self._last_consumed_bytes = 0

    def record_sample(self) -> dict:
        with self._history_lock:
            now = time.time()
            buffer_snapshot = self.buffer.snapshot()
            elapsed = max(0.001, now - self._last_sample_time)
            consumed = buffer_snapshot["total_consumed_bytes"]
            sample = {
                "timestamp": now,
                "current_rate_bytes_per_second": buffer_snapshot[
                    "current_rate_bytes_per_second"
                ],
                "buffer_available_bytes": buffer_snapshot["buffer_available_bytes"],
                "buffer_fill_percent": buffer_snapshot["buffer_fill_percent"],
                "consumption_rate_bytes_per_second": max(
                    0.0, (consumed - self._last_consumed_bytes) / elapsed
                ),
            }
            self._last_sample_time = now
            self._last_consumed_bytes = consumed
            self._history.append(sample)
        return sample

    def status(self, *, include_history: bool = True) -> dict:
        result = {
            **self.buffer.snapshot(),
            **self.link.snapshot(),
            "session_id": self.session_id,
            "uptime_seconds": max(0.0, time.time() - self.started_at),
        }
        if include_history:
            with self._history_lock:
                result["history"] = list(self._history)
        return result

    def clear_history(self) -> dict:
        with self._history_lock:
            now = time.time()
            snapshot = self.buffer.snapshot()
            self._history.clear()
            self._last_sample_time = now
            self._last_consumed_bytes = snapshot["total_consumed_bytes"]
            self._history.append(
                {
                    "timestamp": now,
                    "current_rate_bytes_per_second": snapshot[
                        "current_rate_bytes_per_second"
                    ],
                    "buffer_available_bytes": snapshot["buffer_available_bytes"],
                    "buffer_fill_percent": snapshot["buffer_fill_percent"],
                    "consumption_rate_bytes_per_second": 0.0,
                }
            )
        return self.status()

    def apply_configuration(
        self, config: RateModelConfig, *, capacity_bytes: Optional[int] = None
    ) -> dict:
        self.buffer.configure(config, capacity_bytes=capacity_bytes)
        self.record_sample()
        return self.status()


class MockKmsService:
    """Owns the TCP listener, simulation state, and metric history."""

    def __init__(
        self,
        host: str,
        port: int,
        seed_hex: str,
        rate_bps: float,
        buffer_bytes: int,
        initial_bytes: int,
        sae_a: str,
        sae_b: str,
        *,
        rate_model: Optional[RateModelConfig] = None,
        history_points: int = 900,
    ) -> None:
        try:
            seed = bytes.fromhex(seed_hex)
        except ValueError as exc:
            raise ValueError("seed must contain hexadecimal characters") from exc
        if not seed:
            raise ValueError("seed must not be empty")
        if not 0 <= initial_bytes <= buffer_bytes:
            raise ValueError(
                "initial bytes must be between zero and the buffer capacity"
            )
        if sae_a == sae_b:
            raise ValueError("SAE A and SAE B must be different")

        self.host = host
        self.port = port
        self.seed_hex = seed_hex
        self.started_at = time.time()
        self._seed = seed
        self._rate_bps = rate_bps
        self._buffer_bytes = buffer_bytes
        self._initial_bytes = initial_bytes
        self._sae_a = sae_a
        self._sae_b = sae_b
        self._rate_model = rate_model
        self._history_points = history_points
        self._contexts_lock = threading.Lock()
        self._contexts: Dict[str, KmsSessionState] = {}
        self.get_context("standalone")
        self._listener: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._server_thread: Optional[threading.Thread] = None
        self._monitor_thread: Optional[threading.Thread] = None

    def get_context(self, session_id: str = "standalone") -> KmsSessionState:
        session_id = session_id.strip() or "standalone"
        if len(session_id) > 128 or not all(
            character.isalnum() or character in "-_" for character in session_id
        ):
            raise ValueError("invalid KMS session id")
        with self._contexts_lock:
            existing = self._contexts.get(session_id)
            if existing is not None:
                return existing
            seed = (
                self._seed
                if session_id == "standalone"
                else hashlib.sha256(
                    self._seed + b"\x00linqkd-session\x00" + session_id.encode("utf-8")
                ).digest()
            )
            context = KmsSessionState(
                session_id=session_id,
                seed=seed,
                rate_bps=self._rate_bps,
                buffer_bytes=self._buffer_bytes,
                initial_bytes=self._initial_bytes,
                sae_a=self._sae_a,
                sae_b=self._sae_b,
                rate_model=self._rate_model,
                history_points=self._history_points,
            )
            self._contexts[session_id] = context
            return context

    @property
    def link(self) -> LinkState:
        return self.get_context().link

    @property
    def buffer(self) -> TokenBucket:
        return self.get_context().buffer

    @property
    def socket_address(self) -> Tuple[str, int]:
        if self._listener is None:
            return self.host, self.port
        bound_host, bound_port = self._listener.getsockname()[:2]
        return str(bound_host), int(bound_port)

    def _bind(self) -> None:
        if self._listener is not None:
            return
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, self.port))
        listener.listen(32)
        listener.settimeout(0.5)
        self._listener = listener

    def start(self) -> None:
        self._bind()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="mock-kms-metrics",
            daemon=True,
        )
        self._server_thread = threading.Thread(
            target=self._accept_loop,
            name="mock-kms-tcp",
            daemon=True,
        )
        self._monitor_thread.start()
        self._server_thread.start()
        self._print_startup()

    def serve_forever(self) -> None:
        self._bind()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="mock-kms-metrics",
            daemon=True,
        )
        self._monitor_thread.start()
        self._print_startup()
        self._accept_loop()

    def _print_startup(self) -> None:
        bound_host, bound_port = self.socket_address
        snap = self.buffer.snapshot()
        print(f"[mock-kms] TCP data plane listening on {bound_host}:{bound_port}")
        print(f"[mock-kms] SAE A={self.link.sae_a}  SAE B={self.link.sae_b}")
        print(
            "[mock-kms] "
            f"average rate={snap['configuration']['average_rate_bytes_per_second']:.1f} B/s  "
            f"buffer={snap['buffer_capacity_bytes']} B  "
            f"available={snap['buffer_available_bytes']} B"
        )

    def _accept_loop(self) -> None:
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                raise
            threading.Thread(
                target=handle_client,
                args=(conn, addr, self),
                daemon=True,
            ).start()

    def _monitor_loop(self) -> None:
        while not self._stop.is_set():
            with self._contexts_lock:
                contexts = list(self._contexts.values())
            for context in contexts:
                context.record_sample()
            self._stop.wait(1.0)

    def record_sample(self, session_id: str = "standalone") -> dict:
        return self.get_context(session_id).record_sample()

    def status(
        self, session_id: str = "standalone", *, include_history: bool = True
    ) -> dict:
        context = self.get_context(session_id)
        result = {
            **context.status(include_history=include_history),
            "socket_host": self.socket_address[0],
            "socket_port": self.socket_address[1],
        }
        return result

    def clear_history(self, session_id: str = "standalone") -> dict:
        """Discard recorded telemetry and establish a fresh zero-consumption baseline."""
        self.get_context(session_id).clear_history()
        return self.status(session_id)

    def apply_configuration(
        self,
        config: RateModelConfig,
        *,
        capacity_bytes: Optional[int] = None,
        session_id: str = "standalone",
    ) -> dict:
        self.get_context(session_id).apply_configuration(
            config, capacity_bytes=capacity_bytes
        )
        return self.status(session_id)

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        with self._contexts_lock:
            contexts = list(self._contexts.values())
        for context in contexts:
            with context.buffer._condition:
                context.buffer._condition.notify_all()
        current = threading.current_thread()
        for thread in (self._server_thread, self._monitor_thread):
            if thread is not None and thread is not current:
                thread.join(timeout=2.0)


def serve(
    host: str,
    port: int,
    seed_hex: str,
    rate_bps: float,
    buffer_bytes: int,
    initial_bytes: int,
    sae_a: str,
    sae_b: str,
    *,
    rate_model: Optional[RateModelConfig] = None,
) -> None:
    """Legacy blocking entry point retained for existing launch scripts."""
    service = MockKmsService(
        host,
        port,
        seed_hex,
        rate_bps,
        buffer_bytes,
        initial_bytes,
        sae_a,
        sae_b,
        rate_model=rate_model,
    )
    try:
        service.serve_forever()
    finally:
        service.stop()


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the QKD KMS simulator.")
    parser.add_argument("--host", default="127.0.0.1", help="TCP KMS bind address")
    parser.add_argument("--port", type=int, default=9000, help="TCP KMS port")
    parser.add_argument(
        "--seed-hex",
        default=None,
        help="optional deterministic seed for reproducible tests; random by default",
    )
    parser.add_argument(
        "--rate-bps",
        type=float,
        default=10_000.0,
        help="initial average key generation rate in bytes/second",
    )
    parser.add_argument(
        "--buffer-bytes",
        type=int,
        default=MAX_BUFFER_CAPACITY_BYTES,
        help="KMS key buffer capacity (maximum 100 MiB)",
    )
    parser.add_argument(
        "--initial-bytes",
        type=int,
        default=0,
        help="key bytes initially available in the buffer",
    )
    parser.add_argument("--sae-a", default="SAE_002")
    parser.add_argument("--sae-b", default="SAE_001")

    parser.add_argument("--variation-percent", type=float, default=0.0)
    parser.add_argument("--fluctuation-interval", type=float, default=5.0)
    parser.add_argument("--smoothing", type=float, default=0.65)
    parser.add_argument("--minimum-rate-bps", type=float, default=0.0)
    parser.add_argument("--dropout-chance", type=float, default=0.0)
    parser.add_argument("--dropout-duration", type=float, default=5.0)

    parser.add_argument(
        "--headless",
        action="store_true",
        help="run only the socket KMS, configured entirely from the command line",
    )
    parser.add_argument("--web-host", default="127.0.0.1", help="web UI bind address")
    parser.add_argument("--web-port", type=int, default=8080, help="web UI port")
    parser.add_argument(
        "--admin-password",
        default=os.environ.get("LINQKD_ADMIN_PASSWORD"),
        help="web UI password (or set LINQKD_ADMIN_PASSWORD)",
    )
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="disable web login; intended only for trusted local networks",
    )
    parser.add_argument(
        "--secure-cookies",
        action="store_true",
        default=os.environ.get("LINQKD_KMS_SECURE_COOKIES", "").lower()
        in {"1", "true", "yes"},
        help="mark the session cookie Secure when the UI is served behind HTTPS",
    )
    parser.add_argument(
        "--presets-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "presets",
        help="directory containing JSON simulation presets",
    )
    return parser


def main() -> None:
    args = build_argument_parser().parse_args()
    if not 0 < args.buffer_bytes <= MAX_BUFFER_CAPACITY_BYTES:
        raise SystemExit("--buffer-bytes must be between 1 byte and 100 MiB")
    if not 0 <= args.initial_bytes <= args.buffer_bytes:
        raise SystemExit("--initial-bytes must satisfy 0 <= initial <= buffer")
    if not args.headless and not args.no_auth and not args.admin_password:
        raise SystemExit(
            "web mode requires --admin-password or --no-auth for local use"
        )

    try:
        rate_model = RateModelConfig(
            average_rate_bytes_per_second=args.rate_bps,
            variation_percent=args.variation_percent,
            fluctuation_interval_seconds=args.fluctuation_interval,
            smoothing=args.smoothing,
            minimum_rate_bytes_per_second=args.minimum_rate_bps,
            dropout_chance_per_minute=args.dropout_chance,
            dropout_duration_seconds=args.dropout_duration,
        ).validate()
        service = MockKmsService(
            args.host,
            args.port,
            args.seed_hex or os.urandom(32).hex(),
            args.rate_bps,
            args.buffer_bytes,
            args.initial_bytes,
            args.sae_a,
            args.sae_b,
            rate_model=rate_model,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    if args.headless:
        try:
            service.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            service.stop()
        return

    try:
        import uvicorn

        if __package__:
            from .web import create_app
        else:
            from qkd_kms.web import create_app
    except ImportError as exc:
        raise SystemExit(
            "web mode needs FastAPI and Uvicorn; install them with "
            "`python -m pip install -e '.[web]'`"
        ) from exc

    service.start()
    try:
        app = create_app(
            service,
            password=None if args.no_auth else args.admin_password,
            presets_dir=args.presets_dir,
            secure_cookies=args.secure_cookies,
        )
        print(
            f"[mock-kms] web control plane listening on "
            f"http://{args.web_host}:{args.web_port}"
        )
        uvicorn.run(app, host=args.web_host, port=args.web_port, log_level="info")
    finally:
        service.stop()


if __name__ == "__main__":
    main()
