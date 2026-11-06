"""Small, interchangeable clients: simulator TCP and ETSI GS QKD 014 HTTPS."""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
import json
import socket
import ssl
from typing import Any, Protocol
from urllib.parse import quote, urlsplit


# One flat configuration describes one application's KMS connection.
DEFAULT_CONFIG_JSON = """
{
  "backend": "simulator",
  "host": "127.0.0.1",
  "port": 9000,
  "local_sae_id": "SAE_002",
  "session_id": "standalone",
  "timeout": 30
}
"""

# Unused example. Set the KMS URL and SAE IDs before selecting it.
# Certificate paths are relative to the repository root.
# peer_sae_id is required only for backend="etsi014": it identifies the OTHER
# application that will share the keys, for both allocation and key-ID retrieval.
# Here the sender is SAE_002 and its peer is SAE_001. The receiver uses the
# reverse: local_sae_id=SAE_001, peer_sae_id=SAE_002, and its own KMS/certificates.
# The simulator already has a fixed pair of SAE IDs, so peer_sae_id is not used.
# For ETSI, the client certificate establishes your local identity; local_sae_id
# is kept here so force_simulator=True can select the matching simulator identity.
NETWORK_KMS_CONFIG_JSON = """
{
  "backend": "etsi014",
  "base_url": "https://kms.example:443",
  "local_sae_id": "SAE_002",
  "peer_sae_id": "SAE_001",
  "client_cert": "certs_out/qkd_client.cert",
  "client_key": "certs_out/qkd_client.key",
  "ca_cert": "certs_out/root_ca.cert",
  "ignore_cert": false
}
"""


class KmsError(RuntimeError):
    """A KMS transport, protocol, or key-delivery error."""


@dataclass(frozen=True)
class KeyHandle:
    key_id: str
    key: bytes = field(repr=False)


class KmsClient(Protocol):
    """Application-facing contract. All key sizes are in bytes."""

    def allocate_key(self, length_bytes: int = 32) -> KeyHandle: ...
    def fetch_key(self, key_id: str, length_bytes: int = 32) -> KeyHandle: ...


def _length(length_bytes: int) -> None:
    if (
        isinstance(length_bytes, bool)
        or not isinstance(length_bytes, int)
        or not 1 <= length_bytes <= 1_000_000
    ):
        raise ValueError("length_bytes must be an integer between 1 and 1,000,000")


def _extract(
    data: dict, field_name: str, length_bytes: int, expected_id: str | None = None
) -> KeyHandle:
    try:
        keys = data["keys"]
        if len(keys) != 1:
            raise ValueError("expected exactly one key")
        record = keys[0]
        key_id = record["key_id"]
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("missing key ID")
        material = base64.b64decode(record[field_name], validate=True)
        if len(material) != length_bytes:
            raise ValueError("unexpected key length")
        if expected_id is not None and key_id != expected_id:
            raise ValueError("returned key ID differs from requested ID")
        return KeyHandle(key_id, material)
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise KmsError("KMS returned malformed key data") from exc


class SimulatorClient:
    """Connect to the extracted simulator. Session IDs isolate team key pools.

    This development TCP transport has no authentication or TLS. A session ID
    is a namespace, not an access credential. Requests have a bounded timeout.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9000,
        *,
        local_sae_id: str,
        session_id: str = "standalone",
        timeout: float = 30,
    ):
        self.host, self.port = host, port
        self.local_sae_id, self.session_id = local_sae_id, session_id
        self.timeout = timeout

    def _rpc(self, request: dict) -> dict:
        try:
            with socket.create_connection(
                (self.host, self.port), timeout=self.timeout
            ) as conn:
                with conn.makefile("rwb") as stream:

                    def exchange(payload: dict) -> dict:
                        stream.write(json.dumps(payload).encode() + b"\n")
                        stream.flush()
                        line = stream.readline(1_000_001)
                        if not line.endswith(b"\n") or len(line) > 1_000_000:
                            raise KmsError("Invalid or oversized simulator response")
                        result = json.loads(line)
                        if not isinstance(result, dict):
                            raise KmsError("Invalid simulator response")
                        if result.get("type") == "error":
                            raise KmsError(
                                str(result.get("error", "Simulator request failed"))
                            )
                        return result

                    hello = exchange(
                        {
                            "type": "hello",
                            "sae_id": self.local_sae_id,
                            "session_id": self.session_id,
                        }
                    )
                    if hello.get("type") != "hello_ack":
                        raise KmsError("Unexpected simulator handshake")
                    result = exchange(request)
                    if result.get("type") != "keys":
                        raise KmsError("Unexpected simulator key response")
                    return result
        except (OSError, ValueError) as exc:
            raise KmsError(
                "Simulator request failed; check the server and timeout"
            ) from exc

    def allocate_key(self, length_bytes: int = 32) -> KeyHandle:
        _length(length_bytes)
        return _extract(
            self._rpc({"type": "get_key", "length_bytes": length_bytes}),
            "key_b64",
            length_bytes,
        )

    def fetch_key(self, key_id: str, length_bytes: int = 32) -> KeyHandle:
        _length(length_bytes)
        return _extract(
            self._rpc(
                {
                    "type": "get_key_with_key_IDs",
                    "key_ids": [key_id],
                    "length_bytes": length_bytes,
                }
            ),
            "key_b64",
            length_bytes,
            key_id,
        )


class Etsi014Client:
    """ETSI GS QKD 014 v1 HTTPS adapter with configurable TLS certificates.

    Each side connects to its local KMS and addresses its peer SAE in the URL.
    client_cert/client_key identify this application when the KMS requires mTLS.
    ca_cert verifies the server; omitting it uses the library's default trust store.
    ignore_cert=True skips server certificate and hostname verification for lab
    testing. It does not bypass a KMS requirement for a valid client certificate.
    """

    def __init__(
        self,
        base_url: str,
        *,
        peer_sae_id: str,
        client_cert: str | None = None,
        client_key: str | None = None,
        ca_cert: str | None = None,
        ignore_cert: bool = False,
    ):
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise ValueError(
                "base_url must be an HTTPS origin, e.g. https://kms.example:443"
            )
        if not peer_sae_id:
            raise ValueError("peer_sae_id must not be empty")
        if not isinstance(ignore_cert, bool):
            raise ValueError("ignore_cert must be a boolean (true or false in JSON)")
        if bool(client_cert) != bool(client_key):
            raise ValueError("client_cert and client_key must be supplied together")
        try:
            from etsi_qkd_014_client import QKD014Client
        except ModuleNotFoundError as exc:
            if exc.name != "etsi_qkd_014_client":
                raise
            raise KmsError("Install qkd-kms-starter[etsi] to use the ETSI client") from exc

        # Validate configured files before the first request. The library loads
        # them for HTTPS and handles server verification on each connection.
        if ca_cert and not ignore_cert:
            ssl.create_default_context(cafile=ca_cert)
        if client_cert:
            ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_cert_chain(client_cert, client_key)
        self.base_url = base_url.rstrip("/")
        self.peer_sae_id = peer_sae_id
        self._client = QKD014Client(
            kme_hostname=parsed.netloc,
            cert_path=client_cert or None,
            key_path=client_key or None,
            ca_path=ca_cert or True,
            force_insecure=ignore_cert,
        )

    def _request_key(
        self,
        request: Callable[[], tuple[int, Any]],
        length_bytes: int,
        expected_id: str | None = None,
    ) -> KeyHandle:
        try:
            status, data = request()
        except Exception as exc:
            # The upstream client also raises plain Exception for malformed replies.
            raise KmsError("KMS HTTPS request failed") from exc
        if status != 200:
            raise KmsError(f"KMS returned HTTP {status}")
        keys = [{"key_id": key.key_id, "key": key.key} for key in data.keys]
        return _extract({"keys": keys}, "key", length_bytes, expected_id)

    def allocate_key(self, length_bytes: int = 32) -> KeyHandle:
        _length(length_bytes)
        peer = quote(self.peer_sae_id, safe="")
        return self._request_key(
            lambda: self._client.get_key(peer, number=1, size=length_bytes * 8),
            length_bytes,
        )

    def fetch_key(self, key_id: str, length_bytes: int = 32) -> KeyHandle:
        _length(length_bytes)
        peer = quote(self.peer_sae_id, safe="")
        return self._request_key(
            lambda: self._client.get_key_with_key_IDs(peer, [key_id]),
            length_bytes,
            key_id,
        )


def create_client(
    config: str | Mapping[str, Any] = DEFAULT_CONFIG_JSON,
    *,
    force_simulator: bool = False,
) -> KmsClient:
    """Create one client from flat JSON or a dictionary; no role names needed.

    Omitting config uses the local simulator example above. No environment
    variables are read. force_simulator=True overrides backend selection without
    loading certificates. Simulator host/port default to localhost:9000, including
    when overriding a real-KMS configuration. This connects to an existing server;
    it does not start one. Connection failures never trigger automatic fallback.
    """
    settings = json.loads(config) if isinstance(config, str) else config
    if not isinstance(settings, Mapping):
        raise ValueError("KMS configuration must be a JSON object or mapping")
    backend = "simulator" if force_simulator else settings.get("backend")
    try:
        if backend == "simulator":
            return SimulatorClient(
                host=settings.get("host", "127.0.0.1"),
                port=settings.get("port", 9000),
                local_sae_id=settings["local_sae_id"],
                session_id=settings.get("session_id", "standalone"),
                timeout=settings.get("timeout", 30),
            )
        if backend == "etsi014":
            return Etsi014Client(
                base_url=settings["base_url"],
                peer_sae_id=settings["peer_sae_id"],
                client_cert=settings.get("client_cert"),
                client_key=settings.get("client_key"),
                ca_cert=settings.get("ca_cert"),
                ignore_cert=settings.get("ignore_cert", False),
            )
    except KeyError as exc:
        raise ValueError(f"Missing KMS configuration field: {exc.args[0]}") from exc
    except (TypeError, AttributeError) as exc:
        raise ValueError("Invalid KMS configuration structure or field types") from exc
    raise ValueError("KMS backend must be 'simulator' or 'etsi014'")
