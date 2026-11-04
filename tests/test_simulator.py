from pathlib import Path
import pytest
from qkd_kms.simulator import (
    TokenBucket,
    RateModelConfig,
    MAX_BUFFER_CAPACITY_BYTES,
    MockKmsService,
    DEFAULT_SEED_HEX,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_constant_rate_refills_finite_buffer() -> None:
    clock = FakeClock()
    bucket = TokenBucket(100, 250, initial_tokens=0, clock=clock)

    clock.advance(2)
    assert bucket.snapshot()["buffer_available_bytes"] == 200

    clock.advance(2)
    snapshot = bucket.snapshot()
    assert snapshot["buffer_available_bytes"] == 250
    assert snapshot["buffer_fill_percent"] == 100


def test_live_configuration_resizes_and_pauses_buffer() -> None:
    clock = FakeClock()
    bucket = TokenBucket(100, 1_000, initial_tokens=600, clock=clock)
    paused = RateModelConfig(
        average_rate_bytes_per_second=200,
        generation_enabled=False,
    )

    bucket.configure(paused, capacity_bytes=500)
    assert bucket.snapshot()["buffer_available_bytes"] == 500
    clock.advance(5)
    assert bucket.snapshot()["buffer_available_bytes"] == 500
    assert bucket.snapshot()["current_rate_bytes_per_second"] == 0


def test_rate_floor_cannot_exceed_average() -> None:
    with pytest.raises(ValueError, match="minimum rate"):
        RateModelConfig(
            average_rate_bytes_per_second=100,
            minimum_rate_bytes_per_second=101,
        ).validate()


def test_key_larger_than_buffer_is_rejected_instead_of_waiting_forever() -> None:
    bucket = TokenBucket(100, 32, initial_tokens=32)
    with pytest.raises(ValueError, match="exceeds buffer capacity"):
        bucket.consume_blocking(64)


def test_buffer_capacity_is_capped_at_thinkquantum_size() -> None:
    TokenBucket(100, MAX_BUFFER_CAPACITY_BYTES)
    with pytest.raises(ValueError, match="100 MiB"):
        TokenBucket(100, MAX_BUFFER_CAPACITY_BYTES + 1)


def test_clearing_history_resets_the_consumption_baseline() -> None:
    service = MockKmsService(
        "127.0.0.1",
        0,
        DEFAULT_SEED_HEX,
        10_000,
        4_096,
        4_096,
        "SAE_002",
        "SAE_001",
    )
    service.buffer.consume_blocking(64)
    service.record_sample()

    status = service.clear_history()

    assert len(status["history"]) == 1
    assert status["history"][0]["consumption_rate_bytes_per_second"] == 0


def test_presets_are_valid_and_have_unique_ids() -> None:
    pytest.importorskip("fastapi")
    from qkd_kms.web import load_presets

    directory = Path(__file__).parents[1] / "src" / "qkd_kms" / "presets"
    presets = load_presets(directory)
    assert {
        "long-distance-fiber",
        "metropolitan-fiber",
        "short-haul-fiber",
        "stable-lab",
    }.issubset(presets)


def test_password_login_creates_expiring_opaque_session() -> None:
    fastapi = pytest.importorskip("fastapi")
    from qkd_kms.web import AuthenticationManager

    auth = AuthenticationManager("correct horse battery staple")
    with pytest.raises(fastapi.HTTPException) as rejected:
        auth.login("wrong password", "127.0.0.1")
    assert rejected.value.status_code == 401

    session = auth.login("correct horse battery staple", "127.0.0.1")
    assert session.token
    assert session.csrf_token
    assert auth.get(session.token) == session


def test_dashboard_has_no_external_runtime_dependencies() -> None:
    dashboard = (
        Path(__file__).parents[1]
        / "src"
        / "qkd_kms"
        / "static"
        / "mock_kms_dashboard.html"
    ).read_text(encoding="utf-8")
    assert "https://" not in dashboard
    assert "/api/configuration" in dashboard
    assert "/api/history/clear" in dashboard
    assert "/api/presets" in dashboard


def test_outage_stops_generation_without_erasing_buffer_or_backfilling():
    clock = FakeClock()
    bucket = TokenBucket(100, 2000, initial_tokens=32, clock=clock)
    clock.advance(1)
    bucket.set_outage(True)
    assert bucket.snapshot()["buffer_available_bytes"] == 132
    clock.advance(10)
    status = bucket.snapshot()
    assert status["outage_active"] is True
    assert status["current_rate_bytes_per_second"] == 0
    assert status["buffer_available_bytes"] == 132
    assert status["configuration"]["generation_enabled"] is True
    bucket.consume_blocking(32)  # Buffered keys are still available.
    clock.advance(10)
    bucket.set_outage(False)
    assert bucket.snapshot()["buffer_available_bytes"] == 100
    clock.advance(1)
    assert bucket.snapshot()["buffer_available_bytes"] == 200


def test_configuration_changes_cannot_clear_outage_and_pause_is_preserved():
    clock = FakeClock()
    bucket = TokenBucket(100, 1000, clock=clock)
    bucket.set_outage(True)
    bucket.configure(RateModelConfig(average_rate_bytes_per_second=200))
    clock.advance(5)
    assert bucket.snapshot()["buffer_available_bytes"] == 0
    bucket.configure(RateModelConfig(average_rate_bytes_per_second=200, generation_enabled=False))
    bucket.set_outage(False)
    clock.advance(5)
    status = bucket.snapshot()
    assert status["outage_active"] is False
    assert status["configuration"]["generation_enabled"] is False
    assert status["current_rate_bytes_per_second"] == 0
    assert status["buffer_available_bytes"] == 0
