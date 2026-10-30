import json

import pytest

from qkd_kms import SimulatorClient, create_client
from qkd_kms.client import DEFAULT_CONFIG_JSON, NETWORK_KMS_CONFIG_JSON


def test_default_client_and_no_environment_overrides(monkeypatch):
    monkeypatch.setenv("KMS_BACKEND", "etsi014")
    monkeypatch.setenv("KMS_HOST", "unused.example")
    client = create_client()
    assert isinstance(client, SimulatorClient)
    assert (client.host, client.port, client.local_sae_id) == (
        "127.0.0.1",
        9000,
        "SAE_002",
    )


def test_flat_configuration_without_role_names():
    config = json.loads(DEFAULT_CONFIG_JSON)
    config.update(
        host="simulator.example",
        port=9010,
        local_sae_id="my-application",
        session_id="team-one",
        timeout=60,
    )
    client = create_client(config)
    assert (
        client.host,
        client.port,
        client.local_sae_id,
        client.session_id,
        client.timeout,
    ) == ("simulator.example", 9010, "my-application", "team-one", 60)


def test_force_simulator_does_not_load_network_credentials():
    client = create_client(NETWORK_KMS_CONFIG_JSON, force_simulator=True)
    assert isinstance(client, SimulatorClient)
    assert (client.host, client.port, client.local_sae_id) == (
        "127.0.0.1",
        9000,
        "SAE_002",
    )


def test_real_configuration_failure_never_falls_back(tmp_path):
    config = json.loads(NETWORK_KMS_CONFIG_JSON)
    config["ca_cert"] = str(tmp_path / "missing-ca.crt")
    with pytest.raises(FileNotFoundError):
        create_client(config)


@pytest.mark.parametrize(
    "config",
    [
        {"backend": "unknown"},
        {},
        [],
        "[]",
        "not json",
        {"backend": "etsi014"},
        {"backend": "simulator"},
    ],
)
def test_invalid_configuration_is_reported(config):
    with pytest.raises(ValueError):
        create_client(config)
