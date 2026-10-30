# QKD KMS hackathon starter

Build an app that consumes shared keys from a QKD key management system (KMS).
This repository contains an installable Python module, the standalone simulator
extracted from `qkd-demo-apps`, its dashboard and link presets, and a small
AES-256-GCM example. No portal or other demo apps are needed.

The simulator generates software keys; it does not simulate quantum physics or
provide QKD security. Its finite buffer, generation rate, fluctuations and
outages let you explore how an application behaves when keys are scarce.

## Start in two terminals

Requires Python 3.10 or newer. From this repository's root:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[demo,web]'
qkd-kms-simulator --headless
```

On Windows, activate with `.venv\Scripts\activate`.
In another terminal, activate the same environment and run:

```sh
python examples/aes_demo.py
```

Expected output (the key ID varies):

```text
Alice encrypted a message with key ID 1.
Bob decrypted: Hello from the QKD hackathon!
```

The simulator serves both Alice and Bob at `127.0.0.1:9000`. The default SAE
(application) identities are `SAE_002` and `SAE_001`. Leave it running while you
experiment. To see the dashboard, restart it without `--headless`:

```sh
qkd-kms-simulator --no-auth
```

Open <http://127.0.0.1:8080>. Change the rate, fill or drain the buffer, pause
key generation, or load a fiber/lab preset. `--no-auth` is for local development.
To require a dashboard password, set `LINQKD_ADMIN_PASSWORD` and omit `--no-auth`.
Dashboard authentication only protects the control plane; the simulator's TCP
key transport has no TLS or authentication. Both listeners bind to localhost by
default. Use it locally or on a trusted, isolated hackathon network.

## What the example teaches

1. Alice requests a fresh 32-byte key from her KMS.
2. She encrypts with AES-GCM and a fresh random 12-byte nonce.
3. She sends Bob a JSON envelope containing the key ID, nonce and ciphertext
   (which includes the authentication tag). **Key bytes never go in the envelope.**
4. Bob requests the same key ID from his KMS and decrypts the message.

The key ID is also authenticated as AES-GCM associated data. A fresh key is
allocated for every message. AES-GCM authenticates the encrypted payload; an
application still needs to establish who its peers are and protect its channels.

For separate sender and receiver processes:

```sh
python examples/aes_demo.py encrypt --message 'Hello Bob' > message.json
python examples/aes_demo.py decrypt < message.json
```

The demo uses a file in place of your application's message channel. A simulator
key is removed after delivery to both parties, so a consumed envelope cannot be
decrypted again by fetching its key. Simulator state is in memory and resets on
restart. Random seeding is the default; `--seed-hex HEX` enables reproducible
software keys for testing only.

## Import it in your own MVP

Install this repository once, then import `qkd_kms`:

```python
from qkd_kms import create_client

CONFIG = """
{
  "backend": "simulator",
  "host": "127.0.0.1",
  "port": 9000,
  "local_sae_id": "SAE_002"
}
"""

kms = create_client(CONFIG)
key = kms.allocate_key(32)
# Send key.key_id to your peer over the application's channel, never key.key.
# The peer uses its own client: matching_key = peer.fetch_key(key.key_id, 32).
```

Each configuration describes one application's connection. There are no role
names to pass to the module. The demo runs both participants in one process, so
it declares `SENDER_CONFIG` and `RECEIVER_CONFIG` as inline multiline JSON strings.
Their `local_sae_id` values match the two identities configured on the simulator.

`KmsClient` is the shared interface: `allocate_key(length_bytes=32)` and
`fetch_key(key_id, length_bytes=32)` both return `KeyHandle(key_id, key)` with
raw `bytes`. Key material is excluded from the handle's printed representation.
The client converts base64 and validates lengths at the boundary.

To install into another app's environment, use `python -m pip install /path/to/qkd-kms-starter`.
The clients and headless simulator need only Python's standard library. The
`demo` extra adds `cryptography`; the `web` extra adds FastAPI and Uvicorn.
You can also embed the simulator by constructing `qkd_kms.simulator.MockKmsService`,
calling `start()`, and always calling `stop()` when finished (see the tests).

For multiple teams sharing a simulator, set `session_id` to `team-one`
in the code configuration for both peers and view `http://127.0.0.1:8080/?session_id=team-one` in the dashboard.
Session IDs are namespaces, not credentials. Each namespace has its own buffer
and keys. The client waits up to 30 seconds for a key; if you deliberately pause
or greatly slow generation, increase `timeout` in the configuration.
A timed-out allocation may still complete on the server; a retry requests a new
key and may leave an undelivered record until restart.

## Replace the simulator with a real KMS

Keep calling `create_client(CONFIG)` and change the flat JSON configuration:

```python
CONFIG = """
{
  "backend": "etsi014",
  "base_url": "https://kms.example:443",
  "local_sae_id": "SAE_002",
  "peer_sae_id": "SAE_001",
  "client_cert": "certs/client.crt",
  "client_key": "certs/client.key",
  "ca_cert": "certs/kms-ca.crt"
}
"""

kms = create_client(CONFIG)
```

The example hostname, identities and certificate paths are placeholders. Each
participant configures its own local KMS and credentials. Relative certificate
paths are resolved from the directory where you run the application. Only paths
go into configuration; private keys stay in their files.

The AES demo includes an unused `NETWORK_KMS_CONFIG` string you can adapt for
`SENDER_CONFIG`; set up `RECEIVER_CONFIG` for the peer too. All client classes,
`create_client()`, and the module's example configurations live in
[`src/qkd_kms/client.py`](src/qkd_kms/client.py). The demo defines its configurations
directly so it can be read on its own. No separate configuration module or
environment-variable overrides are involved. A Python dictionary is also accepted.

The factory defaults to the local simulator example when called with no arguments.
The optional `force_simulator` argument defaults to `False`. Set it to `True` to
explicitly override a real-KMS configuration without loading its certificates:

```python
kms = create_client(CONFIG, force_simulator=True)
```

Simulator connections use `host` (default `127.0.0.1`), `port` (default `9000`),
`local_sae_id`, optional `session_id` (default `standalone`) and `timeout` (default
30 seconds). The override uses these same fields; the real KMS's `base_url` is
ignored. Keep `local_sae_id` compatible with the running simulator when overriding.
It connects to a simulator you have already started; it does not launch a server.
The demo exposes the same override:

```sh
python examples/aes_demo.py --force-simulator
```

The real adapter targets the
[ETSI GS QKD 014 v1.1.1 key-delivery API](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf):
`GET enc_keys` and `POST dec_keys`. It converts byte lengths to bits for ETSI,
decodes base64 replies and uses HTTPS with client certificates and CA validation.
The simulator itself retains the original custom TCP protocol; it is not an
ETSI REST server. The interchangeable Python adapters provide the common interface.

Alice connects to her local KMS with Bob's SAE ID; Bob connects to his local KMS
with Alice's SAE ID. The KMS operator must provision their peer relationship,
identities, certificates and permissions. Hostnames must match certificates.
There is no insecure TLS option and no automatic fallback to simulated keys.
Real-KMS configuration and connection failures are reported to the app.

For the roundtrip demo, the machine needs connectivity and credentials for both
sites. Separate `encrypt`/`decrypt` processes each need only their own credentials
and their peer's SAE ID. Encryption and decryption code stays unchanged.

The HTTPS adapter is tested against a local mutual-TLS test server. Actual QKD
hardware was not available for verification. Confirm the API version and vendor
requirements with the operator before the hackathon; a different API can be
supported by implementing the two `KmsClient` methods.

## Development and provenance

```sh
python -m pip install -e '.[demo,web,test]'
python -m pytest
```

CI runs the tests on Python 3.10, 3.12 and 3.14. See [PROVENANCE.md](PROVENANCE.md)
for the extraction inventory and remaining publication decisions. The original
repository is unchanged. No certificates, private keys, local addresses or Git
history were copied. A public license has not been chosen; confirm reuse rights
and add the agreed license before publishing this repository.
