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
from qkd_kms import SimulatorClient

alice = SimulatorClient(local_sae_id='SAE_002')
bob = SimulatorClient(local_sae_id='SAE_001')
key = alice.allocate_key(32)
# Send key.key_id to Bob over your application's channel, never key.key.
matching_key = bob.fetch_key(key.key_id, 32)
assert key.key == matching_key.key
```

`KmsClient` is the shared interface: `allocate_key(length_bytes=32)` and
`fetch_key(key_id, length_bytes=32)` both return `KeyHandle(key_id, key)` with
raw `bytes`. Key material is excluded from the handle's printed representation.
The client converts base64 and validates lengths at the boundary.

To install into another app's environment, use `python -m pip install /path/to/qkd-kms-starter`.
The clients and headless simulator need only Python's standard library. The
`demo` extra adds `cryptography`; the `web` extra adds FastAPI and Uvicorn.
You can also embed the simulator by constructing `qkd_kms.simulator.MockKmsService`,
calling `start()`, and always calling `stop()` when finished (see the tests).

For multiple teams sharing a simulator, set `KMS_SESSION_ID=team-one` for both
peers and view `http://127.0.0.1:8080/?session_id=team-one` in the dashboard.
Session IDs are namespaces, not credentials. Each namespace has its own buffer
and keys. The client waits up to 30 seconds for a key; if you deliberately pause
or greatly slow generation, pass a larger `timeout` to `SimulatorClient`.
A timed-out allocation may still complete on the server; a retry requests a new
key and may leave an undelivered record until restart.

## Replace the simulator with a real KMS

Construct `Etsi014Client` instead of `SimulatorClient`. The encryption and
decryption functions stay unchanged. The adapter targets the
[ETSI GS QKD 014 v1.1.1 key-delivery API](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf):
`GET enc_keys` and `POST dec_keys`. It converts byte lengths to bits for ETSI,
decodes base64 replies and uses HTTPS with client certificates and CA validation.
The simulator itself retains the original custom TCP protocol; it is not an
ETSI REST server. The interchangeable Python adapters provide the common interface.

```python
from qkd_kms import Etsi014Client

alice = Etsi014Client(
    'https://alice-kms.example',
    peer_sae_id='BOB_SAE_ID',
    client_cert='/path/to/alice-client.crt',
    client_key='/path/to/alice-client.key',
    ca_cert='/path/to/kms-ca.crt',
)
key = alice.allocate_key(32)
```

Alice connects to her local KMS with Bob's SAE ID; Bob connects to his local KMS
with Alice's SAE ID. The KMS operator must provision their peer relationship,
identities, certificates and permissions. Hostnames must match certificates.
There is no insecure TLS option and no fallback to simulated keys.

To run the same AES demo against hardware, set these environment variables:

| Variable | Value |
| --- | --- |
| `KMS_BACKEND` | `etsi014` |
| `ALICE_KMS_URL`, `BOB_KMS_URL` | Each site's HTTPS KMS origin |
| `ALICE_SAE_ID`, `BOB_SAE_ID` | Operator-provisioned application identities |
| `ALICE_CLIENT_CERT`, `BOB_CLIENT_CERT` | Each application's certificate file |
| `ALICE_CLIENT_KEY`, `BOB_CLIENT_KEY` | Each application's private key file |
| `ALICE_CA_CERT`, `BOB_CA_CERT` | Trusted KMS CA certificate file |

For the roundtrip demo, the machine needs connectivity and credentials for both
sites. Separate `encrypt`/`decrypt` processes each need only their own credentials
and their peer's SAE ID. For the simulator, optional `KMS_HOST` and `KMS_PORT`
select its address; `KMS_BACKEND` defaults to `simulator`.

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
