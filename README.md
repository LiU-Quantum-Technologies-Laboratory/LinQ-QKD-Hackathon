# QKD KMS hackathon starter

This repo shows how to build a small app that consumes shared keys from a QKD 
key management system (KMS).
This repository contains an installable Python module called `qkd-kms`, which exposes 
an API to consome keys. It is steup so you can easily switch between simulated keys or 
keys from a real QKD system. You can also launch a web interface where you can monitor the KMS
or change parameters if it uses a simulated QKD system.

To show how to build an app is very simple AES-256-GCM example is included inside `examples/aes_demo.py`. 

The simulator generates pseudo-random key material; it does not simulate quantum physics or
provide QKD security. Its finite buffer, generation rate, fluctuations and
outages let you explore how an application behaves when keys are scarce or the buffers fills up very slowly. 

## Getting started
You need to run the kms in one terminal and then the consuming app in another terminal.

### Starting the KMS

Requires Python 3.10 or newer. From this repository's root:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[demo,web]'
qkd-kms-simulator --headless
```

or if you prefer uv:
```sh
uv sync --all-extras
uv run qkd-kms-simulator --headless
```

If you want to also serve the dashboard where you can change the parameters exchange `--headless` 
for  `--admin-password` or `--no-auth`.

On Windows, activate with `.venv\Scripts\activate`.

### Start the demo consumer app
In another terminal, activate the same environment and run:

```sh
python examples/aes_demo.py
```
or if using uv:
```sh
uv run python examples/aes_demo.py
```

Expected output (the key ID varies if you rerun it):

```text
Alice encrypted a message with key ID 1.
Bob decrypted: Hello from the QKD hackathon!
```


### Experimenting
The simulator serves keys to both Alice and Bob at `127.0.0.1:9000`. The default SAE
(application) identities are `SAE_002` and `SAE_001`. You can leave it running while you
experiment.

If you didn't start it with `--headless` you can open <http://127.0.0.1:8080> to view the dashboard. 
Change the rate, fill or drain the buffer, pause
key generation, or load a fiber/lab preset. `--no-auth` is for local development.
Dashboard authentication only protects the control plane; the simulator's TCP
key transport has no TLS or authentication. Both listeners bind to localhost by
default. Use it locally or on a trusted, isolated network if you want to make it harder for Eve.
To require a dashboard password, set `LINQKD_ADMIN_PASSWORD` and omit `--no-auth`.
```sh
export LINQKD_ADMIN_PASSWORD='choose-your-password'
.venv/bin/qkd-kms-simulator
```

## More examples

Keep the KMS running in the first terminal. Each example has its own inline JSON
configuration and can use either client backend.

### Just fetch and inspect a key

This is the smallest example: request one 256-bit key and print its ID, binary
bits (eight per byte), and hexadecimal representation. It needs no demo extras.

```sh
python examples/fetch_key.py
```

With uv:

```sh
uv run python examples/fetch_key.py
```

### Encrypt and decrypt a PNG with a one-time pad

The image example uses a bundled 32×32 PNG. The sender requests a fresh pad
with exactly one key byte per byte of the PNG, then XORs them together. The
receiver fetches the same pad by key ID and XORs it with the ciphertext to
recover the PNG. The demo compares the original and recovered files byte for byte.

```sh
python examples/png_demo.py
```

With uv:

```sh
uv run python examples/png_demo.py
```

Or provide your own small PNG and output folder:

```sh
uv run python examples/png_demo.py path/to/image.png --output-dir demo-output
```

The sender writes the key ID and ciphertext to `demo-output/image.encrypted.json`
for the receiver, who saves the recovered file as `demo-output/image.decrypted.png`.
The demo also writes `demo-output/image.ciphertext.bmp` for viewing. The encrypted
PNG header prevents image viewers from opening the raw ciphertext as a PNG.
The bitmap gives those bytes a valid image header and shows each byte as a
grayscale pixel. The receiver decrypts from the JSON envelope.
Each run uses a new pad and replaces the output files. The simulator uses
pseudorandom keys to demonstrate the technique. A true one-time pad requires
uniformly random key bytes used only once. XOR alone provides no authentication:
flipping a ciphertext bit flips the corresponding bit in the recovered file.
If you use a real KMS, it must support requesting a key the size of your PNG.


## What the example teaches

1. Alice requests a fresh 32-byte key from her KMS.
2. She encrypts with AES-GCM and a fresh random 12-byte nonce.
3. She sends Bob a JSON envelope containing the key ID, nonce and ciphertext
   (which includes the authentication tag). **Key bytes never go in the envelope.**
4. Bob requests the same key ID from his KMS and decrypts the message.

The key ID is also authenticated as AES-GCM associated data. A fresh key is
allocated for every message. AES-GCM authenticates the encrypted payload; an
application still needs to establish who its peers are and protect its channels.

AES-GCM always produces an authentication tag. The `AESGCM` library appends a
16-byte tag to the encrypted bytes, so our envelope's `ciphertext` already
contains it. Decryption verifies the tag automatically and raises `InvalidTag`
if verification fails; no separate tag field or manual check is needed.

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

## Import it in your own app

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

Each configuration describes one application's connection. 
The demo runs both participants in one process, so
it declares `SENDER_CONFIG` and `RECEIVER_CONFIG` as inline multiline JSON strings.
Their `local_sae_id` values match the two identities configured on the simulator.

`KmsClient` is the shared interface: `allocate_key(length_bytes=32)` and
`fetch_key(key_id, length_bytes=32)` both return `KeyHandle(key_id, key)` with
raw `bytes`. Key material is excluded from the handle's printed representation.
The client converts base64 and validates lengths at the boundary.

To install into another app's environment, use `python -m pip install /path/to/qkd-kms-starter`.
The simulator client and headless simulator need only Python's standard library.
The `etsi` extra adds the ETSI client library, `demo` adds `cryptography`, and
`web` adds FastAPI and Uvicorn.
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

Install the [ETSI QKD 014 client package](https://pypi.org/project/etsi-qkd-014-client/)
through the `etsi` extra. From the repository root, use either command.

```sh
python -m pip install -e '.[demo,etsi]'
```

```sh
uv sync --extra demo --extra etsi
```

Keep calling `create_client(CONFIG)` and set the ETSI configuration as follows.

```python
CONFIG = """
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

kms = create_client(CONFIG)
```

Run the example from the repository root so the relative paths resolve to
`certs_out/`. The example uses `qkd_client.cert` and `qkd_client.key` for
client authentication and `root_ca.cert` to verify the KMS server. Set the
KMS URL and SAE IDs for each participant. Certificate and private key files
are ignored by Git, so each checkout needs a local copy of the credentials.

The certificate settings match the options in the supplied `qkd014-client` CLI:

| Configuration field | CLI equivalent | Purpose |
| --- | --- | --- |
| `base_url` | `--hostname` / `-H` | HTTPS address of the local KMS, including `https://` |
| `peer_sae_id` | `sae_id` argument | The other application's SAE ID |
| `client_cert` | `--cert` / `-c` | Certificate identifying this application to the KMS |
| `client_key` | `--key` / `-k` | Private key matching that client certificate |
| `ca_cert` | `--ca` / `-r` | CA certificate used to verify the KMS server |
| `ignore_cert` | `--force` / `-f` | Skip checking the server's certificate and hostname |

`ignore_cert` defaults to `false`. With verification enabled, `ca_cert` may be
omitted to use the ETSI library's default trust store. For a real KMS using mutual TLS, supply
both `client_cert` and `client_key`; they must be a matching pair provisioned by
the operator. The server establishes the local SAE identity from that certificate.
The wrapper passes these settings to the same Python library used by the CLI.

For an HTTPS lab server whose certificate is not set up correctly, explicitly use
`"ignore_cert": true`. For example, if it does not require client authentication:

```python
CONFIG = """
{
  "backend": "etsi014",
  "base_url": "https://localhost:9443",
  "local_sae_id": "SAE_002",
  "peer_sae_id": "SAE_001",
  "ignore_cert": true
}
"""

kms = create_client(CONFIG)
```

This stays on HTTPS but disables server identity checks; use it only for trusted
lab testing. In this mode `ca_cert` is ignored, including any configured file path.
It does **not** bypass client authentication: if the KMS requires mutual TLS, keep
supplying valid `client_cert` and `client_key` files. Supplying just one is an error,
and supplied client files are always loaded, even with `ignore_cert: true`.
This example expects a separate ETSI HTTPS lab server; the included simulator
still uses its own TCP protocol. The AES functions work with either client.

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
[ETSI GS QKD 014 v1.1.1 key-delivery API](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf).
The wrapper calls `get_key()` for allocation and `get_key_with_key_IDs()` for
retrieval. It converts byte lengths to bits and decodes replies into raw key bytes.
The library uses HTTPS POST for both requests and sets a 10-second request
timeout. The `timeout` configuration field applies to the simulator client.
The simulator itself retains the original custom TCP protocol; it is not an
ETSI REST server. The interchangeable Python adapters provide the common interface.

Alice connects to her local KMS with Bob's SAE ID; Bob connects to his local KMS
with Alice's SAE ID. The KMS operator must provision their peer relationship,
identities, certificates and permissions. With `ignore_cert: false`, hostnames
must match certificates. There is no automatic fallback to simulated keys.
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
python -m pip install -e '.[demo,web,test,etsi]'
python -m pytest
```

CI runs the tests on Python 3.10, 3.12 and 3.14. See [PROVENANCE.md](PROVENANCE.md)
for the extraction inventory and remaining publication decisions. The original
repository is unchanged. No certificates, private keys, local addresses or Git
history were copied. A public license has not been chosen; confirm reuse rights
and add the agreed license before publishing this repository.


## Build and use as a library in your own project

From your own project's directory, install this repository as a dependency.
With pip, activate your project's environment first:

```sh
python -m pip install "/path/to/qkd-kms-starter"
```

Or with uv, which records the dependency in your project's `pyproject.toml`:

```sh
uv add "/path/to/qkd-kms-starter"
```

Then use the same API in your application:

```python
from qkd_kms import create_client

kms = create_client(CONFIG)  # Your inline JSON configuration from the examples.
key = kms.allocate_key(32)
```

To distribute a packaged release, build from this repository's root:

```sh
uv build
```

Or using Python's build tool:

```sh
python -m pip install build
python -m build
```

This generates a `.whl` (installable package) and `.tar.gz` (source archive) in
`dist/`. You can install the wheel in another project with either tool:

```sh
python -m pip install "/path/to/qkd-kms-starter/dist/qkd_kms_starter-0.1.0-py3-none-any.whl"
```

```sh
uv add "/path/to/qkd-kms-starter/dist/qkd_kms_starter-0.1.0-py3-none-any.whl"
```

Installing directly from the source checkout also builds the package automatically;
no separate build step is needed. Add `[etsi]` to the source installation path
for the ETSI client. The simulator client is available with the base installation.

Commit source code and `pyproject.toml` to Git; keep generated `dist/` artifacts
out of Git (already ignored). Rebuild them for each release, then attach them to
a GitHub Release or publish them to a package registry such as PyPI.
