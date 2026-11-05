import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import ssl
import struct
import subprocess
import sys
import threading

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from qkd_kms import Etsi014Client, KmsError, SimulatorClient, create_client
from qkd_kms.client import _extract
from qkd_kms.simulator import DEFAULT_SEED_HEX, MockKmsService

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("aes_demo", ROOT / "examples/aes_demo.py")
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


@pytest.fixture
def service():
    server = MockKmsService(
        "127.0.0.1", 0, DEFAULT_SEED_HEX, 10_000, 4096, 4096, "SAE_002", "SAE_001"
    )
    server.start()
    try:
        yield server
    finally:
        server.stop()


def pair(service, session_id="standalone"):
    host, port = service.socket_address
    return (
        SimulatorClient(host, port, local_sae_id="SAE_002", session_id=session_id),
        SimulatorClient(host, port, local_sae_id="SAE_001", session_id=session_id),
    )


def test_aes_roundtrip_and_consumed_key(service):
    alice, bob = pair(service)
    envelope = demo.encrypt(alice, b"Hello Bob")
    assert set(envelope) == {"key_id", "nonce", "ciphertext"}
    assert demo.decrypt(bob, json.loads(json.dumps(envelope))) == b"Hello Bob"
    with pytest.raises(KmsError, match="unknown key_id"):
        demo.decrypt(bob, envelope)


def test_tampered_ciphertext_is_rejected(service):
    alice, bob = pair(service)
    envelope = demo.encrypt(alice, b"secret")
    ciphertext = bytearray(base64.b64decode(envelope["ciphertext"]))
    ciphertext[0] ^= 1
    envelope["ciphertext"] = base64.b64encode(ciphertext).decode()
    with pytest.raises(InvalidTag):
        demo.decrypt(bob, envelope)


def test_session_isolation_and_lengths(service):
    a1, b1 = pair(service, "team-one")
    a2, b2 = pair(service, "team-two")
    k1, k2 = a1.allocate_key(), a2.allocate_key()
    assert k1.key_id == k2.key_id
    assert k1.key != k2.key
    with pytest.raises(KmsError, match="length mismatch"):
        b1.fetch_key(k1.key_id, 16)
    assert b1.fetch_key(k1.key_id).key == k1.key
    assert b2.fetch_key(k2.key_id).key == k2.key
    assert "key=" not in repr(k1)


def test_invalid_identity_and_unknown_key(service):
    host, port = service.socket_address
    with pytest.raises(KmsError, match="unknown SAE"):
        SimulatorClient(host, port, local_sae_id="unregistered").allocate_key()
    _, bob = pair(service)
    with pytest.raises(KmsError, match="unknown key_id"):
        bob.fetch_key("99999")


@pytest.mark.parametrize("force_simulator", [False, True])
def test_demo_in_separate_processes(service, force_simulator):
    # Inject a code configuration for this temporary server into each process.
    sender = {
        "backend": "etsi014" if force_simulator else "simulator",
        "host": service.socket_address[0],
        "port": service.socket_address[1],
        "local_sae_id": "SAE_002",
    }
    receiver = {**sender, "local_sae_id": "SAE_001"}
    runner = [
        sys.executable,
        "-c",
        "from examples import aes_demo; import sys; "
        "aes_demo.SENDER_CONFIG = sys.argv.pop(1); "
        "aes_demo.RECEIVER_CONFIG = sys.argv.pop(1); aes_demo.main()",
        json.dumps(sender),
        json.dumps(receiver),
    ]
    flags = ["--force-simulator"] if force_simulator else []
    encrypted = subprocess.run(
        runner + ["encrypt", "--message", "Hi Bob"] + flags,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "key" not in json.loads(encrypted.stdout)
    decrypted = subprocess.run(
        runner + ["decrypt"] + flags,
        cwd=ROOT,
        input=encrypted.stdout,
        check=True,
        capture_output=True,
        text=True,
    )
    assert decrypted.stdout.strip() == "Hi Bob"


@pytest.mark.parametrize(
    "record",
    [
        {"keys": []},
        {"keys": [{"key_id": "1", "key": "%%%"}]},
        {"keys": [{"key_id": "1", "key": base64.b64encode(b"x").decode()}]},
        {"keys": [{"key_id": "wrong", "key": base64.b64encode(b"x" * 32).decode()}]},
    ],
)
def test_malformed_real_key_data(record):
    with pytest.raises(KmsError):
        _extract(record, "key", 32, "1")


@pytest.fixture
def tls_files(tmp_path):
    """Ephemeral test-only credentials, generated here and never checked in."""
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    files = {"ca": str(tmp_path / "ca.crt")}
    Path(files["ca"]).write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for role, usage in [
        ("server", ExtendedKeyUsageOID.SERVER_AUTH),
        ("client", ExtendedKeyUsageOID.CLIENT_AUTH),
    ]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
            )
            .sign(ca_key, hashes.SHA256())
        )
        files[role + "_cert"] = str(tmp_path / (role + ".crt"))
        files[role + "_key"] = str(tmp_path / (role + ".key"))
        Path(files[role + "_cert"]).write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        Path(files[role + "_key"]).write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return files


@contextmanager
def https_kms(files, *, require_client_cert=True):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, code, data):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())

        def do_GET(self):
            requests.append(
                ("GET", self.path, None, bool(self.connection.getpeercert()))
            )
            if "/missing/" in self.path:
                return self.respond(404, {})
            self.respond(
                200,
                {
                    "keys": [
                        {
                            "key_id": "test-id",
                            "key": base64.b64encode(b"x" * 32).decode(),
                        }
                    ]
                },
            )

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(
                ("POST", self.path, body, bool(self.connection.getpeercert()))
            )
            self.respond(
                200,
                {
                    "keys": [
                        {
                            "key_id": "test-id",
                            "key": base64.b64encode(b"x" * 32).decode(),
                        }
                    ]
                },
            )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(files["server_cert"], files["server_key"])
    context.load_verify_locations(files["ca"])
    context.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_NONE
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    try:
        yield f"https://localhost:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def real_client(url, files, peer="SAE/peer"):
    return Etsi014Client(
        url,
        peer_sae_id=peer,
        ca_cert=files["ca"],
        client_cert=files["client_cert"],
        client_key=files["client_key"],
    )


def test_etsi_https_mutual_tls_and_wire_format(tls_files):
    with https_kms(tls_files) as (url, requests):
        alice = real_client(url, tls_files)
        bob = real_client(url, tls_files, "SAE/alice")
        handle = alice.allocate_key(32)
        assert bob.fetch_key(handle.key_id).key == handle.key == b"x" * 32
        assert requests == [
            ("GET", "/api/v1/keys/SAE%2Fpeer/enc_keys?number=1&size=256", None, True),
            (
                "POST",
                "/api/v1/keys/SAE%2Falice/dec_keys",
                {"key_IDs": [{"key_ID": "test-id"}]},
                True,
            ),
        ]


def test_real_adapter_runs_same_aes_functions(tls_files):
    with https_kms(tls_files) as (url, _):
        assert (
            demo.decrypt(
                real_client(url, tls_files, "alice"),
                demo.encrypt(real_client(url, tls_files, "bob"), b"unchanged app"),
            )
            == b"unchanged app"
        )


def test_real_adapter_http_error_and_tls_hostname_check(tls_files):
    with https_kms(tls_files) as (url, _):
        with pytest.raises(KmsError, match="HTTP 404"):
            real_client(url, tls_files, "missing").allocate_key()
        with pytest.raises(KmsError, match="HTTPS request failed"):
            real_client(url.replace("localhost", "127.0.0.1"), tls_files).allocate_key()
    with pytest.raises(ValueError, match="HTTPS origin"):
        real_client("http://localhost", tls_files)


def test_factory_real_kms_roundtrip(tls_files):
    with https_kms(tls_files) as (url, _):
        endpoint = {
            "base_url": url,
            "peer_sae_id": "bob",
            "ca_cert": tls_files["ca"],
            "client_cert": tls_files["client_cert"],
            "client_key": tls_files["client_key"],
        }
        sender_config = {"backend": "etsi014", **endpoint}
        receiver_config = {**sender_config, "peer_sae_id": "alice"}
        alice = create_client(sender_config)
        bob = create_client(json.dumps(receiver_config))
        assert (
            demo.decrypt(bob, demo.encrypt(alice, b"factory-created clients"))
            == b"factory-created clients"
        )


def test_ignore_cert_allows_untrusted_server_without_client_auth(tls_files):
    with https_kms(tls_files, require_client_cert=False) as (url, requests):
        config = {
            "backend": "etsi014",
            "base_url": url.replace("localhost", "127.0.0.1"),
            "peer_sae_id": "bob",
            "ignore_cert": True,
        }
        # Both the server CA and hostname are untrusted; strict mode rejects it.
        with pytest.raises(KmsError, match="HTTPS request failed"):
            create_client({**config, "ignore_cert": False}).allocate_key()
        alice = create_client(config)
        bob = create_client({**config, "peer_sae_id": "alice"})
        assert demo.decrypt(bob, demo.encrypt(alice, b"lab keys")) == b"lab keys"
        assert all(not request[3] for request in requests)


def test_ignore_cert_still_sends_client_certificate(tls_files, tmp_path):
    with https_kms(tls_files) as (url, requests):
        config = {
            "backend": "etsi014",
            "base_url": url.replace("localhost", "127.0.0.1"),
            "peer_sae_id": "bob",
            "client_cert": tls_files["client_cert"],
            "client_key": tls_files["client_key"],
            "ca_cert": str(tmp_path / "unused-ca.crt"),
            "ignore_cert": True,
            "timeout": 2,
        }
        assert create_client(config).allocate_key().key == b"x" * 32
        assert requests[-1][3] is True
        # Ignoring the server certificate cannot bypass server-side mTLS rules.
        with pytest.raises(KmsError, match="HTTPS request failed"):
            create_client({**config, "client_cert": None, "client_key": None}).allocate_key()


def load_example(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"examples/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_png_example_roundtrip(service, tmp_path):
    sender = {"backend": "simulator", "host": service.socket_address[0],
              "port": service.socket_address[1], "local_sae_id": "SAE_002"}
    receiver = {**sender, "local_sae_id": "SAE_001"}
    command = [sys.executable, "-c",
               "from examples import png_demo; import sys; "
               "png_demo.SENDER_CONFIG = sys.argv.pop(1); "
               "png_demo.RECEIVER_CONFIG = sys.argv.pop(1); png_demo.main()",
               json.dumps(sender), json.dumps(receiver), "--output-dir", str(tmp_path)]
    result = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
    assert "matches the original" in result.stdout
    original = (ROOT / "examples/sample.png").read_bytes()
    assert (tmp_path / "image.decrypted.png").read_bytes() == original
    envelope = json.loads((tmp_path / "image.encrypted.json").read_text())
    assert set(envelope) == {"key_id", "ciphertext"}
    ciphertext = base64.b64decode(envelope["ciphertext"])
    assert len(ciphertext) == len(original)
    bitmap = (tmp_path / "image.ciphertext.bmp").read_bytes()
    signature, file_size, _, _, offset = struct.unpack_from("<2sIHHI", bitmap)
    assert (signature, file_size) == (b"BM", len(bitmap))
    _, width, height, _, depth = struct.unpack_from("<IiiHH", bitmap, 14)
    assert height < 0 and depth == 24
    stride = (width * 3 + 3) & ~3
    for index, byte in enumerate(ciphertext):
        row, column = divmod(index, width)
        pixel = offset + row * stride + column * 3
        assert bitmap[pixel : pixel + 3] == bytes([byte]) * 3


def test_png_example_ciphertext_bit_flip_changes_the_matching_plaintext_bit(service, tmp_path):
    png = load_example("png_demo")
    alice, bob = pair(service)
    encrypted = tmp_path / "encrypted.json"
    output = tmp_path / "decrypted.png"
    original = ROOT / "examples/sample.png"
    png.encrypt_image(alice, original, encrypted)
    envelope = json.loads(encrypted.read_text())
    ciphertext = bytearray(base64.b64decode(envelope["ciphertext"]))
    ciphertext[0] ^= 1
    envelope["ciphertext"] = base64.b64encode(ciphertext).decode()
    encrypted.write_text(json.dumps(envelope))
    png.decrypt_image(bob, encrypted, output)
    expected = bytearray(original.read_bytes())
    expected[0] ^= 1
    assert output.read_bytes() == expected


def test_minimal_key_example_prints_matching_binary_hex_and_id(service):
    config = {"backend": "simulator", "host": service.socket_address[0],
              "port": service.socket_address[1], "local_sae_id": "SAE_002"}
    result = subprocess.run(
        [sys.executable, "-c", "from examples import fetch_key; import sys; "
         "fetch_key.CONFIG = sys.argv[1]; fetch_key.main()", json.dumps(config)],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    lines = dict(line.split(": ", 1) for line in result.stdout.strip().splitlines())
    bits = lines["Binary"].split()
    assert len(bits) == 32
    assert all(len(value) == 8 and set(value) <= {"0", "1"} for value in bits)
    binary_key = bytes(int(value, 2) for value in bits)
    assert binary_key.hex() == lines["Hex"]
    _, bob = pair(service)
    assert bob.fetch_key(lines["Key ID"]).key == binary_key


def test_outage_allows_peer_fetch_and_waiting_allocation_resumes(service):
    from concurrent.futures import ThreadPoolExecutor
    import time

    alice, bob = pair(service)
    key = alice.allocate_key()
    service.buffer.set_outage(True)
    assert bob.fetch_key(key.key_id).key == key.key
    service.buffer.set_available_bytes(0)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(alice.allocate_key)
        try:
            deadline = time.monotonic() + 2
            while service.buffer.snapshot()["blocked_consumers"] == 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert service.buffer.snapshot()["blocked_consumers"] == 1
            assert not future.done()
        finally:
            service.buffer.set_outage(False)
        resumed_key = future.result(timeout=2)
        assert bob.fetch_key(resumed_key.key_id).key == resumed_key.key
