"""Alice encrypts; Bob retrieves the same key by ID and decrypts.

Run from the repository root: python examples/aes_demo.py
"""

import argparse
import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from qkd_kms import Etsi014Client, KmsClient, SimulatorClient


def encrypt(kms: KmsClient, plaintext: bytes) -> dict:
    handle = kms.allocate_key(32)  # 32 bytes = AES-256
    nonce = os.urandom(12)  # Fresh nonce for every encryption.
    ciphertext = AESGCM(handle.key).encrypt(nonce, plaintext, handle.key_id.encode())
    # Only this envelope crosses the application's channel; never send key bytes.
    return {
        "key_id": handle.key_id,
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def decrypt(kms: KmsClient, envelope: dict) -> bytes:
    handle = kms.fetch_key(envelope["key_id"], 32)
    return AESGCM(handle.key).decrypt(
        base64.b64decode(envelope["nonce"], validate=True),
        base64.b64decode(envelope["ciphertext"], validate=True),
        envelope["key_id"].encode(),
    )


def make_client(role: str) -> KmsClient:
    # Changing the backend only changes construction; encrypt/decrypt stay the same.
    prefix = role.upper()
    local_id = os.getenv(
        f"{prefix}_SAE_ID", "SAE_002" if role == "alice" else "SAE_001"
    )
    backend = os.getenv("KMS_BACKEND", "simulator")
    if backend == "simulator":
        return SimulatorClient(
            os.getenv("KMS_HOST", "127.0.0.1"),
            int(os.getenv("KMS_PORT", "9000")),
            local_sae_id=local_id,
            session_id=os.getenv("KMS_SESSION_ID", "standalone"),
        )
    if backend == "etsi014":
        peer = "BOB" if role == "alice" else "ALICE"
        return Etsi014Client(
            os.environ[f"{prefix}_KMS_URL"],
            peer_sae_id=os.environ[f"{peer}_SAE_ID"],
            client_cert=os.environ[f"{prefix}_CLIENT_CERT"],
            client_key=os.environ[f"{prefix}_CLIENT_KEY"],
            ca_cert=os.environ[f"{prefix}_CA_CERT"],
        )
    raise ValueError("KMS_BACKEND must be simulator or etsi014")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode",
        nargs="?",
        choices=["roundtrip", "encrypt", "decrypt"],
        default="roundtrip",
    )
    parser.add_argument("--message", default="Hello from the QKD hackathon!")
    args = parser.parse_args()
    if args.mode == "decrypt":
        # Read the JSON envelope on stdin, as if received over an application channel.
        import sys

        print(decrypt(make_client("bob"), json.load(sys.stdin)).decode())
    else:
        envelope = encrypt(make_client("alice"), args.message.encode())
        if args.mode == "encrypt":
            print(json.dumps(envelope))
        else:
            print(f"Alice encrypted a message with key ID {envelope['key_id']}.")
            print("Bob decrypted:", decrypt(make_client("bob"), envelope).decode())


if __name__ == "__main__":
    main()
