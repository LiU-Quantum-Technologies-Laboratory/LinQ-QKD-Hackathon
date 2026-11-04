"""Alice encrypts; Bob retrieves the same key by ID and decrypts.

Run from the repository root: python examples/aes_demo.py
"""

import argparse
import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from qkd_kms import KmsClient, create_client

# This program plays both participants. A normal app needs only its own config.
# The only difference here is each participant's local SAE (application) identity.
SENDER_CONFIG = """
{
  "backend": "simulator",
  "host": "127.0.0.1",
  "port": 9000,
  "local_sae_id": "SAE_002"
}
"""

RECEIVER_CONFIG = """
{
  "backend": "simulator",
  "host": "127.0.0.1",
  "port": 9000,
  "local_sae_id": "SAE_001"
}
"""

# Unused network example. Configure each participant's local KMS and credentials.
# To use it, fill in the actual values and assign it to SENDER_CONFIG above.
# peer_sae_id is required only for backend="etsi014": it identifies the OTHER
# application that will share the keys, for both allocation and key-ID retrieval.
# Here the sender is SAE_002 and its peer is SAE_001. The receiver uses the
# reverse: local_sae_id=SAE_001, peer_sae_id=SAE_002, and its own KMS/certificates.
# The simulator already has a fixed pair of SAE IDs, so peer_sae_id is not used.
# For ETSI, the client certificate establishes your local identity; local_sae_id
# is kept here so force_simulator=True can select the matching simulator identity.
# client_cert/client_key authenticate this app; ca_cert verifies the KMS server.
# ignore_cert=true skips only server certificate/hostname checks for lab testing.
# Client cert/key may be omitted only if the server allows connections without them.
NETWORK_KMS_CONFIG = """
{
  "backend": "etsi014",
  "base_url": "https://kms.example:443",
  "local_sae_id": "SAE_002",
  "peer_sae_id": "SAE_001",
  "client_cert": "certs/client.crt",
  "client_key": "certs/client.key",
  "ca_cert": "certs/kms-ca.crt",
  "ignore_cert": false
}
"""


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode",
        nargs="?",
        choices=["roundtrip", "encrypt", "decrypt"],
        default="roundtrip",
    )
    parser.add_argument("--message", default="Hello from the QKD hackathon!")
    parser.add_argument(
        "--force-simulator",
        action="store_true",
        help="use the simulator even when the configuration selects a real KMS",
    )
    args = parser.parse_args()
    if args.mode == "decrypt":
        # Read the JSON envelope on stdin, as if received over an application channel.
        import sys

        print(
            decrypt(
                create_client(RECEIVER_CONFIG, force_simulator=args.force_simulator),
                json.load(sys.stdin),
            ).decode()
        )
    else:
        envelope = encrypt(
            create_client(SENDER_CONFIG, force_simulator=args.force_simulator),
            args.message.encode(),
        )
        if args.mode == "encrypt":
            print(json.dumps(envelope))
        else:
            print(f"Alice encrypted a message with key ID {envelope['key_id']}.")
            print(
                "Bob decrypted:",
                decrypt(
                    create_client(
                        RECEIVER_CONFIG, force_simulator=args.force_simulator
                    ),
                    envelope,
                ).decode(),
            )


if __name__ == "__main__":
    main()
