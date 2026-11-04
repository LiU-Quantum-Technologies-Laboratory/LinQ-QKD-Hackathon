"""Encrypt a small PNG with a KMS key, then decrypt it with the peer's matching key.

Run: python examples/png_demo.py [path/to/image.png]
The bundled sample is used if no path is provided. Outputs go to demo-output/.
"""

import argparse
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from qkd_kms import KmsClient, create_client

# One configuration for each participant; change these to use a real ETSI KMS.
# See aes_demo.py for the inline network configuration and certificate settings.
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

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def encrypt_image(kms: KmsClient, image_path: Path, encrypted_path: Path) -> str:
    image = image_path.read_bytes()
    if not image.startswith(PNG_SIGNATURE):
        raise ValueError("Input must be a PNG file")
    handle = kms.allocate_key(32)
    nonce = os.urandom(12)
    # Encrypt the entire PNG file, including its header. Authenticate the key ID.
    ciphertext = AESGCM(handle.key).encrypt(nonce, image, handle.key_id.encode())
    envelope = {
        "key_id": handle.key_id,
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    # Send this envelope to the peer. It contains no secret key material.
    encrypted_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    return handle.key_id


def decrypt_image(kms: KmsClient, encrypted_path: Path, output_path: Path) -> None:
    envelope = json.loads(encrypted_path.read_text(encoding="utf-8"))
    handle = kms.fetch_key(envelope["key_id"], 32)
    # AES-GCM rejects modified ciphertext before any output file is written.
    image = AESGCM(handle.key).decrypt(
        base64.b64decode(envelope["nonce"], validate=True),
        base64.b64decode(envelope["ciphertext"], validate=True),
        envelope["key_id"].encode(),
    )
    output_path.write_bytes(image)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", nargs="?", type=Path,
                        default=Path(__file__).with_name("sample.png"))
    parser.add_argument("--output-dir", type=Path, default=Path("demo-output"))
    parser.add_argument("--force-simulator", action="store_true")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    encrypted = args.output_dir / "image.encrypted.json"
    decrypted = args.output_dir / "image.decrypted.png"
    if args.image.resolve() == decrypted.resolve():
        parser.error("Input image must be different from the decrypted output path")

    sender = create_client(SENDER_CONFIG, force_simulator=args.force_simulator)
    receiver = create_client(RECEIVER_CONFIG, force_simulator=args.force_simulator)
    key_id = encrypt_image(sender, args.image, encrypted)
    decrypt_image(receiver, encrypted, decrypted)
    if args.image.read_bytes() != decrypted.read_bytes():
        raise RuntimeError("Decrypted PNG differs from the original")
    print("Key ID:", key_id)
    print("Original PNG:", args.image)
    print("Encrypted envelope:", encrypted)
    print("Decrypted PNG:", decrypted)
    print("Verified: decrypted PNG matches the original byte for byte.")


if __name__ == "__main__":
    main()
