"""Encrypt and decrypt a small PNG with a one-time pad from the KMS.

Run: python examples/png_demo.py [path/to/image.png]
The bundled sample is used if no path is provided. Outputs go to demo-output/.
"""

import argparse
import base64
import json
from math import isqrt
from pathlib import Path
from struct import pack

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


def xor_bytes(data: bytes, pad: bytes) -> bytes:
    return bytes(value ^ pad_byte for value, pad_byte in zip(data, pad, strict=True))


def encrypt_image(kms: KmsClient, image_path: Path, encrypted_path: Path) -> str:
    image = image_path.read_bytes()
    if not image.startswith(PNG_SIGNATURE):
        raise ValueError("Input must be a PNG file")
    # A one-time pad uses one fresh key byte per byte of the file.
    handle = kms.allocate_key(len(image))
    ciphertext = xor_bytes(image, handle.key)
    envelope = {
        "key_id": handle.key_id,
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    # Send this envelope to the peer. It contains no secret key material.
    encrypted_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    return handle.key_id


def decrypt_image(kms: KmsClient, encrypted_path: Path, output_path: Path) -> None:
    envelope = json.loads(encrypted_path.read_text(encoding="utf-8"))
    ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    handle = kms.fetch_key(envelope["key_id"], len(ciphertext))
    # XOR with the same pad reverses encryption. A pad provides no integrity check.
    image = xor_bytes(ciphertext, handle.key)
    output_path.write_bytes(image)


def write_ciphertext_bitmap(ciphertext: bytes, output_path: Path) -> None:
    """Render each ciphertext byte as a grayscale pixel in a viewable BMP."""
    width = isqrt(len(ciphertext) - 1) + 1
    height = (len(ciphertext) + width - 1) // width
    row_size = (width * 3 + 3) & ~3  # BMP rows are padded to four bytes.
    pixels = bytearray()
    for start in range(0, len(ciphertext), width):
        row = ciphertext[start : start + width]
        # The three color channels have the same intensity for grayscale.
        rgb = b"".join(bytes([value]) * 3 for value in row)
        pixels.extend(rgb.ljust(row_size, b"\0"))

    pixel_offset = 14 + 40
    file_header = pack("<2sIHHI", b"BM", pixel_offset + len(pixels), 0, 0, pixel_offset)
    # A negative height stores rows from top to bottom.
    image_header = pack(
        "<IiiHHIIiiII", 40, width, -height, 1, 24, 0, len(pixels), 0, 0, 0, 0
    )
    output_path.write_bytes(file_header + image_header + pixels)


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
    bitmap = args.output_dir / "image.ciphertext.bmp"
    if args.image.resolve() in {path.resolve() for path in (encrypted, decrypted, bitmap)}:
        parser.error("Input image must be different from the output paths")

    sender = create_client(SENDER_CONFIG, force_simulator=args.force_simulator)
    receiver = create_client(RECEIVER_CONFIG, force_simulator=args.force_simulator)
    key_id = encrypt_image(sender, args.image, encrypted)
    decrypt_image(receiver, encrypted, decrypted)
    if args.image.read_bytes() != decrypted.read_bytes():
        raise RuntimeError("Decrypted PNG differs from the original")
    envelope = json.loads(encrypted.read_text(encoding="utf-8"))
    write_ciphertext_bitmap(base64.b64decode(envelope["ciphertext"], validate=True), bitmap)
    print("Key ID:", key_id)
    print("Original PNG:", args.image)
    print("Encrypted envelope:", encrypted)
    print("Ciphertext bitmap:", bitmap)
    print("Decrypted PNG:", decrypted)
    print("Verified: decrypted PNG matches the original byte for byte.")


if __name__ == "__main__":
    main()
