"""Minimal key-consumption example. Run: python examples/fetch_key.py"""

from qkd_kms import create_client

CONFIG = """
{
  "backend": "simulator",
  "host": "127.0.0.1",
  "port": 9000,
  "local_sae_id": "SAE_002"
}
"""


def main():
    kms = create_client(CONFIG)
    key = kms.allocate_key(32)  # 256 bits
    # Print key material only for learning; avoid logging keys in a real app.
    print("Key ID:", key.key_id)
    print("Binary:", " ".join(f"{byte:08b}" for byte in key.key))
    print("Hex:", key.key.hex())


if __name__ == "__main__":
    main()
