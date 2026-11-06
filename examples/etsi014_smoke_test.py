"""Check key allocation, peer retrieval, and status on the lab KMS pair."""

import base64
from pathlib import Path

from etsi_qkd_014_client import QKD014Client

ALICE_KMS_HOST = "10.161.10.240"
BOB_KMS_HOST = "10.161.10.230"
SAE_ID_ALICE = "SAE_002"
SAE_ID_BOB = "SAE_001"

CERTS = Path(__file__).resolve().parents[1] / "certs_out"
CLIENT_CERT = str(CERTS / "qkd_client.cert")
CLIENT_KEY = str(CERTS / "qkd_client.key")
ROOT_CA_CERT = str(CERTS / "root_ca.cert")


def main():
    alice = QKD014Client(
        ALICE_KMS_HOST, CLIENT_CERT, CLIENT_KEY, ROOT_CA_CERT, force_insecure=False
    )
    bob = QKD014Client(
        BOB_KMS_HOST, CLIENT_CERT, CLIENT_KEY, ROOT_CA_CERT, force_insecure=False
    )

    code, data = alice.get_key(SAE_ID_BOB, number=1, size=256)
    if code != 200:
        raise SystemExit(f"Alice key allocation failed (HTTP {code}): {data}")
    alice_key = data.keys[0]
    alice_bytes = base64.b64decode(alice_key.key, validate=True)

    code, data = bob.get_key_with_key_IDs(SAE_ID_ALICE, [alice_key.key_id])
    if code != 200:
        raise SystemExit(f"Bob key retrieval failed (HTTP {code}): {data}")
    bob_key = data.keys[0]
    bob_bytes = base64.b64decode(bob_key.key, validate=True)

    print(f"Alice key_id={alice_key.key_id}, {len(alice_bytes)} bytes")
    print(f"Bob   key_id={bob_key.key_id}, {len(bob_bytes)} bytes")
    print(f"Keys match: {alice_bytes == bob_bytes}")
    if alice_key.key_id != bob_key.key_id or len(alice_bytes) != 32 or alice_bytes != bob_bytes:
        raise SystemExit("Expected matching 256-bit keys with the same key ID")

    code, status = alice.get_status(SAE_ID_BOB)
    if code != 200:
        raise SystemExit(f"Alice status request failed (HTTP {code}): {status}")
    print("Alice KMS status:", status)


if __name__ == "__main__":
    main()
