"""
generate_keys.py — One-time ECDSA P-256 keypair generator
==========================================================
Run once to create the institution's signing keypair.

  python keys/generate_keys.py

Output:
  keys/private_key.pem   ← SECRET. Never commit this. (.gitignore'd)
  Console prints the public key in JWK format for embedding in verifier.html
"""

import os
import json
import base64

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def _int_to_base64url(n: int, length: int) -> str:
    """Convert a big integer to base64url encoding (no padding)."""
    raw = n.to_bytes(length, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_keypair(output_dir: str = None):
    """Generate an ECDSA P-256 keypair and save/print results."""
    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(__file__))

    private_key = ec.generate_private_key(ec.SECP256R1())

    # ── Save private key PEM ──────────────────────────────────────────────
    pem_path = os.path.join(output_dir, "private_key.pem")
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(pem_path, "wb") as f:
        f.write(pem_bytes)

    # ── Export public key as JWK ──────────────────────────────────────────
    pub = private_key.public_key()
    pub_numbers = pub.public_numbers()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _int_to_base64url(pub_numbers.x, 32),
        "y": _int_to_base64url(pub_numbers.y, 32),
    }

    # ── Also save public key PEM for reference ────────────────────────────
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_path = os.path.join(output_dir, "public_key.pem")
    with open(pub_path, "wb") as f:
        f.write(pub_pem)

    # ── Print results ─────────────────────────────────────────────────────
    print("=" * 60)
    print("  ECDSA P-256 Keypair Generated")
    print("=" * 60)
    print(f"\n  Private key saved -> {pem_path}")
    print(f"  Public key saved  -> {pub_path}")
    print(f"\n  WARNING: NEVER commit private_key.pem to version control!")
    print(f"\n{'-' * 60}")
    print("  PUBLIC KEY (JWK) -- paste this into verifier.html:")
    print(f"{'-' * 60}")
    print(json.dumps(jwk, indent=2))
    print(f"{'-' * 60}\n")

    return pem_path, jwk


if __name__ == "__main__":
    generate_keypair()
