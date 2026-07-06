"""
run.py  --  Generate ECDSA-signed tamper-evident certificates
=============================================================
Run this to produce:
  outputs/certificate_ORIGINAL.pdf     <- the real, signed certificate
  outputs/certificate_TAMPERED.pdf     <- a forged copy (grade changed)

Then open verifier.html in any browser to verify either certificate.
"""

import os, sys
sys.path.insert(0, os.path.dirname(__file__))

from seal_engine import (
    get_cert_id, sha256_digest, sign_fields, verify_signature,
    signature_to_base64, ensure_keypair, canonical_string,
)
from cert_generator import generate_certificate

OUT = os.path.join(os.path.dirname(__file__), "outputs")
os.makedirs(OUT, exist_ok=True)


# -- Load or generate ECDSA keypair --
private_key, public_jwk, key_path = ensure_keypair()

# -- Define the certificate fields --
original = {
    "recipient":  "Arjun Sharma",
    "course":     "Machine Learning Fundamentals",
    "grade":      "A+",
    "issued_by":  "Chennai Institute of Technology",
    "date":       "2026-05-12",
    "subtitle":   "Certificate of Completion",
}

# Simulate attacker changing the grade
tampered = {**original, "grade": "B-"}

print()
print("=" * 58)
print("  ECDSA-Signed Tamper-Evident Certificate System")
print("=" * 58)

# -- Step 1: Show what happens to the hash and signature --
h_orig = get_cert_id(original)
h_tamp = get_cert_id(tampered)

sig_orig = sign_fields(original, private_key)
sig_tamp = sign_fields(tampered, private_key)

print(f"\n[1] Computing hashes and signatures...")
print(f"    Original Cert ID  : {h_orig}")
print(f"    Tampered Cert ID  : {h_tamp}")
print(f"    IDs match?        : {'YES' if h_orig == h_tamp else 'NO -- seals will look completely different'}")
print(f"\n    Original signature: {signature_to_base64(sig_orig)[:40]}...")
print(f"    Tampered signature: {signature_to_base64(sig_tamp)[:40]}...")
print(f"\n    Canonical (orig)  : {canonical_string(original)[:60]}...")

# -- Step 2: Verify signatures --
print(f"\n[2] Verifying signatures...")
v1 = verify_signature(original, sig_orig, private_key.public_key())
v2 = verify_signature(tampered, sig_orig, private_key.public_key())
v3 = verify_signature(tampered, sig_tamp, private_key.public_key())

print(f"    Original fields + original sig : {'VALID' if v1 else 'INVALID'}")
print(f"    Tampered fields + original sig : {'VALID' if v2 else 'INVALID (correctly detected!)'}")
print(f"    Tampered fields + tampered sig : {'VALID' if v3 else 'INVALID'}")

# -- Step 3: Generate both PDFs --
print(f"\n[3] Generating certificates...")
orig_path = os.path.join(OUT, "certificate_ORIGINAL.pdf")
tamp_path = os.path.join(OUT, "certificate_TAMPERED.pdf")

generate_certificate(original, orig_path, private_key=private_key)
generate_certificate(tampered, tamp_path, private_key=private_key, override_signature=sig_orig)

# -- Step 4: Print verification instructions --
print(f"""
[4] How to verify tamper detection
    --------------------------------------------------------
    A) Open verifier.html in any browser (no internet needed)
    
    B) Drag-drop certificate_ORIGINAL.pdf
       -> Should show: AUTHENTIC (green, valid ECDSA signature)

    C) Drag-drop certificate_TAMPERED.pdf
       -> Should show: TAMPERED (red overlay, field diff showing A+ -> B-)
       -> The ECDSA signature was made for grade=A+, but the PDF
          says grade=B-, so verification FAILS.

    D) Drop any random PDF without CERT_SIG metadata
       -> Should show: CANNOT VERIFY (amber, no signature found)

[5] Security model
    --------------------------------------------------------
    The ECDSA signature is the cryptographic guarantee.
    The visual seal, cert ID, and security texture are
    deterrents / quick-glance checks.

    Without the private key ({key_path}),
    nobody can forge a valid signature.

Files saved:
  {orig_path}
  {tamp_path}
=""")
