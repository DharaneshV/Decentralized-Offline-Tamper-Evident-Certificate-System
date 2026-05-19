"""
run.py  —  Generate tamper-evident certificates
================================================
Run this to produce:
  outputs/certificate_ORIGINAL.pdf     ← the real certificate
  outputs/certificate_TAMPERED.pdf     ← a forged copy (grade changed)

Then open verifier.html in any browser to verify either certificate.
"""

import os, sys
sys.path.insert(0, os.path.dirname(__file__))

from seal_engine import get_cert_id, sha256_digest
from cert_generator import generate_certificate

OUT = os.path.join(os.path.dirname(__file__), "outputs")
os.makedirs(OUT, exist_ok=True)


# ── Define the certificate fields ────────────────────────────────────────────
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
print("  Tamper-Evident Certificate System")
print("=" * 58)

# ── Step 1: Show what happens to the hash ────────────────────────────────────
h_orig = get_cert_id(original)
h_tamp = get_cert_id(tampered)

print(f"\n[1] Computing hashes...")
print(f"    Original  Cert ID : {h_orig}  ← printed on real cert")
print(f"    Tampered  Cert ID : {h_tamp}  ← completely different")
print(f"    Match?            : {'YES' if h_orig == h_tamp else 'NO — seals will look completely different'}")

# ── Step 2: Generate both PDFs ───────────────────────────────────────────────
print(f"\n[2] Generating certificates...")
orig_path = os.path.join(OUT, "certificate_ORIGINAL.pdf")
tamp_path = os.path.join(OUT, "certificate_TAMPERED.pdf")

generate_certificate(original, orig_path)
generate_certificate(tampered, tamp_path)

# ── Step 3: Print verification instructions ──────────────────────────────────
print(f"""
[3] How to verify tamper detection
    ─────────────────────────────────────────────────────
    A) Open verifier.html in any browser (no internet needed)
    
    B) Enter these fields for the ORIGINAL certificate:
         Recipient : Arjun Sharma
         Course    : Machine Learning Fundamentals
         Grade     : A+
         Issued By : Chennai Institute of Technology
         Date      : 2026-05-12
         Cert ID   : {h_orig}
       → You will see the seal and it will show VALID

    C) Now change Grade to "B-" (simulating tampering)
       → The seal immediately changes completely — different
         colours, different shape count, different dot pattern.
         The Cert ID also won't match → flagged as TAMPERED.
    
    D) The TAMPERED PDF has the same effect — the seal printed
       on it does NOT match what the verifier generates for
       the text on that certificate.

[4] Three layers of protection
    ─────────────────────────────────────────────────────
    Layer 1 — Visual Seal (works on paper + screen)
      Geometric pattern generated from SHA-256 of all fields.
      Change any field → seal looks completely different.

    Layer 2 — Certificate ID (works on paper + screen)
      First 16 hex chars of SHA-256. Quick numeric check.
      Change a field → completely different ID.

    Layer 3 — PDF Metadata hash (digital only)
      The SHA-256 is stored in PDF Author metadata.
      verifier.html can read this from a drag-dropped PDF (future).

Files saved:
  {orig_path}
  {tamp_path}
=""")
