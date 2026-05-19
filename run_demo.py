"""
run_demo.py
===========
Master demo script — runs everything end to end.

Produces:
  outputs/certificate_original.pdf   ← the real certificate
  outputs/certificate_tampered.pdf   ← a forged one (grade changed)
  outputs/seal_comparison.png        ← side-by-side seal diff (the money shot)
"""

import os, sys
sys.path.insert(0, os.path.dirname(__file__))

from seal_engine import generate_seal, get_hash_label
from cert_generator import generate_certificate
from PIL import Image, ImageDraw, ImageFont

OUT = os.path.join(os.path.dirname(__file__), "outputs")
os.makedirs(OUT, exist_ok=True)

# ── Certificate fields ────────────────────────────────────────────────────────
original_fields = {
    "recipient":  "Arjun Sharma",
    "course":     "Machine Learning Fundamentals",
    "grade":      "A+",
    "issued_by":  "Chennai Institute of Technology",
    "date":       "2026-05-12",
    "subtitle":   "Certificate of Completion",
}

# Attacker changes grade from A+ to B-
tampered_fields = {**original_fields, "grade": "B-"}

print("=" * 55)
print("  Tamper-Evident Certificate System — Demo")
print("=" * 55)

# ── Step 1: Print hashes ──────────────────────────────────────────────────────
h_orig = get_hash_label(original_fields)
h_tamp = get_hash_label(tampered_fields)

print(f"\n[1] Hashing fields...")
print(f"    Original hash : {h_orig}")
print(f"    Tampered hash : {h_tamp}")
print(f"    Match?        : {'YES ✓' if h_orig == h_tamp else 'NO ✗ — seals will look different!'}")

# ── Step 2: Generate PDFs ─────────────────────────────────────────────────────
print(f"\n[2] Generating certificates...")
orig_pdf = os.path.join(OUT, "certificate_original.pdf")
tamp_pdf = os.path.join(OUT, "certificate_tampered.pdf")

generate_certificate(original_fields, orig_pdf)
generate_certificate(tampered_fields, tamp_pdf)

# ── Step 3: Side-by-side seal comparison image ────────────────────────────────
print(f"\n[3] Building seal comparison image...")

SEAL_PX  = 420
PAD      = 40
LABEL_H  = 80
TOTAL_W  = SEAL_PX * 2 + PAD * 3
TOTAL_H  = SEAL_PX + LABEL_H + PAD * 2

comparison = Image.new("RGB", (TOTAL_W, TOTAL_H), (245, 247, 250))
draw = ImageDraw.Draw(comparison)

# Title bar
draw.rectangle([0, 0, TOTAL_W, 52], fill=(26, 46, 74))
draw.text((TOTAL_W // 2, 26), "Tamper-Evident Seal — Visual Comparison",
          fill=(201, 168, 76), anchor="mm")

# Generate both seals
seal_orig = generate_seal(original_fields, size=SEAL_PX)
seal_tamp = generate_seal(tampered_fields, size=SEAL_PX)

# Paste seals
x1 = PAD
x2 = PAD * 2 + SEAL_PX
y  = 52 + PAD

comparison.paste(seal_orig, (x1, y), seal_orig)
comparison.paste(seal_tamp, (x2, y), seal_tamp)

# Labels
label_y = y + SEAL_PX + 14

def centre_text(draw, x, w, y, text, fill, size=15):
    # Simple manual centring using textlength approximation
    approx_w = len(text) * size * 0.55
    draw.text((x + w // 2 - approx_w // 2, y), text, fill=fill)

# Original label
draw.rectangle([x1, label_y, x1 + SEAL_PX, label_y + 60], fill=(230, 249, 240))
draw.rectangle([x1, label_y, x1 + SEAL_PX, label_y + 60],
               outline=(39, 174, 96), width=2)
centre_text(draw, x1, SEAL_PX, label_y + 8,  "✓ ORIGINAL",         (39, 174, 96), 15)
centre_text(draw, x1, SEAL_PX, label_y + 28, f'Grade: A+',          (30, 80, 50),  12)
centre_text(draw, x1, SEAL_PX, label_y + 46, f'ID: {h_orig}',       (100, 130, 100), 10)

# Tampered label
draw.rectangle([x2, label_y, x2 + SEAL_PX, label_y + 60], fill=(254, 240, 240))
draw.rectangle([x2, label_y, x2 + SEAL_PX, label_y + 60],
               outline=(231, 76, 60), width=2)
centre_text(draw, x2, SEAL_PX, label_y + 8,  "✗ TAMPERED (grade→B-)", (231, 76, 60), 13)
centre_text(draw, x2, SEAL_PX, label_y + 28, f'Grade: B-',             (130, 30, 30), 12)
centre_text(draw, x2, SEAL_PX, label_y + 46, f'ID: {h_tamp}',          (160, 100, 100), 10)

comparison.save(os.path.join(OUT, "seal_comparison.png"))

print(f"\n{'='*55}")
print(f"  Done! Files saved to outputs/")
print(f"  certificate_original.pdf  ← authentic cert")
print(f"  certificate_tampered.pdf  ← forged cert")
print(f"  seal_comparison.png       ← visual proof of tamper detection")
print(f"{'='*55}\n")
