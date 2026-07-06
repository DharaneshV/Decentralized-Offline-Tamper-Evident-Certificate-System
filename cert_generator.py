"""
cert_generator.py  --  ECDSA-signed tamper-evident PDF certificate builder
============================================================================

SIX layers of tamper detection:

LAYER 1 -- Visual Seal (works on paper + screen)
  A geometric seal is generated from SHA-256 of all field values.
  It is embedded on the certificate. Anyone can visually compare
  the seal against a regenerated one (at verifier.html or online).
  Change any text -> seal looks completely different.

LAYER 2 -- Embedded Certificate ID (works on paper + screen)
  The first 16 hex chars of the hash are printed as the Cert ID.
  If you change a field and the ID no longer matches -> tampered.

LAYER 3 -- ECDSA P-256 Digital Signature (the cryptographic guarantee)
  The institution signs the canonical field string with its private key.
  The verifier uses the embedded public key to verify the signature
  fully offline via crypto.subtle.verify(). Cryptographically impossible
  to forge without the private key.

LAYER 4 -- Security Texture (visual deterrent)
  Signature-derived micro-dots, guilloche waves, and field tints
  embedded in the certificate background. A deterrent and quick-glance
  check -- not a cryptographic guarantee (PDF editors may preserve
  background elements when modifying text).

LAYER 5 -- QR Code (convenience pointer)
  Contains cert_id|base64(signature) for quick lookup. NOT standalone
  verification -- you need the full field values for that. Useful for
  quickly opening verifier.html with a pre-filled cert ID.

LAYER 6 -- PDF Metadata Embedding
  The signature and canonical field data are stored in PDF metadata.
  verifier.html extracts these via pdf.js for automated verification.

CONSTRAINT: All text fields are drawn as real selectable text
  (drawString/drawCentredString), never outlined or converted to paths.
  This ensures pdf.js getTextContent() can extract them for
  cross-referencing with the embedded metadata.
"""

import io
import os
import json
import hashlib
import math
import base64

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfdoc

import qrcode

from seal_engine import (
    generate_seal, get_cert_id, sha256_digest, canonical_string,
    sign_fields, verify_signature, signature_to_base64,
    generate_security_texture, get_field_tints,
    load_private_key, ensure_keypair,
    FIELD_ORDER,
)


# -- Colour palette --
DARK_BLUE  = colors.HexColor("#1A2E4A")
GOLD       = colors.HexColor("#C9A84C")
LIGHT_GOLD = colors.HexColor("#F5EDD6")
MID_BLUE   = colors.HexColor("#2E5180")
MID_GREY   = colors.HexColor("#AAAAAA")
LIGHT_GREY = colors.HexColor("#F4F6F8")
WHITE      = colors.white


def _pil_to_reader(img):
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return ImageReader(buf)


def _generate_qr_image(data_str: str, box_size: int = 4) -> 'Image':
    """Generate a QR code image from a data string."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=2,
    )
    qr.add_data(data_str)
    qr.make(fit=True)
    return qr.make_image(fill_color="#1A2E4A", back_color="#F4F6F8").convert("RGBA")


def draw_security_texture_on_canvas(c, sig_bytes, W, H):
    """
    Draw the unified security texture directly on the ReportLab canvas.

    Uses the ECDSA signature bytes to deterministically generate:
    - Micro-dot integrity grid (bytes 0-15)
    - Guilloche security waves (bytes 16-31)
    - Border pattern accents (bytes 48-63)

    These are drawn as very subtle, nearly-invisible elements that add
    a professional security aesthetic (like currency).
    """
    import colorsys as cs

    sig = sig_bytes[:64] if len(sig_bytes) >= 64 else sig_bytes + b'\x00' * (64 - len(sig_bytes))

    c.saveState()

    # -- Guilloche security waves (bytes 16-31) --
    wave_bytes = sig[16:32]
    n_waves = 3 + (wave_bytes[0] % 4)

    for wave_idx in range(n_waves):
        bi = wave_idx * 4
        freq   = 0.008 + (wave_bytes[bi % 16] / 255) * 0.025
        amp    = 6 + (wave_bytes[(bi + 1) % 16] / 255) * 14
        phase  = (wave_bytes[(bi + 2) % 16] / 255) * math.pi * 2
        y_base = H * (0.12 + wave_idx * 0.18)

        hue = wave_bytes[(bi + 3) % 16] / 255
        r, g, b = cs.hls_to_rgb(hue, 0.82, 0.18)
        c.setStrokeColor(colors.Color(r, g, b, alpha=0.06))
        c.setLineWidth(0.4)

        # Top wave
        p = c.beginPath()
        started = False
        for x in range(0, int(W) + 3, 3):
            y = y_base + amp * math.sin(x * freq + phase)
            y += amp * 0.4 * math.sin(x * freq * 2.7 + phase * 1.3)
            if not started:
                p.moveTo(x, y)
                started = True
            else:
                p.lineTo(x, y)
        c.drawPath(p, fill=0, stroke=1)

        # Bottom mirror wave
        p = c.beginPath()
        y_mirror = H - y_base
        started = False
        for x in range(0, int(W) + 3, 3):
            y = y_mirror + amp * math.sin(x * freq + phase + math.pi)
            y += amp * 0.4 * math.sin(x * freq * 2.7 + phase * 1.3 + math.pi)
            if not started:
                p.moveTo(x, y)
                started = True
            else:
                p.lineTo(x, y)
        c.drawPath(p, fill=0, stroke=1)

    # -- Micro-dot grid (bytes 0-15) --
    dot_bytes = sig[0:16]
    grid_cols = 10 + (dot_bytes[0] % 6)
    grid_rows = 14 + (dot_bytes[1] % 6)
    cell_w = W / grid_cols
    cell_h = H / grid_rows

    for row in range(grid_rows):
        for col in range(grid_cols):
            byte_idx = (row * grid_cols + col) % 16
            b = dot_bytes[byte_idx]

            jx = (b * 7 + col * 13) % max(1, int(cell_w * 0.6))
            jy = (b * 11 + row * 17) % max(1, int(cell_h * 0.6))
            x = col * cell_w + cell_w * 0.2 + jx
            y = row * cell_h + cell_h * 0.2 + jy

            hue = (b * 3 + col + row) % 360
            r, g, bl = cs.hls_to_rgb(hue / 360, 0.78, 0.22)
            c.setFillColor(colors.Color(r, g, bl, alpha=0.04))

            dot_size = 0.4 + (b % 2) * 0.3
            c.circle(x, y, dot_size, fill=1, stroke=0)

    # -- Border pattern accents (bytes 48-63) --
    border_bytes = sig[48:64]
    n_accents = 8 + (border_bytes[0] % 8)
    margin = min(W, H) * 0.04

    for i in range(n_accents):
        b = border_bytes[i % 16]
        side = i % 4
        pos_frac = (b * 7 + i * 31) % 256 / 256

        if side == 0:
            x, y = pos_frac * W, H - margin
        elif side == 1:
            x, y = W - margin, pos_frac * H
        elif side == 2:
            x, y = pos_frac * W, margin
        else:
            x, y = margin, pos_frac * H

        hue = b / 255
        r, g, bl = cs.hls_to_rgb(hue, 0.72, 0.28)
        c.setFillColor(colors.Color(r, g, bl, alpha=0.06))
        size = 1.5 + (b % 3) * 0.5
        c.circle(x, y, size, fill=1, stroke=0)

    c.restoreState()


def draw_field_tint_zone(c, sig_bytes, x, y, w, h, field_name):
    """
    Draw a very subtle tinted background zone behind a field.

    The tint color is derived from the signature bytes, so each signed
    certificate has unique field zone colors.
    """
    tints = get_field_tints(sig_bytes)
    tint = tints.get(field_name, (240, 240, 245, 8))
    r, g, b, a = tint
    c.saveState()
    c.setFillColor(colors.Color(r/255, g/255, b/255, alpha=a/255))
    c.roundRect(x, y, w, h, radius=2, fill=1, stroke=0)
    c.restoreState()


def generate_certificate(fields: dict, output_path: str, private_key=None, private_key_path: str = None, override_signature: bytes = None):
    """
    Generate an ECDSA-signed tamper-evident PDF certificate.

    Required field keys:
        recipient, course, grade, issued_by, date

    Optional:
        subtitle  (defaults to "Certificate of Completion")

    Parameters
    ----------
    fields             : dict   Certificate key-value pairs
    output_path        : str    Path to save the PDF
    private_key        : key    Pre-loaded ECDSA private key (optional)
    private_key_path   : str    Path to PEM file (optional, used if private_key is None)
    override_signature : bytes  (TESTING ONLY) forcefully inject this signature instead of signing
    """
    # Ensure subtitle has a default
    if "subtitle" not in fields:
        fields["subtitle"] = "Certificate of Completion"

    # Load or auto-generate key
    if private_key is None:
        if private_key_path and os.path.exists(private_key_path):
            private_key = load_private_key(private_key_path)
        else:
            private_key, _, _ = ensure_keypair()

    # Sign the fields (or use override for testing forgery)
    if override_signature:
        raw_sig = override_signature
    else:
        raw_sig = sign_fields(fields, private_key)
        
    sig_b64 = signature_to_base64(raw_sig)

    W, H = A4
    cert_id     = get_cert_id(fields)
    canonical   = canonical_string(fields)
    c = canvas.Canvas(output_path, pagesize=A4)

    # -- Store signature and field data in PDF metadata --
    # Author:  CERT_SIG:<base64_raw_signature>
    # Subject: CERT_DATA:<pipe_delimited_canonical_string>
    c.setAuthor(f"CERT_SIG:{sig_b64}")
    c.setTitle(f"Certificate - {fields.get('recipient','')}")
    c.setSubject(f"CERT_DATA:{canonical}")

    # -- Background --
    c.setFillColor(LIGHT_GREY)
    c.rect(0, 0, W, H, fill=1, stroke=0)

    # -- Security Texture (signature-derived, Layer 4) --
    draw_security_texture_on_canvas(c, raw_sig, W, H)

    # Decorative corner accent blocks
    corner_size = 22*mm
    c.setFillColor(DARK_BLUE)
    for x, y in [(0,0),(W-corner_size,0),(0,H-corner_size),(W-corner_size,H-corner_size)]:
        c.rect(x, y, corner_size, corner_size, fill=1, stroke=0)

    # Outer border (double)
    margin = 16*mm
    c.setStrokeColor(DARK_BLUE)
    c.setLineWidth(2.5)
    c.rect(margin, margin, W-2*margin, H-2*margin, fill=0, stroke=1)
    c.setStrokeColor(GOLD)
    c.setLineWidth(0.8)
    off = 5
    c.rect(margin+off, margin+off, W-2*margin-2*off, H-2*margin-2*off, fill=0, stroke=1)

    # -- Header band --
    hdr_y = H - margin - 44*mm
    c.setFillColor(DARK_BLUE)
    c.rect(margin, hdr_y, W-2*margin, 38*mm, fill=1, stroke=0)

    # Gold rule inside header
    c.setStrokeColor(GOLD)
    c.setLineWidth(0.5)
    c.line(margin+18*mm, hdr_y+14*mm, W-margin-18*mm, hdr_y+14*mm)

    # Field tint zone for issued_by (header)
    draw_field_tint_zone(c, raw_sig,
                         margin+18*mm, hdr_y+22*mm,
                         W-2*margin-36*mm, 12*mm, "issued_by")

    c.setFillColor(GOLD)
    c.setFont("Helvetica-Bold", 17)
    c.drawCentredString(W/2, hdr_y+27*mm, fields.get("issued_by", "Institution Name"))

    c.setFillColor(LIGHT_GOLD)
    c.setFont("Helvetica", 10.5)
    c.drawCentredString(W/2, hdr_y+7*mm, fields.get("subtitle", "Certificate of Completion"))

    # -- Body text --
    body_top = hdr_y - 6*mm

    c.setFillColor(MID_GREY)
    c.setFont("Helvetica", 10.5)
    c.drawCentredString(W/2, body_top - 10*mm, "This is to certify that")

    # Field tint zone for recipient
    name_text = fields.get("recipient", "")
    name_w = c.stringWidth(name_text, "Helvetica-Bold", 28)
    draw_field_tint_zone(c, raw_sig,
                         W/2 - name_w/2 - 4, body_top - 30*mm,
                         name_w + 8, 16*mm, "recipient")

    # Recipient name (real selectable text - CONSTRAINT)
    c.setFont("Helvetica-Bold", 28)
    c.setFillColor(DARK_BLUE)
    c.drawCentredString(W/2, body_top - 26*mm, name_text)

    # Gold underline under name
    c.setStrokeColor(GOLD)
    c.setLineWidth(1.0)
    c.line(W/2-name_w/2, body_top-29*mm, W/2+name_w/2, body_top-29*mm)

    c.setFillColor(MID_GREY)
    c.setFont("Helvetica", 10.5)
    c.drawCentredString(W/2, body_top-38*mm, "has successfully completed")

    # Field tint zone for course
    course_text = fields.get("course", "")
    course_w = c.stringWidth(course_text, "Helvetica-Bold", 17)
    draw_field_tint_zone(c, raw_sig,
                         W/2 - course_w/2 - 4, body_top - 54*mm,
                         course_w + 8, 12*mm, "course")

    c.setFont("Helvetica-Bold", 17)
    c.setFillColor(MID_BLUE)
    c.drawCentredString(W/2, body_top-50*mm, course_text)

    c.setFont("Helvetica", 10.5)
    c.setFillColor(MID_GREY)
    c.drawCentredString(W/2, body_top-62*mm, "with a final grade of")

    # Field tint zone for grade
    grade_text = fields.get("grade", "")
    grade_w = c.stringWidth(grade_text, "Helvetica-Bold", 22)
    draw_field_tint_zone(c, raw_sig,
                         W/2 - grade_w/2 - 4, body_top - 78*mm,
                         grade_w + 8, 12*mm, "grade")

    c.setFont("Helvetica-Bold", 22)
    c.setFillColor(GOLD)
    c.drawCentredString(W/2, body_top-74*mm, grade_text)

    # -- Divider line --
    div_y = body_top - 86*mm
    c.setStrokeColor(MID_GREY)
    c.setLineWidth(0.4)
    c.line(margin+18*mm, div_y, W-margin-18*mm, div_y)

    # -- Footer row: date + issued_by labels --
    ft_y = div_y - 10*mm
    left_x  = margin + 20*mm
    right_x = W - margin - 20*mm

    c.setFont("Helvetica", 8.5)
    c.setFillColor(MID_GREY)
    c.drawString(left_x, ft_y,          "Issued by")
    c.drawRightString(right_x, ft_y,    "Date issued")

    c.setFont("Helvetica-Bold", 9)
    c.setFillColor(DARK_BLUE)
    c.drawString(left_x,     ft_y-5*mm, fields.get("issued_by", ""))
    c.drawRightString(right_x, ft_y-5*mm, fields.get("date", ""))

    # -- Seal --
    seal_pts  = 88
    seal_px   = 500
    seal_x    = left_x
    seal_y    = margin + 18*mm

    pil_seal = generate_seal(fields, size=seal_px)
    c.drawImage(_pil_to_reader(pil_seal),
                seal_x, seal_y, width=seal_pts, height=seal_pts, mask="auto")

    c.setFont("Helvetica", 7)
    c.setFillColor(MID_GREY)
    c.drawCentredString(seal_x + seal_pts/2, seal_y - 4*mm, "Tamper-Evident Seal")

    # -- Digital Signature indicator --
    c.setFont("Helvetica", 6)
    c.setFillColor(colors.HexColor("#6B8E23"))
    c.drawCentredString(seal_x + seal_pts/2, seal_y - 9*mm, "Digitally Signed - ECDSA P-256")

    # -- QR Code (Layer 5 - convenience pointer) --
    qr_data = f"{cert_id}|{sig_b64}"
    qr_img = _generate_qr_image(qr_data, box_size=6)
    qr_size = 22*mm
    qr_x = W/2 - qr_size/2
    qr_y = margin + 16*mm
    c.drawImage(_pil_to_reader(qr_img),
                qr_x, qr_y, width=qr_size, height=qr_size, mask="auto")

    c.setFont("Helvetica", 5.5)
    c.setFillColor(MID_GREY)
    c.drawCentredString(qr_x + qr_size/2, qr_y - 3*mm, "Scan for quick lookup")

    # -- Certificate ID --
    c.setFont("Helvetica", 7.5)
    c.setFillColor(MID_GREY)
    c.drawRightString(right_x, margin+26*mm, "Certificate ID")

    c.setFont("Courier-Bold", 9)
    c.setFillColor(DARK_BLUE)
    c.drawRightString(right_x, margin+20*mm, cert_id)

    # Verification note
    c.setFont("Helvetica", 6.5)
    c.setFillColor(MID_GREY)
    c.drawRightString(right_x, margin+13*mm,
        "Verify: open verifier.html and drop this PDF for instant offline check.")
    c.drawRightString(right_x, margin+8*mm,
        f"ECDSA P-256 signed. Cert ID = first 16 chars of SHA-256.")

    c.save()
    print(f"  Certificate saved -> {output_path}")
    print(f"  Certificate ID : {cert_id}")
    print(f"  ECDSA Signature: {sig_b64[:32]}...")
    print(f"  Canonical      : {canonical[:50]}...")
