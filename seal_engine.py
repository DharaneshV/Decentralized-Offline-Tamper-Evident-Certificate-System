"""
seal_engine.py  --  Core visual hash + ECDSA signature engine
==============================================================
Takes certificate fields -> SHA-256 hash -> ECDSA P-256 signature
-> unique geometric seal + security texture.

TRUST MODEL:
  The institution holds a private ECDSA key. At issuance, all fields
  are canonicalized (pipe-delimited, fixed order), hashed with SHA-256,
  and signed with the private key. The 64-byte raw signature (r||s)
  drives every visual property of the seal and security texture.

  At verification: the verifier (verifier.html, 100% client-side) uses
  the embedded public key and crypto.subtle.verify() to check the
  signature. This is cryptographically impossible to forge without the
  private key.

  The visual security texture (micro-dots, guilloche, field tints) is
  a deterrent and quick-glance check -- the ECDSA signature verified
  in verifier.html is the actual cryptographic guarantee.

CANONICALIZATION:
  Fields are joined by '|' in a fixed alphabetical order (FIELD_ORDER).
  No JSON involved -- this avoids cross-platform serialization mismatches
  between Python's json.dumps() and JavaScript's JSON.stringify().
  The '|' character is forbidden in field values (validated at signing).
"""

import hashlib
import json
import math
import colorsys
import base64
import os

from PIL import Image, ImageDraw

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives import hashes, serialization


# ── Canonical field ordering (alphabetical, fixed) ────────────────────────────
FIELD_ORDER = ["course", "date", "grade", "issued_by", "recipient", "subtitle"]


def canonical_string(fields: dict) -> str:
    """
    Produce a stable canonical string from cert fields.

    Format: pipe-delimited values in fixed FIELD_ORDER.
    Example: "Machine Learning Fundamentals|2026-05-12|A+|CIT|Arjun|Certificate of Completion"

    This exact format must be implemented identically in verifier.html (JavaScript).
    No JSON involved -- avoids cross-platform serialization mismatches.
    """
    return "|".join(fields.get(k, "") for k in FIELD_ORDER)


def validate_fields(fields: dict):
    """
    Validate field values before signing.
    Raises ValueError if any value contains the pipe delimiter.
    """
    for key in FIELD_ORDER:
        val = fields.get(key, "")
        if "|" in val:
            raise ValueError(
                f"Field '{key}' contains the pipe character '|', which is "
                f"forbidden (used as the canonical delimiter). Value: {val!r}"
            )


def sha256_digest(fields: dict) -> bytes:
    """Return 32-byte SHA-256 digest of the canonical field string."""
    return hashlib.sha256(canonical_string(fields).encode("utf-8")).digest()


def get_cert_id(fields: dict) -> str:
    """Return first 16 hex chars of digest -- used as the Certificate ID on the cert."""
    return sha256_digest(fields).hex()[:16].upper()


get_hash_label = get_cert_id


# ── ECDSA P-256 Signing & Verification ────────────────────────────────────────

def load_private_key(pem_path: str):
    """Load an ECDSA private key from a PEM file."""
    with open(pem_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(pem_path: str):
    """Load an ECDSA public key from a PEM file."""
    with open(pem_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def get_public_key_jwk(private_key) -> dict:
    """Export the public key component as a JWK dict (for embedding in verifier.html)."""
    pub = private_key.public_key()
    pub_numbers = pub.public_numbers()

    def _int_to_b64url(n: int, length: int) -> str:
        raw = n.to_bytes(length, byteorder="big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _int_to_b64url(pub_numbers.x, 32),
        "y": _int_to_b64url(pub_numbers.y, 32),
    }


def sign_fields(fields: dict, private_key) -> bytes:
    """
    Sign certificate fields with ECDSA P-256.

    1. Validate fields (no pipe characters)
    2. Canonicalize -> SHA-256 (done internally by ECDSA signer)
    3. Sign with private key (produces DER-encoded signature)
    4. Convert DER -> raw r||s format (64 bytes)

    The raw format is what gets embedded in the PDF and what
    crypto.subtle.verify() expects in the browser.

    Returns: 64 bytes (r: 32 bytes big-endian || s: 32 bytes big-endian)
    """
    validate_fields(fields)
    canonical_bytes = canonical_string(fields).encode("utf-8")

    # Python's .sign() returns DER-encoded (ASN.1) signature
    der_sig = private_key.sign(canonical_bytes, ec.ECDSA(hashes.SHA256()))

    # Convert to raw r||s (64 bytes) -- this is what crypto.subtle.verify() expects
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    return raw_sig


def verify_signature(fields: dict, raw_sig: bytes, public_key) -> bool:
    """
    Verify an ECDSA P-256 signature against certificate fields.

    Converts raw r||s (64 bytes) back to DER format for Python's verify().

    Returns: True if signature is valid, False otherwise.
    """
    try:
        canonical_bytes = canonical_string(fields).encode("utf-8")

        # Convert raw r||s back to DER
        r = int.from_bytes(raw_sig[:32], "big")
        s = int.from_bytes(raw_sig[32:], "big")
        der_sig = encode_dss_signature(r, s)

        public_key.verify(der_sig, canonical_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def signature_to_base64(raw_sig: bytes) -> str:
    """Encode raw 64-byte signature as base64 string for PDF metadata embedding."""
    return base64.b64encode(raw_sig).decode("ascii")


def signature_from_base64(b64_str: str) -> bytes:
    """Decode base64 string back to raw 64-byte signature."""
    return base64.b64decode(b64_str)


# ── Key auto-generation helper ────────────────────────────────────────────────

def ensure_keypair(keys_dir: str = None):
    """
    Ensure a keypair exists. If not, generate one automatically.
    Returns (private_key, public_key_jwk, private_key_path).
    """
    if keys_dir is None:
        keys_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
    os.makedirs(keys_dir, exist_ok=True)

    pem_path = os.path.join(keys_dir, "private_key.pem")

    if os.path.exists(pem_path):
        pk = load_private_key(pem_path)
        jwk = get_public_key_jwk(pk)
        return pk, jwk, pem_path

    # Auto-generate
    print("[*] No keypair found. Generating ECDSA P-256 keypair...")
    pk = ec.generate_private_key(ec.SECP256R1())
    pem_bytes = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(pem_path, "wb") as f:
        f.write(pem_bytes)

    jwk = get_public_key_jwk(pk)
    print(f"[*] Private key saved -> {pem_path}")
    print(f"[*] Public key JWK: {json.dumps(jwk)}")

    return pk, jwk, pem_path


# ── Visual Seal Generation ───────────────────────────────────────────────────

def _hsl(h: float, s: float, l: float) -> tuple:
    r, g, b = colorsys.hls_to_rgb(h, l, s)
    return (int(r * 255), int(g * 255), int(b * 255))


def generate_seal(fields: dict, size: int = 400) -> Image.Image:
    """
    Generate a square RGBA seal image from certificate fields.

    Every visual property is deterministically derived from the SHA-256
    hash of the fields. Same fields -> always the same seal.
    Change any field -> completely different seal.

    Parameters
    ----------
    fields : dict   Certificate key-value pairs
    size   : int    Pixel size of the square output image

    Returns
    -------
    PIL.Image.Image  RGBA (transparent background)
    """
    d = sha256_digest(fields)   # 32 bytes
    cx = cy = size // 2
    R  = size // 2 - 6

    # -- Decode visual parameters from hash bytes --
    bg_col       = _hsl(d[0]/255,        0.30, 0.93)
    primary_col  = _hsl(d[3]/255,        0.75, 0.42)
    secondary_col= _hsl((d[3]+128)%256/255, 0.60, 0.55)
    accent_col   = _hsl(d[5]/255,        0.85, 0.32)
    ring3_col    = _hsl(d[20]/255,       0.55, 0.58)
    border_col   = _hsl(d[22]/255,       0.65, 0.28)

    n_petals     = 4  + (d[6]  % 9)
    n_petals2    = 5  + (d[11] % 8)
    spoke_count  = 3  + (d[10] % 6)
    star_points  = 3  + (d[21] % 6)
    outer_scale  = 0.52 + (d[9] /255)*0.18
    inner_scale  = 0.24 + (d[8] /255)*0.18
    rot1         = d[7] /255 * math.pi
    rot2         = d[12]/255 * math.pi
    dot_bits     = int.from_bytes(d[16:20], "big")

    # -- Draw --
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Background disc
    draw.ellipse([4, 4, size-4, size-4], fill=bg_col+(255,))

    # Helper: draw a ring of filled circles (petals)
    def petal_ring(count, radius, col, alpha, rotation):
        for i in range(count):
            angle = (2*math.pi*i/count) + rotation
            px = cx + radius*math.cos(angle)
            py = cy + radius*math.sin(angle)
            pr = radius * 0.26
            draw.ellipse([px-pr, py-pr, px+pr, py+pr], fill=col+(alpha,))

    petal_ring(n_petals,  R*outer_scale,        primary_col,   210, rot1)
    petal_ring(n_petals2, R*(outer_scale-0.14),  secondary_col, 180, rot2+0.3)

    # Spokes (radial lines from centre)
    for i in range(spoke_count):
        angle = (2*math.pi*i/spoke_count) + (d[12]/255)
        x2 = cx + R*0.70*math.cos(angle)
        y2 = cy + R*0.70*math.sin(angle)
        draw.line([cx, cy, x2, y2], fill=primary_col+(70,), width=max(1, size//90))

    # Inner star polygon
    def star_pts(cx, cy, r_out, r_in, n):
        pts = []
        for i in range(n*2):
            a = (math.pi*i/n) - math.pi/2
            r = r_out if i%2==0 else r_in
            pts.append((cx+r*math.cos(a), cy+r*math.sin(a)))
        return pts

    draw.polygon(star_pts(cx, cy, R*inner_scale*1.4, R*inner_scale*0.55, star_points),
                 fill=ring3_col+(225,))

    # Outer dot ring (32 dots, on/off from hash bits)
    dot_radius = R * 0.84
    dot_r = max(2, size//68)
    for bit in range(32):
        if dot_bits & (1 << bit):
            angle = (2*math.pi*bit/32)
            dx = cx + dot_radius*math.cos(angle)
            dy = cy + dot_radius*math.sin(angle)
            draw.ellipse([dx-dot_r, dy-dot_r, dx+dot_r, dy+dot_r],
                         fill=accent_col+(195,))

    # Centre dot
    cr = R*0.11
    draw.ellipse([cx-cr, cy-cr, cx+cr, cy+cr], fill=accent_col+(255,))

    # Border ring
    bw = max(2, size//55)
    draw.ellipse([4, 4, size-4, size-4],
                 outline=border_col+(185,), width=bw)

    # Inner border ring (double ring effect)
    draw.ellipse([4+bw+3, 4+bw+3, size-4-bw-3, size-4-bw-3],
                 outline=border_col+(80,), width=1)

    return img


# ── Unified Security Texture Generation ───────────────────────────────────────

def generate_security_texture(sig_bytes: bytes, width: int, height: int) -> Image.Image:
    """
    Generate a unified security texture overlay from ECDSA signature bytes.

    One function produces all visual security elements from slices of the
    64-byte raw signature:
      Bytes  0-15: Micro-dot grid (positions, colors, sizes)
      Bytes 16-31: Guilloche wave parameters (freq, amplitude, phase)
      Bytes 32-47: Field zone tint values
      Bytes 48-63: Border pattern / dot ring seeds

    The texture is a deterrent and quick-glance check -- not a cryptographic
    guarantee. Modern PDF editors can modify content without destroying
    background elements. The real protection is the ECDSA signature.

    Parameters
    ----------
    sig_bytes : bytes   64-byte raw ECDSA signature (r||s)
    width     : int     Page width in pixels
    height    : int     Page height in pixels

    Returns
    -------
    PIL.Image.Image  RGBA overlay (mostly transparent)
    """
    img = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Ensure we have 64 bytes to work with (pad if needed)
    sig = sig_bytes[:64] if len(sig_bytes) >= 64 else sig_bytes + b'\x00' * (64 - len(sig_bytes))

    # ── Region 1: Micro-dot integrity grid (bytes 0-15) ──────────────────
    # Tiny colored dots scattered across the page in a deterministic pattern
    dot_bytes = sig[0:16]
    grid_cols = 12 + (dot_bytes[0] % 8)   # 12-19 columns
    grid_rows = 16 + (dot_bytes[1] % 8)   # 16-23 rows
    cell_w = width / grid_cols
    cell_h = height / grid_rows

    for row in range(grid_rows):
        for col in range(grid_cols):
            byte_idx = (row * grid_cols + col) % 16
            b = dot_bytes[byte_idx]

            # Position offset within cell (deterministic jitter)
            jx = (b * 7 + col * 13) % int(cell_w * 0.6)
            jy = (b * 11 + row * 17) % int(cell_h * 0.6)
            x = int(col * cell_w + cell_w * 0.2 + jx)
            y = int(row * cell_h + cell_h * 0.2 + jy)

            # Color from signature byte (very subtle, low alpha)
            hue = (b * 3 + col + row) % 360
            r, g, bl = colorsys.hls_to_rgb(hue / 360, 0.75, 0.25)
            color = (int(r * 255), int(g * 255), int(bl * 255), 12)  # very low alpha

            dot_size = 1 + (b % 2)
            draw.ellipse([x - dot_size, y - dot_size, x + dot_size, y + dot_size],
                         fill=color)

    # ── Region 2: Guilloche security waves (bytes 16-31) ─────────────────
    wave_bytes = sig[16:32]
    n_waves = 3 + (wave_bytes[0] % 4)  # 3-6 wave layers

    for wave_idx in range(n_waves):
        bi = wave_idx * 4
        freq   = 0.008 + (wave_bytes[bi % 16] / 255) * 0.025
        amp    = 6 + (wave_bytes[(bi + 1) % 16] / 255) * 14
        phase  = (wave_bytes[(bi + 2) % 16] / 255) * math.pi * 2
        y_base = height * (0.12 + wave_idx * 0.18)

        hue = wave_bytes[(bi + 3) % 16] / 255
        r, g, b = colorsys.hls_to_rgb(hue, 0.80, 0.20)
        color = (int(r * 255), int(g * 255), int(b * 255), 18)

        # Draw wave as connected line segments
        points = []
        for x in range(0, width + 3, 3):
            y = y_base + amp * math.sin(x * freq + phase)
            y += amp * 0.4 * math.sin(x * freq * 2.7 + phase * 1.3)
            points.append((x, int(y)))

        if len(points) >= 2:
            draw.line(points, fill=color, width=1)

        # Mirror wave at bottom
        points_bottom = []
        y_mirror = height - y_base
        for x in range(0, width + 3, 3):
            y = y_mirror + amp * math.sin(x * freq + phase + math.pi)
            y += amp * 0.4 * math.sin(x * freq * 2.7 + phase * 1.3 + math.pi)
            points_bottom.append((x, int(y)))

        if len(points_bottom) >= 2:
            draw.line(points_bottom, fill=color, width=1)

    # ── Region 3: Border pattern accents (bytes 48-63) ───────────────────
    border_bytes = sig[48:64]
    n_accents = 8 + (border_bytes[0] % 8)
    margin = min(width, height) * 0.04

    for i in range(n_accents):
        b = border_bytes[i % 16]
        side = i % 4  # 0=top, 1=right, 2=bottom, 3=left
        pos_frac = (b * 7 + i * 31) % 256 / 256

        if side == 0:
            x = int(pos_frac * width)
            y = int(margin)
        elif side == 1:
            x = int(width - margin)
            y = int(pos_frac * height)
        elif side == 2:
            x = int(pos_frac * width)
            y = int(height - margin)
        else:
            x = int(margin)
            y = int(pos_frac * height)

        hue = b / 255
        r, g, bl = colorsys.hls_to_rgb(hue, 0.70, 0.30)
        color = (int(r * 255), int(g * 255), int(bl * 255), 20)
        size = 2 + (b % 3)
        draw.ellipse([x - size, y - size, x + size, y + size], fill=color)

    return img


def get_field_tints(sig_bytes: bytes) -> dict:
    """
    Compute subtle background tint colors for each field zone.

    Uses bytes 32-47 of the signature to derive per-field HSL tints.
    These are rendered as very faint colored rectangles behind each
    text field on the certificate.

    Parameters
    ----------
    sig_bytes : bytes   64-byte raw ECDSA signature

    Returns
    -------
    dict  {field_name: (R, G, B, A)} for each field in FIELD_ORDER
    """
    sig = sig_bytes[:64] if len(sig_bytes) >= 64 else sig_bytes + b'\x00' * (64 - len(sig_bytes))
    tint_bytes = sig[32:48]

    tints = {}
    for i, field_name in enumerate(FIELD_ORDER):
        b1 = tint_bytes[i * 2 % 16]
        b2 = tint_bytes[(i * 2 + 1) % 16]
        hue = b1 / 255
        sat = 0.15 + (b2 / 255) * 0.15  # 0.15-0.30 (very subtle)
        r, g, b = colorsys.hls_to_rgb(hue, 0.95, sat)  # very light
        tints[field_name] = (int(r * 255), int(g * 255), int(b * 255), 8)

    return tints
