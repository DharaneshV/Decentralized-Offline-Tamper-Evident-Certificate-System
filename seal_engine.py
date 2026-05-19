"""
seal_engine.py  —  Core visual hash engine
============================================
Takes certificate fields → SHA-256 hash → unique geometric seal image.

HOW TAMPER DETECTION WORKS:
  SHA-256 is an avalanche hash. Change ONE character in ANY field
  and ALL 32 output bytes change completely. Every visual property
  of the seal (colours, shapes, petal count, dot ring, star shape)
  is driven by those bytes — so the seal looks ENTIRELY DIFFERENT.

  On a printed certificate: the human compares the printed seal
  with the seal regenerated from the text they can read on the cert.
  If they don't match → tampered.

  On a digital PDF: our self-verifying PDF runs JavaScript that
  reads the visible text fields, regenerates the expected seal hash,
  and overlays a big red TAMPERED watermark if anything has changed.
"""

import hashlib
import json
import math
import colorsys
from PIL import Image, ImageDraw


def canonical_string(fields: dict) -> str:
    """
    Produce a stable canonical string from cert fields.
    sort_keys=True ensures field order never matters.
    ensure_ascii=True avoids encoding ambiguity.
    """
    return json.dumps(fields, sort_keys=True, ensure_ascii=True)


def sha256_digest(fields: dict) -> bytes:
    """Return 32-byte SHA-256 digest of the canonical field string."""
    return hashlib.sha256(canonical_string(fields).encode("utf-8")).digest()


def get_cert_id(fields: dict) -> str:
    """Return first 16 hex chars of digest — used as the Certificate ID on the cert."""
    return sha256_digest(fields).hex()[:16].upper()


get_hash_label = get_cert_id


def _hsl(h: float, s: float, l: float) -> tuple:
    r, g, b = colorsys.hls_to_rgb(h, l, s)
    return (int(r * 255), int(g * 255), int(b * 255))


def generate_seal(fields: dict, size: int = 400) -> Image.Image:
    """
    Generate a square RGBA seal image from certificate fields.

    Every visual property is deterministically derived from the SHA-256
    hash of the fields. Same fields → always the same seal.
    Change any field → completely different seal.

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

    # ── Decode visual parameters from hash bytes ──────────────────────────
    # Each byte controls an independent visual property
    bg_col       = _hsl(d[0]/255,        0.30, 0.93)   # very light background
    primary_col  = _hsl(d[3]/255,        0.75, 0.42)   # vivid primary colour
    secondary_col= _hsl((d[3]+128)%256/255, 0.60, 0.55)# complementary colour
    accent_col   = _hsl(d[5]/255,        0.85, 0.32)   # dark accent
    ring3_col    = _hsl(d[20]/255,       0.55, 0.58)   # inner star colour
    border_col   = _hsl(d[22]/255,       0.65, 0.28)   # outer border

    n_petals     = 4  + (d[6]  % 9)         # 4..12  outer petals
    n_petals2    = 5  + (d[11] % 8)         # 5..12  inner petals
    spoke_count  = 3  + (d[10] % 6)         # 3..8   spokes
    star_points  = 3  + (d[21] % 6)         # 3..8   star arms
    outer_scale  = 0.52 + (d[9] /255)*0.18  # 0.52..0.70 petal ring radius
    inner_scale  = 0.24 + (d[8] /255)*0.18  # 0.24..0.42 inner radius
    rot1         = d[7] /255 * math.pi      # petal ring rotation
    rot2         = d[12]/255 * math.pi      # spoke rotation
    dot_bits     = int.from_bytes(d[16:20], "big")  # 32 bits → dot ring on/off

    # ── Draw ─────────────────────────────────────────────────────────────
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
