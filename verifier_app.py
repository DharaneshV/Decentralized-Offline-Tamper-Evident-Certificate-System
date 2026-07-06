"""
verifier_app.py  --  Optional issuer-side minting server
=========================================================
This is a CONVENIENCE tool for institutions to mint certificates
via a web form. It is NOT required for verification.

Verification is always done client-side in verifier.html using
crypto.subtle.verify() with the embedded public key -- no server needed.

Usage:
    python verifier_app.py
    Open http://localhost:5050 in your browser

The server:
  - Serves verifier.html at /  (which works standalone too)
  - Accepts POST /generate to mint and download signed PDFs
"""

import os
from flask import Flask, request, send_file
from cert_generator import generate_certificate
from seal_engine import ensure_keypair

app = Flask(__name__)

# Outputs directory for temporary certificate storage
OUT = os.path.join(os.path.dirname(__file__), "outputs")
os.makedirs(OUT, exist_ok=True)

# Load signing key at startup
_private_key, _public_jwk, _key_path = ensure_keypair()


@app.route("/", methods=["GET"])
def index():
    """Serve the standalone verifier.html dashboard directly from disk."""
    html_path = os.path.join(os.path.dirname(__file__), "verifier.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()


@app.route("/outputs/<path:filename>", methods=["GET"])
def serve_output(filename):
    """Serve certificate files from the outputs directory (for testing)."""
    return send_file(os.path.join(OUT, filename))


@app.route("/generate", methods=["POST"])
def generate():
    """
    Generate an ECDSA-signed tamper-evident PDF certificate and
    trigger a download attachment in the user's browser.
    """
    fields = {
        "recipient": request.form.get("recipient", "").strip(),
        "course":    request.form.get("course", "").strip(),
        "subtitle":  request.form.get("subtitle", "Certificate of Completion").strip(),
        "grade":     request.form.get("grade", "").strip(),
        "issued_by": request.form.get("issued_by", "").strip(),
        "date":      request.form.get("date", "").strip(),
    }

    # Basic validations
    if not all([fields["recipient"], fields["course"], fields["grade"], fields["issued_by"], fields["date"]]):
        return "<h3>Error: All form fields are required.</h3><a href='/'>Go Back</a>", 400

    # Validate no pipe characters in field values
    for key, val in fields.items():
        if "|" in val:
            return f"<h3>Error: Field '{key}' contains the pipe character '|', which is forbidden.</h3><a href='/'>Go Back</a>", 400

    # Format filename safely
    safe_name = "".join([c if c.isalnum() else "_" for c in fields["recipient"]])
    pdf_filename = f"certificate_{safe_name}.pdf"
    pdf_path = os.path.join(OUT, pdf_filename)

    try:
        generate_certificate(fields, pdf_path, private_key=_private_key)

        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=pdf_filename,
            mimetype="application/pdf"
        )
    except Exception as e:
        return f"<h3>Certificate Generation Failed:</h3><p>{e}</p><a href='/'>Go Back</a>", 500


if __name__ == "__main__":
    print("=" * 60)
    print("  ECDSA-Signed Certificate Minting Server (Issuer Only)")
    print("  Verification is always client-side -- no server needed.")
    print(f"  Running at: http://localhost:5050")
    print(f"  Signing key: {_key_path}")
    print("=" * 60)
    app.run(debug=True, port=5050)
