"""
Main entry point for the hybrid post‑quantum encryption demo.

This module defines a very small REST API using FastAPI.  The API
exposes two endpoints:

    * ``GET /`` – serves a static HTML page that contains a tiny user
      interface.  The UI allows you to type a message, pick a KEM
      algorithm (Kyber512, Kyber768 or Kyber1024) and then invoke
      encryption or decryption against the API.

    * ``POST /encrypt`` – accepts JSON containing a UTF‑8 string and
      optional overrides for the key encapsulation mechanism (KEM).
      It returns a JSON document with the base64‑encoded ciphertext,
      nonce, KEM ciphertext and the server’s public keys.  The client
      must retain this payload in order to decrypt it later.

    * ``POST /decrypt`` – accepts the JSON package returned from
      ``/encrypt`` and attempts to recover the plaintext.  It returns
      the decoded string on success.

All cryptographic operations (key generation, encapsulation and
decapsulation) are delegated to helper functions in
``crypto/openssl_utils.py``.  The AES‑GCM encryption is performed
locally using the ``cryptography`` package.  See the ``HybridCrypto``
class in ``crypto/encryptor.py`` for details.

Note: the application assumes that OpenSSL has been compiled with
support for liboqs and the OQS provider module installed under
``/usr/local/lib64/ossl-modules``.  When running inside Docker this is
handled by the provided Dockerfile.
"""

from pathlib import Path
import json
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .crypto.encryptor import HybridCrypto


app = FastAPI(title="Post‑Quantum Hybrid Encryption Demo")

# Load the default policy from disk.  The file should reside under
# ``policy/policy_pqc.json`` relative to this module.
_policy_path = Path(__file__).resolve().parent / "policy" / "policy_pqc.json"
try:
    with _policy_path.open("r", encoding="utf-8") as fh:
        _policy = json.load(fh)
except Exception as exc:
    # If the policy cannot be loaded the application will refuse to
    # start.  This is preferable to silently falling back to an
    # undefined configuration.
    raise RuntimeError(f"Could not load policy from {_policy_path}: {exc}")

_engine = HybridCrypto(_policy)


class EncryptRequest(BaseModel):
    """Input model for the /encrypt endpoint."""

    data: str
    kem: Optional[str] = None


class DecryptRequest(BaseModel):
    """Input model for the /decrypt endpoint."""

    package: dict


@app.get("/", response_class=HTMLResponse)
async def root() -> str:
    """Serve the static HTML page for the demo UI."""
    index_path = Path(__file__).resolve().parent / "static" / "index.html"
    return index_path.read_text(encoding="utf-8")


@app.post("/encrypt")
async def encrypt(req: EncryptRequest):
    """
    Encrypt a UTF‑8 message using the configured hybrid scheme.

    The request body must contain a ``data`` field with the plaintext
    string.  An optional ``kem`` field may override the algorithm in
    the default policy (e.g. ``Kyber512`` or ``Kyber1024``).  The
    response will include all values necessary for decryption.
    """
    try:
        overrides = {}
        # Only override the KEM if a value is provided.  The
        # ``HybridCrypto`` class will ignore ``None`` values.
        overrides["kem"] = req.kem
        result = _engine.encrypt(req.data.encode("utf-8"), override=overrides)
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/decrypt")
async def decrypt(req: DecryptRequest):
    """
    Recover a plaintext from a previously generated encryption package.

    The request body must contain a ``package`` field matching the
    structure returned by ``/encrypt``.  If decryption succeeds the
    plaintext string is returned in the ``plaintext`` field; otherwise
    an HTTP 500 error is raised.
    """
    try:
        plaintext, info = _engine.decrypt(req.package)
        return {"plaintext": plaintext.decode("utf-8", errors="replace"), **info}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# Mount static assets so that the browser can fetch the UI and any
# supporting resources (e.g. CSS, JS) directly.
_static_path = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=_static_path), name="static")