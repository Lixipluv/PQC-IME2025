"""
High level hybrid encryption primitives for the PQC demo.
"""

from __future__ import annotations

import base64
import hmac
import hashlib
import os
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .openssl_utils import (
    ensure_server_keys,
    gen_client_ephemeral_x25519,
    kem_encapsulate,
    kem_decapsulate,
    ecdh_derive,
    KEYS,
)


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def hkdf_sha256(ikm: bytes, length: int = 32, salt: bytes | None = None, info: bytes = b"pqc-hybrid-demo") -> bytes:
    """
    Perform HKDF extract and expand using SHA‑256.
    ... (o resto da função) ...
    """
    if salt is None:
        salt = bytes([0] * hashlib.sha256().digest_size)
    # Step 1: extract
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    # Step 2: expand
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


class HybridCrypto:
    """Stateful helper for hybrid encryption and decryption."""

    def __init__(self, base_policy: Dict[str, str]):
        # The base policy defines the default KEM and symmetric cipher.
        self.base_policy = base_policy

    def _effective(self, override: Optional[Dict[str, str]]) -> Dict[str, str]:
        """Merge overrides into the base policy and return the result."""
        eff = dict(self.base_policy)
        if override:
            for key, value in override.items():
                if value is not None:
                    eff[key] = value
        return eff

    def encrypt(self, plaintext: bytes, override: Optional[Dict[str, str]] = None) -> Dict[str, object]:
        """
        Encrypt a plaintext and return a package suitable for transport/storage.
        ... (o resto do docstring) ...
        """
        policy = self._effective(override)
        kem_alg = policy.get("kem", "Kyber768")

        # Generate (or retrieve) the server’s persistent keys
        pqc_priv, pqc_pub, dh_priv_srv, dh_pub_srv = ensure_server_keys(kem_alg)

        # 1. Gerar chaves (retorna Paths)
        client_priv_path, client_pub_path = gen_client_ephemeral_x25519()

        # 2. Ler os bytes da chave pública (para o JSON de retorno)
        client_pub_bytes = client_pub_path.read_bytes()

        # 3. Perform KEM encapsulation (retorna kem_ct_bytes, kem_ss_bytes)
        kem_ct, kem_ss = kem_encapsulate(pqc_pub, kem_alg)

        # 4. Escrever os bytes da chave pública num arquivo temporário SEGURO
        tmp_client_pub_path = KEYS / "_client_pub_encrypt_tmp.pem"
        tmp_client_pub_path.write_bytes(client_pub_bytes)

        # 5. Derivar a chave ECDH (retorna ecdh_ss_bytes)
        ecdh_ss = ecdh_derive(dh_priv_srv, tmp_client_pub_path)
        
        # *** INÍCIO DA CORREÇÃO ***
        # 6. Concatenar os bytes do segredo (sem .read_bytes())
        key_material = kem_ss + ecdh_ss
        # *** FIM DA CORREÇÃO ***
        
        aes_key = hkdf_sha256(key_material, length=32)

        # Encrypt using AES‑GCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        ct = aesgcm.encrypt(nonce, plaintext, None)

        # Prepare the output package.
        result: Dict[str, object] = {
            "ciphertext": _b64e(ct),
            "nonce": _b64e(nonce),
            "kem_ciphertext": _b64e(kem_ct),
            "client_dh_pub_pem": _b64e(client_pub_bytes),
            "public_keys": {
                "pqc_pub_pem": _b64e(pqc_pub.read_bytes()),
                "dh_pub_pem": _b64e(dh_pub_srv.read_bytes()),
            },
            "meta": policy,
        }
        return result

    def decrypt(self, package: Dict[str, object]) -> Tuple[bytes, Dict[str, object]]:
        """
        Decrypt a package produced by ``encrypt`` and return the plaintext.
        ... (o resto do docstring) ...
        """
        policy = package.get("meta", self.base_policy)
        kem_alg = policy.get("kem", "Kyber768")

        # Base64 decode
        ct = _b64d(package["ciphertext"])
        nonce = _b64d(package["nonce"])
        kem_ct = _b64d(package["kem_ciphertext"])
        client_dh_pub_pem = _b64d(package["client_dh_pub_pem"])

        # Escrever a chave pública do cliente num arquivo temporário
        tmp_path = KEYS / "_client_pub_tmp.pem"
        tmp_path.write_bytes(client_dh_pub_pem)

        # Obter chaves do servidor
        pqc_priv, pqc_pub, dh_priv_srv, dh_pub_srv = ensure_server_keys(kem_alg)

        # Decapsular PQC (retorna kem_ss_bytes)
        kem_ss = kem_decapsulate(pqc_priv, kem_ct, kem_alg)

        # Derivar ECDH (retorna ecdh_ss_bytes)
        ecdh_ss = ecdh_derive(dh_priv_srv, tmp_path)

        # *** INÍCIO DA CORREÇÃO ***
        # Concatenar os bytes do segredo (sem .read_bytes())
        key_material = kem_ss + ecdh_ss
        # *** FIM DA CORREÇÃO ***
        
        aes_key = hkdf_sha256(key_material, length=32)

        # Decrypt; AESGCM will verify the authentication tag
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ct, None)

        return plaintext, {"ok": True, "provider": policy.get("provider", "oqsprovider"), "kem": kem_alg}