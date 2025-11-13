"""
Helpers for performing post‑quantum and classical key operations via
OpenSSL’s command line interface.

This module centralises all interactions with the OpenSSL binary and
the OQS provider.  It is responsible for generating and caching
server‑side keys, performing encapsulation/decapsulation using PQC
algorithms and deriving shared secrets using classical Diffie–Hellman
(X25519).  All operations are executed via subprocess calls to
OpenSSL; in the case of errors the stderr output is surfaced as part
of the exception for easier debugging.

Important notes:

  * The OpenSSL binary used is determined by the ``OPENSSL_BIN``
    environment variable if set, otherwise ``openssl`` on the PATH.
  * The provider search path is determined by the
    ``OPENSSL_MODULES`` environment variable.  At runtime this
    variable should point at a directory containing ``oqsprovider.so``.
  * Keys are stored in the ``keys`` directory relative to this
    module's grandparent (``app/app/keys`` when running inside Docker).

The functions in this module are intentionally low‑level: they know
nothing about HTTP requests or JSON structures.  They operate solely
on files and return bytes.  Higher level logic lives in
``crypto/encryptor.py``.
"""

from __future__ import annotations

import os
import subprocess
import ctypes
import ctypes.util
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterable, List, Tuple

# Determine the OpenSSL binary and provider path from environment
OPENSSL_BIN = os.environ.get("OPENSSL_BIN", "openssl")
PROVIDER_PATH = os.environ.get("OPENSSL_MODULES", "/usr/local/lib64/ossl-modules")

# Location where server keys are stored.  Keys are persisted across
# process restarts so that decryptions work reliably.  The directory
# will be created if it does not already exist.
HERE = Path(__file__).resolve().parent  # crypto/
KEYS = HERE.parent / "keys"
KEYS.mkdir(parents=True, exist_ok=True)


def _run(cmd: List[str]) -> str:
    """Run a command and return stdout on success.

    If the command exits with a non‑zero status a RuntimeError is
    raised with the combined stdout/stderr attached for debugging.
    """
    try:
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return proc.stdout
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\nstdout:\n{exc.stdout}\nstderr:\n{exc.stderr}"
        )


def _normalize_alg_name(name: str) -> str:
    """Convert algorithm name to mlkemXXX format (lowercase, no hyphens).
    
    The oqs-provider uses lowercase names without hyphens (e.g., mlkem768).
    This function converts KyberXXX or ML-KEM-XXX to mlkemXXX format.
    """
    normalized = name.lower().replace("-", "")
    if normalized.startswith("kyber"):
        number = normalized.replace("kyber", "")
        return f"mlkem{number}"
    elif normalized.startswith("mlkem"):
        return normalized
    return normalized


def _kem_name_candidates(requested: str) -> List[str]:
    """Return a list of plausible algorithm names for a given KEM.

    The OpenSSL OQS provider has switched from KyberXXX names to
    ML‑KEM‑XXX in recent versions.  To maintain compatibility this
    function returns both the requested name and its ML‑KEM variant.
    """
    mapping = {
        "Kyber512": ["Kyber512", "ML-KEM-512"],
        "Kyber768": ["Kyber768", "ML-KEM-768"],
        "Kyber1024": ["Kyber1024", "ML-KEM-1024"],
        "ML-KEM-512": ["ML-KEM-512", "Kyber512"],
        "ML-KEM-768": ["ML-KEM-768", "Kyber768"],
        "ML-KEM-1024": ["ML-KEM-1024", "Kyber1024"],
    }
    return mapping.get(requested, [requested])


def _gen_pqc_keypair(kem_alg: str, priv_path: Path, pub_path: Path) -> None:
    """Generate a PQC key pair using the OQS provider.

    This function first tries to use OpenSSL genpkey. If that fails (which
    is common for KEM algorithms), it falls back to using pyoqs to generate
    the keys directly via liboqs.
    """
    errors: List[str] = []
    
    # Map algorithm names to pyoqs format
    pyoqs_alg_map = {
        "mlkem512": "ML-KEM-512",
        "mlkem768": "ML-KEM-768", 
        "mlkem1024": "ML-KEM-1024",
        "kyber512": "ML-KEM-512",
        "kyber768": "ML-KEM-768",
        "kyber1024": "ML-KEM-1024",
    }
    
    # Try the normalized name first (most likely to work)
    normalized_alg = _normalize_alg_name(kem_alg)
    algorithms_to_try = [normalized_alg] + _kem_name_candidates(kem_alg)
    
    # First, try OpenSSL genpkey
    for alg in algorithms_to_try:
        alg_to_try = _normalize_alg_name(alg)
        try:
            _run([
                OPENSSL_BIN,
                "genpkey",
                "-provider-path", PROVIDER_PATH,
                "-provider", "base",
                "-provider", "default",
                "-provider", "oqsprovider",
                "-algorithm", alg_to_try,
                "-out", str(priv_path),
            ])
            _run([
                OPENSSL_BIN,
                "pkey",
                "-provider-path", PROVIDER_PATH,
                "-provider", "base",
                "-provider", "default",
                "-provider", "oqsprovider",
                "-in", str(priv_path),
                "-pubout",
                "-out", str(pub_path),
            ])
            return
        except Exception as exc:
            errors.append(f"OpenSSL genpkey with '{alg_to_try}': {str(exc)}")
    
    # If OpenSSL genpkey fails, try using liboqs directly via ctypes
    try:
        # Map algorithm names to liboqs format
        liboqs_alg_map = {
            "mlkem512": b"ML-KEM-512",
            "mlkem768": b"ML-KEM-768",
            "mlkem1024": b"ML-KEM-1024",
        }
        liboqs_alg = liboqs_alg_map.get(normalized_alg, b"ML-KEM-768")
        alg_name_str = liboqs_alg.decode('utf-8')
        
        # Load liboqs library
        liboqs_path = ctypes.util.find_library("oqs") or "/usr/local/lib/liboqs.so"
        liboqs = ctypes.CDLL(liboqs_path, mode=ctypes.RTLD_GLOBAL)
        
        # Try to get KEM object - liboqs uses OQS_KEM object pattern
        # First, try to get algorithm info
        try:
            # Check if OQS_KEM_alg_is_enabled exists
            if hasattr(liboqs, 'OQS_KEM_alg_is_enabled'):
                liboqs.OQS_KEM_alg_is_enabled.argtypes = [ctypes.c_char_p]
                liboqs.OQS_KEM_alg_is_enabled.restype = ctypes.c_int
                if liboqs.OQS_KEM_alg_is_enabled(liboqs_alg) == 0:
                    raise RuntimeError(f"Algorithm {alg_name_str} is not enabled")
        except AttributeError:
            pass  # Function may not exist in this version
        
        # Try OQS_KEM_new pattern (common in liboqs)
        try:
            liboqs.OQS_KEM_new.argtypes = [ctypes.c_char_p]
            liboqs.OQS_KEM_new.restype = ctypes.c_void_p
            
            kem_obj = liboqs.OQS_KEM_new(liboqs_alg)
            if not kem_obj:
                raise RuntimeError(f"Failed to create KEM object for {alg_name_str}")
            
            # Get key lengths from the KEM object
            # The KEM object structure contains length fields
            # We'll use fixed sizes for ML-KEM algorithms
            size_map = {
                "ML-KEM-512": (800, 1632),
                "ML-KEM-768": (1184, 2400),
                "ML-KEM-1024": (1568, 3168),
            }
            pub_len, priv_len = size_map.get(alg_name_str, (1184, 2400))
            
            # Allocate buffers
            public_key = (ctypes.c_uint8 * pub_len)()
            private_key = (ctypes.c_uint8 * priv_len)()
            
            # Generate key pair
            liboqs.OQS_KEM_keypair.argtypes = [
                ctypes.c_void_p,  # kem
                ctypes.POINTER(ctypes.c_uint8),  # public_key
                ctypes.POINTER(ctypes.c_uint8),  # secret_key
            ]
            liboqs.OQS_KEM_keypair.restype = ctypes.c_int
            
            result = liboqs.OQS_KEM_keypair(
                kem_obj,
                ctypes.cast(public_key, ctypes.POINTER(ctypes.c_uint8)),
                ctypes.cast(private_key, ctypes.POINTER(ctypes.c_uint8))
            )
            
            # Clean up
            if hasattr(liboqs, 'OQS_KEM_free'):
                liboqs.OQS_KEM_free.argtypes = [ctypes.c_void_p]
                liboqs.OQS_KEM_free(kem_obj)
            
            if result != 0:
                raise RuntimeError(f"OQS_KEM_keypair failed with code {result}")
            
            # Convert to bytes and save
            pub_bytes = bytes(public_key)
            priv_bytes = bytes(private_key)
            
            priv_path.write_bytes(priv_bytes)
            pub_path.write_bytes(pub_bytes)
            
            return
        except AttributeError:
            # Fallback: try direct function calls (older API)
            # This is a simplified approach - may need adjustment
            raise RuntimeError("liboqs API not compatible - need pyoqs or different approach")
        
    except (OSError, AttributeError, RuntimeError) as exc:
        errors.append(f"liboqs direct key generation failed: {str(exc)}")
    except Exception as exc:
        errors.append(f"Unexpected error in liboqs key generation: {str(exc)}")
    
    raise RuntimeError(
        f"Failed to generate PQC keypair for {kem_alg}. Tried: {normalized_alg}, {', '.join(_kem_name_candidates(kem_alg))}.\n"
        + "\n---\n".join(errors)
    )


def ensure_server_keys(kem_alg: str) -> Tuple[Path, Path, Path, Path]:
    """Ensure that the server has PQC and X25519 keys on disk.

    Returns a tuple ``(pqc_priv, pqc_pub, dh_priv, dh_pub)`` where
    each element is a ``Path`` pointing at the corresponding PEM file.
    Keys are generated lazily on first use and then reused for all
    subsequent operations.
    """
    pqc_priv = KEYS / f"server_{kem_alg}_pqc_priv.pem"
    pqc_pub = KEYS / f"server_{kem_alg}_pqc_pub.pem"
    dh_priv = KEYS / "server_dh_priv.pem"
    dh_pub = KEYS / "server_dh_pub.pem"

    # Generate PQC key if missing
    if not (pqc_priv.exists() and pqc_pub.exists()):
        _gen_pqc_keypair(kem_alg, pqc_priv, pqc_pub)

    # Generate X25519 key if missing
    if not (dh_priv.exists() and dh_pub.exists()):
        _run([
            OPENSSL_BIN,
            "genpkey",
            "-provider-path", PROVIDER_PATH,
            "-provider", "base",
            "-provider", "default",
            "-algorithm", "X25519",
            "-out", str(dh_priv),
        ])
        _run([
            OPENSSL_BIN,
            "pkey",
            "-provider-path", PROVIDER_PATH,
            "-provider", "base",
            "-provider", "default",
            "-in", str(dh_priv),
            "-pubout",
            "-out", str(dh_pub),
        ])

    return pqc_priv, pqc_pub, dh_priv, dh_pub


# Global list to keep temporary directories alive
_temp_dirs = []

def gen_client_ephemeral_x25519() -> Tuple[Path, Path]:
    """Generate an ephemeral X25519 key pair for the client.

    The keys are created in a temporary directory that is kept alive
    in a global list to prevent premature deletion.  The returned paths
    are guaranteed to remain valid for the lifetime of the program but
    should not be persisted.
    """
    tmp = TemporaryDirectory()
    _temp_dirs.append(tmp)  # Keep reference to prevent deletion
    tmp_dir = Path(tmp.name)
    priv = tmp_dir / "client_dh_priv.pem"
    pub = tmp_dir / "client_dh_pub.pem"
    _run([
        OPENSSL_BIN,
        "genpkey",
        "-provider-path", PROVIDER_PATH,
        "-provider", "base",
        "-provider", "default",
        "-algorithm", "X25519",
        "-out", str(priv),
    ])
    _run([
        OPENSSL_BIN,
        "pkey",
        "-provider-path", PROVIDER_PATH,
        "-provider", "base",
        "-provider", "default",
        "-in", str(priv),
        "-pubout",
        "-out", str(pub),
    ])
    return priv, pub


def _is_pyoqs_key(key_path: Path) -> bool:
    """Check if a key file was generated by pyoqs (raw bytes, not PEM)."""
    try:
        key_data = key_path.read_bytes()
        # PEM files start with "-----BEGIN"
        # pyoqs keys are raw bytes
        return not key_data.startswith(b"-----BEGIN")
    except Exception:
        return False


def kem_encapsulate(pqc_pub_path: Path, kem_alg: str) -> Tuple[bytes, bytes]:
    """Perform KEM encapsulation and return the (ciphertext, shared_secret).

    If the public key was generated by liboqs directly (raw bytes), use liboqs
    for encapsulation. Otherwise, try OpenSSL first.
    """
    # Check if key was generated by liboqs/pyoqs (raw bytes, not PEM)
    if _is_pyoqs_key(pqc_pub_path):
        try:
            # Try pyoqs first if available
            import oqs
            pyoqs_alg_map = {
                "mlkem512": "ML-KEM-512",
                "mlkem768": "ML-KEM-768",
                "mlkem1024": "ML-KEM-1024",
            }
            normalized_alg = _normalize_alg_name(kem_alg)
            pyoqs_alg = pyoqs_alg_map.get(normalized_alg, "ML-KEM-768")
            
            public_key = pqc_pub_path.read_bytes()
            kem = oqs.KeyEncapsulation(pyoqs_alg, public_key)
            ciphertext, shared_secret = kem.encap_secret()
            return ciphertext, shared_secret
        except ImportError:
            # Fall back to liboqs via ctypes
            try:
                liboqs_alg_map = {
                    "mlkem512": b"ML-KEM-512",
                    "mlkem768": b"ML-KEM-768",
                    "mlkem1024": b"ML-KEM-1024",
                }
                normalized_alg = _normalize_alg_name(kem_alg)
                liboqs_alg = liboqs_alg_map.get(normalized_alg, b"ML-KEM-768")
                alg_name_str = liboqs_alg.decode('utf-8')
                
                # Load liboqs library
                liboqs_path = ctypes.util.find_library("oqs") or "/usr/local/lib/liboqs.so"
                liboqs = ctypes.CDLL(liboqs_path, mode=ctypes.RTLD_GLOBAL)
                
                # Create KEM object
                liboqs.OQS_KEM_new.argtypes = [ctypes.c_char_p]
                liboqs.OQS_KEM_new.restype = ctypes.c_void_p
                
                kem_obj = liboqs.OQS_KEM_new(liboqs_alg)
                if not kem_obj:
                    raise RuntimeError(f"Failed to create KEM object for {alg_name_str}")
                
                # Get lengths from size map
                size_map = {
                    "ML-KEM-512": (800, 736, 32),
                    "ML-KEM-768": (1184, 1088, 32),
                    "ML-KEM-1024": (1568, 1568, 32),
                }
                pub_len, ct_len, ss_len = size_map.get(alg_name_str, (1184, 1088, 32))
                
                # Allocate buffers
                ciphertext = (ctypes.c_uint8 * ct_len)()
                shared_secret = (ctypes.c_uint8 * ss_len)()
                public_key = pqc_pub_path.read_bytes()
                pub_key_array = (ctypes.c_uint8 * len(public_key)).from_buffer_copy(public_key)
                
                # Perform encapsulation
                liboqs.OQS_KEM_encaps.argtypes = [
                    ctypes.c_void_p,  # kem
                    ctypes.POINTER(ctypes.c_uint8),  # ciphertext
                    ctypes.POINTER(ctypes.c_uint8),  # shared_secret
                    ctypes.POINTER(ctypes.c_uint8),  # public_key
                ]
                liboqs.OQS_KEM_encaps.restype = ctypes.c_int
                
                result = liboqs.OQS_KEM_encaps(
                    kem_obj,
                    ctypes.cast(ciphertext, ctypes.POINTER(ctypes.c_uint8)),
                    ctypes.cast(shared_secret, ctypes.POINTER(ctypes.c_uint8)),
                    ctypes.cast(pub_key_array, ctypes.POINTER(ctypes.c_uint8))
                )
                
                # Clean up
                if hasattr(liboqs, 'OQS_KEM_free'):
                    liboqs.OQS_KEM_free.argtypes = [ctypes.c_void_p]
                    liboqs.OQS_KEM_free(kem_obj)
                
                if result != 0:
                    raise RuntimeError(f"OQS_KEM_encaps failed with code {result}")
                
                return bytes(ciphertext), bytes(shared_secret)
            except (OSError, AttributeError, RuntimeError) as exc:
                raise RuntimeError(f"liboqs encapsulation failed: {str(exc)}")
        except Exception as exc:
            raise RuntimeError(f"Encapsulation failed: {str(exc)}")
    
    # Try OpenSSL first
    ct_file = KEYS / "kem_ct.bin"
    ss_file = KEYS / "kem_ss.bin"
    errors: List[str] = []
    
    normalized_alg = _normalize_alg_name(kem_alg)
    algorithms_to_try = [normalized_alg] + _kem_name_candidates(kem_alg)
    
    for alg in algorithms_to_try:
        alg_to_try = _normalize_alg_name(alg)
        try:
            _run([
                OPENSSL_BIN,
                "pkeyutl",
                "-provider-path", PROVIDER_PATH,
                "-provider", "base",
                "-provider", "default",
                "-provider", "oqsprovider",
                "-pubin",
                "-inkey", str(pqc_pub_path),
                "-kem",
                "-algorithm", alg_to_try,
                "-out", str(ct_file),
                "-keyout", str(ss_file),
            ])
            return ct_file.read_bytes(), ss_file.read_bytes()
        except Exception as exc:
            errors.append(f"Algorithm '{alg_to_try}': {str(exc)}")
    
    raise RuntimeError(
        f"Failed to encapsulate using {kem_alg}.\n" + "\n---\n".join(errors)
    )


def kem_decapsulate(pqc_priv_path: Path, kem_ct: bytes, kem_alg: str) -> bytes:
    """Perform KEM decapsulation and return the shared secret bytes.
    
    If the private key was generated by liboqs directly (raw bytes), use liboqs
    for decapsulation. Otherwise, try OpenSSL first.
    """
    # Check if key was generated by liboqs/pyoqs (raw bytes, not PEM)
    if _is_pyoqs_key(pqc_priv_path):
        try:
            # Try pyoqs first if available
            import oqs
            pyoqs_alg_map = {
                "mlkem512": "ML-KEM-512",
                "mlkem768": "ML-KEM-768",
                "mlkem1024": "ML-KEM-1024",
            }
            normalized_alg = _normalize_alg_name(kem_alg)
            pyoqs_alg = pyoqs_alg_map.get(normalized_alg, "ML-KEM-768")
            
            private_key = pqc_priv_path.read_bytes()
            kem = oqs.KeyEncapsulation(pyoqs_alg, private_key)
            shared_secret = kem.decap_secret(kem_ct)
            return shared_secret
        except ImportError:
            # Fall back to liboqs via ctypes
            try:
                liboqs_alg_map = {
                    "mlkem512": b"ML-KEM-512",
                    "mlkem768": b"ML-KEM-768",
                    "mlkem1024": b"ML-KEM-1024",
                }
                normalized_alg = _normalize_alg_name(kem_alg)
                liboqs_alg = liboqs_alg_map.get(normalized_alg, b"ML-KEM-768")
                alg_name_str = liboqs_alg.decode('utf-8')
                
                # Load liboqs library
                liboqs_path = ctypes.util.find_library("oqs") or "/usr/local/lib/liboqs.so"
                liboqs = ctypes.CDLL(liboqs_path, mode=ctypes.RTLD_GLOBAL)
                
                # Create KEM object
                liboqs.OQS_KEM_new.argtypes = [ctypes.c_char_p]
                liboqs.OQS_KEM_new.restype = ctypes.c_void_p
                
                kem_obj = liboqs.OQS_KEM_new(liboqs_alg)
                if not kem_obj:
                    raise RuntimeError(f"Failed to create KEM object for {alg_name_str}")
                
                # Get shared secret length from size map
                size_map = {
                    "ML-KEM-512": 32,
                    "ML-KEM-768": 32,
                    "ML-KEM-1024": 32,
                }
                ss_len = size_map.get(alg_name_str, 32)
                
                # Allocate buffer
                shared_secret = (ctypes.c_uint8 * ss_len)()
                private_key = pqc_priv_path.read_bytes()
                priv_key_array = (ctypes.c_uint8 * len(private_key)).from_buffer_copy(private_key)
                ct_array = (ctypes.c_uint8 * len(kem_ct)).from_buffer_copy(kem_ct)
                
                # Perform decapsulation
                liboqs.OQS_KEM_decaps.argtypes = [
                    ctypes.c_void_p,  # kem
                    ctypes.POINTER(ctypes.c_uint8),  # shared_secret
                    ctypes.POINTER(ctypes.c_uint8),  # ciphertext
                    ctypes.POINTER(ctypes.c_uint8),  # secret_key
                ]
                liboqs.OQS_KEM_decaps.restype = ctypes.c_int
                
                result = liboqs.OQS_KEM_decaps(
                    kem_obj,
                    ctypes.cast(shared_secret, ctypes.POINTER(ctypes.c_uint8)),
                    ctypes.cast(ct_array, ctypes.POINTER(ctypes.c_uint8)),
                    ctypes.cast(priv_key_array, ctypes.POINTER(ctypes.c_uint8))
                )
                
                # Clean up
                if hasattr(liboqs, 'OQS_KEM_free'):
                    liboqs.OQS_KEM_free.argtypes = [ctypes.c_void_p]
                    liboqs.OQS_KEM_free(kem_obj)
                
                if result != 0:
                    raise RuntimeError(f"OQS_KEM_decaps failed with code {result}")
                
                return bytes(shared_secret)
            except (OSError, AttributeError, RuntimeError) as exc:
                raise RuntimeError(f"liboqs decapsulation failed: {str(exc)}")
        except Exception as exc:
            raise RuntimeError(f"Decapsulation failed: {str(exc)}")
    
    # Try OpenSSL first
    in_file = KEYS / "kem_ct_in.bin"
    out_file = KEYS / "kem_ss_out.bin"
    in_file.write_bytes(kem_ct)
    errors: List[str] = []
    
    normalized_alg = _normalize_alg_name(kem_alg)
    algorithms_to_try = [normalized_alg] + _kem_name_candidates(kem_alg)
    
    for alg in algorithms_to_try:
        alg_to_try = _normalize_alg_name(alg)
        try:
            _run([
                OPENSSL_BIN,
                "pkeyutl",
                "-provider-path", PROVIDER_PATH,
                "-provider", "base",
                "-provider", "default",
                "-provider", "oqsprovider",
                "-inkey", str(pqc_priv_path),
                "-kem",
                "-algorithm", alg_to_try,
                "-in", str(in_file),
                "-out", str(out_file),
            ])
            return out_file.read_bytes()
        except Exception as exc:
            errors.append(f"Algorithm '{alg_to_try}': {str(exc)}")
    raise RuntimeError(
        f"Failed to decapsulate using {kem_alg}.\n" + "\n---\n".join(errors)
    )


def ecdh_derive(local_priv: Path, peer_pub: Path) -> bytes:
    """Derive a shared secret using X25519 via OpenSSL."""
    out_file = KEYS / "ecdh_ss.bin"
    _run([
        OPENSSL_BIN,
        "pkeyutl",
        "-provider-path", PROVIDER_PATH,
        "-provider", "base",
        "-provider", "default",
        "-derive",
        "-inkey", str(local_priv),
        "-peerkey", str(peer_pub),
        "-out", str(out_file),
    ])
    return out_file.read_bytes()

