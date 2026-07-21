"""
VaultX - Encryption Module
Handles AES-256-CBC file encryption/decryption, SHA-256 integrity hashing,
and AES key retrieval from HashiCorp Vault (with local-file fallback for dev).
"""
import os
import hashlib
import logging

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger("vaultx.encryption")

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "root")
VAULT_SECRET_PATH = os.environ.get("VAULT_SECRET_PATH", "vaultx-key")
USE_VAULT = os.environ.get("USE_VAULT", "true").lower() == "true"

LOCAL_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vaultx.key")

AES_KEY_LENGTH_BYTES = 32  # 256-bit key
IV_LENGTH_BYTES = 16       # 128-bit IV (AES block size)


class VaultConnectionError(Exception):
    """Raised when HashiCorp Vault is unreachable or the secret is missing."""


def _generate_local_key():
    """Generate and persist a local AES-256 key for development fallback."""
    key = os.urandom(AES_KEY_LENGTH_BYTES)
    with open(LOCAL_KEY_FILE, "w") as f:
        f.write(key.hex())
    os.chmod(LOCAL_KEY_FILE, 0o600)
    return key.hex()


def _get_local_key():
    if not os.path.exists(LOCAL_KEY_FILE):
        return _generate_local_key()
    with open(LOCAL_KEY_FILE, "r") as f:
        return f.read().strip()


def get_vault_client():
    """Create and return an hvac.Client, raising VaultConnectionError if unreachable."""
    try:
        import hvac
    except ImportError as e:
        raise VaultConnectionError(f"hvac library not installed: {e}")

    try:
        client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
        if not client.is_authenticated():
            raise VaultConnectionError("Vault client failed authentication")
        return client
    except Exception as e:
        raise VaultConnectionError(f"Could not connect to Vault at {VAULT_ADDR}: {e}")


def get_encryption_key():
    """
    Retrieve the AES-256 key (as raw bytes) used for file encryption.

    Priority:
      1. HashiCorp Vault KV v2 secret at VAULT_SECRET_PATH (key stored as hex string
         under the field 'key'), if USE_VAULT=true.
      2. Local vaultx.key file fallback (development only).
    """
    if USE_VAULT:
        try:
            client = get_vault_client()
            secret = client.secrets.kv.v2.read_secret_version(path=VAULT_SECRET_PATH)
            key_hex = secret["data"]["data"]["key"]
            return bytes.fromhex(key_hex)
        except Exception as e:
            logger.warning("Vault unavailable, falling back to local key file: %s", e)

    key_hex = _get_local_key()
    return bytes.fromhex(key_hex)


def check_vault_status():
    """Return a dict describing current Vault connectivity status (for /api/vault/status)."""
    if not USE_VAULT:
        return {"vault_enabled": False, "connected": False, "mode": "local_fallback",
                "message": "USE_VAULT is disabled; using local key file."}
    try:
        client = get_vault_client()
        sealed = client.sys.is_sealed()
        return {
            "vault_enabled": True,
            "connected": True,
            "sealed": sealed,
            "vault_addr": VAULT_ADDR,
            "secret_path": VAULT_SECRET_PATH,
            "mode": "vault",
        }
    except Exception as e:
        return {
            "vault_enabled": True,
            "connected": False,
            "mode": "local_fallback",
            "message": str(e),
        }


def sha256_bytes(data: bytes) -> str:
    """Return hex SHA-256 digest of the given bytes."""
    return hashlib.sha256(data).hexdigest()


def encrypt_file_bytes(plaintext: bytes):
    """
    Encrypt raw file bytes with AES-256-CBC.

    Flow: sha256(raw) -> os.urandom(16) IV -> AES-256-CBC encrypt (PKCS7 padded)
    Returns: (blob, sha256_hash) where blob = IV (16 bytes) || ciphertext
    """
    original_hash = sha256_bytes(plaintext)

    key = get_encryption_key()
    iv = os.urandom(IV_LENGTH_BYTES)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    blob = iv + ciphertext
    return blob, original_hash


def decrypt_file_bytes(blob: bytes):
    """
    Decrypt a stored .enc blob produced by encrypt_file_bytes.

    Flow: extract IV (first 16 bytes) -> AES-256-CBC decrypt -> unpad -> sha256(decrypted)
    Returns: (plaintext, recomputed_sha256_hash)
    """
    if len(blob) < IV_LENGTH_BYTES:
        raise ValueError("Encrypted blob is too short to contain a valid IV")

    iv = blob[:IV_LENGTH_BYTES]
    ciphertext = blob[IV_LENGTH_BYTES:]

    key = get_encryption_key()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    recomputed_hash = sha256_bytes(plaintext)
    return plaintext, recomputed_hash
