import base64
import hashlib

from cryptography.fernet import Fernet

from app.core.config import get_settings

settings = get_settings()

def get_fernet() -> Fernet:
    # Derive a 32-byte url-safe base64 key from the SECRET_KEY
    key_bytes = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(fernet_key)

fernet = get_fernet()

def encrypt_data(data: str) -> str:
    if not data:
        return data
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(token: str) -> str:
    if not token:
        return token
    try:
        return fernet.decrypt(token.encode()).decode()
    except Exception as e:
        # Security: Never silently return the raw token — it could be ciphertext
        # that the caller treats as a valid key/secret.
        raise ValueError("Decryption failed: data may be corrupted or the encryption key has changed") from e
