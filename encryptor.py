from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from keyvault import get_key, generate_new_key
import base64
import hashlib

BLOCK_SIZE = 16

def _derive_key(base_key, salt=None):
    """
    Optional: Derive a unique per-record key using a salt (e.g., user_id or record_id).
    """
    if not salt:
        return base_key
    derived = hashlib.sha256(base_key + salt.encode()).digest()
    return derived

def encrypt(data, version=None, salt=None):
    """
    Encrypts data using AES-CBC with optional key derivation based on salt.
    Returns (encrypted_data_b64, key_version).
    """
    if version is None:
        version = generate_new_key()
    base_key = get_key(version)
    key = _derive_key(base_key, salt)
    
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data.encode(), BLOCK_SIZE))

    encrypted = base64.b64encode(iv + ciphertext).decode()
    return encrypted, version

def decrypt(enc_data, version, salt=None):
    """
    Decrypts data using AES-CBC with optional salt-based key derivation.
    """
    base_key = get_key(version)
    key = _derive_key(base_key, salt)

    raw = base64.b64decode(enc_data)
    iv, ct = raw[:BLOCK_SIZE], raw[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), BLOCK_SIZE).decode()
    return decrypted
