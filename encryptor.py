from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from keyvault import get_key, generate_new_key
import base64

BLOCK_SIZE = 16

def encrypt(data, version=None):
    if version is None:
        version = generate_new_key()
    key = get_key(version)
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(data.encode(), BLOCK_SIZE))
    return base64.b64encode(cipher.iv + ct).decode(), version

def decrypt(enc_data, version):
    key = get_key(version)
    enc = base64.b64decode(enc_data)
    iv, ct = enc[:BLOCK_SIZE], enc[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), BLOCK_SIZE).decode()
