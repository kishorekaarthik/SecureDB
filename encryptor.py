from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from keyvault import get_key, generate_new_key
import base64

BLOCK_SIZE = 16

def encrypt(data):
    version = generate_new_key()
    key = get_key(version)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), BLOCK_SIZE))
    encrypted = base64.b64encode(cipher.iv + ct_bytes).decode()
    return encrypted, version

def decrypt(enc_data, version):
    key = get_key(version)
    enc = base64.b64decode(enc_data)
    iv = enc[:BLOCK_SIZE]
    ct = enc[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), BLOCK_SIZE).decode()
