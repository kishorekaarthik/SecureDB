import os
import json
from Crypto.Random import get_random_bytes

KEYS_FILE = "keyvault.json"

def load_keys():
    if not os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, "w") as f:
            json.dump({}, f)
    with open(KEYS_FILE, "r") as f:
        return json.load(f)

def save_keys(keys):
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f)

def get_key(version):
    keys = load_keys()
    return bytes.fromhex(keys[str(version)])

def generate_new_key():
    key = get_random_bytes(32)
    keys = load_keys()
    version = str(len(keys) + 1)
    keys[version] = key.hex()
    save_keys(keys)
    return version

def rotate_user_key(user_id=None):  # user_id is optional
    return generate_new_key()
