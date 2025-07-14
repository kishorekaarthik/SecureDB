import os
import json
from Crypto.Random import get_random_bytes

KEYS_FILE = "keyvault.json"

def generate_new_key():
    key = get_random_bytes(32)
    keys = load_keys()
    version = str(len(keys) + 1)
    keys[version] = key.hex()
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f)
    return version

def load_keys():
    if not os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, "w") as f:
            json.dump({}, f)
    with open(KEYS_FILE, "r") as f:
        return json.load(f)

def get_key(version):
    keys = load_keys()
    return bytes.fromhex(keys[str(version)])
