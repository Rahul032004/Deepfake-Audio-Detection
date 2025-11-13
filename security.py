import os
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def derive_key_from_passphrase(passphrase):
    return hashlib.sha256(passphrase.encode()).digest()

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def encrypt_file_aes_gcm(path, key_bytes):
    with open(path, "rb") as f:
        data = f.read()
    h = sha256_bytes(data)
    nonce = get_random_bytes(12)
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "nonce_b64": base64.b64encode(nonce).decode(),
        "tag_b64": base64.b64encode(tag).decode(),
        "sha256": h,
    }

def decrypt_bytes_aes_gcm(ciphertext_b64, nonce_b64, tag_b64, key_bytes):
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data