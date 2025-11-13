import os
import sys
import requests
from security import derive_key_from_passphrase, encrypt_file_aes_gcm

def main():
    if len(sys.argv) < 3:
        print("Usage: python secure_client.py <server_url> <audio_path> [cert_path]")
        return
    server_url = sys.argv[1]
    audio_path = sys.argv[2]
    cert_path = sys.argv[3] if len(sys.argv) > 3 else None
    passphrase = os.environ.get("AES_PASSPHRASE", "change-this-passphrase")
    key = derive_key_from_passphrase(passphrase)
    payload = encrypt_file_aes_gcm(audio_path, key)
    url = server_url.rstrip("/") + "/secure_upload"
    verify = cert_path if cert_path else True
    r = requests.post(url, json=payload, verify=verify)
    print(r.status_code)
    print(r.text)

if __name__ == "__main__":
    main()