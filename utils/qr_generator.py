import qrcode
import os
from utils.token_generator import create_secure_token

BASE_VERIFY_URL = "http://127.0.0.1:5000/verify"

def generate_qr():
    token = create_secure_token()
    verify_url = f"{BASE_VERIFY_URL}?token={token}"

    folder = "static/qr_codes"
    os.makedirs(folder, exist_ok=True)

    path = f"{folder}/{token}.png"
    qrcode.make(verify_url).save(path)

    return {
        "secure_token": token,
        "qr_path": f"qr_codes/{token}.png"
    }
