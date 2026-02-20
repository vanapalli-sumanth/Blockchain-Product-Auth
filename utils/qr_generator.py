import qrcode
import os
from flask import request
from utils.token_generator import create_secure_token


def generate_qr():

    token = create_secure_token()

    # ✅ AUTO detect current domain
    base_url = request.host_url.rstrip("/")

    verify_url = f"{base_url}/verify?token={token}"

    folder = "static/qr_codes"
    os.makedirs(folder, exist_ok=True)

    path = f"{folder}/{token}.png"

    qrcode.make(verify_url).save(path)

    return {
        "secure_token": token,
        "qr_path": f"qr_codes/{token}.png"
    }