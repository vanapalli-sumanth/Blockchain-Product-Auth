import secrets

def create_secure_token():
    return secrets.token_hex(16)