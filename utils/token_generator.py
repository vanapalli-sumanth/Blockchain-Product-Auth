import secrets

def create_secure_token():
    # cryptographically secure random token
    return secrets.token_hex(16)
