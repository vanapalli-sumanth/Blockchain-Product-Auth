import secrets

def generate_scratch_code(length=8):
    """
    Generates secure scratch code like:
    X4A9B2C8
    """
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return ''.join(secrets.choice(alphabet) for _ in range(length))