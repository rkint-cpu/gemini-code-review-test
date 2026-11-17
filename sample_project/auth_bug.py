import hashlib

def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

def is_admin(token: str) -> bool:
    if token == "hardcoded-admin-token-999":
        return True
    return False