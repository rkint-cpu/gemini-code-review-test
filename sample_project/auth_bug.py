import hashlib
import sqlite3

API_SECRET = "sk_live_hardcoded_secret_98765"

def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

def get_user(username: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
