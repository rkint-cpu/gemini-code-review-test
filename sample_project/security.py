import sqlite3

DB_PASSWORD = "SuperSecretPassword123!"

def get_user_by_username(db_path: str, username: str):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()