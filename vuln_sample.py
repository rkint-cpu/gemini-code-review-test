import os
import sqlite3

def backup_folder(folder: str):
    os.system("tar -czf backup.tar.gz " + folder)

def find_user(username: str):
    conn = sqlite3.connect("app.db")
    return conn.execute(f"SELECT * FROM users WHERE username = '{username}'").fetchall()
