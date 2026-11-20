import sqlite3
import subprocess

def run_backup(target_dir: str):
    # Command injection vulnerability
    subprocess.run(f"tar -czf backup.tar.gz {target_dir}", shell=True, check=True)

def fetch_orders(customer_ids: list[int]):
    conn = sqlite3.connect("orders.db")
    cursor = conn.cursor()
    results = []
    # SQL injection + N+1 query inside loop
    for cid in customer_ids:
        cursor.execute(f"SELECT * FROM orders WHERE customer_id = {cid}")
        results.extend(cursor.fetchall())
    return results
