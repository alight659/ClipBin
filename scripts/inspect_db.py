import sqlite3
import os

DB = os.path.join(os.path.dirname(__file__), "..", "clipbin.db")
DB = os.path.abspath(DB)
print("Inspecting DB:", DB)
conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE sql IS NOT NULL")
rows = cur.fetchall()
found = False
for r in rows:
    typ, name, tbl_name, sql = r
    if "old_users" in sql.lower() or "old_users" in (name or "").lower() or "old_users" in (tbl_name or "").lower():
        print("--- MATCH ---")
        print("type:", typ)
        print("name:", name)
        print("tbl_name:", tbl_name)
        print("sql:", sql)
        found = True

if not found:
    print("No sqlite_master entries mention old_users")

# Also list all tables
cur.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")
for name, sql in cur.fetchall():
    print("\nTable:", name)
    print(sql)

conn.close()
