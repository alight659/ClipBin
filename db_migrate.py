# db_migrate.py
import sqlite3
import os

DB_FILE = "clipbin.db"

def migrate():
    """Performs a safe, multi-step migration to add required columns to the users table."""
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        print("Starting safe database migration for 'users' table...")

        # Check if migration is needed (by checking for github_id)
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]

        if 'github_id' in columns and 'email' in columns:
            print("Migration skipped: 'github_id' and 'email' columns already exist.")
            return

        # --- SAFE MIGRATION STEPS ---
        
        # 1. Rename the existing users table
        print("1. Renaming 'users' to 'old_users'...")
        cursor.execute("ALTER TABLE users RENAME TO old_users")

        # 2. Create the new users table with the correct schema
        print("2. Creating new 'users' table with 'github_id' and 'email' columns...")
        # NOTE: Adjust this CREATE TABLE statement if your existing users table has other custom columns!
        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                username TEXT NOT NULL,
                password TEXT,
                github_id TEXT UNIQUE,
                email TEXT
            )
        """)
        
        # 3. Copy data from the old table to the new table
        # We copy the existing columns (id, username, password) and leave github_id/email NULL
        print("3. Copying data from 'old_users' to 'users'...")
        cursor.execute("""
            INSERT INTO users (id, username, password)
            SELECT id, username, password FROM old_users
        """)

        # 4. Drop the temporary old table
        print("4. Dropping 'old_users' table...")
        cursor.execute("DROP TABLE old_users")
        
        conn.commit()
        print("SUCCESS: Database migration complete. 'users' table schema is updated.")
        
    except Exception as e:
        print(f"FATAL ERROR during migration: {e}")
        print("Migration failed. Manual review of the database schema is required.")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    migrate()