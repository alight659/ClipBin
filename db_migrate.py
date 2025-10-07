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

        # If users table already has the needed columns, migration of users is not required.
        users_ok = "github_id" in columns and "email" in columns

        # Additionally detect whether any tables still reference an old_users table
        cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND sql LIKE '%old_users%'")
        tables_ref_old = cursor.fetchall()

        if users_ok and not tables_ref_old:
            print("Migration skipped: 'github_id' and 'email' columns already exist and no tables reference old_users.")
            return

        # --- SAFE MIGRATION STEPS ---

        # 1. Rename the existing users table
        print("1. Renaming 'users' to 'old_users'...")
        cursor.execute("ALTER TABLE users RENAME TO old_users")

        # 2. Create the new users table with the correct schema
        print("2. Creating new 'users' table with 'github_id' and 'email' columns...")
        # NOTE: Adjust this CREATE TABLE statement if your existing users table has other custom columns!
        cursor.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                username TEXT NOT NULL,
                password TEXT,
                github_id TEXT UNIQUE,
                email TEXT
            )
        """
        )

        # 3. Copy data from the old table to the new table
        # We copy the existing columns (id, username, password) and leave github_id/email NULL
        print("3. Copying data from 'old_users' to 'users'...")
        cursor.execute(
            """
            INSERT INTO users (id, username, password)
            SELECT id, username, password FROM old_users
        """
        )

        # 4. Drop the temporary old table
        print("4. Dropping 'old_users' table...")
        cursor.execute("DROP TABLE old_users")

        # 5. Repair any tables that still reference the historical "old_users" name.
        # This can happen if some tables were created while users was temporarily renamed.
        cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND sql LIKE '%old_users%'")
        ref_tables = cursor.fetchall()

        for tbl_name, tbl_sql in ref_tables:
            print(f"Repairing table '{tbl_name}' which references old_users...")
            # Rename the affected table
            temp_name = f"old_{tbl_name}"
            cursor.execute(f"ALTER TABLE {tbl_name} RENAME TO {temp_name}")

            # Create new table SQL by replacing references to old_users with users
            new_sql = tbl_sql.replace('"old_users"', "users").replace("old_users", "users")
            cursor.execute(new_sql)

            # Copy columns from temp table to new table. Use PRAGMA to get column names.
            cursor.execute(f"PRAGMA table_info({temp_name})")
            cols = [row[1] for row in cursor.fetchall()]
            cols_list = ", ".join(cols)

            cursor.execute(f"INSERT INTO {tbl_name} ({cols_list}) SELECT {cols_list} FROM {temp_name}")
            cursor.execute(f"DROP TABLE {temp_name}")

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
