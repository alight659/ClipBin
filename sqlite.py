import sqlite3
import threading
import logging

logging.basicConfig(level=logging.ERROR)


class SQLite:
    def __init__(self, database_url):
        self.database_url = database_url
        self.lock = threading.Lock()

    def _get_connection(self):
        conn = sqlite3.connect(self.database_url, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def execute(self, query, *args):
        try:
            with self.lock:
                conn = self._get_connection()
                conn.execute("PRAGMA foreign_keys = ON")
                with conn:
                    cursor = conn.cursor()
                    cursor.execute(query, args)

                    if query.strip().upper().startswith(("INSERT", "UPDATE", "DELETE")):
                        conn.commit()
                        return True

                    result = cursor.fetchall()
                    return [dict(row) for row in result]
        except sqlite3.Error as e:
            logging.error("SQLite error: %s", e)
            return None
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def cleanup_all_tables(self):
        """
        Clean up all tables in the database including sqlite_sequence.
        This is useful for testing to ensure a fresh database state.
        """
        try:
            with self.lock:
                conn = self._get_connection()

                # Disable foreign key constraints for cleanup
                conn.execute("PRAGMA foreign_keys = OFF")

                # Get all user tables (excluding sqlite internal tables)
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
                tables = cursor.fetchall()

                # Delete all data from tables
                for table in tables:
                    table_name = table[0]
                    cursor.execute(f"DELETE FROM {table_name}")

                # Reset autoincrement sequences
                cursor.execute("DELETE FROM sqlite_sequence")

                # Re-enable foreign key constraints
                conn.execute("PRAGMA foreign_keys = ON")
                conn.commit()

                return True

        except sqlite3.Error as e:
            logging.error("SQLite cleanup error: %s", e)
            return False
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def get_table_names(self):
        """Get a list of all user-created table names in the database."""
        try:
            result = self.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            return [row["name"] for row in result] if result else []
        except Exception as e:
            logging.error("Error getting table names: %s", e)
            return []

    def close(self):
        pass
