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
                with conn:
                    cursor = conn.cursor()
                    cursor.execute(query, args)

                    if query.strip().upper().startswith(('INSERT', 'UPDATE', 'DELETE')):
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

    def close(self):
        pass
