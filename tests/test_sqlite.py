"""
Unit tests for the SQLite database module.
"""

import pytest
import tempfile
import os
import sqlite3
from sqlite import SQLite


class TestSQLite:
    """Test cases for the SQLite class."""

    def test_init(self):
        """Test SQLite class initialization."""
        db_path = "test.db"
        sqlite_instance = SQLite(db_path)
        assert sqlite_instance.database_url == db_path
        assert sqlite_instance.lock is not None

    def test_get_connection(self, test_db):
        """Test database connection creation."""
        conn = test_db._get_connection()
        assert conn is not None
        assert isinstance(conn, sqlite3.Connection)
        conn.close()

    def test_execute_create_table(self, test_db):
        """Test executing CREATE TABLE query."""
        result = test_db.execute("""
            CREATE TABLE test_table (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )
        """)
        # CREATE statements return an empty list, not True
        assert result == []

    def test_execute_insert(self, test_db):
        """Test executing INSERT query."""
        # First create table
        test_db.execute("""
            CREATE TABLE test_table (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )
        """)
        
        # Then insert data
        result = test_db.execute(
            "INSERT INTO test_table (name) VALUES (?)",
            "Test Name"
        )
        assert result is True

    def test_execute_select(self, test_db):
        """Test executing SELECT query."""
        # Create table and insert data
        test_db.execute("""
            CREATE TABLE test_table (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )
        """)
        test_db.execute("INSERT INTO test_table (name) VALUES (?)", "Test Name")
        
        # Select data
        result = test_db.execute("SELECT * FROM test_table")
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]['name'] == "Test Name"

    def test_execute_update(self, test_db):
        """Test executing UPDATE query."""
        # Create table and insert data
        test_db.execute("""
            CREATE TABLE test_table (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )
        """)
        test_db.execute("INSERT INTO test_table (name) VALUES (?)", "Test Name")
        
        # Update data
        result = test_db.execute(
            "UPDATE test_table SET name = ? WHERE id = ?",
            "Updated Name", 1
        )
        assert result is True
        
        # Verify update
        updated_data = test_db.execute("SELECT * FROM test_table WHERE id = ?", 1)
        assert updated_data[0]['name'] == "Updated Name"

    def test_execute_delete(self, test_db):
        """Test executing DELETE query."""
        # Create table and insert data
        test_db.execute("""
            CREATE TABLE test_table (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )
        """)
        test_db.execute("INSERT INTO test_table (name) VALUES (?)", "Test Name")
        
        # Delete data
        result = test_db.execute("DELETE FROM test_table WHERE id = ?", 1)
        assert result is True
        
        # Verify deletion
        remaining_data = test_db.execute("SELECT * FROM test_table")
        assert len(remaining_data) == 0

    def test_execute_multiple_args(self, test_db):
        """Test executing query with multiple arguments."""
        test_db.execute("""
            CREATE TABLE test_table (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                age INTEGER
            )
        """)
        
        result = test_db.execute(
            "INSERT INTO test_table (name, age) VALUES (?, ?)",
            "John Doe", 25
        )
        assert result is True
        
        data = test_db.execute("SELECT * FROM test_table")
        assert data[0]['name'] == "John Doe"
        assert data[0]['age'] == 25

    def test_execute_invalid_query(self, test_db):
        """Test handling of invalid SQL queries."""
        result = test_db.execute("INVALID SQL QUERY")
        assert result is None

    def test_execute_with_foreign_keys(self, test_db):
        """Test that foreign keys are enabled."""
        # Create parent table
        test_db.execute("""
            CREATE TABLE parent (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )
        """)
        
        # Create child table with foreign key
        test_db.execute("""
            CREATE TABLE child (
                id INTEGER PRIMARY KEY,
                parent_id INTEGER,
                name TEXT NOT NULL,
                FOREIGN KEY (parent_id) REFERENCES parent (id)
            )
        """)
        
        # Insert parent record
        test_db.execute("INSERT INTO parent (name) VALUES (?)", "Parent")
        
        # Insert child record with valid foreign key
        result = test_db.execute(
            "INSERT INTO child (parent_id, name) VALUES (?, ?)",
            1, "Child"
        )
        assert result is True

    def test_row_factory_dict(self, test_db):
        """Test that rows are returned as dictionaries."""
        test_db.execute("""
            CREATE TABLE test_table (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                age INTEGER
            )
        """)
        test_db.execute(
            "INSERT INTO test_table (name, age) VALUES (?, ?)",
            "John", 30
        )
        
        result = test_db.execute("SELECT * FROM test_table")
        assert isinstance(result, list)
        assert isinstance(result[0], dict)
        assert 'id' in result[0]
        assert 'name' in result[0]
        assert 'age' in result[0]

    def test_close_method(self, test_db):
        """Test the close method (should not raise an error)."""
        test_db.close()  # Should not raise any exception

    def test_thread_safety(self, test_db):
        """Test basic thread safety with lock."""
        import threading
        
        def insert_data(name):
            test_db.execute("INSERT INTO test_table (name) VALUES (?)", name)
        
        # Create table
        test_db.execute("""
            CREATE TABLE test_table (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )
        """)
        
        # Create multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=insert_data, args=[f"Name{i}"])
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all records were inserted
        result = test_db.execute("SELECT COUNT(*) as count FROM test_table")
        assert result[0]['count'] == 5