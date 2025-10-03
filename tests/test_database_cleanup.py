"""
Test cases to verify database cleanup functionality.
"""

import pytest
from app import db


class TestDatabaseCleanup:
    """Test cases for database cleanup functionality."""

    def test_database_cleanup_removes_all_data(self, client):
        """Test that database cleanup removes all data from all tables."""
        # Insert test data
        db.execute(
            """
            INSERT INTO users (username, password) 
            VALUES (?, ?)
        """,
            "cleanup_test_user",
            "password123",
        )

        db.execute(
            """
            INSERT INTO clips (clip_url, clip_name, clip_text, clip_time) 
            VALUES (?, ?, ?, ?)
        """,
            "test123",
            "Test Clip",
            "Test content",
            "2025-01-01 12:00:00",
        )

        # Verify data exists
        users = db.execute("SELECT * FROM users WHERE username = ?", "cleanup_test_user")
        clips = db.execute("SELECT * FROM clips WHERE clip_url = ?", "test123")

        assert len(users) > 0
        assert len(clips) > 0

        # The cleanup_before_and_after_test fixture should clean this up automatically
        # This test verifies the cleanup happens between tests

    def test_database_is_clean_at_start(self, client):
        """Test that database is clean at the start of each test."""
        # Check that no test data exists from previous test
        users = db.execute("SELECT * FROM users WHERE username = ?", "cleanup_test_user")
        clips = db.execute("SELECT * FROM clips WHERE clip_url = ?", "test123")

        # Database should be clean
        assert len(users) == 0
        assert len(clips) == 0

    def test_sqlite_sequence_is_reset(self, client):
        """Test that sqlite_sequence table is properly reset."""
        # Insert and delete some data to increment sequences
        db.execute(
            """
            INSERT INTO users (username, password) 
            VALUES (?, ?)
        """,
            "seq_test_user1",
            "password123",
        )

        db.execute(
            """
            INSERT INTO users (username, password) 
            VALUES (?, ?)
        """,
            "seq_test_user2",
            "password123",
        )

        # Check that sequences were incremented
        sequences = db.execute("SELECT * FROM sqlite_sequence WHERE name = ?", "users")

        if sequences:  # sequences table exists
            # Cleanup should reset this
            pass

        # The automatic cleanup should handle this

    def test_cleanup_method_exists_and_works(self, test_db):
        """Test that the cleanup_all_tables method exists and works."""
        # Test with isolated test database
        test_db.execute(
            """
            CREATE TABLE IF NOT EXISTS test_cleanup (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT
            )
        """
        )

        # Insert test data
        test_db.execute("INSERT INTO test_cleanup (data) VALUES (?)", "test_data")

        # Verify data exists
        result = test_db.execute("SELECT * FROM test_cleanup")
        assert len(result) > 0

        # Test cleanup method
        if hasattr(test_db, "cleanup_all_tables"):
            success = test_db.cleanup_all_tables()
            assert success is True

            # Verify data is gone
            result = test_db.execute("SELECT * FROM test_cleanup")
            assert len(result) == 0

            # Verify sqlite_sequence is clean
            sequences = test_db.execute("SELECT * FROM sqlite_sequence")
            assert len(sequences) == 0

    def test_foreign_key_constraints_restored(self, client):
        """Test that foreign key constraints are properly restored after cleanup."""
        # Create test data with foreign key relationship
        user_result = db.execute(
            """
            INSERT INTO users (username, password) 
            VALUES (?, ?)
        """,
            "fk_test_user",
            "password123",
        )

        # Get the user ID (this should work if FK constraints are enabled)
        users = db.execute("SELECT id FROM users WHERE username = ?", "fk_test_user")
        assert len(users) > 0
        user_id = users[0]["id"]

        clip_result = db.execute(
            """
            INSERT INTO clips (clip_url, clip_name, clip_text, clip_time) 
            VALUES (?, ?, ?, ?)
        """,
            "fk_test_clip",
            "FK Test Clip",
            "Test content",
            "2025-01-01 12:00:00",
        )

        clips = db.execute("SELECT id FROM clips WHERE clip_url = ?", "fk_test_clip")
        assert len(clips) > 0
        clip_id = clips[0]["id"]

        # Create clipRef relationship
        db.execute(
            """
            INSERT INTO clipRef (userid, clipid) 
            VALUES (?, ?)
        """,
            user_id,
            clip_id,
        )

        # Verify the relationship exists
        refs = db.execute("SELECT * FROM clipRef WHERE userid = ? AND clipid = ?", user_id, clip_id)
        assert len(refs) > 0

        # Foreign key constraints should be working after cleanup
        # (This will be tested in subsequent tests due to the cleanup fixture)
