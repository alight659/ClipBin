import pytest
import tempfile
import os
from app import app, db
from sqlite import SQLite
from io import BytesIO


def cleanup_database(database_instance):
    """
    Completely clean up the database, including all tables and sqlite_sequence.
    This ensures a fresh state for each test.
    """
    try:
        # Use the new cleanup method if available
        if hasattr(database_instance, 'cleanup_all_tables'):
            success = database_instance.cleanup_all_tables()
            if success:
                return
        
        # Fallback to manual cleanup if the method doesn't exist or fails
        # Disable foreign key constraints temporarily for cleanup
        database_instance.execute("PRAGMA foreign_keys = OFF")
        
        # Get all table names
        tables_result = database_instance.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
        
        if tables_result:
            tables = [row['name'] for row in tables_result]
            
            # Delete all data from tables
            for table in tables:
                database_instance.execute(f"DELETE FROM {table}")
            
            # Reset the sqlite_sequence table to reset autoincrement counters
            database_instance.execute("DELETE FROM sqlite_sequence")
        
        # Re-enable foreign key constraints
        database_instance.execute("PRAGMA foreign_keys = ON")
        
    except Exception as e:
        # If cleanup fails, log the error but continue
        import logging
        logging.warning(f"Database cleanup warning: {e}")


@pytest.fixture(autouse=True)
def cleanup_before_and_after_test():
    """
    Automatically clean up the database before and after each test.
    This fixture runs automatically for all tests.
    """
    # Clean up before test
    cleanup_database(db)
    
    yield
    
    # Clean up after test
    cleanup_database(db)


@pytest.fixture
def client():
    """Create a test client for the Flask application."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECRET_KEY'] = 'test_secret_key'
    
    # Ensure clean database state
    cleanup_database(db)
    
    with app.test_client() as client:
        with app.app_context():
            # Initialize test database
            init_test_db()
        yield client
    
    # Final cleanup after client is done
    cleanup_database(db)


@pytest.fixture
def test_db():
    """Create a test database instance with proper cleanup."""
    db_fd, db_path = tempfile.mkstemp()
    test_sqlite = SQLite(db_path)
    
    # Initialize test database with required tables
    init_test_db_with_sqlite(test_sqlite)
    
    yield test_sqlite
    
    # Clean up the test database completely
    try:
        cleanup_database(test_sqlite)
    except:
        pass  # Database might already be cleaned up
    
    # Close and remove the temporary database file
    try:
        os.close(db_fd)
        os.unlink(db_path)
    except:
        pass  # File might already be removed


def init_test_db():
    """Initialize the test database with required tables."""
    # Create required tables for testing
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            PRIMARY KEY(id AUTOINCREMENT)
        )
    """)
    
    db.execute("""
        CREATE TABLE IF NOT EXISTS clips (
            id INTEGER NOT NULL UNIQUE,
            clip_url TEXT NOT NULL UNIQUE,
            clip_name TEXT,
            clip_text TEXT,
            clip_pwd TEXT,
            is_editable INTEGER,
            is_unlisted INTEGER,
            clip_time TEXT,
            update_time TEXT,
            delete_time TEXT,
            PRIMARY KEY(id AUTOINCREMENT)
        )
    """)
    
    db.execute("""
        CREATE TABLE IF NOT EXISTS clipRef(
            id INTEGER NOT NULL UNIQUE,
            userid INTEGER,
            clipid INTEGER,
            PRIMARY KEY(id AUTOINCREMENT),
            FOREIGN KEY(clipid) REFERENCES clips(id) ON DELETE CASCADE,
            FOREIGN KEY(userid) REFERENCES users(id)
        )
    """)


def init_test_db_with_sqlite(sqlite_instance):
    """Initialize a SQLite instance with required tables."""
    sqlite_instance.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            PRIMARY KEY(id AUTOINCREMENT)
        )
    """)
    
    sqlite_instance.execute("""
        CREATE TABLE IF NOT EXISTS clips (
            id INTEGER NOT NULL UNIQUE,
            clip_url TEXT NOT NULL UNIQUE,
            clip_name TEXT,
            clip_text TEXT,
            clip_pwd TEXT,
            is_editable INTEGER,
            is_unlisted INTEGER,
            clip_time TEXT,
            update_time TEXT,
            delete_time TEXT,
            PRIMARY KEY(id AUTOINCREMENT)
        )
    """)
    
    sqlite_instance.execute("""
        CREATE TABLE IF NOT EXISTS clipRef(
            id INTEGER NOT NULL UNIQUE,
            userid INTEGER,
            clipid INTEGER,
            PRIMARY KEY(id AUTOINCREMENT),
            FOREIGN KEY(clipid) REFERENCES clips(id) ON DELETE CASCADE,
            FOREIGN KEY(userid) REFERENCES users(id)
        )
    """)


@pytest.fixture
def sample_user_data():
    """Provide sample user data for testing."""
    return {
        'uname': 'testuser',
        'passwd': 'testpassword123',
        'passwdconf': 'testpassword123'
    }


@pytest.fixture
def sample_clip_data():
    """Provide sample clip data for testing."""
    return {
        'clip_name': 'Test Clip',
        'clip_text': 'This is a test clip content',
        'clip_passwd': '',
        'clip_edit': None,
        'clip_disp': None,
        'clip_alias': 'testclip',
        'clip_delete': 'day',
        'clip_custom_delete': '',
        'clip_file': (BytesIO(b''), '')  # Empty file
    }


@pytest.fixture
def authenticated_client(client, sample_user_data):
    """Create an authenticated client with a logged-in user."""
    # Register user
    client.post('/register', data=sample_user_data)
    
    # Login user
    client.post('/login', data={
        'uname': sample_user_data['uname'],
        'passwd': sample_user_data['passwd']
    })
    
    return client