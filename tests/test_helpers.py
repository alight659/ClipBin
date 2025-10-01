"""
Mock data and utilities for testing the ClipBin application.
"""

import tempfile
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash


class MockData:
    """Class containing mock data for testing."""
    
    @staticmethod
    def get_sample_users():
        """Get sample user data for testing."""
        return [
            {
                'id': 1,
                'username': 'testuser1',
                'password_hash': generate_password_hash('password123'),
                'email': 'test1@example.com',
                'created_at': datetime.now()
            },
            {
                'id': 2,
                'username': 'testuser2',
                'password_hash': generate_password_hash('password456'),
                'email': 'test2@example.com',
                'created_at': datetime.now()
            }
        ]
    
    @staticmethod
    def get_sample_clips():
        """Get sample clip data for testing."""
        return [
            {
                'id': 1,
                'clip_id': 'abc123',
                'name': 'Test Clip 1',
                'content': 'This is the content of test clip 1',
                'password_hash': None,
                'is_editable': 0,
                'is_unlisted': 0,
                'alias': 'testclip1',
                'user_id': 1,
                'created_at': datetime.now(),
                'expires_at': datetime.now() + timedelta(days=1)
            },
            {
                'id': 2,
                'clip_id': 'def456',
                'name': 'Protected Clip',
                'content': 'This is protected content',
                'password_hash': generate_password_hash('clippass'),
                'is_editable': 1,
                'is_unlisted': 1,
                'alias': None,
                'user_id': 2,
                'created_at': datetime.now(),
                'expires_at': datetime.now() + timedelta(weeks=1)
            },
            {
                'id': 3,
                'clip_id': 'ghi789',
                'name': 'Public Clip',
                'content': 'def main():\n    print("Hello, World!")\n\nif __name__ == "__main__":\n    main()',
                'password_hash': None,
                'is_editable': 0,
                'is_unlisted': 0,
                'alias': 'hello',
                'user_id': None,
                'created_at': datetime.now(),
                'expires_at': datetime.now() + timedelta(days=30)
            }
        ]
    
    @staticmethod
    def get_valid_file_extensions():
        """Get list of valid file extensions for testing."""
        return [
            'txt', 'md', 'csv', 'json', 'xml', 'html', 'css', 'js',
            'py', 'java', 'c', 'cpp', 'cs', 'h', 'php', 'rb', 'go',
            'sh', 'bat', 'pl', 'r', 'kt', 'swift', 'ts'
        ]
    
    @staticmethod
    def get_invalid_file_extensions():
        """Get list of invalid file extensions for testing."""
        return [
            'exe', 'dll', 'so', 'dylib', 'jpg', 'png', 'gif', 'pdf',
            'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar',
            '7z', 'tar', 'gz', 'mp3', 'mp4', 'avi', 'mov'
        ]
    
    @staticmethod
    def get_test_file_contents():
        """Get various test file contents."""
        return {
            'python': {
                'content': 'def hello():\n    print("Hello, World!")\n\nhello()',
                'filename': 'hello.py'
            },
            'javascript': {
                'content': 'function hello() {\n    console.log("Hello, World!");\n}\n\nhello();',
                'filename': 'hello.js'
            },
            'html': {
                'content': '<!DOCTYPE html>\n<html>\n<head>\n    <title>Test</title>\n</head>\n<body>\n    <h1>Hello, World!</h1>\n</body>\n</html>',
                'filename': 'index.html'
            },
            'css': {
                'content': 'body {\n    font-family: Arial, sans-serif;\n    margin: 0;\n    padding: 20px;\n}',
                'filename': 'style.css'
            },
            'json': {
                'content': '{\n    "name": "test",\n    "version": "1.0.0",\n    "description": "Test JSON file"\n}',
                'filename': 'data.json'
            },
            'csv': {
                'content': 'Name,Age,City\nJohn Doe,30,New York\nJane Smith,25,Los Angeles',
                'filename': 'data.csv'
            }
        }
    
    @staticmethod
    def get_xss_test_strings():
        """Get XSS test strings for security testing."""
        return [
            '<script>alert("XSS")</script>',
            '<img src="x" onerror="alert(\'XSS\')">',
            'javascript:alert("XSS")',
            '<svg onload="alert(\'XSS\')">',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>',
            '"><script>alert("XSS")</script>',
            "'; alert('XSS'); //",
            '<body onload="alert(\'XSS\')">',
        ]
    
    @staticmethod
    def get_sql_injection_strings():
        """Get SQL injection test strings for security testing."""
        return [
            "'; DROP TABLE users; --",
            "admin'--",
            "admin'/*",
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1'; INSERT INTO users VALUES('hacker','pass'); --",
            "' OR 'a'='a",
            "') OR '1'='1--",
            "admin'; --",
        ]
    
    @staticmethod
    def get_long_strings():
        """Get various long strings for testing limits."""
        return {
            'short': 'a' * 10,
            'medium': 'b' * 100,
            'long': 'c' * 1000,
            'very_long': 'd' * 10000,
            'extreme': 'e' * 100000,
        }
    
    @staticmethod
    def get_unicode_test_strings():
        """Get Unicode test strings for internationalization testing."""
        return [
            'Hello, 世界',  # Chinese
            'مرحبا بالعالم',  # Arabic
            'Привет, мир',  # Russian
            'こんにちは世界',  # Japanese
            '🌍🚀✨🎉💻',  # Emojis
            'Ñandú Café',  # Spanish with accents
            'naïve résumé',  # French with accents
            'Ελληνικά',  # Greek
            'עברית',  # Hebrew
            'हिन्दी',  # Hindi
        ]
    
    @staticmethod
    def get_special_characters():
        """Get special characters for testing."""
        return [
            '!@#$%^&*()',
            '[]{}|\\;:\'",.<>?',
            '~`-_=+',
            '№§©®™',
            '€£¥¢',
            '°±×÷',
            'αβγδε',
            '∑∏∆∇',
        ]


class TestHelpers:
    """Helper functions for testing."""
    
    @staticmethod
    def create_temp_file(content, filename=None):
        """Create a temporary file with given content."""
        fd, path = tempfile.mkstemp(suffix=filename)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as tmp:
                tmp.write(content)
        except:
            os.close(fd)
            raise
        return path
    
    @staticmethod
    def create_temp_binary_file(content, filename=None):
        """Create a temporary binary file with given content."""
        fd, path = tempfile.mkstemp(suffix=filename)
        try:
            with os.fdopen(fd, 'wb') as tmp:
                tmp.write(content)
        except:
            os.close(fd)
            raise
        return path
    
    @staticmethod
    def cleanup_temp_file(path):
        """Clean up a temporary file."""
        try:
            os.unlink(path)
        except (OSError, FileNotFoundError):
            pass
    
    @staticmethod
    def assert_response_contains(response, text):
        """Assert that response contains specific text."""
        content = response.get_data(as_text=True)
        assert text in content, f"Text '{text}' not found in response"
    
    @staticmethod
    def assert_response_not_contains(response, text):
        """Assert that response does not contain specific text."""
        content = response.get_data(as_text=True)
        assert text not in content, f"Text '{text}' found in response but shouldn't be"
    
    @staticmethod
    def extract_csrf_token(response):
        """Extract CSRF token from response (if implemented)."""
        # This would be implemented if CSRF protection is added
        return None
    
    @staticmethod
    def get_flash_messages(response):
        """Extract flash messages from response."""
        # This would need to be implemented based on how flash messages are rendered
        return []