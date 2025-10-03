"""
Unit tests for the additional utility functions module.
"""

import pytest
import base64
from unittest.mock import patch, MagicMock
from additional import (
    gen_id,
    login_required,
    stat,
    file_check,
    keygen,
    encrypt,
    decrypt,
    validate_alias,
    jsonfy,
    csvfy,
    textify,
)
from flask import Flask, session


class TestGenId:
    """Test cases for the gen_id function."""

    def test_gen_id_returns_string(self):
        """Test that gen_id returns a string."""
        result = gen_id()
        assert isinstance(result, str)

    def test_gen_id_length(self):
        """Test that gen_id returns a 7-character string."""
        result = gen_id()
        assert len(result) == 7

    def test_gen_id_uniqueness(self):
        """Test that gen_id generates unique IDs."""
        ids = [gen_id() for _ in range(100)]
        assert len(set(ids)) == 100  # All IDs should be unique

    def test_gen_id_characters(self):
        """Test that gen_id only contains valid URL-safe characters."""
        result = gen_id()
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        assert all(char in valid_chars for char in result)


class TestLoginRequired:
    """Test cases for the login_required decorator."""

    def test_login_required_with_authenticated_user(self):
        """Test login_required allows access for authenticated users."""
        app = Flask(__name__)
        app.secret_key = "test_key"

        @login_required
        def protected_view():
            return "Protected content"

        with app.test_request_context():
            with app.test_client() as client:
                with client.session_transaction() as sess:
                    sess["user_id"] = 1

                with app.test_request_context():
                    session["user_id"] = 1
                    result = protected_view()
                    assert result == "Protected content"

    def test_login_required_without_authentication(self):
        """Test login_required redirects unauthenticated users."""
        app = Flask(__name__)
        app.secret_key = "test_key"

        @login_required
        def protected_view():
            return "Protected content"

        with app.test_request_context():
            result = protected_view()
            assert result.status_code == 302  # Redirect
            assert "/login" in result.location


class TestStat:
    """Test cases for the stat function."""

    def test_stat_zero_returns_no(self):
        """Test that stat(0) returns 'No'."""
        assert stat(0) == "No"

    def test_stat_one_returns_yes(self):
        """Test that stat(1) returns 'Yes'."""
        assert stat(1) == "Yes"

    def test_stat_other_values(self):
        """Test stat with other values."""
        assert stat(2) is None
        assert stat(-1) is None
        assert stat("string") is None


class TestFileCheck:
    """Test cases for the file_check function."""

    def test_file_check_valid_extensions(self):
        """Test file_check with valid file extensions."""
        valid_files = [
            "test.txt",
            "readme.md",
            "data.csv",
            "config.json",
            "style.css",
            "script.js",
            "main.py",
            "App.java",
            "program.c",
            "header.h",
            "index.html",
        ]
        for filename in valid_files:
            assert file_check(filename) is True

    def test_file_check_invalid_extensions(self):
        """Test file_check with invalid file extensions."""
        invalid_files = ["image.jpg", "video.mp4", "audio.mp3", "document.pdf", "archive.zip", "executable.exe"]
        for filename in invalid_files:
            assert file_check(filename) is False

    def test_file_check_no_extension(self):
        """Test file_check with files without extensions."""
        assert file_check("filename") is False
        assert file_check("README") is False

    def test_file_check_case_insensitive(self):
        """Test that file_check is case insensitive."""
        assert file_check("TEST.TXT") is True
        assert file_check("Script.JS") is True
        assert file_check("DATA.CSV") is True

    def test_file_check_multiple_dots(self):
        """Test file_check with multiple dots in filename."""
        assert file_check("backup.data.txt") is True
        assert file_check("config.dev.json") is True


class TestKeygen:
    """Test cases for the keygen function."""

    def test_keygen_returns_bytes(self):
        """Test that keygen returns bytes."""
        salt = b"test_salt_16_bytes"
        result = keygen("password", salt)
        assert isinstance(result, bytes)

    def test_keygen_key_length(self):
        """Test that keygen returns 32-byte key."""
        salt = b"test_salt_16_bytes"
        result = keygen("password", salt)
        assert len(result) == 32

    def test_keygen_same_input_same_output(self):
        """Test that same password and salt produce same key."""
        salt = b"test_salt_16_bytes"
        password = "test_password"
        key1 = keygen(password, salt)
        key2 = keygen(password, salt)
        assert key1 == key2

    def test_keygen_different_salt_different_output(self):
        """Test that different salts produce different keys."""
        password = "test_password"
        salt1 = b"test_salt_16_byte1"
        salt2 = b"test_salt_16_byte2"
        key1 = keygen(password, salt1)
        key2 = keygen(password, salt2)
        assert key1 != key2


class TestEncryptDecrypt:
    """Test cases for encrypt and decrypt functions."""

    def test_encrypt_returns_bytes(self):
        """Test that encrypt returns bytes."""
        result = encrypt(b"test_data", "password")
        assert isinstance(result, bytes)

    def test_encrypt_decrypt_roundtrip(self):
        """Test that data can be encrypted and then decrypted."""
        original_data = b"This is test data to encrypt"
        password = "test_password"

        encrypted = encrypt(original_data, password)
        decrypted = decrypt(encrypted, password)

        assert decrypted == original_data

    def test_encrypt_different_passwords_different_output(self):
        """Test that different passwords produce different encrypted output."""
        data = b"test_data"
        encrypted1 = encrypt(data, "password1")
        encrypted2 = encrypt(data, "password2")
        assert encrypted1 != encrypted2

    def test_decrypt_wrong_password_returns_exception(self):
        """Test that decryption with wrong password raises exception."""
        data = b"test_data"
        password = "correct_password"
        wrong_password = "wrong_password"

        encrypted = encrypt(data, password)

        # Decryption with wrong password should raise an exception
        with pytest.raises(Exception):
            decrypt(encrypted, wrong_password)

    def test_encrypt_empty_bytes(self):
        """Test encrypting empty bytes."""
        encrypted = encrypt(b"", "password")
        decrypted = decrypt(encrypted, "password")
        assert decrypted == b""

    def test_decrypt_invalid_data(self):
        """Test decrypting invalid data raises exception."""
        with pytest.raises(Exception):
            decrypt(b"invalid_encrypted_data", "password")


class TestValidateAlias:
    """Test cases for the validate_alias function."""

    def test_validate_alias_valid_lengths(self):
        """Test validate_alias with valid lengths (4-12 characters)."""
        assert validate_alias("test") is True  # 4 chars
        assert validate_alias("testing") is True  # 7 chars
        assert validate_alias("testingalias") is True  # 12 chars

    def test_validate_alias_invalid_lengths(self):
        """Test validate_alias with invalid lengths."""
        assert validate_alias("abc") is False  # 3 chars (too short)
        assert validate_alias("testingaliaslong") is False  # 16 chars (too long)
        assert validate_alias("") is False  # 0 chars

    def test_validate_alias_valid_characters(self):
        """Test validate_alias with valid characters."""
        assert validate_alias("test123") is True
        assert validate_alias("test_alias") is True
        assert validate_alias("test-alias") is True
        assert validate_alias("TestAlias") is True

    def test_validate_alias_invalid_characters(self):
        """Test validate_alias with invalid characters."""
        assert validate_alias("test@alias") is False
        assert validate_alias("test alias") is False  # space
        assert validate_alias("test.alias") is False
        assert validate_alias("test#alias") is False

    def test_validate_alias_none_input(self):
        """Test validate_alias with None input."""
        with pytest.raises(TypeError):
            validate_alias(None)


class TestJsonfy:
    """Test cases for the jsonfy function."""

    def test_jsonfy_valid_data(self):
        """Test jsonfy with valid data."""
        data = [{"id": 1, "name": "Test"}, {"id": 2, "name": "Another Test"}]
        result = jsonfy(data)
        assert hasattr(result, "read")  # It's a BytesIO object
        content = result.read().decode("utf-8")
        assert '"id": 1' in content
        assert '"name": "Test"' in content

    def test_jsonfy_empty_list(self):
        """Test jsonfy with empty list."""
        result = jsonfy([])
        content = result.read().decode("utf-8")
        assert content.strip() == "[]"

    def test_jsonfy_single_item(self):
        """Test jsonfy with single item."""
        data = [{"id": 1, "name": "Single"}]
        result = jsonfy(data)
        content = result.read().decode("utf-8")
        assert '"id": 1' in content
        assert '"name": "Single"' in content


class TestCsvfy:
    """Test cases for the csvfy function."""

    def test_csvfy_valid_data(self):
        """Test csvfy with valid data."""
        data = [{"id": 1, "name": "Test"}, {"id": 2, "name": "Another"}]
        result = csvfy(data)
        assert isinstance(result, str)
        assert "id,name" in result
        assert "1,Test" in result
        assert "2,Another" in result

    def test_csvfy_empty_list(self):
        """Test csvfy with empty list."""
        result = csvfy([])
        assert result == ""

    def test_csvfy_single_item(self):
        """Test csvfy with single item."""
        data = [{"id": 1, "name": "Single"}]
        result = csvfy(data)
        assert "id,name" in result
        assert "1,Single" in result


class TestTextify:
    """Test cases for the textify function."""

    def test_textify_valid_data(self):
        """Test textify with valid data."""
        data = [
            {"id": 1, "name": "Test", "text": "Test content", "time": "2023-01-01"},
            {"id": 2, "name": "Another", "text": "Another content", "time": "2023-01-02"},
        ]
        result = textify(data)
        assert isinstance(result, str)
        assert "ID: 1" in result
        assert "Name: Test" in result
        assert "Text: Test content" in result
        assert "ID: 2" in result
        assert "Name: Another" in result

    def test_textify_empty_list(self):
        """Test textify with empty list."""
        result = textify([])
        assert result == ""

    def test_textify_single_item(self):
        """Test textify with single item."""
        data = [{"id": 1, "name": "Single", "text": "Single content", "time": "2023-01-01"}]
        result = textify(data)
        assert "ID: 1" in result
        assert "Name: Single" in result
        assert "Text: Single content" in result
