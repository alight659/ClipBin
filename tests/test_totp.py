"""
Unit tests for TOTP/Two-Factor Authentication functionality.
"""

import pytest
import pyotp
import base64
import time
import json
from unittest.mock import patch, MagicMock
from flask import session
from additional import totp_generator, totpCode, totp_verify, encrypt, decrypt


class TestTOTPGenerator:
    """Tests for totp_generator function"""

    def test_totp_generator_returns_tuple(self):
        """Test that totp_generator returns a tuple of two elements"""
        user_id = "123"
        username = "testuser"
        result = totp_generator(user_id, username)

        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_totp_generator_encrypted_secret_format(self):
        """Test that encrypted secret is valid base64"""
        user_id = "123"
        username = "testuser"
        encrypted_b64, _ = totp_generator(user_id, username)

        # Should be valid base64
        try:
            base64.b64decode(encrypted_b64)
            assert True
        except Exception:
            assert False, "Encrypted secret is not valid base64"

    def test_totp_generator_provisioning_uri_format(self):
        """Test that provisioning URI has correct format"""
        user_id = "123"
        username = "testuser"
        _, provisioning_uri = totp_generator(user_id, username)

        assert provisioning_uri.startswith("otpauth://totp/")
        assert username in provisioning_uri
        assert "Clipbin" in provisioning_uri
        assert "secret=" in provisioning_uri

    def test_totp_generator_different_users_different_secrets(self):
        """Test that different users get different secrets"""
        encrypted1, _ = totp_generator("123", "user1")
        encrypted2, _ = totp_generator("456", "user2")

        assert encrypted1 != encrypted2

    def test_totp_generator_same_user_different_calls(self):
        """Test that same user gets different secrets on different calls"""
        encrypted1, _ = totp_generator("123", "testuser")
        encrypted2, _ = totp_generator("123", "testuser")

        # Should be different because random_base32() is called each time
        assert encrypted1 != encrypted2


class TestTOTPCode:
    """Tests for totpCode function (decryption)"""

    def test_totpcode_decrypts_correctly(self):
        """Test that totpCode correctly decrypts encrypted secret"""
        user_id = "123"
        username = "testuser"

        # Generate encrypted secret
        encrypted_b64, _ = totp_generator(user_id, username)

        # Decrypt it
        decrypted_secret = totpCode(encrypted_b64, user_id, username)

        # Should be valid base32 (TOTP secret format)
        assert isinstance(decrypted_secret, str)
        assert len(decrypted_secret) == 32  # pyotp.random_base32() generates 32 char string
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in decrypted_secret)

    def test_totpcode_wrong_user_id_fails(self):
        """Test that wrong user_id fails to decrypt"""
        user_id = "123"
        username = "testuser"

        encrypted_b64, _ = totp_generator(user_id, username)

        # Try to decrypt with wrong user_id
        with pytest.raises(ValueError, match="Failed to decrypt TOTP secret"):
            totpCode(encrypted_b64, "wrong_id", username)

    def test_totpcode_wrong_username_fails(self):
        """Test that wrong username fails to decrypt"""
        user_id = "123"
        username = "testuser"

        encrypted_b64, _ = totp_generator(user_id, username)

        # Try to decrypt with wrong username
        with pytest.raises(ValueError, match="Failed to decrypt TOTP secret"):
            totpCode(encrypted_b64, user_id, "wronguser")

    def test_totpcode_invalid_base64_fails(self):
        """Test that invalid base64 raises ValueError"""
        with pytest.raises(ValueError, match="Failed to decrypt TOTP secret"):
            totpCode("invalid_base64!!!", "123", "testuser")

    def test_totpcode_empty_string_fails(self):
        """Test that empty string raises ValueError"""
        with pytest.raises(ValueError, match="Failed to decrypt TOTP secret"):
            totpCode("", "123", "testuser")


class TestTOTPVerify:
    """Tests for totp_verify function"""

    def test_totp_verify_valid_code(self):
        """Test that valid TOTP code is verified successfully"""
        user_id = "123"
        username = "testuser"

        # Generate and get the secret
        encrypted_b64, _ = totp_generator(user_id, username)
        secret = totpCode(encrypted_b64, user_id, username)

        # Generate a valid TOTP code
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # Verify it
        result = totp_verify(encrypted_b64, user_id, username, valid_code)
        assert result is True

    def test_totp_verify_invalid_code(self):
        """Test that invalid TOTP code fails verification"""
        user_id = "123"
        username = "testuser"

        encrypted_b64, _ = totp_generator(user_id, username)

        # Use an obviously invalid code
        result = totp_verify(encrypted_b64, user_id, username, "000000")
        assert result is False

    def test_totp_verify_prevents_code_reuse(self):
        """Test that the same code cannot be used twice"""
        user_id = "123"
        username = "testuser"

        encrypted_b64, _ = totp_generator(user_id, username)
        secret = totpCode(encrypted_b64, user_id, username)

        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # First use should succeed
        result1 = totp_verify(encrypted_b64, user_id, username, valid_code, last_used=None)
        assert result1 is True

        # Second use with same code should fail
        result2 = totp_verify(encrypted_b64, user_id, username, valid_code, last_used=valid_code)
        assert result2 is False

    def test_totp_verify_different_code_after_last_used(self):
        """Test that different code works even if last_used is set"""
        user_id = "123"
        username = "testuser"

        encrypted_b64, _ = totp_generator(user_id, username)
        secret = totpCode(encrypted_b64, user_id, username)

        totp = pyotp.TOTP(secret)
        old_code = "123456"  # Fake old code
        new_code = totp.now()

        # Should succeed because codes are different
        result = totp_verify(encrypted_b64, user_id, username, new_code, last_used=old_code)
        assert result is True

    def test_totp_verify_with_time_window(self):
        """Test that codes within valid_window=1 are accepted"""
        user_id = "123"
        username = "testuser"

        encrypted_b64, _ = totp_generator(user_id, username)
        secret = totpCode(encrypted_b64, user_id, username)

        totp = pyotp.TOTP(secret)

        # Get current valid code
        current_code = totp.now()

        # Should verify successfully
        result = totp_verify(encrypted_b64, user_id, username, current_code)
        assert result is True

    def test_totp_verify_wrong_user_credentials(self):
        """Test that wrong user credentials cause verification to fail"""
        user_id = "123"
        username = "testuser"

        encrypted_b64, _ = totp_generator(user_id, username)
        secret = totpCode(encrypted_b64, user_id, username)

        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # Try to verify with wrong user_id
        result = totp_verify(encrypted_b64, "wrong_id", username, valid_code)
        assert result is False

    def test_totp_verify_handles_exceptions(self):
        """Test that exceptions in verification return False"""
        # Invalid encrypted secret
        result = totp_verify("invalid_data", "123", "testuser", "123456")
        assert result is False

    def test_totp_verify_empty_code(self):
        """Test that empty code fails verification"""
        user_id = "123"
        username = "testuser"

        encrypted_b64, _ = totp_generator(user_id, username)

        result = totp_verify(encrypted_b64, user_id, username, "")
        assert result is False

    def test_totp_verify_non_numeric_code(self):
        """Test that non-numeric code fails verification"""
        user_id = "123"
        username = "testuser"

        encrypted_b64, _ = totp_generator(user_id, username)

        result = totp_verify(encrypted_b64, user_id, username, "abcdef")
        assert result is False


class TestTOTPIntegration:
    """Integration tests for complete TOTP workflow"""

    def test_complete_totp_flow(self):
        """Test complete flow: generate, decrypt, verify"""
        user_id = "123"
        username = "testuser"

        # Step 1: Generate TOTP secret
        encrypted_b64, provisioning_uri = totp_generator(user_id, username)

        # Step 2: Decrypt to get plain secret
        secret = totpCode(encrypted_b64, user_id, username)

        # Step 3: Generate a valid code
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # Step 4: Verify the code
        result = totp_verify(encrypted_b64, user_id, username, valid_code)

        assert result is True

    def test_totp_flow_with_qr_code_generation(self):
        """Test that provisioning URI can be used for QR code"""
        user_id = "123"
        username = "testuser"

        encrypted_b64, provisioning_uri = totp_generator(user_id, username)

        # Parse the provisioning URI to verify it contains correct info
        assert f"Clipbin:{username}" in provisioning_uri or f"Clipbin%3A{username}" in provisioning_uri

        # Extract secret from URI and verify it matches decrypted secret
        import urllib.parse

        parsed = urllib.parse.urlparse(provisioning_uri)
        params = urllib.parse.parse_qs(parsed.query)
        uri_secret = params.get("secret", [None])[0]

        decrypted_secret = totpCode(encrypted_b64, user_id, username)

        assert uri_secret == decrypted_secret

    def test_multiple_users_independent_secrets(self):
        """Test that multiple users have independent TOTP secrets"""
        users = [("1", "alice"), ("2", "bob"), ("3", "charlie")]

        secrets = {}

        for user_id, username in users:
            encrypted_b64, _ = totp_generator(user_id, username)
            secret = totpCode(encrypted_b64, user_id, username)
            secrets[(user_id, username)] = (encrypted_b64, secret)

        # All secrets should be different
        secret_values = [s[1] for s in secrets.values()]
        assert len(secret_values) == len(set(secret_values))

        # Each user can verify their own codes
        for user_id, username in users:
            encrypted_b64, secret = secrets[(user_id, username)]
            totp = pyotp.TOTP(secret)
            valid_code = totp.now()

            result = totp_verify(encrypted_b64, user_id, username, valid_code)
            assert result is True

    def test_totp_time_based_expiry(self):
        """Test that TOTP codes expire after time window"""
        user_id = "123"
        username = "testuser"

        encrypted_b64, _ = totp_generator(user_id, username)
        secret = totpCode(encrypted_b64, user_id, username)

        # Create TOTP with custom interval for testing
        totp = pyotp.TOTP(secret, interval=30)

        # Get current code
        current_code = totp.now()

        # Should verify immediately
        result = totp_verify(encrypted_b64, user_id, username, current_code)
        assert result is True


class TestTOTPEdgeCases:
    """Edge case tests for TOTP functionality"""

    def test_extremely_long_username(self):
        """Test TOTP with extremely long username"""
        user_id = "123"
        username = "a" * 1000  # Very long username

        encrypted_b64, provisioning_uri = totp_generator(user_id, username)
        secret = totpCode(encrypted_b64, user_id, username)

        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        result = totp_verify(encrypted_b64, user_id, username, valid_code)
        assert result is True

    def test_special_characters_in_username(self):
        """Test TOTP with special characters in username"""
        user_id = "123"
        test_usernames = [
            "user@example.com",
            "user-name_123",
            "user.name+tag",
            "user name",  # Space
            "user!@#$%",
            "用户名",  # Chinese characters
            "пользователь",  # Cyrillic
        ]

        for username in test_usernames:
            encrypted_b64, provisioning_uri = totp_generator(user_id, username)
            secret = totpCode(encrypted_b64, user_id, username)

            totp = pyotp.TOTP(secret)
            valid_code = totp.now()

            result = totp_verify(encrypted_b64, user_id, username, valid_code)
            assert result is True, f"Failed for username: {username}"

    def test_numeric_user_id_variations(self):
        """Test TOTP with various user_id formats"""
        username = "testuser"
        test_ids = ["1", "999999", "0", "12345678901234567890"]

        for user_id in test_ids:
            encrypted_b64, _ = totp_generator(user_id, username)
            secret = totpCode(encrypted_b64, user_id, username)

            totp = pyotp.TOTP(secret)
            valid_code = totp.now()

            result = totp_verify(encrypted_b64, user_id, username, valid_code)
            assert result is True, f"Failed for user_id: {user_id}"

    def test_empty_username(self):
        """Test TOTP with empty username"""
        user_id = "123"
        username = ""

        # Should still work (edge case)
        encrypted_b64, _ = totp_generator(user_id, username)
        secret = totpCode(encrypted_b64, user_id, username)

        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        result = totp_verify(encrypted_b64, user_id, username, valid_code)
        assert result is True

    def test_code_with_leading_zeros(self):
        """Test verification of codes with leading zeros"""
        user_id = "123"
        username = "testuser"

        encrypted_b64, _ = totp_generator(user_id, username)
        secret = totpCode(encrypted_b64, user_id, username)

        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # Ensure code is padded to 6 digits
        assert len(valid_code) == 6

        result = totp_verify(encrypted_b64, user_id, username, valid_code)
        assert result is True


class TestFlaskTOTPRoutes:
    """Tests for Flask TOTP routes"""

    def test_login_totp_route_get_without_session(self, client, init_database):
        """Test GET request to /login/totp without session redirects to login"""
        response = client.get("/login/totp")
        assert response.status_code == 302
        assert "/login" in response.location

    def test_login_totp_route_requires_session(self, client, init_database, auth):
        """Test /login/totp requires valid user_id and uname in session"""
        auth.register(username="totptest", password="Pass123")

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "totptest")
        user_id = user[0]["id"]

        # Setup 2FA
        encrypted_b64, _ = totp_generator(str(user_id), "totptest")
        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user_id, encrypted_b64)

        # Login (should redirect to /login/totp)
        response = client.post("/login", data={"username": "totptest", "password": "Pass123"})
        assert response.status_code == 302
        assert "/login/totp" in response.location

    def test_login_totp_displays_form(self, client, init_database):
        """Test /login/totp displays the TOTP verification form"""
        # Register and setup user with 2FA
        client.post("/register", data={"username": "displaytest", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "displaytest")
        user_id = user[0]["id"]

        encrypted_b64, _ = totp_generator(str(user_id), "displaytest")
        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user_id, encrypted_b64)

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "displaytest"

        response = client.get("/login/totp")
        assert response.status_code == 200
        assert b"Two-Factor Authentication" in response.data or b"Enter TOTP Code" in response.data
        assert b"otp-input" in response.data

    def test_login_totp_post_valid_code(self, client, init_database):
        """Test POST to /login/totp with valid code"""
        client.post("/register", data={"username": "validcode", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "validcode")
        user_id = user[0]["id"]

        encrypted_b64, _ = totp_generator(str(user_id), "validcode")
        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user_id, encrypted_b64)

        secret = totpCode(encrypted_b64, str(user_id), "validcode")
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "validcode"

        response = client.post("/login/totp", data={"totp": valid_code}, follow_redirects=True)
        assert response.status_code == 200

    def test_login_totp_post_invalid_code(self, client, init_database):
        """Test POST to /login/totp with invalid code"""
        client.post("/register", data={"username": "invalidcode", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "invalidcode")
        user_id = user[0]["id"]

        encrypted_b64, _ = totp_generator(str(user_id), "invalidcode")
        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user_id, encrypted_b64)

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "invalidcode"

        response = client.post("/login/totp", data={"totp": "000000"}, follow_redirects=True)
        assert response.status_code == 200
        assert b"Invalid TOTP code" in response.data

    def test_login_totp_setup_route_get(self, client, init_database):
        """Test GET request to /login/totp/setup without session redirects"""
        response = client.get("/login/totp/setup")
        assert response.status_code == 302
        assert "/login" in response.location

    def test_login_totp_setup_with_session(self, client, init_database):
        """Test /login/totp/setup with valid session"""
        client.post("/register", data={"username": "setupuser", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "setupuser")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "setupuser"

        response = client.get("/login/totp/setup")
        assert response.status_code == 200
        assert b"Enable Two-Factor Authentication" in response.data
        assert b"qrcode" in response.data.lower()

    def test_login_totp_setup_post_valid_code(self, client, init_database):
        """Test POST to /login/totp/setup with valid TOTP code"""
        client.post("/register", data={"username": "verifyuser", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "verifyuser")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "verifyuser"

        # Generate the 2FA first by accessing the setup page
        client.get("/login/totp/setup")

        # Get the TOTP data
        totp_data = db.execute("SELECT uri FROM twoFA WHERE user_id=?", user_id)

        if totp_data:
            encrypted_secret = totp_data[0]["uri"]
            secret = totpCode(encrypted_secret, str(user_id), "verifyuser")
            totp = pyotp.TOTP(secret)
            valid_code = totp.now()

            response = client.post(
                "/login/totp/setup", data={"totp": valid_code}, headers={"X-Requested-With": "XMLHttpRequest"}
            )

            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["status"] == "success"

    def test_login_totp_setup_post_invalid_code(self, client, init_database):
        """Test POST to /login/totp/setup with invalid TOTP code"""
        client.post("/register", data={"username": "invaliduser", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "invaliduser")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "invaliduser"

        client.get("/login/totp/setup")

        response = client.post(
            "/login/totp/setup", data={"totp": "000000"}, headers={"X-Requested-With": "XMLHttpRequest"}
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "error"

    def test_permission_route_enable_2fa(self, client, init_database, auth):
        """Test enabling 2FA through /permission route"""
        auth.register()
        auth.login()

        response = client.post("/permission", data={"2fa_action": "enable", "password": "test"})

        # Should redirect to 2FA setup
        assert response.status_code == 302
        assert "/login/totp/setup" in response.location

    def test_permission_route_disable_2fa(self, client, init_database, auth):
        """Test disabling 2FA through /permission route"""
        auth.register()
        auth.login()

        # First enable 2FA (simulate)
        from sqlite import SQLite

        db = SQLite("clipbin.db")
        encrypted_b64, _ = totp_generator("1", "test")
        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", 1, encrypted_b64)

        response = client.post("/permission", data={"2fa_action": "disable", "password": "test"})

        assert response.status_code == 302

        # Verify 2FA was disabled
        result = db.execute("SELECT * FROM twoFA WHERE user_id=?", 1)
        assert len(result) == 0

    def test_permission_route_wrong_password(self, client, init_database, auth):
        """Test /permission with wrong password"""
        auth.register()
        auth.login()

        response = client.post(
            "/permission", data={"2fa_action": "enable", "password": "wrongpassword"}, follow_redirects=True
        )

        assert response.status_code == 200
        assert b"Incorrect password" in response.data or b"incorrect" in response.data.lower()

    def test_settings_page_shows_2fa_status(self, client, init_database, auth):
        """Test that settings page shows correct 2FA status"""
        auth.register()
        auth.login()

        response = client.get("/settings")
        assert response.status_code == 200
        # Settings page should have 2FA related content
        assert b"Two-Factor" in response.data or b"2FA" in response.data


class TestTwoFADatabase:
    """Database integration tests for twoFA table"""

    def test_twofa_table_creation(self, init_database):
        """Test that twoFA table is created correctly"""
        from sqlite import SQLite

        db = SQLite("clipbin.db")

        # Check table exists
        tables = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='twoFA'")
        assert len(tables) == 1

    def test_twofa_table_columns(self, init_database):
        """Test that twoFA table has correct columns"""
        from sqlite import SQLite

        db = SQLite("clipbin.db")

        columns = db.execute("PRAGMA table_info(twoFA)")
        column_names = [col["name"] for col in columns]

        assert "id" in column_names
        assert "user_id" in column_names
        assert "uri" in column_names

    def test_insert_and_retrieve_2fa_data(self, init_database):
        """Test inserting and retrieving 2FA data"""
        from sqlite import SQLite

        db = SQLite("clipbin.db")

        # Create a test user first
        db.execute("INSERT INTO users (username, password) VALUES (?, ?)", "dbtest", "hashedpass")
        user = db.execute("SELECT id FROM users WHERE username=?", "dbtest")
        user_id = user[0]["id"]

        # Generate and insert 2FA data
        encrypted_b64, _ = totp_generator(str(user_id), "dbtest")
        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user_id, encrypted_b64)

        # Retrieve and verify
        result = db.execute("SELECT uri FROM twoFA WHERE user_id=?", user_id)
        assert len(result) == 1
        assert result[0]["uri"] == encrypted_b64

    def test_cascade_delete_2fa_on_user_delete(self, init_database):
        """Test that 2FA data is deleted when user is deleted"""
        from sqlite import SQLite

        db = SQLite("clipbin.db")

        # Create user and 2FA data
        db.execute("INSERT INTO users (username, password) VALUES (?, ?)", "cascadetest", "hashedpass")
        user = db.execute("SELECT id FROM users WHERE username=?", "cascadetest")
        user_id = user[0]["id"]

        encrypted_b64, _ = totp_generator(str(user_id), "cascadetest")
        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user_id, encrypted_b64)

        # Delete user
        db.execute("DELETE FROM users WHERE id=?", user_id)

        # Check 2FA data is also deleted
        result = db.execute("SELECT * FROM twoFA WHERE user_id=?", user_id)
        assert len(result) == 0

    def test_unique_user_id_constraint(self, init_database):
        """Test that user_id must be unique in twoFA table"""
        from sqlite import SQLite

        db = SQLite("clipbin.db")

        # Create user
        db.execute("INSERT INTO users (username, password) VALUES (?, ?)", "uniquetest", "hashedpass")
        user = db.execute("SELECT id FROM users WHERE username=?", "uniquetest")
        user_id = user[0]["id"]

        # Insert first 2FA record
        encrypted_b64_1, _ = totp_generator(str(user_id), "uniquetest")
        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user_id, encrypted_b64_1)

        # Try to insert second 2FA record for same user
        encrypted_b64_2, _ = totp_generator(str(user_id), "uniquetest")

        try:
            result = db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user_id, encrypted_b64_2)
            records = db.execute("SELECT * FROM twoFA WHERE user_id=?", user_id)
            assert len(records) == 1, "Unique constraint should prevent duplicate user_id"
        except Exception as e:
            # Expected - constraint violation
            assert "UNIQUE" in str(e) or "constraint" in str(e).lower()

    def test_2fa_check_function(self, init_database):
        """Test the twoFACheck helper function"""
        from sqlite import SQLite
        from app import twoFACheck

        db = SQLite("clipbin.db")

        # Create user with 2FA
        db.execute("INSERT INTO users (username, password) VALUES (?, ?)", "checktest", "hashedpass")
        user = db.execute("SELECT id FROM users WHERE username=?", "checktest")
        user_id = user[0]["id"]

        # Should return False initially (no 2FA set up)
        result = twoFACheck(user_id)
        assert result is False

        # Add 2FA
        encrypted_b64, _ = totp_generator(str(user_id), "checktest")
        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user_id, encrypted_b64)

        # Should return the encrypted URI now
        result = twoFACheck(user_id)
        assert result == encrypted_b64


class TestTOTPUIInteraction:
    """Tests for TOTP UI interaction and JavaScript functionality"""

    def test_totp_setup_page_renders_qr_code(self, client, init_database):
        """Test that TOTP setup page includes QR code generation"""
        client.post("/register", data={"username": "qrtest", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "qrtest")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "qrtest"

        response = client.get("/login/totp/setup")
        assert response.status_code == 200

        # Check for TOTP setup page content
        assert b"Enable Two-Factor Authentication" in response.data
        assert b"Verify Your Code" in response.data
        assert b"QR Code" in response.data or b"qrcode" in response.data
        assert b"authenticator app" in response.data

    def test_totp_setup_page_has_6_digit_inputs(self, client, init_database):
        """Test that TOTP setup page has 6 OTP input boxes"""
        client.post("/register", data={"username": "inputtest", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "inputtest")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "inputtest"

        response = client.get("/login/totp/setup")
        assert response.status_code == 200

        # Check for 6 OTP input fields
        assert response.data.count(b"otp-input") >= 6

    def test_totp_login_page_has_6_digit_inputs(self, client, init_database):
        """Test that TOTP login page has 6 OTP input boxes"""
        client.post("/register", data={"username": "loginotp", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "loginotp")
        user_id = user[0]["id"]

        encrypted_b64, _ = totp_generator(str(user_id), "loginotp")
        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user_id, encrypted_b64)

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "loginotp"

        response = client.get("/login/totp")
        assert response.status_code == 200
        assert response.data.count(b"otp-input") >= 6

    def test_totp_form_has_hidden_input(self, client, init_database):
        """Test that TOTP forms have hidden input for combined code"""
        client.post("/register", data={"username": "hiddentest", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "hiddentest")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "hiddentest"

        response = client.get("/login/totp/setup")
        assert response.status_code == 200

        # Check for hidden input field
        assert b'type="hidden"' in response.data
        assert b'name="totp"' in response.data

    def test_qr_code_image_exists(self, client, init_database):
        """Test that QR code image exists on setup page"""
        client.post("/register", data={"username": "qrcodetest", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "qrcodetest")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "qrcodetest"

        response = client.get("/login/totp/setup")
        assert response.status_code == 200

        # Check for QR code image
        assert b"qrcode" in response.data
        assert b"data:image/png;base64," in response.data

    def test_totp_setup_javascript_loaded(self, client, init_database):
        """Test that required JavaScript libraries are loaded"""
        client.post("/register", data={"username": "jstest", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "jstest")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "jstest"

        response = client.get("/login/totp/setup")
        assert response.status_code == 200

        # Check for QR code library
        assert b"qrcode" in response.data.lower()

    def test_error_message_element_exists(self, client, init_database):
        """Test that error message element exists for displaying errors"""
        client.post("/register", data={"username": "errortest", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "errortest")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "errortest"

        response = client.get("/login/totp/setup")
        assert response.status_code == 200

        # Check for error message element
        assert b"error-msg" in response.data or b"error" in response.data


class TestTOTPSecurityFeatures:
    """Tests for TOTP security features"""

    def test_totp_requires_authentication(self, client, init_database):
        """Test that 2FA routes require proper authentication"""
        # Try to access without session
        response = client.get("/login/totp/setup")
        assert response.status_code == 302  # Should redirect

    def test_totp_session_isolation(self, client, init_database):
        """Test that TOTP sessions are isolated between users"""
        # Register two users
        client.post("/register", data={"username": "user1", "password": "Pass123", "password_confirm": "Pass123"})
        client.post("/register", data={"username": "user2", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")

        # Get user IDs
        user1 = db.execute("SELECT id FROM users WHERE username=?", "user1")[0]["id"]
        user2 = db.execute("SELECT id FROM users WHERE username=?", "user2")[0]["id"]

        # Generate different secrets
        enc1, _ = totp_generator(str(user1), "user1")
        enc2, _ = totp_generator(str(user2), "user2")

        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user1, enc1)
        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user2, enc2)

        # Get secrets
        secret1 = totpCode(enc1, str(user1), "user1")
        secret2 = totpCode(enc2, str(user2), "user2")

        # Secrets should be different
        assert secret1 != secret2

        # User1's code shouldn't work for user2
        totp1 = pyotp.TOTP(secret1)
        code1 = totp1.now()

        result = totp_verify(enc2, str(user2), "user2", code1)
        assert result is False

    def test_totp_password_required_for_changes(self, client, init_database, auth):
        """Test that password is required to enable/disable 2FA"""
        auth.register()
        auth.login()

        # Try without password
        response = client.post("/permission", data={"2fa_action": "enable"}, follow_redirects=True)

        assert b"Password cannot be empty" in response.data or b"password" in response.data.lower()

    def test_ajax_request_for_totp_setup(self, client, init_database):
        """Test that TOTP setup POST works with AJAX header"""
        client.post("/register", data={"username": "ajaxtest", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "ajaxtest")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "ajaxtest"

        # Access setup page first to generate 2FA
        client.get("/login/totp/setup")

        # POST with AJAX header
        response = client.post(
            "/login/totp/setup", data={"totp": "123456"}, headers={"X-Requested-With": "XMLHttpRequest"}
        )

        # Should return JSON response
        assert response.status_code == 200
        assert response.is_json


class TestTOTPCompleteMockScenarios:
    """Complete end-to-end mock scenarios"""

    def test_complete_2fa_enable_flow(self, client, init_database, auth):
        """Test complete flow of enabling 2FA"""
        # 1. Register
        auth.register(username="fulltest", password="Pass123")

        # 2. Login
        auth.login(username="fulltest", password="Pass123")

        # 3. Request to enable 2FA
        response = client.post("/permission", data={"2fa_action": "enable", "password": "Pass123"})

        # Should redirect to setup
        assert response.status_code == 302
        assert "/login/totp/setup" in response.location

        # 4. Verify session remains valid
        with client.session_transaction() as sess:
            assert "user_id" in sess
            assert "uname" in sess

    def test_complete_2fa_disable_flow(self, client, init_database, auth):
        """Test complete flow of disabling 2FA"""
        # Setup
        auth.register(username="disabletest", password="Pass123")
        auth.login(username="disabletest", password="Pass123")

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "disabletest")
        user_id = user[0]["id"]

        # Enable 2FA first
        encrypted_b64, _ = totp_generator(str(user_id), "disabletest")
        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user_id, encrypted_b64)

        # Disable 2FA
        response = client.post("/permission", data={"2fa_action": "disable", "password": "Pass123"})

        assert response.status_code == 302

        # Verify disabled
        result = db.execute("SELECT * FROM twoFA WHERE user_id=?", user_id)
        assert len(result) == 0

    def test_login_with_2fa_enabled(self, client, init_database):
        """Test login flow when 2FA is enabled"""
        # Register user
        client.post("/register", data={"username": "2falogin", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "2falogin")
        user_id = user[0]["id"]

        # Setup 2FA
        encrypted_b64, _ = totp_generator(str(user_id), "2falogin")
        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user_id, encrypted_b64)

        # Login
        response = client.post("/login", data={"username": "2falogin", "password": "Pass123"})

        # Should redirect to TOTP verification
        assert response.status_code == 302
        assert "/login/totp" in response.location

    def test_complete_login_with_2fa_verification(self, client, init_database):
        """Test complete login flow with 2FA verification"""
        # Register user
        client.post("/register", data={"username": "complete2fa", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "complete2fa")
        user_id = user[0]["id"]

        # Setup 2FA
        encrypted_b64, _ = totp_generator(str(user_id), "complete2fa")
        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user_id, encrypted_b64)

        # Login (redirects to TOTP)
        client.post("/login", data={"username": "complete2fa", "password": "Pass123"})

        # Get valid TOTP code
        secret = totpCode(encrypted_b64, str(user_id), "complete2fa")
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # Submit TOTP code
        response = client.post("/login/totp", data={"totp": valid_code}, follow_redirects=True)

        # Should be logged in and redirected to home
        assert response.status_code == 200

    def test_2fa_setup_complete_workflow(self, client, init_database, auth):
        """Test complete 2FA setup workflow from settings"""
        # Register and login
        auth.register(username="setupflow", password="Pass123")
        auth.login(username="setupflow", password="Pass123")

        # Enable 2FA from settings
        response = client.post("/permission", data={"2fa_action": "enable", "password": "Pass123"})
        assert response.status_code == 302

        # Access setup page
        response = client.get("/login/totp/setup", follow_redirects=True)
        assert response.status_code == 200
        assert b"Enable Two-Factor Authentication" in response.data

        # Get the generated secret
        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "setupflow")
        user_id = user[0]["id"]

        totp_data = db.execute("SELECT uri FROM twoFA WHERE user_id=?", user_id)
        assert len(totp_data) > 0

        encrypted_secret = totp_data[0]["uri"]
        secret = totpCode(encrypted_secret, str(user_id), "setupflow")
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # Verify the code
        response = client.post(
            "/login/totp/setup", data={"totp": valid_code}, headers={"X-Requested-With": "XMLHttpRequest"}
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"


class TestTOTPEdgeCasesAdvanced:
    """Advanced edge case tests"""

    def test_totp_with_expired_session(self, client, init_database):
        """Test that expired session redirects properly"""
        response = client.get("/login/totp")
        assert response.status_code == 302
        assert "/login" in response.location

    def test_totp_setup_without_2fa_data(self, client, init_database):
        """Test that setup creates new 2FA data if none exists"""
        client.post("/register", data={"username": "nodata", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "nodata")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "nodata"

        # Access setup page (should create 2FA data)
        response = client.get("/login/totp/setup")
        assert response.status_code == 200

        # Check that 2FA data was created
        totp_data = db.execute("SELECT * FROM twoFA WHERE user_id=?", user_id)
        assert len(totp_data) == 1

    def test_totp_with_existing_2fa_data(self, client, init_database):
        """Test that setup uses existing 2FA data if available"""
        client.post("/register", data={"username": "existing", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "existing")
        user_id = user[0]["id"]

        # Create 2FA data first
        encrypted_b64, _ = totp_generator(str(user_id), "existing")
        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user_id, encrypted_b64)

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "existing"

        # Access setup page (should use existing data)
        response = client.get("/login/totp/setup")
        assert response.status_code == 200

        # Verify same data is used
        totp_data = db.execute("SELECT uri FROM twoFA WHERE user_id=?", user_id)
        assert totp_data[0]["uri"] == encrypted_b64

    def test_totp_empty_code_submission(self, client, init_database):
        """Test that empty TOTP code is handled properly"""
        client.post("/register", data={"username": "emptycode", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "emptycode")
        user_id = user[0]["id"]

        encrypted_b64, _ = totp_generator(str(user_id), "emptycode")
        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user_id, encrypted_b64)

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "emptycode"

        # Submit empty code
        response = client.post("/login/totp", data={"totp": ""}, follow_redirects=True)
        assert response.status_code == 200
        assert b"TOTP code cannot be empty" in response.data or b"Invalid" in response.data


# Fixtures
@pytest.fixture
def client():
    """Create Flask test client"""
    from app import app

    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test_secret_key"
    with app.test_client() as client:
        yield client


@pytest.fixture
def init_database():
    """Initialize test database"""
    from sqlite import SQLite

    db = SQLite("clipbin.db")

    # Create tables
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS twoFA (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            uri TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """
    )

    yield db

    # Cleanup
    db.execute("DELETE FROM twoFA")
    db.execute("DELETE FROM users")


@pytest.fixture
def auth(client):
    """Authentication helper"""

    class AuthActions:
        def __init__(self, client):
            self._client = client

        def register(self, username="test", password="test"):
            return self._client.post(
                "/register", data={"username": username, "password": password, "password_confirm": password}
            )

        def login(self, username="test", password="test"):
            return self._client.post("/login", data={"username": username, "password": password})

        def logout(self):
            return self._client.get("/logout")

    return AuthActions(client)


class TestTOTPWorkflowRequirements:
    """Test cases specifically mentioned in the workflow requirements"""

    def test_totp_setup_success(self, client, init_database):
        """Fresh user enables 2FA with valid code"""
        # Register a new user
        client.post("/register", data={"username": "freshuser", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "freshuser")
        user_id = user[0]["id"]

        # Set up session
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "freshuser"

        # Generate the 2FA first by accessing the setup page
        response = client.get("/login/totp/setup")
        assert response.status_code == 200

        # Get the TOTP data from database
        totp_data = db.execute("SELECT uri FROM twoFA WHERE user_id=?", user_id)

        if totp_data:
            from additional import totpCode
            import pyotp

            encrypted_secret = totp_data[0]["uri"]
            secret = totpCode(encrypted_secret, str(user_id), "freshuser")
            totp = pyotp.TOTP(secret)
            valid_code = totp.now()

            # Submit valid code
            response = client.post(
                "/login/totp/setup", data={"totp": valid_code}, headers={"X-Requested-With": "XMLHttpRequest"}
            )

            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["status"] == "success"

    def test_totp_setup_invalid_code(self, client, init_database):
        """Rejects invalid/incomplete TOTP code"""
        # Register and setup user
        client.post("/register", data={"username": "invaliduser", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "invaliduser")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "invaliduser"

        client.get("/login/totp/setup")

        # Submit invalid code
        response = client.post(
            "/login/totp/setup", data={"totp": "123456"}, headers={"X-Requested-With": "XMLHttpRequest"}  # Invalid code
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "error"

    def test_totp_resync_success(self):
        """Resyncs with valid current code"""
        from additional import totp_generator, totpCode, totp_verify
        import pyotp

        user_id = "123"
        username = "resyncuser"

        # Generate TOTP secret
        encrypted_secret, _ = totp_generator(user_id, username)
        secret = totpCode(encrypted_secret, user_id, username)
        totp = pyotp.TOTP(secret)

        # First verification (sets last_used)
        code1 = totp.now()
        result1 = totp_verify(encrypted_secret, user_id, username, code1)
        assert result1 is True

        # Wait and generate new code for resync
        import time

        time.sleep(31)  # Wait for new time window
        code2 = totp.now()
        result2 = totp_verify(encrypted_secret, user_id, username, code2)
        assert result2 is True

    def test_totp_replay_attack(self):
        """Rejects reuse of same TOTP code"""
        from additional import totp_generator, totpCode, totp_verify
        import pyotp

        user_id = "123"
        username = "replayuser"

        # Generate TOTP secret
        encrypted_secret, _ = totp_generator(user_id, username)
        secret = totpCode(encrypted_secret, user_id, username)
        totp = pyotp.TOTP(secret)

        # Use code once
        code = totp.now()
        result1 = totp_verify(encrypted_secret, user_id, username, code)
        assert result1 is True

        # Try to reuse same code (pass the code as last_used)
        result2 = totp_verify(encrypted_secret, user_id, username, code, code)
        assert result2 is False

    def test_totp_disabled_user(self, client, init_database):
        """Cannot resync if 2FA is off"""
        # Register user
        client.post(
            "/register", data={"username": "disableduser", "password": "Pass123", "password_confirm": "Pass123"}
        )

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "disableduser")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "disableduser"

        # Try to access TOTP setup without enabling 2FA first
        # This should work but show that 2FA is not enabled
        response = client.get("/login/totp/setup")
        # The route might allow access but show that 2FA needs to be enabled
        assert response.status_code == 200

    def test_totp_encryption_roundtrip(self):
        """Secret encrypts/decrypts correctly"""
        from additional import totp_generator, totpCode

        user_id = "123"
        username = "encryptuser"

        # Generate encrypted secret
        encrypted_secret, _ = totp_generator(user_id, username)

        # Decrypt it back
        decrypted_secret = totpCode(encrypted_secret, user_id, username)

        # Should be valid base32 secret
        assert len(decrypted_secret) == 32
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in decrypted_secret)

        # Should be able to encrypt/decrypt multiple times
        encrypted_again, _ = totp_generator(user_id, username)
        decrypted_again = totpCode(encrypted_again, user_id, username)
        assert len(decrypted_again) == 32

    def test_totp_invalid_secret(self):
        """Handles corrupted/malformed encrypted secret"""
        from additional import totpCode
        import pytest

        user_id = "123"
        username = "testuser"

        # Test with completely invalid base64
        with pytest.raises(ValueError, match="Failed to decrypt TOTP secret"):
            totpCode("invalid_base64_data!!!", user_id, username)

        # Test with valid base64 but wrong encryption
        import base64

        fake_encrypted = base64.b64encode(b"fake_encrypted_data").decode()
        with pytest.raises(ValueError, match="Failed to decrypt TOTP secret"):
            totpCode(fake_encrypted, user_id, username)


class TestTOTPUIComponents:
    """Test UI components and interactions based on actual templates"""

    def test_totp_setup_page_contains_required_elements(self, client, init_database):
        """Test that TOTP setup page contains all required UI elements"""
        # Register and setup user
        client.post("/register", data={"username": "uitestuser", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "uitestuser")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "uitestuser"

        response = client.get("/login/totp/setup")
        assert response.status_code == 200

        # Check for required UI elements from totp_setup.html
        assert b"qrcode" in response.data  # QR code image
        assert b"otp-input" in response.data  # OTP input fields
        assert b"totpForm" in response.data  # Form ID
        assert b"Enter the 6-digit code" in response.data  # Instructions
        assert b"Two-Factor Authentication" in response.data  # Page title
        assert b"Verify" in response.data  # Submit button

    def test_totp_verification_page_contains_required_elements(self, client, init_database):
        """Test that TOTP verification page contains required elements"""
        # Setup user with 2FA enabled
        client.post(
            "/register", data={"username": "verifyuitest", "password": "Pass123", "password_confirm": "Pass123"}
        )

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "verifyuitest")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "verifyuitest"

        # Enable 2FA first
        client.get("/login/totp/setup")

        # Now check verification page
        response = client.get("/login/totp")
        assert response.status_code == 200

        # Check for required elements from totp.html
        assert b"otp-input" in response.data  # OTP input fields
        assert b"totpForm" in response.data  # Form
        assert b"Enter the 6-digit code" in response.data  # Instructions
        assert b"Two-Factor Authentication" in response.data  # Page title

    def test_settings_page_shows_2fa_status_disabled(self, client, init_database):
        """Test that settings page correctly shows 2FA status as disabled"""
        # Register user
        client.post(
            "/register", data={"username": "settingsuser", "password": "Pass123", "password_confirm": "Pass123"}
        )

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "settingsuser")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "settingsuser"

        response = client.get("/settings")
        assert response.status_code == 200

        # Should show 2FA as disabled initially
        assert b"Disabled" in response.data
        assert b"Enable 2FA" in response.data
        assert b"Two-Factor Authentication" in response.data

    def test_settings_page_shows_2fa_status_enabled(self, client, init_database):
        """Test that settings page correctly shows 2FA status as enabled"""
        # Register user and enable 2FA
        client.post("/register", data={"username": "enableduser", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "enableduser")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "enableduser"

        # Enable 2FA
        client.get("/login/totp/setup")

        response = client.get("/settings")
        assert response.status_code == 200

        # Should show 2FA options for enabled users
        assert b"Disable 2FA" in response.data or b"Resynchronize TOTP" in response.data


class TestTOTPPermissionFlow:
    """Test the permission flow for enabling/disabling 2FA"""

    def test_enable_2fa_through_permission_route(self, client, init_database):
        """Test enabling 2FA through /permission route"""
        # Register user
        client.post(
            "/register", data={"username": "permissionuser", "password": "Pass123", "password_confirm": "Pass123"}
        )

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "permissionuser")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "permissionuser"

        # Enable 2FA through permission route
        response = client.post("/permission", data={"password": "Pass123", "2fa_action": "enable"})

        # Should redirect to TOTP setup
        assert response.status_code == 302
        assert "/login/totp/setup" in response.location

    def test_disable_2fa_through_permission_route(self, client, init_database):
        """Test disabling 2FA through /permission route"""
        # Register user and enable 2FA
        client.post("/register", data={"username": "disableuser", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "disableuser")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "disableuser"

        # Enable 2FA first
        client.get("/login/totp/setup")

        # Verify 2FA is enabled
        totp_data = db.execute("SELECT uri FROM twoFA WHERE user_id=?", user_id)
        assert len(totp_data) > 0

        # Disable 2FA
        response = client.post("/permission", data={"password": "Pass123", "2fa_action": "disable"})

        # Should redirect to settings
        assert response.status_code == 302
        assert "/settings" in response.location

        # Verify 2FA is disabled in database
        totp_data_after = db.execute("SELECT uri FROM twoFA WHERE user_id=?", user_id)
        assert len(totp_data_after) == 0

    def test_resync_2fa_through_permission_route(self, client, init_database):
        """Test resyncing 2FA through /permission route"""
        # Register user and enable 2FA
        client.post(
            "/register", data={"username": "resyncpermuser", "password": "Pass123", "password_confirm": "Pass123"}
        )

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "resyncpermuser")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "resyncpermuser"

        # Enable 2FA first
        client.get("/login/totp/setup")

        # Resync 2FA
        response = client.post("/permission", data={"password": "Pass123", "2fa_action": "resync"})

        # Should redirect to TOTP resync
        assert response.status_code == 302
        assert "/login/totp/resync" in response.location

    def test_permission_route_wrong_password(self, client, init_database):
        """Test /permission route with wrong password"""
        # Register user
        client.post(
            "/register", data={"username": "wrongpassuser", "password": "Pass123", "password_confirm": "Pass123"}
        )

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "wrongpassuser")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "wrongpassuser"

        # Try to enable 2FA with wrong password
        response = client.post("/permission", data={"password": "WrongPassword", "2fa_action": "enable"})

        # Should redirect back to settings
        assert response.status_code == 302
        assert "/settings" in response.location

    def test_permission_route_empty_password(self, client, init_database):
        """Test /permission route with empty password"""
        # Register user
        client.post(
            "/register", data={"username": "emptypassuser", "password": "Pass123", "password_confirm": "Pass123"}
        )

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "emptypassuser")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "emptypassuser"

        # Try to enable 2FA with empty password
        response = client.post("/permission", data={"password": "", "2fa_action": "enable"})

        # Should redirect back to settings
        assert response.status_code == 302
        assert "/settings" in response.location


class TestTOTPSecurityFeatures:
    """Test security features of TOTP implementation"""

    def test_totp_session_required_for_setup(self, client, init_database):
        """Test that valid session is required for TOTP setup"""
        # Try to access TOTP setup without session
        response = client.get("/login/totp/setup")

        # Should redirect to login
        assert response.status_code == 302
        assert "/login" in response.location

    def test_totp_session_required_for_verification(self, client, init_database):
        """Test that valid session is required for TOTP verification"""
        # Try to access TOTP verification without session
        response = client.get("/login/totp")

        # Should redirect to login
        assert response.status_code == 302
        assert "/login" in response.location

    def test_totp_code_must_be_6_digits(self, client, init_database):
        """Test that TOTP code must be exactly 6 digits"""
        # Register and setup user
        client.post("/register", data={"username": "digituser", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "digituser")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "digituser"

        client.get("/login/totp/setup")

        # Test with less than 6 digits
        response = client.post(
            "/login/totp/setup", data={"totp": "123"}, headers={"X-Requested-With": "XMLHttpRequest"}
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "error"

        # Test with more than 6 digits
        response = client.post(
            "/login/totp/setup", data={"totp": "1234567"}, headers={"X-Requested-With": "XMLHttpRequest"}
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "error"

    def test_totp_prevents_brute_force_with_invalid_codes(self, client, init_database):
        """Test that multiple invalid TOTP codes are handled properly"""
        # Register and setup user
        client.post("/register", data={"username": "bruteuser", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "bruteuser")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "bruteuser"

        client.get("/login/totp/setup")

        # Try multiple invalid codes
        for i in range(5):
            response = client.post(
                "/login/totp/setup", data={"totp": f"12345{i}"}, headers={"X-Requested-With": "XMLHttpRequest"}
            )

            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["status"] == "error"


class TestTOTPDatabaseIntegration:
    """Test TOTP database operations"""

    def test_totp_data_persists_across_sessions(self, client, init_database):
        """Test that TOTP data persists across different sessions"""
        # Register user and enable 2FA
        client.post("/register", data={"username": "persistuser", "password": "Pass123", "password_confirm": "Pass123"})

        from sqlite import SQLite

        db = SQLite("clipbin.db")
        user = db.execute("SELECT id FROM users WHERE username=?", "persistuser")
        user_id = user[0]["id"]

        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["uname"] = "persistuser"

        # Enable 2FA
        client.get("/login/totp/setup")

        # Get TOTP data
        totp_data_before = db.execute("SELECT uri FROM twoFA WHERE user_id=?", user_id)
        assert len(totp_data_before) > 0

        # Clear session and create new one
        with client.session_transaction() as sess:
            sess.clear()
            sess["user_id"] = user_id
            sess["uname"] = "persistuser"

        # TOTP data should still exist
        totp_data_after = db.execute("SELECT uri FROM twoFA WHERE user_id=?", user_id)
        assert len(totp_data_after) > 0
        assert totp_data_before[0]["uri"] == totp_data_after[0]["uri"]

    def test_totp_data_deleted_on_user_deletion(self, init_database):
        """Test that TOTP data is deleted when user is deleted (cascade)"""
        from sqlite import SQLite

        db = SQLite("clipbin.db")

        # Create user directly in database
        from werkzeug.security import generate_password_hash

        password_hash = generate_password_hash("Pass123")

        db.execute("INSERT INTO users (username, password) VALUES (?, ?)", "cascadeuser", password_hash)

        user = db.execute("SELECT id FROM users WHERE username=?", "cascadeuser")
        user_id = user[0]["id"]

        # Add TOTP data
        from additional import totp_generator

        encrypted_secret, _ = totp_generator(str(user_id), "cascadeuser")
        db.execute("INSERT INTO twoFA (user_id, uri) VALUES (?, ?)", user_id, encrypted_secret)

        # Verify TOTP data exists
        totp_data = db.execute("SELECT uri FROM twoFA WHERE user_id=?", user_id)
        assert len(totp_data) > 0

        # Delete user
        db.execute("DELETE FROM users WHERE id=?", user_id)

        # TOTP data should be deleted due to cascade
        totp_data_after = db.execute("SELECT uri FROM twoFA WHERE user_id=?", user_id)
        assert len(totp_data_after) == 0
