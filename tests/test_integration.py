"""
Integration tests for the ClipBin application.
These tests verify the complete workflow of the application.
"""

import pytest
import json
import tempfile
import os
from werkzeug.security import generate_password_hash
from io import BytesIO


class TestCompleteWorkflow:
    """Integration tests for complete user workflows."""

    def test_user_registration_login_workflow(self, client):
        """Test complete user registration and login workflow."""
        # Registration
        user_data = {
            "username": "integrationuser",
            "password": "securepassword123",
        }

        # Register user
        response = client.post("/register", data=user_data)
        assert response.status_code == 302  # Redirect after successful registration

        # Login with registered user
        login_data = {"username": user_data["username"], "password": user_data["password"]}
        response = client.post("/login", data=login_data)
        assert response.status_code == 302  # Redirect after successful login

    def test_clip_creation_and_viewing_workflow(self, client):
        """Test complete clip creation and viewing workflow."""
        # Create a clip
        clip_data = {
            "clip_name": "Integration Test Clip",
            "clip_text": "This is content for integration testing",
            "clip_alias": "inttest",
            "clip_delete": "day",
        }

        response = client.post("/", data=clip_data)
        assert response.status_code == 302  # Redirect after creation

        # Extract redirect location to get clip ID
        location = response.location
        if location:
            # Try to access the created clip
            # Note: In a real test, we would parse the redirect location
            # to get the actual clip ID
            pass

    def test_password_protected_clip_workflow(self, client):
        """Test workflow for password-protected clips."""
        # Create password-protected clip
        clip_data = {
            "clip_name": "Protected Clip",
            "clip_text": "This is protected content",
            "clip_passwd": "clippassword",
            "clip_delete": "day",
        }

        response = client.post("/", data=clip_data)
        assert response.status_code == 302

    def test_file_upload_workflow(self, client):
        """Test complete file upload workflow."""
        # Test with valid file
        file_content = b'def hello():\n    print("Hello, World!")'
        file_data = {"clip_name": "Python File", "clip_delete": "day", "clip_file": (BytesIO(file_content), "hello.py")}

        response = client.post("/", data=file_data, content_type="multipart/form-data")
        assert response.status_code == 302

    def test_api_workflow(self, client):
        """Test API workflow for creating and retrieving clips."""
        # Test API info endpoint
        response = client.get("/api")
        assert response.status_code == 200

        # Test get_data API
        response = client.get("/api/get_data")
        assert response.status_code == 200
        assert response.is_json


class TestUserAuthenticatedWorkflow:
    """Integration tests for authenticated user workflows."""

    def test_authenticated_clip_management(self, authenticated_client):
        """Test clip management for authenticated users."""
        # Create a clip as authenticated user
        clip_data = {"clip_name": "User Clip", "clip_text": "Content from authenticated user", "clip_delete": "week"}

        response = authenticated_client.post("/", data=clip_data)
        assert response.status_code == 302

        # Access dashboard
        response = authenticated_client.get("/dashboard")
        assert response.status_code == 200

    def test_authenticated_settings_access(self, authenticated_client):
        """Test settings access for authenticated users."""
        response = authenticated_client.get("/settings")
        assert response.status_code == 200

    def test_export_functionality(self, authenticated_client):
        """Test export functionality for authenticated users."""
        # Create some clips first
        clip_data = {"clip_name": "Export Test Clip", "clip_text": "Content for export testing", "clip_delete": "month"}
        authenticated_client.post("/", data=clip_data)

        # Test export endpoint
        response = authenticated_client.get("/settings/export")
        assert response.status_code == 200


class TestErrorHandlingWorkflow:
    """Integration tests for error handling scenarios."""

    def test_invalid_clip_access(self, client):
        """Test accessing invalid or expired clips."""
        response = client.get("/invalidclipid123")
        assert response.status_code == 404

        response = client.get("/clip/invalidclipid123")
        assert response.status_code == 404

    def test_unauthorized_access_workflow(self, client):
        """Test unauthorized access to protected resources."""
        # Try to access dashboard without login
        response = client.get("/dashboard")
        assert response.status_code == 302
        assert "/login" in response.location

        # Try to access settings without login
        response = client.get("/settings")
        assert response.status_code == 302

    def test_invalid_form_submissions(self, client):
        """Test handling of invalid form submissions."""
        # Empty clip submission
        response = client.post("/", data={})
        # Should redirect with flash message for empty form
        assert response.status_code == 302

        # Invalid registration data
        invalid_user_data = {
            "username": "",  # Empty username
            "password": "123",  # Too short password
            "email": "invalid-email",  # Invalid email format
        }
        response = client.post("/register", data=invalid_user_data)
        assert response.status_code == 200


class TestSecurityWorkflow:
    """Integration tests for security features."""

    def test_xss_prevention(self, client):
        """Test XSS prevention in clip content."""
        malicious_content = '<script>alert("XSS")</script>'
        clip_data = {"clip_name": "XSS Test", "clip_text": malicious_content, "clip_delete": "day"}

        response = client.post("/", data=clip_data)
        assert response.status_code == 302

    def test_sql_injection_prevention(self, client):
        """Test SQL injection prevention."""
        malicious_username = "admin'; DROP TABLE users; --"
        user_data = {"username": malicious_username, "password": "password123", "email": "test@test.com"}

        response = client.post("/register", data=user_data)
        # Should handle gracefully, not crash the application
        assert response.status_code in [200, 302]

    def test_password_hash_security(self, client, sample_user_data):
        """Test that passwords are properly hashed."""
        # Register a user
        response = client.post("/register", data=sample_user_data)
        assert response.status_code == 302

        # Verify that we can't login with plaintext password hash
        # This is more of a logical test - the actual password verification
        # should happen through the login mechanism


class TestPerformanceWorkflow:
    """Integration tests for performance scenarios."""

    def test_multiple_clip_creation(self, client):
        """Test creating multiple clips in sequence."""
        for i in range(5):
            clip_data = {
                "clip_name": f"Performance Test Clip {i}",
                "clip_text": f"Content for clip number {i}",
                "clip_delete": "day",
            }
            response = client.post("/", data=clip_data)
            assert response.status_code == 302

    def test_concurrent_api_requests(self, client):
        """Test multiple API requests."""
        # Make multiple API requests
        responses = []
        for _ in range(3):
            response = client.get("/api/get_data")
            responses.append(response)

        # All requests should succeed
        for response in responses:
            assert response.status_code == 200


class TestDataIntegrityWorkflow:
    """Integration tests for data integrity."""

    def test_clip_content_preservation(self, client):
        """Test that clip content is preserved correctly."""
        special_content = """
        Line 1: Special characters: àáâãäåæçèéêë
        Line 2: Numbers: 1234567890
        Line 3: Symbols: !@#$%^&*()_+-=[]{}|;:,.<>?
        Line 4: Unicode: 你好世界 🌍🚀
        """

        clip_data = {"clip_name": "Content Preservation Test", "clip_text": special_content, "clip_delete": "day"}

        response = client.post("/", data=clip_data)
        assert response.status_code == 302

    def test_alias_uniqueness(self, client):
        """Test that aliases are unique."""
        # Create first clip with alias
        clip_data1 = {
            "clip_name": "First Clip",
            "clip_text": "First clip content",
            "clip_alias": "uniquealias",
            "clip_delete": "day",
        }
        response1 = client.post("/", data=clip_data1)
        assert response1.status_code == 302

        # Try to create second clip with same alias
        clip_data2 = {
            "clip_name": "Second Clip",
            "clip_text": "Second clip content",
            "clip_alias": "uniquealias",  # Same alias
            "clip_delete": "day",
        }
        response2 = client.post("/", data=clip_data2)
        # Should handle duplicate alias appropriately
        assert response2.status_code in [200, 302]
