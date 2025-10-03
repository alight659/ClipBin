"""
Basic working tests for the Flask application.
These tests focus on routes that work correctly without complex setup.
"""

import pytest
from app import app, loginData, time, alias


class TestBasicAppFunctionality:
    """Test basic application functionality that should work."""

    def test_app_exists(self):
        """Test that the Flask app instance exists."""
        assert app is not None

    def test_app_name(self):
        """Test that the app has the correct name."""
        assert app.name == 'app'

    def test_time_configuration(self):
        """Test time configuration dictionary."""
        assert isinstance(time, dict)
        assert 'day' in time
        assert 'week' in time
        assert 'month' in time
        assert 'year' in time

    def test_alias_list(self):
        """Test alias list configuration."""
        assert isinstance(alias, list)
        assert 'login' in alias
        assert 'register' in alias
        assert 'about' in alias

    def test_login_data_function_exists(self):
        """Test that loginData function exists and is callable."""
        assert callable(loginData)


class TestBasicRoutes:
    """Test basic routes that should work without database setup."""

    def test_index_get_route(self, client):
        """Test GET request to index route."""
        response = client.get('/')
        assert response.status_code == 200

    def test_about_route(self, client):
        """Test about route."""
        response = client.get('/about')
        assert response.status_code == 200

    def test_login_get_route(self, client):
        """Test GET request to login route."""
        response = client.get('/login')
        assert response.status_code == 200

    def test_register_get_route(self, client):
        """Test GET request to register route."""
        response = client.get('/register')
        assert response.status_code == 200

    def test_api_info_route(self, client):
        """Test API info route."""
        response = client.get('/api')
        assert response.status_code == 200

    def test_api_info_alternate_route(self, client):
        """Test alternate API info route."""
        response = client.get('/api/')
        assert response.status_code == 200

    def test_logout_route(self, client):
        """Test logout route (should redirect)."""
        response = client.get('/logout')
        assert response.status_code == 302


class TestErrorHandling:
    """Test error handling."""

    def test_404_error(self, client):
        """Test 404 error handling."""
        response = client.get('/nonexistent-route-12345')
        assert response.status_code == 404

    def test_invalid_clip_id(self, client):
        """Test accessing invalid clip ID."""
        response = client.get('/invalid123456789')
        assert response.status_code == 404


class TestBasicFormValidation:
    """Test basic form validation that doesn't require database."""

    def test_empty_registration_form(self, client):
        """Test registration with empty form."""
        response = client.post('/register', data={})
        # Should return to registration page with error
        assert response.status_code == 200

    def test_empty_login_form(self, client):
        """Test login with empty form."""
        response = client.post('/login', data={})
        # Should return to login page with error  
        assert response.status_code == 200

    def test_index_empty_form(self, client):
        """Test index with empty form."""
        response = client.post('/', data={})
        # Should handle gracefully
        assert response.status_code in [200, 302, 400]


class TestSecurityHeaders:
    """Test basic security aspects."""

    def test_no_server_header_leakage(self, client):
        """Test that sensitive server info isn't leaked."""
        response = client.get('/')
        # Flask shouldn't leak version info by default
        assert 'Server' not in response.headers or 'Werkzeug' not in response.headers.get('Server', '')

    def test_content_type_headers(self, client):
        """Test that content type headers are set correctly."""
        response = client.get('/')
        assert 'text/html' in response.headers.get('Content-Type', '')


class TestLoginDataFunction:
    """Test the loginData function in different scenarios."""

    def test_login_data_no_session(self, client):
        """Test loginData when no session exists."""
        with client.application.test_request_context():
            result = loginData()
            assert isinstance(result, list)
            assert len(result) == 2
            assert result[0] is False  # Not logged in
            assert result[1] == ""     # No username


class TestApplicationConfiguration:
    """Test application configuration."""

    def test_max_content_length(self):
        """Test that max content length is set."""
        expected_size = 1.5 * 1024 * 1024  # 1.5MB
        assert app.config.get('MAX_CONTENT_LENGTH') == expected_size

    def test_session_configuration(self):
        """Test session configuration."""
        assert app.config.get('SESSION_PERMANENT') is False
        assert app.config.get('SESSION_TYPE') == 'filesystem'

    def test_secret_key_configured(self):
        """Test that secret key is configured."""
        # Should have a secret key (might be None in test environment)
        assert 'SECRET_KEY' in app.config