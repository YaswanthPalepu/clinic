# Standard library imports
import os
from unittest.mock import patch

from app.auth import APIKeyAuth


class TestAPIKeyAuth:
    """Test API key authentication functionality"""

    def test_init_no_api_keys(self):
        """Test initialization with no API keys"""
        with patch.dict(os.environ, {"API_KEYS": ""}):
            auth = APIKeyAuth()
            assert auth.api_keys == set()

    def test_init_with_api_keys(self):
        """Test initialization with API keys"""
        with patch.dict(os.environ, {"API_KEYS": "key1,key2,key3"}):
            auth = APIKeyAuth()
            assert auth.api_keys == {"key1", "key2", "key3"}

    def test_init_with_whitespace_api_keys(self):
        """Test initialization with whitespace in API keys"""
        with patch.dict(os.environ, {"API_KEYS": " key1 , key2 , key3 "}):
            auth = APIKeyAuth()
            assert auth.api_keys == {"key1", "key2", "key3"}

    def test_verify_key_no_keys_required(self):
        """Test key verification when no keys are required"""
        with patch.dict(os.environ, {"API_KEYS": ""}):
            auth = APIKeyAuth()
            assert auth.verify_key("any_key") is True

    def test_verify_key_valid(self):
        """Test key verification with valid key"""
        with patch.dict(os.environ, {"API_KEYS": "key1,key2"}):
            auth = APIKeyAuth()
            assert auth.verify_key("key1") is True
            assert auth.verify_key("key2") is True

    def test_verify_key_invalid(self):
        """Test key verification with invalid key"""
        with patch.dict(os.environ, {"API_KEYS": "key1,key2"}):
            auth = APIKeyAuth()
            assert auth.verify_key("invalid_key") is False


class TestVerifyAPIKey:
    """Test API key verification dependency"""

    def test_verify_api_key_health_endpoint(self, auth_client):
        """Test that health endpoint doesn't require API key"""
        response = auth_client.get("/health")
        assert response.status_code == 200

    def test_verify_api_key_root_endpoint(self, auth_client):
        """Test that root endpoint doesn't require API key"""
        response = auth_client.get("/")
        assert response.status_code == 200

    def test_verify_api_key_metrics_endpoint(self, auth_client):
        """Test that metrics endpoint doesn't require API key"""
        response = auth_client.get("/metrics")
        assert response.status_code == 200

    def test_verify_api_key_no_keys_required(self, auth_client):
        """Test endpoints when no API keys are required"""
        with patch.dict(os.environ, {"API_KEYS": "", "REQUIRE_API_KEY": "false"}):
            response = auth_client.get("/model/info")
            assert response.status_code == 200

    def test_verify_api_key_missing_from_request(self, auth_client):
        """Test API key verification when key is missing"""
        with patch.dict(
            os.environ, {"API_KEYS": "test_key", "REQUIRE_API_KEY": "true"}
        ):
            response = auth_client.get("/model/info")
            assert response.status_code == 401
            data = response.json()
            assert "API key required" in data["error"]

    def test_verify_api_key_invalid(self, auth_client):
        """Test API key verification with invalid key"""
        with patch.dict(
            os.environ, {"API_KEYS": "test_key", "REQUIRE_API_KEY": "true"}
        ):
            response = auth_client.get(
                "/model/info", headers={"Authorization": "Bearer invalid_key"}
            )
            assert response.status_code == 401
            data = response.json()
            assert "Invalid API key" in data["error"]

    def test_verify_api_key_valid_bearer(self, auth_client):
        """Test API key verification with valid Bearer token"""
        with patch.dict(
            os.environ, {"API_KEYS": "test_key", "REQUIRE_API_KEY": "true"}
        ):
            response = auth_client.get(
                "/model/info", headers={"Authorization": "Bearer test_key"}
            )
            assert response.status_code == 200

    def test_verify_api_key_valid_header(self, auth_client):
        """Test API key verification with valid X-API-Key header"""
        with patch.dict(
            os.environ, {"API_KEYS": "test_key", "REQUIRE_API_KEY": "true"}
        ):
            response = auth_client.get("/model/info", headers={"X-API-Key": "test_key"})
            assert response.status_code == 200

    def test_verify_api_key_valid_query_param(self, auth_client):
        """Test API key verification with valid query parameter"""
        with patch.dict(
            os.environ, {"API_KEYS": "test_key", "REQUIRE_API_KEY": "true"}
        ):
            response = auth_client.get("/model/info?api_key=test_key")
            assert response.status_code == 200

    def test_verify_api_key_logging_invalid_key(self):
        """Test that invalid API key attempts are logged"""
        # Standard library imports
        from unittest.mock import Mock

        from app.auth import verify_api_key

        with patch.dict(
            os.environ, {"API_KEYS": "valid_key", "REQUIRE_API_KEY": "true"}
        ), patch("app.auth.logger") as mock_logger:
            mock_request = Mock()
            mock_request.url.path = "/api/test"
            mock_request.client = Mock()
            mock_request.client.host = "192.168.1.1"
            mock_request.headers = {}
            mock_request.query_params = {}

            # This should raise an exception and log the invalid attempt
            try:
                verify_api_key(mock_request, None)
            except Exception:
                pass

            # Verify that warning was logged for invalid key attempt
            mock_logger.warning.assert_called()

    def test_verify_api_key_multiple_keys(self):
        """Test API key verification with multiple valid keys"""
        with patch.dict(os.environ, {"API_KEYS": "key1,key2,key3"}):
            auth = APIKeyAuth()
            assert auth.verify_key("key1") is True
            assert auth.verify_key("key2") is True
            assert auth.verify_key("key3") is True
            assert auth.verify_key("invalid") is False

    def test_verify_api_key_empty_key_string(self):
        """Test API key verification with empty key in environment"""
        with patch.dict(os.environ, {"API_KEYS": "key1,,key2"}):
            auth = APIKeyAuth()
            assert auth.verify_key("key1") is True
            assert auth.verify_key("") is False
            assert auth.verify_key("key2") is True

    def test_verify_api_key_whitespace_only(self):
        """Test API key verification with whitespace-only key"""
        with patch.dict(os.environ, {"API_KEYS": "key1,   ,key2"}):
            auth = APIKeyAuth()
            assert auth.verify_key("key1") is True
            assert auth.verify_key("   ") is False
            assert auth.verify_key("key2") is True

    def test_verify_api_key_special_characters(self):
        """Test API key verification with special characters"""
        with patch.dict(os.environ, {"API_KEYS": "key-1,key_2,key.3"}):
            auth = APIKeyAuth()
            assert auth.verify_key("key-1") is True
            assert auth.verify_key("key_2") is True
            assert auth.verify_key("key.3") is True
            assert auth.verify_key("invalid-key") is False

    def test_verify_api_key_case_sensitive(self):
        """Test API key verification is case sensitive"""
        with patch.dict(os.environ, {"API_KEYS": "Key1,KEY2"}):
            auth = APIKeyAuth()
            assert auth.verify_key("Key1") is True
            assert auth.verify_key("key1") is False
            assert auth.verify_key("KEY2") is True
            assert auth.verify_key("key2") is False
