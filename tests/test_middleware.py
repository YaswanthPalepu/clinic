# Standard library imports
import time
from unittest.mock import Mock, patch

# Third party imports
import pytest
from fastapi.responses import JSONResponse, Response

from app.middleware import (
    MetricsMiddleware,
    RateLimitMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
)


class TestSecurityHeadersMiddleware:
    """Test security headers middleware"""

    @pytest.fixture
    def middleware(self):
        """Create security headers middleware instance"""
        return SecurityHeadersMiddleware(None)

    @pytest.fixture
    def middleware_with_csp(self):
        """Create security headers middleware with CSP"""
        return SecurityHeadersMiddleware(None, csp_policy="default-src 'self'")

    def test_init(self, middleware):
        """Test middleware initialization"""
        assert middleware.app is None
        assert middleware.csp_policy is None
        assert middleware.hsts_max_age == 31536000

    def test_init_with_csp(self, middleware_with_csp):
        """Test middleware initialization with CSP policy"""
        assert middleware_with_csp.csp_policy == "default-src 'self'"

    @pytest.mark.asyncio
    async def test_dispatch_no_csp_http(self, middleware):
        """Test dispatch without CSP on HTTP"""
        mock_request = Mock()
        mock_request.url.scheme = "http"
        mock_response = Response()

        async def mock_call_next(request):
            return mock_response

        result = await middleware.dispatch(mock_request, mock_call_next)

        assert result.headers["X-Content-Type-Options"] == "nosniff"
        assert result.headers["X-Frame-Options"] == "DENY"
        assert result.headers["X-XSS-Protection"] == "1; mode=block"
        assert result.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert "Content-Security-Policy" not in result.headers
        assert "Strict-Transport-Security" not in result.headers

    @pytest.mark.asyncio
    async def test_dispatch_with_csp_https(self, middleware_with_csp):
        """Test dispatch with CSP on HTTPS"""
        mock_request = Mock()
        mock_request.url.scheme = "https"
        mock_response = Response()

        async def mock_call_next(request):
            return mock_response

        result = await middleware_with_csp.dispatch(mock_request, mock_call_next)

        assert result.headers["Content-Security-Policy"] == "default-src 'self'"
        assert result.headers["Strict-Transport-Security"] == "max-age=31536000"


class TestRateLimitMiddleware:
    """Test rate limiting middleware"""

    @pytest.fixture
    def middleware(self):
        """Create rate limit middleware instance"""
        return RateLimitMiddleware(None, requests_per_minute=10)

    def test_init(self, middleware):
        """Test middleware initialization"""
        assert middleware.app is None
        assert middleware.requests_per_minute == 10
        assert middleware.requests == {}

    def test_get_client_id_with_x_forwarded_for(self, middleware):
        """Test client ID extraction with X-Forwarded-For header"""
        mock_request = Mock()
        mock_request.headers = {"X-Forwarded-For": "192.168.1.1, 10.0.0.1"}
        mock_request.client = None

        client_id = middleware.get_client_id(mock_request)
        assert client_id == "192.168.1.1"

    def test_get_client_id_with_client(self, middleware):
        """Test client ID extraction with request client"""
        mock_request = Mock()
        mock_request.headers = {}
        mock_client = Mock()
        mock_client.host = "192.168.1.1"
        mock_request.client = mock_client

        client_id = middleware.get_client_id(mock_request)
        assert client_id == "192.168.1.1"

    def test_get_client_id_unknown(self, middleware):
        """Test client ID extraction when no client info available"""
        mock_request = Mock()
        mock_request.headers = {}
        mock_request.client = None

        client_id = middleware.get_client_id(mock_request)
        assert client_id == "unknown"

    @pytest.mark.asyncio
    async def test_dispatch_health_endpoint(self, middleware):
        """Test that health endpoint bypasses rate limiting"""
        mock_request = Mock()
        mock_request.url.path = "/health"
        mock_response = Response()

        async def mock_call_next(request):
            return mock_response

        result = await middleware.dispatch(mock_request, mock_call_next)

        assert result == mock_response
        assert "X-RateLimit-Limit" not in result.headers

    @pytest.mark.asyncio
    async def test_dispatch_under_limit(self, middleware):
        """Test dispatch when under rate limit"""
        mock_request = Mock()
        mock_request.url.path = "/api/test"
        mock_request.headers = {}
        mock_request.client = None
        mock_response = Response()

        async def mock_call_next(request):
            return mock_response

        with patch.object(middleware, "get_client_id", return_value="test_client"):
            result = await middleware.dispatch(mock_request, mock_call_next)

            assert result.headers["X-RateLimit-Limit"] == "10"
            assert result.headers["X-RateLimit-Remaining"] == "9"

    @pytest.mark.asyncio
    async def test_dispatch_over_limit(self, middleware):
        """Test dispatch when over rate limit"""
        mock_request = Mock()
        mock_request.url.path = "/api/test"
        mock_request.headers = {}
        mock_request.client = None

        # Simulate rate limit exceeded
        middleware.requests["unknown"] = [time.time()] * 10

        async def mock_call_next(request):
            return JSONResponse(status_code=200, content={"test": "data"})

        result = await middleware.dispatch(mock_request, mock_call_next)

        assert result.status_code == 429
        assert "Rate limit exceeded" in result.body.decode()


class TestRequestLoggingMiddleware:
    """Test request logging middleware"""

    @pytest.fixture
    def middleware(self):
        """Create request logging middleware instance"""
        return RequestLoggingMiddleware(None)

    def test_init(self, middleware):
        """Test middleware initialization"""
        assert middleware.app is None

    def test_get_client_id_with_x_forwarded_for(self, middleware):
        """Test client ID extraction with X-Forwarded-For header"""
        mock_request = Mock()
        mock_request.headers = {"X-Forwarded-For": "192.168.1.1, 10.0.0.1"}
        mock_request.client = None

        client_id = middleware.get_client_id(mock_request)
        assert client_id == "192.168.1.1"

    def test_get_client_id_with_client(self, middleware):
        """Test client ID extraction with request client"""
        mock_request = Mock()
        mock_request.headers = {}
        mock_client = Mock()
        mock_client.host = "192.168.1.1"
        mock_request.client = mock_client

        client_id = middleware.get_client_id(mock_request)
        assert client_id == "192.168.1.1"

    def test_get_client_id_unknown(self, middleware):
        """Test client ID extraction when no client info available"""
        mock_request = Mock()
        mock_request.headers = {}
        mock_request.client = None

        client_id = middleware.get_client_id(mock_request)
        assert client_id == "unknown"

    @pytest.mark.asyncio
    async def test_dispatch_success(self, middleware):
        """Test successful request dispatch"""
        mock_request = Mock()
        mock_request.method = "GET"
        mock_request.url.path = "/api/test"
        mock_request.headers = {"X-Request-ID": "test-123"}
        mock_request.client = None
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}

        async def mock_call_next(request):
            return mock_response

        with patch("time.time", side_effect=[1000.0, 1000.5, 1000.5]), patch(
            "app.middleware.logger"
        ) as mock_logger:
            result = await middleware.dispatch(mock_request, mock_call_next)

            assert result == mock_response
            assert result.headers["X-Request-ID"] == "test-123"

            # Verify logging calls
            assert mock_logger.info.call_count == 2  # start and complete

    @pytest.mark.asyncio
    async def test_dispatch_with_exception(self, middleware):
        """Test request dispatch with exception"""
        mock_request = Mock()
        mock_request.method = "POST"
        mock_request.url.path = "/api/test"
        mock_request.headers = {}
        mock_request.client = None

        async def failing_call_next(request):
            raise Exception("Test error")

        with patch("time.time", side_effect=[1000.0, 1000.3]), patch(
            "app.middleware.logger"
        ) as mock_logger:
            with pytest.raises(Exception, match="Test error"):
                await middleware.dispatch(mock_request, failing_call_next)

            # Verify error logging
            mock_logger.error.assert_called_once()


class TestMetricsMiddleware:
    """Test metrics middleware"""

    @pytest.fixture
    def middleware(self):
        """Create metrics middleware instance"""
        return MetricsMiddleware(None)

    def test_init(self, middleware):
        """Test middleware initialization"""
        assert middleware.app is None
        assert middleware.request_count == 0
        assert middleware.error_count == 0

    @pytest.mark.asyncio
    async def test_dispatch_success(self, middleware):
        """Test successful request dispatch"""
        mock_request = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}

        async def mock_call_next(request):
            return mock_response

        result = await middleware.dispatch(mock_request, mock_call_next)

        assert result == mock_response
        assert middleware.request_count == 1
        assert middleware.error_count == 0
        assert result.headers["X-Response-Time"] == "0.000s"

    @pytest.mark.asyncio
    async def test_dispatch_error(self, middleware):
        """Test request dispatch with error response"""
        mock_request = Mock()
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.headers = {}

        async def mock_call_next(request):
            return mock_response

        result = await middleware.dispatch(mock_request, mock_call_next)

        assert result == mock_response
        assert middleware.request_count == 1
        assert middleware.error_count == 1

    @pytest.mark.asyncio
    async def test_dispatch_exception(self, middleware):
        """Test request dispatch with exception"""
        mock_request = Mock()

        async def failing_call_next(request):
            raise Exception("Test error")

        with pytest.raises(Exception, match="Test error"):
            await middleware.dispatch(mock_request, failing_call_next)

        assert middleware.request_count == 1
        assert middleware.error_count == 1
