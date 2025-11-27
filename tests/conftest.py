# Standard library imports
import asyncio
import os
from unittest.mock import AsyncMock, Mock, patch

# Third party imports
import pytest
from fastapi.testclient import TestClient

# Set test environment variables
os.environ["ENVIRONMENT"] = "development"
os.environ["LOG_LEVEL"] = "ERROR"
os.environ["REQUIRE_API_KEY"] = "false"
os.environ["ENABLE_RATE_LIMITING"] = "false"


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


@pytest.fixture
def mock_model():
    """Create a mocked clinical assertion model"""
    mock = Mock()
    mock.is_loaded.return_value = True
    mock.predict = AsyncMock(return_value={"label": "ABSENT", "score": 0.9842})
    mock.predict_batch = AsyncMock(
        return_value=[
            {"label": "ABSENT", "score": 0.9842},
            {"label": "PRESENT", "score": 0.8976},
        ]
    )
    mock.get_model_info.return_value = {
        "model_name": "bvanaken/clinical-assertion-negation-bert",
        "device": "cpu",
        "loaded": True,
        "labels": ["PRESENT", "ABSENT", "POSSIBLE"],
        "cuda_available": False,
    }
    return mock


@pytest.fixture
def app_with_mock_model(mock_model):
    """Create FastAPI app with mocked model"""
    with patch("app.main.model", mock_model):
        from app.main import app

        yield app


@pytest.fixture
def client(app_with_mock_model):
    """Create a test client for the FastAPI application"""
    return TestClient(app_with_mock_model)


@pytest.fixture
def auth_client():
    """Create a test client for auth tests with mocked model"""
    with patch("app.main.model") as mock_model:
        mock_model.is_loaded.return_value = True
        mock_model.get_model_info.return_value = {
            "model_name": "test-model",
            "device": "cpu",
            "loaded": True,
            "labels": ["PRESENT", "ABSENT", "POSSIBLE"],
            "cuda_available": False,
        }
        from app.main import app

        return TestClient(app)


@pytest.fixture
def sample_predictions():
    """Sample prediction data for testing"""
    return {
        "single": {"label": "ABSENT", "score": 0.9842},
        "batch": [
            {"label": "ABSENT", "score": 0.9842},
            {"label": "PRESENT", "score": 0.8976},
            {"label": "POSSIBLE", "score": 0.7123},
        ],
    }


@pytest.fixture
def clinical_test_sentences():
    """Clinical test sentences with expected labels"""
    return [
        {
            "sentence": "The patient denies chest pain.",
            "expected_label": "ABSENT",
            "description": "Negation example",
        },
        {
            "sentence": "He has a history of hypertension.",
            "expected_label": "PRESENT",
            "description": "Present condition",
        },
        {
            "sentence": "If symptoms persist, call doctor.",
            "expected_label": "CONDITIONAL",
            "description": "Conditional statement",
        },
        {
            "sentence": "No signs of pneumonia were observed.",
            "expected_label": "ABSENT",
            "description": "Absent finding",
        },
    ]


@pytest.fixture(autouse=True)
def mock_system_utils():
    """Mock system utility functions"""
    with patch("app.utils.get_system_metrics") as mock_metrics:
        mock_metrics.return_value = {
            "memory_mb": 512.0,
            "memory_percent": 50.0,
            "cpu_percent": 25.0,
            "disk_percent": 30.0,
        }
        yield mock_metrics
