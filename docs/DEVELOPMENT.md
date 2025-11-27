# Clinical BERT API - Development Guide

## Development Environment Setup

### Prerequisites
- **Python**: 3.12.0 or higher
- **Git**: Latest version
- **Docker**: Optional, for containerized development
- **Virtual Environment**: venv, conda, or virtualenv

### Quick Start Development
```bash
# 1. Clone the repository
git clone https://github.com/Basavarajsm2102/Clinical_BERT_Assertion_API.git
cd Clinical_BERT_Assertion_API

# 2. Set up Python virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install development dependencies
pip install -r requirements-dev.txt

# 5. Set up pre-commit hooks
pip install pre-commit
pre-commit install

# 6. Configure environment variables
cp .env.example .env
# Edit .env with your development settings

# 7. Start development server
uvicorn app.main:app --reload --port 8000 --log-level debug

# 8. Access API documentation
open http://localhost:8000/docs
```

### Development Dependencies
```txt
# requirements-dev.txt
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
black==23.10.1
isort==5.12.0
flake8==6.1.0
mypy==1.7.0
bandit==1.7.5
safety==2.3.4
pre-commit==3.5.0
python-json-logger==2.0.7
```

## Testing Strategy

### Test Categories

#### Unit Tests
```python
# tests/test_model.py
import pytest
from app.model import ClinicalAssertionModel

class TestClinicalAssertionModel:
    def test_model_initialization(self):
        """Test model initialization"""
        model = ClinicalAssertionModel()
        assert model is not None

    def test_model_loading(self):
        """Test model loading"""
        model = ClinicalAssertionModel()
        assert model.is_loaded() == False

        # Test async loading
        import asyncio
        asyncio.run(model.load_model())
        assert model.is_loaded() == True

    def test_prediction_validation(self):
        """Test prediction input validation"""
        model = ClinicalAssertionModel()

        # Test empty input
        with pytest.raises(ValueError):
            model.predict("")

        # Test long input
        long_text = "word " * 1000
        with pytest.raises(ValueError):
            model.predict(long_text)
```

#### Integration Tests
```python
# tests/test_api_integration.py
import pytest
from httpx import AsyncClient
from app.main import app

@pytest.mark.asyncio
class TestAPIIntegration:
    @pytest.fixture
    async def client(self):
        """Create test client"""
        async with AsyncClient(app=app, base_url="http://testserver") as client:
            yield client

    async def test_health_endpoint(self, client):
        """Test health endpoint integration"""
        response = await client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert "status" in data
        assert "model_loaded" in data
        assert "timestamp" in data

    async def test_prediction_workflow(self, client):
        """Test complete prediction workflow"""
        # Test single prediction
        payload = {"sentence": "The patient reports chest pain."}
        response = await client.post("/predict", json=payload)

        assert response.status_code == 200
        data = response.json()

        assert "label" in data
        assert "score" in data
        assert "prediction_time_ms" in data
        assert data["label"] in ["PRESENT", "ABSENT", "POSSIBLE"]
        assert 0.0 <= data["score"] <= 1.0

    async def test_batch_prediction_workflow(self, client):
        """Test batch prediction workflow"""
        payload = {
            "sentences": [
                "Patient has fever.",
                "No signs of infection.",
                "Blood pressure elevated."
            ]
        }
        response = await client.post("/predict/batch", json=payload)

        assert response.status_code == 200
        data = response.json()

        assert "predictions" in data
        assert "batch_size" in data
        assert len(data["predictions"]) == 3
        assert data["batch_size"] == 3
```

#### Performance Tests
```python
# tests/test_performance.py
import pytest
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
import requests

class TestPerformance:
    def test_single_prediction_performance(self):
        """Test single prediction performance"""
        payload = {"sentence": "The patient reports chest pain."}

        start_time = time.time()
        response = requests.post("http://localhost:8000/predict", json=payload)
        end_time = time.time()

        assert response.status_code == 200
        response_time = (end_time - start_time) * 1000  # Convert to ms

        # Assert performance requirements
        assert response_time < 500  # Less than 500ms
        print(f"Response time: {response_time:.2f}ms")

    def test_concurrent_predictions(self):
        """Test concurrent prediction handling"""
        payload = {"sentence": "Patient has symptoms."}

        def make_request():
            return requests.post("http://localhost:8000/predict", json=payload)

        # Test with 10 concurrent requests
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            responses = [future.result() for future in futures]

        # All requests should succeed
        assert all(response.status_code == 200 for response in responses)

        # Calculate average response time
        response_times = []
        for response in responses:
            # Extract response time from custom header or calculate
            response_times.append(response.elapsed.total_seconds() * 1000)

        avg_response_time = sum(response_times) / len(response_times)
        print(f"Average response time: {avg_response_time:.2f}ms")

        # Assert performance under concurrent load
        assert avg_response_time < 1000  # Less than 1 second average

    @pytest.mark.asyncio
    async def test_batch_processing_efficiency(self):
        """Test batch processing efficiency"""
        sentences = [
            "Patient reports pain.",
            "No abnormal findings.",
            "Vital signs stable.",
            "Laboratory results normal.",
            "Physical examination unremarkable."
        ] * 10  # 50 sentences total

        payload = {"sentences": sentences}

        start_time = time.time()
        response = requests.post("http://localhost:8000/predict/batch", json=payload)
        end_time = time.time()

        assert response.status_code == 200
        data = response.json()

        batch_time = (end_time - start_time) * 1000
        per_item_time = batch_time / len(sentences)

        print(f"Batch time: {batch_time:.2f}ms")
        print(f"Per item time: {per_item_time:.2f}ms")

        # Assert batch efficiency
        assert per_item_time < 100  # Less than 100ms per item
        assert len(data["predictions"]) == len(sentences)
```

### Running Tests

#### Basic Test Execution
```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_api.py

# Run specific test class
pytest tests/test_api.py::TestHealthEndpoint

# Run specific test method
pytest tests/test_api.py::TestHealthEndpoint::test_health_check_success
```

#### Test Coverage
```bash
# Generate coverage report
pytest --cov=app --cov-report=html --cov-report=term

# View coverage report in browser
open htmlcov/index.html

# Coverage thresholds
pytest --cov=app --cov-report=term --cov-fail-under=75
```

#### Test Configuration
```ini
# pytest.ini
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts =
    --strict-markers
    --disable-warnings
    --tb=short
    --cov=app
    --cov-report=html
    --cov-report=term
markers =
    unit: Unit tests
    integration: Integration tests
    performance: Performance tests
    slow: Slow running tests
```

## Code Quality Tools

### Black - Code Formatting
```bash
# Format all Python files
black .

# Check formatting without changes
black --check .

# Format specific files
black app/main.py app/model.py
```

### isort - Import Sorting
```bash
# Sort imports in all files
isort .

# Check import sorting
isort --check-only .

# Sort imports with specific profile
isort --profile black .
```

### flake8 - Linting
```bash
# Lint all Python files
flake8 .

# Lint specific files
flake8 app/main.py

# Show statistics
flake8 --statistics
```

### mypy - Type Checking
```bash
# Type check all files
mypy .

# Type check specific module
mypy app/model.py

# Generate type checking report
mypy --html-report mypy-report .
```

### bandit - Security Scanning
```bash
# Scan for security issues
bandit -r app/

# Scan with specific severity
bandit -r app/ -l high

# Generate HTML report
bandit -r app/ -f html -o security-report.html
```

### safety - Dependency Vulnerability Scanning
```bash
# Check for known vulnerabilities
safety check

# Check specific requirements file
safety check -r requirements.txt

# Generate detailed report
safety check --full-report
```

## Development Workflow

### Git Workflow
```bash
# Create feature branch
git checkout -b feature/new-feature

# Make changes with tests
# ... development work ...

# Run quality checks
make quality

# Run tests
make test

# Commit changes
git add .
git commit -m "feat: add new feature

- Add feature description
- Update tests
- Update documentation"

# Push branch
git push origin feature/new-feature

# Create pull request
# ... GitHub PR process ...
```

### Pre-commit Hooks
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files

  - repo: https://github.com/psf/black
    rev: 23.10.1
    hooks:
      - id: black
        language_version: python3.12

  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort
        args: ["--profile", "black"]

  - repo: https://github.com/pycqa/flake8
    rev: 6.1.0
    hooks:
      - id: flake8
        args: ["--max-line-length=88", "--extend-ignore=E203,W503"]

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.7.0
    hooks:
      - id: mypy
        additional_dependencies: [types-all]
```

### Makefile Commands
```makefile
# Makefile
.PHONY: help install test quality clean

help:
    @echo "Available commands:"
    @echo "  install     Install dependencies"
    @echo "  test        Run test suite"
    @echo "  quality     Run quality checks"
    @echo "  clean       Clean up generated files"

install:
    pip install -r requirements.txt
    pip install -r requirements-dev.txt

test:
    pytest --cov=app --cov-report=html --cov-report=term

quality:
    black --check .
    isort --check-only .
    flake8 .
    mypy .
    bandit -r app/
    safety check

clean:
    find . -type f -name "*.pyc" -delete
    find . -type d -name "__pycache__" -delete
    rm -rf .coverage htmlcov .mypy_cache .pytest_cache
```

## Debugging Techniques

### Local Debugging
```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Add debug prints
def debug_prediction(sentence: str):
    print(f"Input sentence: {sentence}")
    print(f"Sentence length: {len(sentence)}")

    # ... prediction logic ...

    print(f"Model output: {result}")
    return result
```

### Remote Debugging
```python
# Enable remote debugging with debugpy
import debugpy

# Allow other computers to attach
debugpy.listen(("0.0.0.0", 5678))
print("Debugger listening on port 5678")

# Wait for debugger to attach
debugpy.wait_for_client()

# Your code here
# ...
```

### Performance Profiling
```python
import cProfile
import pstats
from io import StringIO

def profile_function():
    pr = cProfile.Profile()
    pr.enable()

    # Code to profile
    result = make_prediction("Test sentence")

    pr.disable()
    s = StringIO()
    sortby = 'cumulative'
    ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
    ps.print_stats()
    print(s.getvalue())

    return result
```

### Memory Profiling
```python
from memory_profiler import profile

@profile
def memory_intensive_prediction():
    # This function will be profiled for memory usage
    sentences = ["Long sentence " * 100] * 50
    results = []

    for sentence in sentences:
        result = predict_single(sentence)
        results.append(result)

    return results

if __name__ == "__main__":
    memory_intensive_prediction()
```

## Development Metrics

### Code Quality Metrics
```python
# Calculate code quality metrics
import radon.complexity as cc
import radon.metrics as mt

def analyze_code_quality(file_path: str):
    """Analyze code quality metrics"""

    # Cyclomatic complexity
    complexity = cc.cc_visit(file_path)
    avg_complexity = sum(c.complexity for c in complexity) / len(complexity)

    # Maintainability index
    mi = mt.mi_visit(file_path, multi=True)

    return {
        "complexity": avg_complexity,
        "maintainability_index": mi,
        "lines_of_code": sum(1 for _ in open(file_path)),
    }
```

### Test Coverage Analysis
```python
# Analyze test coverage gaps
import coverage
import os

def analyze_coverage_gaps():
    """Analyze areas with insufficient test coverage"""

    cov = coverage.Coverage()
    cov.load()

    # Get coverage data
    covered_lines = cov.get_covered_lines()
    missing_lines = cov.get_missing_lines()

    # Analyze by module
    for module in covered_lines:
        covered = len(covered_lines[module])
        missing = len(missing_lines.get(module, []))

        if covered + missing > 0:
            coverage_pct = covered / (covered + missing) * 100
            print(f"{module}: {coverage_pct:.1f}% coverage")

            if coverage_pct < 80:
                print(f"  Low coverage areas: {missing_lines[module][:5]}...")
```

## Deployment for Development

### Local Docker Development
```bash
# Build development image
docker build -t clinical-bert-dev -f Dockerfile.dev .

# Run with hot reload
docker run -p 8000:8000 -v $(pwd):/app clinical-bert-dev

# Run with debugging
docker run -p 8000:8000 -p 5678:5678 \
  -v $(pwd):/app \
  -e DEBUG=true \
  clinical-bert-dev
```

### Development Environment Variables
```bash
# .env.development
ENVIRONMENT=development
LOG_LEVEL=DEBUG
DEBUG=true

# Model settings
MODEL_CACHE_DIR=./model_cache
MAX_SEQUENCE_LENGTH=512

# API settings
HOST=0.0.0.0
PORT=8000
WORKERS=1

# Development features
AUTO_RELOAD=true
ENABLE_DOCS=true
ENABLE_DEBUG=true

# Optional: Authentication (development only)
API_KEY=dev-api-key-12345
REQUIRE_API_KEY=false
```

## Learning Resources

### Recommended Reading
- **FastAPI Documentation**: https://fastapi.tiangolo.com/
- **Hugging Face Transformers**: https://huggingface.co/docs/transformers/
- **Python Testing**: https://docs.python.org/3/library/unittest.html
- **Docker Best Practices**: https://docs.docker.com/develop/dev-best-practices/

### Online Courses
- **FastAPI Course**: Build APIs with Python
- **ML Engineering**: Production ML systems
- **DevOps for Developers**: CI/CD pipelines
- **Security Best Practices**: Application security

### Community Resources
- **FastAPI Discord**: Real-time help and discussions
- **Hugging Face Forums**: ML model discussions
- **Stack Overflow**: Programming Q&A
- **GitHub Issues**: Bug reports and feature requests

---

## Advanced Development Workflows

### Development Environment Variations

#### Multi-Service Development Setup
```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  clinical-bert-api:
    build:
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "8000:8080"
    volumes:
      - .:/app
      - ./model_cache:/app/model_cache
    environment:
      - ENVIRONMENT=development
      - LOG_LEVEL=DEBUG
      - DEBUG=true
      - AUTO_RELOAD=true
    command: uvicorn app.main:app --reload --host 0.0.0.0 --port 8080

  # Redis for caching (optional)
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_dev_data:/data
    command: redis-server --appendonly yes

  # PostgreSQL for development (optional)
  postgres:
    image: postgres:15-alpine
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_DB=clinical_bert_dev
      - POSTGRES_USER=dev_user
      - POSTGRES_PASSWORD=dev_password
    volumes:
      - postgres_dev_data:/var/lib/postgresql/data

  # Monitoring stack
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.dev.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_dev_data:/var/lib/grafana

volumes:
  redis_dev_data:
  postgres_dev_data:
  grafana_dev_data:
```

#### Cloud Development Environment
```bash
# Set up Google Cloud development environment
export GCP_PROJECT_ID="your-dev-project"
export GCP_REGION="us-central1"

# Create development service
gcloud run deploy clinical-bert-dev \
  --image=us-central1-docker.pkg.dev/$GCP_PROJECT_ID/clinical-bert-dev/clinical-bert-api:dev \
  --region=$GCP_REGION \
  --allow-unauthenticated \
  --memory=2Gi \
  --cpu=1 \
  --port=8080 \
  --set-env-vars="ENVIRONMENT=development,LOG_LEVEL=DEBUG,DEBUG=true"

# Get development URL
DEV_URL=$(gcloud run services describe clinical-bert-dev \
  --region=$GCP_REGION \
  --format="value(status.url)")

echo "Development API: $DEV_URL"
echo "Development Docs: $DEV_URL/docs"
```

### Advanced Debugging Techniques

#### Interactive Debugging with IPython
```python
# Install IPython for enhanced debugging
pip install ipython ipdb

# Add IPython startup file
# ~/.ipython/profile_default/startup/debug_startup.py
import ipdb
import sys

def debug_hook(type, value, tb):
    if hasattr(sys, 'ps1') or not sys.stderr.isatty():
        # Not in interactive mode
        sys.__excepthook__(type, value, tb)
    else:
        # Interactive mode
        import traceback
        import ipdb
        traceback.print_exception(type, value, tb)
        print()
        ipdb.pm()

# Enable debug hook
sys.excepthook = debug_hook
```

#### Memory Leak Detection
```python
import gc
import tracemalloc
from functools import wraps
import psutil
from typing import Dict, Any, List

class MemoryDebugger:
    """Advanced memory debugging and leak detection"""

    def __init__(self):
        self.snapshots = []
        self.memory_traces = {}

    def start_tracing(self):
        """Start memory tracing"""
        tracemalloc.start()
        print("Memory tracing started")

    def take_snapshot(self, name: str):
        """Take a memory snapshot"""
        if tracemalloc.is_tracing():
            snapshot = tracemalloc.take_snapshot()
            self.snapshots.append((name, snapshot))
            print(f"Memory snapshot '{name}' taken")

    def compare_snapshots(self, start_name: str, end_name: str) -> Dict[str, Any]:
        """Compare two memory snapshots"""
        start_snapshot = None
        end_snapshot = None

        for name, snapshot in self.snapshots:
            if name == start_name:
                start_snapshot = snapshot
            elif name == end_name:
                end_snapshot = snapshot

        if not start_snapshot or not end_snapshot:
            return {"error": "Snapshots not found"}

        # Compare snapshots
        stats = end_snapshot.compare_to(start_snapshot, 'lineno')

        return {
            "top_stats": stats[:10],  # Top 10 memory differences
            "total_increase": sum(stat.size_diff for stat in stats),
            "total_decrease": sum(-stat.size_diff for stat in stats if stat.size_diff < 0)
        }

    def detect_memory_leaks(self, threshold_mb: int = 10) -> Dict[str, Any]:
        """Detect potential memory leaks"""
        process = psutil.Process()
        memory_info = process.memory_info()

        # Get garbage collection stats
        gc_stats = {
            "collections": gc.get_count(),
            "collected": gc.get_stats(),
            "thresholds": gc.get_threshold()
        }

        # Check for increasing memory usage
        if len(self.snapshots) >= 2:
            comparison = self.compare_snapshots(
                self.snapshots[0][0],
                self.snapshots[-1][0]
            )

            if comparison.get('total_increase', 0) > threshold_mb * 1024 * 1024:
                return {
                    "memory_leak_detected": True,
                    "memory_increase_mb": comparison['total_increase'] / (1024 * 1024),
                    "recommendations": [
                        "Check for circular references",
                        "Use weak references where appropriate",
                        "Implement proper cleanup in __del__ methods",
                        "Monitor object creation/destruction patterns"
                    ]
                }

        return {
            "memory_leak_detected": False,
            "current_memory_mb": memory_info.rss / (1024 * 1024),
            "gc_stats": gc_stats
        }

    def profile_memory_usage(self, func):
        """Decorator to profile memory usage of a function"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Take snapshot before
            if tracemalloc.is_tracing():
                snapshot_before = tracemalloc.take_snapshot()

            # Execute function
            result = func(*args, **kwargs)

            # Take snapshot after
            if tracemalloc.is_tracing():
                snapshot_after = tracemalloc.take_snapshot()
                stats = snapshot_after.compare_to(snapshot_before, 'lineno')

                print(f"\nMemory profile for {func.__name__}:")
                for stat in stats[:5]:  # Top 5 memory consumers
                    print(f"  {stat}")

            return result
        return wrapper

# Usage
memory_debugger = MemoryDebugger()
memory_debugger.start_tracing()

@memory_debugger.profile_memory_usage
def test_memory_usage():
    # Your function to profile
    data = []
    for i in range(1000):
        data.append(f"Item {i}" * 100)
    return data

# Take memory snapshots
memory_debugger.take_snapshot("initial")
test_memory_usage()
memory_debugger.take_snapshot("after_test")

# Check for memory leaks
leak_report = memory_debugger.detect_memory_leaks()
print(f"Memory leak detected: {leak_report['memory_leak_detected']}")
```

#### Advanced Performance Profiling
```python
import cProfile
import pstats
import io
import functools
from line_profiler import LineProfiler
from memory_profiler import profile
import time
from contextlib import contextmanager

class AdvancedProfiler:
    """Advanced performance profiling tools"""

    def __init__(self):
        self.profilers = {}

    @contextmanager
    def profile_function(self, func_name: str):
        """Context manager for function profiling"""
        pr = cProfile.Profile()
        pr.enable()

        try:
            yield
        finally:
            pr.disable()

            # Save profile results
            s = io.StringIO()
            ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
            ps.print_stats()

            self.profilers[func_name] = s.getvalue()
            print(f"Profile results for {func_name}:")
            print(s.getvalue())

    def profile_line_by_line(self, func):
        """Line-by-line profiling"""
        lp = LineProfiler()
        lp.add_function(func)
        lp.enable_by_count()

        try:
            result = func()
        finally:
            lp.disable_by_count()
            lp.print_stats()

        return result

    def benchmark_function(self, func, iterations: int = 100):
        """Benchmark function performance"""
        times = []

        for _ in range(iterations):
            start_time = time.perf_counter()
            result = func()
            end_time = time.perf_counter()
            times.append(end_time - start_time)

        avg_time = sum(times) / len(times)
        min_time = min(times)
        max_time = max(times)

        return {
            "function": func.__name__,
            "iterations": iterations,
            "avg_time_seconds": avg_time,
            "min_time_seconds": min_time,
            "max_time_seconds": max_time,
            "throughput_per_second": 1 / avg_time if avg_time > 0 else float('inf')
        }

    def compare_functions(self, func1, func2, iterations: int = 100):
        """Compare performance of two functions"""
        benchmark1 = self.benchmark_function(func1, iterations)
        benchmark2 = self.benchmark_function(func2, iterations)

        improvement = (
            (benchmark1['avg_time_seconds'] - benchmark2['avg_time_seconds'])
            / benchmark1['avg_time_seconds'] * 100
        )

        return {
            "function1": benchmark1,
            "function2": benchmark2,
            "improvement_percent": improvement,
            "winner": func2.__name__ if improvement > 0 else func1.__name__
        }

# Usage
profiler = AdvancedProfiler()

# Profile a function
def slow_function():
    time.sleep(0.1)
    return sum(i**2 for i in range(1000))

def fast_function():
    return sum(i**2 for i in range(1000))

# Line-by-line profiling
result = profiler.profile_line_by_line(slow_function)

# Benchmark comparison
comparison = profiler.compare_functions(slow_function, fast_function)
print(f"Performance improvement: {comparison['improvement_percent']:.2f}%")
print(f"Winner: {comparison['winner']}")
```

### Database Integration for Development

#### SQLite Development Database
```python
# app/database.py
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from datetime import datetime

Base = declarative_base()

class PredictionLog(Base):
    """Log of all predictions for development analysis"""
    __tablename__ = "prediction_logs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    input_text = Column(Text, nullable=False)
    prediction_label = Column(String(20), nullable=False)
    confidence_score = Column(Float, nullable=False)
    processing_time_ms = Column(Float, nullable=False)
    model_version = Column(String(50), default="1.0.0")
    request_id = Column(String(100), unique=True)

class APIMetrics(Base):
    """API usage metrics"""
    __tablename__ = "api_metrics"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    endpoint = Column(String(100), nullable=False)
    method = Column(String(10), nullable=False)
    status_code = Column(Integer, nullable=False)
    response_time_ms = Column(Float, nullable=False)
    user_agent = Column(String(200))
    ip_address = Column(String(45))

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./clinical_bert_dev.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Initialize database tables"""
    Base.metadata.create_all(bind=engine)

def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Initialize database on startup
init_db()
```

#### Database Query Optimization
```python
from sqlalchemy.orm import Session
from typing import List, Dict, Any
import logging

class DatabaseOptimizer:
    """Database query optimization utilities"""

    def __init__(self, db_session: Session):
        self.db = db_session
        self.logger = logging.getLogger(__name__)

    def log_prediction(self, prediction_data: Dict[str, Any]):
        """Log prediction with optimized batching"""
        try:
            log_entry = PredictionLog(**prediction_data)
            self.db.add(log_entry)
            self.db.commit()
        except Exception as e:
            self.logger.error(f"Failed to log prediction: {e}")
            self.db.rollback()

    def get_prediction_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get prediction statistics with optimized query"""
        from datetime import datetime, timedelta
        from sqlalchemy import func, and_

        cutoff_time = datetime.utcnow() - timedelta(hours=hours)

        # Optimized query with aggregation
        stats = self.db.query(
            func.count(PredictionLog.id).label('total_predictions'),
            func.avg(PredictionLog.confidence_score).label('avg_confidence'),
            func.avg(PredictionLog.processing_time_ms).label('avg_processing_time'),
            func.count(func.distinct(PredictionLog.prediction_label)).label('unique_labels')
        ).filter(
            PredictionLog.timestamp >= cutoff_time
        ).first()

        return {
            "total_predictions": stats.total_predictions,
            "avg_confidence": float(stats.avg_confidence) if stats.avg_confidence else 0,
            "avg_processing_time_ms": float(stats.avg_processing_time) if stats.avg_processing_time else 0,
            "unique_labels": stats.unique_labels
        }

    def get_performance_trends(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get performance trends with time bucketing"""
        from datetime import datetime, timedelta
        from sqlalchemy import func

        cutoff_date = datetime.utcnow() - timedelta(days=days)

        # Query with time bucketing
        trends = self.db.query(
            func.date(PredictionLog.timestamp).label('date'),
            func.count(PredictionLog.id).label('count'),
            func.avg(PredictionLog.processing_time_ms).label('avg_time'),
            func.avg(PredictionLog.confidence_score).label('avg_confidence')
        ).filter(
            PredictionLog.timestamp >= cutoff_date
        ).group_by(
            func.date(PredictionLog.timestamp)
        ).order_by(
            func.date(PredictionLog.timestamp)
        ).all()

        return [
            {
                "date": trend.date.isoformat(),
                "count": trend.count,
                "avg_processing_time_ms": float(trend.avg_time),
                "avg_confidence": float(trend.avg_confidence)
            }
            for trend in trends
        ]

# Usage
db_optimizer = DatabaseOptimizer(next(get_db()))

# Log prediction
db_optimizer.log_prediction({
    "input_text": "Patient reports chest pain",
    "prediction_label": "PRESENT",
    "confidence_score": 0.95,
    "processing_time_ms": 245.67,
    "request_id": "req-12345"
})

# Get statistics
stats = db_optimizer.get_prediction_stats(hours=24)
print(f"Predictions in last 24h: {stats['total_predictions']}")
```

### API Development Tools

#### FastAPI Development Server with Advanced Features
```bash
# Development with hot reload and debugging
uvicorn app.main:app \
  --reload \
  --host 0.0.0.0 \
  --port 8000 \
  --log-level debug \
  --access-log \
  --reload-dir app \
  --reload-exclude "tests/*" \
  --reload-exclude "__pycache__/*"

# Development with WebSocket support for real-time updates
uvicorn app.main:app \
  --reload \
  --host 0.0.0.0 \
  --port 8000 \
  --ws wsproto

# Development with custom middleware
class DevelopmentMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # Add development headers
            start_time = time.time()

            async def send_with_timing(message):
                if message["type"] == "http.response.start":
                    # Add processing time header
                    process_time = time.time() - start_time
                    headers = dict(message.get("headers", []))
                    headers[b"x-process-time"] = str(process_time).encode()
                    message["headers"] = list(headers.items())

                await send(message)

            await self.app(scope, receive, send_with_timing)
        else:
            await self.app(scope, receive, send)

# Apply development middleware
app.add_middleware(DevelopmentMiddleware)
```

#### API Documentation Enhancement
```python
# Enhanced OpenAPI documentation
from fastapi.openapi.utils import get_openapi

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Clinical BERT Assertion API",
        version="2.0.0",
        description="""
        ## Clinical BERT Assertion API

        A production-ready API for clinical text classification using state-of-the-art transformer models.

        ### Features
        - ⚡ Real-time clinical assertion detection
        - 🔒 Enterprise-grade security
        - 📊 Comprehensive monitoring
        - 🏥 HIPAA compliant
        - 🚀 Auto-scaling deployment

        ### Quick Start
        1. Get your API key from the dashboard
        2. Make requests to the prediction endpoints
        3. Monitor usage through the metrics endpoint

        ### Support
        - 📧 Email: support@company.com
        - 📚 Documentation: https://docs.company.com
        - 🐛 Issues: https://github.com/company/clinical-bert-api/issues
        """,
        routes=app.routes,
    )

    # Add custom components
    openapi_schema["components"]["securitySchemes"] = {
        "APIKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "API key authentication. Format: Bearer {api_key}"
        }
    }

    # Add security to all endpoints
    for path_data in openapi_schema["paths"].values():
        for operation in path_data.values():
            operation["security"] = [{"APIKeyAuth": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi
```

### Testing Advanced Features

#### Load Testing with Locust
```python
# advanced_locustfile.py
from locust import HttpUser, task, between, events
import json
import time
from typing import Dict, Any

class ClinicalBERTUser(HttpUser):
    """Advanced load testing user"""

    wait_time = between(1, 5)

    def on_start(self):
        """Initialize user session"""
        self.api_key = "test-api-key"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

    @task(5)  # Higher priority
    def predict_single(self):
        """Test single prediction endpoint"""
        payload = {
            "sentence": "The patient reports chest pain and shortness of breath."
        }

        with self.client.post(
            "/predict",
            json=payload,
            headers=self.headers,
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Status code: {response.status_code}")

    @task(3)  # Medium priority
    def predict_batch(self):
        """Test batch prediction endpoint"""
        payload = {
            "sentences": [
                "Patient has fever and cough.",
                "No signs of infection observed.",
                "Blood pressure is elevated at 160/95.",
                "Patient reports no chest pain.",
                "Laboratory results are normal."
            ]
        }

        with self.client.post(
            "/predict/batch",
            json=payload,
            headers=self.headers,
            catch_response=True
        ) as response:
            if response.status_code == 200:
                data = response.json()
                if len(data.get("predictions", [])) == len(payload["sentences"]):
                    response.success()
                else:
                    response.failure("Incorrect number of predictions")
            else:
                response.failure(f"Status code: {response.status_code}")

    @task(1)  # Lower priority
    def health_check(self):
        """Test health endpoint"""
        with self.client.get("/health", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Health check failed: {response.status_code}")

    @task(2)  # Medium priority
    def mixed_workload(self):
        """Test mixed workload patterns"""
        # Simulate realistic clinical workflow
        scenarios = [
            {"sentence": "Patient denies any chest pain or discomfort."},
            {"sentence": "The patient has a history of hypertension."},
            {"sentence": "No abnormal heart sounds detected."},
            {"sentence": "Patient reports possible medication side effects."}
        ]

        for scenario in scenarios:
            with self.client.post(
                "/predict",
                json=scenario,
                headers=self.headers,
                catch_response=True
            ) as response:
                if response.status_code != 200:
                    response.failure(f"Scenario failed: {response.status_code}")
                    break
            else:
                response.success()

            # Small delay between requests
            time.sleep(0.1)

@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Initialize load test"""
    print("Load test starting...")

@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Cleanup after load test"""
    print("Load test completed.")

@events.request.add_listener
def on_request(request_type, name, response_time, response_length, exception, **kwargs):
    """Log request details"""
    if exception:
        print(f"Request failed: {name} - {exception}")
```

#### Contract Testing
```python
# tests/contract_tests.py
import pytest
from pact import Consumer, Provider
from pact.matchers import EachLike, Term

# Pact contract testing
@pytest.fixture
def consumer():
    return Consumer('ClinicalBERTClient').has_pact_with(
        Provider('ClinicalBERTAPI'),
        host_name='localhost',
        port=8000
    )

def test_health_endpoint_contract(consumer):
    """Test health endpoint contract"""
    (
        consumer
        .given('API is healthy')
        .upon_receiving('a request for health status')
        .with_request('get', '/health')
        .will_respond_with(200, body={
            'status': 'healthy',
            'model_loaded': True,
            'timestamp': Term(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z', '2024-01-15T10:30:00.123Z'),
            'version': '1.0.0'
        })
    )

    with consumer:
        response = requests.get('http://localhost:8000/health')
        assert response.status_code == 200

def test_prediction_contract(consumer):
    """Test prediction endpoint contract"""
    (
        consumer
        .given('Model is loaded and ready')
        .upon_receiving('a prediction request')
        .with_request('post', '/predict', body={
            'sentence': 'The patient reports chest pain.'
        })
        .will_respond_with(200, body={
            'label': 'PRESENT',
            'score': 0.95,
            'model_label': 'PRESENT',
            'prediction_time_ms': 245.67,
            'request_id': Term(r'req-\w+-\w+', 'req-12345-abcde')
        })
    )

    with consumer:
        response = requests.post(
            'http://localhost:8000/predict',
            json={'sentence': 'The patient reports chest pain.'}
        )
        assert response.status_code == 200
```

### Development Productivity Tools

#### Code Generation Scripts
```python
# scripts/generate_api_client.py
import json
import requests
from pathlib import Path

def generate_python_client(base_url: str, output_file: str = "api_client.py"):
    """Generate Python API client from OpenAPI spec"""
    # Get OpenAPI specification
    response = requests.get(f"{base_url}/openapi.json")
    openapi_spec = response.json()

    # Generate client code
    client_code = f'''
"""
Auto-generated Clinical BERT API client
Generated from: {base_url}
Generated on: {datetime.now().isoformat()}
"""

import requests
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

@dataclass
class PredictionResult:
    """Prediction result data structure"""
    label: str
    score: float
    model_label: str
    prediction_time_ms: float
    request_id: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PredictionResult':
        return cls(**data)

@dataclass
class BatchPredictionResult:
    """Batch prediction result data structure"""
    predictions: List[PredictionResult]
    batch_size: int
    total_prediction_time_ms: float
    request_id: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BatchPredictionResult':
        predictions = [PredictionResult.from_dict(p) for p in data['predictions']]
        return cls(
            predictions=predictions,
            batch_size=data['batch_size'],
            total_prediction_time_ms=data['total_prediction_time_ms'],
            request_id=data['request_id']
        )

class ClinicalBERTClient:
    """Clinical BERT API client"""

    def __init__(self, base_url: str, api_key: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()

        if api_key:
            self.session.headers.update({{
                'Authorization': f'Bearer {{api_key}}'
            }})

    def predict(self, sentence: str) -> PredictionResult:
        """Make a single prediction"""
        response = self.session.post(
            f"{{self.base_url}}/predict",
            json={{"sentence": sentence}}
        )
        response.raise_for_status()
        return PredictionResult.from_dict(response.json())

    def predict_batch(self, sentences: List[str]) -> BatchPredictionResult:
        """Make batch predictions"""
        response = self.session.post(
            f"{{self.base_url}}/predict/batch",
            json={{"sentences": sentences}}
        )
        response.raise_for_status()
        return BatchPredictionResult.from_dict(response.json())

    def health_check(self) -> Dict[str, Any]:
        """Check API health"""
        response = self.session.get(f"{{self.base_url}}/health")
        response.raise_for_status()
        return response.json()

# Usage example
if __name__ == "__main__":
    client = ClinicalBERTClient("{base_url}")
    result = client.predict("The patient reports chest pain.")
    print(f"Prediction: {{result.label}} ({{result.score:.4f}})")
'''

    # Write client code
    with open(output_file, 'w') as f:
        f.write(client_code)

    print(f"API client generated: {output_file}")

# Generate client
generate_python_client("http://localhost:8000")
```

#### Development Dashboard
```python
# app/development_dashboard.py
from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from pathlib import Path
import json
from typing import Dict, Any

router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/dev/dashboard")
async def development_dashboard(request: Request):
    """Development dashboard with real-time metrics"""
    # Get current metrics
    metrics = {
        "health": await get_health_status(),
        "performance": await get_performance_metrics(),
        "errors": await get_error_summary(),
        "predictions": await get_prediction_stats()
    }

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "metrics": metrics,
            "title": "Development Dashboard"
        }
    )

@router.get("/dev/metrics/json")
async def development_metrics_json():
    """JSON endpoint for development metrics"""
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "health": await get_health_status(),
        "performance": await get_performance_metrics(),
        "errors": await get_error_summary(),
        "predictions": await get_prediction_stats()
    }

async def get_health_status() -> Dict[str, Any]:
    """Get current health status"""
    # Implementation would check actual health
    return {
        "status": "healthy",
        "model_loaded": True,
        "uptime": "2h 15m",
        "memory_usage": "1.2GB / 4GB"
    }

async def get_performance_metrics() -> Dict[str, Any]:
    """Get performance metrics"""
    return {
        "avg_response_time": "245ms",
        "requests_per_minute": 150,
        "error_rate": "0.02%",
        "throughput": "2.5 req/sec"
    }

async def get_error_summary() -> Dict[str, Any]:
    """Get error summary"""
    return {
        "total_errors": 5,
        "error_rate_trend": "decreasing",
        "top_errors": [
            {"type": "ValidationError", "count": 3},
            {"type": "ModelError", "count": 2}
        ]
    }

async def get_prediction_stats() -> Dict[str, Any]:
    """Get prediction statistics"""
    return {
        "total_predictions": 1250,
        "predictions_by_label": {
            "PRESENT": 650,
            "ABSENT": 450,
            "POSSIBLE": 150
        },
        "avg_confidence": 0.94,
        "processing_trend": "stable"
    }
```

---

**Develop • Test • Deploy • Debug • Analyze**

*Advanced development guide for Clinical BERT API*
