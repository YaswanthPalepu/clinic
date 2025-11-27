# Standard library imports
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator

# Third party imports
import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from .auth import verify_api_key
from .middleware import (
    MetricsMiddleware,
    RateLimitMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
)
from .model import ClinicalAssertionModel
from .schemas import (
    BatchPredictionRequest,
    BatchPredictionResponse,
    HealthResponse,
    MetricsResponse,
    ModelInfoResponse,
    PredictionRequest,
    PredictionResponse,
)
from .utils import apply_hybrid_pipeline, get_system_metrics, sanitize_clinical_text

# Configure structured logging
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Prometheus metrics
REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)
REQUEST_DURATION = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration",
    ["method", "endpoint"],
)
MODEL_INFERENCE_DURATION = Histogram(
    "model_inference_duration_seconds", "Model inference time"
)
MODEL_PREDICTIONS_TOTAL = Counter(
    "model_predictions_total", "Total model predictions", ["label"]
)

# Global variables
model = None
app_start_time = time.time()
prediction_count = 0


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Enhanced application lifespan management"""
    global model

    logger.info("Starting Clinical BERT API...")
    logger.info(f"Environment: {os.getenv('ENVIRONMENT', 'development')}")
    logger.info(f"Log Level: {os.getenv('LOG_LEVEL', 'INFO')}")

    try:
        # Initialize model
        model = ClinicalAssertionModel()
        await model.load_model()

        # Warm up model with a test prediction
        logger.info("Warming up model...")
        await model.predict("Test sentence for model warmup.")

        logger.info("Clinical BERT API started successfully!")
        logger.info(f"Model Info: {model.get_model_info()}")

    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise

    yield

    # Cleanup
    logger.info("Shutting down Clinical BERT API...")
    if model:
        # Cleanup model resources if needed
        pass
    logger.info("Shutdown completed")


# Create FastAPI app with enhanced configuration
app = FastAPI(
    title="Clinical BERT Assertion API",
    description="""
    Production-Grade Clinical Text Classification API

    Real-time inference API for clinical assertion detection using
    `bvanaken/clinical-assertion-negation-bert` from Hugging Face.

    ## Features
    - Sub-500ms response time
    - Enterprise security
    - Comprehensive monitoring
    - Auto-scaling deployment
    - Extensive testing coverage

    ## Assertion Categories
    - **PRESENT**: Medical condition is explicitly present
    - **ABSENT**: Medical condition is explicitly absent/negated
    - **POSSIBLE**: Medical condition is possible/uncertain
    """,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",  # Always enable docs for testing
    redoc_url="/redoc",  # Always enable redoc for testing
)

# Add middleware stack (order matters!)
app.add_middleware(
    SecurityHeadersMiddleware,
    csp_policy="default-src 'self' https://cdn.jsdelivr.net https://fastapi.tiangolo.com; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com",
    hsts_max_age=31536000,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=(
        ["*"]
        if os.getenv("ENVIRONMENT") == "development"
        else ["*.run.app", "localhost", "127.0.0.1"]  # Google Cloud Run
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(MetricsMiddleware)

# Add rate limiting if configured
if os.getenv("ENABLE_RATE_LIMITING", "false").lower() == "true":
    app.add_middleware(
        RateLimitMiddleware, requests_per_minute=int(os.getenv("RATE_LIMIT_RPM", "100"))
    )


# Simple status endpoint for CI/CD and basic checks (no authentication required)
@app.get(
    "/status",
    tags=["Health Check"],
    summary="Basic service status",
    description="Returns basic service status without model dependency",
)
async def service_status() -> dict:
    """Simple status endpoint for CI/CD and basic health checks"""
    global app_start_time

    uptime_seconds = time.time() - app_start_time

    return {
        "status": "running",
        "timestamp": time.time(),
        "version": "1.0.0",
        "environment": os.getenv("ENVIRONMENT", "development"),
        "uptime_seconds": uptime_seconds,
        "message": "Clinical BERT API is running",
    }


# Health check endpoint (no authentication required)
@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Health Check"],
    summary="Service health check",
    description="Returns service health status and model readiness",
)
async def health_check() -> HealthResponse:
    """Comprehensive health check endpoint"""
    global model, app_start_time, prediction_count

    try:
        # Basic health check
        if model is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Model not loaded",
            )

        # Model readiness check
        model_loaded = model.is_loaded()

        # System metrics
        uptime_seconds = time.time() - app_start_time
        system_metrics = get_system_metrics()

        # Create response with proper typing
        return HealthResponse(
            status="healthy" if model_loaded else "unhealthy",
            model_loaded=model_loaded,
            timestamp=time.time(),
            version="1.0.0",
            environment=os.getenv("ENVIRONMENT", "development"),
            uptime_seconds=uptime_seconds,
            total_predictions=prediction_count,
            system_metrics=system_metrics,
            model_info=model.get_model_info() if model_loaded else None,
        )

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Health check failed: {str(e)}",
        )


# Metrics endpoint for Prometheus
@app.get("/metrics", tags=["Monitoring"])
async def metrics() -> Response:
    """Prometheus metrics endpoint"""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# Model info endpoint
@app.get(
    "/model/info",
    response_model=ModelInfoResponse,
    tags=["Model"],
    dependencies=[Depends(verify_api_key)] if os.getenv("REQUIRE_API_KEY") else [],
)
async def model_info() -> ModelInfoResponse:
    """Get detailed model information"""
    if not model or not model.is_loaded():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Model not loaded"
        )

    return ModelInfoResponse(**model.get_model_info())


# Prediction endpoint
@app.post(
    "/predict",
    response_model=PredictionResponse,
    tags=["Prediction"],
    dependencies=[Depends(verify_api_key)] if os.getenv("REQUIRE_API_KEY") else [],
    summary="Single sentence prediction",
    description="Classify a single clinical sentence for assertion status",
)
async def predict_assertion(
    request: PredictionRequest,
    background_tasks: BackgroundTasks,
) -> PredictionResponse:
    """Enhanced prediction endpoint with monitoring and security"""
    global model, prediction_count

    if not model or not model.is_loaded():
        REQUEST_COUNT.labels(method="POST", endpoint="/predict", status="503").inc()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Model not loaded"
        )

    # Generate request ID for tracing
    request_id = str(uuid.uuid4())

    # Sanitize input for security
    sanitized_sentence = sanitize_clinical_text(request.sentence)

    try:
        start_time = time.time()

        # Log request (sanitized)
        logger.info(
            f"Prediction request {request_id}: sentence_length={len(request.sentence)}"
        )

        # Model inference with timing
        with MODEL_INFERENCE_DURATION.time():
            model_result = await model.predict(sanitized_sentence)

        # Apply hybrid pipeline for enhanced classification
        enhanced_results = apply_hybrid_pipeline([model_result], [sanitized_sentence])
        result = enhanced_results[0]

        prediction_time = time.time() - start_time
        prediction_count += 1

        # Update metrics
        REQUEST_COUNT.labels(method="POST", endpoint="/predict", status="200").inc()
        MODEL_PREDICTIONS_TOTAL.labels(label=result["label"]).inc()

        # Log successful prediction
        logger.info(
            f"Prediction completed {request_id}: "
            f"label={result['label']}, model_label={result['model_label']}, "
            f"rule_applied={result.get('rule_applied')}, score={result['score']:.4f}, "
            f"time={prediction_time:.3f}s"
        )

        # Background task for analytics (if needed)
        background_tasks.add_task(
            log_prediction_analytics, request_id, result["label"], prediction_time
        )

        return PredictionResponse(
            label=result["label"],
            model_label=result["model_label"],
            score=result["score"],
            rule_applied=result.get("rule_applied"),
            prediction_time_ms=prediction_time * 1000,
            request_id=request_id,
        )

    except Exception as e:
        REQUEST_COUNT.labels(method="POST", endpoint="/predict", status="500").inc()
        logger.error(f"Prediction failed {request_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Prediction failed: {str(e)}",
        )


# Batch prediction endpoint
@app.post(
    "/predict/batch",
    response_model=BatchPredictionResponse,
    tags=["Prediction"],
    dependencies=[Depends(verify_api_key)] if os.getenv("REQUIRE_API_KEY") else [],
    summary="Batch sentence prediction",
    description="Classify multiple clinical sentences for assertion status",
)
async def predict_batch(
    request: BatchPredictionRequest, background_tasks: BackgroundTasks
) -> BatchPredictionResponse:
    """Enhanced batch prediction with optimizations"""
    global model, prediction_count

    if not model or not model.is_loaded():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Model not loaded"
        )

    # Validate batch size
    max_batch_size = int(os.getenv("MAX_BATCH_SIZE", "100"))
    if len(request.sentences) > max_batch_size:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Batch size cannot exceed {max_batch_size} sentences",
        )

    request_id = str(uuid.uuid4())

    try:
        start_time = time.time()

        # Sanitize all sentences
        sanitized_sentences = [
            sanitize_clinical_text(sentence) for sentence in request.sentences
        ]

        logger.info(
            f"Batch prediction request {request_id}: "
            f"batch_size={len(request.sentences)}"
        )

        # Batch inference
        with MODEL_INFERENCE_DURATION.time():
            model_results = await model.predict_batch(sanitized_sentences)

        # Apply hybrid pipeline for enhanced classification
        enhanced_results = apply_hybrid_pipeline(model_results, sanitized_sentences)

        prediction_time = time.time() - start_time
        prediction_count += len(request.sentences)

        # Update metrics
        REQUEST_COUNT.labels(
            method="POST", endpoint="/predict/batch", status="200"
        ).inc()
        for result in enhanced_results:
            MODEL_PREDICTIONS_TOTAL.labels(label=result["label"]).inc()

        # Convert to response format
        predictions = [
            PredictionResponse(
                label=result["label"],
                model_label=result["model_label"],
                score=result["score"],
                rule_applied=result.get("rule_applied"),
                prediction_time_ms=(prediction_time * 1000) / len(enhanced_results),
                request_id=request_id,
            )
            for result in enhanced_results
        ]

        logger.info(
            f"Batch prediction completed {request_id}: "
            f"batch_size={len(enhanced_results)}, time={prediction_time:.3f}s"
        )

        # Background analytics
        background_tasks.add_task(
            log_batch_analytics, request_id, len(enhanced_results), prediction_time
        )

        return BatchPredictionResponse(
            predictions=predictions,
            batch_size=len(enhanced_results),
            total_prediction_time_ms=prediction_time * 1000,
            request_id=request_id,
        )

    except Exception as e:
        REQUEST_COUNT.labels(
            method="POST", endpoint="/predict/batch", status="500"
        ).inc()
        logger.error(f"Batch prediction failed {request_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch prediction failed: {str(e)}",
        )


# System metrics endpoint
@app.get(
    "/system/metrics",
    response_model=MetricsResponse,
    tags=["Monitoring"],
    dependencies=[Depends(verify_api_key)] if os.getenv("REQUIRE_API_KEY") else [],
)
async def system_metrics() -> MetricsResponse:
    """Get system performance metrics"""
    global app_start_time, prediction_count

    uptime_seconds = time.time() - app_start_time
    system_metrics = get_system_metrics()

    return MetricsResponse(
        total_predictions=prediction_count,
        uptime_seconds=uptime_seconds,
        memory_usage_mb=system_metrics.get("memory_mb", 0),
        cpu_usage_percent=system_metrics.get("cpu_percent", 0),
        model_loaded=model.is_loaded() if model else False,
    )


# Root endpoint
@app.get("/", tags=["Root"])
async def root() -> dict:
    """API information and status"""
    return {
        "name": "Clinical BERT Assertion API",
        "version": "1.0.0",
        "description": "Production-grade clinical text classification API",
        "model": "bvanaken/clinical-assertion-negation-bert",
        "environment": os.getenv("ENVIRONMENT", "development"),
        "status": "healthy" if model and model.is_loaded() else "initializing",
        "endpoints": {
            "status": "/status",
            "health": "/health",
            "predict": "/predict",
            "batch_predict": "/predict/batch",
            "model_info": "/model/info",
            "metrics": "/metrics",
            "docs": "/docs",
            "redoc": "/redoc",
        },
        "features": [
            "Sub-500ms response time",
            "Batch processing",
            "Comprehensive monitoring",
            "Security middleware",
            "Auto-scaling deployment",
        ],
    }


# Background tasks
async def log_prediction_analytics(
    request_id: str, label: str, prediction_time: float
) -> None:
    """Log prediction analytics for monitoring"""
    logger.info(f"Analytics {request_id}: label={label}, time={prediction_time:.3f}s")


async def log_batch_analytics(
    request_id: str, batch_size: int, prediction_time: float
) -> None:
    """Log batch prediction analytics"""
    logger.info(
        f"Batch analytics {request_id}: size={batch_size}, time={prediction_time:.3f}s"
    )


# Custom exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Enhanced HTTP exception handler"""
    REQUEST_COUNT.labels(
        method=request.method, endpoint=request.url.path, status=str(exc.status_code)
    ).inc()

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": time.time(),
            "path": str(request.url.path),
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Enhanced general exception handler"""
    REQUEST_COUNT.labels(
        method=request.method, endpoint=request.url.path, status="500"
    ).inc()

    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)

    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500,
            "timestamp": time.time(),
            "path": str(request.url.path),
        },
    )


# Application startup configuration is handled in lifespan


if __name__ == "__main__":
    # Production server configuration
    port = int(os.getenv("PORT", "8080"))  # Cloud Run default is 8080
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        workers=int(os.getenv("WORKERS", 1)),
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
        access_log=True,
        use_colors=False if os.getenv("ENVIRONMENT") == "production" else True,
    )
