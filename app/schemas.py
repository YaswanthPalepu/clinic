# Standard library imports
from enum import Enum
from typing import Any, Dict, List, Optional

# Third party imports
from pydantic import BaseModel, ConfigDict, Field, field_validator


class AssertionLabel(str, Enum):
    """Possible assertion labels"""

    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    POSSIBLE = "POSSIBLE"
    CONDITIONAL = "CONDITIONAL"


class PredictionRequest(BaseModel):
    """Request model for single prediction"""

    model_config = ConfigDict(
        protected_namespaces=(),
        json_schema_extra={"example": {"sentence": "The patient denies chest pain."}},
    )

    sentence: str = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="Clinical sentence to classify",
    )

    @field_validator("sentence")
    @classmethod
    def validate_sentence(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Sentence cannot be empty or whitespace only")
        return v.strip()


class PredictionResponse(BaseModel):
    """Response model for single prediction"""

    model_config = ConfigDict(
        protected_namespaces=(),
        json_schema_extra={
            "example": {
                "label": "ABSENT",
                "score": 0.9842,
                "prediction_time_ms": 45.2,
                "request_id": "req-12345",
            }
        },
    )

    label: str = Field(..., description="Predicted assertion label")
    model_label: str = Field(..., description="Raw model prediction label")
    score: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence score between 0 and 1"
    )
    rule_applied: Optional[str] = Field(
        None, description="Rule applied for label enhancement"
    )
    prediction_time_ms: Optional[float] = Field(
        None, description="Prediction time in milliseconds"
    )
    request_id: Optional[str] = Field(None, description="Request identifier")


class BatchPredictionRequest(BaseModel):
    """Request model for batch prediction"""

    model_config = ConfigDict(protected_namespaces=())

    sentences: List[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="List of clinical sentences to classify",
    )

    @field_validator("sentences")
    @classmethod
    def validate_sentences(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("Sentences list cannot be empty")

        for i, sentence in enumerate(v):
            if not sentence or not sentence.strip():
                raise ValueError(
                    f"Sentence at index {i} cannot be empty or whitespace only"
                )
            if len(sentence) > 1000:
                raise ValueError(
                    f"Sentence at index {i} is too long (max 1000 characters)"
                )

        return [sentence.strip() for sentence in v]


class BatchPredictionResponse(BaseModel):
    """Response model for batch prediction"""

    model_config = ConfigDict(protected_namespaces=())

    predictions: List[PredictionResponse] = Field(
        ..., description="List of predictions for each sentence"
    )
    batch_size: int = Field(..., description="Number of sentences processed")
    total_prediction_time_ms: Optional[float] = Field(
        None, description="Total time for batch prediction"
    )
    request_id: Optional[str] = Field(None, description="Request identifier")


class HealthResponse(BaseModel):
    """Response model for health check endpoint"""

    model_config = ConfigDict(protected_namespaces=())

    status: str = Field(..., description="Overall health status")
    model_loaded: bool = Field(
        ..., description="Whether the ML model is loaded and ready"
    )
    timestamp: float = Field(..., description="Unix timestamp of the health check")
    version: Optional[str] = Field("1.0.0", description="API version")
    environment: Optional[str] = Field(None, description="Environment name")
    uptime_seconds: Optional[float] = Field(None, description="Uptime in seconds")
    total_predictions: Optional[int] = Field(None, description="Total predictions made")
    system_metrics: Optional[Dict[str, Any]] = Field(
        None, description="System performance metrics"
    )
    model_info: Optional[Dict[str, Any]] = Field(None, description="Model information")


class MetricsResponse(BaseModel):
    """Response model for system metrics"""

    model_config = ConfigDict(protected_namespaces=())

    total_predictions: int = Field(..., description="Total number of predictions made")
    uptime_seconds: float = Field(..., description="API uptime in seconds")
    memory_usage_mb: Optional[float] = Field(
        None, description="Current memory usage in MB"
    )
    cpu_usage_percent: Optional[float] = Field(None, description="CPU usage percentage")
    model_loaded: bool = Field(..., description="Whether model is loaded and ready")


class ModelInfoResponse(BaseModel):
    """Response model for model information"""

    model_config = ConfigDict(protected_namespaces=())

    model_name: str = Field(..., description="Name of the Hugging Face model")
    device: str = Field(..., description="Device the model is running on")
    loaded: bool = Field(..., description="Whether model is loaded")
    labels: List[str] = Field(..., description="Possible prediction labels")
    cuda_available: bool = Field(..., description="Whether CUDA is available")
