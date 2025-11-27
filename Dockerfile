# Multi-stage Dockerfile for optimized Clinical BERT API
# Stage 1: Builder - Install dependencies and pre-download model
FROM python:3.12-slim AS builder

WORKDIR /install

# Install system build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt

# Pre-download the Clinical BERT model to cache it in the image
# This prevents rate limiting issues during container startup in Cloud Run
RUN mkdir -p /root/.cache/huggingface/hub && \
    PYTHONPATH=/install/lib/python3.12/site-packages:$PYTHONPATH \
    HF_HUB_CACHE=/root/.cache/huggingface/hub python -c "\
import os; \
from transformers import AutoTokenizer, AutoModelForSequenceClassification; \
print('Downloading Clinical BERT model...'); \
model_name = 'bvanaken/clinical-assertion-negation-bert'; \
tokenizer = AutoTokenizer.from_pretrained(model_name); \
model = AutoModelForSequenceClassification.from_pretrained(model_name); \
print('Model downloaded successfully!')\
"

# Stage 2: Runtime - Optimized for Cloud Run
FROM python:3.12-slim

WORKDIR /code

# Install only runtime system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && adduser --disabled-password --gecos '' --shell /bin/bash appuser \
    && chown -R appuser:appuser /code

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy the pre-downloaded model cache from builder stage
COPY --from=builder /root/.cache/huggingface /root/.cache/huggingface

# Set environment variables before switching user
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/usr/local/bin:$PATH" \
    HF_HUB_CACHE=/root/.cache/huggingface/hub

# Copy application code
COPY --chown=appuser:appuser ./app ./app
COPY --chown=appuser:appuser entrypoint.sh .

# Make entrypoint executable
RUN chmod +x entrypoint.sh

USER appuser

# Health check for Cloud Run (extended for model loading)
HEALTHCHECK --interval=30s --timeout=60s --start-period=520s --retries=5 \
    CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080

# Use entrypoint script for proper PORT handling
ENTRYPOINT ["./entrypoint.sh"]
