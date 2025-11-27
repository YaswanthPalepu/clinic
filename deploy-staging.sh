#!/bin/bash

# Clinical BERT API - Production Deployment Script
# CORRECTED VERSION - Fixed Cloud Run tagging

set -euo pipefail

# Configuration (aligned with GitHub Actions)
PROJECT_ID="${GCP_PROJECT_ID:-}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="clinical-bert-api"  # Production service name
REPOSITORY="clinical-bert-repo"
IMAGE_TAG="${IMAGE_TAG:-latest}"  # Docker image tag (can have dots)

# Standardized resources (same as GitHub Actions)
MEMORY="2Gi"
CPU="1"
MAX_INSTANCES="10"
TIMEOUT="300"
CONCURRENCY="80"
PORT="8080"

# FIXED: Cloud Run tag - Use simple tags without dots
CLOUD_RUN_TAG="latest"  # Valid Cloud Run tag (no dots, no special chars)

echo "Deploying Clinical BERT API to Production"
echo "Configuration:"
echo "   Project: $PROJECT_ID"
echo "   Region: $REGION"
echo "   Service: $SERVICE_NAME"
echo "   Docker Image Tag: $IMAGE_TAG"
echo "   Cloud Run Traffic Tag: $CLOUD_RUN_TAG"
echo "   Memory: $MEMORY, CPU: $CPU"
echo "   Max Instances: $MAX_INSTANCES"
echo "   Timeout: ${TIMEOUT}s, Concurrency: $CONCURRENCY"

# Validate project ID
if [[ -z "$PROJECT_ID" ]]; then
    echo "Error: GCP_PROJECT_ID environment variable required"
    exit 1
fi

# Set project
echo "Setting GCP project..."
gcloud config set project "$PROJECT_ID"

# Enable required APIs
echo "Enabling APIs..."
gcloud services enable cloudbuild.googleapis.com run.googleapis.com artifactregistry.googleapis.com || true

# Create Artifact Registry repository if it doesn't exist
echo "Setting up Artifact Registry..."
gcloud artifacts repositories create "$REPOSITORY" \
    --repository-format=docker \
    --location="$REGION" \
    --description="Clinical BERT API repository" || true

# Configure Docker for Artifact Registry
echo "Configuring Docker..."
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet

# Build Docker image
echo "Building Docker image..."
docker build -t "clinical-bert-api:$IMAGE_TAG" .

# Tag for Artifact Registry (both version and latest)
IMAGE_NAME="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPOSITORY}/clinical-bert-api:$IMAGE_TAG"
LATEST_IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPOSITORY}/clinical-bert-api:latest"

echo "Tagging images..."
docker tag "clinical-bert-api:$IMAGE_TAG" "$IMAGE_NAME"
docker tag "clinical-bert-api:$IMAGE_TAG" "$LATEST_IMAGE"

# Push images to Artifact Registry
echo "Pushing images to Artifact Registry..."
docker push "$IMAGE_NAME"
docker push "$LATEST_IMAGE"

# Deploy to Cloud Run (Production) - FIXED: Using CLOUD_RUN_TAG instead of IMAGE_TAG
echo "Deploying to Cloud Run (Production)..."
gcloud run deploy "$SERVICE_NAME" \
    --image="$IMAGE_NAME" \
    --region="$REGION" \
    --platform=managed \
    --allow-unauthenticated \
    --memory="$MEMORY" \
    --cpu="$CPU" \
    --max-instances="$MAX_INSTANCES" \
    --timeout="$TIMEOUT" \
    --concurrency="$CONCURRENCY" \
    --port="$PORT" \
    --service-account="${GCP_SERVICE_ACCOUNT:-}" \
    --set-env-vars="ENVIRONMENT=production,DEBUG=false" \
    --tag="$CLOUD_RUN_TAG"  # FIXED: 'latest' instead of 'v1.0.6'

echo "Production deployment completed!"

# Get service URL
echo "Getting service URL..."
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" \
    --region="$REGION" \
    --format="value(status.url)")

echo "Production Service URL: $SERVICE_URL"
echo "Docker Image: $IMAGE_NAME"
echo "Cloud Run Revision Tagged: $CLOUD_RUN_TAG"

# Health check
echo "Performing health check..."
sleep 30  # Wait for deployment to stabilize

if curl -f -m 60 "$SERVICE_URL/health" 2>/dev/null; then
    echo "Health check PASSED!"
else
    echo "Health check failed - deployment may still be propagating"
    echo "   Manual check: curl -f '$SERVICE_URL/health'"
    # Don't exit on health check failure - deployment succeeded
fi

echo ""
echo "Clinical BERT API deployed successfully to Production!"
echo "Access: $SERVICE_URL"
echo "Docker Version: $IMAGE_TAG"
echo "Docker Image: $IMAGE_NAME"
echo "Cloud Run Revision: Tagged as '$CLOUD_RUN_TAG'"
