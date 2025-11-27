#!/bin/bash

# Clinical BERT API - Production Deployment Script
# FIXED VERSION

set -euo pipefail

PROJECT_ID="${GCP_PROJECT_ID:-}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="clinical-bert-api"
REPOSITORY="clinical-bert-repo"
IMAGE_TAG="${IMAGE_TAG:-latest}"

MEMORY="2Gi"
CPU="1"
MAX_INSTANCES="10"
TIMEOUT="300"
CONCURRENCY="80"
PORT="8080"

CLOUD_RUN_TAG="latest"  # FIXED: Valid Cloud Run tag

echo "Deploying Clinical BERT API to Production"
echo "   Docker Image: $IMAGE_TAG"
echo "   Cloud Run Tag: $CLOUD_RUN_TAG"

if [[ -z "$PROJECT_ID" ]]; then
    echo "Error: GCP_PROJECT_ID required"
    exit 1
fi

gcloud config set project "$PROJECT_ID"
gcloud services enable run.googleapis.com artifactregistry.googleapis.com || true
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet

echo "Building Docker image..."
docker build -t "clinical-bert-api:$IMAGE_TAG" .

IMAGE_NAME="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPOSITORY}/clinical-bert-api:$IMAGE_TAG"
LATEST_IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPOSITORY}/clinical-bert-api:latest"

echo "Tagging images..."
docker tag "clinical-bert-api:$IMAGE_TAG" "$IMAGE_NAME"
docker tag "clinical-bert-api:$IMAGE_TAG" "$LATEST_IMAGE"

echo "Pushing images..."
docker push "$IMAGE_NAME"
docker push "$LATEST_IMAGE"

echo "Deploying to Cloud Run..."
gcloud run deploy "$SERVICE_NAME" \
    --image="$IMAGE_NAME" \
    --region="$REGION" \
    --allow-unauthenticated \
    --memory="$MEMORY" \
    --cpu="$CPU" \
    --max-instances="$MAX_INSTANCES" \
    --timeout="$TIMEOUT" \
    --concurrency="$CONCURRENCY" \
    --port="$PORT" \
    --service-account="${GCP_SERVICE_ACCOUNT:-}" \
    --set-env-vars="ENVIRONMENT=production,DEBUG=false" \
    --tag="$CLOUD_RUN_TAG"  # FIXED!

SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --region="$REGION" --format="value(status.url)")

echo "Deployment completed!"
echo "URL: $SERVICE_URL"

# Health check
echo "Health check..."
sleep 30
if curl -f -m 60 "$SERVICE_URL/health" 2>/dev/null; then
    echo "Health check PASSED!"
else
    echo "Health check failed - check manually"
fi

echo "Deployed successfully!"
