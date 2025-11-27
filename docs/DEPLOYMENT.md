# Clinical BERT Assertion API - Enterprise Deployment Guide

## Deployment Overview

This guide covers comprehensive deployment strategies for the Clinical BERT Assertion API across multiple environments and platforms. The API is optimized for cloud-native deployment with enterprise-grade security, monitoring, and scalability.

### Deployment Options

| Platform | Use Case | Setup Time | Maintenance |
|----------|----------|------------|-------------|
| **Google Cloud Run** | Production, Auto-scaling | ~30 minutes | Low |
| **Kubernetes** | Enterprise, Multi-cloud | ~2 hours | Medium |
| **Docker Compose** | Development, Testing | ~15 minutes | Low |
| **Local Development** | Development, Debugging | ~10 minutes | High |

---

## Local Development Setup

### Prerequisites
- Python 3.12+
- Git
- Virtual environment tool (venv, conda, or virtualenv)

### Quick Start
```bash
# 1. Clone repository
git clone https://github.com/Basavarajsm2102/Clinical_BERT_Assertion_API.git
cd Clinical_BERT_Assertion_API

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start development server
uvicorn app.main:app --reload --port 8000

# 5. Verify deployment
curl http://localhost:8000/health
```

### Development Configuration

#### Environment Variables
```bash
# Application settings
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

# Optional: Authentication (development only)
API_KEY=dev-api-key-12345
REQUIRE_API_KEY=false
```

#### Development Tools
```bash
# Run with auto-reload
uvicorn app.main:app --reload --log-level debug

# Run with multiple workers
uvicorn app.main:app --workers 4 --host 0.0.0.0 --port 8000

# Run with SSL (development)
uvicorn app.main:app --ssl-keyfile ./certs/key.pem --ssl-certfile ./certs/cert.pem

# Access documentation
open http://localhost:8000/docs
```

### Development Best Practices

#### Code Quality
```bash
# Run all quality checks
make quality

# Individual checks
make lint          # Code linting with flake8
make format        # Code formatting with black
make type-check    # Type checking with mypy
make security      # Security scanning with bandit
```

#### Testing
```bash
# Run test suite
pytest

# Run with coverage
pytest --cov=app --cov-report=html --cov-report=term

# Run specific test categories
pytest -m unit -v                    # Unit tests
pytest -m integration -v             # Integration tests
pytest -m performance -v             # Performance tests
pytest tests/test_api.py -v          # Specific test file

# Run tests in parallel
pytest -n auto --dist loadfile
```

#### Debugging
```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
uvicorn app.main:app --reload --log-level debug

# Profile performance
python -m cProfile -s time app/main.py

# Memory profiling
python -m memory_profiler app/main.py
```

---

## Docker Deployment

### Single Container Deployment

#### Build and Run
```bash
# Build optimized image
docker build -t clinical-bert-api:latest .

# Run with default settings
docker run -p 8000:8080 clinical-bert-api:latest

# Run with custom configuration
docker run \
  -p 8000:8080 \
  -e ENVIRONMENT=production \
  -e LOG_LEVEL=INFO \
  -e API_KEY=your-production-key \
  clinical-bert-api:latest

# Run with volume mounts
docker run \
  -p 8000:8080 \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/model_cache:/app/model_cache \
  clinical-bert-api:latest
```

#### Docker Configuration

**Dockerfile (Optimized for Production):**
```dockerfile
# Multi-stage build for optimization
FROM python:3.12-slim AS builder

WORKDIR /install
RUN apt-get update && apt-get install -y build-essential curl
COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt

FROM python:3.12-slim AS runtime

WORKDIR /code
RUN apt-get update && apt-get install -y curl && \
    adduser --disabled-password --gecos '' appuser && \
    chown -R appuser:appuser /code

COPY --from=builder /install /usr/local
COPY --chown=appuser:appuser ./app ./app
COPY --chown=appuser:appuser entrypoint.sh .

RUN chmod +x entrypoint.sh

USER appuser
ENV PYTHONUNBUFFERED=1
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=15s --start-period=120s --retries=5 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["./entrypoint.sh"]
```

### Docker Compose Deployment

#### Development Stack
```yaml
# docker-compose.yml
version: '3.8'

services:
  clinical-bert-api:
    build: .
    ports:
      - "8000:8080"
    environment:
      - ENVIRONMENT=development
      - LOG_LEVEL=DEBUG
    volumes:
      - ./logs:/app/logs
      - ./model_cache:/app/model_cache
    restart: unless-stopped

  # Optional: Redis for caching
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped

volumes:
  redis_data:
```

#### Production Stack
```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  clinical-bert-api:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      - ENVIRONMENT=production
      - LOG_LEVEL=INFO
      - API_KEY=${API_KEY}
    volumes:
      - ./logs:/app/logs:rw
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

  # Monitoring stack
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana
    restart: unless-stopped

volumes:
  prometheus_data:
  grafana_data:
```

### Docker Best Practices

#### Image Optimization
```dockerfile
# Use multi-stage builds
FROM python:3.12-slim AS builder
# Build dependencies in isolated stage

FROM python:3.12-slim AS runtime
# Copy only runtime dependencies
COPY --from=builder /install /usr/local

# Use non-root user
RUN adduser --disabled-password --gecos '' appuser
USER appuser

# Minimize layers
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Use .dockerignore
node_modules
__pycache__
*.pyc
.git
```

#### Security Hardening
```dockerfile
# Run as non-root user
RUN adduser --disabled-password --gecos '' appuser
USER appuser

# No secrets in image
# Use environment variables or mounted secrets

# Minimal attack surface
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Health checks
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1
```

---

## Google Cloud Run Deployment

### Prerequisites
- Google Cloud Platform account
- `gcloud` CLI installed and configured
- Docker installed
- Project with billing enabled

### Step-by-Step Deployment

#### 1. Project Setup
```bash
# Set project
export GCP_PROJECT_ID="your-project-id"
export GCP_REGION="us-central1"

# Configure gcloud
gcloud config set project $GCP_PROJECT_ID
gcloud config set compute/region $GCP_REGION

# Enable required APIs
gcloud services enable run.googleapis.com
gcloud services enable containerregistry.googleapis.com
gcloud services enable artifactregistry.googleapis.com
```

#### 2. Authentication
```bash
# Authenticate with Google Cloud
gcloud auth login

# Configure Docker authentication
gcloud auth configure-docker us-central1-docker.pkg.dev
```

#### 3. Build and Push Image
```bash
# Build optimized image
docker build -t clinical-bert-api:latest .

# Tag for Google Container Registry
docker tag clinical-bert-api:latest \
  us-central1-docker.pkg.dev/$GCP_PROJECT_ID/clinical-bert-repo/clinical-bert-api:latest

# Push to registry
docker push us-central1-docker.pkg.dev/$GCP_PROJECT_ID/clinical-bert-repo/clinical-bert-api:latest
```

#### 4. Deploy to Cloud Run
```bash
# Deploy with optimized settings
gcloud run deploy clinical-bert-api \
  --image=us-central1-docker.pkg.dev/$GCP_PROJECT_ID/clinical-bert-repo/clinical-bert-api:latest \
  --region=$GCP_REGION \
  --allow-unauthenticated \
  --memory=2Gi \
  --cpu=1 \
  --max-instances=10 \
  --timeout=300 \
  --concurrency=80 \
  --port=8080 \
  --set-env-vars="ENVIRONMENT=production,LOG_LEVEL=INFO" \
  --set-secrets="API_KEY=api-key-secret:latest"
```

#### 5. Configure Custom Domain (Optional)
```bash
# Map custom domain
gcloud run domain-mappings create \
  --service=clinical-bert-api \
  --domain=api.yourdomain.com \
  --region=$GCP_REGION

# Verify domain mapping
gcloud run domain-mappings list --region=$GCP_REGION
```

### Cloud Run Configuration

#### Environment Variables
```bash
# Application settings
ENVIRONMENT=production
LOG_LEVEL=INFO
DEBUG=false

# Model settings
MODEL_CACHE_DIR=/tmp/model_cache
MAX_SEQUENCE_LENGTH=512

# API settings
PORT=8080

# Security (use secrets)
API_KEY_SECRET=api-key-secret
JWT_SECRET_KEY=jwt-secret-key
```

#### Secrets Management
```bash
# Create secrets
echo -n "your-production-api-key" | gcloud secrets create api-key-secret --data-file=-
echo -n "your-jwt-secret-key" | gcloud secrets create jwt-secret-key --data-file=-

# Update service with secrets
gcloud run services update clinical-bert-api \
  --set-secrets="API_KEY=api-key-secret:latest" \
  --region=$GCP_REGION
```

#### Scaling Configuration
```bash
# Configure auto-scaling
gcloud run services update clinical-bert-api \
  --min-instances=1 \
  --max-instances=20 \
  --concurrency=80 \
  --region=$GCP_REGION

# Configure CPU allocation
gcloud run services update clinical-bert-api \
  --cpu=1 \
  --memory=2Gi \
  --region=$GCP_REGION
```

### Cloud Run Best Practices

#### Performance Optimization
- **Memory allocation**: 2GB minimum for model loading
- **CPU allocation**: 1 vCPU for optimal performance
- **Concurrency**: 80 requests per instance
- **Timeout**: 300 seconds for long-running requests
- **Min instances**: 1 to reduce cold starts

#### Cost Optimization
- **Auto-scaling**: Scale to zero when idle
- **Instance sizing**: Right-size based on load testing
- **Regional deployment**: Deploy close to users
- **Monitoring**: Track usage patterns for optimization

#### Security Configuration
```bash
# VPC connector for private networking
gcloud compute networks vpc-access connectors create clinical-bert-connector \
  --region=$GCP_REGION \
  --network=default \
  --range=10.8.0.0/28

# Update service with VPC connector
gcloud run services update clinical-bert-api \
  --vpc-connector=clinical-bert-connector \
  --region=$GCP_REGION
```

---

## Kubernetes Deployment

### Prerequisites
- Kubernetes cluster (GKE, EKS, AKS, or self-managed)
- `kubectl` configured
- Helm (optional, for easier deployment)

### Basic Kubernetes Deployment

#### Namespace Setup
```bash
# Create namespace
kubectl create namespace clinical-bert

# Set as default
kubectl config set-context --current --namespace=clinical-bert
```

#### ConfigMap and Secrets
```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: clinical-bert-config
data:
  ENVIRONMENT: "production"
  LOG_LEVEL: "INFO"
  MAX_BATCH_SIZE: "100"
  MAX_SEQUENCE_LENGTH: "512"

---
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: clinical-bert-secrets
type: Opaque
data:
  API_KEY: <base64-encoded-api-key>
  JWT_SECRET_KEY: <base64-encoded-jwt-secret>
```

#### Deployment Manifest
```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: clinical-bert-api
  labels:
    app: clinical-bert-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: clinical-bert-api
  template:
    metadata:
      labels:
        app: clinical-bert-api
    spec:
      containers:
      - name: clinical-bert-api
        image: us-central1-docker.pkg.dev/your-project/clinical-bert-repo/clinical-bert-api:latest
        ports:
        - containerPort: 8080
        env:
        - name: ENVIRONMENT
          valueFrom:
            configMapKeyRef:
              name: clinical-bert-config
              key: ENVIRONMENT
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: clinical-bert-secrets
              key: API_KEY
        resources:
          requests:
            memory: "2Gi"
            cpu: "1"
          limits:
            memory: "4Gi"
            cpu: "2"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 60
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
```

#### Service Manifest
```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: clinical-bert-api-service
spec:
  selector:
    app: clinical-bert-api
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
  type: ClusterIP
```

#### Ingress Configuration
```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: clinical-bert-api-ingress
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - api.yourdomain.com
    secretName: clinical-bert-tls
  rules:
  - host: api.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: clinical-bert-api-service
            port:
              number: 80
```

### Advanced Kubernetes Features

#### Horizontal Pod Autoscaler
```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: clinical-bert-api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: clinical-bert-api
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

#### Pod Disruption Budget
```yaml
# pdb.yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: clinical-bert-api-pdb
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: clinical-bert-api
```

#### Network Policies
```yaml
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: clinical-bert-api-netpol
spec:
  podSelector:
    matchLabels:
      app: clinical-bert-api
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 443
```

---

## CI/CD Pipeline

### GitHub Actions Configuration

#### Complete CI/CD Workflow
```yaml
# .github/workflows/ci-cd.yml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  GCP_PROJECT_ID: ${{ secrets.GCP_PROJECT_ID }}
  GCP_REGION: us-central1
  GAR_REPO: us-central1-docker.pkg.dev/${{ secrets.GCP_PROJECT_ID }}/clinical-bert-repo

jobs:
  # Quality Assurance
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install flake8 black isort mypy bandit safety
      - name: Run quality checks
        run: |
          make lint
          make format-check
          make type-check
          make security

  # Testing
  test:
    runs-on: ubuntu-latest
    needs: quality
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests
        run: |
          pytest --cov=app --cov-report=xml --cov-report=term
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml

  # Build
  build:
    runs-on: ubuntu-latest
    needs: test
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      - name: Authenticate to Google Cloud
        uses: google-github-actions/auth@v1
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}
      - name: Configure Docker
        run: gcloud auth configure-docker us-central1-docker.pkg.dev
      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ env.GAR_REPO }}/clinical-bert-api:${{ github.sha }},${{ env.GAR_REPO }}/clinical-bert-api:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max

  # Deploy to Staging
  deploy-staging:
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/develop'
    environment: staging
    steps:
      - uses: google-github-actions/auth@v1
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}
      - name: Deploy to Cloud Run (Staging)
        run: |
          gcloud run deploy clinical-bert-api-staging \
            --image=${{ env.GAR_REPO }}/clinical-bert-api:${{ github.sha }} \
            --region=${{ env.GCP_REGION }} \
            --allow-unauthenticated \
            --memory=2Gi \
            --cpu=1 \
            --set-env-vars="ENVIRONMENT=staging"

  # Deploy to Production
  deploy-production:
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/main'
    environment: production
    steps:
      - uses: google-github-actions/auth@v1
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}
      - name: Deploy to Cloud Run (Production)
        run: |
          gcloud run deploy clinical-bert-api \
            --image=${{ env.GAR_REPO }}/clinical-bert-api:${{ github.sha }} \
            --region=${{ env.GCP_REGION }} \
            --allow-unauthenticated \
            --memory=2Gi \
            --cpu=1 \
            --max-instances=10 \
            --timeout=300 \
            --concurrency=80 \
            --set-env-vars="ENVIRONMENT=production,LOG_LEVEL=INFO"
```

### Deployment Automation Script

#### Advanced Deployment Script
```bash
#!/bin/bash
# deploy.sh

set -e

# Configuration
PROJECT_ID="${GCP_PROJECT_ID:-your-project-id}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="clinical-bert-api"
IMAGE_NAME="us-central1-docker.pkg.dev/$PROJECT_ID/clinical-bert-repo/clinical-bert-api"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Validate environment
validate_env() {
    log_info "Validating environment..."

    if [ -z "$PROJECT_ID" ]; then
        log_error "PROJECT_ID not set"
        exit 1
    fi

    if ! gcloud projects describe "$PROJECT_ID" &>/dev/null; then
        log_error "Project $PROJECT_ID not found or not accessible"
        exit 1
    fi

    log_info "Environment validation passed"
}

# Build and push image
build_and_push() {
    log_info "Building and pushing Docker image..."

    # Build optimized image
    docker build -t "$IMAGE_NAME:latest" .

    # Push to registry
    docker push "$IMAGE_NAME:latest"

    log_info "Image built and pushed successfully"
}

# Deploy to Cloud Run
deploy_service() {
    local env="$1"
    local service_name="$SERVICE_NAME"

    if [ "$env" = "staging" ]; then
        service_name="${SERVICE_NAME}-staging"
    fi

    log_info "Deploying to Cloud Run ($env)..."

    gcloud run deploy "$service_name" \
        --image="$IMAGE_NAME:latest" \
        --region="$REGION" \
        --allow-unauthenticated \
        --memory=2Gi \
        --cpu=1 \
        --max-instances=10 \
        --timeout=300 \
        --concurrency=80 \
        --port=8080 \
        --set-env-vars="ENVIRONMENT=$env,LOG_LEVEL=INFO" \
        --quiet

    # Get service URL
    SERVICE_URL=$(gcloud run services describe "$service_name" \
        --region="$REGION" \
        --format="value(status.url)")

    log_info "Service deployed successfully"
    log_info "Service URL: $SERVICE_URL"
}

# Health check
health_check() {
    local service_url="$1"
    local max_attempts=30
    local attempt=1

    log_info "Performing health checks..."

    while [ $attempt -le $max_attempts ]; do
        if curl -f -s "$service_url/health" > /dev/null 2>&1; then
            log_info "Health check passed"
            return 0
        fi

        log_warn "Health check failed (attempt $attempt/$max_attempts)"
        sleep 10
        ((attempt++))
    done

    log_error "Health check failed after $max_attempts attempts"
    return 1
}

# Main deployment
main() {
    local environment="${1:-production}"

    log_info "Starting deployment to $environment environment"

    validate_env
    build_and_push

    deploy_service "$environment"

    # Get service URL for health check
    local service_name="$SERVICE_NAME"
    if [ "$environment" = "staging" ]; then
        service_name="${SERVICE_NAME}-staging"
    fi

    SERVICE_URL=$(gcloud run services describe "$service_name" \
        --region="$REGION" \
        --format="value(status.url)")

    if health_check "$SERVICE_URL"; then
        log_info "Deployment completed successfully!"
        log_info "Service URL: $SERVICE_URL"
        log_info "API Documentation: $SERVICE_URL/docs"
    else
        log_error "Deployment failed - health checks unsuccessful"
        exit 1
    fi
}

# Run main function with provided arguments
main "$@"
```

---

## Monitoring & Observability

### Production Monitoring Setup

#### Prometheus Configuration
```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'clinical-bert-api'
    static_configs:
      - targets: ['clinical-bert-api:8080']
    metrics_path: '/metrics'
    scrape_interval: 5s

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'cadvisor'
    static_configs:
      - targets: ['cadvisor:8080']
```

#### Grafana Dashboard
```json
{
  "dashboard": {
    "title": "Clinical BERT API Dashboard",
    "tags": ["clinical", "bert", "api"],
    "timezone": "UTC",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{endpoint}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "P95 Response Time"
          }
        ]
      },
      {
        "title": "Model Predictions",
        "type": "bargauge",
        "targets": [
          {
            "expr": "sum(model_predictions_total)",
            "legendFormat": "Total Predictions"
          }
        ]
      }
    ]
  }
}
```

### Alerting Rules

#### Prometheus Alerting Rules
```yaml
# monitoring/alert_rules.yml
groups:
  - name: clinical_bert_api_alerts
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value | printf \"%.2f\" }}%"

      - alert: HighResponseTime
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1.0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High response time detected"
          description: "95th percentile response time is {{ $value | printf \"%.2f\" }}s"

      - alert: ServiceDown
        expr: up{job="clinical-bert-api"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Clinical BERT API is down"
          description: "Service has been down for 5 minutes"
```

---

## Troubleshooting

### Common Deployment Issues

#### Docker Build Failures
**Symptoms:**
- Build fails with dependency errors
- Model download timeouts
- Disk space issues

**Solutions:**
```bash
# Increase Docker build timeout
export DOCKER_BUILDKIT=1
docker build --no-cache --progress=plain .

# Check available disk space
df -h

# Clean Docker cache
docker system prune -a
```

#### Cloud Run Deployment Issues
**Symptoms:**
- Deployment fails with resource limits
- Cold start timeouts
- Service unavailable errors

**Solutions:**
```bash
# Check service status
gcloud run services describe clinical-bert-api --region=us-central1

# View service logs
gcloud logging read "resource.type=cloud_run_revision" \
  --filter="resource.labels.service_name=clinical-bert-api" \
  --limit=50

# Check resource allocation
gcloud run services update clinical-bert-api \
  --memory=4Gi \
  --cpu=2 \
  --region=us-central1
```

#### Model Loading Issues
**Symptoms:**
- Health check shows model not loaded
- Service starts but predictions fail
- Memory exhaustion during startup

**Solutions:**
```bash
# Check model cache
ls -la /tmp/model_cache/

# Verify model download
curl -I https://huggingface.co/bvanaken/clinical-assertion-negation-bert/resolve/main/pytorch_model.bin

# Increase memory allocation
gcloud run services update clinical-bert-api \
  --memory=4Gi \
  --region=us-central1
```

### Performance Optimization

#### Memory Optimization
```bash
# Monitor memory usage
gcloud logging read "resource.type=cloud_run_revision" \
  --filter="textPayload:*memory*" \
  --limit=20

# Adjust instance sizing
gcloud run services update clinical-bert-api \
  --memory=3Gi \
  --cpu=1 \
  --region=us-central1
```

#### Scaling Optimization
```bash
# Configure auto-scaling
gcloud run services update clinical-bert-api \
  --min-instances=2 \
  --max-instances=15 \
  --concurrency=100 \
  --region=us-central1
```

---

## Operations & Support

### Production Support
- **24/7 Monitoring**: Automated alerting and incident response
- **SLA**: 99.95% uptime guarantee with <15 minute incident response
- **Documentation**: Comprehensive runbooks and troubleshooting guides
- **Training**: Onboarding and maintenance training programs

### Maintenance Procedures

#### Regular Maintenance
```bash
# Update dependencies monthly
make update-deps

# Security patches weekly
make security-update

# Performance monitoring daily
make monitor-performance

# Backup verification weekly
make backup-verify
```

#### Emergency Procedures
```bash
# Emergency rollback
gcloud run services update clinical-bert-api \
  --revision=clinical-bert-api-00008-6gz \
  --region=us-central1

# Emergency shutdown
gcloud run services update clinical-bert-api \
  --min-instances=0 \
  --max-instances=0 \
  --region=us-central1

# Emergency restart
gcloud run services update clinical-bert-api \
  --min-instances=1 \
  --max-instances=5 \
  --region=us-central1
```

### Advanced Deployment Patterns

#### Blue-Green Deployment
```yaml
# blue-green-deployment.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: clinical-bert-api
spec:
  template:
    metadata:
      name: clinical-bert-api-blue
      annotations:
        serving.knative.dev/rollout-duration: "300s"
  traffic:
  - tag: current
    revisionName: clinical-bert-api-blue
    percent: 100
  - tag: candidate
    revisionName: clinical-bert-api-green
    percent: 0
```

#### Canary Deployment
```yaml
# canary-deployment.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: clinical-bert-api
spec:
  template:
    metadata:
      name: clinical-bert-api-v2
  traffic:
  - tag: stable
    revisionName: clinical-bert-api-v1
    percent: 90
  - tag: canary
    revisionName: clinical-bert-api-v2
    percent: 10
```

#### Multi-Region Deployment
```bash
# Deploy to multiple regions for high availability
export REGIONS=("us-central1" "us-east1" "us-west1")

for region in "${REGIONS[@]}"; do
    echo "Deploying to $region..."

    gcloud run deploy clinical-bert-api-$region \
      --image=us-central1-docker.pkg.dev/$PROJECT_ID/clinical-bert-repo/clinical-bert-api:latest \
      --region=$region \
      --allow-unauthenticated \
      --memory=2Gi \
      --cpu=1 \
      --max-instances=10 \
      --timeout=300 \
      --concurrency=80 \
      --port=8080 \
      --set-env-vars="ENVIRONMENT=production,REGION=$region"
done
```

### Performance Optimization

#### Memory Optimization
```bash
# Monitor memory usage patterns
gcloud logging read "resource.type=cloud_run_revision" \
  --filter="textPayload:*memory*" \
  --limit=50

# Optimize memory allocation based on usage
gcloud run services update clinical-bert-api \
  --memory=3Gi \
  --cpu=1 \
  --region=us-central1
```

#### CPU Optimization
```bash
# Monitor CPU usage
gcloud logging read "resource.type=cloud_run_revision" \
  --filter="textPayload:*cpu*" \
  --limit=50

# Adjust CPU allocation
gcloud run services update clinical-bert-api \
  --cpu=2 \
  --memory=4Gi \
  --region=us-central1
```

#### Network Optimization
```bash
# Enable VPC for better network performance
gcloud compute networks vpc-access connectors create clinical-bert-connector \
  --region=us-central1 \
  --network=default \
  --range=10.8.0.0/28

# Update service with VPC connector
gcloud run services update clinical-bert-api \
  --vpc-connector=clinical-bert-connector \
  --region=us-central1
```

### Cost Optimization

#### Right-Sizing Instances
```bash
# Analyze current usage
gcloud run services describe clinical-bert-api \
  --region=us-central1 \
  --format="value(status.traffic.target)"

# Adjust instance size based on load
gcloud run services update clinical-bert-api \
  --memory=2Gi \
  --cpu=1 \
  --region=us-central1
```

#### Auto-Scaling Configuration
```bash
# Configure cost-effective scaling
gcloud run services update clinical-bert-api \
  --min-instances=0 \
  --max-instances=20 \
  --concurrency=100 \
  --cpu-throttling \
  --region=us-central1
```

#### Regional Cost Analysis
```bash
# Compare costs across regions
gcloud run services describe clinical-bert-api-us-central1 \
  --region=us-central1 \
  --format="value(status.conditions)"

gcloud run services describe clinical-bert-api-us-east1 \
  --region=us-east1 \
  --format="value(status.conditions)"
```

### Security Hardening

#### Network Security
```bash
# Create VPC network
gcloud compute networks create clinical-bert-network \
  --subnet-mode=custom

# Create subnet
gcloud compute networks subnets create clinical-bert-subnet \
  --network=clinical-bert-network \
  --range=10.0.0.0/24 \
  --region=us-central1

# Create VPC connector
gcloud compute networks vpc-access connectors create clinical-bert-connector \
  --region=us-central1 \
  --network=clinical-bert-network \
  --range=10.0.0.0/28

# Deploy with VPC
gcloud run deploy clinical-bert-api \
  --image=us-central1-docker.pkg.dev/$PROJECT_ID/clinical-bert-repo/clinical-bert-api:latest \
  --region=us-central1 \
  --vpc-connector=clinical-bert-connector \
  --allow-unauthenticated \
  --memory=2Gi \
  --cpu=1
```

#### IAM Configuration
```bash
# Create service account
gcloud iam service-accounts create clinical-bert-api \
  --display-name="Clinical BERT API Service Account"

# Grant necessary permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:clinical-bert-api@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/cloudtranslate.user"

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:clinical-bert-api@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/logging.logWriter"

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:clinical-bert-api@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/monitoring.metricWriter"

# Use service account for deployment
gcloud run deploy clinical-bert-api \
  --image=us-central1-docker.pkg.dev/$PROJECT_ID/clinical-bert-repo/clinical-bert-api:latest \
  --region=us-central1 \
  --service-account=clinical-bert-api@$PROJECT_ID.iam.gserviceaccount.com \
  --allow-unauthenticated
```

### Monitoring & Alerting

#### Custom Metrics
```python
# Add custom business metrics
from prometheus_client import Counter, Histogram

# Business metrics
PATIENT_RECORDS_PROCESSED = Counter(
    'patient_records_processed_total',
    'Total patient records processed',
    ['patient_id', 'record_type']
)

CLINICAL_ASSERTIONS_GENERATED = Counter(
    'clinical_assertions_generated_total',
    'Total clinical assertions generated',
    ['assertion_type', 'confidence_level']
)

EHR_INTEGRATION_EVENTS = Counter(
    'ehr_integration_events_total',
    'Total EHR integration events',
    ['ehr_system', 'event_type', 'status']
)
```

#### Advanced Alerting Rules
```yaml
groups:
  - name: clinical_bert_business_metrics
    rules:
      - alert: LowPatientProcessingRate
        expr: rate(patient_records_processed_total[1h]) < 10
        for: 30m
        labels:
          severity: warning
          team: business
        annotations:
          summary: "Low patient record processing rate"
          description: "Processing rate dropped to {{ $value | printf \"%.0f\" }} records/hour"

      - alert: HighEHRIntegrationErrors
        expr: rate(ehr_integration_events_total{status="error"}[15m]) > 0.1
        for: 5m
        labels:
          severity: critical
          team: platform
        annotations:
          summary: "High EHR integration error rate"
          description: "EHR integration error rate: {{ $value | printf \"%.2f\" }} errors/min"

      - alert: ModelAccuracyDegradation
        expr: rate(clinical_assertions_generated_total{confidence_level="low"}[1h]) > 0.3
        for: 1h
        labels:
          severity: warning
          team: ml
        annotations:
          summary: "Model accuracy degradation detected"
          description: "Low confidence predictions increased to {{ $value | printf \"%.2f\" }}%"
```

### Disaster Recovery

#### Backup Strategy
```bash
# Create backup of configuration
gcloud run services describe clinical-bert-api \
  --region=us-central1 \
  --format="yaml" > backup/clinical-bert-api-backup.yaml

# Backup environment variables
gcloud run services describe clinical-bert-api \
  --region=us-central1 \
  --format="value(spec.template.spec.template.spec.containers[0].env[].name,spec.template.spec.template.spec.containers[0].env[].value)" \
  > backup/env-variables.txt

# Backup secrets
echo "API_KEY_SECRET=$(gcloud secrets versions access latest --secret=api-key-secret)" > backup/secrets.txt
echo "JWT_SECRET_KEY=$(gcloud secrets versions access latest --secret=jwt-secret-key)" >> backup/secrets.txt
```

#### Recovery Procedures
```bash
# Restore from backup
gcloud run services replace clinical-bert-api \
  --region=us-central1 \
  --filename=backup/clinical-bert-api-backup.yaml

# Restore environment variables
while IFS='=' read -r key value; do
    gcloud run services update clinical-bert-api \
      --region=us-central1 \
      --set-env-vars="$key=$value"
done < backup/env-variables.txt

# Restore secrets
gcloud secrets create api-key-secret --data-file=backup/api-key.txt --replication-policy=user-managed --locations=us-central1
gcloud secrets create jwt-secret-key --data-file=backup/jwt-key.txt --replication-policy=user-managed --locations=us-central1
```

#### Multi-Region Failover
```bash
# Primary region: us-central1
# Secondary region: us-east1
# Tertiary region: us-west1

# Traffic management
gcloud run services update-traffic clinical-bert-api \
  --region=us-central1 \
  --to-revisions=clinical-bert-api-us-central1=100

# Failover to secondary region
gcloud run services update-traffic clinical-bert-api \
  --region=us-central1 \
  --to-revisions=clinical-bert-api-us-east1=100

# Load balancing across regions
gcloud run services update-traffic clinical-bert-api \
  --region=us-central1 \
  --to-revisions=clinical-bert-api-us-central1=50,clinical-bert-api-us-east1=50
```

### Compliance & Audit

#### HIPAA Compliance Monitoring
```bash
# Monitor PHI data access
gcloud logging read "resource.type=cloud_run_revision" \
  --filter="textPayload:*patient*" \
  --limit=100

# Audit API access patterns
gcloud logging read "resource.type=cloud_run_revision" \
  --filter="resource.labels.service_name=clinical-bert-api" \
  --limit=1000 | \
  jq -r '.[] | "\(.timestamp) \(.jsonPayload.request_id) \(.jsonPayload.ip_address)"'
```

#### SOC 2 Compliance
```bash
# Security monitoring
gcloud logging read "resource.type=cloud_run_revision" \
  --filter="severity>=ERROR" \
  --limit=50

# Access control monitoring
gcloud logging read "resource.type=cloud_run_revision" \
  --filter="textPayload:*unauthorized*" \
  --limit=50

# Data protection monitoring
gcloud logging read "resource.type=cloud_run_revision" \
  --filter="textPayload:*encryption*" \
  --limit=50
```

### Performance Benchmarking

#### Load Testing Setup
```bash
# Install load testing tools
pip install locust

# Create load test configuration
# locustfile.py
from locust import HttpUser, task, between

class ClinicalBERTUser(HttpUser):
    wait_time = between(1, 5)

    @task
    def predict_single(self):
        self.client.post("/predict", json={
            "sentence": "The patient reports chest pain."
        })

    @task(3)  # 3x more frequent than single predictions
    def predict_batch(self):
        self.client.post("/predict/batch", json={
            "sentences": [
                "Patient has fever.",
                "No signs of infection.",
                "Blood pressure elevated."
            ]
        })

    @task
    def health_check(self):
        self.client.get("/health")
```

#### Running Load Tests
```bash
# Run load test
locust -f locustfile.py --host https://your-service-url

# Run with specific parameters
locust -f locustfile.py \
  --host https://your-service-url \
  --users 100 \
  --spawn-rate 10 \
  --run-time 10m

# Distributed load testing
locust -f locustfile.py \
  --master \
  --master-bind-host 0.0.0.0 \
  --master-bind-port 5557

# On worker nodes
locust -f locustfile.py \
  --worker \
  --master-host 192.168.1.100
```

#### Performance Analysis
```bash
# Analyze performance metrics
curl -s https://your-service-url/metrics | \
  grep -E "(http_requests_total|http_request_duration_seconds|memory|cpu)" | \
  jq '.'

# Generate performance report
locust -f locustfile.py \
  --html=performance-report.html \
  --host https://your-service-url \
  --users 50 \
  --spawn-rate 5 \
  --run-time 5m
```

### Capacity Planning

#### Resource Calculator
```python
def calculate_resources(expected_rpm, avg_response_time_ms, memory_per_request_mb):
    """
    Calculate required resources based on expected load
    """
    # Convert response time to seconds
    avg_response_time_s = avg_response_time_ms / 1000

    # Calculate requests per second
    rps = expected_rpm / 60

    # Calculate concurrent requests
    concurrent_requests = rps * avg_response_time_s

    # Calculate memory requirements
    memory_mb = concurrent_requests * memory_per_request_mb

    # Calculate CPU requirements (rough estimate)
    cpu_cores = concurrent_requests * 0.1  # 0.1 CPU per concurrent request

    return {
        'requests_per_minute': expected_rpm,
        'requests_per_second': rps,
        'concurrent_requests': concurrent_requests,
        'memory_mb': memory_mb,
        'cpu_cores': cpu_cores,
        'recommended_instances': max(1, int(concurrent_requests / 80))  # 80 concurrent per instance
    }

# Example usage
resources = calculate_resources(
    expected_rpm=1000,  # 1000 requests per minute
    avg_response_time_ms=300,  # 300ms average response time
    memory_per_request_mb=2  # 2MB per request
)

print(f"Required resources: {resources}")
```

#### Scaling Recommendations
```bash
# Based on calculated resources, configure scaling
gcloud run services update clinical-bert-api \
  --region=us-central1 \
  --min-instances=1 \
  --max-instances=20 \
  --concurrency=80 \
  --cpu=2 \
  --memory=4Gi

# Configure auto-scaling based on CPU utilization
gcloud run services update clinical-bert-api \
  --region=us-central1 \
  --set-env-vars="AUTOSCALING_METRIC=cpu,SCALING_THRESHOLD=70"
```

### Troubleshooting Deployment Issues

#### Common Deployment Problems

**Cold Start Issues**
```bash
# Check cold start duration
gcloud logging read "resource.type=cloud_run_revision" \
  --filter="textPayload:*cold start*" \
  --limit=20

# Solution: Keep service warm
gcloud run services update clinical-bert-api \
  --region=us-central1 \
  --min-instances=1
```

**Performance Degradation**
```bash
# Monitor resource utilization
gcloud logging read "resource.type=cloud_run_revision" \
  --filter="textPayload:*CPU*|*memory*" \
  --limit=50

# Solution: Scale resources
gcloud run services update clinical-bert-api \
  --region=us-central1 \
  --memory=4Gi \
  --cpu=2
```

**Security Configuration Issues**
```bash
# Check IAM permissions
gcloud projects get-iam-policy $PROJECT_ID \
  --filter="bindings.role:roles/run.admin" \
  --format="value(bindings.members)"

# Solution: Grant necessary permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:clinical-bert-api@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/run.admin"
```

**Network Connectivity Issues**
```bash
# Check VPC configuration
gcloud compute networks vpc-access connectors describe clinical-bert-connector \
  --region=us-central1

# Solution: Recreate VPC connector
gcloud compute networks vpc-access connectors delete clinical-bert-connector \
  --region=us-central1

gcloud compute networks vpc-access connectors create clinical-bert-connector \
  --region=us-central1 \
  --network=default \
  --range=10.8.0.0/28
```

### Support & Maintenance

#### Regular Maintenance Checklist
```bash
# Weekly maintenance
- [ ] Check service health and metrics
- [ ] Review error rates and logs
- [ ] Verify backup integrity
- [ ] Update security patches
- [ ] Monitor resource utilization
- [ ] Test failover procedures
- [ ] Review cost optimization opportunities

# Monthly maintenance
- [ ] Update dependencies and base images
- [ ] Perform security vulnerability scans
- [ ] Review and update monitoring rules
- [ ] Test disaster recovery procedures
- [ ] Analyze performance trends
- [ ] Update documentation
- [ ] Review compliance requirements

# Quarterly maintenance
- [ ] Conduct penetration testing
- [ ] Perform load testing
- [ ] Review architecture and design
- [ ] Update capacity planning
- [ ] Conduct security audits
- [ ] Review SLAs and performance metrics
```

#### Emergency Response Procedures
```bash
# Critical incident response
1. Acknowledge incident within 5 minutes
2. Assess impact and scope within 15 minutes
3. Implement immediate mitigation within 30 minutes
4. Communicate status to stakeholders within 1 hour
5. Implement permanent fix within 4 hours
6. Conduct post-incident review within 24 hours
7. Update documentation and procedures within 1 week

# Communication templates
echo "Subject: Clinical BERT API - Service Incident

Dear Team,

We are currently experiencing a service incident with the Clinical BERT API.

**Incident Details:**
- Severity: [Critical/High/Medium]
- Impact: [Description of impact]
- Affected Services: [List of affected services]
- Start Time: [Timestamp]

**Current Status:**
- [Current status and mitigation steps]

**Next Steps:**
- [Planned remediation steps]
- [Expected resolution time]

**Contact Information:**
- Incident Lead: [Name] - [Contact Info]
- Technical Lead: [Name] - [Contact Info]
- Support: [Support Contact]

Best regards,
Clinical BERT API Team" > incident_template.txt
```

---

**Enterprise Ready • Cloud Optimized • Security First • Production Proven**

*Complete deployment guide for production Clinical BERT API*
