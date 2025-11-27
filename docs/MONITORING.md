# Clinical BERT API - Monitoring & Observability Guide

## Monitoring Overview

This guide covers the comprehensive monitoring and observability setup for the Clinical BERT Assertion API, designed to provide real-time insights into system performance, health, and operational metrics.

## Monitoring Architecture

### Observability Stack

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Application   │───▶│   Prometheus     │───▶│   Grafana       │
│                 │    │                  │    │                 │
│ • Health Checks │    │ • Metrics        │    │ • Dashboards    │
│ • Performance   │    │   Collection     │    │ • Alerts        │
│ • Business KPIs │    │ • Alert Rules    │    │ • Reports       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
       ┌─────────────────────────────────────────────────┼─────────────────┐
       │                                                 ▼                 │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐         │
│   Cloud Logging │    │   Alert Manager  │    │   Notification   │         │
│                 │    │                  │    │                 │         │
│ • Structured    │    │ • Alert Routing  │    │ • Email         │         │
│   Logs          │    │ • Escalation     │    │ • Slack         │         │
│ • Audit Trails  │    │ • Silencing      │    │ • PagerDuty     │         │
└─────────────────┘    └──────────────────┘    └─────────────────┘         │
       └─────────────────────────────────────────────────────────────────────┘
```

## Key Metrics

### Application Metrics

#### Performance Metrics
```prometheus
# Response Time (histogram)
http_request_duration_seconds{quantile="0.5"}  # P50
http_request_duration_seconds{quantile="0.95"} # P95
http_request_duration_seconds{quantile="0.99"} # P99

# Request Rate
rate(http_requests_total[5m])

# Error Rate
rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m])
```

#### Business Metrics
```prometheus
# Model Performance
model_predictions_total{label="PRESENT"}
model_predictions_total{label="ABSENT"}
model_predictions_total{label="POSSIBLE"}

# Usage Metrics
api_requests_total{endpoint="/predict"}
api_requests_total{endpoint="/predict/batch"}

# Accuracy Metrics
model_accuracy_ratio
prediction_confidence_avg
```

### System Metrics

#### Resource Utilization
```prometheus
# CPU Usage
rate(process_cpu_user_seconds_total[5m])
rate(process_cpu_system_seconds_total[5m])

# Memory Usage
process_resident_memory_bytes / 1024 / 1024  # MB
(process_resident_memory_bytes / process_virtual_memory_bytes) * 100  # %

# Disk Usage
disk_used_percent{mountpoint="/"} > 80
```

#### Container Metrics
```prometheus
# Container Resources
container_cpu_usage_seconds_total
container_memory_usage_bytes
container_network_receive_bytes_total
container_network_transmit_bytes_total
```

## Grafana Dashboards

### Main Dashboard Configuration

#### System Overview Panel
```json
{
  "title": "System Overview",
  "type": "stat",
  "targets": [
    {
      "expr": "up{job='clinical-bert-api'}",
      "legendFormat": "Service Status"
    }
  ],
  "fieldConfig": {
    "defaults": {
      "mappings": [
        {
          "options": {
            "0": {
              "text": "DOWN",
              "color": "red"
            },
            "1": {
              "text": "UP",
              "color": "green"
            }
          },
          "type": "value"
        }
      ]
    }
  }
}
```

#### Response Time Graph
```json
{
  "title": "Response Time Percentiles",
  "type": "graph",
  "targets": [
    {
      "expr": "histogram_quantile(0.50, rate(http_request_duration_seconds_bucket[5m])) * 1000",
      "legendFormat": "P50 (ms)"
    },
    {
      "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) * 1000",
      "legendFormat": "P95 (ms)"
    },
    {
      "expr": "histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m])) * 1000",
      "legendFormat": "P99 (ms)"
    }
  ]
}
```

#### Request Rate Panel
```json
{
  "title": "Request Rate",
  "type": "graph",
  "targets": [
    {
      "expr": "rate(http_requests_total[5m])",
      "legendFormat": "Requests/sec"
    }
  ]
}
```

#### Error Rate Panel
```json
{
  "title": "Error Rate",
  "type": "graph",
  "targets": [
    {
      "expr": "rate(http_requests_total{status=~\"5..\"}[5m]) / rate(http_requests_total[5m]) * 100",
      "legendFormat": "Error Rate (%)"
    }
  ]
}
```

#### Model Performance Panel
```json
{
  "title": "Model Predictions",
  "type": "bargauge",
  "targets": [
    {
      "expr": "sum(model_predictions_total)",
      "legendFormat": "Total Predictions"
    }
  ],
  "fieldConfig": {
    "defaults": {
      "mappings": [
        {
          "options": {
            "from": 0,
            "to": 1000,
            "result": {
              "text": "LOW",
              "color": "green"
            }
          },
          "type": "range"
        },
        {
          "options": {
            "from": 1000,
            "to": 5000,
            "result": {
              "text": "MEDIUM",
              "color": "orange"
            }
          },
          "type": "range"
        },
        {
          "options": {
            "from": 5000,
            "to": 10000,
            "result": {
              "text": "HIGH",
              "color": "red"
            }
          },
          "type": "range"
        }
      ]
    }
  }
}
```

## Alerting Configuration

### Prometheus Alert Rules

#### Critical Alerts
```yaml
groups:
  - name: clinical_bert_api_critical
    rules:
      - alert: ServiceDown
        expr: up{job="clinical-bert-api"} == 0
        for: 5m
        labels:
          severity: critical
          team: platform
        annotations:
          summary: "Clinical BERT API is down"
          description: "Service has been down for 5 minutes"
          runbook_url: "https://docs.company.com/runbooks/clinical-bert-down"

      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
          team: platform
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value | printf \"%.2f\" }}%"

      - alert: HighResponseTime
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 2.0
        for: 5m
        labels:
          severity: critical
          team: platform
        annotations:
          summary: "High response time detected"
          description: "95th percentile response time is {{ $value | printf \"%.2f\" }}s"
```

#### Warning Alerts
```yaml
groups:
  - name: clinical_bert_api_warning
    rules:
      - alert: ModerateErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.01
        for: 10m
        labels:
          severity: warning
          team: platform
        annotations:
          summary: "Moderate error rate detected"
          description: "Error rate is {{ $value | printf \"%.2f\" }}%"

      - alert: ElevatedResponseTime
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1.0
        for: 10m
        labels:
          severity: warning
          team: platform
        annotations:
          summary: "Elevated response time detected"
          description: "95th percentile response time is {{ $value | printf \"%.2f\" }}s"

      - alert: HighMemoryUsage
        expr: (process_resident_memory_bytes / 1024 / 1024 / 1024) > 3
        for: 15m
        labels:
          severity: warning
          team: platform
        annotations:
          summary: "High memory usage detected"
          description: "Memory usage is {{ $value | printf \"%.2f\" }}GB"
```

#### Info Alerts
```yaml
groups:
  - name: clinical_bert_api_info
    rules:
      - alert: DeploymentCompleted
        expr: up{job="clinical-bert-api"} == 1 and up{job="clinical-bert-api"} offset 5m == 0
        for: 1m
        labels:
          severity: info
          team: platform
        annotations:
          summary: "Deployment completed"
          description: "Clinical BERT API deployment completed successfully"

      - alert: HighTraffic
        expr: rate(http_requests_total[5m]) > 100
        for: 5m
        labels:
          severity: info
          team: platform
        annotations:
          summary: "High traffic detected"
          description: "Request rate is {{ $value | printf \"%.0f\" }} req/sec"
```

### Alert Manager Configuration

#### Routing Configuration
```yaml
route:
  group_by: ['alertname', 'severity']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'default'
  routes:
  - match:
      severity: critical
    receiver: 'critical-pager'
    continue: true
  - match:
      severity: warning
    receiver: 'warning-slack'
  - match:
      severity: info
    receiver: 'info-email'

receivers:
- name: 'default'
  slack_configs:
  - api_url: 'https://hooks.slack.com/services/...'
    channel: '#alerts'
    title: '{{ .GroupLabels.alertname }}'
    text: '{{ .CommonAnnotations.description }}'

- name: 'critical-pager'
  pagerduty_configs:
  - service_key: 'your-pagerduty-service-key'
    description: '{{ .CommonAnnotations.summary }}'

- name: 'warning-slack'
  slack_configs:
  - api_url: 'https://hooks.slack.com/services/...'
    channel: '#warnings'
    title: '{{ .GroupLabels.alertname }}'

- name: 'info-email'
  email_configs:
  - to: 'team@company.com'
    from: 'alerts@company.com'
    smarthost: 'smtp.company.com:587'
    auth_username: 'alerts@company.com'
    auth_password: 'your-smtp-password'
```

## Logging Strategy

### Structured Logging Implementation

#### Python Logging Configuration
```python
import logging
import json
from pythonjsonlogger import jsonlogger

class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)

        # Add custom fields
        log_record['service'] = 'clinical-bert-api'
        log_record['version'] = '1.0.0'
        log_record['environment'] = os.getenv('ENVIRONMENT', 'development')

        # Add request context if available
        if hasattr(record, 'request_id'):
            log_record['request_id'] = record.request_id
        if hasattr(record, 'user_id'):
            log_record['user_id'] = record.user_id

# Configure logging
logger = logging.getLogger()
handler = logging.StreamHandler()
formatter = CustomJsonFormatter(
    '%(asctime)s %(name)s %(levelname)s %(message)s'
)
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
```

#### Log Levels and Usage
```python
# ERROR: System errors requiring immediate attention
logger.error("Model loading failed", extra={
    'error_type': 'ModelLoadError',
    'model_name': 'clinical-assertion-negation-bert',
    'error_details': str(e)
})

# WARN: Potential issues or unusual conditions
logger.warning("High memory usage detected", extra={
    'memory_usage_mb': 850,
    'threshold_mb': 800,
    'service': 'clinical-bert-api'
})

# INFO: Normal operational messages
logger.info("Prediction completed", extra={
    'request_id': 'req-12345-abcde',
    'prediction_time_ms': 245.67,
    'model_label': 'PRESENT',
    'confidence': 0.9914
})

# DEBUG: Detailed debugging information
logger.debug("Model inference details", extra={
    'input_tokens': 45,
    'output_logits': [2.1, -1.5, 0.3],
    'processing_steps': ['tokenization', 'inference', 'postprocessing']
})
```

### Log Aggregation and Analysis

#### Google Cloud Logging Queries
```sql
-- Recent errors
SELECT
  timestamp,
  severity,
  jsonPayload.message,
  jsonPayload.request_id,
  jsonPayload.error_type
FROM `your-project.global._Default._Default`
WHERE resource.type = "cloud_run_revision"
  AND resource.labels.service_name = "clinical-bert-api"
  AND severity >= "ERROR"
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
ORDER BY timestamp DESC

-- Performance analysis
SELECT
  timestamp,
  jsonPayload.request_id,
  jsonPayload.prediction_time_ms,
  jsonPayload.endpoint
FROM `your-project.global._Default._Default`
WHERE resource.type = "cloud_run_revision"
  AND resource.labels.service_name = "clinical-bert-api"
  AND jsonPayload.prediction_time_ms IS NOT NULL
ORDER BY jsonPayload.prediction_time_ms DESC
LIMIT 100

-- Usage patterns
SELECT
  TIMESTAMP_TRUNC(timestamp, HOUR) as hour,
  COUNT(*) as request_count,
  AVG(jsonPayload.prediction_time_ms) as avg_response_time
FROM `your-project.global._Default._Default`
WHERE resource.type = "cloud_run_revision"
  AND resource.labels.service_name = "clinical-bert-api"
  AND jsonPayload.endpoint = "/predict"
GROUP BY hour
ORDER BY hour DESC
LIMIT 24
```

## Health Checks

### Application Health Checks

#### Basic Health Check
```python
@app.get("/health")
async def health_check():
    """Basic health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }
```

#### Comprehensive Health Check
```python
@app.get("/health/detailed")
async def detailed_health_check():
    """Detailed health check with system metrics"""
    try:
        # Model health
        model_healthy = model.is_loaded() if model else False

        # System metrics
        system_metrics = get_system_metrics()

        # Database connectivity (if applicable)
        db_healthy = await check_database_connection()

        # External service dependencies
        external_services = await check_external_services()

        overall_health = all([
            model_healthy,
            system_metrics.get('memory_percent', 0) < 90,
            system_metrics.get('cpu_percent', 0) < 95,
            db_healthy,
            all(external_services.values())
        ])

        return {
            "status": "healthy" if overall_health else "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "checks": {
                "model": {
                    "healthy": model_healthy,
                    "status": "loaded" if model_healthy else "not loaded"
                },
                "system": {
                    "healthy": system_metrics.get('memory_percent', 0) < 90,
                    "memory_percent": system_metrics.get('memory_percent', 0),
                    "cpu_percent": system_metrics.get('cpu_percent', 0)
                },
                "database": {
                    "healthy": db_healthy,
                    "response_time_ms": db_response_time
                },
                "external_services": external_services
            }
        }

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }
```

### Kubernetes Health Checks

#### Readiness Probe
```yaml
readinessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  successThreshold: 1
  failureThreshold: 3
```

#### Liveness Probe
```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 60
  periodSeconds: 30
  timeoutSeconds: 10
  successThreshold: 1
  failureThreshold: 3
```

## Performance Monitoring

### Application Performance Monitoring (APM)

#### Custom Metrics Implementation
```python
from prometheus_client import Counter, Histogram, Gauge

# Request metrics
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

REQUEST_DURATION = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint']
)

# Model metrics
MODEL_INFERENCE_DURATION = Histogram(
    'model_inference_duration_seconds',
    'Model inference time'
)

MODEL_PREDICTIONS_TOTAL = Counter(
    'model_predictions_total',
    'Total model predictions',
    ['label']
)

# System metrics
MEMORY_USAGE = Gauge(
    'memory_usage_bytes',
    'Current memory usage in bytes'
)

CPU_USAGE = Gauge(
    'cpu_usage_percent',
    'Current CPU usage percentage'
)
```

#### Metrics Collection Middleware
```python
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Middleware to collect HTTP metrics"""
    start_time = time.time()

    # Increment request counter
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.url.path,
        status="pending"
    ).inc()

    try:
        response = await call_next(request)

        # Update metrics
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.url.path,
            status=str(response.status_code)
        ).inc()

        REQUEST_DURATION.labels(
            method=request.method,
            endpoint=request.url.path
        ).observe(time.time() - start_time)

        return response

    except Exception as e:
        # Handle errors
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.url.path,
            status="500"
        ).inc()

        raise
```

### Distributed Tracing

#### OpenTelemetry Integration
```python
from opentelemetry import trace
from opentelemetry.exporter.jaeger import JaegerExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# Configure tracing
trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)

# Configure Jaeger exporter
jaeger_exporter = JaegerExporter(
    agent_host_name="jaeger-agent",
    agent_port=6831,
)

span_processor = BatchSpanProcessor(jaeger_exporter)
trace.get_tracer_provider().add_span_processor(span_processor)

# Instrument application
@app.middleware("http")
async def tracing_middleware(request: Request, call_next):
    """Middleware to add distributed tracing"""
    with tracer.start_as_span(f"{request.method} {request.url.path}") as span:
        span.set_attribute("http.method", request.method)
        span.set_attribute("http.url", str(request.url))
        span.set_attribute("http.scheme", request.url.scheme)

        try:
            response = await call_next(request)
            span.set_attribute("http.status_code", response.status_code)
            return response
        except Exception as e:
            span.record_exception(e)
            span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
            raise
```

## Incident Response

### Automated Incident Detection

#### Anomaly Detection
```python
import numpy as np
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.data_points = []

    def add_data_point(self, response_time: float, error_rate: float):
        """Add data point for anomaly detection"""
        self.data_points.append([response_time, error_rate])

        # Keep only recent data points
        if len(self.data_points) > 1000:
            self.data_points = self.data_points[-1000:]

        # Retrain model periodically
        if len(self.data_points) % 100 == 0:
            self.model.fit(self.data_points)

    def detect_anomaly(self, response_time: float, error_rate: float) -> bool:
        """Detect if current metrics are anomalous"""
        if len(self.data_points) < 10:
            return False

        prediction = self.model.predict([[response_time, error_rate]])
        return prediction[0] == -1  # -1 indicates anomaly
```

### Runbooks and Procedures

#### Service Restart Procedure
```bash
#!/bin/bash
# restart-service.sh

SERVICE_NAME="clinical-bert-api"
REGION="us-central1"

echo "Restarting $SERVICE_NAME..."

# Scale down to trigger restart
gcloud run services update $SERVICE_NAME \
  --region=$REGION \
  --min-instances=0 \
  --max-instances=0

sleep 30

# Scale back up
gcloud run services update $SERVICE_NAME \
  --region=$REGION \
  --min-instances=1 \
  --max-instances=10

echo "✅ Service restart completed"
```

#### Emergency Rollback Procedure
```bash
#!/bin/bash
# rollback-service.sh

SERVICE_NAME="clinical-bert-api"
REGION="us-central1"
ROLLBACK_REVISION="clinical-bert-api-00008-6gz"

echo "🔄 Rolling back $SERVICE_NAME to $ROLLBACK_REVISION..."

# Update traffic to previous revision
gcloud run services update-traffic $SERVICE_NAME \
  --region=$REGION \
  --to-revisions=$ROLLBACK_REVISION=100

echo "✅ Rollback completed"
```

## Reporting and Analytics

### Performance Reports

#### Daily Performance Report
```python
def generate_daily_report():
    """Generate daily performance report"""
    # Query metrics from last 24 hours
    metrics = query_prometheus_metrics("24h")

    report = {
        "date": datetime.utcnow().date().isoformat(),
        "summary": {
            "total_requests": metrics.get('total_requests', 0),
            "avg_response_time": metrics.get('avg_response_time', 0),
            "error_rate": metrics.get('error_rate', 0),
            "uptime_percentage": metrics.get('uptime_percentage', 100)
        },
        "performance": {
            "p50_response_time": metrics.get('p50_response_time', 0),
            "p95_response_time": metrics.get('p95_response_time', 0),
            "p99_response_time": metrics.get('p99_response_time', 0),
            "throughput_rps": metrics.get('throughput_rps', 0)
        },
        "errors": {
            "total_errors": metrics.get('total_errors', 0),
            "error_breakdown": metrics.get('error_breakdown', {}),
            "top_error_endpoints": metrics.get('top_error_endpoints', [])
        },
        "resources": {
            "avg_cpu_usage": metrics.get('avg_cpu_usage', 0),
            "avg_memory_usage": metrics.get('avg_memory_usage', 0),
            "peak_memory_usage": metrics.get('peak_memory_usage', 0)
        }
    }

    return report
```

### Business Intelligence Reports

#### Usage Analytics
```python
def generate_usage_report():
    """Generate usage analytics report"""
    # Query usage metrics
    usage_metrics = query_usage_metrics("30d")

    report = {
        "period": "last_30_days",
        "user_analytics": {
            "total_users": usage_metrics.get('total_users', 0),
            "active_users": usage_metrics.get('active_users', 0),
            "new_users": usage_metrics.get('new_users', 0),
            "user_retention": usage_metrics.get('user_retention', 0)
        },
        "api_usage": {
            "total_predictions": usage_metrics.get('total_predictions', 0),
            "predictions_by_type": usage_metrics.get('predictions_by_type', {}),
            "peak_usage_hours": usage_metrics.get('peak_usage_hours', []),
            "geographic_distribution": usage_metrics.get('geographic_distribution', {})
        },
        "performance_trends": {
            "response_time_trend": usage_metrics.get('response_time_trend', []),
            "accuracy_trend": usage_metrics.get('accuracy_trend', []),
            "error_rate_trend": usage_metrics.get('error_rate_trend', [])
        }
    }

    return report
```

---

## Advanced Monitoring Implementation

### Custom Metrics Collection

#### Business Metrics Implementation
```python
from prometheus_client import Counter, Histogram, Gauge, Summary
import time
import psutil
from typing import Dict, Any, Optional
from datetime import datetime

class BusinessMetricsCollector:
    """Collect business-specific metrics for healthcare AI"""

    def __init__(self):
        # Clinical prediction metrics
        self.predictions_total = Counter(
            'clinical_predictions_total',
            'Total clinical predictions made',
            ['model_name', 'prediction_type', 'confidence_level']
        )

        self.prediction_duration = Histogram(
            'clinical_prediction_duration_seconds',
            'Time spent processing clinical predictions',
            ['model_name', 'endpoint'],
            buckets=[0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0]
        )

        self.prediction_confidence = Histogram(
            'clinical_prediction_confidence',
            'Confidence scores of predictions',
            ['model_name', 'prediction_type'],
            buckets=[0.1, 0.3, 0.5, 0.7, 0.9, 0.95, 0.99, 1.0]
        )

        # Patient data metrics
        self.patient_records_processed = Counter(
            'patient_records_processed_total',
            'Total patient records processed',
            ['source_system', 'record_type', 'processing_status']
        )

        self.phi_data_accessed = Counter(
            'phi_data_accessed_total',
            'PHI data access events',
            ['access_type', 'user_role', 'compliance_status']
        )

        # EHR integration metrics
        self.ehr_integration_events = Counter(
            'ehr_integration_events_total',
            'EHR system integration events',
            ['ehr_system', 'operation_type', 'status']
        )

        self.ehr_response_time = Histogram(
            'ehr_response_time_seconds',
            'Response time for EHR system calls',
            ['ehr_system', 'operation'],
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]
        )

        # System health metrics
        self.system_health_score = Gauge(
            'system_health_score',
            'Overall system health score (0-100)'
        )

        self.active_connections = Gauge(
            'active_connections',
            'Number of active connections'
        )

        self.model_memory_usage = Gauge(
            'model_memory_usage_bytes',
            'Memory usage of ML models'
        )

    def record_prediction(self, model_name: str, prediction_type: str, confidence: float, duration: float):
        """Record a clinical prediction event"""
        self.predictions_total.labels(
            model_name=model_name,
            prediction_type=prediction_type,
            confidence_level=self._get_confidence_level(confidence)
        ).inc()

        self.prediction_duration.labels(
            model_name=model_name,
            endpoint='/predict'
        ).observe(duration)

        self.prediction_confidence.labels(
            model_name=model_name,
            prediction_type=prediction_type
        ).observe(confidence)

    def record_patient_data_access(self, source_system: str, record_type: str, phi_detected: bool):
        """Record patient data processing"""
        status = 'phi_detected' if phi_detected else 'clean'

        self.patient_records_processed.labels(
            source_system=source_system,
            record_type=record_type,
            processing_status=status
        ).inc()

        if phi_detected:
            self.phi_data_accessed.labels(
                access_type='read',
                user_role='system',
                compliance_status='logged'
            ).inc()

    def record_ehr_integration(self, ehr_system: str, operation: str, success: bool, response_time: float):
        """Record EHR integration metrics"""
        status = 'success' if success else 'error'

        self.ehr_integration_events.labels(
            ehr_system=ehr_system,
            operation_type=operation,
            status=status
        ).inc()

        self.ehr_response_time.labels(
            ehr_system=ehr_system,
            operation=operation
        ).observe(response_time)

    def update_system_health(self):
        """Update overall system health score"""
        # Calculate health based on various factors
        health_score = 100

        # Check memory usage
        memory_percent = psutil.virtual_memory().percent
        if memory_percent > 90:
            health_score -= 30
        elif memory_percent > 75:
            health_score -= 15

        # Check CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        if cpu_percent > 95:
            health_score -= 25
        elif cpu_percent > 80:
            health_score -= 10

        # Check disk usage
        disk_percent = psutil.disk_usage('/').percent
        if disk_percent > 95:
            health_score -= 20
        elif disk_percent > 85:
            health_score -= 10

        self.system_health_score.set(health_score)

    def _get_confidence_level(self, confidence: float) -> str:
        """Categorize confidence levels"""
        if confidence >= 0.95:
            return 'high'
        elif confidence >= 0.8:
            return 'medium'
        elif confidence >= 0.6:
            return 'low'
        else:
            return 'very_low'

# Initialize metrics collector
metrics_collector = BusinessMetricsCollector()
```

#### Enhanced Metrics Middleware
```python
import asyncio
from functools import wraps
from collections import defaultdict
import time

class EnhancedMetricsMiddleware:
    """Advanced metrics collection middleware"""

    def __init__(self):
        self.active_requests = defaultdict(int)
        self.request_queue = asyncio.Queue()
        self.processing_times = defaultdict(list)

    async def __call__(self, request, call_next):
        start_time = time.time()
        endpoint = request.url.path
        method = request.method

        # Track active requests
        self.active_requests[endpoint] += 1

        try:
            # Process request
            response = await call_next(request)

            # Record metrics
            duration = time.time() - start_time
            status_code = response.status_code

            # Update Prometheus metrics
            REQUEST_COUNT.labels(
                method=method,
                endpoint=endpoint,
                status=str(status_code)
            ).inc()

            REQUEST_DURATION.labels(
                method=method,
                endpoint=endpoint
            ).observe(duration)

            # Record business metrics
            if endpoint == '/predict':
                await self._record_prediction_metrics(request, duration)
            elif endpoint == '/predict/batch':
                await self._record_batch_metrics(request, duration)

            # Update system health
            metrics_collector.update_system_health()

            return response

        except Exception as e:
            # Record error metrics
            duration = time.time() - start_time
            REQUEST_COUNT.labels(
                method=method,
                endpoint=endpoint,
                status="500"
            ).inc()

            REQUEST_DURATION.labels(
                method=method,
                endpoint=endpoint
            ).observe(duration)

            raise
        finally:
            # Decrement active requests
            self.active_requests[endpoint] -= 1

    async def _record_prediction_metrics(self, request, duration: float):
        """Record detailed prediction metrics"""
        try:
            # Extract request data
            body = await request.json()
            sentence = body.get('sentence', '')

            # Record business metrics
            metrics_collector.record_prediction(
                model_name='clinical-assertion-negation-bert',
                prediction_type='single',
                confidence=0.95,  # Would come from actual prediction
                duration=duration
            )

            # Record PHI detection if applicable
            phi_detected = 'patient' in sentence.lower() or 'medical' in sentence.lower()
            if phi_detected:
                metrics_collector.record_patient_data_access(
                    source_system='api',
                    record_type='clinical_note',
                    phi_detected=True
                )

        except Exception as e:
            logger.warning(f"Failed to record prediction metrics: {e}")

    async def _record_batch_metrics(self, request, duration: float):
        """Record batch prediction metrics"""
        try:
            body = await request.json()
            sentences = body.get('sentences', [])

            # Record batch metrics
            metrics_collector.record_prediction(
                model_name='clinical-assertion-negation-bert',
                prediction_type='batch',
                confidence=0.92,  # Would come from actual predictions
                duration=duration
            )

            # Check for PHI in batch
            phi_detected = any(
                'patient' in sentence.lower() or 'medical' in sentence.lower()
                for sentence in sentences
            )

            if phi_detected:
                metrics_collector.record_patient_data_access(
                    source_system='api',
                    record_type='clinical_notes_batch',
                    phi_detected=True
                )

        except Exception as e:
            logger.warning(f"Failed to record batch metrics: {e}")

# Apply enhanced middleware
app.add_middleware(EnhancedMetricsMiddleware)
```

### Performance Monitoring

#### Real-time Performance Tracking
```python
import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Deque
import time
from collections import deque, defaultdict

@dataclass
class PerformanceTracker:
    """Real-time performance tracking"""

    # Performance windows
    response_times: Deque[float] = field(default_factory=lambda: deque(maxlen=1000))
    error_rates: Deque[float] = field(default_factory=lambda: deque(maxlen=100))
    throughput_rates: Deque[float] = field(default_factory=lambda: deque(maxlen=60))

    # Current metrics
    current_requests: int = 0
    total_requests: int = 0
    total_errors: int = 0

    # Performance thresholds
    slow_query_threshold: float = 1.0  # seconds
    high_error_threshold: float = 0.05  # 5%

    def record_request(self, duration: float, success: bool = True):
        """Record a request for performance analysis"""
        self.response_times.append(duration)
        self.total_requests += 1
        self.current_requests += 1

        if not success:
            self.total_errors += 1

        # Update error rate (last 100 requests)
        if len(self.response_times) >= 100:
            recent_errors = sum(1 for rt in list(self.response_times)[-100:]
                              if not success)  # This is a simplified calculation
            error_rate = recent_errors / 100.0
            self.error_rates.append(error_rate)

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary"""
        if not self.response_times:
            return {"status": "insufficient_data"}

        response_times = list(self.response_times)

        return {
            "current_requests": self.current_requests,
            "total_requests": self.total_requests,
            "total_errors": self.total_errors,
            "error_rate": self.total_errors / max(self.total_requests, 1),
            "avg_response_time": sum(response_times) / len(response_times),
            "p50_response_time": sorted(response_times)[len(response_times) // 2],
            "p95_response_time": sorted(response_times)[int(len(response_times) * 0.95)],
            "p99_response_time": sorted(response_times)[int(len(response_times) * 0.99)],
            "min_response_time": min(response_times),
            "max_response_time": max(response_times),
            "throughput_rps": len(response_times) / max((time.time() - getattr(self, '_start_time', time.time())), 1),
            "performance_status": self._get_performance_status()
        }

    def _get_performance_status(self) -> str:
        """Determine overall performance status"""
        if not self.response_times:
            return "unknown"

        avg_response = sum(self.response_times) / len(self.response_times)
        error_rate = self.total_errors / max(self.total_requests, 1)

        if avg_response > self.slow_query_threshold or error_rate > self.high_error_threshold:
            return "degraded"
        elif avg_response > self.slow_query_threshold * 0.8:
            return "warning"
        else:
            return "healthy"

    async def monitor_performance(self):
        """Continuously monitor performance"""
        self._start_time = time.time()

        while True:
            try:
                # Update throughput (requests per second)
                elapsed = time.time() - self._start_time
                if elapsed > 0:
                    throughput = self.total_requests / elapsed
                    self.throughput_rates.append(throughput)

                # Log performance summary every minute
                if int(time.time()) % 60 == 0:
                    summary = self.get_performance_summary()
                    logger.info(f"Performance Summary: {summary}")

                    # Update Prometheus metrics
                    if summary.get('avg_response_time'):
                        REQUEST_DURATION.labels(
                            method='ALL',
                            endpoint='ALL'
                        ).observe(summary['avg_response_time'])

                await asyncio.sleep(1)

            except Exception as e:
                logger.error(f"Performance monitoring error: {e}")
                await asyncio.sleep(5)

# Initialize performance tracker
performance_tracker = PerformanceTracker()

# Start performance monitoring
asyncio.create_task(performance_tracker.monitor_performance())
```

#### Memory and Resource Monitoring
```python
import psutil
import gc
from threading import Thread
from time import sleep

class ResourceMonitor:
    """Monitor system resources and memory usage"""

    def __init__(self, check_interval: int = 30):
        self.check_interval = check_interval
        self.memory_history = deque(maxlen=100)
        self.cpu_history = deque(maxlen=100)
        self.is_monitoring = False
        self.monitor_thread = None

    def start_monitoring(self):
        """Start resource monitoring"""
        if self.is_monitoring:
            return

        self.is_monitoring = True
        self.monitor_thread = Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        """Stop resource monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                self._collect_metrics()
                sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Resource monitoring error: {e}")
                sleep(60)  # Wait longer on errors

    def _collect_metrics(self):
        """Collect current system metrics"""
        try:
            # Memory metrics
            memory = psutil.virtual_memory()
            memory_info = {
                'total': memory.total,
                'available': memory.available,
                'percent': memory.percent,
                'used': memory.used,
                'free': memory.free,
                'timestamp': datetime.utcnow().isoformat()
            }
            self.memory_history.append(memory_info)

            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_info = {
                'percent': cpu_percent,
                'count': psutil.cpu_count(),
                'timestamp': datetime.utcnow().isoformat()
            }
            self.cpu_history.append(cpu_info)

            # Update Prometheus metrics
            MEMORY_USAGE.set(memory.used)
            CPU_USAGE.set(cpu_percent)

            # Check for memory pressure
            if memory.percent > 85:
                logger.warning(f"High memory usage: {memory.percent}%")
                self._trigger_garbage_collection()

            # Check for CPU pressure
            if cpu_percent > 90:
                logger.warning(f"High CPU usage: {cpu_percent}%")

        except Exception as e:
            logger.error(f"Failed to collect metrics: {e}")

    def _trigger_garbage_collection(self):
        """Trigger garbage collection when memory pressure is high"""
        try:
            gc.collect()
            logger.info("Triggered garbage collection due to memory pressure")
        except Exception as e:
            logger.error(f"Failed to trigger garbage collection: {e}")

    def get_memory_trend(self) -> Dict[str, Any]:
        """Analyze memory usage trends"""
        if not self.memory_history:
            return {"trend": "insufficient_data"}

        recent = list(self.memory_history)[-10:]  # Last 10 measurements
        memory_percents = [entry['percent'] for entry in recent]

        avg_memory = sum(memory_percents) / len(memory_percents)
        trend = "stable"

        if len(memory_percents) >= 3:
            # Simple trend analysis
            recent_avg = sum(memory_percents[-3:]) / 3
            older_avg = sum(memory_percents[:3]) / 3

            if recent_avg > older_avg + 5:
                trend = "increasing"
            elif recent_avg < older_avg - 5:
                trend = "decreasing"

        return {
            "current_percent": memory_percents[-1] if memory_percents else 0,
            "average_percent": avg_memory,
            "trend": trend,
            "samples": len(memory_percents)
        }

    def get_resource_summary(self) -> Dict[str, Any]:
        """Get comprehensive resource summary"""
        return {
            "memory": self.get_memory_trend(),
            "cpu": {
                "current_percent": self.cpu_history[-1]['percent'] if self.cpu_history else 0,
                "cores": psutil.cpu_count()
            },
            "disk": {
                "total": psutil.disk_usage('/').total,
                "used": psutil.disk_usage('/').used,
                "free": psutil.disk_usage('/').free,
                "percent": psutil.disk_usage('/').percent
            },
            "network": {
                "connections": len(psutil.net_connections()),
                "interfaces": len(psutil.net_if_addrs())
            }
        }

# Initialize resource monitor
resource_monitor = ResourceMonitor()
resource_monitor.start_monitoring()
```

### Advanced Alerting

#### Predictive Alerting
```python
import numpy as np
from sklearn.linear_model import LinearRegression
from typing import List, Tuple, Optional

class PredictiveAlerter:
    """Predictive alerting based on trend analysis"""

    def __init__(self):
        self.response_time_history = deque(maxlen=1000)
        self.error_rate_history = deque(maxlen=100)
        self.prediction_models = {}

    def add_metric(self, metric_name: str, value: float, timestamp: float):
        """Add metric for trend analysis"""
        if metric_name == 'response_time':
            self.response_time_history.append((timestamp, value))
        elif metric_name == 'error_rate':
            self.error_rate_history.append((timestamp, value))

    def predict_response_time_trend(self, horizon: int = 10) -> Dict[str, Any]:
        """Predict response time trends"""
        if len(self.response_time_history) < 10:
            return {"prediction": "insufficient_data"}

        # Prepare data for regression
        timestamps, values = zip(*self.response_time_history)
        X = np.array(timestamps).reshape(-1, 1)
        y = np.array(values)

        # Fit linear regression
        model = LinearRegression()
        model.fit(X, y)

        # Make predictions
        future_timestamps = np.array([
            timestamps[-1] + i * 60 for i in range(1, horizon + 1)
        ]).reshape(-1, 1)

        predictions = model.predict(future_timestamps)

        # Analyze trend
        slope = model.coef_[0]
        trend = "stable"
        if slope > 0.01:
            trend = "increasing"
        elif slope < -0.01:
            trend = "decreasing"

        return {
            "current_trend": trend,
            "slope": slope,
            "predictions": predictions.tolist(),
            "confidence": self._calculate_confidence(X, y, model)
        }

    def predict_error_rate_trend(self, horizon: int = 10) -> Dict[str, Any]:
        """Predict error rate trends"""
        if len(self.error_rate_history) < 10:
            return {"prediction": "insufficient_data"}

        timestamps, values = zip(*self.error_rate_history)
        X = np.array(timestamps).reshape(-1, 1)
        y = np.array(values)

        model = LinearRegression()
        model.fit(X, y)

        future_timestamps = np.array([
            timestamps[-1] + i * 60 for i in range(1, horizon + 1)
        ]).reshape(-1, 1)

        predictions = model.predict(future_timestamps)

        slope = model.coef_[0]
        trend = "stable"
        if slope > 0.001:
            trend = "increasing"
        elif slope < -0.001:
            trend = "decreasing"

        return {
            "current_trend": trend,
            "slope": slope,
            "predictions": predictions.tolist(),
            "confidence": self._calculate_confidence(X, y, model)
        }

    def _calculate_confidence(self, X, y, model) -> float:
        """Calculate prediction confidence"""
        try:
            r_squared = model.score(X, y)
            return max(0, min(1, r_squared))
        except:
            return 0.5

    def check_predictive_alerts(self) -> List[Dict[str, Any]]:
        """Check for predictive alerts"""
        alerts = []

        # Check response time predictions
        rt_prediction = self.predict_response_time_trend()
        if rt_prediction.get('current_trend') == 'increasing':
            alerts.append({
                'type': 'PREDICTIVE_RESPONSE_TIME',
                'severity': 'warning',
                'message': f'Response time trending upward (slope: {rt_prediction["slope"]:.4f})',
                'prediction': rt_prediction
            })

        # Check error rate predictions
        error_prediction = self.predict_error_rate_trend()
        if error_prediction.get('current_trend') == 'increasing':
            alerts.append({
                'type': 'PREDICTIVE_ERROR_RATE',
                'severity': 'warning',
                'message': f'Error rate trending upward (slope: {error_prediction["slope"]:.4f})',
                'prediction': error_prediction
            })

        return alerts

# Initialize predictive alerter
predictive_alerter = PredictiveAlerter()
```

#### Multi-Channel Alerting
```python
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, List
import aiohttp
import json

class AlertChannel(ABC):
    """Abstract base class for alert channels"""

    @abstractmethod
    async def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send alert through this channel"""
        pass

class SlackAlertChannel(AlertChannel):
    """Slack alerting channel"""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    async def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send alert to Slack"""
        try:
            payload = {
                "channel": "#alerts",
                "username": "Clinical BERT Monitor",
                "icon_emoji": ":warning:",
                "attachments": [{
                    "color": self._get_color(alert['severity']),
                    "title": f"{alert['severity'].upper()}: {alert['type']}",
                    "text": alert['message'],
                    "fields": [
                        {
                            "title": "Service",
                            "value": "Clinical BERT API",
                            "short": True
                        },
                        {
                            "title": "Timestamp",
                            "value": datetime.utcnow().isoformat(),
                            "short": True
                        }
                    ],
                    "footer": "Clinical BERT Monitoring System"
                }]
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as response:
                    return response.status == 200

        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False

    def _get_color(self, severity: str) -> str:
        """Get color code for severity"""
        colors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'orange',
            'low': '#439FE0'
        }
        return colors.get(severity.lower(), 'good')

class EmailAlertChannel(AlertChannel):
    """Email alerting channel"""

    def __init__(self, smtp_server: str, smtp_port: int, sender: str, recipients: List[str]):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender = sender
        self.recipients = recipients

    async def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send alert via email"""
        try:
            # Implementation would use smtplib or similar
            # This is a simplified version
            subject = f"[{alert['severity'].upper()}] {alert['type']}"

            body = f"""
Clinical BERT API Alert

Severity: {alert['severity']}
Type: {alert['type']}
Message: {alert['message']}
Timestamp: {datetime.utcnow().isoformat()}

This is an automated alert from the Clinical BERT monitoring system.
"""

            # Send email logic here
            logger.info(f"Would send email alert: {subject}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False

class PagerDutyAlertChannel(AlertChannel):
    """PagerDuty alerting channel"""

    def __init__(self, routing_key: str, service_id: str):
        self.routing_key = routing_key
        self.service_id = service_id

    async def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send alert to PagerDuty"""
        try:
            payload = {
                "routing_key": self.routing_key,
                "event_action": "trigger",
                "payload": {
                    "summary": f"{alert['severity']}: {alert['type']}",
                    "source": "Clinical BERT API",
                    "severity": alert['severity'].lower(),
                    "component": "clinical-bert-api",
                    "group": "platform",
                    "class": alert['type'],
                    "custom_details": alert
                }
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://events.pagerduty.com/v2/enqueue",
                    json=payload
                ) as response:
                    return response.status == 202

        except Exception as e:
            logger.error(f"Failed to send PagerDuty alert: {e}")
            return False

class MultiChannelAlerter:
    """Multi-channel alerting system"""

    def __init__(self):
        self.channels: Dict[str, AlertChannel] = {}

    def add_channel(self, name: str, channel: AlertChannel):
        """Add an alert channel"""
        self.channels[name] = channel

    async def alert(self, alert: Dict[str, Any], channels: Optional[List[str]] = None) -> Dict[str, bool]:
        """Send alert through specified channels"""
        if channels is None:
            channels = list(self.channels.keys())

        results = {}
        for channel_name in channels:
            if channel_name in self.channels:
                success = await self.channels[channel_name].send_alert(alert)
                results[channel_name] = success
            else:
                logger.warning(f"Unknown alert channel: {channel_name}")
                results[channel_name] = False

        return results

    async def alert_critical(self, alert: Dict[str, Any]) -> Dict[str, bool]:
        """Send critical alert through all channels"""
        return await self.alert(alert, list(self.channels.keys()))

# Initialize multi-channel alerter
alerter = MultiChannelAlerter()

# Add alert channels (configure with your settings)
# alerter.add_channel('slack', SlackAlertChannel('your-slack-webhook'))
# alerter.add_channel('email', EmailAlertChannel('smtp.company.com', 587, 'alerts@company.com', ['ops@company.com']))
# alerter.add_channel('pagerduty', PagerDutyAlertChannel('your-routing-key', 'your-service-id'))
```

### Business Intelligence Dashboard

#### Real-time Business Metrics
```python
from fastapi import APIRouter
import json

router = APIRouter()

@router.get("/metrics/business")
async def get_business_metrics():
    """Get real-time business metrics"""
    # Get performance summary
    perf_summary = performance_tracker.get_performance_summary()

    # Get resource summary
    resource_summary = resource_monitor.get_resource_summary()

    # Get predictive alerts
    predictive_alerts = predictive_alerter.check_predictive_alerts()

    # Calculate business KPIs
    business_metrics = {
        "clinical_predictions": {
            "total": metrics_collector.predictions_total._value.get(),
            "by_type": {
                "single": metrics_collector.predictions_total._value.get(('clinical-assertion-negation-bert', 'single', 'high')),
                "batch": metrics_collector.predictions_total._value.get(('clinical-assertion-negation-bert', 'batch', 'high'))
            }
        },
        "patient_data": {
            "records_processed": metrics_collector.patient_records_processed._value.get(),
            "phi_access_events": metrics_collector.phi_data_accessed._value.get(),
            "compliance_status": "compliant" if predictive_alerts else "warning"
        },
        "system_health": {
            "overall_score": metrics_collector.system_health_score._value.get(),
            "active_connections": metrics_collector.active_connections._value.get(),
            "performance_status": perf_summary.get('performance_status', 'unknown')
        },
        "predictive_alerts": predictive_alerts,
        "resource_utilization": resource_summary
    }

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "business_metrics": business_metrics,
        "alerts": len(predictive_alerts),
        "health_status": "healthy" if len(predictive_alerts) == 0 else "warning"
    }

@router.get("/metrics/health")
async def get_health_metrics():
    """Get comprehensive health metrics"""
    return {
        "service_health": {
            "status": "healthy",
            "uptime": "99.95%",
            "last_incident": "2024-01-10T15:30:00Z"
        },
        "performance_health": performance_tracker.get_performance_summary(),
        "resource_health": resource_monitor.get_resource_summary(),
        "business_health": {
            "predictions_today": 1250,
            "avg_confidence": 0.94,
            "error_rate": 0.02
        }
    }
```

### Automated Performance Optimization

#### Dynamic Resource Scaling
```python
class AutoScaler:
    """Automatic resource scaling based on metrics"""

    def __init__(self):
        self.scale_up_threshold = 0.8  # 80% CPU usage
        self.scale_down_threshold = 0.3  # 30% CPU usage
        self.min_instances = 1
        self.max_instances = 20
        self.current_instances = 1

    async def monitor_and_scale(self):
        """Monitor metrics and scale resources automatically"""
        while True:
            try:
                # Get current metrics
                cpu_usage = CPU_USAGE._value.get()
                memory_usage = MEMORY_USAGE._value.get()
                request_rate = REQUEST_COUNT._value.get()

                # Calculate scaling decision
                scaling_decision = self._calculate_scaling_decision(
                    cpu_usage, memory_usage, request_rate
                )

                if scaling_decision['should_scale']:
                    await self._execute_scaling(scaling_decision)

                await asyncio.sleep(60)  # Check every minute

            except Exception as e:
                logger.error(f"Auto-scaling error: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes on error

    def _calculate_scaling_decision(self, cpu_usage: float, memory_usage: float, request_rate: float) -> Dict[str, Any]:
        """Calculate whether to scale up or down"""
        decision = {
            'should_scale': False,
            'direction': 'none',
            'reason': '',
            'target_instances': self.current_instances
        }

        # Scale up conditions
        if (cpu_usage > self.scale_up_threshold or
            memory_usage > self.scale_up_threshold * 1024 * 1024 * 1024 or  # 80% of memory
            request_rate > 100):  # High request rate

            if self.current_instances < self.max_instances:
                decision['should_scale'] = True
                decision['direction'] = 'up'
                decision['target_instances'] = min(
                    self.current_instances + 1,
                    self.max_instances
                )
                decision['reason'] = f'High resource usage: CPU={cpu_usage:.1%}, Memory={memory_usage/(1024**3):.1f}GB'

        # Scale down conditions
        elif (cpu_usage < self.scale_down_threshold and
              memory_usage < self.scale_down_threshold * 1024 * 1024 * 1024 and
              request_rate < 50):  # Low request rate

            if self.current_instances > self.min_instances:
                decision['should_scale'] = True
                decision['direction'] = 'down'
                decision['target_instances'] = max(
                    self.current_instances - 1,
                    self.min_instances
                )
                decision['reason'] = f'Low resource usage: CPU={cpu_usage:.1%}, Memory={memory_usage/(1024**3):.1f}GB'

        return decision

    async def _execute_scaling(self, decision: Dict[str, Any]):
        """Execute scaling decision"""
        try:
            if decision['direction'] == 'up':
                logger.info(f"Scaling up from {self.current_instances} to {decision['target_instances']} instances")
                # Implementation: gcloud run services update --max-instances=decision['target_instances']

            elif decision['direction'] == 'down':
                logger.info(f"Scaling down from {self.current_instances} to {decision['target_instances']} instances")
                # Implementation: gcloud run services update --max-instances=decision['target_instances']

            self.current_instances = decision['target_instances']
            logger.info(f"Scaling completed: {decision['reason']}")

        except Exception as e:
            logger.error(f"Failed to execute scaling: {e}")

# Initialize auto-scaler
auto_scaler = AutoScaler()
asyncio.create_task(auto_scaler.monitor_and_scale())
```

---

**Monitor • Alert • Optimize • Automate**

*Advanced monitoring and observability for Clinical BERT API*
