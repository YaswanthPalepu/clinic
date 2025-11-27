# Clinical BERT Assertion API - Complete API Documentation

## Overview

The Clinical BERT Assertion API provides real-time clinical text classification capabilities using state-of-the-art transformer models. The API analyzes clinical sentences and categorizes medical assertions as **PRESENT**, **ABSENT**, or **POSSIBLE**.

### Base URLs
- **Production**: `https://your-service-url`
- **Staging**: `https://staging-your-service-url`
- **Development**: `http://localhost:8000`

### Authentication
All API endpoints support optional authentication via API keys:
```bash
# Include in request headers
Authorization: Bearer YOUR_API_KEY
```

---

## Core Endpoints

### Health Check Endpoint

#### GET /health
Returns comprehensive service health information including model status, system metrics, and uptime.

**Request:**
```bash
curl -X GET https://your-service-url/health \
  -H "Content-Type: application/json"
```

**Response (200 OK):**
```json
{
  "status": "healthy",
  "model_loaded": true,
  "timestamp": 1642857600.123,
  "version": "1.0.0",
  "environment": "production",
  "uptime_seconds": 3600.5,
  "total_predictions": 1250,
  "system_metrics": {
    "memory_mb": 730.6,
    "memory_percent": 87.7,
    "cpu_percent": 12.3,
    "disk_percent": 45.2
  },
  "model_info": {
    "model_name": "bvanaken/clinical-assertion-negation-bert",
    "device": "cpu",
    "loaded": true,
    "labels": ["PRESENT", "ABSENT", "POSSIBLE"]
  }
}
```

**Response Fields:**
- `status`: Service health status ("healthy" or "unhealthy")
- `model_loaded`: Whether ML model is loaded and ready
- `timestamp`: Unix timestamp of health check
- `version`: API version
- `environment`: Deployment environment
- `uptime_seconds`: Service uptime in seconds
- `total_predictions`: Total predictions made since startup
- `system_metrics`: System resource utilization
- `model_info`: ML model details and status

---

### Single Prediction Endpoint

#### POST /predict
Analyzes a single clinical sentence and returns assertion classification.

**Request:**
```bash
curl -X POST https://your-service-url/predict \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "sentence": "The patient reports chest pain."
  }'
```

**Request Body:**
```json
{
  "sentence": "string (required, max 512 tokens)"
}
```

**Response (200 OK):**
```json
{
  "label": "PRESENT",
  "score": 0.9914,
  "model_label": "PRESENT",
  "prediction_time_ms": 245.67,
  "request_id": "req-12345-abcde"
}
```

**Response Fields:**
- `label`: Final classification ("PRESENT", "ABSENT", "POSSIBLE")
- `score`: Confidence score (0.0 to 1.0)
- `model_label`: Raw model prediction
- `prediction_time_ms`: Processing time in milliseconds
- `request_id`: Unique request identifier for tracing

**Error Responses:**

**400 Bad Request - Invalid Input:**
```json
{
  "error": "ValidationError",
  "message": "Input validation failed",
  "details": {
    "sentence": "Field required"
  },
  "request_id": "req-12345-error"
}
```

**429 Too Many Requests - Rate Limited:**
```json
{
  "error": "RateLimitError",
  "message": "Rate limit exceeded",
  "retry_after": 60,
  "request_id": "req-12345-rate"
}
```

**500 Internal Server Error:**
```json
{
  "error": "InternalError",
  "message": "Model inference failed",
  "request_id": "req-12345-500"
}
```

---

### Batch Prediction Endpoint

#### POST /predict/batch
Analyzes multiple clinical sentences in a single request for improved efficiency.

**Request:**
```bash
curl -X POST https://your-service-url/predict/batch \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "sentences": [
      "The patient reports chest pain.",
      "No signs of pneumonia were observed.",
      "He has a history of hypertension."
    ]
  }'
```

**Request Body:**
```json
{
  "sentences": [
    "string (required, 1-100 sentences, max 512 tokens each)"
  ]
}
```

**Response (200 OK):**
```json
{
  "predictions": [
    {
      "label": "PRESENT",
      "score": 0.9914,
      "model_label": "PRESENT",
      "prediction_time_ms": 89.23,
      "request_id": "batch-12345-abcde"
    },
    {
      "label": "ABSENT",
      "score": 0.9654,
      "model_label": "ABSENT",
      "prediction_time_ms": 87.45,
      "request_id": "batch-12345-abcde"
    },
    {
      "label": "PRESENT",
      "score": 0.9953,
      "model_label": "PRESENT",
      "prediction_time_ms": 91.12,
      "request_id": "batch-12345-abcde"
    }
  ],
  "batch_size": 3,
  "total_prediction_time_ms": 267.8,
  "request_id": "batch-12345-abcde"
}
```

**Batch Processing Notes:**
- **Maximum batch size**: 100 sentences
- **Processing**: All sentences processed in parallel
- **Efficiency**: ~3x faster than individual requests
- **Memory**: Optimized for large batches
- **Error handling**: Individual sentence failures don't affect batch

---

### Model Information Endpoint

#### GET /model/info
Returns detailed information about the loaded ML model and its capabilities.

**Request:**
```bash
curl -X GET https://your-service-url/model/info \
  -H "Authorization: Bearer YOUR_API_KEY"
```

**Response (200 OK):**
```json
{
  "model_name": "bvanaken/clinical-assertion-negation-bert",
  "device": "cpu",
  "loaded": true,
  "labels": ["PRESENT", "ABSENT", "POSSIBLE"],
  "max_sequence_length": 512,
  "model_size_mb": 420.5,
  "tokenizer_type": "BERT",
  "framework": "transformers",
  "version": "1.0.0"
}
```

---

## Monitoring Endpoints

### Prometheus Metrics

#### GET /metrics
Returns comprehensive metrics in Prometheus format for monitoring and alerting.

**Request:**
```bash
curl -X GET https://your-service-url/metrics
```

**Sample Output:**
```prometheus
# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="POST",endpoint="/predict",status="200"} 1250

# HELP http_request_duration_seconds HTTP request duration
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{method="POST",endpoint="/predict",le="0.1"} 850
http_request_duration_seconds_bucket{method="POST",endpoint="/predict",le="0.5"} 1200
http_request_duration_seconds_bucket{method="POST",endpoint="/predict",le="+Inf"} 1250

# HELP model_predictions_total Total model predictions
# TYPE model_predictions_total counter
model_predictions_total{label="PRESENT"} 650
model_predictions_total{label="ABSENT"} 450
model_predictions_total{label="POSSIBLE"} 150
```

**Available Metrics:**
- **Request metrics**: Count, duration, error rates by endpoint
- **Model metrics**: Prediction counts, inference times, accuracy
- **System metrics**: CPU, memory, disk usage
- **Business metrics**: Usage patterns, client distribution

---

## API Specifications

### Request/Response Format

#### Content Types
- **Request**: `application/json`
- **Response**: `application/json`
- **Encoding**: UTF-8

#### Rate Limiting
- **Default limit**: 100 requests per minute per client
- **Headers**: Include rate limit information in responses
- **Backoff**: Exponential backoff recommended

#### Timeouts
- **Request timeout**: 30 seconds
- **Connection timeout**: 10 seconds
- **Read timeout**: 30 seconds

### Error Handling

#### HTTP Status Codes
- **200 OK**: Successful request
- **400 Bad Request**: Invalid input parameters
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Endpoint doesn't exist
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Server error
- **503 Service Unavailable**: Service temporarily unavailable

#### Error Response Format
```json
{
  "error": "ErrorType",
  "message": "Human-readable error message",
  "details": {
    "field": "specific field error",
    "constraint": "validation constraint"
  },
  "request_id": "unique-request-identifier",
  "timestamp": 1642857600.123
}
```

---

## Testing & Validation

### Test Data Examples

#### Clinical Assertion Examples

**PRESENT Assertions:**
- "The patient reports chest pain."
- "He has a history of hypertension."
- "Blood pressure is elevated at 160/95."
- "Patient exhibits signs of pneumonia."

**ABSENT Assertions:**
- "The patient denies chest pain."
- "No signs of pneumonia were observed."
- "Patient reports no history of diabetes."
- "Blood pressure within normal limits."

**POSSIBLE Assertions:**
- "If symptoms persist, call doctor."
- "Patient may have pneumonia."
- "Suspected cardiac arrhythmia."
- "Possible medication interaction."

### Validation Rules

#### Input Validation
- **Sentence length**: 1-512 tokens
- **Content type**: Plain text only
- **Encoding**: UTF-8
- **Special characters**: Limited sanitization applied

#### Output Validation
- **Label format**: One of ["PRESENT", "ABSENT", "POSSIBLE"]
- **Score range**: 0.0 to 1.0
- **Response time**: <500ms for single predictions
- **Request ID**: UUID format

---

## Security Considerations

### Authentication Methods
1. **API Key Authentication** (recommended for production)
2. **OAuth 2.0** (for enterprise integrations)
3. **JWT Tokens** (for stateless authentication)

### Data Protection
- **Input sanitization**: Automatic cleaning of clinical text
- **Output filtering**: Sensitive information masking
- **Audit logging**: All requests logged with correlation IDs
- **Rate limiting**: Protection against abuse

### Compliance
- **HIPAA**: Protected health information handling
- **GDPR**: Data protection and privacy
- **SOC 2**: Security and availability controls

---

## Usage Guidelines

### Best Practices

#### Request Optimization
- Use batch predictions for multiple sentences
- Implement client-side caching for repeated queries
- Respect rate limits and implement backoff strategies
- Monitor response times and adjust timeouts accordingly

#### Error Handling
- Implement comprehensive error handling
- Use request IDs for debugging and support
- Log errors with appropriate detail levels
- Implement retry logic with exponential backoff

#### Monitoring Integration
- Monitor API usage and performance metrics
- Set up alerts for error rates and response times
- Track business metrics and usage patterns
- Implement logging and tracing for debugging

### Performance Tips

#### Client-Side Optimization
- **Connection pooling**: Reuse HTTP connections
- **Compression**: Enable gzip compression
- **Async processing**: Use async/await for concurrent requests
- **Load balancing**: Distribute requests across multiple instances

#### Server-Side Optimization
- **Caching**: Implement response caching for frequent queries
- **Batch processing**: Use batch endpoints for efficiency
- **Resource allocation**: Monitor and adjust instance sizing
- **Auto-scaling**: Configure appropriate scaling policies

---

## Integration Examples

### Python Integration (Enhanced)
```python
import requests
from typing import List, Dict, Any

class ClinicalBERTClient:
    def __init__(self, base_url: str, api_key: str = None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {api_key}'
            })

    def predict(self, sentence: str) -> Dict[str, Any]:
        """Single sentence prediction"""
        response = self.session.post(
            f"{self.base_url}/predict",
            json={"sentence": sentence}
        )
        response.raise_for_status()
        return response.json()

    def predict_batch(self, sentences: List[str]) -> Dict[str, Any]:
        """Batch prediction"""
        response = self.session.post(
            f"{self.base_url}/predict/batch",
            json={"sentences": sentences}
        )
        response.raise_for_status()
        return response.json()

    def health_check(self) -> Dict[str, Any]:
        """Service health check"""
        response = self.session.get(f"{self.base_url}/health")
        response.raise_for_status()
        return response.json()

# Usage example
client = ClinicalBERTClient("https://your-service-url", "your-api-key")
result = client.predict("The patient reports chest pain.")
print(f"Prediction: {result['label']} (confidence: {result['score']:.4f})")
```

### JavaScript/Node.js Integration
```javascript
const axios = require('axios');

class ClinicalBERTClient {
    constructor(baseURL, apiKey = null) {
        this.client = axios.create({
            baseURL,
            headers: apiKey ? {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            } : {
                'Content-Type': 'application/json'
            }
        });
    }

    async predict(sentence) {
        const response = await this.client.post('/predict', { sentence });
        return response.data;
    }

    async predictBatch(sentences) {
        const response = await this.client.post('/predict/batch', { sentences });
        return response.data;
    }

    async healthCheck() {
        const response = await this.client.get('/health');
        return response.data;
    }
}

// Usage example
const client = new ClinicalBERTClient('https://your-service-url', 'your-api-key');
client.predict('The patient reports chest pain.')
    .then(result => {
        console.log(`Prediction: ${result.label} (confidence: ${result.score.toFixed(4)})`);
    })
    .catch(error => {
        console.error('API Error:', error.response.data);
    });
```

### Java Integration
```java
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class ClinicalBERTClient {
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final String baseUrl;
    private final String apiKey;

    public ClinicalBERTClient(String baseUrl, String apiKey) {
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
    }

    public Map<String, Object> predict(String sentence) throws Exception {
        Map<String, String> requestBody = Map.of("sentence", sentence);

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/predict"))
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer " + apiKey)
            .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(requestBody)))
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new RuntimeException("API Error: " + response.statusCode() + " - " + response.body());
        }

        return objectMapper.readValue(response.body(), new TypeReference<Map<String, Object>>(){});
    }

    public Map<String, Object> predictBatch(List<String> sentences) throws Exception {
        Map<String, List<String>> requestBody = Map.of("sentences", sentences);

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/predict/batch"))
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer " + apiKey)
            .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(requestBody)))
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new RuntimeException("API Error: " + response.statusCode() + " - " + response.body());
        }

        return objectMapper.readValue(response.body(), new TypeReference<Map<String, Object>>(){});
    }

    public Map<String, Object> healthCheck() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/health"))
            .GET()
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        return objectMapper.readValue(response.body(), new TypeReference<Map<String, Object>>(){});
    }
}

// Usage example
public class Example {
    public static void main(String[] args) {
        ClinicalBERTClient client = new ClinicalBERTClient("https://your-service-url", "your-api-key");

        try {
            // Single prediction
            Map<String, Object> result = client.predict("The patient reports chest pain.");
            System.out.println("Prediction: " + result.get("label"));
            System.out.println("Confidence: " + result.get("score"));

            // Batch prediction
            List<String> sentences = List.of(
                "Patient has fever.",
                "No signs of infection.",
                "Blood pressure elevated."
            );
            Map<String, Object> batchResult = client.predictBatch(sentences);
            System.out.println("Batch processed: " + batchResult.get("batch_size") + " sentences");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
```

### EHR Integration Example

#### Epic EHR Integration
```python
import requests
import json
from typing import Dict, List, Any
from datetime import datetime

class EpicClinicalBERTIntegration:
    """Integration with Epic EHR system"""

    def __init__(self, epic_base_url: str, clinical_bert_url: str, api_key: str):
        self.epic_base_url = epic_base_url
        self.clinical_bert_url = clinical_bert_url
        self.api_key = api_key
        self.session = requests.Session()

        # Configure headers
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        })

    def get_patient_notes(self, patient_id: str, date_from: str = None) -> List[str]:
        """Extract clinical notes from Epic EHR"""
        # Epic-specific API call to get patient notes
        epic_endpoint = f"{self.epic_base_url}/api/epic/patients/{patient_id}/notes"

        params = {}
        if date_from:
            params['date_from'] = date_from

        response = requests.get(epic_endpoint, params=params)
        response.raise_for_status()

        # Parse Epic response and extract clinical text
        epic_data = response.json()
        clinical_notes = []

        for note in epic_data.get('notes', []):
            # Extract relevant clinical text
            clinical_text = note.get('clinical_text', '')
            if clinical_text:
                clinical_notes.append(clinical_text)

        return clinical_notes

    def process_patient_assertions(self, patient_id: str) -> Dict[str, Any]:
        """Process all clinical assertions for a patient"""
        # Get clinical notes from Epic
        clinical_notes = self.get_patient_notes(patient_id)

        if not clinical_notes:
            return {"patient_id": patient_id, "assertions": [], "total_processed": 0}

        # Process notes in batches
        batch_size = 10
        all_assertions = []

        for i in range(0, len(clinical_notes), batch_size):
            batch = clinical_notes[i:i + batch_size]

            # Send to Clinical BERT API
            batch_response = self.session.post(
                f"{self.clinical_bert_url}/predict/batch",
                json={"sentences": batch}
            )
            batch_response.raise_for_status()

            batch_result = batch_response.json()
            all_assertions.extend(batch_result['predictions'])

        # Aggregate results
        assertion_summary = {
            "patient_id": patient_id,
            "total_notes": len(clinical_notes),
            "total_assertions": len(all_assertions),
            "assertions": all_assertions,
            "summary": self._summarize_assertions(all_assertions),
            "processed_at": datetime.utcnow().isoformat()
        }

        return assertion_summary

    def _summarize_assertions(self, assertions: List[Dict]) -> Dict[str, Any]:
        """Create summary of assertions"""
        summary = {"PRESENT": 0, "ABSENT": 0, "POSSIBLE": 0}

        for assertion in assertions:
            label = assertion.get('label', 'UNKNOWN')
            if label in summary:
                summary[label] += 1

        return summary

# Usage example
def main():
    epic_integration = EpicClinicalBERTIntegration(
        epic_base_url="https://your-epic-system.com",
        clinical_bert_url="https://your-clinical-bert-api.com",
        api_key="your-api-key"
    )

    # Process patient clinical notes
    patient_id = "PAT12345"
    result = epic_integration.process_patient_assertions(patient_id)

    print(f"Patient {patient_id} Analysis:")
    print(f"Total notes processed: {result['total_notes']}")
    print(f"Assertion summary: {result['summary']}")

    # Store results back in Epic or other system
    store_results_in_ehr(result)

if __name__ == "__main__":
    main()
```

### Real-time Processing with Webhooks

#### Webhook Server Implementation
```python
from flask import Flask, request, jsonify
import requests
from typing import Dict, Any
import logging

app = Flask(__name__)

class ClinicalBERTWebhookProcessor:
    def __init__(self, clinical_bert_url: str, api_key: str):
        self.clinical_bert_url = clinical_bert_url
        self.api_key = api_key

    def process_webhook(self, webhook_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process incoming webhook data"""

        # Extract clinical text from webhook
        clinical_text = self._extract_clinical_text(webhook_data)

        if not clinical_text:
            return {"error": "No clinical text found in webhook data"}

        # Send to Clinical BERT API
        try:
            response = requests.post(
                f"{self.clinical_bert_url}/predict",
                json={"sentence": clinical_text},
                headers={'Authorization': f'Bearer {self.api_key}'},
                timeout=30
            )
            response.raise_for_status()

            prediction_result = response.json()

            # Enhance webhook data with prediction
            enhanced_data = {
                **webhook_data,
                "clinical_assertion": prediction_result,
                "processed_at": datetime.utcnow().isoformat(),
                "processor": "clinical-bert-webhook"
            }

            return enhanced_data

        except requests.exceptions.RequestException as e:
            logging.error(f"Clinical BERT API error: {e}")
            return {"error": f"Clinical BERT processing failed: {str(e)}"}

    def _extract_clinical_text(self, webhook_data: Dict[str, Any]) -> str:
        """Extract clinical text from various webhook formats"""
        # Handle different EHR system formats
        if 'clinical_text' in webhook_data:
            return webhook_data['clinical_text']
        elif 'note_text' in webhook_data:
            return webhook_data['note_text']
        elif 'assessment' in webhook_data:
            return webhook_data['assessment']
        elif 'clinical_note' in webhook_data:
            return webhook_data['clinical_note']
        else:
            # Try to find text in nested structures
            return self._find_text_recursively(webhook_data)

    def _find_text_recursively(self, data: Dict[str, Any], max_depth: int = 3) -> str:
        """Recursively search for clinical text in nested data"""
        if max_depth <= 0:
            return ""

        if isinstance(data, dict):
            for key, value in data.items():
                if 'text' in key.lower() or 'note' in key.lower() or 'clinical' in key.lower():
                    if isinstance(value, str) and len(value) > 10:
                        return value
                elif isinstance(value, (dict, list)):
                    result = self._find_text_recursively(value, max_depth - 1)
                    if result:
                        return result
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    result = self._find_text_recursively(item, max_depth - 1)
                    if result:
                        return result

        return ""

# Initialize webhook processor
webhook_processor = ClinicalBERTWebhookProcessor(
    clinical_bert_url="https://your-clinical-bert-api.com",
    api_key="your-api-key"
)

@app.route('/webhook/clinical-notes', methods=['POST'])
def clinical_notes_webhook():
    """Webhook endpoint for processing clinical notes"""
    try:
        webhook_data = request.get_json()

        if not webhook_data:
            return jsonify({"error": "No data provided"}), 400

        # Process the webhook
        result = webhook_processor.process_webhook(webhook_data)

        # Forward enhanced data to downstream systems
        forward_to_downstream_systems(result)

        return jsonify(result), 200

    except Exception as e:
        logging.error(f"Webhook processing error: {e}")
        return jsonify({"error": str(e)}), 500

def forward_to_downstream_systems(enhanced_data: Dict[str, Any]):
    """Forward processed data to downstream systems"""
    # Example: Forward to data warehouse, analytics system, etc.
    try:
        # Forward to analytics system
        requests.post(
            "https://analytics-system.com/webhook/clinical-insights",
            json=enhanced_data,
            timeout=10
        )

        # Forward to alerting system if critical findings
        if enhanced_data.get('clinical_assertion', {}).get('label') == 'POSSIBLE':
            requests.post(
                "https://alerting-system.com/webhook/critical-findings",
                json=enhanced_data,
                timeout=10
            )

    except Exception as e:
        logging.error(f"Error forwarding to downstream systems: {e}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host='0.0.0.0', port=8080, debug=True)
```

---

## Troubleshooting Guide

### Quick Diagnostics

#### 1. Health Check First
```bash
# Always start with health check
curl -s https://your-service-url/health | jq '.'

# Expected response:
{
  "status": "healthy",
  "model_loaded": true,
  "uptime_seconds": 3600,
  "total_predictions": 1250
}
```

#### 2. Check Service Metrics
```bash
# Check Prometheus metrics
curl -s https://your-service-url/metrics | grep -E "(http_requests_total|model_predictions_total)"

# Check model status
curl -s https://your-service-url/model/info | jq '.'
```

### Common Issues & Solutions

#### Service Unavailable (503)
**Symptoms:**
- Health check shows `"model_loaded": false`
- All prediction requests return 503 errors

**Diagnosis:**
```bash
# Check detailed health
curl -s https://your-service-url/health | jq '.'

# Check service logs
gcloud logging read "resource.type=cloud_run_revision" \
  --filter="resource.labels.service_name=clinical-bert-api" \
  --limit=20
```

**Solutions:**
1. **Model Loading Issue:**
   ```bash
   # Restart the service to reload model
   gcloud run services update clinical-bert-api \
     --region=us-central1 \
     --min-instances=0 --max-instances=0
   sleep 30
   gcloud run services update clinical-bert-api \
     --region=us-central1 \
     --min-instances=1 --max-instances=10
   ```

2. **Memory Issues:**
   ```bash
   # Increase memory allocation
   gcloud run services update clinical-bert-api \
     --memory=4Gi \
     --region=us-central1
   ```

3. **Cold Start Timeout:**
   ```bash
   # Increase timeout and min instances
   gcloud run services update clinical-bert-api \
     --timeout=600 \
     --min-instances=1 \
     --region=us-central1
   ```

#### Slow Response Times (>500ms)
**Symptoms:**
- Predictions taking longer than expected
- Timeout errors on client side

**Diagnosis:**
```bash
# Check current performance
curl -s https://your-service-url/metrics | grep -A5 -B5 "http_request_duration"

# Monitor system resources
curl -s https://your-service-url/health | jq '.system_metrics'
```

**Solutions:**
1. **Enable Batching:**
   ```python
   # Instead of multiple single requests
   single_results = []
   for sentence in sentences:
       result = client.predict(sentence)  # Slow
       single_results.append(result)

   # Use batch processing
   batch_result = client.predict_batch(sentences)  # Fast
   ```

2. **Optimize Client Configuration:**
   ```python
   import requests

   # Use connection pooling
   session = requests.Session()
   adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=20)
   session.mount("https://", adapter)

   # Set appropriate timeouts
   response = session.post(url, json=data, timeout=(10, 30))
   ```

3. **Scale Service:**
   ```bash
   # Increase concurrency
   gcloud run services update clinical-bert-api \
     --concurrency=100 \
     --region=us-central1

   # Add more instances
   gcloud run services update clinical-bert-api \
     --max-instances=20 \
     --region=us-central1
   ```

#### Rate Limiting (429)
**Symptoms:**
- Getting 429 "Too Many Requests" errors
- Requests being throttled

**Diagnosis:**
```bash
# Check rate limit headers
curl -v https://your-service-url/predict \
  -H "Content-Type: application/json" \
  -d '{"sentence": "test"}' 2>&1 | grep -i "x-ratelimit"

# Monitor your usage
curl -s https://your-service-url/metrics | grep "http_requests_total"
```

**Solutions:**
1. **Implement Exponential Backoff:**
   ```python
   import time
   import random

   def make_request_with_backoff(client, sentence, max_retries=5):
       for attempt in range(max_retries):
           try:
               response = client.predict(sentence)
               return response
           except requests.exceptions.HTTPError as e:
               if e.response.status_code == 429:
                   # Exponential backoff with jitter
                   wait_time = (2 ** attempt) + random.uniform(0, 1)
                   print(f"Rate limited. Waiting {wait_time:.2f}s...")
                   time.sleep(wait_time)
                   continue
               else:
                   raise
       raise Exception("Max retries exceeded")
   ```

2. **Batch Requests:**
   ```python
   # Instead of 100 single requests (100 req/min limit)
   # Use 10 batch requests with 10 sentences each
   sentences = [...]  # Your 100 sentences
   batch_size = 10

   for i in range(0, len(sentences), batch_size):
       batch = sentences[i:i + batch_size]
       result = client.predict_batch(batch)
       # Process results
   ```

3. **Request Optimization:**
   ```python
   # Use connection pooling
   session = requests.Session()

   # Make concurrent requests efficiently
   from concurrent.futures import ThreadPoolExecutor

   def process_sentences(sentences):
       with ThreadPoolExecutor(max_workers=5) as executor:
           results = list(executor.map(client.predict, sentences))
       return results
   ```

#### Authentication Issues (401/403)
**Symptoms:**
- 401 Unauthorized errors
- 403 Forbidden errors

**Diagnosis:**
```bash
# Test without authentication first
curl -X POST https://your-service-url/predict \
  -H "Content-Type: application/json" \
  -d '{"sentence": "test"}'

# Check if API key is required
curl -s https://your-service-url/health | jq '.'

# Test with API key
curl -X POST https://your-service-url/predict \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"sentence": "test"}'
```

**Solutions:**
1. **API Key Configuration:**
   ```python
   # Method 1: Header authentication
   headers = {
       'Authorization': 'Bearer YOUR_API_KEY',
       'Content-Type': 'application/json'
   }

   # Method 2: Query parameter (if supported)
   params = {'api_key': 'YOUR_API_KEY'}

   # Method 3: Multiple API keys for different environments
   API_KEYS = {
       'development': 'dev-key-123',
       'staging': 'staging-key-456',
       'production': 'prod-key-789'
   }
   ```

2. **Environment-Specific Keys:**
   ```bash
   # Set different keys for different environments
   export CLINICAL_BERT_API_KEY="your-production-key"

   # In your client code
   import os
   api_key = os.getenv('CLINICAL_BERT_API_KEY')
   ```

#### Monitoring & Alerting Issues
**Symptoms:**
- Not receiving alerts
- Missing metrics data
- Dashboard not loading

**Diagnosis:**
```bash
# Check if metrics endpoint is accessible
curl -s https://your-service-url/metrics | head -10

# Verify Prometheus configuration
curl -s http://prometheus:9090/api/v1/query?query=up | jq '.'

# Check Grafana dashboards
curl -s http://grafana:3000/api/health
```

**Solutions:**
1. **Metrics Collection:**
   ```python
   # Ensure metrics are being collected
   from prometheus_client import Counter, Histogram
   import time

   REQUEST_COUNT = Counter('api_requests_total', 'Total API requests', ['endpoint'])
   REQUEST_DURATION = Histogram('api_request_duration_seconds', 'Request duration')

   @app.middleware("http")
   async def metrics_middleware(request, call_next):
       start_time = time.time()
       REQUEST_COUNT.labels(endpoint=request.url.path).inc()

       response = await call_next(request)

       REQUEST_DURATION.observe(time.time() - start_time)
       return response
   ```

2. **Alert Configuration:**
   ```yaml
   # Ensure alerts are properly configured
   groups:
     - name: clinical_bert_alerts
       rules:
         - alert: HighErrorRate
           expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
           for: 5m
           labels:
             severity: critical
           annotations:
             summary: "High error rate detected"
   ```

#### Batch Processing Issues
**Symptoms:**
- Batch requests failing
- Individual items in batch failing
- Memory errors with large batches

**Diagnosis:**
```bash
# Test with small batch first
curl -X POST https://your-service-url/predict/batch \
  -H "Content-Type: application/json" \
  -d '{"sentences": ["test sentence"]}'

# Check batch size limits
curl -s https://your-service-url/health | jq '.'

# Monitor memory usage
curl -s https://your-service-url/metrics | grep "memory"
```

**Solutions:**
1. **Optimal Batch Sizing:**
   ```python
   def process_optimal_batches(sentences, optimal_size=10):
       """Process sentences in optimally sized batches"""
       results = []

       for i in range(0, len(sentences), optimal_size):
           batch = sentences[i:i + optimal_size]
           try:
               batch_result = client.predict_batch(batch)
               results.extend(batch_result['predictions'])

               # Add small delay between batches
               time.sleep(0.1)

           except Exception as e:
               print(f"Batch {i//optimal_size} failed: {e}")
               # Fallback to individual processing
               for sentence in batch:
                   try:
                       result = client.predict(sentence)
                       results.append(result)
                   except Exception as inner_e:
                       print(f"Individual processing failed: {inner_e}")

       return results
   ```

2. **Error Handling in Batches:**
   ```python
   def robust_batch_processing(sentences, batch_size=10):
       """Robust batch processing with error handling"""
       all_results = []

       for i in range(0, len(sentences), batch_size):
           batch = sentences[i:i + batch_size]

           for attempt in range(3):  # Retry up to 3 times
               try:
                   result = client.predict_batch(batch)
                   all_results.extend(result['predictions'])
                   break
               except Exception as e:
                   if attempt == 2:  # Last attempt
                       print(f"Batch failed after 3 attempts: {e}")
                       # Process individually
                       for sentence in batch:
                           try:
                               individual_result = client.predict(sentence)
                               all_results.append(individual_result)
                           except Exception as inner_e:
                               print(f"Individual processing failed: {inner_e}")
                   else:
                       time.sleep(2 ** attempt)  # Exponential backoff

       return all_results
   ```

#### EHR Integration Issues
**Symptoms:**
- Cannot connect to EHR system
- Data format mismatches
- Authentication problems with EHR APIs

**Diagnosis:**
```bash
# Test EHR connectivity
curl -s https://your-ehr-system.com/api/test | jq '.'

# Check data format compatibility
curl -s https://your-ehr-system.com/api/patients/PAT123/notes | jq '.'
```

**Solutions:**
1. **EHR Data Format Handling:**
   ```python
   def normalize_ehr_data(ehr_data):
       """Normalize different EHR data formats"""
       normalized_notes = []

       # Handle Epic format
       if 'notes' in ehr_data:
           for note in ehr_data['notes']:
               if 'clinical_text' in note:
                   normalized_notes.append(note['clinical_text'])
               elif 'note_text' in note:
                   normalized_notes.append(note['note_text'])

       # Handle Cerner format
       elif 'clinical_notes' in ehr_data:
           for note in ehr_data['clinical_notes']:
               if 'content' in note:
                   normalized_notes.append(note['content'])

       # Handle generic format
       else:
           # Try to extract text from any string fields
           for key, value in ehr_data.items():
               if isinstance(value, str) and len(value) > 50:
                   normalized_notes.append(value)
               elif isinstance(value, list):
                   for item in value:
                       if isinstance(item, str) and len(item) > 50:
                           normalized_notes.append(item)

       return normalized_notes
   ```

2. **EHR Authentication:**
   ```python
   class EHRAuthenticator:
       def __init__(self, ehr_base_url: str, credentials: dict):
           self.ehr_base_url = ehr_base_url
           self.credentials = credentials
           self.session = requests.Session()

       def authenticate_epic(self):
           """Authenticate with Epic EHR"""
           auth_url = f"{self.ehr_base_url}/api/oauth/token"

           auth_data = {
               'grant_type': 'client_credentials',
               'client_id': self.credentials['client_id'],
               'client_secret': self.credentials['client_secret']
           }

           response = self.session.post(auth_url, data=auth_data)
           response.raise_for_status()

           tokens = response.json()
           self.session.headers.update({
               'Authorization': f"Bearer {tokens['access_token']}"
           })

           return tokens

       def authenticate_cerner(self):
           """Authenticate with Cerner EHR"""
           # Cerner-specific authentication logic
           pass
   ```

### Performance Optimization

#### Client-Side Optimizations
```python
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor

class OptimizedClinicalBERTClient:
    def __init__(self, base_url: str, api_key: str = None):
        self.base_url = base_url
        self.api_key = api_key
        self.session = requests.Session()

        # Optimize connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=20,
            pool_maxsize=50,
            max_retries=3
        )
        self.session.mount("https://", adapter)

        if api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {api_key}'
            })

    async def predict_async(self, sentence: str) -> dict:
        """Async prediction for high throughput"""
        async with aiohttp.ClientSession() as session:
            headers = {'Authorization': f'Bearer {self.api_key}'} if self.api_key else {}
            async with session.post(
                f"{self.base_url}/predict",
                json={"sentence": sentence},
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                return await response.json()

    def predict_parallel(self, sentences: List[str], max_workers: int = 10) -> List[dict]:
        """Parallel prediction using ThreadPoolExecutor"""
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(self.predict, sentences))
        return results

    def predict_batch_optimized(self, sentences: List[str]) -> dict:
        """Optimized batch prediction with error handling"""
        # Split into optimal batch sizes
        optimal_batch_size = 20
        all_results = []

        for i in range(0, len(sentences), optimal_batch_size):
            batch = sentences[i:i + optimal_batch_size]

            try:
                result = self.predict_batch(batch)
                all_results.extend(result['predictions'])

                # Small delay to prevent overwhelming the service
                time.sleep(0.05)

            except Exception as e:
                print(f"Batch {i//optimal_batch_size} failed: {e}")
                # Fallback to individual processing
                for sentence in batch:
                    try:
                        individual_result = self.predict(sentence)
                        all_results.append(individual_result)
                    except Exception as inner_e:
                        print(f"Individual processing failed: {inner_e}")

        return {"predictions": all_results, "total_processed": len(all_results)}
```

#### Monitoring Your Usage
```python
import time
from collections import defaultdict

class UsageMonitor:
    def __init__(self):
        self.metrics = defaultdict(int)
        self.start_time = time.time()

    def track_request(self, endpoint: str, response_time: float, status_code: int):
        """Track API usage metrics"""
        self.metrics['total_requests'] += 1
        self.metrics[f'{endpoint}_requests'] += 1
        self.metrics['total_response_time'] += response_time
        self.metrics[f'{status_code}_responses'] += 1

        if status_code >= 400:
            self.metrics['error_requests'] += 1

    def get_summary(self) -> dict:
        """Get usage summary"""
        uptime = time.time() - self.start_time
        total_requests = self.metrics['total_requests']
        avg_response_time = (
            self.metrics['total_response_time'] / total_requests
            if total_requests > 0 else 0
        )
        error_rate = (
            self.metrics['error_requests'] / total_requests * 100
            if total_requests > 0 else 0
        )

        return {
            'uptime_seconds': uptime,
            'total_requests': total_requests,
            'avg_response_time_ms': avg_response_time * 1000,
            'error_rate_percent': error_rate,
            'requests_per_second': total_requests / uptime if uptime > 0 else 0,
            'endpoint_breakdown': {
                k: v for k, v in self.metrics.items()
                if k.endswith('_requests') and k != 'total_requests'
            }
        }

# Usage
monitor = UsageMonitor()

def monitored_predict(client, sentence):
    start_time = time.time()
    try:
        result = client.predict(sentence)
        response_time = time.time() - start_time
        monitor.track_request('/predict', response_time, 200)
        return result
    except Exception as e:
        response_time = time.time() - start_time
        monitor.track_request('/predict', response_time, 500)
        raise

# Monitor your usage
result = monitored_predict(client, "Patient reports chest pain.")
summary = monitor.get_summary()
print(f"Usage Summary: {summary}")
```

### Getting Additional Help

#### Debug Information Checklist
When reporting issues, please include:

1. **Service Health Status:**
   ```bash
   curl -s https://your-service-url/health | jq '.'
   ```

2. **Request Details:**
   ```bash
   curl -v https://your-service-url/predict \
     -H "Content-Type: application/json" \
     -d '{"sentence": "test"}' 2>&1 | head -20
   ```

3. **Client Information:**
   - Programming language and version
   - HTTP client library and version
   - Network environment (VPN, proxy, etc.)

4. **Error Details:**
   - Full error message and stack trace
   - Request ID from error response
   - Timestamp when error occurred

#### Support Request Template
```
**Issue Description:**
[Brief description of the problem]

**Environment:**
- API Endpoint: [URL]
- Client Language: [Python/JavaScript/etc.]
- Client Version: [version]
- Network: [direct/VPN/proxy]

**Steps to Reproduce:**
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Expected Behavior:**
[What should happen]

**Actual Behavior:**
[What actually happens]

**Debug Information:**
[Include health check, request details, error messages]

**Request ID:**
[From error response, if available]
```

### Support Channels
- **Documentation**: This comprehensive API guide
- **GitHub Issues**: Bug reports and feature requests
- **Email Support**: enterprise-support@yourcompany.com
- **Response SLA**: <4 hours for production issues
- **Emergency Support**: +1-800-EMERGENCY (24/7 for critical issues)

---

**Clinical AI • Production Ready • Enterprise Secure**

*Complete API documentation for healthcare AI integration*
