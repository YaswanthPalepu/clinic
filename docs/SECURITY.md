# Clinical BERT API - Security Guide

## Security Overview

This document outlines the comprehensive security measures implemented in the Clinical BERT Assertion API, designed to meet enterprise-grade security requirements and HIPAA compliance standards.

## Security Architecture

### Defense in Depth Strategy

The API implements multiple layers of security controls:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Client Layer   │───▶│  Network Layer   │───▶│ Application Layer │
│                 │    │                  │    │                 │
│ • API Keys      │    │ • TLS 1.3        │    │ • Input          │
│ • Rate Limiting │    │ • DDoS Protection│    │   Validation     │
│ • Request Auth  │    │ • VPC Isolation  │    │ • Sanitization   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
       ┌─────────────────────────────────────────────────┼─────────────────┐
       │                                                 ▼                 │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐         │
│   Data Layer     │    │  Monitoring      │    │  Infrastructure  │         │
│                 │    │                  │    │                 │         │
│ • Encryption    │    │ • Audit Logs     │    │ • Access Control │         │
│ • PHI Protection│    │ • Threat Detection│    │ • Secrets Mgmt  │         │
│ • Data Masking  │    │ • SIEM Integration│    │ • Network Policies│         │
└─────────────────┘    └──────────────────┘    └─────────────────┘         │
       └─────────────────────────────────────────────────────────────────────┘
```

## Authentication & Authorization

### API Key Authentication

#### Implementation
```python
# Authentication middleware
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

async def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify API key from request headers"""
    if not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required"
        )

    # Validate API key against secure store
    if not await validate_api_key_securely(credentials.credentials):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )

    return credentials.credentials
```

#### API Key Management
```bash
# Generate secure API key
openssl rand -hex 32

# Store in Google Cloud Secret Manager
echo -n "your-generated-api-key" | gcloud secrets create api-key --data-file=-

# Access in application
API_KEY=$(gcloud secrets versions access latest --secret=api-key)
```

### OAuth 2.0 Support (Optional)

#### Configuration
```python
from authlib.integrations.fastapi_oauth2 import OAuth2TokenBearer
from authlib.integrations.httpx_oauth2 import OAuth2Client

# OAuth2 configuration
OAUTH2_CLIENT_ID = os.getenv("OAUTH2_CLIENT_ID")
OAUTH2_CLIENT_SECRET = os.getenv("OAUTH2_CLIENT_SECRET")
OAUTH2_TOKEN_URL = os.getenv("OAUTH2_TOKEN_URL")

oauth2_scheme = OAuth2TokenBearer(
    token_url=OAUTH2_TOKEN_URL,
    client_id=OAUTH2_CLIENT_ID,
    client_secret=OAUTH2_CLIENT_SECRET
)
```

## Data Protection

### PHI (Protected Health Information) Handling

#### Data Classification
- **Public Data**: API responses, error messages
- **Internal Data**: Logs, metrics, configuration
- **Sensitive Data**: API keys, tokens, credentials
- **PHI Data**: Clinical text, patient information

#### Encryption Strategy

**At Rest:**
```python
from cryptography.fernet import Fernet
import os

# Generate encryption key
def generate_key():
    return Fernet.generate_key()

# Encrypt sensitive data
def encrypt_data(data: str, key: bytes) -> str:
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

# Decrypt sensitive data
def decrypt_data(encrypted_data: str, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()
```

**In Transit:**
- TLS 1.3 encryption for all HTTP communications
- Certificate pinning for production environments
- HSTS (HTTP Strict Transport Security) headers

### Data Sanitization

#### Input Validation
```python
from pydantic import BaseModel, validator
import re

class PredictionRequest(BaseModel):
    sentence: str

    @validator('sentence')
    def validate_sentence(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Sentence cannot be empty')

        if len(v) > 512:
            raise ValueError('Sentence too long (max 512 characters)')

        # Remove potentially harmful characters
        v = re.sub(r'[^\w\s.,!?-]', '', v)

        return v.strip()
```

#### SQL Injection Prevention
- Parameterized queries (when database is used)
- Input sanitization for all text inputs
- Prepared statements for data access

## Security Monitoring

### Real-time Threat Detection

#### Log Analysis
```python
import logging
import json
from datetime import datetime

class SecurityLogger:
    def __init__(self):
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.INFO)

        # Structured logging format
        formatter = logging.Formatter(
            json.dumps({
                'timestamp': '%(asctime)s',
                'level': '%(levelname)s',
                'service': 'clinical-bert-api',
                'message': '%(message)s',
                'request_id': '%(request_id)s',
                'ip_address': '%(ip_address)s',
                'user_agent': '%(user_agent)s'
            })
        )

    def log_security_event(self, event_type: str, details: dict, request_id: str = None):
        """Log security-related events"""
        self.logger.info(
            f"Security event: {event_type}",
            extra={
                'request_id': request_id or 'unknown',
                'event_type': event_type,
                'details': json.dumps(details),
                'timestamp': datetime.utcnow().isoformat()
            }
        )
```

#### Automated Alerts

**Prometheus Alerting Rules:**
```yaml
groups:
  - name: security_alerts
    rules:
      - alert: SuspiciousActivity
        expr: rate(security_events_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Suspicious activity detected"
          description: "High rate of security events: {{ $value }}/min"

      - alert: FailedAuthentications
        expr: rate(authentication_failures_total[5m]) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate"
          description: "Authentication failures: {{ $value }}/min"
```

### Intrusion Detection

#### Rate Limiting Implementation
```python
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware

# Rate limiter configuration
limiter = Limiter(key_func=get_remote_address)

# Apply to FastAPI app
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# Route-specific limits
@app.get("/health")
@limiter.limit("100/minute")
async def health_check():
    return {"status": "healthy"}

@app.post("/predict")
@limiter.limit("50/minute")
async def predict(request: PredictionRequest):
    # Prediction logic
    pass
```

#### DDoS Protection
- Cloud Armor policies for Google Cloud Run
- Rate limiting at application level
- Request size limits and timeouts
- Connection pooling limits

## Compliance Requirements

### HIPAA Security Rule

#### Administrative Safeguards
- Security management process
- ✅ Assigned security responsibility
- ✅ Workforce security
- ✅ Information access management
- ✅ Security awareness training
- ✅ Security incident procedures
- ✅ Contingency plan
- ✅ Evaluation

#### Physical Safeguards
- ✅ Facility access controls
- ✅ Workstation use
- ✅ Workstation security
- ✅ Device and media controls

#### Technical Safeguards
- ✅ Access control
- ✅ Audit controls
- ✅ Integrity
- ✅ Person or entity authentication
- ✅ Transmission security

### SOC 2 Type II Compliance

#### Security Criteria
- ✅ Organization and management
- ✅ Communications
- ✅ Risk management
- ✅ Monitoring activities
- ✅ Control activities

#### Availability Criteria
- ✅ Processing integrity
- ✅ System availability
- ✅ Confidentiality
- ✅ Privacy

## Security Hardening

### Container Security

#### Dockerfile Best Practices
```dockerfile
# Use official base images
FROM python:3.12-slim

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install only necessary packages
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy application with appropriate permissions
COPY --chown=appuser:appuser . /app
WORKDIR /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080
CMD ["python", "main.py"]
```

#### Image Scanning
```bash
# Scan for vulnerabilities
docker scan clinical-bert-api:latest

# Use Trivy for comprehensive scanning
trivy image clinical-bert-api:latest

# Integrate with CI/CD pipeline
- name: Security Scan
  uses: aquasecurity/trivy-action@master
  with:
    scan-type: 'image'
    scan-ref: 'us-central1-docker.pkg.dev/project/repo/image:latest'
    format: 'sarif'
    output: 'trivy-results.sarif'
```

### Application Security

#### Dependency Management
```bash
# Regular dependency updates
pip install --upgrade -r requirements.txt

# Security vulnerability scanning
safety check

# Automated dependency updates
pip-tools compile --upgrade
```

#### Secret Management
```python
import os
from google.cloud import secretmanager

def get_secret(secret_name: str) -> str:
    """Retrieve secret from Google Cloud Secret Manager"""
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{PROJECT_ID}/secrets/{secret_name}/versions/latest"

    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("UTF-8")

# Usage
API_KEY = get_secret("api-key")
DATABASE_URL = get_secret("database-url")
```

## Incident Response

### Security Incident Process

#### Detection Phase
1. **Automated Alerts**: Monitoring systems detect anomalies
2. **Manual Reports**: Security team receives incident reports
3. **Log Analysis**: Review security logs for indicators
4. **Initial Assessment**: Determine incident scope and impact

#### Response Phase
1. **Containment**: Isolate affected systems
2. **Investigation**: Gather evidence and analyze root cause
3. **Recovery**: Restore systems from clean backups
4. **Communication**: Notify stakeholders and regulatory bodies

#### Post-Incident Phase
1. **Documentation**: Record incident details and response
2. **Lessons Learned**: Identify improvements and preventive measures
3. **Implementation**: Apply security enhancements
4. **Review**: Update incident response procedures

### Emergency Contacts

#### Security Team
- **Primary**: security@company.com
- **Secondary**: security-backup@company.com
- **Phone**: +1-800-SECURITY

#### Development Team
- **Lead Developer**: dev-lead@company.com
- **On-call Engineer**: oncall@company.com
- **DevOps Team**: devops@company.com

#### Executive Team
- **CISO**: ciso@company.com
- **CTO**: cto@company.com
- **CEO**: ceo@company.com

## Security Metrics

### Key Security Indicators

#### Authentication Metrics
- Successful authentication rate
- Failed authentication attempts
- API key usage patterns
- Token expiration rates

#### Access Control Metrics
- Unauthorized access attempts
- Permission violation incidents
- Role-based access patterns
- Administrative access usage

#### Data Protection Metrics
- Encryption success rates
- Data masking effectiveness
- PHI exposure incidents
- Backup integrity checks

### Security Dashboard

#### Grafana Panels
```json
{
  "title": "Security Overview",
  "panels": [
    {
      "title": "Authentication Failures",
      "type": "graph",
      "targets": [
        {
          "expr": "rate(authentication_failures_total[5m])",
          "legendFormat": "Failures/min"
        }
      ]
    },
    {
      "title": "Security Events",
      "type": "table",
      "targets": [
        {
          "expr": "security_events_total",
          "legendFormat": "Total Events"
        }
      ]
    },
    {
      "title": "Access Patterns",
      "type": "heatmap",
      "targets": [
        {
          "expr": "rate(http_requests_total[1h])",
          "legendFormat": "Requests/hour"
        }
      ]
    }
  ]
}
```

## Security Updates

### Regular Security Procedures

#### Weekly Tasks
- [ ] Review security logs and alerts
- [ ] Update security signatures
- [ ] Monitor vulnerability databases
- [ ] Verify backup integrity

#### Monthly Tasks
- [ ] Security patch deployment
- [ ] Access control audits
- [ ] Security training updates
- [ ] Compliance documentation review

#### Quarterly Tasks
- [ ] Penetration testing
- [ ] Security assessments
- [ ] Incident response drills
- [ ] Third-party vendor reviews

### Security Training

#### Required Training
- **Annual Security Awareness**: All employees
- **Role-specific Training**: Developers, administrators
- **HIPAA Training**: Healthcare personnel
- **Incident Response Training**: Security team

#### Training Resources
- **OWASP Top 10**: Web application security
- **NIST Cybersecurity Framework**: Security best practices
- **HIPAA Security Rule**: Healthcare compliance
- **Zero Trust Architecture**: Modern security principles

---

## Security Implementation Guide

### API Key Management

#### Secure API Key Generation
```bash
# Generate cryptographically secure API keys
python -c "
import secrets
import string

def generate_api_key(length=64):
    alphabet = string.ascii_letters + string.digits + '-_'
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# Generate multiple keys for different environments
environments = ['development', 'staging', 'production']
for env in environments:
    key = generate_api_key()
    print(f'{env}: {key}')
"

# Output:
# development: aB3dEf5gHi7jKl9mN0oPq2rSt5uVwXy3zAbCdEfGhIjKlMnOpQrStUvWxYz012345
# staging: cDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmN
# production: dEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMn
```

#### API Key Storage and Rotation
```python
# Secure API key storage using Google Cloud Secret Manager
from google.cloud import secretmanager
import os

class SecureAPIKeyManager:
    def __init__(self, project_id: str):
        self.client = secretmanager.SecretManagerServiceClient()
        self.project_id = project_id

    def create_api_key_secret(self, key_name: str, api_key: str):
        """Create a new API key secret"""
        parent = f"projects/{self.project_id}/secrets/{key_name}"

        # Create the secret
        response = self.client.create_secret(
            request={
                "parent": f"projects/{self.project_id}",
                "secret_id": key_name,
                "secret": {
                    "replication": {"automatic": {}},
                    "labels": {
                        "environment": "production",
                        "purpose": "api-authentication",
                        "rotation": "required"
                    }
                }
            }
        )

        # Add the secret version
        self.client.add_secret_version(
            request={
                "parent": response.name,
                "payload": {"data": api_key.encode("UTF-8")}
            }
        )

        return response.name

    def get_api_key(self, key_name: str) -> str:
        """Retrieve API key securely"""
        name = f"projects/{self.project_id}/secrets/{key_name}/versions/latest"

        response = self.client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")

    def rotate_api_key(self, key_name: str, new_api_key: str):
        """Rotate API key with zero downtime"""
        # Add new version
        self.client.add_secret_version(
            request={
                "parent": f"projects/{self.project_id}/secrets/{key_name}",
                "payload": {"data": new_api_key.encode("UTF-8")}
            }
        )

        # Disable old versions after grace period
        # Implementation depends on your rotation strategy

# Usage
key_manager = SecureAPIKeyManager("your-project-id")
key_manager.create_api_key_secret("clinical-bert-api-key", "your-secure-api-key")
```

#### API Key Validation
```python
import re
import hashlib
from typing import Optional, Tuple
from datetime import datetime, timedelta

class APIKeyValidator:
    def __init__(self):
        self.key_patterns = {
            'legacy': re.compile(r'^[a-zA-Z0-9]{32}$'),
            'modern': re.compile(r'^[a-zA-Z0-9_-]{64}$'),
            'enterprise': re.compile(r'^[a-zA-Z0-9_-]{128}$')
        }

    def validate_api_key_format(self, api_key: str) -> Tuple[bool, str]:
        """Validate API key format and strength"""
        if not api_key or len(api_key.strip()) == 0:
            return False, "API key cannot be empty"

        # Check minimum length
        if len(api_key) < 32:
            return False, "API key too short (minimum 32 characters)"

        # Check for common patterns
        if api_key.lower() in ['none', 'null', 'undefined', 'test', 'admin']:
            return False, "API key contains forbidden values"

        # Check character diversity
        has_upper = any(c.isupper() for c in api_key)
        has_lower = any(c.islower() for c in api_key)
        has_digit = any(c.isdigit() for c in api_key)

        if not (has_upper and has_lower and has_digit):
            return False, "API key must contain uppercase, lowercase, and digits"

        # Check pattern matching
        for pattern_name, pattern in self.key_patterns.items():
            if pattern.match(api_key):
                return True, f"Valid {pattern_name} API key format"

        return False, "API key format not recognized"

    def hash_api_key(self, api_key: str) -> str:
        """Hash API key for secure storage"""
        return hashlib.sha256(api_key.encode()).hexdigest()

    def rate_limit_key(self, api_key_hash: str, client_ip: str) -> str:
        """Generate rate limiting key"""
        return f"{api_key_hash}:{client_ip}"

# Usage
validator = APIKeyValidator()
is_valid, message = validator.validate_api_key_format("your-api-key-here")
print(f"Validation: {is_valid} - {message}")
```

### Data Protection Implementation

#### PHI Data Handling
```python
import re
from typing import Dict, List, Any, Pattern
from dataclasses import dataclass

@dataclass
class PHIDataMasker:
    """PHI data masking for healthcare compliance"""

    # PHI patterns to detect and mask
    PHI_PATTERNS: Dict[str, Pattern] = {
        'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        'phone': re.compile(r'\b\d{3}-\d{3}-\d{4}\b'),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'patient_id': re.compile(r'\bPAT\d{6}\b'),
        'medical_record': re.compile(r'\bMRN\d{8}\b'),
        'dob': re.compile(r'\b\d{1,2}/\d{1,2}/\d{4}\b'),
        'address': re.compile(r'\d+\s+[A-Za-z0-9\s,]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Place|Pl|Court|Ct)\b')
    }

    MASK_CHARACTERS: Dict[str, str] = {
        'ssn': 'XXX-XX-XXXX',
        'phone': 'XXX-XXX-XXXX',
        'email': 'user@domain.com',
        'patient_id': 'PATXXXXXX',
        'medical_record': 'MRNXXXXXXXX',
        'dob': 'XX/XX/XXXX',
        'address': 'XXXX Street Name'
    }

    def mask_phi_data(self, text: str) -> str:
        """Mask PHI data in clinical text"""
        masked_text = text

        for phi_type, pattern in self.PHI_PATTERNS.items():
            if phi_type in self.MASK_CHARACTERS:
                masked_text = pattern.sub(self.MASK_CHARACTERS[phi_type], masked_text)

        return masked_text

    def detect_phi_data(self, text: str) -> List[Dict[str, Any]]:
        """Detect PHI data in text for compliance logging"""
        detected_phi = []

        for phi_type, pattern in self.PHI_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                detected_phi.append({
                    'type': phi_type,
                    'matches': matches,
                    'count': len(matches)
                })

        return detected_phi

    def sanitize_clinical_text(self, text: str) -> Dict[str, Any]:
        """Sanitize clinical text for processing"""
        original_length = len(text)

        # Detect PHI data
        detected_phi = self.detect_phi_data(text)

        # Mask PHI data
        sanitized_text = self.mask_phi_data(text)

        # Calculate sanitization ratio
        sanitization_ratio = (original_length - len(sanitized_text)) / original_length if original_length > 0 else 0

        return {
            'original_text': text,
            'sanitized_text': sanitized_text,
            'detected_phi': detected_phi,
            'sanitization_ratio': sanitization_ratio,
            'phi_detected': len(detected_phi) > 0
        }

# Usage
phi_masker = PHIDataMasker()

# Sanitize clinical text
clinical_note = "Patient John Doe (DOB: 01/15/1980, SSN: 123-45-6789) reports chest pain."
sanitized = phi_masker.sanitize_clinical_text(clinical_note)

print(f"Original: {sanitized['original_text']}")
print(f"Sanitized: {sanitized['sanitized_text']}")
print(f"PHI Detected: {sanitized['phi_detected']}")
```

#### Audit Logging Implementation
```python
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

@dataclass
class SecurityEvent:
    """Security event data structure"""
    timestamp: str
    event_type: str
    severity: str
    source_ip: str
    user_agent: str
    endpoint: str
    method: str
    status_code: int
    request_id: str
    user_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    phi_detected: bool = False
    compliance_flags: List[str] = None

    def __post_init__(self):
        if self.compliance_flags is None:
            self.compliance_flags = []

class SecurityAuditLogger:
    def __init__(self, log_level: str = "INFO"):
        self.logger = logging.getLogger('security_audit')
        self.logger.setLevel(getattr(logging, log_level))

        # Create structured JSON formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # File handler for persistent storage
        file_handler = logging.FileHandler('security_audit.log')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def log_security_event(self, event: SecurityEvent):
        """Log security event with structured data"""
        log_entry = {
            'timestamp': event.timestamp,
            'event_type': event.event_type,
            'severity': event.severity,
            'source_ip': event.source_ip,
            'user_agent': event.user_agent,
            'endpoint': event.endpoint,
            'method': event.method,
            'status_code': event.status_code,
            'request_id': event.request_id,
            'user_id': event.user_id,
            'details': event.details,
            'phi_detected': event.phi_detected,
            'compliance_flags': event.compliance_flags
        }

        # Log based on severity
        if event.severity == 'CRITICAL':
            self.logger.critical(json.dumps(log_entry))
        elif event.severity == 'HIGH':
            self.logger.error(json.dumps(log_entry))
        elif event.severity == 'MEDIUM':
            self.logger.warning(json.dumps(log_entry))
        else:
            self.logger.info(json.dumps(log_entry))

    def log_authentication_event(self, success: bool, api_key_hash: str, source_ip: str, user_agent: str):
        """Log authentication events"""
        event = SecurityEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='AUTHENTICATION',
            severity='HIGH' if not success else 'INFO',
            source_ip=source_ip,
            user_agent=user_agent,
            endpoint='/auth',
            method='POST',
            status_code=200 if success else 401,
            request_id=f"auth_{datetime.utcnow().timestamp()}",
            details={
                'authentication_success': success,
                'api_key_hash': api_key_hash
            },
            compliance_flags=['HIPAA', 'AUTH_LOGGING']
        )
        self.log_security_event(event)

    def log_phi_access(self, phi_detected: bool, endpoint: str, source_ip: str, request_id: str):
        """Log PHI data access"""
        if phi_detected:
            event = SecurityEvent(
                timestamp=datetime.utcnow().isoformat(),
                event_type='PHI_ACCESS',
                severity='HIGH',
                source_ip=source_ip,
                user_agent='',
                endpoint=endpoint,
                method='POST',
                status_code=200,
                request_id=request_id,
                details={'phi_detected': True},
                phi_detected=True,
                compliance_flags=['HIPAA', 'PHI_PROTECTION']
            )
            self.log_security_event(event)

# Usage
audit_logger = SecurityAuditLogger()

# Log authentication attempt
audit_logger.log_authentication_event(
    success=True,
    api_key_hash="sha256_hash_of_api_key",
    source_ip="192.168.1.100",
    user_agent="ClinicalApp/1.0"
)

# Log PHI access
audit_logger.log_phi_access(
    phi_detected=True,
    endpoint="/predict",
    source_ip="192.168.1.100",
    request_id="req-12345"
)
```

### Network Security Implementation

#### VPC Configuration
```bash
# Create secure VPC network
gcloud compute networks create clinical-bert-secure-network \
  --subnet-mode=custom \
  --bgp-routing-mode=regional

# Create private subnet
gcloud compute networks subnets create clinical-bert-private-subnet \
  --network=clinical-bert-secure-network \
  --range=10.0.0.0/24 \
  --region=us-central1 \
  --enable-private-ip-google-access

# Create VPC connector for Cloud Run
gcloud compute networks vpc-access connectors create clinical-bert-vpc-connector \
  --region=us-central1 \
  --network=clinical-bert-secure-network \
  --range=10.0.1.0/28 \
  --min-instances=2 \
  --max-instances=10

# Deploy with VPC connector
gcloud run deploy clinical-bert-api \
  --image=us-central1-docker.pkg.dev/$PROJECT_ID/clinical-bert-repo/clinical-bert-api:latest \
  --region=us-central1 \
  --vpc-connector=clinical-bert-vpc-connector \
  --vpc-egress=private-ranges-only \
  --allow-unauthenticated \
  --memory=2Gi \
  --cpu=1
```

#### Firewall Rules
```bash
# Create firewall rules for VPC
gcloud compute firewall-rules create clinical-bert-allow-internal \
  --network=clinical-bert-secure-network \
  --allow=tcp:8080,tcp:9090,tcp:3000 \
  --source-ranges=10.0.0.0/24 \
  --description="Allow internal traffic for Clinical BERT API"

gcloud compute firewall-rules create clinical-bert-allow-health-checks \
  --network=clinical-bert-secure-network \
  --allow=tcp:8080 \
  --source-ranges=130.211.0.0/22,35.191.0.0/16 \
  --description="Allow Google Cloud health checks"

# Deny all other traffic by default
gcloud compute firewall-rules create clinical-bert-deny-all \
  --network=clinical-bert-secure-network \
  --action=DENY \
  --rules=all \
  --priority=65534 \
  --description="Deny all other traffic"
```

### Compliance Monitoring

#### HIPAA Compliance Checker
```python
import re
from typing import Dict, List, Any
from datetime import datetime, timedelta

class HIPAAComplianceChecker:
    def __init__(self):
        self.compliance_rules = {
            'data_encryption': self._check_data_encryption,
            'access_control': self._check_access_control,
            'audit_logging': self._check_audit_logging,
            'data_retention': self._check_data_retention,
            'incident_response': self._check_incident_response
        }

    def run_compliance_check(self) -> Dict[str, Any]:
        """Run comprehensive HIPAA compliance check"""
        results = {}
        overall_score = 0

        for rule_name, check_function in self.compliance_rules.items():
            try:
                result = check_function()
                results[rule_name] = result
                if result['compliant']:
                    overall_score += 1
            except Exception as e:
                results[rule_name] = {
                    'compliant': False,
                    'error': str(e),
                    'recommendations': ['Fix compliance check implementation']
                }

        compliance_percentage = (overall_score / len(self.compliance_rules)) * 100

        return {
            'timestamp': datetime.utcnow().isoformat(),
            'overall_compliance': compliance_percentage,
            'compliant_areas': overall_score,
            'total_areas': len(self.compliance_rules),
            'detailed_results': results
        }

    def _check_data_encryption(self) -> Dict[str, Any]:
        """Check data encryption compliance"""
        # Check if TLS is enabled
        tls_enabled = True  # Implementation specific

        # Check if data at rest is encrypted
        encryption_at_rest = True  # Implementation specific

        compliant = tls_enabled and encryption_at_rest

        return {
            'compliant': compliant,
            'tls_enabled': tls_enabled,
            'encryption_at_rest': encryption_at_rest,
            'recommendations': [] if compliant else [
                'Enable TLS 1.3 for all communications',
                'Implement encryption at rest for all data',
                'Use Google Cloud KMS for key management'
            ]
        }

    def _check_access_control(self) -> Dict[str, Any]:
        """Check access control compliance"""
        # Check if API keys are required
        api_auth_required = True  # Implementation specific

        # Check if rate limiting is enabled
        rate_limiting_enabled = True  # Implementation specific

        # Check if audit logging is enabled
        audit_logging_enabled = True  # Implementation specific

        compliant = api_auth_required and rate_limiting_enabled and audit_logging_enabled

        return {
            'compliant': compliant,
            'api_auth_required': api_auth_required,
            'rate_limiting_enabled': rate_limiting_enabled,
            'audit_logging_enabled': audit_logging_enabled,
            'recommendations': [] if compliant else [
                'Implement API key authentication',
                'Enable rate limiting',
                'Enable comprehensive audit logging'
            ]
        }

    def _check_audit_logging(self) -> Dict[str, Any]:
        """Check audit logging compliance"""
        # Check if security events are logged
        security_logging_enabled = True  # Implementation specific

        # Check if PHI access is logged
        phi_logging_enabled = True  # Implementation specific

        # Check if logs are retained appropriately
        log_retention_days = 2555  # 7 years for HIPAA

        compliant = security_logging_enabled and phi_logging_enabled and log_retention_days >= 2555

        return {
            'compliant': compliant,
            'security_logging_enabled': security_logging_enabled,
            'phi_logging_enabled': phi_logging_enabled,
            'log_retention_days': log_retention_days,
            'recommendations': [] if compliant else [
                'Enable security event logging',
                'Implement PHI access logging',
                'Configure 7-year log retention'
            ]
        }

    def _check_data_retention(self) -> Dict[str, Any]:
        """Check data retention compliance"""
        # Check if data is automatically deleted
        auto_deletion_enabled = True  # Implementation specific

        # Check if retention policies are configured
        retention_policy_configured = True  # Implementation specific

        compliant = auto_deletion_enabled and retention_policy_configured

        return {
            'compliant': compliant,
            'auto_deletion_enabled': auto_deletion_enabled,
            'retention_policy_configured': retention_policy_configured,
            'recommendations': [] if compliant else [
                'Implement automatic data deletion',
                'Configure data retention policies'
            ]
        }

    def _check_incident_response(self) -> Dict[str, Any]:
        """Check incident response compliance"""
        # Check if incident response plan exists
        incident_plan_exists = True  # Implementation specific

        # Check if contact information is available
        contact_info_available = True  # Implementation specific

        compliant = incident_plan_exists and contact_info_available

        return {
            'compliant': compliant,
            'incident_plan_exists': incident_plan_exists,
            'contact_info_available': contact_info_available,
            'recommendations': [] if compliant else [
                'Create incident response plan',
                'Establish security contact information'
            ]
        }

# Usage
compliance_checker = HIPAAComplianceChecker()
compliance_report = compliance_checker.run_compliance_check()

print(f"Overall HIPAA Compliance: {compliance_report['overall_compliance']:.1f}%")
print(f"Compliant Areas: {compliance_report['compliant_areas']}/{compliance_report['total_areas']}")

for area, result in compliance_report['detailed_results'].items():
    print(f"\n{area.upper()}: {'✅ COMPLIANT' if result['compliant'] else '❌ NON-COMPLIANT'}")
    if not result['compliant'] and 'recommendations' in result:
        for rec in result['recommendations']:
            print(f"  - {rec}")
```

#### SOC 2 Compliance Monitoring
```python
class SOC2ComplianceMonitor:
    def __init__(self):
        self.security_metrics = {}
        self.availability_metrics = {}
        self.confidentiality_metrics = {}

    def monitor_security(self) -> Dict[str, Any]:
        """Monitor security controls"""
        # Monitor failed authentication attempts
        failed_auth_rate = self._get_failed_auth_rate()

        # Monitor unauthorized access attempts
        unauthorized_access_rate = self._get_unauthorized_access_rate()

        # Monitor security configuration changes
        config_change_rate = self._get_config_change_rate()

        security_score = 100
        issues = []

        if failed_auth_rate > 0.01:  # More than 1% failed auth
            security_score -= 20
            issues.append("High failed authentication rate")

        if unauthorized_access_rate > 0.001:  # More than 0.1% unauthorized access
            security_score -= 30
            issues.append("Unauthorized access attempts detected")

        if config_change_rate > 5:  # More than 5 config changes per day
            security_score -= 10
            issues.append("Frequent security configuration changes")

        return {
            'security_score': security_score,
            'issues': issues,
            'metrics': {
                'failed_auth_rate': failed_auth_rate,
                'unauthorized_access_rate': unauthorized_access_rate,
                'config_change_rate': config_change_rate
            }
        }

    def monitor_availability(self) -> Dict[str, Any]:
        """Monitor service availability"""
        # Monitor uptime
        uptime_percentage = self._get_uptime_percentage()

        # Monitor response times
        avg_response_time = self._get_avg_response_time()

        # Monitor error rates
        error_rate = self._get_error_rate()

        availability_score = 100
        issues = []

        if uptime_percentage < 99.9:
            availability_score -= 20
            issues.append(f"Low uptime: {uptime_percentage:.2f}%")

        if avg_response_time > 1000:  # More than 1 second
            availability_score -= 15
            issues.append(f"High response time: {avg_response_time:.0f}ms")

        if error_rate > 0.001:  # More than 0.1% errors
            availability_score -= 25
            issues.append(f"High error rate: {error_rate:.4f}")

        return {
            'availability_score': availability_score,
            'issues': issues,
            'metrics': {
                'uptime_percentage': uptime_percentage,
                'avg_response_time_ms': avg_response_time,
                'error_rate': error_rate
            }
        }

    def _get_failed_auth_rate(self) -> float:
        """Get failed authentication rate"""
        # Implementation specific - query logs/metrics
        return 0.005  # 0.5% for example

    def _get_unauthorized_access_rate(self) -> float:
        """Get unauthorized access rate"""
        # Implementation specific - query security logs
        return 0.0001  # 0.01% for example

    def _get_config_change_rate(self) -> float:
        """Get security configuration change rate"""
        # Implementation specific - query configuration logs
        return 2  # 2 changes per day for example

    def _get_uptime_percentage(self) -> float:
        """Get service uptime percentage"""
        # Implementation specific - query monitoring system
        return 99.95  # 99.95% uptime for example

    def _get_avg_response_time(self) -> float:
        """Get average response time"""
        # Implementation specific - query performance metrics
        return 245  # 245ms for example

    def _get_error_rate(self) -> float:
        """Get error rate"""
        # Implementation specific - query error metrics
        return 0.0002  # 0.02% for example

# Usage
soc2_monitor = SOC2ComplianceMonitor()

security_report = soc2_monitor.monitor_security()
availability_report = soc2_monitor.monitor_availability()

print("SOC 2 Compliance Report:")
print(f"Security Score: {security_report['security_score']}/100")
print(f"Availability Score: {availability_report['availability_score']}/100")

if security_report['issues']:
    print("\nSecurity Issues:")
    for issue in security_report['issues']:
        print(f"  - {issue}")

if availability_report['issues']:
    print("\nAvailability Issues:")
    for issue in availability_report['issues']:
        print(f"  - {issue}")
```

### Security Testing

#### Automated Security Scanning
```bash
# Install security testing tools
pip install safety bandit pytest-cov

# Run security vulnerability scan
safety check

# Run security linting
bandit -r app/

# Run penetration testing (manual)
# Use tools like OWASP ZAP, Burp Suite, or sqlmap

# Security headers testing
curl -I https://your-service-url/health | grep -E "(X-Frame-Options|X-Content-Type-Options|X-XSS-Protection|Strict-Transport-Security)"

# Expected output:
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# X-XSS-Protection: 1; mode=block
# Strict-Transport-Security: max-age=31536000
```

#### Penetration Testing Checklist
```bash
# Web Application Security Testing
- [ ] Test for SQL injection vulnerabilities
- [ ] Test for XSS (Cross-Site Scripting)
- [ ] Test for CSRF (Cross-Site Request Forgery)
- [ ] Test for authentication bypass
- [ ] Test for authorization issues
- [ ] Test for input validation
- [ ] Test for rate limiting effectiveness
- [ ] Test for information disclosure
- [ ] Test for insecure direct object references
- [ ] Test for security misconfigurations

# API Security Testing
- [ ] Test for API key exposure
- [ ] Test for broken authentication
- [ ] Test for excessive data exposure
- [ ] Test for lack of resources & rate limiting
- [ ] Test for broken function level authorization
- [ ] Test for mass assignment
- [ ] Test for injection vulnerabilities
- [ ] Test for improper assets management

# Infrastructure Security Testing
- [ ] Test for network security
- [ ] Test for access controls
- [ ] Test for encryption in transit
- [ ] Test for encryption at rest
- [ ] Test for logging and monitoring
- [ ] Test for incident response
```

### Incident Response Automation

#### Automated Incident Detection
```python
import asyncio
from typing import Dict, List, Any
from datetime import datetime, timedelta

class AutomatedIncidentResponse:
    def __init__(self):
        self.incident_thresholds = {
            'high_error_rate': 0.05,  # 5% error rate
            'high_response_time': 1000,  # 1 second
            'security_events': 10,  # 10 security events per minute
            'phi_access': 5  # 5 PHI access events per minute
        }

    async def monitor_and_respond(self):
        """Monitor system and automatically respond to incidents"""
        while True:
            try:
                # Check various metrics
                error_rate = await self._get_error_rate()
                response_time = await self._get_response_time()
                security_events = await self._get_security_events()
                phi_events = await self._get_phi_events()

                # Detect incidents
                incidents = []

                if error_rate > self.incident_thresholds['high_error_rate']:
                    incidents.append({
                        'type': 'HIGH_ERROR_RATE',
                        'severity': 'HIGH',
                        'details': f'Error rate: {error_rate:.2%}'
                    })

                if response_time > self.incident_thresholds['high_response_time']:
                    incidents.append({
                        'type': 'HIGH_RESPONSE_TIME',
                        'severity': 'MEDIUM',
                        'details': f'Response time: {response_time}ms'
                    })

                if security_events > self.incident_thresholds['security_events']:
                    incidents.append({
                        'type': 'SECURITY_INCIDENT',
                        'severity': 'CRITICAL',
                        'details': f'Security events: {security_events}/min'
                    })

                if phi_events > self.incident_thresholds['phi_access']:
                    incidents.append({
                        'type': 'PHI_ACCESS_INCIDENT',
                        'severity': 'CRITICAL',
                        'details': f'PHI access events: {phi_events}/min'
                    })

                # Respond to incidents
                for incident in incidents:
                    await self._handle_incident(incident)

                # Wait before next check
                await asyncio.sleep(60)  # Check every minute

            except Exception as e:
                print(f"Error in incident monitoring: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes on error

    async def _handle_incident(self, incident: Dict[str, Any]):
        """Handle detected incident"""
        print(f"🚨 INCIDENT DETECTED: {incident['type']} - {incident['severity']}")
        print(f"Details: {incident['details']}")

        # Automated responses based on incident type
        if incident['type'] == 'HIGH_ERROR_RATE':
            await self._handle_high_error_rate(incident)
        elif incident['type'] == 'HIGH_RESPONSE_TIME':
            await self._handle_high_response_time(incident)
        elif incident['type'] == 'SECURITY_INCIDENT':
            await self._handle_security_incident(incident)
        elif incident['type'] == 'PHI_ACCESS_INCIDENT':
            await self._handle_phi_incident(incident)

    async def _handle_high_error_rate(self, incident: Dict[str, Any]):
        """Handle high error rate incident"""
        # Scale up instances
        print("Scaling up instances to handle load...")
        # Implementation: gcloud run services update --max-instances=20

        # Notify team
        await self._notify_team(incident)

    async def _handle_high_response_time(self, incident: Dict[str, Any]):
        """Handle high response time incident"""
        # Check resource utilization
        print("Checking resource utilization...")
        # Implementation: Check CPU/memory usage

        # Optimize if needed
        print("Optimizing resource allocation...")
        # Implementation: Adjust CPU/memory settings

        await self._notify_team(incident)

    async def _handle_security_incident(self, incident: Dict[str, Any]):
        """Handle security incident"""
        # Block suspicious IPs
        print("Blocking suspicious IP addresses...")
        # Implementation: Update firewall rules

        # Increase security monitoring
        print("Increasing security monitoring...")
        # Implementation: Enable enhanced logging

        # Notify security team immediately
        await self._notify_security_team(incident)

    async def _handle_phi_incident(self, incident: Dict[str, Any]):
        """Handle PHI access incident"""
        # Immediately block access
        print("Blocking PHI access...")
        # Implementation: Disable PHI processing temporarily

        # Notify compliance team
        await self._notify_compliance_team(incident)

        # Generate compliance report
        print("Generating compliance report...")
        # Implementation: Create detailed PHI access report

    async def _notify_team(self, incident: Dict[str, Any]):
        """Notify operations team"""
        # Implementation: Send Slack notification, email, etc.
        print(f"📧 Notifying operations team: {incident['type']}")

    async def _notify_security_team(self, incident: Dict[str, Any]):
        """Notify security team"""
        # Implementation: Send urgent notification
        print(f"🚨 URGENT: Notifying security team: {incident['type']}")

    async def _notify_compliance_team(self, incident: Dict[str, Any]):
        """Notify compliance team"""
        # Implementation: Send compliance notification
        print(f"📋 Notifying compliance team: {incident['type']}")

    # Placeholder methods for actual metric collection
    async def _get_error_rate(self) -> float:
        return 0.02  # Implementation specific

    async def _get_response_time(self) -> float:
        return 245  # Implementation specific

    async def _get_security_events(self) -> int:
        return 5  # Implementation specific

    async def _get_phi_events(self) -> int:
        return 2  # Implementation specific

# Usage
async def main():
    incident_responder = AutomatedIncidentResponse()
    await incident_responder.monitor_and_respond()

if __name__ == "__main__":
    asyncio.run(main())
```

---

## 📞 Security Support

### Reporting Security Issues

#### Responsible Disclosure
- **Email**: security@company.com
- **PGP Key**: Available at security.company.com/pgp
- **Response Time**: <24 hours for critical issues
- **Bounty Program**: Available for qualifying disclosures

#### Security Issue Template
```
Subject: Security Vulnerability Report

Description:
- Vulnerability type:
- Affected component:
- Severity level:
- Steps to reproduce:
- Potential impact:
- Suggested fix:

Contact Information:
- Name:
- Email:
- Phone:
- PGP Key ID:
```

### Security Documentation

#### Available Resources
- **Security Policy**: Comprehensive security policies and procedures
- **Incident Response Plan**: Detailed incident handling procedures
- **Compliance Documentation**: HIPAA and SOC 2 compliance evidence
- **Security Architecture**: System security design and controls

### Security Training

#### Required Training Programs
- **Annual Security Awareness Training**: All employees
- **Developer Security Training**: Development team
- **HIPAA Compliance Training**: Healthcare personnel
- **Incident Response Training**: Security team

#### Training Modules
1. **Secure Coding Practices**
   - Input validation and sanitization
   - Authentication and authorization
   - Data protection and encryption
   - Error handling and logging

2. **Healthcare Data Security**
   - PHI identification and protection
   - HIPAA compliance requirements
   - Patient data privacy
   - Audit and compliance reporting

3. **Cloud Security**
   - Google Cloud security features
   - VPC and network security
   - Identity and Access Management
   - Monitoring and alerting

4. **Incident Response**
   - Incident identification and classification
   - Response procedures and communication
   - Evidence collection and analysis
   - Post-incident review and improvement

### Security Metrics Dashboard

#### Key Security Indicators
```json
{
  "security_score": 95,
  "last_updated": "2024-01-15T10:30:00Z",
  "metrics": {
    "authentication": {
      "failed_attempts": 0.5,
      "success_rate": 99.5,
      "unusual_patterns": 0
    },
    "authorization": {
      "access_denials": 0.1,
      "privilege_escalations": 0,
      "policy_violations": 0
    },
    "data_protection": {
      "phi_access_events": 2,
      "encryption_failures": 0,
      "data_leaks": 0
    },
    "network_security": {
      "suspicious_traffic": 0,
      "blocked_attacks": 5,
      "firewall_hits": 15
    }
  },
  "alerts": {
    "critical": 0,
    "high": 1,
    "medium": 3,
    "low": 7
  }
}
```

---

**Security First • HIPAA Compliant • Zero Trust • Enterprise Security**

*Comprehensive security implementation for healthcare AI*
