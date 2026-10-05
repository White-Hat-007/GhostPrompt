# GhostPrompt Architecture Documentation

## System Architecture

### Overview

GhostPrompt is architected as a microservice-ready monolith that can be decomposed into independent services as scale demands. The system follows an API-first design with clear separation between the security engine, API layer, and presentation layer.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CLIENTS / SDKs                              │
├─────────────────────────────────────────────────────────────────────┤
│                     NGINX / Load Balancer                          │
├──────────────────────┬──────────────────────────────────────────────┤
│                      │                                              │
│  ┌──────────────┐    │    ┌──────────────────────────────────────┐  │
│  │   Next.js    │    │    │           FastAPI Backend            │  │
│  │  Dashboard   │    │    │                                      │  │
│  │              │    │    │  ┌─────────┐  ┌──────────────────┐  │  │
│  │  • Overview  │    │    │  │   API   │  │  Firewall Engine │  │  │
│  │  • Attacks   │    │    │  │  Layer  │  │                  │  │  │
│  │  • Scanner   │    │    │  │         │  │  • Injection Det │  │  │
│  │  • Policies  │    │    │  │  /auth  │  │  • Jailbreak Det │  │  │
│  │  • Settings  │    │    │  │  /scan  │  │  • Payload Det   │  │  │
│  │              │    │    │  │  /gate  │  │  • PII Detector  │  │  │
│  │              │    │    │  │  /dash  │  │  • Secret Det    │  │  │
│  │              │    │    │  │  /policy│  │  • Policy Engine │  │  │
│  │              │    │    │  │         │  │  • Obfuscation   │  │  │
│  └──────────────┘    │    │  └─────────┘  └──────────────────┘  │  │
│                      │    │                                      │  │
│                      │    │  ┌──────────┐  ┌─────────────────┐  │  │
│                      │    │  │  AI      │  │  Threat Intel   │  │  │
│                      │    │  │  Gateway │  │  Engine          │  │  │
│                      │    │  │          │  │                  │  │  │
│                      │    │  │ OpenAI   │  │  Signatures      │  │  │
│                      │    │  │ Claude   │  │  Fingerprints    │  │  │
│                      │    │  │ Gemini   │  │  Anomaly Det.    │  │  │
│                      │    │  │ Ollama   │  │  Scoring         │  │  │
│                      │    │  └──────────┘  └─────────────────┘  │  │
│                      │    └──────────────────────────────────────┘  │
│                      │                                              │
├──────────────────────┴──────────────────────────────────────────────┤
│                        Data Layer                                   │
│  ┌─────────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ PostgreSQL  │  │  Redis   │  │  Celery  │  │ ML Models     │  │
│  │ + pgvector  │  │  Cache   │  │  Worker  │  │ (GPU/ONNX)    │  │
│  └─────────────┘  └──────────┘  └──────────┘  └───────────────┘  │
├─────────────────────────────────────────────────────────────────────┤
│                      Observability                                  │
│  ┌─────────────┐  ┌──────────┐  ┌──────────────────────────────┐  │
│  │ Prometheus  │  │ Grafana  │  │ OpenTelemetry + Structured   │  │
│  │             │  │          │  │ Logging (JSON)               │  │
│  └─────────────┘  └──────────┘  └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Detection Pipeline

Every prompt/output passes through a multi-stage detection pipeline:

```
Input ──→ Rate Limit ──→ Input Validation ──→ Detection Pipeline ──→ Scoring ──→ Action
                                │
                    ┌───────────┼───────────────────────────┐
                    │           │                           │
             ┌──────▼────┐ ┌───▼──────┐ ┌───────────┐ ┌───▼─────────┐
             │ Prompt    │ │ Jailbreak│ │ Encoded   │ │ Obfuscation │
             │ Injection │ │ Detector │ │ Payload   │ │ Detector    │
             └───────────┘ └──────────┘ └───────────┘ └─────────────┘
                    │           │                           │
             ┌──────▼────┐ ┌───▼──────┐ ┌───────────┐
             │ PII       │ │ Secret   │ │ Content   │
             │ Detector  │ │ Detector │ │ Policy    │
             └───────────┘ └──────────┘ └───────────┘
                                │
                    ┌───────────▼───────────────────┐
                    │      Threat Score Calculator  │
                    │      (Weighted Aggregation)   │
                    └───────────┬───────────────────┘
                                │
                    ┌───────────▼───────────────────┐
                    │      Action Determiner        │
                    │  SAFE → ALLOWED               │
                    │  LOW  → FLAGGED               │
                    │  MED  → FLAGGED/BLOCKED       │
                    │  HIGH → BLOCKED               │
                    │  CRIT → BLOCKED               │
                    └───────────────────────────────┘
```

## Data Model

### Core Entities

| Entity | Description | Key Fields |
|--------|-------------|------------|
| Organization | Multi-tenant org | name, plan, quotas, settings |
| User | Auth user with RBAC | email, role (owner/admin/analyst/viewer) |
| APIKey | Scoped API keys | hash, scopes, rate limits, usage |
| ScanEvent | Every scan result | threat_level, score, detections, action |
| Policy | Security policy | rules, priority, type |
| PolicyRule | Individual rule | detector, threshold, action |
| ThreatSignature | Known attack pattern | patterns, category, severity |
| AuditLog | Immutable audit trail | action, actor, changes |

## Security Architecture

### Authentication Flow

1. User registers → creates Organization + User
2. Login → returns JWT access + refresh tokens
3. API requests use Bearer token or API key
4. RBAC enforced at route level (owner > admin > analyst > viewer)

### Multi-Tenancy Isolation

- All queries filtered by `organization_id`
- API keys scoped to organization
- Complete data isolation between tenants
- Per-org rate limiting and quotas

### Security Headers

All responses include:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

## Deployment

### Supported Environments

| Environment | Method | Scale |
|------------|--------|-------|
| Development | Docker Compose | Single machine |
| Staging | Kubernetes | Small cluster |
| Production | Helm + K8s | Multi-region |
| On-Premise | Docker/K8s | Enterprise |

### Hardware Requirements

| Component | Min | Recommended | GPU |
|-----------|-----|-------------|-----|
| Backend | 2 CPU, 2GB | 4 CPU, 8GB | Optional |
| Frontend | 1 CPU, 512MB | 2 CPU, 1GB | — |
| PostgreSQL | 2 CPU, 4GB | 4 CPU, 16GB | — |
| Redis | 1 CPU, 256MB | 2 CPU, 1GB | — |
| ML Training | — | 4 CPU, 16GB | RTX 3060+ |

## API Reference

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/v1/auth/register | Register new user + org |
| POST | /api/v1/auth/login | Authenticate |
| POST | /api/v1/scan | Scan prompt/output |
| POST | /api/v1/scan/batch | Batch scan |
| POST | /api/v1/gateway/chat | AI Gateway proxy |
| GET | /api/v1/dashboard/stats | Dashboard analytics |
| GET | /api/v1/dashboard/events | Scan event history |
| GET/POST | /api/v1/policies | Policy CRUD |
| GET | /health | Health check |
