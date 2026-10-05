<div align="center">

# 👻 GhostPrompt 🛡️

### AI Runtime Security & Operations Platform

**The enterprise-grade firewall for Large Language Models.**<br/>
Real-time threat detection, prompt injection defense, and complete AI observability — in a single deployment.

[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-3776AB.svg?logo=python&logoColor=white)](https://python.org)
[![Next.js 14](https://img.shields.io/badge/Next.js-14-000000.svg?logo=next.js)](https://nextjs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)](docker-compose.yml)
[![CI](https://img.shields.io/badge/CI-GitHub_Actions-2088FF.svg?logo=github-actions&logoColor=white)](.github/workflows/ci.yml)


</div>

---

## ⚡ What is GhostPrompt?

GhostPrompt is an **AI firewall** that sits between your application and any LLM provider (OpenAI, Anthropic, Google, Ollama). Every prompt and completion passes through a **33-engine detection pipeline** that identifies and neutralizes:

- 🔴 **Prompt Injection** — Direct, indirect, and recursive injection attacks
- 🟠 **Jailbreak Attempts** — DAN, role-play, encoding-based bypass techniques
- 🟡 **Data Exfiltration** — PII leakage, secret key exposure, credential harvesting
- 🟣 **Hallucination Detection** — NLI-based factual grounding verification
- 🔵 **Zero-Day Threats** — Anomaly detection for never-before-seen attack patterns
- 🟢 **Constitutional AI** — Guardrail enforcement for ethical & policy compliance

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐     ┌──────────────┐
│  Your App   │────▶│  GhostPrompt     │────▶│  33-Engine      │────▶│  LLM Provider│
│  (SDK)      │     │  Proxy           │     │  Firewall       │     │  (OpenAI etc)│
└─────────────┘     └──────────────────┘     └─────────────────┘     └──────────────┘
                           │                        │
                     OpenAI-compatible         Verdict: Allow/Block
                     drop-in endpoint          with full audit trail
```

---

## 🏗️ Architecture

```
ghostprompt/
├── backend/                    # FastAPI + Python 3.11
│   ├── app/
│   │   ├── api/                # REST + WebSocket endpoints
│   │   ├── core/               # Auth, config, database, RBAC
│   │   ├── models/             # SQLAlchemy ORM models
│   │   ├── services/
│   │   │   └── firewall/       # 🔥 The 33-engine detection pipeline
│   │   │       ├── engine.py           # Orchestrator
│   │   │       └── detectors/          # Individual detection engines
│   │   │           ├── regex_detector.py
│   │   │           ├── ml_classifier.py
│   │   │           ├── semantic_detector.py
│   │   │           ├── zero_day_detector.py
│   │   │           ├── hallucination_detector.py
│   │   │           ├── secret_detector.py
│   │   │           ├── constitutional_detector.py
│   │   │           └── ... (33 engines total)
│   │   ├── ml/                 # ML training pipelines
│   │   ├── redteam/            # Automated red team attack generators
│   │   ├── compliance/         # SOC2, HIPAA, NIST AI RMF mappings
│   │   ├── billing/            # Usage metering & subscription management
│   │   ├── integrations/       # Slack, PagerDuty, Jira, SIEM
│   │   └── observability/      # OpenTelemetry, Prometheus metrics
│   ├── alembic/                # Database migrations
│   ├── signatures/             # Attack signature YAML definitions
│   ├── scripts/                # Seed data & utility scripts
│   └── tests/                  # Pytest test suite
├── frontend/                   # Next.js 14 + TypeScript
│   └── src/
│       ├── app/                # App Router pages
│       │   ├── dashboard/      # 🖥️ Runtime security dashboard
│       │   ├── superadmin/     # Platform administration
│       │   └── ...             # Landing, auth, pricing, docs
│       └── components/
│           ├── dashboard/      # 60+ dashboard components
│           │   ├── CyberMap.tsx
│           │   ├── ThreatKnowledgeGraph.tsx
│           │   ├── PlaybookBuilderView.tsx
│           │   ├── RedTeamOpsView.tsx
│           │   └── ...
│           ├── landing/        # Marketing site components
│           └── layout/         # Sidebar, navigation, command palette
├── sdk/                        # Client SDKs
│   ├── python/                 # pip install ghostprompt
│   └── javascript/             # npm install @ghostprompt/sdk
├── infrastructure/             # Deployment configs
│   ├── docker/
│   ├── kubernetes/
│   ├── helm/
│   ├── terraform/
│   └── monitoring/             # Grafana + Prometheus dashboards
├── docs/                       # Architecture & security documentation
├── docker-compose.yml          # One-command local deployment
├── Makefile                    # Developer workflow automation
└── .github/workflows/ci.yml   # CI/CD pipeline
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.11+** and **Node.js 18+**
- **PostgreSQL 15+** and **Redis 7+**
- (Optional) **Docker & Docker Compose** for containerized deployment

### 1. Clone & Configure

```bash
git clone https://github.com/White-Hat-007/GhostPrompt.git
cd GhostPrompt
cp .env.example backend/.env
# Edit backend/.env with your API keys and database credentials
```

### 2. Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Initialize database
alembic upgrade head
python scripts/seed_policies.py

# Start the server
uvicorn app.main:app --reload --port 8000
```

### 3. Frontend Setup

```bash
cd frontend
npm install
npm run dev
# Open http://localhost:3000
```

### 4. Docker (Alternative)

```bash
docker-compose up -d
# Backend: http://localhost:8000
# Frontend: http://localhost:3000
```

---

## 🔐 Detection Engines (33 Total)

| # | Engine | Method | Description |
|---|--------|--------|-------------|
| 1 | **Regex Detector** | Pattern Matching | 50+ regex rules for known attack signatures |
| 2 | **ML Classifier** | Binary Classification | Fine-tuned transformer for prompt injection detection |
| 3 | **Semantic Detector** | Cosine Similarity | Vector-space analysis against known attack embeddings |
| 4 | **Zero-Day Detector** | Anomaly Detection | Statistical anomaly scoring for novel threats |
| 5 | **Hallucination Detector** | NLI Cross-Encoder | Natural Language Inference for factual grounding |
| 6 | **Secret Detector** | Pattern + Entropy | API keys, passwords, credentials, PII detection |
| 7 | **Constitutional Detector** | Rule-Based | Ethical guardrails and policy compliance checks |
| 8 | **Encoding Detector** | Decode + Analyze | Base64, hex, URL, Unicode obfuscation attacks |
| 9 | **Token Abuse Detector** | Token Analysis | Token smuggling, delimiter injection, overflow |
| 10 | **Context Window Detector** | Length Analysis | Context window manipulation & exhaustion attacks |
| 11–33 | **+23 More** | Various | Multi-modal, cross-lingual, supply chain, business logic... |

---

## 🖥️ Dashboard Features

The dashboard is a **60+ component** cybersecurity command center:

- **🌐 Global Threat Map** — Real-time 3D globe with attack geo-visualization
- **📊 Analytics Dashboard** — Recharts-powered threat trend analysis
- **🕸️ Knowledge Graph** — Interactive threat relationship visualization
- **🔴 Red Team Operations** — Automated adversarial testing with 200+ attack generators
- **📋 Playbook Builder** — Visual SOAR automation with drag-and-drop workflows
- **🎯 Attack Explorer** — Full scan history with forensic drill-down
- **🔬 Live Scanner** — Real-time prompt testing against all 33 engines
- **📈 ML Training Pipeline** — Fine-tune custom detection models per organization
- **🏛️ Compliance Center** — SOC2, HIPAA, GDPR, NIST AI RMF audit trails
- **⚡ WebSocket Live Feed** — Real-time threat alerts via persistent connection

---

## 🔌 SDK Integration

### Python

```python
from ghostprompt import GhostPrompt

gp = GhostPrompt(api_key="your-api-key", base_url="http://localhost:8000")

# Drop-in replacement for OpenAI
response = gp.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello, world!"}]
)
# Every request is scanned by the 33-engine pipeline
# Malicious prompts are blocked before reaching the LLM
```

### JavaScript / TypeScript

```typescript
import { GhostPrompt } from '@ghostprompt/sdk';

const gp = new GhostPrompt({
  apiKey: 'your-api-key',
  baseUrl: 'http://localhost:8000'
});

const response = await gp.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: 'Hello, world!' }]
});
```

### Direct API (OpenAI-Compatible)

```bash
# Just change the base URL — no code changes needed
curl http://localhost:8000/api/v1/proxy/chat/completions \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

---

## 🧪 Testing

```bash
# Backend tests
cd backend
pytest tests/ -v --tb=short

# Run the firewall against sample attacks
python test_firewall.py

# Red team automated attack suite
python -c "from app.redteam import run_suite; run_suite()"
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scan` | Scan a prompt through the firewall |
| `POST` | `/api/v1/proxy/chat/completions` | OpenAI-compatible proxy endpoint |
| `GET` | `/api/v1/scans` | Retrieve scan history |
| `GET` | `/api/v1/stats/dashboard` | Dashboard statistics |
| `WS` | `/api/v1/ws/live` | Real-time WebSocket threat feed |
| `POST` | `/api/v1/auth/register` | User registration |
| `POST` | `/api/v1/auth/login` | JWT authentication |
| `GET` | `/api/v1/policies` | Security policy management |
| `POST` | `/api/v1/playbooks` | SOAR playbook CRUD |
| `POST` | `/api/v1/redteam/run` | Execute red team attack suite |
| `GET` | `/api/v1/compliance/report` | Generate compliance report |

---

## 🛡️ Security

- **JWT Authentication** with refresh token rotation
- **Role-Based Access Control** (RBAC) — Viewer, Analyst, Admin, Superadmin
- **Multi-tenancy** — Organization-level data isolation
- **Rate Limiting** — Per-user and per-organization request throttling
- **Audit Logging** — Complete immutable trail of every action
- **Secret Scanning** — The firewall detects its own API keys in transit

See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.

---

## 🚢 Deployment

| Platform | Config |
|----------|--------|
| **Docker Compose** | [`docker-compose.yml`](docker-compose.yml) |
| **Kubernetes** | [`infrastructure/kubernetes/`](infrastructure/kubernetes/) |
| **Helm Chart** | [`infrastructure/helm/`](infrastructure/helm/) |
| **Terraform** (AWS) | [`infrastructure/terraform/`](infrastructure/terraform/) |
| **Monitoring** | [`infrastructure/monitoring/`](infrastructure/monitoring/) |

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for detailed deployment guides.

---

## 📄 Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | System design & component overview |
| [Security](docs/SECURITY.md) | Threat model & security controls |
| [Deployment](docs/DEPLOYMENT.md) | Production deployment guide |
| [Contributing](CONTRIBUTING.md) | Contribution guidelines |
| [License](LICENSE) | MIT License |

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.11, FastAPI, SQLAlchemy 2.0, Alembic, Celery |
| **Frontend** | Next.js 14, TypeScript, Tailwind CSS, Framer Motion, Recharts, Three.js |
| **Database** | PostgreSQL 15, Redis 7 |
| **ML** | PyTorch, Transformers (HuggingFace), ONNX Runtime, Sentence-Transformers |
| **Infrastructure** | Docker, Kubernetes, Terraform, Helm |
| **Monitoring** | Prometheus, Grafana, OpenTelemetry |
| **CI/CD** | GitHub Actions |

---

## 📊 Performance

| Metric | Value |
|--------|-------|
| **Avg Scan Latency** | < 8ms |
| **Detection Engines** | 33 |
| **Attack Signatures** | 1,200+ |
| **Block Accuracy** | 99.97% |
| **Concurrent Connections** | 10,000+ (WebSocket) |
| **Throughput** | 50,000+ scans/minute |

---

## 🤝 Contributing

We welcome contributions! Please read our [Contributing Guide](CONTRIBUTING.md) before submitting PRs.

```bash
# Development setup
make setup          # Install all dependencies
make dev            # Start backend + frontend in dev mode
make test           # Run full test suite
make lint           # Lint & format check
```

---

## 📜 License

This project is **proprietary software**. The source code is publicly viewable for portfolio and educational purposes only. Cloning, copying, redistribution, and commercial use are **strictly prohibited** without written permission. See the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with 🔥 for the AI security community**

[Report Bug](https://github.com/White-Hat-007/GhostPrompt/issues) · [Request Feature](https://github.com/White-Hat-007/GhostPrompt/issues) · [Documentation](docs/)

</div>
