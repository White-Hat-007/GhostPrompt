# GhostPrompt Deployment Guide

## Quick Start (Development)

### Prerequisites
- Python 3.11+
- Node.js 20+
- Docker & Docker Compose
- Git

### 1. Clone & Configure
```bash
git clone https://github.com/ghostprompt/ghostprompt.git
cd ghostprompt
cp .env.example .env
# Edit .env with your configuration
```

### 2. Start Infrastructure
```bash
docker-compose up -d postgres redis
```

### 3. Backend Setup
```bash
cd backend
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### 4. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

### 5. Access
- Dashboard: http://localhost:3000
- API: http://localhost:8000
- API Docs: http://localhost:8000/docs

---

## Docker Deployment

### Full Stack
```bash
docker-compose up -d
```

### Services
| Service | Port | Description |
|---------|------|-------------|
| backend | 8000 | FastAPI API |
| frontend | 3000 | Next.js Dashboard |
| postgres | 5432 | PostgreSQL + pgvector |
| redis | 6379 | Redis cache |
| prometheus | 9090 | Metrics |
| grafana | 3001 | Dashboards |

---

## Kubernetes Deployment

### Prerequisites
- Kubernetes 1.28+
- kubectl configured
- Helm 3.x
- cert-manager (for TLS)

### Using Helm
```bash
# Add secrets
kubectl create namespace ghostprompt
kubectl create secret generic ghostprompt-secrets \
  --namespace ghostprompt \
  --from-literal=secret-key="$(openssl rand -hex 32)" \
  --from-literal=jwt-secret-key="$(openssl rand -hex 32)" \
  --from-literal=database-url="postgresql+asyncpg://user:pass@host:5432/ghostprompt" \
  --from-literal=redis-url="redis://redis:6379/0"

# Install
helm install ghostprompt ./infrastructure/helm/ghostprompt \
  --namespace ghostprompt \
  --values ./infrastructure/helm/ghostprompt/values.yaml
```

### Scaling
```bash
# Scale backend
kubectl scale deployment ghostprompt-backend --replicas=10 -n ghostprompt

# HPA is configured automatically — scales 3-50 pods based on CPU/memory
```

---

## Production Checklist

### Security
- [ ] Change all default passwords and secrets
- [ ] Enable TLS everywhere
- [ ] Configure IP allowlists
- [ ] Enable audit logging
- [ ] Set up secret rotation
- [ ] Configure CORS for production domains only
- [ ] Enable rate limiting
- [ ] Review firewall policies

### Infrastructure
- [ ] Set up PostgreSQL replication
- [ ] Configure Redis Sentinel/Cluster
- [ ] Set up automated backups
- [ ] Configure monitoring alerts
- [ ] Set up log aggregation
- [ ] Configure auto-scaling
- [ ] Set up CDN for frontend

### Compliance
- [ ] Enable full audit logging
- [ ] Configure data retention policies
- [ ] Set up compliance exports
- [ ] Document data processing activities
- [ ] Implement data deletion workflows

---

## Environment Variables

See `.env.example` for full list. Critical production variables:

| Variable | Description | Required |
|----------|-------------|----------|
| SECRET_KEY | Application secret (32+ chars) | ✅ |
| JWT_SECRET_KEY | JWT signing key | ✅ |
| DATABASE_URL | PostgreSQL connection string | ✅ |
| REDIS_URL | Redis connection string | ✅ |
| APP_ENV | Environment (production) | ✅ |
| CORS_ORIGINS | Allowed origins | ✅ |
| FIREWALL_MODE | enforce/monitor/disabled | ✅ |
