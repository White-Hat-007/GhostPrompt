# GhostPrompt Security Hardening Guide

## Security Model

GhostPrompt follows a defense-in-depth security model with multiple layers:

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Network Security (WAF, Rate Limiting, TLS)    │
├─────────────────────────────────────────────────────────┤
│  Layer 2: Authentication (JWT, API Keys, MFA)           │
├─────────────────────────────────────────────────────────┤
│  Layer 3: Authorization (RBAC, Org Isolation, Scopes)   │
├─────────────────────────────────────────────────────────┤
│  Layer 4: Input Validation (Pydantic, Size Limits)      │
├─────────────────────────────────────────────────────────┤
│  Layer 5: AI Firewall Engine (7 Detection Modules)      │
├─────────────────────────────────────────────────────────┤
│  Layer 6: Output Security (PII, Secrets, Policy)        │
├─────────────────────────────────────────────────────────┤
│  Layer 7: Audit & Monitoring (Immutable Logs, Alerts)   │
└─────────────────────────────────────────────────────────┘
```

## Threat Model

### Assets Protected
- Customer prompts and AI interactions
- Organization credentials and API keys
- Security policies and detection rules
- Trained ML models
- Threat intelligence data
- Audit logs

### Attack Vectors Addressed
| Vector | Protection |
|--------|-----------|
| Prompt Injection | Multi-pattern regex + ML classifier |
| Jailbreak Attempts | DAN detection, role-play exploit detection |
| Encoded Payloads | Base64, hex, Unicode, zero-width character detection |
| PII Leakage | Regex + NER-based PII detection in outputs |
| Secret Exposure | 15+ secret patterns (API keys, tokens, certificates) |
| RAG Poisoning | Document context injection scanning |
| Agent Hijacking | Tool call validation, workflow analysis |
| Content Policy | Weaponization, illegal activity detection |
| Obfuscation | Homoglyph, Unicode anomaly, character substitution |
| Multi-turn Manipulation | Context chain analysis |

## Hardening Checklist

### Application Security
- [ ] Generate strong SECRET_KEY (minimum 64 chars)
- [ ] Generate separate JWT_SECRET_KEY (minimum 64 chars)
- [ ] Set APP_DEBUG=false in production
- [ ] Configure CORS_ORIGINS for production domains only
- [ ] Enable rate limiting per API key
- [ ] Set maximum prompt length limits
- [ ] Enable all 7 detection modules
- [ ] Set threat_score_threshold ≥ 0.7

### Authentication
- [ ] Enforce strong passwords (12+ chars, complexity)
- [ ] Enable MFA for admin accounts
- [ ] Set JWT expiration ≤ 1 hour
- [ ] Rotate refresh tokens on use
- [ ] Implement API key rotation policy
- [ ] Log all authentication events

### Database
- [ ] Use strong, unique database passwords
- [ ] Enable encryption at rest (AES-256)
- [ ] Enable TLS for database connections
- [ ] Restrict network access to application only
- [ ] Enable automated backups (30-day retention)
- [ ] Enable PostgreSQL audit logging
- [ ] Use read replicas for analytics queries

### Redis
- [ ] Enable Redis AUTH
- [ ] Enable TLS for Redis connections
- [ ] Set maxmemory limits
- [ ] Disable dangerous commands (FLUSHALL, DEBUG)
- [ ] Use Redis ACLs for service accounts

### Network
- [ ] Enable TLS 1.3 everywhere
- [ ] Configure WAF rules
- [ ] Enable DDoS protection
- [ ] Use private subnets for databases
- [ ] Restrict egress traffic
- [ ] Implement IP allowlisting for admin access

### Kubernetes
- [ ] Use non-root containers
- [ ] Set resource limits on all pods
- [ ] Enable Pod Security Standards (Restricted)
- [ ] Use NetworkPolicies for pod-to-pod communication
- [ ] Scan container images for vulnerabilities
- [ ] Use Secrets with encryption at rest
- [ ] Enable audit logging for API server

### Monitoring
- [ ] Set up alerting for failed authentication
- [ ] Monitor for unusual scan volumes
- [ ] Alert on high threat score clusters
- [ ] Monitor API latency P99
- [ ] Set up log aggregation
- [ ] Enable distributed tracing

### Compliance
- [ ] Enable full audit trail
- [ ] Configure data retention policies
- [ ] Implement right-to-deletion workflows
- [ ] Document data processing agreements
- [ ] Regular penetration testing
- [ ] SOC 2 Type II preparation

## Secret Rotation

### API Keys
```bash
# Generate new API key
POST /api/v1/auth/api-keys

# Deactivate old key
DELETE /api/v1/auth/api-keys/{key_id}
```

### JWT Secrets
```bash
# 1. Generate new secret
openssl rand -hex 64

# 2. Update environment variable
# 3. Rolling restart backend pods
kubectl rollout restart deployment/ghostprompt-backend
```

### Database Credentials
```bash
# 1. Create new password in AWS Secrets Manager
# 2. Update PostgreSQL user password
# 3. Update DATABASE_URL in Kubernetes secrets
# 4. Rolling restart
```

## Incident Response

### Severity Levels
| Level | Description | Response Time |
|-------|-------------|---------------|
| P1 | Active exploitation, data breach | < 15 minutes |
| P2 | Vulnerability in production | < 1 hour |
| P3 | Security misconfiguration | < 4 hours |
| P4 | Best practice improvement | < 1 week |

### Response Playbook
1. **Detect**: Automated alerting or manual report
2. **Contain**: Block offending IPs/keys, escalate
3. **Analyze**: Review audit logs, scan events
4. **Remediate**: Patch, rotate credentials, update policies
5. **Review**: Post-incident review, update procedures
