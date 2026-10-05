"""
GhostPrompt Core Configuration

Centralized configuration using Pydantic Settings with environment variable support.
All configuration is validated at startup to prevent runtime failures.
"""

from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import field_validator
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    APP_NAME: str = "GhostPrompt"
    APP_ENV: str = "development"
    APP_DEBUG: bool = True
    APP_VERSION: str = "1.0.0"
    SECRET_KEY: str = "dev-secret-key-change-in-production-minimum-32-characters"
    API_PREFIX: str = "/api/v1"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://ghostprompt:ghostprompt_secret@localhost:5432/ghostprompt"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_CACHE_TTL: int = 3600

    # JWT Authentication
    JWT_SECRET_KEY: str = "jwt-dev-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15  # Hardened: was 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # AI Providers
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    GOOGLE_AI_API_KEY: Optional[str] = None
    MISTRAL_API_KEY: Optional[str] = None
    COHERE_API_KEY: Optional[str] = None
    GROQ_API_KEY: Optional[str] = None
    TOGETHER_API_KEY: Optional[str] = None
    DEEPSEEK_API_KEY: Optional[str] = None
    PERPLEXITY_API_KEY: Optional[str] = None
    HUGGINGFACE_API_KEY: Optional[str] = None
    XAI_API_KEY: Optional[str] = None
    OLLAMA_BASE_URL: str = "http://localhost:11434"

    # SIEM Integration
    SIEM_WEBHOOK_URL: Optional[str] = None
    SIEM_WEBHOOK_SECRET: Optional[str] = None
    SIEM_PROVIDER: str = "generic"  # splunk, datadog, qradar, generic

    # Firewall
    FIREWALL_ENABLED: bool = True
    FIREWALL_MODE: str = "enforce"  # enforce, monitor, disabled
    FIREWALL_LOG_LEVEL: str = "INFO"
    MAX_PROMPT_LENGTH: int = 32000
    MAX_OUTPUT_LENGTH: int = 64000
    THREAT_SCORE_THRESHOLD: float = 0.7

    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 60
    RATE_LIMIT_BURST: int = 100

    # Monitoring
    PROMETHEUS_ENABLED: bool = True
    OTEL_EXPORTER_OTLP_ENDPOINT: str = "http://localhost:4317"
    OTEL_SERVICE_NAME: str = "ghostprompt-backend"

    # Celery
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # ML / GPU
    CUDA_VISIBLE_DEVICES: str = "0"
    MODEL_CACHE_DIR: str = "./models/cache"
    TRAINING_OUTPUT_DIR: str = "./models/trained"
    USE_GPU: str = "auto"
    ONNX_OPTIMIZATION: bool = True

    # Hallucination Detection — Multi-Layer Engine
    HALLUCINATION_POLICY: str = "ADAPTIVE"  # FAST, STANDARD, THOROUGH, MAXIMUM, ADAPTIVE
    HALLUCINATION_JUDGE_MODEL: str = "gpt-4o-mini"  # LLM-as-Judge model
    HALLUCINATION_SELFCHECK_SAMPLES: int = 3  # SelfCheckGPT sample count
    HALLUCINATION_NLI_MODEL: str = "d:/PROJECTS/GhostPrompt/backend/models/hallucination/nli_finetuned"
    HALLUCINATION_FAITHFULNESS_THRESHOLD: float = 0.5
    GOOGLE_FACTCHECK_API_KEY: Optional[str] = None
    
    # Kaggle
    KAGGLE_USERNAME: Optional[str] = None
    KAGGLE_KEY: Optional[str] = None

    # IP Intelligence (IPinfo.io)
    IPINFO_TOKEN: Optional[str] = None

    # CORS
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:8000,http://127.0.0.1:3000,http://127.0.0.1:8000"
    CORS_ALLOW_CREDENTIALS: bool = True

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    LOG_FILE: str = "logs/ghostprompt.log"

    # Storage
    UPLOAD_DIR: str = "./uploads"
    MAX_UPLOAD_SIZE_MB: int = 100

    # SMTP
    SMTP_PASSWORD: str | None = None
    SMTP_USER: str = "dummyboi393@gmail.com"
    FRONTEND_URL: str = "http://localhost:3000"

    # ─── Security Hardening ───
    SUPERADMIN_EMAIL: str = "dummyboi393@gmail.com"
    SECURITY_BCRYPT_ROUNDS: int = 12
    SECURITY_ACCOUNT_LOCKOUT_THRESHOLD: int = 5
    SECURITY_LOCKOUT_DURATION_MINUTES: int = 15
    SECURITY_DEMO_MODE: bool = False  # Set True ONLY in dev to enable demo_token
    SECURITY_MAX_REQUEST_BODY_BYTES: int = 52_428_800  # 50 MB
    SECURITY_MAX_URL_LENGTH: int = 2048
    SECURITY_ALLOWED_JWT_ALGORITHMS: str = "HS256"

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

    @property
    def allowed_jwt_algorithms(self) -> list[str]:
        return [a.strip() for a in self.SECURITY_ALLOWED_JWT_ALGORITHMS.split(",")]

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def is_development(self) -> bool:
        return self.APP_ENV == "development"

    @field_validator("FIREWALL_MODE")
    @classmethod
    def validate_firewall_mode(cls, v: str) -> str:
        allowed = {"enforce", "monitor", "disabled"}
        if v not in allowed:
            raise ValueError(f"FIREWALL_MODE must be one of {allowed}")
        return v

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
