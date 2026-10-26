from functools import lru_cache
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

API_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = API_ROOT / ".env"

AppEnvironment = Literal["development", "testing", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        env_prefix="ICYLENS_",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
        str_strip_whitespace=True,
    )

    APP_NAME: str = Field(default="iCYLENS API", min_length=1)
    APP_VERSION: str = Field(default="0.4.1", min_length=1)
    APP_ENV: AppEnvironment = "development"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"
    LOG_LEVEL: LogLevel = "INFO"
    MAX_UPLOAD_BYTES: int = Field(
        default=10 * 1024 * 1024,
        gt=0,
        le=1024 * 1024 * 1024,
    )
    INSPECTION_MIN_STRING_LENGTH: int = Field(default=4, gt=0, le=256)
    INSPECTION_MAX_STRINGS: int = Field(default=100, gt=0, le=1000)
    INSPECTION_MAX_STRING_LENGTH: int = Field(default=256, gt=0, le=4096)
    INSPECTION_MAX_INDICATORS: int = Field(default=100, gt=0, le=1000)
    ML_INFERENCE_ENABLED: bool = False
    ML_DEMO_MODE_ENABLED: bool = False
    ML_MAX_CONCURRENT_INFERENCES: int = Field(default=2, ge=1, le=16)
    NVD_API_KEY: SecretStr | None = None
    NVD_TIMEOUT_SECONDS: float = Field(default=10.0, gt=0, le=60)
    NVD_TOTAL_DEADLINE_SECONDS: float = Field(default=45.0, gt=0, le=300)
    NVD_MAX_RESPONSE_BYTES: int = Field(
        default=2 * 1024 * 1024, ge=1024, le=16 * 1024 * 1024
    )
    NVD_MAX_CONCURRENCY: int = Field(default=2, ge=1, le=8)
    NVD_REQUESTS_PER_WINDOW: int = Field(default=5, ge=1, le=100)
    NVD_RATE_WINDOW_SECONDS: float = Field(default=30.0, gt=0, le=3600)
    NVD_MAX_RETRIES: int = Field(default=2, ge=0, le=5)
    NVD_BACKOFF_SECONDS: float = Field(default=0.5, ge=0, le=10)
    NVD_MAX_RETRY_AFTER_SECONDS: float = Field(default=10.0, ge=0, le=60)
    VULNERABILITY_MAX_INVENTORY_BODY_BYTES: int = Field(
        default=256 * 1024, ge=1024, le=2 * 1024 * 1024
    )
    KEV_REFRESH_ON_STARTUP: bool = False
    KEV_TIMEOUT_SECONDS: float = Field(default=15.0, gt=0, le=60)
    KEV_TOTAL_DEADLINE_SECONDS: float = Field(default=60.0, gt=0, le=300)
    KEV_MAX_RESPONSE_BYTES: int = Field(
        default=8 * 1024 * 1024, ge=1024 * 1024, le=32 * 1024 * 1024
    )
    KEV_MAX_ENTRIES: int = Field(default=5000, ge=1, le=20_000)
    KEV_MAX_CONCURRENCY: int = Field(default=1, ge=1, le=2)
    KEV_MAX_RETRIES: int = Field(default=2, ge=0, le=5)
    KEV_BACKOFF_SECONDS: float = Field(default=0.5, ge=0, le=10)
    KEV_MAX_RETRY_AFTER_SECONDS: float = Field(default=10.0, ge=0, le=60)
    KEV_FRESHNESS_SECONDS: float = Field(default=36 * 3600, gt=0, le=30 * 86400)
    EPSS_TIMEOUT_SECONDS: float = Field(default=10.0, gt=0, le=60)
    EPSS_TOTAL_DEADLINE_SECONDS: float = Field(default=30.0, gt=0, le=300)
    EPSS_MAX_RESPONSE_BYTES: int = Field(
        default=256 * 1024, ge=1024, le=2 * 1024 * 1024
    )
    EPSS_MAX_CONCURRENCY: int = Field(default=2, ge=1, le=8)
    EPSS_REQUESTS_PER_WINDOW: int = Field(default=60, ge=1, le=1000)
    EPSS_RATE_WINDOW_SECONDS: float = Field(default=60.0, gt=0, le=3600)
    EPSS_MAX_RETRIES: int = Field(default=2, ge=0, le=5)
    EPSS_BACKOFF_SECONDS: float = Field(default=0.5, ge=0, le=10)
    EPSS_MAX_RETRY_AFTER_SECONDS: float = Field(default=10.0, ge=0, le=60)
    EPSS_CACHE_TTL_SECONDS: float = Field(default=3600.0, gt=0, le=86400)
    EPSS_CACHE_MAX_ENTRIES: int = Field(default=1024, ge=1, le=10_000)
    EPSS_CURRENT_MAX_AGE_DAYS: int = Field(default=1, ge=0, le=7)
    EPSS_STALE_MAX_AGE_DAYS: int = Field(default=7, ge=1, le=30)
    CORRELATION_TOTAL_DEADLINE_SECONDS: float = Field(default=60.0, gt=0, le=300)
    CORRELATION_MAX_CONCURRENCY: int = Field(default=8, ge=1, le=64)
    CORRELATION_MAX_RESPONSE_BYTES: int = Field(
        default=2 * 1024 * 1024, ge=64 * 1024, le=8 * 1024 * 1024
    )

    @field_validator("LOG_LEVEL", mode="before")
    @classmethod
    def normalize_log_level(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @field_validator("API_V1_PREFIX")
    @classmethod
    def validate_api_prefix(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("API_V1_PREFIX must start with '/'")
        if value != "/" and value.endswith("/"):
            raise ValueError("API_V1_PREFIX must not end with '/'")
        return value

    @model_validator(mode="after")
    def validate_environment_safety(self) -> Self:
        if self.APP_ENV == "production" and self.DEBUG:
            raise ValueError("DEBUG must be disabled in production")
        if self.INSPECTION_MAX_STRING_LENGTH < self.INSPECTION_MIN_STRING_LENGTH:
            raise ValueError(
                "INSPECTION_MAX_STRING_LENGTH must be greater than or equal to "
                "INSPECTION_MIN_STRING_LENGTH"
            )
        if self.ML_DEMO_MODE_ENABLED and not self.ML_INFERENCE_ENABLED:
            raise ValueError("ML_DEMO_MODE_ENABLED requires ML_INFERENCE_ENABLED")
        if self.EPSS_STALE_MAX_AGE_DAYS <= self.EPSS_CURRENT_MAX_AGE_DAYS:
            raise ValueError(
                "EPSS_STALE_MAX_AGE_DAYS must exceed EPSS_CURRENT_MAX_AGE_DAYS"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
