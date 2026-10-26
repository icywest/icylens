from functools import lru_cache
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator
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
    APP_VERSION: str = Field(default="0.1.0", min_length=1)
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
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
