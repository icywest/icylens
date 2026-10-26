import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings, get_settings

TEST_ENVIRONMENT = {
    "ICYLENS_APP_NAME": "iCYLENS API",
    "ICYLENS_APP_VERSION": "0.4.1",
    "ICYLENS_APP_ENV": "testing",
    "ICYLENS_DEBUG": "false",
    "ICYLENS_API_V1_PREFIX": "/api/v1",
    "ICYLENS_LOG_LEVEL": "INFO",
    "ICYLENS_MAX_UPLOAD_BYTES": "10485760",
    "ICYLENS_INSPECTION_MIN_STRING_LENGTH": "4",
    "ICYLENS_INSPECTION_MAX_STRINGS": "100",
    "ICYLENS_INSPECTION_MAX_STRING_LENGTH": "256",
    "ICYLENS_INSPECTION_MAX_INDICATORS": "100",
    "ICYLENS_ML_INFERENCE_ENABLED": "false",
    "ICYLENS_ML_DEMO_MODE_ENABLED": "false",
    "ICYLENS_ML_MAX_CONCURRENT_INFERENCES": "2",
    "ICYLENS_NVD_API_KEY": "",
    "ICYLENS_NVD_TIMEOUT_SECONDS": "10",
    "ICYLENS_NVD_TOTAL_DEADLINE_SECONDS": "45",
    "ICYLENS_NVD_MAX_RESPONSE_BYTES": "2097152",
    "ICYLENS_NVD_MAX_CONCURRENCY": "2",
    "ICYLENS_NVD_REQUESTS_PER_WINDOW": "5",
    "ICYLENS_NVD_RATE_WINDOW_SECONDS": "30",
    "ICYLENS_NVD_MAX_RETRIES": "2",
    "ICYLENS_NVD_BACKOFF_SECONDS": "0.5",
    "ICYLENS_NVD_MAX_RETRY_AFTER_SECONDS": "10",
    "ICYLENS_VULNERABILITY_MAX_INVENTORY_BODY_BYTES": "262144",
    "ICYLENS_KEV_REFRESH_ON_STARTUP": "false",
    "ICYLENS_KEV_TIMEOUT_SECONDS": "15",
    "ICYLENS_KEV_TOTAL_DEADLINE_SECONDS": "60",
    "ICYLENS_KEV_MAX_RESPONSE_BYTES": "8388608",
    "ICYLENS_KEV_MAX_ENTRIES": "5000",
    "ICYLENS_KEV_MAX_CONCURRENCY": "1",
    "ICYLENS_KEV_MAX_RETRIES": "2",
    "ICYLENS_KEV_BACKOFF_SECONDS": "0.5",
    "ICYLENS_KEV_MAX_RETRY_AFTER_SECONDS": "10",
    "ICYLENS_KEV_FRESHNESS_SECONDS": "129600",
    "ICYLENS_EPSS_TIMEOUT_SECONDS": "10",
    "ICYLENS_EPSS_TOTAL_DEADLINE_SECONDS": "30",
    "ICYLENS_EPSS_MAX_RESPONSE_BYTES": "262144",
    "ICYLENS_EPSS_MAX_CONCURRENCY": "2",
    "ICYLENS_EPSS_REQUESTS_PER_WINDOW": "60",
    "ICYLENS_EPSS_RATE_WINDOW_SECONDS": "60",
    "ICYLENS_EPSS_MAX_RETRIES": "2",
    "ICYLENS_EPSS_BACKOFF_SECONDS": "0.5",
    "ICYLENS_EPSS_MAX_RETRY_AFTER_SECONDS": "10",
    "ICYLENS_EPSS_CACHE_TTL_SECONDS": "3600",
    "ICYLENS_EPSS_CACHE_MAX_ENTRIES": "1024",
    "ICYLENS_EPSS_CURRENT_MAX_AGE_DAYS": "1",
    "ICYLENS_EPSS_STALE_MAX_AGE_DAYS": "7",
    "ICYLENS_CORRELATION_TOTAL_DEADLINE_SECONDS": "60",
    "ICYLENS_CORRELATION_MAX_CONCURRENCY": "8",
    "ICYLENS_CORRELATION_MAX_RESPONSE_BYTES": "2097152",
}

ENVIRONMENT_VARIABLES = tuple(TEST_ENVIRONMENT)


def pytest_configure() -> None:
    # Test modules can safely import app.main without consulting a developer's
    # local .env because every supported setting is overridden first.
    expected_variables = {f"ICYLENS_{name}" for name in Settings.model_fields}
    missing_variables = expected_variables - set(TEST_ENVIRONMENT)
    if missing_variables:
        raise pytest.UsageError(
            "Missing test environment overrides: "
            + ", ".join(sorted(missing_variables))
        )
    os.environ.update(TEST_ENVIRONMENT)


@pytest.fixture(autouse=True)
def isolate_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for variable in ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(variable, raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def test_settings() -> Settings:
    return Settings(APP_ENV="testing", _env_file=None)


@pytest.fixture
def client(test_settings: Settings) -> Iterator[TestClient]:
    from app.main import create_app

    with TestClient(create_app(test_settings)) as test_client:
        yield test_client
