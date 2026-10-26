from pathlib import Path

import pytest

pytestmark = pytest.mark.security

API_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = API_ROOT.parents[1]


def test_local_env_is_ignored_but_example_is_versionable() -> None:
    gitignore = (REPOSITORY_ROOT / ".gitignore").read_text(encoding="utf-8")

    assert ".env" in gitignore.splitlines()
    assert "!.env.example" in gitignore.splitlines()


def test_env_example_contains_only_documented_non_secret_settings() -> None:
    content = (API_ROOT / ".env.example").read_text(encoding="utf-8")
    keys = {
        line.split("=", maxsplit=1)[0]
        for line in content.splitlines()
        if line and not line.startswith("#")
    }

    assert keys == {
        "ICYLENS_API_V1_PREFIX",
        "ICYLENS_APP_ENV",
        "ICYLENS_APP_NAME",
        "ICYLENS_APP_VERSION",
        "ICYLENS_DEBUG",
        "ICYLENS_LOG_LEVEL",
        "ICYLENS_MAX_UPLOAD_BYTES",
        "ICYLENS_INSPECTION_MIN_STRING_LENGTH",
        "ICYLENS_INSPECTION_MAX_STRINGS",
        "ICYLENS_INSPECTION_MAX_STRING_LENGTH",
        "ICYLENS_INSPECTION_MAX_INDICATORS",
        "ICYLENS_ML_INFERENCE_ENABLED",
        "ICYLENS_ML_DEMO_MODE_ENABLED",
        "ICYLENS_ML_MAX_CONCURRENT_INFERENCES",
        "ICYLENS_NVD_API_KEY",
        "ICYLENS_NVD_TIMEOUT_SECONDS",
        "ICYLENS_NVD_TOTAL_DEADLINE_SECONDS",
        "ICYLENS_NVD_MAX_RESPONSE_BYTES",
        "ICYLENS_NVD_MAX_CONCURRENCY",
        "ICYLENS_NVD_REQUESTS_PER_WINDOW",
        "ICYLENS_NVD_RATE_WINDOW_SECONDS",
        "ICYLENS_NVD_MAX_RETRIES",
        "ICYLENS_NVD_BACKOFF_SECONDS",
        "ICYLENS_NVD_MAX_RETRY_AFTER_SECONDS",
        "ICYLENS_VULNERABILITY_MAX_INVENTORY_BODY_BYTES",
        "ICYLENS_KEV_REFRESH_ON_STARTUP",
        "ICYLENS_KEV_TIMEOUT_SECONDS",
        "ICYLENS_KEV_TOTAL_DEADLINE_SECONDS",
        "ICYLENS_KEV_MAX_RESPONSE_BYTES",
        "ICYLENS_KEV_MAX_ENTRIES",
        "ICYLENS_KEV_MAX_CONCURRENCY",
        "ICYLENS_KEV_MAX_RETRIES",
        "ICYLENS_KEV_BACKOFF_SECONDS",
        "ICYLENS_KEV_MAX_RETRY_AFTER_SECONDS",
        "ICYLENS_KEV_FRESHNESS_SECONDS",
        "ICYLENS_EPSS_TIMEOUT_SECONDS",
        "ICYLENS_EPSS_TOTAL_DEADLINE_SECONDS",
        "ICYLENS_EPSS_MAX_RESPONSE_BYTES",
        "ICYLENS_EPSS_MAX_CONCURRENCY",
        "ICYLENS_EPSS_REQUESTS_PER_WINDOW",
        "ICYLENS_EPSS_RATE_WINDOW_SECONDS",
        "ICYLENS_EPSS_MAX_RETRIES",
        "ICYLENS_EPSS_BACKOFF_SECONDS",
        "ICYLENS_EPSS_MAX_RETRY_AFTER_SECONDS",
        "ICYLENS_EPSS_CACHE_TTL_SECONDS",
        "ICYLENS_EPSS_CACHE_MAX_ENTRIES",
        "ICYLENS_EPSS_CURRENT_MAX_AGE_DAYS",
        "ICYLENS_EPSS_STALE_MAX_AGE_DAYS",
        "ICYLENS_CORRELATION_TOTAL_DEADLINE_SECONDS",
        "ICYLENS_CORRELATION_MAX_CONCURRENCY",
        "ICYLENS_CORRELATION_MAX_RESPONSE_BYTES",
    }


def test_env_example_has_no_credential_fields() -> None:
    content = (API_ROOT / ".env.example").read_text(encoding="utf-8").lower()
    credential_markers = ("password", "secret", "token", "private_key")

    assert not any(marker in content for marker in credential_markers)
    assert "icylens_nvd_api_key=\n" in content
