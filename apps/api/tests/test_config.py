import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import ENV_FILE, Settings, get_settings
from app.core.logging import HANDLER_NAME, configure_logging
from app.main import create_app

pytestmark = pytest.mark.unit


def test_default_settings_without_env_file() -> None:
    settings = Settings(_env_file=None)

    assert settings.APP_NAME == "iCYLENS API"
    assert settings.APP_VERSION == "0.4.1"
    assert settings.APP_ENV == "development"
    assert settings.DEBUG is False
    assert settings.API_V1_PREFIX == "/api/v1"
    assert settings.LOG_LEVEL == "INFO"
    assert settings.MAX_UPLOAD_BYTES == 10 * 1024 * 1024
    assert settings.INSPECTION_MIN_STRING_LENGTH == 4
    assert settings.INSPECTION_MAX_STRINGS == 100
    assert settings.INSPECTION_MAX_STRING_LENGTH == 256
    assert settings.INSPECTION_MAX_INDICATORS == 100


def test_environment_variables_override_env_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        'ICYLENS_APP_NAME="File name"\nICYLENS_APP_VERSION="1.0.0"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("ICYLENS_APP_NAME", "Environment name")

    settings = Settings(_env_file=env_file)

    assert settings.APP_NAME == "Environment name"
    assert settings.APP_VERSION == "1.0.0"


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [("true", True), ("1", True), ("false", False), ("0", False)],
)
def test_boolean_environment_conversion(
    monkeypatch: pytest.MonkeyPatch,
    raw_value: str,
    expected: bool,
) -> None:
    monkeypatch.setenv("ICYLENS_DEBUG", raw_value)

    assert Settings(_env_file=None).DEBUG is expected


def test_invalid_application_environment_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(APP_ENV="staging", _env_file=None)


@pytest.mark.parametrize("maximum", [0, -1, 1024 * 1024 * 1024 + 1])
def test_invalid_upload_limit_is_rejected(maximum: int) -> None:
    with pytest.raises(ValidationError):
        Settings(MAX_UPLOAD_BYTES=maximum, _env_file=None)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("INSPECTION_MIN_STRING_LENGTH", 0),
        ("INSPECTION_MIN_STRING_LENGTH", 257),
        ("INSPECTION_MAX_STRINGS", 0),
        ("INSPECTION_MAX_STRINGS", 1001),
        ("INSPECTION_MAX_STRING_LENGTH", 0),
        ("INSPECTION_MAX_STRING_LENGTH", 4097),
        ("INSPECTION_MAX_INDICATORS", 0),
        ("INSPECTION_MAX_INDICATORS", 1001),
    ],
)
def test_invalid_inspection_limits_are_rejected(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: value}, _env_file=None)


def test_string_maximum_must_cover_minimum() -> None:
    with pytest.raises(ValidationError, match="must be greater than or equal"):
        Settings(
            INSPECTION_MIN_STRING_LENGTH=10,
            INSPECTION_MAX_STRING_LENGTH=9,
            _env_file=None,
        )


def test_invalid_boolean_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(DEBUG="definitely-not-a-boolean", _env_file=None)


def test_invalid_log_level_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(LOG_LEVEL="TRACE", _env_file=None)


def test_blank_application_name_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(APP_NAME="   ", _env_file=None)


@pytest.mark.parametrize("prefix", ["api/v1", "/api/v1/"])
def test_invalid_api_prefix_is_rejected(prefix: str) -> None:
    with pytest.raises(ValidationError):
        Settings(API_V1_PREFIX=prefix, _env_file=None)


def test_log_level_is_normalized() -> None:
    settings = Settings(LOG_LEVEL="warning", _env_file=None)

    assert settings.LOG_LEVEL == "WARNING"


def test_production_rejects_debug_mode() -> None:
    with pytest.raises(ValidationError, match="DEBUG must be disabled"):
        Settings(APP_ENV="production", DEBUG=True, _env_file=None)


def test_production_accepts_disabled_debug_mode() -> None:
    settings = Settings(APP_ENV="production", DEBUG=False, _env_file=None)

    assert settings.APP_ENV == "production"
    assert settings.DEBUG is False


def test_production_rejects_debug_mode_from_env_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        'ICYLENS_APP_ENV="production"\nICYLENS_DEBUG="true"\n',
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="DEBUG must be disabled"):
        Settings(_env_file=env_file)


@pytest.mark.integration
def test_fastapi_uses_injected_name_version_prefix_and_debug() -> None:
    settings = Settings(
        APP_NAME="Configured API",
        APP_VERSION="2.1.0",
        APP_ENV="testing",
        DEBUG=True,
        API_V1_PREFIX="/custom/v1",
        _env_file=None,
    )
    application = create_app(settings)
    client = TestClient(application)

    health = client.get("/custom/v1/health/")

    assert application.title == "Configured API"
    assert application.version == "2.1.0"
    assert application.debug is True
    assert health.status_code == 200
    assert health.json()["service"] == "Configured API"
    assert health.json()["version"] == "2.1.0"


@pytest.mark.integration
def test_default_application_preserves_existing_endpoints() -> None:
    application = create_app(Settings(_env_file=None))
    client = TestClient(application)

    assert client.get("/api/v1/health/").status_code == 200
    assert client.get("/docs").status_code == 200
    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200
    assert application.version == "0.4.1"
    assert openapi.json()["info"]["version"] == "0.4.1"
    assert (
        client.post(
            "/api/v1/analyses/validate",
            json={"filename": "sample.bin"},
        ).status_code
        == 200
    )


def test_settings_cache_can_be_isolated_between_tests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controlled_environment = {
        "ICYLENS_APP_NAME": "Initial API",
        "ICYLENS_APP_VERSION": "0.4.1",
        "ICYLENS_APP_ENV": "testing",
        "ICYLENS_DEBUG": "false",
        "ICYLENS_API_V1_PREFIX": "/api/v1",
        "ICYLENS_LOG_LEVEL": "INFO",
        "ICYLENS_MAX_UPLOAD_BYTES": "10485760",
    }
    for variable, value in controlled_environment.items():
        monkeypatch.setenv(variable, value)

    first = get_settings()
    monkeypatch.setenv("ICYLENS_APP_NAME", "Reloaded API")

    assert get_settings() is first

    get_settings.cache_clear()
    assert get_settings().APP_NAME == "Reloaded API"


def test_env_file_path_is_stable() -> None:
    expected = Path(__file__).resolve().parents[1] / ".env"

    assert ENV_FILE == expected


def test_unknown_env_file_values_are_ignored(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("UNRELATED_VALUE=ignored\n", encoding="utf-8")

    settings = Settings(_env_file=env_file)

    assert settings.APP_NAME == "iCYLENS API"


def test_logging_configuration_does_not_duplicate_handlers() -> None:
    logger = configure_logging("INFO")
    configure_logging("DEBUG")
    managed_handlers = [
        handler for handler in logger.handlers if handler.get_name() == HANDLER_NAME
    ]

    assert logger.level == logging.DEBUG
    assert len(managed_handlers) == 1
    assert managed_handlers[0].level == logging.DEBUG
