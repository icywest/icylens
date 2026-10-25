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
    }


def test_env_example_has_no_credential_fields() -> None:
    content = (API_ROOT / ".env.example").read_text(encoding="utf-8").lower()
    credential_markers = ("password", "secret", "token", "api_key", "private_key")

    assert not any(marker in content for marker in credential_markers)
