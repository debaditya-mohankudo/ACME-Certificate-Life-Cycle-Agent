"""
Unit tests for LLM_DISABLED configuration flag.

Verifies:
- Config flag exists with correct default
- Flag can be set via environment variables
- Flag does not validate other LLM settings
"""
from __future__ import annotations

import os
import pytest
from pathlib import Path


def test_llm_disabled_default_is_true():
    """LLM_DISABLED defaults to True (deterministic mode, no LLM packages required)."""
    from config import Settings

    settings = Settings()
    assert settings.LLM_DISABLED is True


def test_llm_disabled_can_be_set_true(monkeypatch):
    """LLM_DISABLED can be set to True via environment variable."""
    monkeypatch.setenv("LLM_DISABLED", "true")
    from config import Settings

    settings = Settings()
    assert settings.LLM_DISABLED is True


def test_llm_disabled_can_be_set_false(monkeypatch):
    """LLM_DISABLED can be explicitly set to False."""
    monkeypatch.setenv("LLM_DISABLED", "false")
    from config import Settings

    settings = Settings()
    assert settings.LLM_DISABLED is False


def test_llm_disabled_case_insensitive(monkeypatch):
    """LLM_DISABLED is case-insensitive (Pydantic BaseSettings default)."""
    monkeypatch.setenv("llm_disabled", "True")
    from config import Settings

    settings = Settings()
    assert settings.LLM_DISABLED is True


def test_llm_disabled_from_env_file(tmp_path: Path):
    """LLM_DISABLED can be set in .env file."""
    env_file = tmp_path / ".env"
    env_file.write_text("LLM_DISABLED=true\n")

    from config import Settings
    from pydantic_settings import SettingsConfigDict

    # Create settings pointing to our test .env
    class TestSettings(Settings):
        model_config = SettingsConfigDict(
            env_file=str(env_file),
            env_file_encoding="utf-8",
            case_sensitive=False,
        )

    settings = TestSettings()
    assert settings.LLM_DISABLED is True


def test_llm_disabled_does_not_require_llm_provider():
    """When LLM_DISABLED=True, LLM_PROVIDER validation is not enforced."""
    from config import Settings

    # Even though LLM_PROVIDER might be invalid, if LLM_DISABLED=true,
    # it should not be accessed. Config should load without API key.
    settings = Settings(
        LLM_DISABLED=True,
        LLM_PROVIDER="anthropic",  # No API key set
    )
    assert settings.LLM_DISABLED is True
    assert settings.LLM_PROVIDER == "anthropic"


def test_llm_disabled_works_with_any_ca_provider():
    """LLM_DISABLED is independent of CA_PROVIDER selection."""
    from config import Settings

    for ca in ["digicert", "letsencrypt", "zerossl", "sectigo"]:
        settings = Settings(
            LLM_DISABLED=True,
            CA_PROVIDER=ca,
        )
        assert settings.LLM_DISABLED is True
        assert settings.CA_PROVIDER == ca


def test_llm_disabled_works_with_custom_ca_provider():
    """LLM_DISABLED works with custom CA provider (requires ACME_DIRECTORY_URL)."""
    from config import Settings

    settings = Settings(
        LLM_DISABLED=True,
        CA_PROVIDER="custom",
        ACME_DIRECTORY_URL="https://custom-acme.example.com/directory",
    )
    assert settings.LLM_DISABLED is True
    assert settings.CA_PROVIDER == "custom"


def test_llm_disabled_works_with_standalone_challenge_mode(tmp_path):
    """LLM_DISABLED is independent of challenge mode (standalone)."""
    from config import Settings

    settings = Settings(
        LLM_DISABLED=True,
        HTTP_CHALLENGE_MODE="standalone",
    )
    assert settings.LLM_DISABLED is True
    assert settings.HTTP_CHALLENGE_MODE == "standalone"


def test_llm_disabled_works_with_webroot_challenge_mode(tmp_path):
    """LLM_DISABLED is independent of challenge mode (webroot)."""
    from config import Settings

    webroot = tmp_path / "webroot"
    webroot.mkdir()

    settings = Settings(
        LLM_DISABLED=True,
        HTTP_CHALLENGE_MODE="webroot",
        WEBROOT_PATH=str(webroot),
    )
    assert settings.LLM_DISABLED is True
    assert settings.HTTP_CHALLENGE_MODE == "webroot"


def test_llm_disabled_is_boolean_type():
    """LLM_DISABLED field is strictly boolean."""
    from config import Settings

    # Valid boolean values
    for val in [True, False, "true", "false", "1", "0"]:
        settings = Settings(LLM_DISABLED=val)
        assert isinstance(settings.LLM_DISABLED, bool)


def test_llm_disabled_invalid_value_fails():
    """Invalid boolean values are rejected."""
    from config import Settings
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Settings(LLM_DISABLED="maybe")  # Invalid boolean


def test_llm_disabled_env_override_beats_default(monkeypatch):
    """Environment variable overrides default value."""
    monkeypatch.setenv("LLM_DISABLED", "true")

    from config import Settings

    settings = Settings()
    assert settings.LLM_DISABLED is True


def test_llm_disabled_with_other_llm_settings(monkeypatch):
    """LLM_DISABLED can coexist with other LLM settings without conflict."""
    monkeypatch.setenv("LLM_DISABLED", "true")
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_MODEL_PLANNER", "claude-haiku-4-5-20251001")

    from config import Settings

    settings = Settings()
    assert settings.LLM_DISABLED is True
    assert settings.LLM_PROVIDER == "anthropic"
    assert settings.LLM_MODEL_PLANNER == "claude-haiku-4-5-20251001"


def test_llm_disabled_singleton_mutation(pebble_settings):
    """LLM_DISABLED can be mutated on the singleton in tests."""
    assert pebble_settings.LLM_DISABLED is True  # default is True

    pebble_settings.LLM_DISABLED = False
    assert pebble_settings.LLM_DISABLED is False

    pebble_settings.LLM_DISABLED = True
    assert pebble_settings.LLM_DISABLED is True


def test_llm_disabled_accepts_yes_no_strings(monkeypatch):
    """LLM_DISABLED accepts 'yes'/'no' strings."""
    from config import Settings

    for yes_val in ["yes", "YES", "Yes"]:
        monkeypatch.setenv("LLM_DISABLED", yes_val)
        settings = Settings()
        assert settings.LLM_DISABLED is True

    for no_val in ["no", "NO", "No"]:
        monkeypatch.setenv("LLM_DISABLED", no_val)
        settings = Settings()
        assert settings.LLM_DISABLED is False


def test_llm_disabled_accepts_on_off_strings(monkeypatch):
    """LLM_DISABLED accepts 'on'/'off' strings."""
    from config import Settings

    monkeypatch.setenv("LLM_DISABLED", "on")
    settings = Settings()
    assert settings.LLM_DISABLED is True

    monkeypatch.setenv("LLM_DISABLED", "off")
    settings = Settings()
    assert settings.LLM_DISABLED is False


def test_llm_disabled_validator_rejects_invalid_strings():
    """LLM_DISABLED validator rejects nonsense strings."""
    from config import Settings
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc_info:
        Settings(LLM_DISABLED="maybe")

    assert "must be a boolean" in str(exc_info.value).lower()


def test_llm_disabled_validator_accepts_int_0_and_1():
    """LLM_DISABLED validator accepts integer 0 and 1."""
    from config import Settings

    settings = Settings(LLM_DISABLED=1)
    assert settings.LLM_DISABLED is True

    settings = Settings(LLM_DISABLED=0)
    assert settings.LLM_DISABLED is False


def test_llm_disabled_int_with_whitespace(monkeypatch):
    """LLM_DISABLED handles string integers with whitespace."""
    from config import Settings

    monkeypatch.setenv("LLM_DISABLED", "  1  ")
    settings = Settings()
    assert settings.LLM_DISABLED is True

    monkeypatch.setenv("LLM_DISABLED", "  0  ")
    settings = Settings()
    assert settings.LLM_DISABLED is False
