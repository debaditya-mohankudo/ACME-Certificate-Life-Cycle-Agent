"""Tests for llm/factory.py registry pattern and the claude_cli provider."""
import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from llm.factory import ClaudeCLIChatModel, _llm_kwargs_registry, make_llm


class TestLlmKwargsRegistry:
    """Test _llm_kwargs_registry function."""

    def test_anthropic_kwargs(self):
        """Anthropic provider returns api_key and max_tokens."""
        kwargs = _llm_kwargs_registry(
            provider="anthropic",
            api_key="test-api-key",
            base_url="http://unused",
            max_tokens=2048,
        )
        assert kwargs == {
            "api_key": "test-api-key",
            "max_tokens": 2048,
        }

    def test_openai_kwargs(self):
        """OpenAI provider returns api_key and max_tokens."""
        kwargs = _llm_kwargs_registry(
            provider="openai",
            api_key="sk-test-key",
            base_url="http://unused",
            max_tokens=4096,
        )
        assert kwargs == {
            "api_key": "sk-test-key",
            "max_tokens": 4096,
        }

    def test_ollama_kwargs(self):
        """Ollama provider returns base_url and num_predict (not max_tokens)."""
        kwargs = _llm_kwargs_registry(
            provider="ollama",
            api_key="",  # unused for ollama
            base_url="http://localhost:11434",
            max_tokens=512,
        )
        assert kwargs == {
            "base_url": "http://localhost:11434",
            "num_predict": 512,
        }

    def test_ollama_ignores_api_key(self):
        """Ollama provider does not include api_key even if provided."""
        kwargs = _llm_kwargs_registry(
            provider="ollama",
            api_key="should-be-ignored",
            base_url="http://localhost:11434",
            max_tokens=512,
        )
        assert "api_key" not in kwargs
        assert "max_tokens" not in kwargs
        assert kwargs == {
            "base_url": "http://localhost:11434",
            "num_predict": 512,
        }

    def test_unknown_provider_raises_error(self):
        """Unknown LLM_PROVIDER raises ValueError with helpful message."""
        with pytest.raises(ValueError) as exc_info:
            _llm_kwargs_registry(
                provider="unknown-ai",
                api_key="key",
                base_url="http://localhost",
                max_tokens=1024,
            )
        assert "Unsupported LLM_PROVIDER: 'unknown-ai'" in str(exc_info.value)
        assert "anthropic" in str(exc_info.value)
        assert "openai" in str(exc_info.value)
        assert "ollama" in str(exc_info.value)

    def test_case_sensitive_provider_names(self):
        """Provider names are case-sensitive (must be lowercase)."""
        with pytest.raises(ValueError):
            _llm_kwargs_registry(
                provider="Anthropic",
                api_key="key",
                base_url="http://localhost",
                max_tokens=1024,
            )

    def test_max_tokens_respected(self):
        """Different max_tokens values are correctly passed through."""
        for max_tokens in [256, 1024, 4096, 8192]:
            kwargs = _llm_kwargs_registry(
                provider="anthropic",
                api_key="key",
                base_url="http://unused",
                max_tokens=max_tokens,
            )
            assert kwargs["max_tokens"] == max_tokens

    def test_api_key_preserved_exactly(self):
        """API key is passed through without modification."""
        api_keys = [
            "simple-key",
            "key-with-dashes",
            "key_with_underscores",
            "sk-proj-abc123xyz789",
        ]
        for api_key in api_keys:
            kwargs = _llm_kwargs_registry(
                provider="anthropic",
                api_key=api_key,
                base_url="http://unused",
                max_tokens=1024,
            )
            assert kwargs["api_key"] == api_key

    def test_base_url_preserved_exactly(self):
        """Base URL is passed through without modification."""
        base_urls = [
            "http://localhost:11434",
            "http://192.168.1.1:5000",
            "https://custom-ollama.example.com",
        ]
        for base_url in base_urls:
            kwargs = _llm_kwargs_registry(
                provider="ollama",
                api_key="",
                base_url=base_url,
                max_tokens=1024,
            )
            assert kwargs["base_url"] == base_url


class TestClaudeCLIChatModel:
    """Test ClaudeCLIChatModel — the default, no-API-key LLM provider."""

    def _mock_completed_process(self, result_text: str, is_error: bool = False, returncode: int = 0):
        payload = {"result": result_text, "is_error": is_error}
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=json.dumps(payload), stderr="",
        )

    def test_requires_claude_binary_on_path(self):
        with patch("llm.factory.shutil.which", return_value=None):
            with pytest.raises(RuntimeError, match="claude.*binary not found"):
                ClaudeCLIChatModel()

    def test_invoke_builds_expected_command(self):
        with patch("llm.factory.shutil.which", return_value="/usr/local/bin/claude"):
            model = ClaudeCLIChatModel(model="haiku")

        with patch("llm.factory.subprocess.run") as mock_run:
            mock_run.return_value = self._mock_completed_process("ok")
            from langchain_core.messages import HumanMessage, SystemMessage
            model.invoke([SystemMessage(content="be terse"), HumanMessage(content="hello")])

        cmd = mock_run.call_args.args[0]
        assert cmd[0] == "/usr/local/bin/claude"
        assert "-p" in cmd
        assert "--safe-mode" in cmd
        assert "--tools" in cmd and cmd[cmd.index("--tools") + 1] == "none"
        assert "--model" in cmd and cmd[cmd.index("--model") + 1] == "haiku"
        assert "--append-system-prompt" in cmd and cmd[cmd.index("--append-system-prompt") + 1] == "be terse"
        assert mock_run.call_args.kwargs["input"] == "hello"

    def test_invoke_returns_response_with_content_attribute(self):
        with patch("llm.factory.shutil.which", return_value="/usr/local/bin/claude"):
            model = ClaudeCLIChatModel()

        with patch("llm.factory.subprocess.run") as mock_run:
            mock_run.return_value = self._mock_completed_process('{"urgent": ["a.com"]}')
            from langchain_core.messages import HumanMessage
            response = model.invoke([HumanMessage(content="classify")])

        assert response.content == '{"urgent": ["a.com"]}'

    def test_invoke_raises_on_nonzero_exit(self):
        with patch("llm.factory.shutil.which", return_value="/usr/local/bin/claude"):
            model = ClaudeCLIChatModel()

        with patch("llm.factory.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="boom",
            )
            from langchain_core.messages import HumanMessage
            with pytest.raises(RuntimeError, match="claude CLI exited 1"):
                model.invoke([HumanMessage(content="x")])

    def test_invoke_raises_on_is_error_flag(self):
        with patch("llm.factory.shutil.which", return_value="/usr/local/bin/claude"):
            model = ClaudeCLIChatModel()

        with patch("llm.factory.subprocess.run") as mock_run:
            mock_run.return_value = self._mock_completed_process("refused", is_error=True)
            from langchain_core.messages import HumanMessage
            with pytest.raises(RuntimeError, match="claude CLI reported an error"):
                model.invoke([HumanMessage(content="x")])


class TestMakeLLMClaudeCLIRouting:
    """make_llm() must route claude_cli without touching langchain at all."""

    def test_make_llm_routes_to_claude_cli_without_langchain(self):
        with patch("llm.factory.settings") as mock_settings:
            mock_settings.LLM_PROVIDER = "claude_cli"
            with patch("llm.factory._LANGCHAIN_AVAILABLE", False):
                with patch("llm.factory.shutil.which", return_value="/usr/local/bin/claude"):
                    result = make_llm(model="haiku", max_tokens=512)

        assert isinstance(result, ClaudeCLIChatModel)

    def test_make_llm_claude_cli_needs_no_api_key(self):
        with patch("llm.factory.settings") as mock_settings:
            mock_settings.LLM_PROVIDER = "claude_cli"
            mock_settings.ANTHROPIC_API_KEY = ""
            mock_settings.OPENAI_API_KEY = ""
            with patch("llm.factory.shutil.which", return_value="/usr/local/bin/claude"):
                # Should not raise, unlike the anthropic/openai branches which
                # require an API key.
                make_llm(model="haiku", max_tokens=512)
