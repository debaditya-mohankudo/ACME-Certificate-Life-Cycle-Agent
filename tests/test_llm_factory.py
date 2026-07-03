"""Tests for llm/factory.py registry pattern."""
import pytest

from llm.factory import _llm_kwargs_registry


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
