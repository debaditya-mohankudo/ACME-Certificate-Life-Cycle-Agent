"""
LLM factory for the ACME Certificate Lifecycle Agent.

Centralises chat model construction so all nodes share one code path.
Provider is selected by LLM_PROVIDER in settings (anthropic | openai | ollama).

This module is only imported when LLM_DISABLED=False. To use LLM features,
install one of the optional extras:
    uv sync --extra llm-anthropic
    uv sync --extra llm-openai
    uv sync --extra llm-ollama
    uv sync --extra llm-all
"""
from __future__ import annotations

from typing import Any

from config import settings

try:
    from langchain.chat_models import init_chat_model
    from langchain_core.language_models.chat_models import BaseChatModel
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False
    init_chat_model = None  # type: ignore[assignment]
    BaseChatModel = object  # type: ignore[assignment,misc]


def _llm_kwargs_registry(provider: str, api_key: str, base_url: str, max_tokens: int) -> dict[str, Any]:
    """Return the kwargs dict for the given LLM provider."""
    registry: dict[str, Any] = {
        "anthropic": {
            "api_key": api_key,
            "max_tokens": max_tokens,
        },
        "openai": {
            "api_key": api_key,
            "max_tokens": max_tokens,
        },
        "ollama": {
            "base_url": base_url,
            "num_predict": max_tokens,
        },
    }
    if provider not in registry:
        raise ValueError(
            f"Unsupported LLM_PROVIDER: {provider!r}. "
            f"Must be one of: {', '.join(registry.keys())}"
        )
    return registry[provider]


def make_llm(model: str, max_tokens: int) -> "BaseChatModel":
    """Return a chat model for the configured LLM_PROVIDER.

    Raises ImportError if langchain packages are not installed.
    Install with:
        uv sync --extra llm-anthropic   (Anthropic / Claude)
        uv sync --extra llm-openai      (OpenAI)
        uv sync --extra llm-ollama      (local Ollama)
        uv sync --extra llm-all         (all providers)

    Or set LLM_DISABLED=true in .env to run without any LLM.
    """
    if not _LANGCHAIN_AVAILABLE:
        raise ImportError(
            "LLM packages are not installed. "
            "Install with: uv sync --extra llm-anthropic\n"
            "Or set LLM_DISABLED=true in .env to run without LLM."
        )

    provider = settings.LLM_PROVIDER

    # Validate required API keys
    if provider == "anthropic":
        if not settings.ANTHROPIC_API_KEY:
            raise ValueError(
                "ANTHROPIC_API_KEY must be set when LLM_PROVIDER='anthropic'. "
                "Add it to .env or set the environment variable."
            )
    elif provider == "openai":
        if not settings.OPENAI_API_KEY:
            raise ValueError(
                "OPENAI_API_KEY must be set when LLM_PROVIDER='openai'. "
                "Add it to .env or set the environment variable."
            )

    kwargs = _llm_kwargs_registry(
        provider=provider,
        api_key=settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY,
        base_url=settings.OLLAMA_BASE_URL,
        max_tokens=max_tokens,
    )
    return init_chat_model(model, model_provider=provider, **kwargs)
