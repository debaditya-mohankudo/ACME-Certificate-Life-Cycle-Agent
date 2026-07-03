"""
LLM factory for the ACME Certificate Lifecycle Agent.

Centralises chat model construction so all nodes share one code path.
Provider is selected by LLM_PROVIDER in settings (claude_cli | anthropic | openai | ollama).

claude_cli is the default: it shells to `claude -p --safe-mode --tools none`,
reusing the caller's existing Claude Code OAuth login — no API key, no
`uv sync --extra llm-*` install required. The other three providers go
through langchain and are only usable once LLM_DISABLED=False *and* the
matching optional extra is installed:
    uv sync --extra llm-anthropic
    uv sync --extra llm-openai
    uv sync --extra llm-ollama
    uv sync --extra llm-all
"""
from __future__ import annotations

import json
import shutil
import subprocess
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


class _ClaudeCLIResponse:
    """Minimal stand-in for a langchain AIMessage — callers only read .content."""

    def __init__(self, content: str):
        self.content = content


class ClaudeCLIChatModel:
    """Shells out to `claude -p` per call instead of using an API/SDK.

    Reuses the caller's existing Claude Code login (OAuth/keychain) — no
    ANTHROPIC_API_KEY and no langchain install required. Tools are explicitly
    disabled (--tools none): this is a plain text-completion call, not an
    agentic session. Always passes --safe-mode (skips CLAUDE.md/hooks/
    plugins/MCP for lower per-call token overhead).
    """

    def __init__(self, model: str = "haiku", timeout: int = 120):
        self._model = model
        self._claude_path = shutil.which("claude")
        if not self._claude_path:
            raise RuntimeError("claude_cli provider: `claude` binary not found on PATH")
        self._timeout = timeout

    def invoke(self, messages: list) -> _ClaudeCLIResponse:
        system = ""
        user_parts: list[str] = []
        for m in messages:
            role = getattr(m, "type", "") or m.__class__.__name__.lower()
            content = getattr(m, "content", "")
            if "system" in role:
                system = content
            else:
                user_parts.append(content)
        user = "\n\n".join(user_parts)

        cmd = [
            self._claude_path, "-p",
            "--safe-mode",
            "--output-format", "json",
            "--tools", "none",
            "--model", self._model,
        ]
        if system:
            cmd += ["--append-system-prompt", system]

        proc = subprocess.run(
            cmd, input=user, capture_output=True, text=True, timeout=self._timeout,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"claude CLI exited {proc.returncode}: {proc.stderr[:500]}")

        data = json.loads(proc.stdout)
        if data.get("is_error"):
            raise RuntimeError(f"claude CLI reported an error: {data.get('result')}")
        return _ClaudeCLIResponse(data["result"])


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

    claude_cli needs no langchain install and no API key. The other three
    providers raise ImportError if langchain packages are not installed.
    Install with:
        uv sync --extra llm-anthropic   (Anthropic / Claude, via API)
        uv sync --extra llm-openai      (OpenAI)
        uv sync --extra llm-ollama      (local Ollama)
        uv sync --extra llm-all         (all providers)

    Or set LLM_DISABLED=true in .env to run without any LLM.
    """
    provider = settings.LLM_PROVIDER

    if provider == "claude_cli":
        return ClaudeCLIChatModel(model=model)  # type: ignore[return-value]

    if not _LANGCHAIN_AVAILABLE:
        raise ImportError(
            "LLM packages are not installed. "
            "Install with: uv sync --extra llm-anthropic\n"
            "Or set LLM_PROVIDER=claude_cli to use the claude CLI instead (no install needed).\n"
            "Or set LLM_DISABLED=true in .env to run without LLM."
        )

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
