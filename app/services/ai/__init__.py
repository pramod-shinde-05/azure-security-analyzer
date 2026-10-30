import os
from pathlib import Path
from typing import Optional, Any
from flask import current_app

from app.services.ai.provider import (
    BaseAIProvider,
    AIProviderError,
    AIAuthenticationError,
    AIRateLimitError,
    AIQuotaExceededError,
    AITimeoutError,
    AIValidationError
)
from app.services.ai.gemini_provider import GeminiProvider
from app.services.ai.ollama_provider import OllamaProvider
from app.services.ai.context_builder import AIContextBuilder
from app.services.ai.response_validator import AIResponseValidator
from app.services.ai.cache import AIResponseCache

_global_cache: Optional[AIResponseCache] = None

def _find_env_path() -> Optional[Path]:
    """Finds .env file by traversing up from the current file directory."""
    curr = Path(__file__).resolve()
    for parent in [curr] + list(curr.parents):
        candidate = parent / '.env'
        if candidate.is_file():
            return candidate
    return None

def _get_env_val(key: str, default: str = "") -> str:
    """Reads a configuration variable strictly from os.environ or directly from .env file."""
    val = os.environ.get(key)
    if val is not None and val.strip() != "":
        return val.strip()

    env_path = _find_env_path()
    if env_path:
        try:
            with open(env_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        k, v = line.split('=', 1)
                        if k.strip() == key:
                            cleaned_v = v.strip().strip("'\"")
                            if cleaned_v:
                                os.environ[key] = cleaned_v
                                return cleaned_v
        except Exception:
            pass

    return default

def get_ai_cache() -> AIResponseCache:
    """Returns singleton AI cache instance configured from Flask app or settings."""
    global _global_cache
    if _global_cache is None:
        cache_dir = None
        enabled = True
        ttl = 3600
        try:
            if current_app:
                cfg = current_app.config
                cache_dir = os.path.join(cfg.get('UPLOAD_FOLDER', 'instance'), 'ai_cache')
                enabled = cfg.get('AI_CACHE_ENABLED', True)
                ttl = cfg.get('AI_CACHE_TTL_SECONDS', 3600)
        except RuntimeError:
            pass
        _global_cache = AIResponseCache(cache_dir=cache_dir, ttl_seconds=ttl, enabled=enabled)
    return _global_cache

def get_ai_provider(config: Optional[dict] = None) -> Optional[BaseAIProvider]:
    """
    Factory creating configured AI provider instance.
    All secrets, keys, and models are imported strictly from .env without hardcoded dummy defaults.
    Returns GeminiProvider or OllamaProvider based on AI_PROVIDER, or None if disabled/unconfigured.
    """
    cfg = config
    if cfg is None:
        try:
            if current_app:
                cfg = current_app.config
        except RuntimeError:
            pass

    def _lookup(key: str, default: str = "") -> str:
        if cfg is not None and key in cfg:
            val = cfg.get(key)
            if val is not None and str(val).strip() != "":
                return str(val).strip()
        return _get_env_val(key, default=default)

    ai_enabled_raw = _lookup("AI_ENABLED", "true")
    if isinstance(ai_enabled_raw, bool):
        ai_enabled = ai_enabled_raw
    else:
        ai_enabled = str(ai_enabled_raw).lower() in ("true", "1", "yes")

    if not ai_enabled:
        return None

    provider_name = _lookup("AI_PROVIDER", "").lower()
    if not provider_name:
        return None

    timeout = int(_lookup("AI_REQUEST_TIMEOUT", "60"))
    retries = int(_lookup("AI_MAX_RETRIES", "2"))

    if provider_name == "gemini":
        api_key = _lookup("GEMINI_API_KEY", "")
        model_name = _lookup("GEMINI_MODEL", "")
        return GeminiProvider(
            api_key=api_key,
            model_name=model_name,
            timeout_seconds=timeout,
            max_retries=retries
        )

    elif provider_name == "ollama":
        base_url = _lookup("OLLAMA_BASE_URL", "")
        model_name = _lookup("OLLAMA_MODEL", "")
        return OllamaProvider(
            base_url=base_url,
            model_name=model_name,
            timeout_seconds=timeout,
            max_retries=retries
        )

    return None
