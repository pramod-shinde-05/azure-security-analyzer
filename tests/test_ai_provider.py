import json
import pytest
from unittest.mock import patch, MagicMock
import urllib.error

from app.services.ai.gemini_provider import GeminiProvider
from app.services.ai.ollama_provider import OllamaProvider
from app.services.ai import get_ai_provider
from app.services.ai.provider import (
    AIAuthenticationError,
    AIRateLimitError,
    AIQuotaExceededError,
    AITimeoutError,
    AIValidationError,
    AIProviderError,
    AIModelNotFoundError,
    AIConnectionError
)

# -------------------------------------------------------------
# 1. Gemini Provider Tests
# -------------------------------------------------------------

def test_gemini_health_check_unconfigured():
    provider = GeminiProvider(api_key="", model_name="")
    check = provider.health_check()
    assert check["status"] == "unconfigured"
    assert "error" in check

def test_gemini_health_check_configured():
    provider = GeminiProvider(api_key="AIzaSyTestKey123", model_name="gemini-3.5-flash")
    check = provider.health_check()
    assert check["status"] == "configured"
    assert check["model"] == "gemini-3.5-flash"
    assert check["has_key"] is True
    assert "generativelanguage.googleapis.com" in check["base_url"]

def test_missing_api_key_raises_auth_error():
    provider = GeminiProvider(api_key="", model_name="gemini-3.5-flash")
    with pytest.raises(AIAuthenticationError) as exc_info:
        provider.generate_text_response("system", "user")
    assert "not configured" in str(exc_info.value)

def test_gemini_successful_structured_response():
    provider = GeminiProvider(api_key="AIzaSyTestKey", model_name="gemini-3.5-flash", max_retries=1)

    mock_llm_payload = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": json.dumps({
                                "attack_paths": [
                                    {"id": "path-1", "title": "Test Path", "risk": "HIGH"}
                                ]
                            })
                        }
                    ]
                }
            }
        ]
    }

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(mock_llm_payload).encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response):
        result = provider.generate_structured_response("System prompt", "User prompt")
        assert "attack_paths" in result
        assert len(result["attack_paths"]) == 1
        assert result["attack_paths"][0]["title"] == "Test Path"

def test_gemini_auth_error_401():
    provider = GeminiProvider(api_key="invalid_key", model_name="gemini-3.5-flash", max_retries=0)
    http_err = urllib.error.HTTPError("https://api", 401, "Unauthorized", {}, MagicMock(read=lambda: b"Invalid API key"))

    with patch("urllib.request.urlopen", side_effect=http_err):
        with pytest.raises(AIAuthenticationError):
            provider.generate_text_response("Sys", "User")

def test_gemini_quota_exceeded_429():
    provider = GeminiProvider(api_key="valid_key", model_name="gemini-3.5-flash", max_retries=0)
    err_body = json.dumps({"error": {"message": "Resource has been exhausted (e.g. check quota)."}}).encode("utf-8")
    http_err = urllib.error.HTTPError("https://api", 429, "Too Many Requests", {}, MagicMock(read=lambda: err_body))

    with patch("urllib.request.urlopen", side_effect=http_err):
        with pytest.raises(AIQuotaExceededError):
            provider.generate_structured_response("Sys", "User")

def test_gemini_timeout_error():
    provider = GeminiProvider(api_key="valid_key", model_name="gemini-3.5-flash", timeout_seconds=1, max_retries=0)
    url_err = urllib.error.URLError("timed out")

    with patch("urllib.request.urlopen", side_effect=url_err):
        with pytest.raises(AITimeoutError):
            provider.generate_text_response("Sys", "User")

def test_gemini_malformed_json_raises_validation_error():
    provider = GeminiProvider(api_key="valid_key", model_name="gemini-3.5-flash", max_retries=0)

    mock_llm_payload = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": "THIS IS NOT JSON AT ALL"}]
                }
            }
        ]
    }

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(mock_llm_payload).encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response):
        with pytest.raises(AIValidationError) as exc_info:
            provider.generate_structured_response("Sys", "User")
        assert "invalid JSON" in str(exc_info.value)

def test_gemini_model_not_found_fallback():
    # Tests that 404 triggers fallback from non-existent/pending model to working flash model
    provider = GeminiProvider(api_key="valid_key", model_name="gemini-nonexistent-future", max_retries=1)

    http_404 = urllib.error.HTTPError("https://api", 404, "Not Found", {}, MagicMock(read=lambda: b"models/gemini-nonexistent-future is not found"))
    success_payload = {
        "candidates": [{"content": {"parts": [{"text": "Fallback succeeded"}]}}]
    }
    mock_success = MagicMock()
    mock_success.read.return_value = json.dumps(success_payload).encode("utf-8")
    mock_success.__enter__.return_value = mock_success

    with patch("urllib.request.urlopen", side_effect=[http_404, mock_success]):
        result = provider.generate_text_response("Sys", "User")
        assert result == "Fallback succeeded"
        assert "gemini-2.0-flash" in provider.model_name or "gemini-1.5-flash" in provider.model_name

# -------------------------------------------------------------
# 2. Ollama Provider Tests
# -------------------------------------------------------------

def test_ollama_health_check_unconfigured():
    provider = OllamaProvider(base_url="", model_name="")
    check = provider.health_check()
    assert check["status"] == "unconfigured"
    assert "error" in check

def test_ollama_health_check_configured():
    provider = OllamaProvider(base_url="http://localhost:11434", model_name="llama3.2")
    tags_payload = {
        "models": [
            {"name": "llama3.2:latest"},
            {"name": "mistral:latest"}
        ]
    }
    with patch.object(provider, "_http_get_json", return_value=tags_payload):
        check = provider.health_check()
        assert check["status"] == "configured"
        assert "llama3.2" in check["model"]
        assert "llama3.2:latest" in check["installed_models"]

def test_ollama_health_check_model_missing():
    provider = OllamaProvider(base_url="http://localhost:11434", model_name="phi3")
    tags_payload = {
        "models": [
            {"name": "llama3.2:latest"}
        ]
    }
    with patch.object(provider, "_http_get_json", return_value=tags_payload):
        check = provider.health_check()
        assert check["status"] == "model_missing"
        assert "ollama pull phi3" in check["error"]

def test_ollama_health_check_daemon_offline():
    provider = OllamaProvider(base_url="http://localhost:11434", model_name="llama3.2")
    with patch.object(provider, "_http_get_json", side_effect=ConnectionRefusedError("Connection refused")):
        check = provider.health_check()
        assert check["status"] == "unavailable"
        assert "Ensure the Ollama daemon is running" in check["error"]

def test_ollama_successful_structured_response():
    provider = OllamaProvider(base_url="http://localhost:11434", model_name="llama3.2", max_retries=0)
    mock_chat_resp = {
        "model": "llama3.2",
        "message": {
            "role": "assistant",
            "content": json.dumps({"attack_paths": [{"id": "ollama-path-1", "risk": "HIGH"}]})
        },
        "done": True
    }
    with patch.object(provider, "_http_post_json", return_value=mock_chat_resp):
        result = provider.generate_structured_response("System prompt", "User prompt")
        assert "attack_paths" in result
        assert result["attack_paths"][0]["id"] == "ollama-path-1"

def test_ollama_text_response():
    provider = OllamaProvider(base_url="http://localhost:11434", model_name="llama3.2", max_retries=0)
    mock_chat_resp = {
        "model": "llama3.2",
        "message": {
            "role": "assistant",
            "content": "This is a local security explanation."
        },
        "done": True
    }
    with patch.object(provider, "_http_post_json", return_value=mock_chat_resp):
        text = provider.generate_text_response("Sys", "User")
        assert "local security explanation" in text

def test_ollama_model_not_found():
    provider = OllamaProvider(base_url="http://localhost:11434", model_name="nonexistent-model", max_retries=0)
    with patch.object(provider, "_http_post_json", side_effect=AIModelNotFoundError("Model not found")):
        with pytest.raises(AIModelNotFoundError):
            provider.generate_text_response("Sys", "User")

def test_ollama_timeout():
    provider = OllamaProvider(base_url="http://localhost:11434", model_name="llama3.2", max_retries=0)
    with patch.object(provider, "_http_post_json", side_effect=AITimeoutError("Timed out")):
        with pytest.raises(AITimeoutError):
            provider.generate_text_response("Sys", "User")

def test_ollama_malformed_json():
    provider = OllamaProvider(base_url="http://localhost:11434", model_name="llama3.2", max_retries=0)
    mock_bad_resp = {
        "model": "llama3.2",
        "message": {"role": "assistant", "content": "Not valid JSON at all"}
    }
    with patch.object(provider, "_http_post_json", return_value=mock_bad_resp):
        with pytest.raises(AIValidationError):
            provider.generate_structured_response("Sys", "User")

# -------------------------------------------------------------
# 3. Provider Switching & Factory Tests
# -------------------------------------------------------------

def test_provider_factory_switch_gemini():
    cfg = {
        "AI_ENABLED": True,
        "AI_PROVIDER": "gemini",
        "GEMINI_API_KEY": "AIzaSyTest123",
        "GEMINI_MODEL": "gemini-3.5-flash",
        "AI_REQUEST_TIMEOUT": 60,
        "AI_MAX_RETRIES": 2
    }
    provider = get_ai_provider(config=cfg)
    assert isinstance(provider, GeminiProvider)
    assert provider.model_name == "gemini-3.5-flash"

def test_provider_factory_switch_ollama():
    cfg = {
        "AI_ENABLED": True,
        "AI_PROVIDER": "ollama",
        "OLLAMA_BASE_URL": "http://127.0.0.1:11434",
        "OLLAMA_MODEL": "mistral",
        "AI_REQUEST_TIMEOUT": 60,
        "AI_MAX_RETRIES": 2
    }
    provider = get_ai_provider(config=cfg)
    assert isinstance(provider, OllamaProvider)
    assert provider.model_name == "mistral"
    assert provider.base_url == "http://127.0.0.1:11434"

def test_provider_factory_disabled():
    cfg = {
        "AI_ENABLED": False,
        "AI_PROVIDER": "gemini"
    }
    provider = get_ai_provider(config=cfg)
    assert provider is None

def test_provider_factory_missing_provider():
    cfg = {
        "AI_ENABLED": True,
        "AI_PROVIDER": ""
    }
    provider = get_ai_provider(config=cfg)
    assert provider is None
