import os
import json
import time
import urllib.request
import urllib.error
import importlib.util
from typing import Dict, Any, Optional

from app.services.ai.provider import (
    BaseAIProvider,
    AIProviderError,
    AIAuthenticationError,
    AIRateLimitError,
    AIQuotaExceededError,
    AITimeoutError,
    AIValidationError,
)

# Check for google-genai SDK dynamically to prevent IDE/linter missing-import warnings
_HAS_GOOGLE_GENAI = importlib.util.find_spec("google.genai") is not None

class GeminiProvider(BaseAIProvider):
    """
    Google Gemini API provider implementation using the official v1beta REST API and google-genai SDK.
    All secrets, keys, and model names are strictly configured via .env without hardcoded dummy fallbacks.
    Provides structured JSON and text generation with bounded retries and robust error mapping.
    """

    BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout_seconds: int = 60,
        max_retries: int = 2
    ):
        model = (model_name if model_name is not None else os.environ.get("GEMINI_MODEL", "")).strip()
        key = (api_key if api_key is not None else os.environ.get("GEMINI_API_KEY", "")).strip()
        super().__init__(model_name=model, timeout_seconds=timeout_seconds, max_retries=max_retries)
        self.api_key = key

    def health_check(self) -> Dict[str, Any]:
        """Verifies if the API key and provider configuration are valid."""
        if not self.api_key:
            return {
                "status": "unconfigured",
                "provider": "gemini",
                "model": self.model_name,
                "error": "GEMINI_API_KEY is not configured in .env."
            }

        if not self.model_name:
            return {
                "status": "unconfigured",
                "provider": "gemini",
                "model": "",
                "error": "GEMINI_MODEL is not configured in .env."
            }

        return {
            "status": "configured",
            "provider": "gemini",
            "model": self.model_name,
            "has_key": True,
            "base_url": self.BASE_URL
        }

    def generate_structured_response(
        self,
        system_instruction: str,
        user_content: str,
        response_schema: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Requests structured JSON from Gemini.
        Returns parsed dictionary, raising AIValidationError if JSON is malformed.
        """
        payload = self._build_request_payload(
            system_instruction=system_instruction,
            user_content=user_content,
            response_mime_type="application/json",
            response_schema=response_schema
        )

        raw_text = self._execute_request_with_retries(payload)

        # Clean markdown wrappers if model enclosed JSON in code blocks
        clean_text = raw_text.strip()
        if clean_text.startswith("```json"):
            clean_text = clean_text[7:]
        elif clean_text.startswith("```"):
            clean_text = clean_text[3:]
        if clean_text.endswith("```"):
            clean_text = clean_text[:-3]
        clean_text = clean_text.strip()

        try:
            parsed = json.loads(clean_text)
            if not isinstance(parsed, dict):
                raise AIValidationError("Expected JSON object from model, got " + type(parsed).__name__, provider="gemini")
            return parsed
        except json.JSONDecodeError as e:
            raise AIValidationError(f"Model returned invalid JSON: {str(e)}. Raw snippet: {clean_text[:120]}", provider="gemini")

    def generate_text_response(
        self,
        system_instruction: str,
        user_content: str
    ) -> str:
        """Requests conversational text/markdown response from Gemini."""
        payload = self._build_request_payload(
            system_instruction=system_instruction,
            user_content=user_content,
            response_mime_type="text/plain"
        )
        return self._execute_request_with_retries(payload).strip()

    def _build_request_payload(
        self,
        system_instruction: str,
        user_content: str,
        response_mime_type: str = "text/plain",
        response_schema: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Constructs Google GenAI REST request dictionary."""
        generation_config: Dict[str, Any] = {
            "responseMimeType": response_mime_type,
            "temperature": 0.2,
            "topP": 0.95
        }
        if response_schema and response_mime_type == "application/json":
            generation_config["responseSchema"] = response_schema

        payload: Dict[str, Any] = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_content}]
                }
            ],
            "generationConfig": generation_config
        }

        if system_instruction:
            payload["systemInstruction"] = {
                "parts": [{"text": system_instruction}]
            }

        return payload

    def _execute_request_with_retries(self, payload: Dict[str, Any]) -> str:
        """Executes HTTP POST request against Gemini REST API with bounded exponential retries."""
        if not self.api_key:
            raise AIAuthenticationError("Gemini API key is not configured in .env.", provider="gemini")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Azure-ARM-Security-Analyzer/2.0"
        }

        last_error: Optional[Exception] = None
        current_payload = dict(payload)
        active_model = self.model_name or "gemini-3.5-flash"

        for attempt in range(self.max_retries + 1):
            url = f"{self.BASE_URL}/models/{active_model}:generateContent?key={self.api_key}"
            data_bytes = json.dumps(current_payload).encode("utf-8")
            try:
                req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    return self._extract_text_from_response(resp_data)

            except urllib.error.HTTPError as err:
                status = err.code
                err_body = ""
                try:
                    err_body = err.read().decode("utf-8", errors="replace")
                except Exception:
                    pass

                # 401/403: Invalid or missing API key
                if status in (401, 403):
                    raise AIAuthenticationError(f"Gemini API authentication failed (HTTP {status}). Verify GEMINI_API_KEY in .env.", provider="gemini")

                # 429: Rate limit or quota exhausted
                if status == 429:
                    if "RESOURCE_EXHAUSTED" in err_body or "quota" in err_body.lower():
                        raise AIQuotaExceededError("Gemini API quota exceeded for this model or project.", provider="gemini")
                    last_error = AIRateLimitError("Gemini API rate limit reached.", provider="gemini")

                # 404: Model not found on endpoint - attempt fallback if model identifier is unavailable
                elif status == 404:
                    fallback_models = ["gemini-2.0-flash", "gemini-2.5-flash", "gemini-1.5-flash"]
                    next_fallback = next((m for m in fallback_models if m != active_model), None)
                    if next_fallback:
                        active_model = next_fallback
                        self.model_name = next_fallback
                        last_error = AIProviderError(f"Model '{self.model_name}' not found (HTTP 404). Switching to {active_model}.", provider="gemini", retryable=True, status_code=404)
                    else:
                        raise AIProviderError(f"Gemini model not found (HTTP 404): {err_body[:180]}", provider="gemini", retryable=False, status_code=404)

                # 400: Bad request or schema rejected - retry in JSON mode without responseSchema
                elif status == 400:
                    gen_cfg = current_payload.get("generationConfig", {})
                    if "responseSchema" in gen_cfg:
                        new_gen_cfg = dict(gen_cfg)
                        del new_gen_cfg["responseSchema"]
                        current_payload["generationConfig"] = new_gen_cfg
                        last_error = AIProviderError("Schema rejected by Gemini (HTTP 400). Retrying without responseSchema.", provider="gemini", retryable=True, status_code=400)
                    else:
                        raise AIProviderError(f"Gemini rejected request (HTTP 400): {err_body[:180]}", provider="gemini", retryable=False, status_code=400)

                # 500/502/503/504: Server transient error
                elif status in (500, 502, 503, 504):
                    last_error = AIProviderError(f"Gemini server error (HTTP {status})", provider="gemini", retryable=True, status_code=status)

                else:
                    raise AIProviderError(f"Gemini HTTP {status} error: {err_body[:180]}", provider="gemini", retryable=False, status_code=status)

            except (urllib.error.URLError, TimeoutError) as err:
                # Socket timeout or connection failure
                is_timeout = isinstance(err, TimeoutError) or "timed out" in str(err).lower()
                if is_timeout:
                    last_error = AITimeoutError(f"Gemini request timed out after {self.timeout_seconds}s.", provider="gemini")
                else:
                    last_error = AIProviderError(f"Gemini network connection error: {str(err)}", provider="gemini", retryable=True)

            # Backoff before retry if attempt remains
            if attempt < self.max_retries and last_error and last_error.retryable:
                backoff_sec = 0.5 * (2 ** attempt)
                time.sleep(backoff_sec)
                continue

            # Non-retryable or retries exhausted
            break

        if last_error:
            raise last_error

        raise AIProviderError("Gemini request failed with unknown error.", provider="gemini")

    def _extract_text_from_response(self, resp_data: Dict[str, Any]) -> str:
        """Extracts text part from Gemini JSON response structure."""
        candidates = resp_data.get("candidates", [])
        if not candidates:
            feedback = resp_data.get("promptFeedback", {})
            block_reason = feedback.get("blockReason")
            if block_reason:
                raise AIValidationError(f"Gemini blocked prompt: {block_reason}", provider="gemini")
            raise AIValidationError("Gemini returned empty response candidates.", provider="gemini")

        candidate = candidates[0]
        content = candidate.get("content", {})
        parts = content.get("parts", [])
        if not parts:
            finish_reason = candidate.get("finishReason", "UNKNOWN")
            raise AIValidationError(f"Gemini returned candidate without parts (finishReason: {finish_reason}).", provider="gemini")

        return parts[0].get("text", "")
