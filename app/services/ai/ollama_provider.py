import os
import json
import time
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, List

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

from app.services.ai.provider import (
    BaseAIProvider,
    AIProviderError,
    AITimeoutError,
    AIValidationError,
    AIModelNotFoundError,
    AIConnectionError,
)

class OllamaProvider(BaseAIProvider):
    """
    Local Ollama inference provider.
    All base URLs and model names are strictly configured via .env without hardcoded dummy fallbacks.
    Communicates with Ollama daemon via REST endpoints (/api/chat, /api/generate, /api/tags).
    Supports structured JSON responses with bounded retries, dynamic model tag resolution, and local availability checks.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout_seconds: int = 60,
        max_retries: int = 2
    ):
        base = (base_url if base_url is not None else os.environ.get("OLLAMA_BASE_URL", "")).strip().rstrip("/")
        model = (model_name if model_name is not None else os.environ.get("OLLAMA_MODEL", "")).strip()
        super().__init__(model_name=model, timeout_seconds=timeout_seconds, max_retries=max_retries)
        self.base_url = base

    def _resolve_model_name(self) -> str:
        """
        Dynamically resolves the exact installed model tag from Ollama.
        For example: if OLLAMA_MODEL is 'qwen3.5', and Ollama has 'qwen3.5:4b' installed,
        this automatically resolves to 'qwen3.5:4b' instead of failing with 404.
        """
        if not self.base_url or not self.model_name:
            return self.model_name

        try:
            resp = self._http_get_json(f"{self.base_url}/api/tags", timeout=4)
            installed = [
                m.get("name") for m in resp.get("models", [])
                if isinstance(m, dict) and m.get("name")
            ]
            if not installed:
                return self.model_name

            # 1. Exact match
            if self.model_name in installed:
                return self.model_name

            # 2. Case-insensitive exact match
            for m in installed:
                if m.lower() == self.model_name.lower():
                    return m

            # 3. Match prefix before tag (e.g. 'qwen3.5' matches 'qwen3.5:4b' or 'qwen3.5:latest')
            req_lower = self.model_name.lower()
            for m in installed:
                if m.lower().startswith(f"{req_lower}:"):
                    return m

            # 4. Match base model name without any tags (e.g. 'qwen3.5:latest' matches 'qwen3.5:4b')
            req_base = req_lower.split(":")[0]
            for m in installed:
                if m.lower().split(":")[0] == req_base:
                    return m

        except Exception:
            pass

        return self.model_name

    def health_check(self) -> Dict[str, Any]:
        """
        Verifies if local Ollama daemon is active and if the configured model is installed.
        Queries GET /api/tags without triggering model execution.
        """
        if not self.base_url:
            return {
                "status": "unconfigured",
                "provider": "ollama",
                "model": self.model_name,
                "error": "OLLAMA_BASE_URL is not configured in .env."
            }

        if not self.model_name:
            return {
                "status": "unconfigured",
                "provider": "ollama",
                "model": "",
                "error": "OLLAMA_MODEL is not configured in .env."
            }

        url = f"{self.base_url}/api/tags"
        try:
            resp_data = self._http_get_json(url, timeout=5)
            installed_models = [
                m.get("name") for m in resp_data.get("models", [])
                if isinstance(m, dict) and m.get("name")
            ]

            # Match model name with or without tag (e.g. qwen3.5 matches qwen3.5:4b)
            req_model = self.model_name.lower().strip()
            req_base = req_model.split(':')[0]
            matched_model = next((
                m for m in installed_models
                if req_model == m.lower() or
                m.lower().startswith(f"{req_model}:") or
                req_model.startswith(f"{m.lower()}:") or
                req_base == m.lower().split(':')[0]
            ), None)

            if matched_model or not installed_models:
                effective_model = matched_model or self.model_name
                return {
                    "status": "configured",
                    "provider": "ollama",
                    "model": effective_model,
                    "base_url": self.base_url,
                    "installed_models": installed_models
                }
            else:
                return {
                    "status": "model_missing",
                    "provider": "ollama",
                    "model": self.model_name,
                    "base_url": self.base_url,
                    "installed_models": installed_models,
                    "error": f"Model '{self.model_name}' is not installed in Ollama. Run: ollama pull {self.model_name}"
                }

        except (urllib.error.URLError, TimeoutError, ConnectionRefusedError, Exception) as err:
            return {
                "status": "unavailable",
                "provider": "ollama",
                "model": self.model_name,
                "base_url": self.base_url,
                "error": f"Cannot connect to Ollama at {self.base_url}. Ensure the Ollama daemon is running."
            }

    def generate_structured_response(
        self,
        system_instruction: str,
        user_content: str,
        response_schema: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Requests structured JSON from Ollama using /api/chat with format='json'.
        Parses and returns Python dict, validating against syntax errors.
        Enforces num_ctx=8192 to prevent token truncation on large ARM templates.
        """
        active_model = self._resolve_model_name()
        payload: Dict[str, Any] = {
            "model": active_model,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": user_content}
            ],
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.2,
                "num_ctx": 8192
            }
        }

        raw_text = self._execute_chat_with_retries(payload)
        clean_text = self._strip_markdown_code_fences(raw_text)

        try:
            parsed = json.loads(clean_text)
            if not isinstance(parsed, dict):
                raise AIValidationError(
                    f"Ollama returned {type(parsed).__name__} instead of JSON object.",
                    provider="ollama"
                )
            return parsed
        except json.JSONDecodeError as e:
            raise AIValidationError(
                f"Ollama returned malformed JSON: {str(e)}. Snippet: {clean_text[:120]}",
                provider="ollama"
            )

    def generate_text_response(
        self,
        system_instruction: str,
        user_content: str
    ) -> str:
        """Requests conversational text/markdown response from Ollama."""
        active_model = self._resolve_model_name()
        payload: Dict[str, Any] = {
            "model": active_model,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": user_content}
            ],
            "stream": False,
            "options": {
                "temperature": 0.3,
                "num_ctx": 8192
            }
        }
        return self._execute_chat_with_retries(payload).strip()

    def _execute_chat_with_retries(self, payload: Dict[str, Any]) -> str:
        """Executes POST /api/chat with bounded exponential retries."""
        url = f"{self.base_url}/api/chat"
        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            try:
                resp_dict = self._http_post_json(url, payload, timeout=self.timeout_seconds)
                message = resp_dict.get("message", {})
                content = message.get("content", "")
                if not content:
                    content = resp_dict.get("response", "")
                if not content:
                    raise AIValidationError("Ollama returned empty response content.", provider="ollama")
                return content

            except AIModelNotFoundError:
                raise

            except AITimeoutError as err:
                last_error = err

            except AIConnectionError as err:
                last_error = err

            except AIProviderError as err:
                if not err.retryable:
                    raise
                last_error = err

            if attempt < self.max_retries and last_error and last_error.retryable:
                time.sleep(0.5 * (2 ** attempt))
                continue

            break

        if last_error:
            raise last_error

        raise AIProviderError("Ollama request failed with unknown error.", provider="ollama")

    def _http_get_json(self, url: str, timeout: int = 10) -> Dict[str, Any]:
        """Performs HTTP GET returning parsed JSON."""
        if _HAS_REQUESTS:
            try:
                r = requests.get(url, timeout=timeout)
                if r.status_code != 200:
                    raise AIProviderError(f"HTTP GET {r.status_code}", provider="ollama", status_code=r.status_code)
                return r.json()
            except requests.exceptions.Timeout:
                raise AITimeoutError(f"Ollama request to {url} timed out.", provider="ollama")
            except requests.exceptions.ConnectionError as ce:
                raise AIConnectionError(f"Cannot connect to Ollama: {ce}", provider="ollama")
            except Exception as e:
                raise AIProviderError(f"Ollama GET error: {e}", provider="ollama")
        else:
            req = urllib.request.Request(url, headers={"User-Agent": "Azure-ARM-Security-Analyzer/2.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))

    def _http_post_json(self, url: str, data: Dict[str, Any], timeout: int = 60) -> Dict[str, Any]:
        """Performs HTTP POST returning parsed JSON with comprehensive error mapping."""
        if _HAS_REQUESTS:
            try:
                r = requests.post(url, json=data, timeout=timeout)
                if r.status_code == 404:
                    err_msg = r.text
                    model_sent = data.get("model", self.model_name)
                    raise AIModelNotFoundError(
                        f"Model '{model_sent}' not found in Ollama: {err_msg[:120]}. Run: ollama pull {self.model_name}",
                        provider="ollama"
                    )
                if r.status_code >= 500:
                    raise AIProviderError(f"Ollama server error (HTTP {r.status_code})", provider="ollama", retryable=True, status_code=r.status_code)
                if r.status_code != 200:
                    raise AIProviderError(f"Ollama HTTP {r.status_code}: {r.text[:120]}", provider="ollama", retryable=False, status_code=r.status_code)
                return r.json()
            except requests.exceptions.Timeout:
                raise AITimeoutError(f"Ollama request timed out after {timeout}s.", provider="ollama")
            except requests.exceptions.ConnectionError as ce:
                raise AIConnectionError(f"Cannot reach Ollama daemon at {self.base_url}: {ce}", provider="ollama")
            except AIProviderError:
                raise
            except Exception as e:
                raise AIProviderError(f"Ollama POST error: {e}", provider="ollama")
        else:
            data_bytes = json.dumps(data).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data_bytes,
                headers={"Content-Type": "application/json", "User-Agent": "Azure-ARM-Security-Analyzer/2.0"},
                method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as err:
                status = err.code
                err_body = ""
                try:
                    err_body = err.read().decode("utf-8", errors="replace")
                except Exception:
                    pass
                if status == 404:
                    model_sent = data.get("model", self.model_name)
                    raise AIModelNotFoundError(
                        f"Model '{model_sent}' not found in Ollama: {err_body[:120]}. Run: ollama pull {self.model_name}",
                        provider="ollama"
                    )
                elif status in (500, 502, 503, 504):
                    raise AIProviderError(f"Ollama server error (HTTP {status})", provider="ollama", retryable=True, status_code=status)
                else:
                    raise AIProviderError(f"Ollama HTTP {status} error: {err_body[:120]}", provider="ollama", retryable=False, status_code=status)
            except (urllib.error.URLError, TimeoutError) as err:
                if isinstance(err, TimeoutError) or "timed out" in str(err).lower():
                    raise AITimeoutError(f"Ollama request timed out after {timeout}s.", provider="ollama")
                raise AIConnectionError(f"Cannot reach Ollama daemon at {self.base_url}: {err}", provider="ollama")

    def _strip_markdown_code_fences(self, text: str) -> str:
        """Strips ```json ... ``` markdown wrappers if present."""
        clean = text.strip()
        if clean.startswith("```json"):
            clean = clean[7:]
        elif clean.startswith("```"):
            clean = clean[3:]
        if clean.endswith("```"):
            clean = clean[:-3]
        return clean.strip()
