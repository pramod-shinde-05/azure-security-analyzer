from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class AIProviderError(Exception):
    """Base exception for AI provider failures."""
    def __init__(self, message: str, provider: str = "unknown", retryable: bool = False, status_code: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.provider = provider
        self.retryable = retryable
        self.status_code = status_code

class AIAuthenticationError(AIProviderError):
    """Raised when API credentials are missing, invalid, or expired."""
    def __init__(self, message: str, provider: str = "unknown"):
        super().__init__(message, provider=provider, retryable=False, status_code=401)

class AIRateLimitError(AIProviderError):
    """Raised when API rate limits are exceeded."""
    def __init__(self, message: str, provider: str = "unknown"):
        super().__init__(message, provider=provider, retryable=True, status_code=429)

class AIQuotaExceededError(AIProviderError):
    """Raised when free-tier or project quota is exhausted."""
    def __init__(self, message: str, provider: str = "unknown"):
        super().__init__(message, provider=provider, retryable=False, status_code=429)

class AITimeoutError(AIProviderError):
    """Raised when request times out."""
    def __init__(self, message: str, provider: str = "unknown"):
        super().__init__(message, provider=provider, retryable=True, status_code=504)

class AIValidationError(AIProviderError):
    """Raised when the model response fails schema or grounding validation."""
    def __init__(self, message: str, provider: str = "unknown"):
        super().__init__(message, provider=provider, retryable=False, status_code=422)

class AIModelNotFoundError(AIProviderError):
    """Raised when the configured model is not available or not installed locally."""
    def __init__(self, message: str, provider: str = "unknown"):
        super().__init__(message, provider=provider, retryable=False, status_code=404)

class AIConnectionError(AIProviderError):
    """Raised when the provider endpoint cannot be reached (daemon offline, network broken)."""
    def __init__(self, message: str, provider: str = "unknown"):
        super().__init__(message, provider=provider, retryable=True, status_code=503)


class BaseAIProvider(ABC):
    """Abstract interface defining the contract for AI model providers."""

    def __init__(self, model_name: str, timeout_seconds: int = 45, max_retries: int = 2):
        self.model_name = model_name
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    @abstractmethod
    def generate_structured_response(
        self,
        system_instruction: str,
        user_content: str,
        response_schema: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Submits prompt to model requesting guaranteed JSON output adhering to schema.
        Returns parsed dictionary.
        """
        pass

    @abstractmethod
    def generate_text_response(
        self,
        system_instruction: str,
        user_content: str
    ) -> str:
        """
        Submits prompt to model requesting natural language text/markdown response.
        """
        pass

    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """
        Verifies provider configuration and connectivity without consuming significant quota.
        """
        pass

