from typing import Dict, Any, List, Optional
from app.services.ai.provider import BaseAIProvider, AIValidationError
from app.services.ai.context_builder import AIContextBuilder
from app.services.ai.cache import AIResponseCache

class FindingExplainer:
    """
    Synthesizes clear, contextual security explanations for specific deterministic findings.
    Explains the real-world risk within the context of the analyzed ARM template topology.
    """

    SYSTEM_INSTRUCTION = (
        "You are an expert Azure Cloud Security Consultant. "
        "Your role is to explain a static security finding in plain English, specific to the architecture "
        "of the user's ARM template.\n\n"
        "STRICT GROUNDING RULES:\n"
        "1. Do not invent non-existent resources or findings. Ground your explanation strictly on the provided target resource and finding.\n"
        "2. Explain *why* this misconfiguration matters in the context of this specific deployment (e.g. if a storage account is public and exposed).\n"
        "3. Provide realistic verification steps that a security auditor or engineer can use to confirm the issue.\n"
        "4. Return valid JSON conforming to the requested schema."
    )

    JSON_SCHEMA = {
        "type": "OBJECT",
        "properties": {
            "summary": {"type": "STRING"},
            "architectural_context": {"type": "STRING"},
            "attacker_perspective": {"type": "STRING"},
            "verification_steps": {"type": "ARRAY", "items": {"type": "STRING"}},
            "quick_fix_summary": {"type": "STRING"}
        },
        "required": ["summary", "architectural_context", "attacker_perspective", "quick_fix_summary"]
    }

    def __init__(
        self,
        provider: BaseAIProvider,
        context_builder: Optional[AIContextBuilder] = None,
        cache: Optional[AIResponseCache] = None
    ):
        self.provider = provider
        self.context_builder = context_builder or AIContextBuilder()
        self.cache = cache

    def explain_finding(
        self,
        file_id: str,
        finding_id: str,
        finding: Any,
        target_resource: Any,
        related_resources: Optional[List[Any]] = None,
        related_findings: Optional[List[Any]] = None,
        force_refresh: bool = False
    ) -> Dict[str, Any]:
        """Generates or retrieves cached contextual explanation for a single finding."""
        feature_key = f"explain_{finding_id}"

        if self.cache and not force_refresh:
            cached = self.cache.get(file_id, feature_key)
            if cached:
                cached["cached"] = True
                return cached

        user_content = self.context_builder.build_finding_explanation_context(
            finding=finding,
            target_resource=target_resource,
            related_resources=related_resources,
            related_findings=related_findings
        )
        user_content += "\n\nExplain this finding in architectural context. Return the validated JSON object."

        response_json = self.provider.generate_structured_response(
            system_instruction=self.SYSTEM_INSTRUCTION,
            user_content=user_content,
            response_schema=self.JSON_SCHEMA
        )

        result = {
            "finding_id": finding_id,
            "summary": response_json.get("summary", ""),
            "architectural_context": response_json.get("architectural_context", ""),
            "attacker_perspective": response_json.get("attacker_perspective", ""),
            "verification_steps": response_json.get("verification_steps", []),
            "quick_fix_summary": response_json.get("quick_fix_summary", ""),
            "cached": False
        }

        if self.cache:
            self.cache.set(file_id, feature_key, result)

        return result

