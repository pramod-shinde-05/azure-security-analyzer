from typing import List, Dict, Any, Optional, Set
from app.services.template_parser import NormalizedResource
from app.services.ai.provider import BaseAIProvider, AIValidationError
from app.services.ai.context_builder import AIContextBuilder
from app.services.ai.response_validator import AIResponseValidator
from app.services.ai.cache import AIResponseCache

class ThreatModeler:
    """
    Synthesizes deterministic findings, cloud resources, and network/data relationships
    into correlated multi-step attack paths.
    Enforces strict grounding against the analyzed template.
    """

    SYSTEM_INSTRUCTION = (
        "You are an expert Azure Cloud Security Architect and Threat Modeling specialist. "
        "Your task is to analyze static Azure Resource Manager (ARM) infrastructure configurations "
        "and synthesize potential attack paths. "
        "An attack path traces how an attacker could move from an external or misconfigured entry point "
        "(such as an Internet-exposed Public IP, an unrestricted NSG rule, or an unauthenticated web app) "
        "toward high-value targets (such as Storage Accounts, SQL Databases, Redis Caches, Key Vaults, or Privileged Role Assignments).\n\n"
        "STRICT GROUNDING RULES:\n"
        "1. Every resource cited in a step MUST exist in the provided resources inventory. Use the exact resource 'id'.\n"
        "2. When citing security findings, cite ONLY existing finding IDs provided in the deterministic findings list.\n"
        "3. Explicitly state whether each path is 'CONFIGURATION_SUPPORTED' (direct configuration evidence) "
        "or 'HYPOTHETICAL' (requires unverified runtime conditions).\n"
        "4. A deployment dependency ('dependsOn') is NOT proof of network connectivity. Do not assume resources can "
        "communicate over a network unless network association, subnet containment, or exposure evidence exists.\n"
        "5. Output must be strictly valid JSON matching the requested schema."
    )

    JSON_SCHEMA = {
        "type": "OBJECT",
        "properties": {
            "attack_paths": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "id": {"type": "STRING"},
                        "title": {"type": "STRING"},
                        "risk": {"type": "STRING", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                        "summary": {"type": "STRING"},
                        "steps": {
                            "type": "ARRAY",
                            "items": {
                                "type": "OBJECT",
                                "properties": {
                                    "step": {"type": "INTEGER"},
                                    "resource_id": {"type": "STRING"},
                                    "description": {"type": "STRING"},
                                    "finding_ids": {"type": "ARRAY", "items": {"type": "STRING"}},
                                    "evidence": {"type": "ARRAY", "items": {"type": "STRING"}},
                                    "preconditions": {"type": "ARRAY", "items": {"type": "STRING"}}
                                },
                                "required": ["step", "resource_id", "description"]
                            }
                        },
                        "impact": {"type": "STRING"},
                        "assumptions": {"type": "ARRAY", "items": {"type": "STRING"}},
                        "unknowns": {"type": "ARRAY", "items": {"type": "STRING"}},
                        "recommendations": {"type": "ARRAY", "items": {"type": "STRING"}},
                        "evidence_strength": {"type": "STRING", "enum": ["CONFIGURATION_SUPPORTED", "HYPOTHETICAL", "INFERRED"]},
                        "confidence": {"type": "STRING", "enum": ["HIGH", "MEDIUM", "LOW"]}
                    },
                    "required": ["id", "title", "risk", "summary", "steps", "impact", "evidence_strength", "confidence"]
                }
            }
        },
        "required": ["attack_paths"]
    }

    def __init__(
        self,
        provider: BaseAIProvider,
        context_builder: Optional[AIContextBuilder] = None,
        validator: Optional[AIResponseValidator] = None,
        cache: Optional[AIResponseCache] = None
    ):
        self.provider = provider
        self.context_builder = context_builder or AIContextBuilder()
        self.validator = validator or AIResponseValidator()
        self.cache = cache

    def analyze_attack_paths(
        self,
        file_id: str,
        resources: List[NormalizedResource],
        findings: List[Any],
        edges: List[Dict[str, Any]],
        summary: Optional[Dict[str, Any]] = None,
        warnings: Optional[List[str]] = None,
        force_refresh: bool = False
    ) -> Dict[str, Any]:
        """
        Executes threat modeling analysis.
        Checks cache first, then prompts LLM and validates output against active session data.
        """
        feature_key = "attack_paths"

        # Check cache
        if self.cache and not force_refresh:
            cached_data = self.cache.get(file_id, feature_key)
            if cached_data:
                cached_data["cached"] = True
                return cached_data

        valid_resource_ids: Set[str] = {
            (r.id if hasattr(r, 'id') else r.get('id', ''))
            for r in resources
            if (r.id if hasattr(r, 'id') else r.get('id'))
        }
        valid_finding_ids: Set[str] = {
            (f.finding_id if hasattr(f, 'finding_id') else f.get('finding_id'))
            for f in findings
            if (f.finding_id if hasattr(f, 'finding_id') else f.get('finding_id'))
        }

        # Build minimized, masked, isolated prompt context
        user_prompt = self.context_builder.build_threat_model_context(
            resources=resources,
            findings=findings,
            edges=edges,
            summary=summary,
            warnings=warnings
        )

        user_prompt += (
            "\n\nSynthesize all configuration-supported attack paths from initial access to objective. "
            "Return the validated JSON structure according to the specification."
        )

        # Call AI provider
        raw_llm_json = self.provider.generate_structured_response(
            system_instruction=self.SYSTEM_INSTRUCTION,
            user_content=user_prompt,
            response_schema=self.JSON_SCHEMA
        )

        # Strictly validate response schema and ground all referenced IDs
        validated_result = self.validator.validate_threat_model_response(
            raw_response=raw_llm_json,
            valid_resource_ids=valid_resource_ids,
            valid_finding_ids=valid_finding_ids
        )

        validated_result["file_id"] = file_id
        validated_result["provider"] = self.provider.model_name
        validated_result["cached"] = False

        # Store in cache
        if self.cache:
            self.cache.set(file_id, feature_key, validated_result)

        return validated_result

