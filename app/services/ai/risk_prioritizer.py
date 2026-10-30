from typing import Dict, Any, List, Optional, Set
from app.services.ai.provider import BaseAIProvider, AIValidationError
from app.services.ai.context_builder import AIContextBuilder
from app.services.ai.cache import AIResponseCache

class RiskPrioritizer:
    """
    Ranks and contextualizes deterministic security findings based on composite architectural exposure,
    identifying which vulnerabilities pose the highest immediate exploitability.
    """

    SYSTEM_INSTRUCTION = (
        "You are an expert Azure Cloud Security Architect specializing in risk triage and remediation prioritization. "
        "Your task is to re-rank deterministic security findings by evaluating their real-world exploitability, "
        "taking into account ingress exposure (e.g. Public IPs), network isolation (NSG rules), "
        "and data sensitivity.\n\n"
        "STRICT GROUNDING RULES:\n"
        "1. Every finding in 'prioritized_findings' MUST correspond to a valid 'finding_id' from the provided findings list.\n"
        "2. Do not invent findings or resources.\n"
        "3. Provide clear rationale for why a finding was prioritized (e.g. 'Co-located with an unauthenticated public ingress').\n"
        "4. Return valid JSON conforming to the requested schema."
    )

    JSON_SCHEMA = {
        "type": "OBJECT",
        "properties": {
            "prioritized_findings": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "finding_id": {"type": "STRING"},
                        "composite_score": {"type": "NUMBER"},
                        "adjusted_priority": {"type": "STRING", "enum": ["IMMEDIATE", "HIGH", "MEDIUM", "LOW"]},
                        "rationale": {"type": "STRING"}
                    },
                    "required": ["finding_id", "composite_score", "adjusted_priority", "rationale"]
                }
            },
            "executive_summary": {"type": "STRING"}
        },
        "required": ["prioritized_findings", "executive_summary"]
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

    def prioritize_risks(
        self,
        file_id: str,
        findings: List[Any],
        resources: List[Any],
        edges: List[Dict[str, Any]],
        attack_paths: Optional[List[Dict[str, Any]]] = None,
        force_refresh: bool = False
    ) -> Dict[str, Any]:
        """Calculates architectural risk priority order for all active findings."""
        feature_key = "risk_prioritization"

        if self.cache and not force_refresh:
            cached = self.cache.get(file_id, feature_key)
            if cached:
                cached["cached"] = True
                return cached

        valid_finding_ids: Set[str] = {
            (f.finding_id if hasattr(f, 'finding_id') else f.get('finding_id'))
            for f in findings
            if (f.finding_id if hasattr(f, 'finding_id') else f.get('finding_id'))
        }

        user_content = self.context_builder.build_threat_model_context(
            resources=resources,
            findings=findings,
            edges=edges
        )

        if attack_paths:
            user_content += f"\n\nActive AI Synthesized Attack Paths: {len(attack_paths)} paths identified."

        user_content += (
            "\n\nPrioritize all findings based on architectural exposure and exploitability. "
            "Return the validated JSON structure."
        )

        response_json = self.provider.generate_structured_response(
            system_instruction=self.SYSTEM_INSTRUCTION,
            user_content=user_content,
            response_schema=self.JSON_SCHEMA
        )

        # Grounding check: filter out any ungrounded finding IDs
        normalized_finding_map = {fid.lower(): fid for fid in valid_finding_ids}
        validated_prioritized = []

        raw_list = response_json.get("prioritized_findings", [])
        if isinstance(raw_list, list):
            for item in raw_list:
                if not isinstance(item, dict):
                    continue
                fid_raw = str(item.get("finding_id", "")).strip()
                canon_fid = normalized_finding_map.get(fid_raw.lower())
                if canon_fid:
                    validated_prioritized.append({
                        "finding_id": canon_fid,
                        "composite_score": float(item.get("composite_score", 5.0)),
                        "adjusted_priority": str(item.get("adjusted_priority", "MEDIUM")).upper(),
                        "rationale": str(item.get("rationale", "")).strip()
                    })

        result = {
            "file_id": file_id,
            "executive_summary": response_json.get("executive_summary", ""),
            "prioritized_findings": validated_prioritized,
            "cached": False
        }

        if self.cache:
            self.cache.set(file_id, feature_key, result)

        return result

