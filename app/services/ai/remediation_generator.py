import json
import copy
from typing import Dict, Any, List, Optional
from app.services.ai.provider import BaseAIProvider, AIValidationError
from app.services.ai.context_builder import AIContextBuilder, _res_field
from app.services.ai.cache import AIResponseCache
from app.services.template_parser import ArmTemplateParser
from app.services.security_scanner import SecurityScanner

class RemediationGenerator:
    """
    Synthesizes minimal ARM JSON patch recommendations and performs dry-run rescan verification
    to prove that a proposed remediation resolves the targeted vulnerability.
    """

    SYSTEM_INSTRUCTION = (
        "You are an expert Azure Resource Manager (ARM) Infrastructure as Code Security Engineer. "
        "Your task is to generate a secure, minimal ARM template patch for a specific security finding.\n\n"
        "STRICT GROUNDING & ACCURACY RULES:\n"
        "1. Provide minimal changes: modify only the properties necessary to remediate the vulnerability.\n"
        "2. Do not break valid ARM template syntax.\n"
        "3. Provide the corrected JSON block in 'suggested_properties_patch'.\n"
        "4. Provide a clear explanation of what changed in 'explanation'.\n"
        "5. Output must be valid JSON conforming to the requested schema."
    )

    JSON_SCHEMA = {
        "type": "OBJECT",
        "properties": {
            "finding_id": {"type": "STRING"},
            "title": {"type": "STRING"},
            "explanation": {"type": "STRING"},
            "code_snippet": {"type": "STRING"},
            "suggested_properties_patch": {"type": "OBJECT"},
            "caveats": {"type": "ARRAY", "items": {"type": "STRING"}}
        },
        "required": ["finding_id", "title", "explanation", "code_snippet", "suggested_properties_patch"]
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

    def generate_remediation(
        self,
        file_id: str,
        finding_id: str,
        finding: Any,
        target_resource: Any,
        force_refresh: bool = False
    ) -> Dict[str, Any]:
        """Generates or retrieves cached ARM JSON fix recommendation."""
        feature_key = f"remediate_{finding_id}"

        if self.cache and not force_refresh:
            cached = self.cache.get(file_id, feature_key)
            if cached:
                cached["cached"] = True
                return cached

        user_content = self.context_builder.build_remediation_context(
            finding=finding,
            target_resource=target_resource
        )
        user_content += "\n\nGenerate the secure ARM JSON remediation patch. Return the validated JSON object."

        response_json = self.provider.generate_structured_response(
            system_instruction=self.SYSTEM_INSTRUCTION,
            user_content=user_content,
            response_schema=self.JSON_SCHEMA
        )

        result = {
            "finding_id": finding_id,
            "title": response_json.get("title", ""),
            "explanation": response_json.get("explanation", ""),
            "code_snippet": response_json.get("code_snippet", ""),
            "suggested_properties_patch": response_json.get("suggested_properties_patch", {}),
            "caveats": response_json.get("caveats", []),
            "cached": False
        }

        if self.cache:
            self.cache.set(file_id, feature_key, result)

        return result

    def dry_run_rescan(
        self,
        original_template_data: Dict[str, Any],
        target_resource_id: str,
        target_rule_id: str,
        patch_properties: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Applies proposed patch in-memory and re-runs deterministic scanner.
        Verifies whether the target rule violation is successfully resolved.
        """
        patched_template = copy.deepcopy(original_template_data)
        resources_list = patched_template.get("resources", [])

        # Locate matching resource in template
        target_res_idx = -1
        for idx, res in enumerate(resources_list):
            r_name = res.get("name", "")
            r_type = res.get("type", "")
            if target_resource_id.endswith(r_name) or (r_name in target_resource_id and r_type in target_resource_id):
                target_res_idx = idx
                break

        if target_res_idx >= 0:
            target_res = resources_list[target_res_idx]
            if "properties" not in target_res or not isinstance(target_res["properties"], dict):
                target_res["properties"] = {}
            # Apply patch properties (deep update)
            self._deep_update(target_res["properties"], patch_properties)

        # Parse and scan patched template in memory
        parser = ArmTemplateParser(patched_template)
        parsed_res, meta, _ = parser.parse()
        scanner = SecurityScanner()
        new_findings = scanner.scan(parsed_res, meta)

        # Check if target rule still triggers on this resource
        target_resolved = True
        remaining_target_findings = []
        for f in new_findings:
            if f.rule_id == target_rule_id:
                if target_resource_id.endswith(f.affected_resource_name) or f.affected_resource_id == target_resource_id:
                    target_resolved = False
                    remaining_target_findings.append(f.to_dict())

        return {
            "resolved": target_resolved,
            "target_rule_id": target_rule_id,
            "target_resource_id": target_resource_id,
            "remaining_rule_violations": len(remaining_target_findings),
            "total_new_findings": len(new_findings),
            "verification_status": "VERIFIED_FIXED" if target_resolved else "STILL_VULNERABLE"
        }

    def _deep_update(self, base_dict: Dict[str, Any], update_dict: Dict[str, Any]) -> None:
        """Recursively updates base dictionary with patch keys."""
        for k, v in update_dict.items():
            if isinstance(v, dict) and k in base_dict and isinstance(base_dict[k], dict):
                self._deep_update(base_dict[k], v)
            else:
                base_dict[k] = v

