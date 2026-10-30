from typing import Dict, Any, List, Set, Optional
from app.services.ai.provider import AIValidationError

class AIResponseValidator:
    """
    Validates AI model outputs against expected schemas and verifies strict grounding
    against active session resources and deterministic security findings.
    """

    ALLOWED_RISK_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    ALLOWED_CONFIDENCE = {"HIGH", "MEDIUM", "LOW"}
    ALLOWED_EVIDENCE_STRENGTH = {"CONFIGURATION_SUPPORTED", "HYPOTHETICAL", "INFERRED"}

    def validate_threat_model_response(
        self,
        raw_response: Dict[str, Any],
        valid_resource_ids: Set[str],
        valid_finding_ids: Set[str]
    ) -> Dict[str, Any]:
        """
        Validates attack-path analysis response.
        Ensures schema compliance and strictly verifies that all cited resource IDs
        and finding IDs exist in the active analysis session.
        """
        if not isinstance(raw_response, dict):
            raise AIValidationError("Threat model response must be a JSON object.")

        attack_paths = raw_response.get("attack_paths")
        if not isinstance(attack_paths, list):
            raise AIValidationError("Field 'attack_paths' must be an array.")

        normalized_res_ids = {rid.lower(): rid for rid in valid_resource_ids}
        normalized_finding_ids = {fid.lower(): fid for fid in valid_finding_ids}

        validated_paths = []

        for idx, path in enumerate(attack_paths):
            if not isinstance(path, dict):
                continue

            path_id = str(path.get("id") or f"path-{idx + 1}")
            title = str(path.get("title") or "Unnamed Attack Path").strip()
            summary = str(path.get("summary") or "").strip()

            raw_risk = str(path.get("risk") or "MEDIUM").upper()
            risk = raw_risk if raw_risk in self.ALLOWED_RISK_LEVELS else "MEDIUM"

            raw_conf = str(path.get("confidence") or "MEDIUM").upper()
            confidence = raw_conf if raw_conf in self.ALLOWED_CONFIDENCE else "MEDIUM"

            raw_strength = str(path.get("evidence_strength") or "CONFIGURATION_SUPPORTED").upper()
            evidence_strength = raw_strength if raw_strength in self.ALLOWED_EVIDENCE_STRENGTH else "CONFIGURATION_SUPPORTED"

            impact = str(path.get("impact") or "Potential compromise of cloud infrastructure.").strip()
            assumptions = [str(a) for a in path.get("assumptions", []) if isinstance(a, (str, int))]
            unknowns = [str(u) for u in path.get("unknowns", []) if isinstance(u, (str, int))]
            recommendations = [str(r) for r in path.get("recommendations", []) if isinstance(r, (str, int))]

            raw_steps = path.get("steps", [])
            validated_steps = []
            path_referenced_resources = set()
            path_referenced_findings = set()

            if isinstance(raw_steps, list):
                for step_idx, step in enumerate(raw_steps):
                    if not isinstance(step, dict):
                        continue

                    r_id_raw = str(step.get("resource_id", "")).strip()
                    r_id_lower = r_id_raw.lower()

                    # Grounding validation: verify resource exists in session
                    matched_canonical_id = normalized_res_ids.get(r_id_lower)
                    if not matched_canonical_id:
                        # Attempt partial match on resource name or suffix
                        for known_lower, known_canon in normalized_res_ids.items():
                            if r_id_lower in known_lower or known_lower.endswith(r_id_lower):
                                matched_canonical_id = known_canon
                                break

                    if not matched_canonical_id:
                        # Ungrounded resource: skip fabricated step or flag as unknown
                        continue

                    path_referenced_resources.add(matched_canonical_id)

                    # Validate referenced finding IDs
                    step_finding_ids = []
                    for f_id in step.get("finding_ids", []):
                        f_id_clean = str(f_id).strip()
                        if f_id_clean.lower() in normalized_finding_ids:
                            canon_f_id = normalized_finding_ids[f_id_clean.lower()]
                            step_finding_ids.append(canon_f_id)
                            path_referenced_findings.add(canon_f_id)

                    description = str(step.get("description", "")).strip()
                    evidence = [str(e) for e in step.get("evidence", []) if isinstance(e, (str, int))]
                    preconditions = [str(p) for p in step.get("preconditions", []) if isinstance(p, (str, int))]

                    validated_steps.append({
                        "step": step_idx + 1,
                        "resource_id": matched_canonical_id,
                        "description": description,
                        "finding_ids": step_finding_ids,
                        "evidence": evidence,
                        "preconditions": preconditions
                    })

            # Only retain path if at least one grounded step exists
            if validated_steps:
                validated_paths.append({
                    "id": path_id,
                    "title": title,
                    "risk": risk,
                    "summary": summary,
                    "steps": validated_steps,
                    "affected_resource_ids": list(path_referenced_resources),
                    "related_finding_ids": list(path_referenced_findings),
                    "impact": impact,
                    "assumptions": assumptions,
                    "unknowns": unknowns,
                    "recommendations": recommendations,
                    "evidence_strength": evidence_strength,
                    "confidence": confidence
                })

        return {
            "attack_paths": validated_paths,
            "total_paths": len(validated_paths),
            "status": "VALIDATED"
        }

    def validate_finding_explanation_response(
        self,
        raw_response: Dict[str, Any],
        target_resource_id: str,
        target_finding_id: str
    ) -> Dict[str, Any]:
        """Validates finding explanation response structure."""
        if not isinstance(raw_response, dict):
            raise AIValidationError("Finding explanation response must be a JSON object.")

        explanation = str(raw_response.get("explanation") or "").strip()
        abuse_scenario = str(raw_response.get("abuse_scenario") or "").strip()
        impact = str(raw_response.get("impact") or "").strip()
        
        remediation_steps = []
        raw_rem = raw_response.get("remediation_steps", [])
        if isinstance(raw_rem, list):
            remediation_steps = [str(s) for s in raw_rem if isinstance(s, (str, int))]

        validation_steps = []
        raw_val = raw_response.get("validation_steps", [])
        if isinstance(raw_val, list):
            validation_steps = [str(v) for v in raw_val if isinstance(v, (str, int))]

        limitations = [str(l) for l in raw_response.get("limitations", []) if isinstance(l, (str, int))]

        if not explanation:
            raise AIValidationError("Model returned empty explanation text.")

        return {
            "finding_id": target_finding_id,
            "resource_id": target_resource_id,
            "explanation": explanation,
            "abuse_scenario": abuse_scenario,
            "impact": impact,
            "remediation_steps": remediation_steps,
            "validation_steps": validation_steps,
            "limitations": limitations
        }

    def validate_prioritization_response(
        self,
        raw_response: Dict[str, Any],
        valid_finding_ids: Set[str]
    ) -> Dict[str, Any]:
        """Validates contextual risk prioritization of findings."""
        if not isinstance(raw_response, dict):
            raise AIValidationError("Prioritization response must be a JSON object.")

        raw_ranked = raw_response.get("prioritized_findings", [])
        if not isinstance(raw_ranked, list):
            raise AIValidationError("Field 'prioritized_findings' must be an array.")

        normalized_finding_ids = {fid.lower(): fid for fid in valid_finding_ids}
        validated_ranked = []

        for item in raw_ranked:
            if not isinstance(item, dict):
                continue
            fid_raw = str(item.get("finding_id", "")).strip()
            canon_fid = normalized_finding_ids.get(fid_raw.lower())
            if not canon_fid:
                continue

            raw_pri = str(item.get("contextual_priority") or "MEDIUM").upper()
            pri = raw_pri if raw_pri in self.ALLOWED_RISK_LEVELS else "MEDIUM"
            rationale = str(item.get("rationale") or "").strip()
            remediation_order = int(item.get("order") or len(validated_ranked) + 1)

            validated_ranked.append({
                "finding_id": canon_fid,
                "contextual_priority": pri,
                "rationale": rationale,
                "order": remediation_order
            })

        validated_ranked.sort(key=lambda x: x["order"])

        return {
            "prioritized_findings": validated_ranked,
            "executive_summary": str(raw_response.get("executive_summary") or "").strip()
        }

