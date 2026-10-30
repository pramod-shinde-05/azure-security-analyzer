import json
import traceback
from flask import Blueprint, jsonify, request, current_app
from app.routes.analysis import _load_and_analyze
from app.services.ai import get_ai_provider, get_ai_cache
from app.services.ai.threat_modeler import ThreatModeler
from app.services.ai.finding_explainer import FindingExplainer
from app.services.ai.risk_prioritizer import RiskPrioritizer
from app.services.ai.remediation_generator import RemediationGenerator
from app.utils.sanitization import get_storage_path
from app.services.ai.provider import (
    AIProviderError,
    AIAuthenticationError,
    AIRateLimitError,
    AIQuotaExceededError,
    AITimeoutError,
    AIValidationError,
    AIModelNotFoundError,
    AIConnectionError,
)

ai_bp = Blueprint('ai', __name__)

@ai_bp.route('/api/ai/status', methods=['GET'])
def ai_status():
    """Returns AI engine availability and provider configuration status."""
    provider = get_ai_provider()
    if not provider:
        return jsonify({
            "enabled": False,
            "status": "disabled",
            "message": "AI analysis is disabled or unconfigured."
        })

    health = provider.health_check()
    health["enabled"] = True
    return jsonify(health)

@ai_bp.route('/api/ai/threat-model/<file_id>', methods=['POST'])
def analyze_threat_model(file_id: str):
    """Generates or retrieves cached AI attack-path analysis for the given session."""
    analysis_data = _load_and_analyze(file_id)
    if not analysis_data:
        return jsonify({
            "success": False,
            "error": "Analysis session not found or expired.",
            "code": "NOT_FOUND"
        }), 404

    provider = get_ai_provider()
    if not provider:
        return jsonify({
            "success": False,
            "error": "AI provider is not configured. Set AI_PROVIDER in your environment.",
            "code": "AI_UNCONFIGURED"
        }), 400

    health = provider.health_check()
    if health.get("status") in ("unconfigured", "unavailable", "model_missing"):
        provider_name = health.get("provider", "ai")
        err_msg = health.get("error", f"{provider_name.capitalize()} provider is not ready.")
        return jsonify({
            "success": False,
            "error": err_msg,
            "code": "AI_UNCONFIGURED" if health.get("status") == "unconfigured" else "AI_UNAVAILABLE",
            "provider": provider_name,
            "details": health
        }), 400

    cache = get_ai_cache()
    force_refresh = request.args.get("refresh", "false").lower() == "true"

    try:
        modeler = ThreatModeler(provider=provider, cache=cache)
        result = modeler.analyze_attack_paths(
            file_id=file_id,
            resources=analysis_data["resources"],
            findings=analysis_data["findings"],
            edges=analysis_data["graph"].get("edges", []),
            summary=analysis_data.get("summary"),
            warnings=analysis_data.get("warnings"),
            force_refresh=force_refresh
        )

        return jsonify({
            "success": True,
            "file_id": file_id,
            "provider": provider.model_name,
            "cached": result.get("cached", False),
            "total_paths": result.get("total_paths", 0),
            "attack_paths": result.get("attack_paths", [])
        })

    except AIModelNotFoundError as e:
        return jsonify({"success": False, "error": str(e), "code": "MODEL_NOT_FOUND"}), 404
    except AIConnectionError as e:
        return jsonify({"success": False, "error": str(e), "code": "CONNECTION_FAILED"}), 503
    except AIAuthenticationError as e:
        return jsonify({"success": False, "error": str(e), "code": "AUTH_FAILED"}), 401
    except AIQuotaExceededError as e:
        return jsonify({"success": False, "error": str(e), "code": "QUOTA_EXCEEDED"}), 429
    except AIRateLimitError as e:
        return jsonify({"success": False, "error": str(e), "code": "RATE_LIMITED"}), 429
    except AITimeoutError as e:
        return jsonify({"success": False, "error": str(e), "code": "TIMEOUT"}), 504
    except AIValidationError as e:
        return jsonify({"success": False, "error": f"AI response validation failed: {str(e)}", "code": "VALIDATION_FAILED"}), 422
    except AIProviderError as e:
        return jsonify({"success": False, "error": f"AI provider error: {str(e)}", "code": "PROVIDER_ERROR"}), 502
    except Exception as e:
        traceback.print_exc()
        current_app.logger.error(f"AI Threat Modeling failed: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": f"An unexpected error occurred during AI threat modeling: {str(e)}", "code": "INTERNAL_ERROR"}), 500

@ai_bp.route('/api/ai/explain/<file_id>/<finding_id>', methods=['POST'])
def explain_finding(file_id: str, finding_id: str):
    """Generates or retrieves contextual architectural explanation for a single finding."""
    analysis_data = _load_and_analyze(file_id)
    if not analysis_data:
        return jsonify({"success": False, "error": "Session not found.", "code": "NOT_FOUND"}), 404

    provider = get_ai_provider()
    if not provider:
        return jsonify({"success": False, "error": "AI provider unconfigured.", "code": "AI_UNCONFIGURED"}), 400

    target_finding = next((f for f in analysis_data["findings"] if f.get("finding_id") == finding_id), None)
    if not target_finding:
        return jsonify({"success": False, "error": "Finding not found in active session.", "code": "FINDING_NOT_FOUND"}), 404

    target_res_id = target_finding.get("affected_resource_id")
    target_res = next((r for r in analysis_data["resources"] if r.get("id") == target_res_id), None)

    cache = get_ai_cache()
    force_refresh = request.args.get("refresh", "false").lower() == "true"

    try:
        explainer = FindingExplainer(provider=provider, cache=cache)
        explanation = explainer.explain_finding(
            file_id=file_id,
            finding_id=finding_id,
            finding=target_finding,
            target_resource=target_res,
            related_resources=analysis_data["resources"],
            related_findings=analysis_data["findings"],
            force_refresh=force_refresh
        )
        return jsonify({"success": True, "explanation": explanation})
    except AIProviderError as e:
        return jsonify({"success": False, "error": str(e), "code": "PROVIDER_ERROR"}), 502
    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e), "code": "INTERNAL_ERROR"}), 500

@ai_bp.route('/api/ai/prioritize/<file_id>', methods=['POST'])
def prioritize_risks(file_id: str):
    """Calculates prioritized finding risk rankings based on deployment architecture."""
    analysis_data = _load_and_analyze(file_id)
    if not analysis_data:
        return jsonify({"success": False, "error": "Session not found.", "code": "NOT_FOUND"}), 404

    provider = get_ai_provider()
    if not provider:
        return jsonify({"success": False, "error": "AI provider unconfigured.", "code": "AI_UNCONFIGURED"}), 400

    cache = get_ai_cache()
    force_refresh = request.args.get("refresh", "false").lower() == "true"

    try:
        prioritizer = RiskPrioritizer(provider=provider, cache=cache)
        result = prioritizer.prioritize_risks(
            file_id=file_id,
            findings=analysis_data["findings"],
            resources=analysis_data["resources"],
            edges=analysis_data["graph"].get("edges", []),
            force_refresh=force_refresh
        )
        return jsonify({"success": True, "prioritization": result})
    except AIProviderError as e:
        return jsonify({"success": False, "error": str(e), "code": "PROVIDER_ERROR"}), 502
    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e), "code": "INTERNAL_ERROR"}), 500

@ai_bp.route('/api/ai/remediate/<file_id>/<finding_id>', methods=['POST'])
def generate_remediation(file_id: str, finding_id: str):
    """Generates minimal ARM JSON fix snippet for a specific finding."""
    analysis_data = _load_and_analyze(file_id)
    if not analysis_data:
        return jsonify({"success": False, "error": "Session not found.", "code": "NOT_FOUND"}), 404

    provider = get_ai_provider()
    if not provider:
        return jsonify({"success": False, "error": "AI provider unconfigured.", "code": "AI_UNCONFIGURED"}), 400

    target_finding = next((f for f in analysis_data["findings"] if f.get("finding_id") == finding_id), None)
    if not target_finding:
        return jsonify({"success": False, "error": "Finding not found.", "code": "FINDING_NOT_FOUND"}), 404

    target_res_id = target_finding.get("affected_resource_id")
    target_res = next((r for r in analysis_data["resources"] if r.get("id") == target_res_id), None)

    cache = get_ai_cache()
    force_refresh = request.args.get("refresh", "false").lower() == "true"

    try:
        generator = RemediationGenerator(provider=provider, cache=cache)
        result = generator.generate_remediation(
            file_id=file_id,
            finding_id=finding_id,
            finding=target_finding,
            target_resource=target_res,
            force_refresh=force_refresh
        )
        return jsonify({"success": True, "remediation": result})
    except AIProviderError as e:
        return jsonify({"success": False, "error": str(e), "code": "PROVIDER_ERROR"}), 502
    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e), "code": "INTERNAL_ERROR"}), 500

@ai_bp.route('/api/ai/remediate/<file_id>/<finding_id>/rescan', methods=['POST'])
def dry_run_rescan(file_id: str, finding_id: str):
    """Dry-runs proposed patch in memory and validates that the security violation is eliminated."""
    analysis_data = _load_and_analyze(file_id)
    if not analysis_data:
        return jsonify({"success": False, "error": "Session not found.", "code": "NOT_FOUND"}), 404

    target_finding = next((f for f in analysis_data["findings"] if f.get("finding_id") == finding_id), None)
    if not target_finding:
        return jsonify({"success": False, "error": "Finding not found.", "code": "FINDING_NOT_FOUND"}), 404

    payload = request.get_json() or {}
    patch_properties = payload.get("patch_properties", {})

    upload_dir = current_app.config['UPLOAD_FOLDER']
    try:
        file_path = get_storage_path(upload_dir, file_id)
        with open(file_path, 'r', encoding='utf-8') as f:
            original_template = json.load(f)
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed reading template: {str(e)}", "code": "FILE_READ_ERROR"}), 500

    provider = get_ai_provider()
    generator = RemediationGenerator(provider=provider or ThreatModeler)
    verification = generator.dry_run_rescan(
        original_template_data=original_template,
        target_resource_id=target_finding.get("affected_resource_id"),
        target_rule_id=target_finding.get("rule_id"),
        patch_properties=patch_properties
    )

    return jsonify({"success": True, "verification": verification})
