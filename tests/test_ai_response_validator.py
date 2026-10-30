import pytest
from app.services.ai.response_validator import AIResponseValidator
from app.services.ai.provider import AIValidationError

def test_validate_threat_model_grounded_path():
    validator = AIResponseValidator()
    valid_resources = {
        "providers/Microsoft.Network/publicIPAddresses/pip-01",
        "providers/Microsoft.Network/networkInterfaces/nic-01",
        "providers/Microsoft.Storage/storageAccounts/sto01"
    }
    valid_findings = {"FIND-001", "FIND-002"}

    raw_response = {
        "attack_paths": [
            {
                "id": "path-01",
                "title": "Public ingress to storage",
                "risk": "HIGH",
                "summary": "External attacker can leverage exposure",
                "steps": [
                    {
                        "step": 1,
                        "resource_id": "providers/Microsoft.Network/publicIPAddresses/pip-01",
                        "description": "Internet ingress reaches PIP",
                        "finding_ids": ["FIND-001"],
                        "evidence": ["Public IP allocation is Dynamic"],
                        "preconditions": ["PIP is active"]
                    },
                    {
                        "step": 2,
                        "resource_id": "sto01",  # Suffix matching
                        "description": "Access storage account directly",
                        "finding_ids": ["FIND-002"],
                        "evidence": ["Blob public access enabled"],
                        "preconditions": ["Storage blob is unauthenticated"]
                    }
                ],
                "impact": "Data exfiltration",
                "assumptions": ["Network permits routing"],
                "unknowns": ["WAF present"],
                "recommendations": ["Disable public blob access"],
                "evidence_strength": "CONFIGURATION_SUPPORTED",
                "confidence": "HIGH"
            }
        ]
    }

    validated = validator.validate_threat_model_response(raw_response, valid_resources, valid_findings)
    assert validated["status"] == "VALIDATED"
    assert validated["total_paths"] == 1
    path = validated["attack_paths"][0]
    assert path["id"] == "path-01"
    assert len(path["steps"]) == 2
    assert "providers/Microsoft.Storage/storageAccounts/sto01" in path["affected_resource_ids"]
    assert "FIND-001" in path["related_finding_ids"]

def test_validate_threat_model_rejects_hallucinated_resources():
    validator = AIResponseValidator()
    valid_resources = {"providers/Microsoft.Network/networkInterfaces/nic-01"}
    valid_findings = {"FIND-001"}

    raw_response = {
        "attack_paths": [
            {
                "id": "path-fake",
                "title": "Path referencing non-existent resources",
                "steps": [
                    {
                        "step": 1,
                        "resource_id": "providers/Microsoft.Compute/virtualMachines/phantom-vm-999",
                        "description": "Fake VM compromised",
                        "finding_ids": ["FIND-001"]
                    }
                ]
            }
        ]
    }

    # Because phantom-vm-999 does not exist, the step is rejected, and path has 0 steps -> omitted
    validated = validator.validate_threat_model_response(raw_response, valid_resources, valid_findings)
    assert validated["total_paths"] == 0
    assert len(validated["attack_paths"]) == 0

def test_validate_threat_model_sanitizes_enums():
    validator = AIResponseValidator()
    valid_resources = {"res-1"}
    valid_findings = set()

    raw_response = {
        "attack_paths": [
            {
                "id": "path-01",
                "risk": "SUPER_EXTREME_DOOMSDAY",  # Invalid enum
                "confidence": "CERTAIN",            # Invalid enum
                "steps": [
                    {"step": 1, "resource_id": "res-1", "description": "Step 1"}
                ]
            }
        ]
    }

    validated = validator.validate_threat_model_response(raw_response, valid_resources, valid_findings)
    assert validated["total_paths"] == 1
    path = validated["attack_paths"][0]
    # Falls back to safe default MEDIUM
    assert path["risk"] == "MEDIUM"
    assert path["confidence"] == "MEDIUM"

def test_validate_finding_explanation_response():
    validator = AIResponseValidator()
    raw = {
        "explanation": "This setting allows open inbound traffic.",
        "abuse_scenario": "Attacker scans port 22 and attempts brute force.",
        "impact": "Host compromise.",
        "remediation_steps": ["Restrict NSG source to bastion subnet"],
        "validation_steps": ["Run nmap to confirm port 22 is closed"],
        "limitations": ["Live NSG runtime flow not confirmed"]
    }

    res = validator.validate_finding_explanation_response(raw, "res-nic", "FIND-01")
    assert res["finding_id"] == "FIND-01"
    assert res["resource_id"] == "res-nic"
    assert "open inbound traffic" in res["explanation"]
    assert len(res["remediation_steps"]) == 1

def test_validate_finding_explanation_empty_raises_error():
    validator = AIResponseValidator()
    with pytest.raises(AIValidationError):
        validator.validate_finding_explanation_response({}, "res-nic", "FIND-01")

