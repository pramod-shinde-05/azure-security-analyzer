import pytest
from unittest.mock import MagicMock
from app.services.template_parser import ArmTemplateParser
from app.services.dependency_resolver import DependencyResolver
from app.services.security_scanner import SecurityScanner
from app.services.ai.threat_modeler import ThreatModeler
from app.services.ai.cache import AIResponseCache
from app.services.ai.provider import BaseAIProvider

class MockAIProvider(BaseAIProvider):
    def __init__(self, mock_response=None):
        super().__init__(model_name="mock-gemini")
        self.mock_response = mock_response or {}
        self.call_count = 0

    def generate_structured_response(self, system_instruction, user_content, response_schema=None):
        self.call_count += 1
        return self.mock_response

    def generate_text_response(self, system_instruction, user_content):
        self.call_count += 1
        return "Mock text response"

    def health_check(self):
        return {"status": "configured", "provider": "mock"}

def test_threat_modeler_synthesizes_attack_path(load_fixture_json):
    data = load_fixture_json("insecure_template.json")
    parser = ArmTemplateParser(data)
    resources, metadata, warnings = parser.parse()

    resolver = DependencyResolver(resources)
    edges = resolver.resolve_edges()

    scanner = SecurityScanner()
    findings = scanner.scan(resources, metadata)

    mock_llm_json = {
        "attack_paths": [
            {
                "id": "path-insecure-pip",
                "title": "Internet Ingress via Public IP to Storage Data",
                "risk": "HIGH",
                "summary": "External attacker can leverage Public IP and lateral data flow to access storage.",
                "steps": [
                    {
                        "step": 1,
                        "resource_id": "providers/Microsoft.Network/publicIPAddresses/insecure-pip",
                        "description": "Attacker initiates connection to public IP address.",
                        "finding_ids": [],
                        "evidence": ["Dynamic public IP allocated"],
                        "preconditions": ["Public IP is routable"]
                    },
                    {
                        "step": 2,
                        "resource_id": "providers/Microsoft.Storage/storageAccounts/insecurestorage9823",
                        "description": "Exfiltrates unencrypted blob data from publicly accessible container.",
                        "finding_ids": [f.finding_id for f in findings if "storage" in f.rule_id.lower()][:1],
                        "evidence": ["Blob public access is enabled"],
                        "preconditions": ["Storage blob is exposed"]
                    }
                ],
                "impact": "Data exfiltration of sensitive blob storage.",
                "assumptions": ["Internet connectivity is unblocked"],
                "unknowns": ["No third-party WAF configured"],
                "recommendations": ["Disable public blob access on storage account"],
                "evidence_strength": "CONFIGURATION_SUPPORTED",
                "confidence": "HIGH"
            }
        ]
    }

    mock_provider = MockAIProvider(mock_response=mock_llm_json)
    cache = AIResponseCache(enabled=True)
    modeler = ThreatModeler(provider=mock_provider, cache=cache)

    result = modeler.analyze_attack_paths(
        file_id="session-test-01",
        resources=resources,
        findings=findings,
        edges=edges,
        summary={"total_resources": len(resources)},
        warnings=warnings
    )

    assert result["status"] == "VALIDATED"
    assert result["total_paths"] == 1
    assert result["cached"] is False
    assert mock_provider.call_count == 1

    path = result["attack_paths"][0]
    assert path["id"] == "path-insecure-pip"
    assert len(path["steps"]) == 2

    # Second call should be served from cache without invoking provider
    cached_result = modeler.analyze_attack_paths(
        file_id="session-test-01",
        resources=resources,
        findings=findings,
        edges=edges
    )
    assert cached_result["cached"] is True
    assert mock_provider.call_count == 1  # Unchanged!

def test_threat_modeler_rejects_hallucinated_resource_ids(load_fixture_json):
    data = load_fixture_json("insecure_template.json")
    parser = ArmTemplateParser(data)
    resources, metadata, warnings = parser.parse()

    mock_llm_json = {
        "attack_paths": [
            {
                "id": "path-fake-ids",
                "title": "Path containing hallucinated resources",
                "risk": "CRITICAL",
                "summary": "This path cites non-existent cloud resources.",
                "steps": [
                    {
                        "step": 1,
                        "resource_id": "providers/Microsoft.Compute/virtualMachines/non-existent-vm-abc",
                        "description": "Attacker targets a phantom virtual machine.",
                        "finding_ids": []
                    }
                ],
                "impact": "None",
                "evidence_strength": "HYPOTHETICAL",
                "confidence": "LOW"
            }
        ]
    }

    mock_provider = MockAIProvider(mock_response=mock_llm_json)
    modeler = ThreatModeler(provider=mock_provider)

    result = modeler.analyze_attack_paths(
        file_id="session-test-fake",
        resources=resources,
        findings=[],
        edges=[]
    )

    # Because non-existent-vm-abc was rejected, the path has 0 valid steps and is discarded
    assert result["total_paths"] == 0
    assert len(result["attack_paths"]) == 0

def test_threat_modeler_handles_dict_inputs():
    dict_resources = [
        {
            "id": "providers/Microsoft.Network/publicIPAddresses/test-pip",
            "name": "test-pip",
            "type": "Microsoft.Network/publicIPAddresses",
            "category": "Network Exposure",
            "location": "eastus",
            "properties": {"publicIPAllocationMethod": "Dynamic"},
            "depends_on": []
        }
    ]
    dict_findings = [
        {
            "finding_id": "FIND-001",
            "rule_id": "SEC-NET-01",
            "title": "Public IP Exposed",
            "severity": "HIGH"
        }
    ]
    mock_llm_json = {
        "attack_paths": [
            {
                "id": "path-01",
                "title": "Ingress Path",
                "risk": "HIGH",
                "summary": "External access",
                "steps": [
                    {
                        "step": 1,
                        "resource_id": "providers/Microsoft.Network/publicIPAddresses/test-pip",
                        "description": "Attacker targets public IP",
                        "finding_ids": ["FIND-001"]
                    }
                ],
                "impact": "Exposure",
                "evidence_strength": "CONFIGURATION_SUPPORTED",
                "confidence": "HIGH"
            }
        ]
    }
    mock_provider = MockAIProvider(mock_response=mock_llm_json)
    modeler = ThreatModeler(provider=mock_provider)
    result = modeler.analyze_attack_paths(
        file_id="session-test-dict",
        resources=dict_resources,
        findings=dict_findings,
        edges=[]
    )
    assert result["total_paths"] == 1
    assert result["attack_paths"][0]["steps"][0]["resource_id"] == "providers/Microsoft.Network/publicIPAddresses/test-pip"


