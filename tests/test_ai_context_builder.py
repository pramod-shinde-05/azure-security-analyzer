import json
import pytest
from app.services.template_parser import NormalizedResource
from app.services.ai.context_builder import AIContextBuilder

@pytest.fixture
def sample_resources():
    return [
        NormalizedResource(
            id="providers/Microsoft.Network/publicIPAddresses/test-pip",
            name="test-pip",
            type="Microsoft.Network/publicIPAddresses",
            api_version="2021-05-01",
            location="eastus",
            properties={"publicIPAllocationMethod": "Dynamic"},
            depends_on=[],
            category="Network Exposure",
            json_path="$.resources[0]",
            raw_json={}
        ),
        NormalizedResource(
            id="providers/Microsoft.Storage/storageAccounts/teststorage",
            name="teststorage",
            type="Microsoft.Storage/storageAccounts",
            api_version="2021-08-01",
            location="eastus",
            properties={
                "allowBlobPublicAccess": True,
                "connectionString": "DefaultEndpointsProtocol=https;AccountName=test;AccountKey=SuperSecret123"
            },
            depends_on=[],
            category="Storage",
            json_path="$.resources[1]",
            raw_json={}
        )
    ]

def test_context_builder_masks_secrets(sample_resources):
    builder = AIContextBuilder()
    context = builder.build_threat_model_context(
        resources=sample_resources,
        findings=[],
        edges=[]
    )

    # Verify boundary notice exists
    assert "BEGIN UNTRUSTED ARM INFRASTRUCTURE DATA" in context
    assert "END UNTRUSTED ARM INFRASTRUCTURE DATA" in context

    # Verify sensitive secret was masked
    assert "SuperSecret123" not in context
    assert "MASKED" in context or "DefaultEndpointsProtocol" in context

def test_context_builder_relationship_evidence_classification(sample_resources):
    builder = AIContextBuilder()
    edges = [
        {
            "data": {
                "source": sample_resources[0].id,
                "target": sample_resources[1].id,
                "relation_type": "dependency",
                "label": "depends on"
            }
        },
        {
            "data": {
                "source": sample_resources[0].id,
                "target": sample_resources[1].id,
                "relation_type": "exposure",
                "label": "assigned Public IP"
            }
        }
    ]

    context = builder.build_threat_model_context(
        resources=sample_resources,
        findings=[],
        edges=edges
    )

    # Dependency is explicitly labeled as deployment order only
    assert "deployment_order_only" in context
    assert "configuration_verified_link" in context

def test_context_builder_budget_truncation(sample_resources):
    small_budget_builder = AIContextBuilder(max_context_chars=250)
    context = small_budget_builder.build_threat_model_context(
        resources=sample_resources,
        findings=[],
        edges=[]
    )

    assert "Truncated for budget" in context

def test_context_builder_handles_dict_resources():
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
            "severity": "HIGH",
            "category": "Network Security",
            "affected_resource_id": "providers/Microsoft.Network/publicIPAddresses/test-pip",
            "evidence": "Dynamic public IP",
            "impact": "Exposed directly to Internet",
            "remediation": "Restrict NSG"
        }
    ]
    builder = AIContextBuilder()
    context = builder.build_threat_model_context(
        resources=dict_resources,
        findings=dict_findings,
        edges=[]
    )
    assert "test-pip" in context
    assert "FIND-001" in context


