import pytest
from app.services.template_parser import ArmTemplateParser
from app.services.resource_mapper import ResourceMapper, determine_resource_risk
from app.services.dependency_resolver import DependencyResolver
from app.security_rules.base_rule import SecurityFinding

def test_dependency_resolver_explicit_depends(load_fixture_json):
    complex_data = load_fixture_json('complex_template.json')
    parser = ArmTemplateParser(complex_data)
    resources, _, _ = parser.parse()

    resolver = DependencyResolver(resources)
    edges = resolver.resolve_edges()

    assert len(edges) > 0
    # Confirm edge structure
    for edge in edges:
        assert "data" in edge
        assert "source" in edge["data"]
        assert "target" in edge["data"]
        assert "relation_type" in edge["data"]

def test_implicit_network_relationship_inference(load_fixture_json):
    complex_data = load_fixture_json('complex_template.json')
    parser = ArmTemplateParser(complex_data)
    resources, _, _ = parser.parse()

    resolver = DependencyResolver(resources)
    edges = resolver.resolve_edges()

    # Look for NIC to Subnet connection
    nic_edges = [e for e in edges if e["data"]["relation_type"] in ("network_association", "security_boundary")]
    assert len(nic_edges) > 0

def test_determine_resource_risk():
    class DummyFinding:
        def __init__(self, sev):
            self.severity = sev

    assert determine_resource_risk([]) == "CLEAN"
    assert determine_resource_risk([DummyFinding("LOW")]) == "LOW"
    assert determine_resource_risk([DummyFinding("LOW"), DummyFinding("CRITICAL")]) == "CRITICAL"
    assert determine_resource_risk([DummyFinding("MEDIUM"), DummyFinding("HIGH")]) == "HIGH"

def test_resource_mapper_generation(load_fixture_json):
    secure_data = load_fixture_json('secure_template.json')
    parser = ArmTemplateParser(secure_data)
    resources, _, _ = parser.parse()

    mapper = ResourceMapper(resources, findings=[])
    graph = mapper.generate_graph()

    assert "nodes" in graph
    assert "edges" in graph
    assert len(graph["nodes"]) == len(resources)
    assert graph["stats"]["total_nodes"] == len(resources)
    # Check that rich attributes are populated
    for node in graph["nodes"]:
        assert "type_short" in node["data"]
        assert "category" in node["data"]
        assert "findings" in node["data"]
        assert isinstance(node["data"]["findings"], list)

