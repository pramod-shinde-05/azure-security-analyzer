import pytest
from app.services.template_parser import ArmTemplateParser
from app.services.dependency_resolver import DependencyResolver

def test_insecure_template_dependency_resolution(load_fixture_json):
    data = load_fixture_json("insecure_template.json")
    parser = ArmTemplateParser(data)
    resources, metadata, _ = parser.parse()

    resolver = DependencyResolver(resources)
    edges = resolver.resolve_edges()

    assert len(resources) == 11
    # Ensure there are multiple rich relationships connecting the nodes
    assert len(edges) >= 7, f"Expected at least 7 edges, got {len(edges)}"

    # Check that connected node ids include webapp, storage, redis, vault, nic, pip, role definition
    edge_nodes = set()
    for e in edges:
        edge_nodes.add(e["data"]["source"])
        edge_nodes.add(e["data"]["target"])
        assert "traffic_flow" in e["data"]
        assert e["data"]["traffic_flow"] in ("incoming", "outgoing", "control", "forward")

    # Resource names to check
    res_dict = {r.id: r for r in resources}
    connected_res_names = {res_dict[nid].name for nid in edge_nodes if nid in res_dict}

    assert "insecure-pip" in connected_res_names
    assert "insecure-nic" in connected_res_names
    assert "insecure-webapp" in connected_res_names
    assert "insecurestorage9823" in connected_res_names
    assert "insecure-redis" in connected_res_names
    assert "insecure-vault-no-diag" in connected_res_names
    assert "insecure-nsg" in connected_res_names
    assert "bad-subscription-role-assign" in connected_res_names
    assert "overly-permissive-custom-role" in connected_res_names
    assert "insecure-auto/secret-token" in connected_res_names

def test_complex_template_dependency_resolution(load_fixture_json):
    data = load_fixture_json("complex_template.json")
    parser = ArmTemplateParser(data)
    resources, metadata, _ = parser.parse()

    resolver = DependencyResolver(resources)
    edges = resolver.resolve_edges()

    assert len(edges) >= 4
    for e in edges:
        assert "traffic_flow" in e["data"]
