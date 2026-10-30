import json
import pytest
from app.services.template_parser import ArmTemplateParser
from app.services.security_scanner import SecurityScanner
from app.services.resource_mapper import ResourceMapper
from app.services.report_generator import ReportGenerator

def test_report_generator_summary_and_export(load_fixture_json):
    insecure_data = load_fixture_json('insecure_template.json')
    parser = ArmTemplateParser(insecure_data)
    resources, metadata, warnings = parser.parse()

    scanner = SecurityScanner()
    findings = scanner.scan(resources, metadata)

    mapper = ResourceMapper(resources, findings)
    graph = mapper.generate_graph()

    reporter = ReportGenerator(
        file_id="test-file-1234",
        filename="insecure_template.json",
        resources=resources,
        edges=graph["edges"],
        findings=findings,
        metadata=metadata,
        warnings=warnings
    )

    summary = reporter.generate_summary()
    assert summary["total_resources"] == len(resources)
    assert summary["total_findings"] == len(findings)
    assert summary["unique_rules_count"] >= 15
    assert len(summary["unique_rule_ids"]) == summary["unique_rules_count"]
    assert summary["severity_counts"]["CRITICAL"] >= 1
    assert summary["severity_counts"]["HIGH"] >= 1

    export_report = reporter.generate_export_report()
    assert export_report["report_metadata"]["file_id"] == "test-file-1234"
    assert "findings" in export_report
    assert "resources" in export_report
    assert len(export_report["findings"]) == len(findings)

def test_export_endpoint(client, load_fixture):
    # Load sample to create a session
    load_res = client.post('/api/load-sample/insecure')
    assert load_res.status_code == 200
    file_id = load_res.get_json()['file_id']

    # Fetch export
    export_res = client.get(f'/report/{file_id}/export')
    assert export_res.status_code == 200
    assert export_res.mimetype == 'application/json'
    assert 'attachment' in export_res.headers.get('Content-Disposition', '')
    
    report_data = json.loads(export_res.data)
    assert report_data['report_metadata']['file_id'] == file_id
    assert len(report_data['findings']) > 0

