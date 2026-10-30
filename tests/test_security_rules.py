import pytest
from app.services.template_parser import ArmTemplateParser
from app.services.security_scanner import SecurityScanner
from app.services.report_generator import ReportGenerator

def test_insecure_template_triggers_rules(load_fixture_json):
    insecure_data = load_fixture_json('insecure_template.json')
    parser = ArmTemplateParser(insecure_data)
    resources, metadata, _ = parser.parse()

    scanner = SecurityScanner()
    findings = scanner.scan(resources, metadata)

    rule_ids = {f.rule_id for f in findings}

    # Verify that initial security rules triggered
    assert "SEC-NET-001" in rule_ids, "Should trigger open SSH rule"
    assert "SEC-NET-002" in rule_ids, "Should trigger open RDP rule"
    assert "SEC-NET-003" in rule_ids, "Should trigger open all ports rule"
    assert "SEC-NET-004" in rule_ids, "Should trigger Public IP without NSG rule"
    assert "SEC-NET-005" in rule_ids, "Should trigger open cleartext HTTP (port 80) rule"
    assert "SEC-STO-001" in rule_ids, "Should trigger storage public blob access rule"
    assert "SEC-STO-002" in rule_ids, "Should trigger storage HTTPS only rule"
    assert "SEC-STO-003" in rule_ids, "Should trigger storage weak TLS rule"
    assert "SEC-ID-001" in rule_ids, "Should trigger broad subscription role assignment rule"
    assert "SEC-ID-002" in rule_ids, "Should trigger wildcard custom role rule"
    assert "SEC-ENC-001" in rule_ids, "Should trigger App Service httpsOnly rule"
    assert "SEC-ENC-002" in rule_ids, "Should trigger SQL DB TDE disabled rule"
    assert "SEC-LOG-001" in rule_ids, "Should trigger Key Vault missing diagnostics rule"

    # Verify newly implemented high-value rules
    assert "SEC-APP-001" in rule_ids, "Should trigger App Service remote debugging rule"
    assert "SEC-APP-002" in rule_ids, "Should trigger App Service FTPS enforcement rule"
    assert "SEC-APP-003" in rule_ids, "Should trigger App Service min TLS version rule"
    assert "SEC-APP-004" in rule_ids, "Should trigger App Service CORS wildcard rule"
    assert "SEC-APP-005" in rule_ids, "Should trigger App Service managed identity rule"
    assert "SEC-KV-001" in rule_ids, "Should trigger Key Vault purge protection disabled rule"
    assert "SEC-REDIS-001" in rule_ids, "Should trigger Redis non-SSL port enabled rule"
    assert "SEC-AUT-001" in rule_ids, "Should trigger Automation variable unencrypted rule"

    # Check finding fields are populated properly
    for f in findings:
        assert f.finding_id
        assert f.title
        assert f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
        assert f.evidence
        assert f.impact
        assert f.remediation
        assert f.json_path

def test_secure_template_passes_cleanly(load_fixture_json):
    secure_data = load_fixture_json('secure_template.json')
    parser = ArmTemplateParser(secure_data)
    resources, metadata, _ = parser.parse()

    scanner = SecurityScanner()
    findings = scanner.scan(resources, metadata)

    rule_ids = {f.rule_id for f in findings}

    # High and critical rules must NOT trigger on the compliant template
    assert "SEC-NET-001" not in rule_ids
    assert "SEC-NET-002" not in rule_ids
    assert "SEC-NET-003" not in rule_ids
    assert "SEC-NET-005" not in rule_ids
    assert "SEC-STO-001" not in rule_ids
    assert "SEC-STO-002" not in rule_ids
    assert "SEC-STO-003" not in rule_ids
    assert "SEC-ENC-001" not in rule_ids
    assert "SEC-LOG-001" not in rule_ids
    assert "SEC-APP-001" not in rule_ids
    assert "SEC-APP-002" not in rule_ids
    assert "SEC-APP-003" not in rule_ids
    assert "SEC-APP-004" not in rule_ids
    assert "SEC-APP-005" not in rule_ids
    assert "SEC-KV-001" not in rule_ids

def test_unique_rules_counted_separately_from_findings(load_fixture_json):
    insecure_data = load_fixture_json('insecure_template.json')
    parser = ArmTemplateParser(insecure_data)
    resources, metadata, _ = parser.parse()

    scanner = SecurityScanner()
    findings = scanner.scan(resources, metadata)

    reporter = ReportGenerator(
        file_id="test-file",
        filename="insecure_template.json",
        resources=resources,
        edges=[],
        findings=findings,
        metadata=metadata,
        warnings=[]
    )
    summary = reporter.generate_summary()

    # Verify separate counts
    assert "unique_rules_count" in summary
    assert "total_findings" in summary
    assert "unique_rule_ids" in summary
    assert summary["unique_rules_count"] == len(summary["unique_rule_ids"])
    assert summary["unique_rules_count"] <= summary["total_findings"]
    assert summary["unique_rules_count"] >= 15
