import uuid
from typing import List, Dict, Any
from app.security_rules.base_rule import BaseSecurityRule, SecurityFinding
from app.services.template_parser import NormalizedResource

MONITORED_SECURITY_TYPES = {
    "microsoft.keyvault/vaults": "Key Vault",
    "microsoft.network/networksecuritygroups": "Network Security Group"
}

class MissingDiagnosticSettingsRule(BaseSecurityRule):
    @property
    def rule_id(self) -> str:
        return "SEC-LOG-001"

    @property
    def title(self) -> str:
        return "Missing Diagnostic Settings for Security-Sensitive Resource"

    @property
    def description(self) -> str:
        return "Security-sensitive resources such as Key Vaults and NSGs should forward audit and activity logs to Log Analytics or a SIEM."

    @property
    def severity(self) -> str:
        return "LOW"

    @property
    def category(self) -> str:
        return "Logging & Monitoring"

    @property
    def applicable_resource_types(self) -> List[str]:
        return list(MONITORED_SECURITY_TYPES.keys())

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        r_type = resource.type.lower()
        if r_type not in MONITORED_SECURITY_TYPES:
            return findings

        # Check if there is an accompanying Microsoft.Insights/diagnosticSettings resource targeting this resource
        diag_found = False
        for other in all_resources:
            if other.type.lower() in ("microsoft.insights/diagnosticsettings", "providers/microsoft.insights/diagnosticsettings"):
                # Check if other depends on this or scopes to this
                if resource.id.lower() in [d.lower() for d in other.depends_on] or resource.name.lower() in other.name.lower():
                    diag_found = True
                    break

        if not diag_found:
            friendly_name = MONITORED_SECURITY_TYPES[r_type]
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                title=f"{friendly_name} Lacks Diagnostic Logging Configuration in Template",
                description=f"{friendly_name} '{resource.name}' does not have an accompanying diagnosticSettings resource defined.",
                severity=self.severity,
                category=self.category,
                affected_resource_id=resource.id,
                affected_resource_name=resource.name,
                affected_resource_type=resource.type,
                json_path=resource.json_path,
                evidence=f"No Microsoft.Insights/diagnosticSettings resource targets {resource.name} in this template.",
                impact="Security incidents, unauthorized secret access, or firewall drop events cannot be investigated without audit trails.",
                remediation="Declare a Microsoft.Insights/diagnosticSettings resource in the template sending audit logs to a Log Analytics Workspace.",
                confidence="Incomplete Evidence"
            ))
        return findings

