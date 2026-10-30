import uuid
from typing import List, Dict, Any
from app.security_rules.base_rule import BaseSecurityRule, SecurityFinding
from app.services.template_parser import NormalizedResource

class StoragePublicBlobAccessRule(BaseSecurityRule):
    @property
    def rule_id(self) -> str:
        return "SEC-STO-001"

    @property
    def title(self) -> str:
        return "Storage Account Allows Public Blob Access"

    @property
    def description(self) -> str:
        return "Storage accounts should disallow public / anonymous read access to containers and blobs."

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def category(self) -> str:
        return "Storage Security"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.storage/storageaccounts"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        allow_public = resource.properties.get("allowBlobPublicAccess")
        # In ARM, boolean true or omitted in older schemas allows public blob access
        if allow_public is True or str(allow_public).lower() == "true":
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                title=self.title,
                description=f"Storage account '{resource.name}' explicitly allows public blob access.",
                severity=self.severity,
                category=self.category,
                affected_resource_id=resource.id,
                affected_resource_name=resource.name,
                affected_resource_type=resource.type,
                json_path=f"{resource.json_path}.properties.allowBlobPublicAccess",
                evidence="allowBlobPublicAccess is set to true.",
                impact="Anonymous internet users can read sensitive container data, logs, or backups stored in the storage account without authentication.",
                remediation="Set 'properties.allowBlobPublicAccess' to false to prevent anonymous read access."
            ))
        return findings


class StorageHttpsOnlyRule(BaseSecurityRule):
    @property
    def rule_id(self) -> str:
        return "SEC-STO-002"

    @property
    def title(self) -> str:
        return "Storage Account Allows Unencrypted HTTP Traffic"

    @property
    def description(self) -> str:
        return "Storage account allows unencrypted HTTP traffic. Secure transfer (HTTPS) must be strictly enforced."

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def category(self) -> str:
        return "Storage Security"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.storage/storageaccounts"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        supports_https = resource.properties.get("supportsHttpsTrafficOnly")
        # If explicitly False, or omitted (default in legacy ARM)
        if supports_https is False or str(supports_https).lower() == "false":
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                title=self.title,
                description=f"Storage account '{resource.name}' has secure transfer disabled (HTTP allowed).",
                severity=self.severity,
                category=self.category,
                affected_resource_id=resource.id,
                affected_resource_name=resource.name,
                affected_resource_type=resource.type,
                json_path=f"{resource.json_path}.properties.supportsHttpsTrafficOnly",
                evidence="supportsHttpsTrafficOnly is set to false.",
                impact="Data in transit can be intercepted, sniffed, or modified via man-in-the-middle (MitM) attacks.",
                remediation="Set 'properties.supportsHttpsTrafficOnly' to true to force all API calls over TLS."
            ))
        return findings


class StorageWeakTlsRule(BaseSecurityRule):
    @property
    def rule_id(self) -> str:
        return "SEC-STO-003"

    @property
    def title(self) -> str:
        return "Storage Account Minimum TLS Version Below 1.2"

    @property
    def description(self) -> str:
        return "Storage accounts should enforce a minimum TLS version of 1.2 to protect against legacy cryptographic weaknesses."

    @property
    def severity(self) -> str:
        return "MEDIUM"

    @property
    def category(self) -> str:
        return "Storage Security"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.storage/storageaccounts"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        min_tls = resource.properties.get("minimumTlsVersion")
        if min_tls is None or str(min_tls).upper() in ("TLS1_0", "TLS1_1"):
            evidence_msg = f"minimumTlsVersion is '{min_tls}'" if min_tls else "minimumTlsVersion property is missing (defaults to legacy TLS versions)"
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                title=self.title,
                description=f"Storage account '{resource.name}' does not enforce TLS 1.2.",
                severity=self.severity,
                category=self.category,
                affected_resource_id=resource.id,
                affected_resource_name=resource.name,
                affected_resource_type=resource.type,
                json_path=f"{resource.json_path}.properties.minimumTlsVersion",
                evidence=evidence_msg,
                impact="Legacy protocols (TLS 1.0/1.1) use deprecated ciphers that are vulnerable to POODLE, BEAST, and other downgrade attacks.",
                remediation="Explicitly configure 'properties.minimumTlsVersion' to 'TLS1_2'."
            ))
        return findings


class StoragePublicNetworkAccessRule(BaseSecurityRule):
    @property
    def rule_id(self) -> str:
        return "SEC-STO-004"

    @property
    def title(self) -> str:
        return "Storage Account Public Network Access Enabled"

    @property
    def description(self) -> str:
        return "Storage accounts should restrict public network access and use private endpoints or virtual network firewalls where applicable."

    @property
    def severity(self) -> str:
        return "LOW"

    @property
    def category(self) -> str:
        return "Storage Security"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.storage/storageaccounts"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        net_access = resource.properties.get("publicNetworkAccess")
        net_acls = resource.properties.get("networkAcls", {})
        default_action = net_acls.get("defaultAction")

        if (net_access and str(net_access).lower() == "enabled") or (default_action and str(default_action).lower() == "allow"):
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                title=self.title,
                description=f"Storage account '{resource.name}' is reachable from all public networks.",
                severity=self.severity,
                category=self.category,
                affected_resource_id=resource.id,
                affected_resource_name=resource.name,
                affected_resource_type=resource.type,
                json_path=f"{resource.json_path}.properties.publicNetworkAccess",
                evidence=f"publicNetworkAccess: '{net_access}', networkAcls.defaultAction: '{default_action}'",
                impact="Broad network accessibility increases attack surface to authentication brute-force or endpoint DDoS attacks.",
                remediation="Restrict access by specifying virtual network rules, private endpoints, or set defaultAction to Deny.",
                confidence="Incomplete Evidence"
            ))
        return findings

