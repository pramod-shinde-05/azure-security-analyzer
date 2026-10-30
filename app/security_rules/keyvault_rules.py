import uuid
from typing import List, Dict, Any
from app.security_rules.base_rule import BaseSecurityRule, SecurityFinding
from app.services.template_parser import NormalizedResource

class KeyVaultPurgeProtectionRule(BaseSecurityRule):
    """
    Key Vault soft delete and purge protection should be enabled to prevent accidental
    or malicious permanent deletion of secrets, keys, and certificates.
    """
    @property
    def rule_id(self) -> str:
        return "SEC-KV-001"

    @property
    def title(self) -> str:
        return "Key Vault Soft Delete or Purge Protection Disabled"

    @property
    def description(self) -> str:
        return "Azure Key Vaults must enable soft delete and purge protection to safeguard cryptographic keys and secrets against ransomware and unrecoverable deletion."

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def category(self) -> str:
        return "Security & Secrets"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.keyvault/vaults"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        enable_soft_delete = resource.properties.get("enableSoftDelete")
        enable_purge_protection = resource.properties.get("enablePurgeProtection")

        is_soft_disabled = (enable_soft_delete is False or str(enable_soft_delete).lower() == "false")
        is_purge_disabled = (enable_purge_protection is False or str(enable_purge_protection).lower() == "false")

        if is_soft_disabled or is_purge_disabled:
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                title=self.title,
                description=f"Key Vault '{resource.name}' does not enforce soft-delete or purge protection.",
                severity=self.severity,
                category=self.category,
                affected_resource_id=resource.id,
                affected_resource_name=resource.name,
                affected_resource_type=resource.type,
                json_path=f"{resource.json_path}.properties",
                evidence=f"enableSoftDelete: {enable_soft_delete}, enablePurgeProtection: {enable_purge_protection}",
                impact="If deleted by a compromised admin account or ransomware script, cryptographic keys and production certificates are permanently lost without recovery.",
                remediation="Set 'properties.enableSoftDelete' to true and 'properties.enablePurgeProtection' to true on Key Vault resources."
            ))
        return findings

