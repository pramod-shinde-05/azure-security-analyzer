import uuid
from typing import List, Dict, Any
from app.security_rules.base_rule import BaseSecurityRule, SecurityFinding
from app.services.template_parser import NormalizedResource

class AppServiceHttpsOnlyRule(BaseSecurityRule):
    @property
    def rule_id(self) -> str:
        return "SEC-ENC-001"

    @property
    def title(self) -> str:
        return "App Service Web App Allows Unencrypted HTTP"

    @property
    def description(self) -> str:
        return "Azure App Service web applications should enforce HTTPS-only traffic to secure communication in transit."

    @property
    def severity(self) -> str:
        return "MEDIUM"

    @property
    def category(self) -> str:
        return "Encryption & Transit"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.web/sites"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        https_only = resource.properties.get("httpsOnly")
        if https_only is False or str(https_only).lower() == "false" or https_only is None:
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                title=self.title,
                description=f"Web App '{resource.name}' does not enforce HTTPS-only traffic.",
                severity=self.severity,
                category=self.category,
                affected_resource_id=resource.id,
                affected_resource_name=resource.name,
                affected_resource_type=resource.type,
                json_path=f"{resource.json_path}.properties.httpsOnly",
                evidence=f"httpsOnly is set to '{https_only}'",
                impact="Unencrypted HTTP requests can leak sensitive tokens, cookies, and user credentials in transit.",
                remediation="Configure 'properties.httpsOnly' to true on the App Service site definition."
            ))
        return findings


class SqlDatabaseTdeRule(BaseSecurityRule):
    @property
    def rule_id(self) -> str:
        return "SEC-ENC-002"

    @property
    def title(self) -> str:
        return "SQL Database Transparent Data Encryption (TDE) Disabled"

    @property
    def description(self) -> str:
        return "Azure SQL Databases should have Transparent Data Encryption enabled to protect data at rest."

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def category(self) -> str:
        return "Encryption & Transit"

    @property
    def applicable_resource_types(self) -> List[str]:
        return [
            "microsoft.sql/servers/databases",
            "microsoft.sql/servers/databases/transparentdataencryption"
        ]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        if resource.type.lower() == "microsoft.sql/servers/databases/transparentdataencryption":
            status = str(resource.properties.get("status", "")).lower()
            if status == "disabled":
                findings.append(SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    rule_id=self.rule_id,
                    title=self.title,
                    description=f"Transparent Data Encryption is explicitly disabled on '{resource.name}'.",
                    severity=self.severity,
                    category=self.category,
                    affected_resource_id=resource.id,
                    affected_resource_name=resource.name,
                    affected_resource_type=resource.type,
                    json_path=f"{resource.json_path}.properties.status",
                    evidence="transparentDataEncryption status is 'Disabled'",
                    impact="Database data files and backups are stored unencrypted at the storage level.",
                    remediation="Set 'properties.status' to 'Enabled' in the transparentDataEncryption resource."
                ))
        return findings


class StorageInfrastructureEncryptionRule(BaseSecurityRule):
    @property
    def rule_id(self) -> str:
        return "SEC-ENC-003"

    @property
    def title(self) -> str:
        return "Storage Account Lacks Double Encryption (Infrastructure Encryption)"

    @property
    def description(self) -> str:
        return "High-security workloads should enable infrastructure encryption (double encryption at rest)."

    @property
    def severity(self) -> str:
        return "LOW"

    @property
    def category(self) -> str:
        return "Encryption & Transit"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.storage/storageaccounts"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        encryption = resource.properties.get("encryption", {})
        infra_enc = encryption.get("requireInfrastructureEncryption")

        if infra_enc is False or str(infra_enc).lower() == "false":
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                title=self.title,
                description=f"Storage account '{resource.name}' has infrastructure encryption disabled.",
                severity=self.severity,
                category=self.category,
                affected_resource_id=resource.id,
                affected_resource_name=resource.name,
                affected_resource_type=resource.type,
                json_path=f"{resource.json_path}.properties.encryption.requireInfrastructureEncryption",
                evidence="requireInfrastructureEncryption is false.",
                impact="Data is encrypted at the service level, but lacks the secondary infrastructure-level hardware encryption layer.",
                remediation="Enable 'requireInfrastructureEncryption: true' for workloads with strict compliance standards.",
                confidence="Direct"
            ))
        return findings


class AutomationVariableEncryptionRule(BaseSecurityRule):
    """
    TA-000021: Automation account variables should be encrypted.
    """
    @property
    def rule_id(self) -> str:
        return "SEC-AUT-001"

    @property
    def title(self) -> str:
        return "Automation Account Variable Asset Unencrypted"

    @property
    def description(self) -> str:
        return "Azure Automation Account variables often store passwords, API keys, or tokens and must be encrypted at creation time."

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def category(self) -> str:
        return "Encryption & Secrets"

    @property
    def applicable_resource_types(self) -> List[str]:
        return [
            "microsoft.automation/automationaccounts/variables",
            "variables"
        ]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        is_encrypted = resource.properties.get("isEncrypted")
        if is_encrypted is False or str(is_encrypted).lower() == "false" or is_encrypted is None:
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                title=self.title,
                description=f"Automation variable '{resource.name}' is created without encryption.",
                severity=self.severity,
                category=self.category,
                affected_resource_id=resource.id,
                affected_resource_name=resource.name,
                affected_resource_type=resource.type,
                json_path=f"{resource.json_path}.properties.isEncrypted",
                evidence=f"isEncrypted is set to '{is_encrypted}'.",
                impact="Sensitive values and credentials stored in the variable can be inspected in plaintext via Azure Portal or ARM APIs.",
                remediation="Set 'properties.isEncrypted' to true when defining Automation account variables."
            ))
        return findings


class RedisNonSslPortRule(BaseSecurityRule):
    """
    TA-000022: Only secure connections to Azure Cache for Redis should be enabled.
    """
    @property
    def rule_id(self) -> str:
        return "SEC-REDIS-001"

    @property
    def title(self) -> str:
        return "Azure Cache for Redis Non-SSL Port Enabled"

    @property
    def description(self) -> str:
        return "Azure Cache for Redis should disable the cleartext non-SSL port (port 6379) to force TLS encryption for all cache client traffic."

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def category(self) -> str:
        return "Encryption & Transit"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.cache/redis"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        non_ssl = resource.properties.get("enableNonSslPort")
        if non_ssl is True or str(non_ssl).lower() == "true":
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                title=self.title,
                description=f"Redis cache '{resource.name}' has non-SSL port enabled.",
                severity=self.severity,
                category=self.category,
                affected_resource_id=resource.id,
                affected_resource_name=resource.name,
                affected_resource_type=resource.type,
                json_path=f"{resource.json_path}.properties.enableNonSslPort",
                evidence="enableNonSslPort is set to true.",
                impact="Unencrypted cache traffic transmits session state, tokens, and cached databases in plaintext, exposing them to network eavesdropping.",
                remediation="Set 'properties.enableNonSslPort' to false or remove the property from the Redis resource definition."
            ))
        return findings


