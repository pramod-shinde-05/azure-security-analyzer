import uuid
from typing import List, Dict, Any, Optional, Tuple
from app.security_rules.base_rule import BaseSecurityRule, SecurityFinding
from app.services.template_parser import NormalizedResource

def extract_app_config(resource: NormalizedResource, all_resources: List[NormalizedResource]) -> Tuple[Dict[str, Any], str]:
    # Check inline siteConfig
    inline_config = resource.properties.get("siteConfig")
    if isinstance(inline_config, dict):
        return inline_config, f"{resource.json_path}.properties.siteConfig"

    # Check child/associated config resources
    res_name_lower = resource.name.lower()
    res_id_lower = resource.id.lower()
    for other in all_resources:
        if other.type.lower() == "microsoft.web/sites/config":
            if other.name.lower() in ("web", "appsettings") or res_name_lower in other.id.lower() or res_id_lower in other.id.lower():
                return other.properties, other.json_path
            # Check dependsOn or parent
            if any(res_name_lower in dep.lower() or res_id_lower in dep.lower() for dep in other.depends_on):
                return other.properties, other.json_path

    # Default to direct properties on site if present
    return resource.properties, f"{resource.json_path}.properties"


class AppServiceRemoteDebuggingRule(BaseSecurityRule):
    """
    TA-000002, TA-000008, TA-000014: Remote debugging should be turned off for API, Function, and Web apps.
    """
    @property
    def rule_id(self) -> str:
        return "SEC-APP-001"

    @property
    def title(self) -> str:
        return "App Service Remote Debugging Enabled"

    @property
    def description(self) -> str:
        return "Remote debugging opens diagnostic inbound ports on App Services, exposing them to internet-based attacks and compromise."

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def category(self) -> str:
        return "App Service"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.web/sites"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        config, path_prefix = extract_app_config(resource, all_resources)
        remote_debug = config.get("remoteDebuggingEnabled")

        if remote_debug is True or str(remote_debug).lower() == "true":
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                title=self.title,
                description=f"App Service '{resource.name}' has remote debugging enabled.",
                severity=self.severity,
                category=self.category,
                affected_resource_id=resource.id,
                affected_resource_name=resource.name,
                affected_resource_type=resource.type,
                json_path=f"{path_prefix}.remoteDebuggingEnabled",
                evidence="remoteDebuggingEnabled is explicitly set to true.",
                impact="Remote debugging opens listening debug ports that bypass standard authentication, enabling remote code execution and data exfiltration.",
                remediation="Set 'remoteDebuggingEnabled' to false or remove the property from the App Service siteConfig."
            ))
        return findings


class AppServiceFtpsEnforcementRule(BaseSecurityRule):
    """
    TA-000003, TA-000009, TA-000015: FTPS only should be required in your App Service.
    """
    @property
    def rule_id(self) -> str:
        return "SEC-APP-002"

    @property
    def title(self) -> str:
        return "App Service Allows Insecure FTP Access"

    @property
    def description(self) -> str:
        return "FTP without TLS encrypts neither credentials nor application code in transit. App Services must enforce FTPS only or disable FTP entirely."

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def category(self) -> str:
        return "App Service"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.web/sites"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        config, path_prefix = extract_app_config(resource, all_resources)
        ftps_state = config.get("ftpsState")

        # Allowed secure states: FtpsOnly or Disabled
        if ftps_state is not None:
            state_str = str(ftps_state).strip().lower()
            if state_str not in ("ftpsonly", "disabled"):
                findings.append(SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    rule_id=self.rule_id,
                    title=self.title,
                    description=f"App Service '{resource.name}' allows unencrypted FTP (ftpsState: '{ftps_state}').",
                    severity=self.severity,
                    category=self.category,
                    affected_resource_id=resource.id,
                    affected_resource_name=resource.name,
                    affected_resource_type=resource.type,
                    json_path=f"{path_prefix}.ftpsState",
                    evidence=f"ftpsState is configured as '{ftps_state}'.",
                    impact="Cleartext FTP deployment credentials and application source files can be sniffed or intercepted over untrusted networks.",
                    remediation="Configure 'ftpsState' to 'FtpsOnly' or 'Disabled' in siteConfig."
                ))
        return findings


class AppServiceMinTlsVersionRule(BaseSecurityRule):
    """
    TA-000005, TA-000011, TA-000017: Latest TLS version (1.2) should be used in App Services.
    """
    @property
    def rule_id(self) -> str:
        return "SEC-APP-003"

    @property
    def title(self) -> str:
        return "App Service Minimum TLS Version Below 1.2"

    @property
    def description(self) -> str:
        return "Legacy TLS versions (1.0 and 1.1) have known protocol vulnerabilities such as POODLE and BEAST. App Services should enforce TLS 1.2."

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def category(self) -> str:
        return "App Service"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.web/sites"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        config, path_prefix = extract_app_config(resource, all_resources)
        min_tls = config.get("minTlsVersion")

        if min_tls is not None:
            tls_str = str(min_tls).strip().lower()
            if tls_str in ("1.0", "1.1", "tls1_0", "tls1_1"):
                findings.append(SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    rule_id=self.rule_id,
                    title=self.title,
                    description=f"App Service '{resource.name}' allows weak TLS version '{min_tls}'.",
                    severity=self.severity,
                    category=self.category,
                    affected_resource_id=resource.id,
                    affected_resource_name=resource.name,
                    affected_resource_type=resource.type,
                    json_path=f"{path_prefix}.minTlsVersion",
                    evidence=f"minTlsVersion is set to '{min_tls}'.",
                    impact="Clients connecting to the web app can negotiate weak cryptographic ciphers vulnerable to decryption and man-in-the-middle attacks.",
                    remediation="Set 'minTlsVersion' to '1.2' in the App Service siteConfig."
                ))
        return findings


class AppServiceCorsWildcardRule(BaseSecurityRule):
    """
    TA-000006, TA-000012, TA-000018: CORS should not allow every origin to access the App Service.
    """
    @property
    def rule_id(self) -> str:
        return "SEC-APP-004"

    @property
    def title(self) -> str:
        return "App Service CORS Allows Wildcard All Origins (*)"

    @property
    def description(self) -> str:
        return "Cross-Origin Resource Sharing (CORS) should restrict domain access. Setting allowedOrigins to '*' permits arbitrary malicious web domains to read API responses."

    @property
    def severity(self) -> str:
        return "MEDIUM"

    @property
    def category(self) -> str:
        return "App Service"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.web/sites"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        config, path_prefix = extract_app_config(resource, all_resources)
        cors = config.get("cors") or {}
        allowed_origins = cors.get("allowedOrigins", [])

        if isinstance(allowed_origins, list) and "*" in allowed_origins:
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                title=self.title,
                description=f"App Service '{resource.name}' has wildcard '*' in CORS allowedOrigins.",
                severity=self.severity,
                category=self.category,
                affected_resource_id=resource.id,
                affected_resource_name=resource.name,
                affected_resource_type=resource.type,
                json_path=f"{path_prefix}.cors.allowedOrigins",
                evidence="allowedOrigins contains wildcard '*'.",
                impact="Malicious websites visited by authenticated users can make cross-origin requests to this service and exfiltrate confidential data.",
                remediation="Replace wildcard '*' in 'cors.allowedOrigins' with explicit, trusted origin domains."
            ))
        return findings


class AppServiceManagedIdentityRule(BaseSecurityRule):
    """
    TA-000007, TA-000013, TA-000019: Managed identity should be used in App Services.
    """
    @property
    def rule_id(self) -> str:
        return "SEC-APP-005"

    @property
    def title(self) -> str:
        return "App Service Managed Identity Disabled"

    @property
    def description(self) -> str:
        return "App Services should utilize Azure Managed Identities (SystemAssigned or UserAssigned) to avoid embedding hardcoded credentials in connection strings."

    @property
    def severity(self) -> str:
        return "LOW"

    @property
    def category(self) -> str:
        return "Identity & Access"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.web/sites"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        identity = resource.raw_json.get("identity") or resource.properties.get("identity")
        identity_type = ""
        if isinstance(identity, dict):
            identity_type = str(identity.get("type", "")).strip()

        valid_types = {"systemassigned", "userassigned", "systemassigned, userassigned", "systemassigned,userassigned"}
        if not identity_type or identity_type.lower() not in valid_types:
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                title=self.title,
                description=f"App Service '{resource.name}' does not configure a Managed Identity.",
                severity=self.severity,
                category=self.category,
                affected_resource_id=resource.id,
                affected_resource_name=resource.name,
                affected_resource_type=resource.type,
                json_path=f"{resource.json_path}.identity",
                evidence=f"identity is '{identity_type or 'None'}'.",
                impact="Applications without Managed Identity often rely on static passwords, access keys, or API tokens stored insecurely in configuration files.",
                remediation="Configure 'identity.type' to 'SystemAssigned' or 'UserAssigned' on the App Service site definition."
            ))
        return findings
