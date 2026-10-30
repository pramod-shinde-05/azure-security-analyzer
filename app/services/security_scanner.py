from typing import List, Dict, Any, Type
from app.services.template_parser import NormalizedResource
from app.security_rules.base_rule import BaseSecurityRule, SecurityFinding
from app.security_rules.network_rules import (
    NSGOpenSSHRule,
    NSGOpenRDPRule,
    NSGAllowAllInboundRule,
    UnprotectedPublicIPRule,
    NSGOpenHTTPRule
)
from app.security_rules.storage_rules import (
    StoragePublicBlobAccessRule,
    StorageHttpsOnlyRule,
    StorageWeakTlsRule,
    StoragePublicNetworkAccessRule
)
from app.security_rules.identity_rules import (
    BroadSubscriptionRoleAssignmentRule,
    CustomRoleWildcardRule
)
from app.security_rules.app_service_rules import (
    AppServiceRemoteDebuggingRule,
    AppServiceFtpsEnforcementRule,
    AppServiceMinTlsVersionRule,
    AppServiceCorsWildcardRule,
    AppServiceManagedIdentityRule
)
from app.security_rules.keyvault_rules import (
    KeyVaultPurgeProtectionRule
)
from app.security_rules.encryption_rules import (
    AppServiceHttpsOnlyRule,
    SqlDatabaseTdeRule,
    StorageInfrastructureEncryptionRule,
    AutomationVariableEncryptionRule,
    RedisNonSslPortRule
)
from app.security_rules.logging_rules import (
    MissingDiagnosticSettingsRule
)

DEFAULT_RULES: List[Type[BaseSecurityRule]] = [
    # Network security rules (5 rules)
    NSGOpenSSHRule,
    NSGOpenRDPRule,
    NSGAllowAllInboundRule,
    UnprotectedPublicIPRule,
    NSGOpenHTTPRule,
    # Storage security rules (4 rules)
    StoragePublicBlobAccessRule,
    StorageHttpsOnlyRule,
    StorageWeakTlsRule,
    StoragePublicNetworkAccessRule,
    # App Service rules (5 rules)
    AppServiceRemoteDebuggingRule,
    AppServiceFtpsEnforcementRule,
    AppServiceMinTlsVersionRule,
    AppServiceCorsWildcardRule,
    AppServiceManagedIdentityRule,
    # Key Vault rules (1 rule)
    KeyVaultPurgeProtectionRule,
    # Identity & Authorization rules (2 rules)
    BroadSubscriptionRoleAssignmentRule,
    CustomRoleWildcardRule,
    # Encryption & Transit rules (5 rules)
    AppServiceHttpsOnlyRule,
    SqlDatabaseTdeRule,
    StorageInfrastructureEncryptionRule,
    AutomationVariableEncryptionRule,
    RedisNonSslPortRule,
    # Logging & Monitoring rules (1 rule)
    MissingDiagnosticSettingsRule
]

class SecurityScanner:
    """Central engine that coordinates the execution of deterministic Azure security rules."""

    def __init__(self, rule_classes: List[Type[BaseSecurityRule]] = None):
        classes = rule_classes or DEFAULT_RULES
        self.rules: List[BaseSecurityRule] = [cls() for cls in classes]

    def scan(self, resources: List[NormalizedResource], template_metadata: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Runs all registered security rules against the resources.
        Returns a flat list of SecurityFinding objects.
        """
        all_findings: List[SecurityFinding] = []

        for resource in resources:
            res_type_lower = resource.type.lower()
            for rule in self.rules:
                applicable_types = [t.lower() for t in rule.applicable_resource_types]
                if any(res_type_lower == app_t or res_type_lower.endswith("/" + app_t) for app_t in applicable_types):
                    rule_findings = rule.evaluate(resource, resources, template_metadata)
                    all_findings.extend(rule_findings)

        return all_findings

