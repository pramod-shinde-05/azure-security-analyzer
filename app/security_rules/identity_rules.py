import uuid
from typing import List, Dict, Any
from app.security_rules.base_rule import BaseSecurityRule, SecurityFinding
from app.services.template_parser import NormalizedResource

OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR_ROLE_ID = "b24988ac-6180-42a0-ab88-20f7382dd24c"

class BroadSubscriptionRoleAssignmentRule(BaseSecurityRule):
    @property
    def rule_id(self) -> str:
        return "SEC-ID-001"

    @property
    def title(self) -> str:
        return "High-Privilege Role Assigned at Subscription Scope"

    @property
    def description(self) -> str:
        return "Role assignments granting Owner or Contributor at the subscription scope violate the principle of least privilege."

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def category(self) -> str:
        return "Identity & Access"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.authorization/roleassignments"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        role_def = str(resource.properties.get("roleDefinitionId", "")).lower()
        scope = str(resource.properties.get("scope", "")).lower()

        is_high_priv = OWNER_ROLE_ID in role_def or CONTRIBUTOR_ROLE_ID in role_def or "owner" in role_def or "contributor" in role_def
        is_broad_scope = not scope or scope in ("/", "[subscription().id]", "subscription()") or (scope.startswith("/subscriptions/") and "/resourcegroups/" not in scope)

        if is_high_priv and is_broad_scope:
            role_label = "Owner" if (OWNER_ROLE_ID in role_def or "owner" in role_def) else "Contributor"
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                title=self.title,
                description=f"Role assignment '{resource.name}' assigns broad '{role_label}' role across the entire subscription scope.",
                severity=self.severity,
                category=self.category,
                affected_resource_id=resource.id,
                affected_resource_name=resource.name,
                affected_resource_type=resource.type,
                json_path=f"{resource.json_path}.properties.scope",
                evidence=f"roleDefinitionId: '{role_def}', scope: '{scope or 'Subscription level'}'",
                impact="If the assigned identity is compromised, the attacker gains full control over all cloud resources in the subscription.",
                remediation="Scope the role assignment to a specific Resource Group or resource, and use custom or specific roles with minimal required permissions."
            ))
        return findings


class CustomRoleWildcardRule(BaseSecurityRule):
    @property
    def rule_id(self) -> str:
        return "SEC-ID-002"

    @property
    def title(self) -> str:
        return "Custom Role Definition Contains Wildcard Actions (*)"

    @property
    def description(self) -> str:
        return "Custom RBAC role definitions should not include wildcard actions '*' which grant unconstrained permissions."

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def category(self) -> str:
        return "Identity & Access"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.authorization/roledefinitions"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        permissions = resource.properties.get("permissions", [])
        if isinstance(permissions, list):
            for idx, perm in enumerate(permissions):
                actions = perm.get("actions", [])
                if isinstance(actions, list) and any(a == "*" or a.endswith("/*") for a in actions):
                    findings.append(SecurityFinding(
                        finding_id=str(uuid.uuid4()),
                        rule_id=self.rule_id,
                        title=self.title,
                        description=f"Custom role '{resource.name}' contains wildcard actions '{actions}'.",
                        severity=self.severity,
                        category=self.category,
                        affected_resource_id=resource.id,
                        affected_resource_name=resource.name,
                        affected_resource_type=resource.type,
                        json_path=f"{resource.json_path}.properties.permissions[{idx}].actions",
                        evidence=f"Permissions contain wildcard: {actions}",
                        impact="Grants excessive actions across current and future Azure resource provider operations, leading to privilege escalation.",
                        remediation="Explicitly enumerate only the specific Azure operations (e.g. 'Microsoft.Storage/storageAccounts/read') needed by the workload."
                    ))
        return findings

