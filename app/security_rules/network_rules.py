import uuid
from typing import List, Dict, Any
from app.security_rules.base_rule import BaseSecurityRule, SecurityFinding
from app.services.template_parser import NormalizedResource

UNRESTRICTED_SOURCES = {"*", "0.0.0.0/0", "internet", "<any>"}

def is_unrestricted_source(source_val: Any) -> bool:
    if isinstance(source_val, str) and source_val.strip().lower() in UNRESTRICTED_SOURCES:
        return True
    if isinstance(source_val, list):
        return any(isinstance(s, str) and s.strip().lower() in UNRESTRICTED_SOURCES for s in source_val)
    return False

def matches_port(port_val: Any, target_port: str) -> bool:
    if isinstance(port_val, str):
        p_clean = port_val.strip()
        if p_clean == target_port or p_clean == "*":
            return True
        if "-" in p_clean:
            try:
                start, end = map(int, p_clean.split("-"))
                t_port = int(target_port)
                return start <= t_port <= end
            except ValueError:
                pass
    elif isinstance(port_val, list):
        return any(matches_port(p, target_port) for p in port_val)
    return False

def get_nsg_rules(resource: NormalizedResource) -> List[Dict[str, Any]]:
    rules = []
    # In properties.securityRules
    sec_rules = resource.properties.get("securityRules", [])
    if isinstance(sec_rules, list):
        for idx, r in enumerate(sec_rules):
            r_props = r.get("properties", r)
            rules.append((f"{resource.json_path}.properties.securityRules[{idx}]", r_props, r.get("name", f"rule_{idx}")))
    return rules

class NSGOpenSSHRule(BaseSecurityRule):
    @property
    def rule_id(self) -> str:
        return "SEC-NET-001"

    @property
    def title(self) -> str:
        return "Unrestricted Inbound SSH Access (Port 22)"

    @property
    def description(self) -> str:
        return "Network Security Group allows inbound SSH traffic (port 22) from the internet (0.0.0.0/0 or *)."

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def category(self) -> str:
        return "Network Security"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.network/networksecuritygroups"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        for path, props, rule_name in get_nsg_rules(resource):
            direction = str(props.get("direction", "")).lower()
            access = str(props.get("access", "")).lower()
            source = props.get("sourceAddressPrefix") or props.get("sourceAddressPrefixes")
            dest_port = props.get("destinationPortRange") or props.get("destinationPortRanges")

            if direction == "inbound" and access == "allow":
                if is_unrestricted_source(source) and matches_port(dest_port, "22"):
                    findings.append(SecurityFinding(
                        finding_id=str(uuid.uuid4()),
                        rule_id=self.rule_id,
                        title=self.title,
                        description=f"NSG rule '{rule_name}' permits inbound SSH (port 22) from '{source}'.",
                        severity=self.severity,
                        category=self.category,
                        affected_resource_id=resource.id,
                        affected_resource_name=resource.name,
                        affected_resource_type=resource.type,
                        json_path=path,
                        evidence=f"Rule: {rule_name}, Access: Allow, Direction: Inbound, Source: {source}, Port: {dest_port}",
                        impact="Exposing SSH to the public internet enables brute force, password spraying, and unauthorized remote code execution attacks.",
                        remediation="Restrict sourceAddressPrefix to specific enterprise IP CIDRs, or deploy Azure Bastion / VPN gateway instead of direct SSH."
                    ))
        return findings


class NSGOpenRDPRule(BaseSecurityRule):
    @property
    def rule_id(self) -> str:
        return "SEC-NET-002"

    @property
    def title(self) -> str:
        return "Unrestricted Inbound RDP Access (Port 3389)"

    @property
    def description(self) -> str:
        return "Network Security Group allows inbound RDP traffic (port 3389) from the internet (0.0.0.0/0 or *)."

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def category(self) -> str:
        return "Network Security"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.network/networksecuritygroups"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        for path, props, rule_name in get_nsg_rules(resource):
            direction = str(props.get("direction", "")).lower()
            access = str(props.get("access", "")).lower()
            source = props.get("sourceAddressPrefix") or props.get("sourceAddressPrefixes")
            dest_port = props.get("destinationPortRange") or props.get("destinationPortRanges")

            if direction == "inbound" and access == "allow":
                if is_unrestricted_source(source) and matches_port(dest_port, "3389"):
                    findings.append(SecurityFinding(
                        finding_id=str(uuid.uuid4()),
                        rule_id=self.rule_id,
                        title=self.title,
                        description=f"NSG rule '{rule_name}' permits inbound RDP (port 3389) from '{source}'.",
                        severity=self.severity,
                        category=self.category,
                        affected_resource_id=resource.id,
                        affected_resource_name=resource.name,
                        affected_resource_type=resource.type,
                        json_path=path,
                        evidence=f"Rule: {rule_name}, Access: Allow, Direction: Inbound, Source: {source}, Port: {dest_port}",
                        impact="Publicly accessible RDP ports frequently suffer from credential compromise, BlueKeep-style protocol vulnerabilities, and ransomware infiltration.",
                        remediation="Disable public inbound access to port 3389. Connect via Azure Bastion or an encrypted VPN tunnel."
                    ))
        return findings


class NSGAllowAllInboundRule(BaseSecurityRule):
    @property
    def rule_id(self) -> str:
        return "SEC-NET-003"

    @property
    def title(self) -> str:
        return "Unrestricted Inbound Access on All Ports (*)"

    @property
    def description(self) -> str:
        return "Network Security Group allows all inbound traffic on any port and protocol from any source."

    @property
    def severity(self) -> str:
        return "CRITICAL"

    @property
    def category(self) -> str:
        return "Network Security"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.network/networksecuritygroups"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        for path, props, rule_name in get_nsg_rules(resource):
            direction = str(props.get("direction", "")).lower()
            access = str(props.get("access", "")).lower()
            source = props.get("sourceAddressPrefix") or props.get("sourceAddressPrefixes")
            dest_port = props.get("destinationPortRange") or props.get("destinationPortRanges")
            protocol = str(props.get("protocol", "")).lower()

            if direction == "inbound" and access == "allow":
                if is_unrestricted_source(source) and dest_port in ("*", "0-65535") and protocol in ("*", "all"):
                    findings.append(SecurityFinding(
                        finding_id=str(uuid.uuid4()),
                        rule_id=self.rule_id,
                        title=self.title,
                        description=f"NSG rule '{rule_name}' allows unrestricted inbound traffic across all ports and protocols.",
                        severity=self.severity,
                        category=self.category,
                        affected_resource_id=resource.id,
                        affected_resource_name=resource.name,
                        affected_resource_type=resource.type,
                        json_path=path,
                        evidence=f"Rule: {rule_name}, Direction: Inbound, Protocol: *, Ports: {dest_port}, Source: {source}",
                        impact="Complete bypass of network perimeter defenses exposing all internal host services and application ports.",
                        remediation="Delete this rule and implement the principle of least privilege, allowing only necessary ports and restricted IP ranges."
                    ))
        return findings


class UnprotectedPublicIPRule(BaseSecurityRule):
    @property
    def rule_id(self) -> str:
        return "SEC-NET-004"

    @property
    def title(self) -> str:
        return "Public IP Associated With NIC Lacking Network Security Group"

    @property
    def description(self) -> str:
        return "A Network Interface has a Public IP address attached but neither the NIC nor its subnet has an NSG associated."

    @property
    def severity(self) -> str:
        return "MEDIUM"

    @property
    def category(self) -> str:
        return "Network Exposure"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.network/networkinterfaces"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        has_nsg = bool(resource.properties.get("networkSecurityGroup"))
        if has_nsg:
            return findings

        # Check if NIC has a public IP
        ip_configs = resource.properties.get("ipConfigurations", [])
        has_pip = False
        pip_path = resource.json_path
        for idx, ip_conf in enumerate(ip_configs):
            props = ip_conf.get("properties", {})
            if props.get("publicIPAddress"):
                has_pip = True
                pip_path = f"{resource.json_path}.properties.ipConfigurations[{idx}].properties.publicIPAddress"
                break

        if has_pip:
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                title=self.title,
                description=f"Network interface '{resource.name}' is directly assigned a Public IP without an attached NSG.",
                severity=self.severity,
                category=self.category,
                affected_resource_id=resource.id,
                affected_resource_name=resource.name,
                affected_resource_type=resource.type,
                json_path=pip_path,
                evidence="publicIPAddress is defined, but networkSecurityGroup property is absent on NIC.",
                impact="Direct exposure to external traffic without host network filtering leaves the associated VM vulnerable to network scanning.",
                remediation="Associate a Network Security Group with the NIC or its containing Subnet to filter ingress traffic.",
                confidence="Direct"
            ))
        return findings


class NSGOpenHTTPRule(BaseSecurityRule):
    """
    SEC-NET-005: Inbound NSG allows unrestricted HTTP (port 80) access from the internet.
    """
    @property
    def rule_id(self) -> str:
        return "SEC-NET-005"

    @property
    def title(self) -> str:
        return "Unrestricted Inbound HTTP Access (Port 80)"

    @property
    def description(self) -> str:
        return "Network Security Group allows inbound cleartext HTTP traffic (port 80) from the internet (0.0.0.0/0 or *)."

    @property
    def severity(self) -> str:
        return "MEDIUM"

    @property
    def category(self) -> str:
        return "Network Security"

    @property
    def applicable_resource_types(self) -> List[str]:
        return ["microsoft.network/networksecuritygroups"]

    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        for path, props, rule_name in get_nsg_rules(resource):
            direction = str(props.get("direction", "")).lower()
            access = str(props.get("access", "")).lower()
            source = props.get("sourceAddressPrefix") or props.get("sourceAddressPrefixes")
            dest_port = props.get("destinationPortRange") or props.get("destinationPortRanges")

            if direction == "inbound" and access == "allow":
                if is_unrestricted_source(source) and matches_port(dest_port, "80"):
                    findings.append(SecurityFinding(
                        finding_id=str(uuid.uuid4()),
                        rule_id=self.rule_id,
                        title=self.title,
                        description=f"NSG rule '{rule_name}' permits inbound cleartext HTTP (port 80) from '{source}'.",
                        severity=self.severity,
                        category=self.category,
                        affected_resource_id=resource.id,
                        affected_resource_name=resource.name,
                        affected_resource_type=resource.type,
                        json_path=path,
                        evidence=f"Rule: {rule_name}, Access: Allow, Direction: Inbound, Source: {source}, Port: {dest_port}",
                        impact="Cleartext HTTP allows transmission of unencrypted session tokens, credentials, and data subject to MitM attacks.",
                        remediation="Enforce HTTPS (port 443) only and configure HTTP to HTTPS automatic redirection on web endpoints or Application Gateways."
                    ))
        return findings


