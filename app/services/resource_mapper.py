from typing import List, Dict, Any
from app.services.template_parser import NormalizedResource
from app.services.dependency_resolver import DependencyResolver
from app.utils.sanitization import mask_sensitive_data

SEVERITY_WEIGHT = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFORMATIONAL": 1,
    "CLEAN": 0
}

def get_short_type(res_type: str) -> str:
    """Returns an intuitive friendly name for Azure resource types."""
    mapping = {
        "microsoft.compute/virtualmachines": "Virtual Machine",
        "microsoft.compute/virtualmachines/extensions": "VM Extension",
        "microsoft.compute/availabilitysets": "Availability Set",
        "microsoft.compute/virtualmachinescalesets": "VM Scale Set",
        "microsoft.network/virtualnetworks": "Virtual Network",
        "microsoft.network/virtualnetworks/subnets": "Subnet",
        "microsoft.network/subnets": "Subnet",
        "microsoft.network/networksecuritygroups": "Network Security Group",
        "microsoft.network/networkinterfaces": "Network Interface",
        "microsoft.network/publicipaddresses": "Public IP",
        "microsoft.network/loadbalancers": "Load Balancer",
        "microsoft.network/applicationgateways": "Application Gateway",
        "microsoft.network/privateendpoints": "Private Endpoint",
        "microsoft.storage/storageaccounts": "Storage Account",
        "microsoft.keyvault/vaults": "Key Vault",
        "microsoft.web/sites": "App Service",
        "microsoft.web/serverfarms": "App Service Plan",
        "microsoft.sql/servers": "SQL Server",
        "microsoft.sql/servers/databases": "SQL Database",
        "microsoft.authorization/roleassignments": "Role Assignment",
        "microsoft.authorization/roledefinitions": "Role Definition",
        "microsoft.managedidentity/userassignedidentities": "Managed Identity",
        "microsoft.automation/automationaccounts": "Automation Account",
        "microsoft.containerservice/managedclusters": "Kubernetes Cluster",
        "microsoft.logic/workflows": "Logic App",
        "microsoft.cache/redis": "Redis Cache",
        "microsoft.insights/diagnosticsettings": "Diagnostic Settings",
    }
    low = (res_type or "").lower()
    if low in mapping:
        return mapping[low]
    parts = res_type.split("/")
    return parts[-1] if parts else "Azure Resource"

def determine_resource_risk(findings_for_res: List[Any]) -> str:
    """Determine highest risk level for a resource based on its findings."""
    if not findings_for_res:
        return "CLEAN"
    highest_sev = "CLEAN"
    max_weight = 0
    for finding in findings_for_res:
        sev = finding.severity.upper() if hasattr(finding, 'severity') else finding.get('severity', 'CLEAN').upper()
        weight = SEVERITY_WEIGHT.get(sev, 0)
        if weight > max_weight:
            max_weight = weight
            highest_sev = sev
    return highest_sev

class ResourceMapper:
    """Transforms normalized resources and security findings into Cytoscape.js graph structure."""

    def __init__(self, resources: List[NormalizedResource], findings: List[Any]):
        self.resources = resources
        self.findings = findings
        # Index findings by affected_resource_id
        self.findings_by_resource: Dict[str, List[Any]] = {}
        for f in findings:
            r_id = f.affected_resource_id if hasattr(f, 'affected_resource_id') else f.get('affected_resource_id')
            if r_id:
                self.findings_by_resource.setdefault(r_id.lower(), []).append(f)

    def generate_graph(self) -> Dict[str, Any]:
        """Generate Cytoscape JSON payload containing nodes and edges."""
        nodes = []
        for res in self.resources:
            res_findings = self.findings_by_resource.get(res.id.lower(), [])
            risk_level = determine_resource_risk(res_findings)

            safe_properties = mask_sensitive_data(res.properties)

            node_data = {
                "id": res.id,
                "label": res.name,
                "type": res.type,
                "type_short": get_short_type(res.type),
                "category": res.category,
                "location": res.location,
                "api_version": res.api_version,
                "risk_level": risk_level,
                "finding_count": len(res_findings),
                "findings": [
                    {
                        "finding_id": f.finding_id if hasattr(f, 'finding_id') else f.get('finding_id'),
                        "rule_id": f.rule_id if hasattr(f, 'rule_id') else f.get('rule_id'),
                        "title": f.title if hasattr(f, 'title') else f.get('title'),
                        "severity": f.severity if hasattr(f, 'severity') else f.get('severity')
                    }
                    for f in res_findings
                ],
                "json_path": res.json_path,
                "properties": safe_properties
            }
            nodes.append({"data": node_data})

        # Resolve edges
        resolver = DependencyResolver(self.resources)
        edges = resolver.resolve_edges()

        return {
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "total_nodes": len(nodes),
                "total_edges": len(edges)
            }
        }

