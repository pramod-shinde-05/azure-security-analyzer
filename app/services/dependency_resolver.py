import re
from typing import List, Dict, Any, Tuple, Optional, Set
from app.services.template_parser import NormalizedResource

class DependencyResolver:
    """
    Analyzes normalized ARM resources to discover deployment dependencies,
    network topologies, security boundaries, data flow channels, and authorization relationships.
    """

    def __init__(self, resources: List[NormalizedResource]):
        self.resources = resources
        self.resource_by_id: Dict[str, NormalizedResource] = {r.id.lower(): r for r in resources}
        self.resource_by_name: Dict[str, NormalizedResource] = {r.name.lower(): r for r in resources}
        
        # Also index parent prefix names and tokens for child resources (e.g. "parent" for "parent/child")
        self.resource_by_short_name: Dict[str, NormalizedResource] = {}
        for r in resources:
            parts = r.name.lower().split("/")
            for part in parts:
                part_clean = part.strip()
                if part_clean and part_clean not in self.resource_by_short_name:
                    self.resource_by_short_name[part_clean] = r
            # Also register type-shortname combo
            short_type = r.type.split("/")[-1].lower()
            self.resource_by_short_name[f"{short_type}:{parts[-1]}"] = r

    def resolve_edges(self) -> List[Dict[str, Any]]:
        """
        Builds graph edges with categorized relationship types and traffic flow direction.
        Returns a list of edge dictionaries formatted for Cytoscape.js and Native SVG.
        """
        edges: List[Dict[str, Any]] = []
        edge_set: Set[Tuple[str, str, str]] = set()

        def add_edge(source_id: str, target_id: str, relation_type: str, label: str):
            if not source_id or not target_id or source_id == target_id:
                return
            edge_key = (source_id, target_id, relation_type)
            if edge_key not in edge_set:
                edge_set.add(edge_key)

                # Determine traffic flow direction:
                # - "incoming": External traffic entering from Public IP / Gateway
                # - "outgoing": Compute workload traffic sending requests to Storage, Cache, DB, Secrets
                # - "control": Policy or Authorization boundary
                # - "forward": General network association or dependency
                traffic_flow = "forward"
                if relation_type == "exposure":
                    traffic_flow = "incoming"
                elif relation_type in ("data_flow", "integration"):
                    traffic_flow = "outgoing"
                elif relation_type in ("security_boundary", "authorization"):
                    traffic_flow = "control"

                edges.append({
                    "data": {
                        "id": f"edge_{len(edges) + 1}",
                        "source": source_id,
                        "target": target_id,
                        "relation_type": relation_type,
                        "label": label,
                        "traffic_flow": traffic_flow
                    }
                })

        for res in self.resources:
            res_type_lower = res.type.lower()

            # 1. Explicit dependsOn edges with intelligent relationship typing
            for dep in res.depends_on:
                target_id = self._match_resource_id(dep)
                if target_id and target_id != res.id:
                    target_res = self.resource_by_id.get(target_id.lower())
                    rel_type = "dependency"
                    rel_label = "depends on"
                    if target_res:
                        t_cat = target_res.category.lower()
                        t_type = target_res.type.lower()
                        if "network security" in t_cat or "networksecuritygroup" in t_type:
                            rel_type = "security_boundary"
                            rel_label = "protected by NSG"
                        elif "exposure" in t_cat or "publicip" in t_type:
                            rel_type = "exposure"
                            rel_label = "assigned Public IP"
                        elif "storage" in t_cat or "storage" in t_type:
                            rel_type = "data_flow"
                            rel_label = "stores data in Storage"
                        elif "redis" in t_cat or "redis" in t_type:
                            rel_type = "data_flow"
                            rel_label = "caches in Redis"
                        elif "database" in t_cat or "sql" in t_type:
                            rel_type = "data_flow"
                            rel_label = "queries Database"
                        elif "keyvault" in t_cat or "keyvault" in t_type:
                            rel_type = "integration"
                            rel_label = "secures secrets in Key Vault"
                        elif "identity" in t_cat or "role" in t_type:
                            rel_type = "authorization"
                            rel_label = "assigns custom role"
                        elif "network" in t_cat:
                            rel_type = "network_association"
                            rel_label = "network link to"
                    add_edge(res.id, target_id, rel_type, rel_label)

            # 2. Virtual Machine network interfaces
            if res_type_lower == "microsoft.compute/virtualmachines":
                nic_refs = res.properties.get("networkProfile", {}).get("networkInterfaces", [])
                for nic_ref in nic_refs:
                    target_nic = self._match_resource_id(nic_ref.get("id", ""))
                    if target_nic:
                        add_edge(res.id, target_nic, "network_association", "uses NIC")

            # 3. Network Interface Card (NIC) associations
            if res_type_lower == "microsoft.network/networkinterfaces":
                # Check NSG association on NIC
                nsg_ref = res.properties.get("networkSecurityGroup", {}).get("id", "")
                target_nsg = self._match_resource_id(nsg_ref)
                if target_nsg:
                    add_edge(res.id, target_nsg, "security_boundary", "protected by NSG")

                # Check Subnet & Public IP associations on IP configurations
                ip_configs = res.properties.get("ipConfigurations", [])
                for ip_conf in ip_configs:
                    ip_props = ip_conf.get("properties", {})
                    # Subnet link
                    subnet_ref = ip_props.get("subnet", {}).get("id", "")
                    target_subnet = self._match_resource_id(subnet_ref)
                    if target_subnet:
                        add_edge(res.id, target_subnet, "network_association", "attached to subnet")

                    # Public IP link
                    pip_ref = ip_props.get("publicIPAddress", {}).get("id", "")
                    target_pip = self._match_resource_id(pip_ref)
                    if target_pip:
                        add_edge(res.id, target_pip, "exposure", "assigned Public IP")

            # 4. Subnet associations
            if res_type_lower in ("microsoft.network/virtualnetworks/subnets", "microsoft.network/subnets"):
                nsg_ref = res.properties.get("networkSecurityGroup", {}).get("id", "")
                target_nsg = self._match_resource_id(nsg_ref)
                if target_nsg:
                    add_edge(res.id, target_nsg, "security_boundary", "protected by NSG")

                for other in self.resources:
                    if other.type.lower() == "microsoft.network/virtualnetworks":
                        if other.name.lower() in res.id.lower() or other.id.lower() in res.id.lower():
                            add_edge(res.id, other.id, "containment", "subnet of")
                            break

            # 5. Role assignments -> Role Definitions and Scopes
            if res_type_lower == "microsoft.authorization/roleassignments":
                # Match custom or assigned role definition in template
                role_def_ref = res.properties.get("roleDefinitionId", "")
                target_role = self._match_resource_id(role_def_ref)
                if target_role:
                    add_edge(res.id, target_role, "authorization", "assigns role")
                else:
                    # Check if any roleDefinition matches by name or id in template
                    for other in self.resources:
                        if other.type.lower() == "microsoft.authorization/roledefinitions":
                            if other.name.lower() in str(role_def_ref).lower() or other.id.lower() in str(role_def_ref).lower():
                                add_edge(res.id, other.id, "authorization", "assigns role")
                                break

                # Match scope
                scope_ref = res.properties.get("scope", "")
                target_scope = self._match_resource_id(scope_ref)
                if target_scope:
                    add_edge(res.id, target_scope, "authorization", "scoped to")

                # Match principal
                principal_ref = res.properties.get("principalId", "")
                target_principal = self._match_resource_id(principal_ref)
                if target_principal:
                    add_edge(res.id, target_principal, "authorization", "granted to")

            # 6. App Service web app hosting, networking, appSettings, and connectionStrings
            if res_type_lower in ("microsoft.web/sites", "microsoft.web/sites/slots"):
                # App Service Plan link
                server_farm_id = res.properties.get("serverFarmId")
                target_plan = self._match_resource_id(server_farm_id)
                if target_plan:
                    add_edge(res.id, target_plan, "hosting", "hosted on Plan")

                # VNet integration
                vnet_subnet_id = res.properties.get("virtualNetworkSubnetId")
                target_vnet_subnet = self._match_resource_id(vnet_subnet_id)
                if target_vnet_subnet:
                    add_edge(res.id, target_vnet_subnet, "network_association", "VNet integrated")

                # AppSettings references (Storage, Redis, Key Vault, Database, etc.)
                site_config = res.properties.get("siteConfig", {})
                app_settings = site_config.get("appSettings", [])
                self._extract_app_service_links(res, app_settings, add_edge)

                # ConnectionStrings references (SQL, Storage, etc.)
                connection_strings = site_config.get("connectionStrings", [])
                self._extract_app_service_links(res, connection_strings, add_edge)

            # 7. SQL Database parent SQL Server or transparent data encryption
            if "microsoft.sql/servers" in res_type_lower:
                if "/" in res.name:
                    parent_server_name = res.name.split("/")[0].lower()
                    if parent_server_name in self.resource_by_name:
                        add_edge(res.id, self.resource_by_name[parent_server_name].id, "containment", "hosted on SQL Server")
                for other in self.resources:
                    if other.type.lower() == "microsoft.sql/servers" and other.id != res.id:
                        if other.name.lower() in res.name.lower():
                            add_edge(res.id, other.id, "containment", "hosted on SQL Server")
                            break

            # 8. Diagnostic settings log destinations
            if res_type_lower == "microsoft.insights/diagnosticsettings":
                storage_id = res.properties.get("storageAccountId")
                target_sto = self._match_resource_id(storage_id)
                if target_sto:
                    add_edge(res.id, target_sto, "monitoring", "logs to Storage")

                workspace_id = res.properties.get("workspaceId")
                target_ws = self._match_resource_id(workspace_id)
                if target_ws:
                    add_edge(res.id, target_ws, "monitoring", "logs to Workspace")

            # 9. Private Endpoints
            if res_type_lower == "microsoft.network/privateendpoints":
                sub_id = res.properties.get("subnet", {}).get("id")
                target_sub = self._match_resource_id(sub_id)
                if target_sub:
                    add_edge(res.id, target_sub, "network_association", "connected to Subnet")

                connections = res.properties.get("privateLinkServiceConnections", [])
                for conn in connections:
                    target_res_id = conn.get("properties", {}).get("privateLinkServiceId")
                    target_svc = self._match_resource_id(target_res_id)
                    if target_svc:
                        add_edge(res.id, target_svc, "network_association", "private link to")

            # 10. General Cross-Resource Property Reference Discovery
            # Recursively inspect all properties of the resource for references to other resources
            self._discover_deep_references(res, res.properties, add_edge)

        return edges

    def _extract_app_service_links(self, source_res: NormalizedResource, settings_data: Any, add_edge):
        """Discovers data-flow and integration edges from App Service config entries."""
        if not settings_data:
            return

        entries = []
        if isinstance(settings_data, list):
            for item in settings_data:
                if isinstance(item, dict):
                    entries.append((item.get("name", ""), item.get("value", "") or item.get("connectionString", "")))
        elif isinstance(settings_data, dict):
            for k, v in settings_data.items():
                entries.append((k, v if isinstance(v, str) else str(v)))

        for key, val in entries:
            target_id = self._match_resource_id(val) or self._match_resource_id(key)
            if target_id and target_id != source_res.id:
                target_res = self.resource_by_id.get(target_id.lower())
                if target_res:
                    cat = target_res.category.lower()
                    t_type = target_res.type.lower()
                    if "storage" in cat or "storage" in t_type:
                        add_edge(source_res.id, target_id, "data_flow", "connects to Storage")
                    elif "redis" in cat or "redis" in t_type:
                        add_edge(source_res.id, target_id, "data_flow", "caches in Redis")
                    elif "keyvault" in cat or "keyvault" in t_type:
                        add_edge(source_res.id, target_id, "integration", "references Key Vault")
                    elif "database" in cat or "sql" in t_type:
                        add_edge(source_res.id, target_id, "data_flow", "queries SQL Database")
                    elif "network" in cat:
                        add_edge(source_res.id, target_id, "network_association", "connected to Network")
                    else:
                        add_edge(source_res.id, target_id, "data_flow", f"connects to {target_res.category}")

    def _discover_deep_references(self, source_res: NormalizedResource, data: Any, add_edge):
        """Recursively scans complex property structures for references to other resources in the template."""
        if isinstance(data, dict):
            for k, v in data.items():
                self._discover_deep_references(source_res, v, add_edge)
        elif isinstance(data, list):
            for item in data:
                self._discover_deep_references(source_res, item, add_edge)
        elif isinstance(data, str) and len(data) > 3:
            # Skip short generic values
            if data.lower() in ("true", "false", "enabled", "disabled", "eastus", "westus", "standard_lrs"):
                return
            target_id = self._match_resource_id(data)
            if target_id and target_id != source_res.id:
                target_res = self.resource_by_id.get(target_id.lower())
                if target_res:
                    cat = target_res.category.lower()
                    if "storage" in cat or "database" in cat or "redis" in cat:
                        add_edge(source_res.id, target_id, "data_flow", f"data flow to {target_res.name}")
                    elif "keyvault" in cat:
                        add_edge(source_res.id, target_id, "integration", f"secures secrets in {target_res.name}")
                    elif "network" in cat:
                        add_edge(source_res.id, target_id, "network_association", f"network link to {target_res.name}")
                    else:
                        add_edge(source_res.id, target_id, "dependency", f"references {target_res.name}")

    def _match_resource_id(self, reference: Any) -> str:
        """Attempts to match a reference string, ARM expression, or resourceId to an existing resource ID."""
        if not reference or not isinstance(reference, str):
            return ""

        ref_str = reference.strip()
        ref_lower = ref_str.lower()

        # 1. Direct match in known IDs
        if ref_lower in self.resource_by_id:
            return self.resource_by_id[ref_lower].id

        # 2. Direct match by exact resource name
        if ref_lower in self.resource_by_name:
            return self.resource_by_name[ref_lower].id

        # 3. Direct match by short name
        if ref_lower in self.resource_by_short_name:
            return self.resource_by_short_name[ref_lower].id

        # 4. Extract resourceId arguments: supports resourceId('type', 'name') and [resourceId: 'type', 'name']
        resource_id_matches = re.findall(r"resourceId[\s:(]+[^)\]]*['\"]([^'\"]+)['\"]", ref_str, re.IGNORECASE)
        # Also collect all quoted tokens inside the reference
        quoted_tokens = re.findall(r"['\"]([^'\"]+)['\"]", ref_str)
        candidates = list(reversed(resource_id_matches)) + list(reversed(quoted_tokens))
        for cand in candidates:
            cand_lower = cand.strip().lower()
            if cand_lower in self.resource_by_name:
                return self.resource_by_name[cand_lower].id
            if cand_lower in self.resource_by_short_name:
                return self.resource_by_short_name[cand_lower].id

        # 5. Try path split by '/'
        # Handle cases like /subscriptions/.../providers/Microsoft.X/resName
        cleaned = re.sub(r"[\[\]'\"\)\(]", "", ref_str).strip()
        parts = cleaned.split("/")
        if parts:
            last_part = parts[-1].strip().lower()
            if last_part in self.resource_by_name:
                return self.resource_by_name[last_part].id
            if last_part in self.resource_by_short_name:
                return self.resource_by_short_name[last_part].id

        # 6. Check if any known resource name is present as a standalone token or substring
        # Prioritize longest matching resource name
        matching_resources = []
        for r_name, res in self.resource_by_name.items():
            if len(r_name) < 4:
                continue
            # Token boundary or delimiters
            pattern = r"(?:\b|_|-|/|'|\"|=)" + re.escape(r_name) + r"(?:\b|_|-|/|'|\"|;|\.|\Z)"
            if re.search(pattern, ref_lower):
                matching_resources.append((len(r_name), res.id))
            elif r_name in ref_lower and (res.type.lower() in ref_lower or "/" in res.name):
                matching_resources.append((len(r_name), res.id))

        if matching_resources:
            matching_resources.sort(key=lambda x: x[0], reverse=True)
            return matching_resources[0][1]

        return ""
