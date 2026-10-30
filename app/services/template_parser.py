import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

RESOURCE_CATEGORIES = {
    "Microsoft.Compute/virtualMachines": "Compute",
    "Microsoft.Compute/virtualMachineScaleSets": "Compute",
    "Microsoft.Compute/disks": "Compute Storage",
    "Microsoft.Network/virtualNetworks": "Network",
    "Microsoft.Network/virtualNetworks/subnets": "Network",
    "Microsoft.Network/subnets": "Network",
    "Microsoft.Network/networkInterfaces": "Network",
    "Microsoft.Network/networkSecurityGroups": "Network Security",
    "Microsoft.Network/publicIPAddresses": "Network Exposure",
    "Microsoft.Network/loadBalancers": "Network",
    "Microsoft.Network/applicationGateways": "Network Security",
    "Microsoft.Storage/storageAccounts": "Storage",
    "Microsoft.KeyVault/vaults": "Security & Identity",
    "Microsoft.Authorization/roleAssignments": "Identity & Access",
    "Microsoft.Authorization/roleDefinitions": "Identity & Access",
    "Microsoft.ManagedIdentity/userAssignedIdentities": "Identity & Access",
    "Microsoft.Web/serverfarms": "Compute",
    "Microsoft.Web/sites": "App Service",
    "Microsoft.Sql/servers": "Database",
    "Microsoft.Sql/servers/databases": "Database",
    "Microsoft.Insights/diagnosticSettings": "Logging & Monitoring",
}

def get_category_for_type(res_type: str) -> str:
    """Categorize an Azure resource type."""
    if not res_type:
        return "General"
    for prefix, cat in RESOURCE_CATEGORIES.items():
        if res_type.lower() == prefix.lower():
            return cat
    # Prefix-based fallbacks
    lower_type = res_type.lower()
    if "microsoft.compute" in lower_type:
        return "Compute"
    if "microsoft.network" in lower_type:
        return "Network"
    if "microsoft.storage" in lower_type:
        return "Storage"
    if "microsoft.keyvault" in lower_type:
        return "Security & Identity"
    if "microsoft.authorization" in lower_type:
        return "Identity & Access"
    if "microsoft.web" in lower_type:
        return "App Service"
    if "microsoft.sql" in lower_type:
        return "Database"
    if "microsoft.insights" in lower_type or "microsoft.operationalinsights" in lower_type:
        return "Logging & Monitoring"
    return "Other Services"

@dataclass
class NormalizedResource:
    id: str
    name: str
    type: str
    api_version: str
    location: str
    properties: Dict[str, Any]
    depends_on: List[str]
    category: str
    json_path: str
    raw_json: Dict[str, Any]
    tags: Dict[str, Any] = field(default_factory=dict)
    unresolved_expressions: List[str] = field(default_factory=list)

class SafeArmExpressionEvaluator:
    """
    Safely resolves common ARM template expressions without python eval().
    Supports: parameters(), variables(), concat(), format(), resourceId(), if(), equals()
    Gracefully flags unsupported or runtime functions as symbolic values.
    """
    def __init__(self, parameters: Dict[str, Any], variables: Dict[str, Any]):
        self.parameters = parameters or {}
        self.variables = variables or {}
        self.resolved_variables: Dict[str, Any] = {}
        self._resolve_variables()

    def _resolve_variables(self):
        """Pre-evaluate variable expressions if they reference parameters or other variables."""
        for k, v in self.variables.items():
            if isinstance(v, str) and v.startswith("[") and v.endswith("]"):
                self.resolved_variables[k] = self.evaluate(v)
            else:
                self.resolved_variables[k] = v

    def evaluate(self, expr_str: Any) -> Any:
        """Evaluate an ARM expression string if enclosed in '[ ... ]'."""
        if not isinstance(expr_str, str):
            return expr_str
        
        trimmed = expr_str.strip()
        # ARM escape: '[[text]' represents literal '[text]'
        if trimmed.startswith("[[") and trimmed.endswith("]"):
            return trimmed[1:]
        
        if not (trimmed.startswith("[") and trimmed.endswith("]")):
            return expr_str
        
        inner = trimmed[1:-1].strip()
        try:
            return self._eval_inner(inner)
        except Exception:
            # Fall back safely to symbolic representation
            return f"[Unresolved: {inner}]"

    def _eval_inner(self, inner: str) -> Any:
        inner = inner.strip()
        
        func_match = re.match(r'^([a-zA-Z0-9_]+)\((.*)\)$', inner, re.DOTALL)
        if not func_match:
            # Check if property navigation or unhandled function call pattern (e.g. func(...).prop)
            if "(" in inner and ")" in inner:
                return f"[Symbolic:{inner}]"
            # Check if literal boolean, number, or quoted string
            if inner.lower() == 'true':
                return True
            if inner.lower() == 'false':
                return False
            if (inner.startswith("'") and inner.endswith("'")) or (inner.startswith('"') and inner.endswith('"')):
                return inner[1:-1]
            try:
                if '.' in inner:
                    return float(inner)
                return int(inner)
            except ValueError:
                if any(c in inner for c in ('.', '[', ']', '(', ')')):
                    return f"[Symbolic:{inner}]"
                return inner

        func_name = func_match.group(1).lower()
        raw_args_str = func_match.group(2).strip()
        args = self._split_arguments(raw_args_str)

        if func_name == "parameters":
            if args:
                pname = self._eval_inner(args[0])
                param_def = self.parameters.get(pname, {})
                if isinstance(param_def, dict) and "defaultValue" in param_def:
                    return param_def["defaultValue"]
                elif isinstance(param_def, (str, int, float, bool)):
                    return param_def
                return f"[Param:{pname}]"
            return "[Param:unknown]"

        elif func_name == "variables":
            if args:
                vname = self._eval_inner(args[0])
                if vname in self.resolved_variables:
                    return self.resolved_variables[vname]
                if vname in self.variables:
                    val = self.variables[vname]
                    if isinstance(val, str) and val.startswith("["):
                        return self.evaluate(val)
                    return val
                return f"[Var:{vname}]"
            return "[Var:unknown]"

        elif func_name == "concat":
            evaluated_args = [str(self._eval_inner(arg)) for arg in args]
            return "".join(evaluated_args)

        elif func_name == "format":
            if args:
                fmt_str = str(self._eval_inner(args[0]))
                format_args = [str(self._eval_inner(arg)) for arg in args[1:]]
                for idx, val in enumerate(format_args):
                    fmt_str = fmt_str.replace(f"{{{idx}}}", val)
                return fmt_str
            return ""

        elif func_name == "equals":
            if len(args) == 2:
                v1 = self._eval_inner(args[0])
                v2 = self._eval_inner(args[1])
                return str(v1).lower() == str(v2).lower()
            return False

        elif func_name == "if":
            if len(args) == 3:
                cond = self._eval_inner(args[0])
                is_true = cond is True or str(cond).lower() == 'true'
                return self._eval_inner(args[1]) if is_true else self._eval_inner(args[2])
            return ""

        elif func_name == "resourceid":
            evaluated_args = [str(self._eval_inner(arg)) for arg in args]
            # e.g., resourceId('Microsoft.Network/virtualNetworks', 'vnetName')
            # normalized representation: providers/type/name
            if len(evaluated_args) >= 2:
                res_type = evaluated_args[0]
                res_names = evaluated_args[1:]
                return f"providers/{res_type}/{'/'.join(res_names)}"
            elif len(evaluated_args) == 1:
                return f"providers/{evaluated_args[0]}"
            return f"[resourceId:{raw_args_str}]"

        elif func_name in ("subscriptionresourceid", "tenantresourceid"):
            evaluated_args = [str(self._eval_inner(arg)) for arg in args]
            return f"providers/{'/'.join(evaluated_args)}"

        # Runtime or complex expressions
        return f"[Symbolic:{func_name}({raw_args_str})]"

    def _split_arguments(self, raw_args: str) -> List[str]:
        """Safely split comma-separated function arguments honoring nested parentheses and quotes."""
        args = []
        current = []
        depth = 0
        in_quote = False
        quote_char = ''

        for char in raw_args:
            if char in ("'", '"') and not in_quote:
                in_quote = True
                quote_char = char
                current.append(char)
            elif char == quote_char and in_quote:
                in_quote = False
                quote_char = ''
                current.append(char)
            elif in_quote:
                current.append(char)
            elif char == '(':
                depth += 1
                current.append(char)
            elif char == ')':
                depth -= 1
                current.append(char)
            elif char == ',' and depth == 0:
                args.append("".join(current).strip())
                current = []
            else:
                current.append(char)

        if current:
            token = "".join(current).strip()
            if token:
                args.append(token)
        return args


class ArmTemplateParser:
    """Parses ARM JSON templates into normalized internal resource representations."""

    def __init__(self, template_data: Dict[str, Any]):
        self.raw_data = template_data
        self.parameters = template_data.get("parameters", {})
        self.variables = template_data.get("variables", {})
        self.evaluator = SafeArmExpressionEvaluator(self.parameters, self.variables)
        self.warnings: List[str] = []
        self.unresolved_constructs: List[str] = []

    def parse(self) -> Tuple[List[NormalizedResource], Dict[str, Any], List[str]]:
        """
        Parses and returns:
            - normalized_resources: list of NormalizedResource
            - metadata: dictionary containing schema, contentVersion, parameter/variable counts
            - warnings: any warnings or unsupported constructs encountered
        """
        normalized_resources: List[NormalizedResource] = []
        raw_resources = self.raw_data.get("resources", [])

        metadata = {
            "schema": self.raw_data.get("$schema", "Unknown"),
            "contentVersion": self.raw_data.get("contentVersion", "1.0.0.0"),
            "parameter_count": len(self.parameters),
            "variable_count": len(self.variables),
            "total_raw_resources": len(raw_resources)
        }

        for idx, res in enumerate(raw_resources):
            parsed_res = self._process_resource(res, f"$.resources[{idx}]")
            if parsed_res:
                normalized_resources.append(parsed_res)
                
                # Check for nested sub-resources (e.g. subnets inside virtualNetworks)
                sub_resources = self._extract_child_resources(res, parsed_res, f"$.resources[{idx}]")
                normalized_resources.extend(sub_resources)

        return normalized_resources, metadata, self.warnings

    def _process_resource(self, res: Dict[str, Any], json_path: str, parent: Optional[NormalizedResource] = None) -> Optional[NormalizedResource]:
        res_type = res.get("type", "")
        raw_name = res.get("name", f"Unnamed_Resource_{json_path}")
        
        # Evaluate expressions in name, type, location
        resolved_name = str(self._resolve_value(raw_name))
        resolved_type = str(self._resolve_value(res_type))
        location = str(self._resolve_value(res.get("location", "global")))
        api_version = str(res.get("apiVersion", ""))
        
        # Resolve properties
        raw_properties = res.get("properties", {})
        resolved_properties = self._resolve_deep(raw_properties) if isinstance(raw_properties, dict) else {}

        # Resolve dependsOn
        raw_depends = res.get("dependsOn", [])
        resolved_depends = []
        if isinstance(raw_depends, list):
            for dep in raw_depends:
                resolved_dep = str(self._resolve_value(dep))
                resolved_depends.append(resolved_dep)

        # Generate a stable resource id
        if parent:
            synthetic_id = f"{parent.id}/{resolved_name}"
        else:
            synthetic_id = f"providers/{resolved_type}/{resolved_name}"

        category = get_category_for_type(resolved_type)
        tags = res.get("tags", {})

        return NormalizedResource(
            id=synthetic_id,
            name=resolved_name,
            type=resolved_type,
            api_version=api_version,
            location=location,
            properties=resolved_properties,
            depends_on=resolved_depends,
            category=category,
            json_path=json_path,
            raw_json=res,
            tags=tags
        )

    def _extract_child_resources(self, raw_res: Dict[str, Any], parent: NormalizedResource, parent_path: str) -> List[NormalizedResource]:
        """Extract child resources defined either in properties (e.g. subnets) or in nested 'resources' array."""
        children = []
        # Case 1: Nested resources array inside a resource
        nested_resources = raw_res.get("resources", [])
        if isinstance(nested_resources, list):
            for c_idx, c_res in enumerate(nested_resources):
                c_path = f"{parent_path}.resources[{c_idx}]"
                child = self._process_resource(c_res, c_path, parent=parent)
                if child:
                    # Inherit dependency to parent automatically
                    if parent.id not in child.depends_on:
                        child.depends_on.append(parent.id)
                    children.append(child)

        # Case 2: Subnets declared inside virtualNetworks properties
        if parent.type.lower() == "microsoft.network/virtualnetworks":
            subnets = raw_res.get("properties", {}).get("subnets", [])
            if isinstance(subnets, list):
                for s_idx, s_data in enumerate(subnets):
                    if isinstance(s_data, dict):
                        s_name = str(self._resolve_value(s_data.get("name", f"subnet_{s_idx}")))
                        s_props = self._resolve_deep(s_data.get("properties", {}))
                        s_id = f"{parent.id}/subnets/{s_name}"
                        child_res = NormalizedResource(
                            id=s_id,
                            name=f"{parent.name}/{s_name}",
                            type="Microsoft.Network/virtualNetworks/subnets",
                            api_version=parent.api_version,
                            location=parent.location,
                            properties=s_props,
                            depends_on=[parent.id],
                            category="Network",
                            json_path=f"{parent_path}.properties.subnets[{s_idx}]",
                            raw_json=s_data
                        )
                        children.append(child_res)

        return children

    def _resolve_value(self, val: Any) -> Any:
        if isinstance(val, str) and val.startswith("[") and val.endswith("]"):
            evaluated = self.evaluator.evaluate(val)
            if isinstance(evaluated, str) and evaluated.startswith("[Unresolved:"):
                self.warnings.append(f"Could not fully resolve expression: {val}")
            return evaluated
        return val

    def _resolve_deep(self, obj: Any) -> Any:
        """Recursively resolve expressions across dictionaries and lists."""
        if isinstance(obj, dict):
            return {k: self._resolve_deep(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._resolve_deep(item) for item in obj]
        elif isinstance(obj, str):
            return self._resolve_value(obj)
        return obj

