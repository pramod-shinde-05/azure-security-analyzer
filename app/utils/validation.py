import json
from typing import Tuple, Dict, Any, List

KNOWN_ARM_SCHEMAS = [
    "schema.management.azure.com/schemas/2014-04-01-preview/deploymenttemplate.json",
    "schema.management.azure.com/schemas/2015-01-01/deploymenttemplate.json",
    "schema.management.azure.com/schemas/2018-05-01/subscriptiondeploymenttemplate.json",
    "schema.management.azure.com/schemas/2019-04-01/deploymenttemplate.json",
    "schema.management.azure.com/schemas/2019-08-01/tenantdeploymenttemplate.json",
    "schema.management.azure.com/schemas/2019-08-01/managementgroupdeploymenttemplate.json",
]

def allowed_file(filename: str, allowed_extensions: set) -> bool:
    """Check if the uploaded file has a permitted extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def validate_arm_content(content_str: str) -> Tuple[bool, str, Dict[str, Any], List[str]]:
    """
    Validates ARM template content string.
    Returns:
        (is_valid: bool, status_code: str, parsed_data: dict, warnings_or_errors: list[str])
    
    Status codes:
        - 'VALID': Well-formed ARM template
        - 'VALID_WITH_WARNINGS': Valid ARM template but contains caveats or missing optional sections
        - 'INVALID_JSON': Malformed JSON syntax
        - 'STRUCTURALLY_INVALID': Valid JSON but not an Azure ARM template
    """
    # 1. Syntax check
    try:
        data = json.loads(content_str)
    except json.JSONDecodeError as e:
        return False, "INVALID_JSON", {}, [f"Invalid JSON syntax at line {e.lineno}, column {e.colno}: {e.msg}"]

    # 2. Top-level object structure check
    if not isinstance(data, dict):
        return False, "STRUCTURALLY_INVALID", {}, ["ARM template root must be a JSON object, received " + type(data).__name__]

    warnings = []
    
    # 3. Schema check
    schema = data.get("$schema", "")
    has_arm_schema = False
    if isinstance(schema, str) and "schema.management.azure.com" in schema.lower():
        has_arm_schema = True
    elif schema:
        warnings.append(f"Unrecognized or custom $schema specified: '{schema}'. Expected Azure deployment template schema.")

    # 4. Resources check
    resources = data.get("resources")
    if resources is None:
        if not has_arm_schema:
            return False, "STRUCTURALLY_INVALID", {}, ["JSON does not contain an Azure '$schema' or a 'resources' array."]
        warnings.append("Template contains an Azure $schema but specifies no 'resources' array.")
        data["resources"] = []
    elif not isinstance(resources, list):
        return False, "STRUCTURALLY_INVALID", {}, ["'resources' field must be an array of resource definitions."]

    # 5. Check individual resource structure basics
    for idx, res in enumerate(data.get("resources", [])):
        if not isinstance(res, dict):
            return False, "STRUCTURALLY_INVALID", {}, [f"Resource at index {idx} must be a JSON object."]
        if "type" not in res:
            warnings.append(f"Resource at index {idx} is missing a 'type' property.")
        if "name" not in res:
            warnings.append(f"Resource at index {idx} is missing a 'name' property.")

    # 6. Check contentVersion
    if "contentVersion" not in data:
        warnings.append("Optional 'contentVersion' field was not specified.")

    status = "VALID_WITH_WARNINGS" if warnings else "VALID"
    return True, status, data, warnings

