import pytest
from app.services.template_parser import ArmTemplateParser, SafeArmExpressionEvaluator, get_category_for_type

def test_safe_evaluator_parameters():
    params = {"env": {"defaultValue": "prod"}, "count": {"defaultValue": 3}}
    evaluator = SafeArmExpressionEvaluator(parameters=params, variables={})
    assert evaluator.evaluate("[parameters('env')]") == "prod"
    assert evaluator.evaluate("[parameters('count')]") == 3

def test_safe_evaluator_concat_and_format():
    params = {"prefix": {"defaultValue": "myapp"}}
    vars_def = {"env": "staging"}
    evaluator = SafeArmExpressionEvaluator(parameters=params, variables=vars_def)
    
    concat_res = evaluator.evaluate("[concat(parameters('prefix'), '-', variables('env'), '-vm')]")
    assert concat_res == "myapp-staging-vm"

    format_res = evaluator.evaluate("[format('{0}-{1}', parameters('prefix'), 'nic')]")
    assert format_res == "myapp-nic"

def test_safe_evaluator_if_and_equals():
    evaluator = SafeArmExpressionEvaluator(parameters={}, variables={})
    assert evaluator.evaluate("[if(equals('a', 'a'), 'yes', 'no')]") == "yes"
    assert evaluator.evaluate("[if(equals('a', 'b'), 'yes', 'no')]") == "no"

def test_safe_evaluator_resource_id():
    evaluator = SafeArmExpressionEvaluator(parameters={}, variables={})
    res = evaluator.evaluate("[resourceId('Microsoft.Network/virtualNetworks', 'vnet-1')]")
    assert res == "providers/Microsoft.Network/virtualNetworks/vnet-1"

def test_unresolved_expression_fallback():
    evaluator = SafeArmExpressionEvaluator(parameters={}, variables={})
    res = evaluator.evaluate("[reference('runtimeResourceId').outputs.val]")
    assert res.startswith("[Symbolic:")

def test_parser_complex_template(load_fixture_json):
    complex_data = load_fixture_json('complex_template.json')
    parser = ArmTemplateParser(complex_data)
    resources, metadata, warnings = parser.parse()

    assert len(resources) >= 4
    # Check that variables and parameters resolved
    vnet = next(r for r in resources if r.type.lower() == 'microsoft.network/virtualnetworks')
    assert vnet.name == "prod-vnet-production"

    # Check child subnet extraction
    subnet = next(r for r in resources if 'subnet' in r.type.lower())
    assert "webTierSubnet" in subnet.name
    assert vnet.id in subnet.depends_on

def test_resource_categories():
    assert get_category_for_type("Microsoft.Compute/virtualMachines") == "Compute"
    assert get_category_for_type("Microsoft.Storage/storageAccounts") == "Storage"
    assert get_category_for_type("Microsoft.Network/networkSecurityGroups") == "Network Security"
    assert get_category_for_type("Microsoft.KeyVault/vaults") == "Security & Identity"

