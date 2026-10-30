import io
import json
import pytest
from app.utils.validation import allowed_file, validate_arm_content
from app.utils.sanitization import generate_secure_storage_id, get_storage_path

def test_allowed_file():
    assert allowed_file('template.json', {'json'}) is True
    assert allowed_file('template.JSON', {'json'}) is True
    assert allowed_file('script.sh', {'json'}) is False
    assert allowed_file('malicious.exe', {'json'}) is False
    assert allowed_file('no_extension', {'json'}) is False

def test_validate_arm_content_valid_json(load_fixture):
    secure_json = load_fixture('secure_template.json')
    is_valid, status, data, warnings = validate_arm_content(secure_json)
    assert is_valid is True
    assert status in ('VALID', 'VALID_WITH_WARNINGS')
    assert "resources" in data

def test_validate_arm_content_invalid_syntax(load_fixture):
    invalid_json = load_fixture('invalid_syntax.json')
    is_valid, status, data, errors = validate_arm_content(invalid_json)
    assert is_valid is False
    assert status == 'INVALID_JSON'
    assert len(errors) > 0

def test_validate_arm_content_non_arm(load_fixture):
    non_arm_json = load_fixture('non_arm.json')
    is_valid, status, data, errors = validate_arm_content(non_arm_json)
    assert is_valid is False
    assert status == 'STRUCTURALLY_INVALID'

def test_path_traversal_prevention(tmp_path):
    # Attempt directory traversal with file ID
    with pytest.raises(ValueError):
        get_storage_path(str(tmp_path), "../../../etc/passwd")

def test_upload_route_success(client, load_fixture):
    secure_content = load_fixture('secure_template.json')
    data = {
        'template_file': (io.BytesIO(secure_content.encode('utf-8')), 'test_secure.json')
    }
    response = client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=False)
    assert response.status_code == 302
    assert '/analysis/' in response.location

def test_upload_route_invalid_json(client, load_fixture):
    invalid_content = load_fixture('invalid_syntax.json')
    data = {
        'template_file': (io.BytesIO(invalid_content.encode('utf-8')), 'bad.json')
    }
    response = client.post('/upload', headers={'X-Requested-With': 'XMLHttpRequest'}, data=data, content_type='multipart/form-data')
    assert response.status_code == 400
    res_json = response.get_json()
    assert res_json['success'] is False
    assert res_json['status'] == 'INVALID_JSON'
