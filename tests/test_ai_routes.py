import json
import pytest
from unittest.mock import patch, MagicMock

def test_ai_status_endpoint(client):
    response = client.get('/api/ai/status')
    assert response.status_code == 200
    data = response.get_json()
    assert "status" in data
    assert "enabled" in data

def test_ai_threat_model_missing_session(client):
    response = client.post('/api/ai/threat-model/non-existent-uuid-1234')
    assert response.status_code == 404
    data = response.get_json()
    assert data["success"] is False
    assert data["code"] == "NOT_FOUND"

def test_ai_threat_model_unconfigured_key(client, sample_insecure_id):
    # When GEMINI_API_KEY is not configured
    with patch.dict("os.environ", {"GEMINI_API_KEY": ""}):
        response = client.post(f'/api/ai/threat-model/{sample_insecure_id}')
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False
        assert data["code"] == "AI_UNCONFIGURED"

def test_ai_threat_model_success_with_mock(client, sample_insecure_id):
    mock_llm_json = {
        "attack_paths": [
            {
                "id": "path-01",
                "title": "Internet Exposure Path",
                "risk": "HIGH",
                "summary": "External access to internal services",
                "steps": [
                    {
                        "step": 1,
                        "resource_id": "providers/Microsoft.Network/publicIPAddresses/insecure-pip",
                        "description": "Public IP entry point",
                        "finding_ids": [],
                        "evidence": [],
                        "preconditions": []
                    }
                ],
                "impact": "Exposure",
                "evidence_strength": "CONFIGURATION_SUPPORTED",
                "confidence": "HIGH"
            }
        ]
    }

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "candidates": [{"content": {"parts": [{"text": json.dumps(mock_llm_json)}]}}]
    }).encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    with patch.dict("os.environ", {"GEMINI_API_KEY": "AIzaSyValidMockKey123"}):
        with patch("urllib.request.urlopen", return_value=mock_response):
            response = client.post(f'/api/ai/threat-model/{sample_insecure_id}')
            assert response.status_code == 200
            data = response.get_json()
            assert data["success"] is True
            assert "attack_paths" in data
            assert len(data["attack_paths"]) == 1
            assert data["attack_paths"][0]["id"] == "path-01"

def test_ai_explain_finding(client, sample_insecure_id):
    # First get session findings to grab a real finding_id
    from app.routes.analysis import _load_and_analyze
    data = _load_and_analyze(sample_insecure_id)
    finding = data["findings"][0]
    finding_id = finding["finding_id"]

    mock_llm_json = {
        "summary": "Storage blob public access allows anonymous reading of sensitive company blobs.",
        "architectural_context": "The storage account is placed within an insecure subnet with no firewall rules.",
        "attacker_perspective": "Attacker issues GET requests directly against storage endpoints without credentials.",
        "verification_steps": ["Execute curl against blob URL anonymously", "Check Azure portal container access level"],
        "quick_fix_summary": "Set allowBlobPublicAccess to false in ARM template."
    }

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "candidates": [{"content": {"parts": [{"text": json.dumps(mock_llm_json)}]}}]
    }).encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    with patch.dict("os.environ", {"GEMINI_API_KEY": "AIzaSyValidMockKey123"}):
        with patch("urllib.request.urlopen", return_value=mock_response):
            response = client.post(f'/api/ai/explain/{sample_insecure_id}/{finding_id}')
            assert response.status_code == 200
            res_json = response.get_json()
            assert res_json["success"] is True
            assert "explanation" in res_json
            assert res_json["explanation"]["summary"] == mock_llm_json["summary"]

def test_ai_prioritize_risks(client, sample_insecure_id):
    from app.routes.analysis import _load_and_analyze
    data = _load_and_analyze(sample_insecure_id)
    f_id = data["findings"][0]["finding_id"]

    mock_llm_json = {
        "executive_summary": "Template contains severe public internet exposures requiring immediate mitigation.",
        "prioritized_findings": [
            {
                "finding_id": f_id,
                "composite_score": 9.5,
                "adjusted_priority": "IMMEDIATE",
                "rationale": "Directly accessible from public Internet."
            }
        ]
    }

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "candidates": [{"content": {"parts": [{"text": json.dumps(mock_llm_json)}]}}]
    }).encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    with patch.dict("os.environ", {"GEMINI_API_KEY": "AIzaSyValidMockKey123"}):
        with patch("urllib.request.urlopen", return_value=mock_response):
            response = client.post(f'/api/ai/prioritize/{sample_insecure_id}')
            assert response.status_code == 200
            res_json = response.get_json()
            assert res_json["success"] is True
            assert len(res_json["prioritization"]["prioritized_findings"]) == 1

def test_ai_remediate_and_rescan(client, sample_insecure_id):
    from app.routes.analysis import _load_and_analyze
    data = _load_and_analyze(sample_insecure_id)
    # Find storage account finding
    storage_finding = next(f for f in data["findings"] if "storage" in f["rule_id"].lower() or "blob" in f["title"].lower())
    f_id = storage_finding["finding_id"]

    mock_llm_json = {
        "finding_id": f_id,
        "title": "Disable Blob Public Access",
        "explanation": "Set allowBlobPublicAccess property to false.",
        "code_snippet": "\"properties\": { \"allowBlobPublicAccess\": false }",
        "suggested_properties_patch": {"allowBlobPublicAccess": False},
        "caveats": []
    }

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "candidates": [{"content": {"parts": [{"text": json.dumps(mock_llm_json)}]}}]
    }).encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    with patch.dict("os.environ", {"GEMINI_API_KEY": "AIzaSyValidMockKey123"}):
        with patch("urllib.request.urlopen", return_value=mock_response):
            response = client.post(f'/api/ai/remediate/{sample_insecure_id}/{f_id}')
            assert response.status_code == 200
            res_json = response.get_json()
            assert res_json["success"] is True
            assert "suggested_properties_patch" in res_json["remediation"]

            # Test Dry-Run Rescan endpoint
            patch_data = res_json["remediation"]["suggested_properties_patch"]
            rescan_resp = client.post(
                f'/api/ai/remediate/{sample_insecure_id}/{f_id}/rescan',
                json={"patch_properties": patch_data}
            )
            assert rescan_resp.status_code == 200
            rescan_json = rescan_resp.get_json()
            assert rescan_json["success"] is True
            assert "verification" in rescan_json
            assert rescan_json["verification"]["resolved"] is True

def test_ai_status_with_ollama(client):
    with patch.dict("os.environ", {"AI_PROVIDER": "ollama", "OLLAMA_MODEL": "llama3.2"}):
        with patch("app.services.ai.ollama_provider.OllamaProvider.health_check", return_value={"status": "configured", "provider": "ollama", "model": "llama3.2"}):
            response = client.get('/api/ai/status')
            assert response.status_code == 200
            data = response.get_json()
            assert data["provider"] == "ollama"
            assert data["status"] == "configured"

def test_ai_threat_model_with_ollama_provider(client, sample_insecure_id):
    mock_llm_json = {
        "attack_paths": [
            {
                "id": "ollama-path-01",
                "title": "Local LLM Ingress Analysis",
                "risk": "HIGH",
                "summary": "External access path synthesized locally",
                "steps": [
                    {
                        "step": 1,
                        "resource_id": "providers/Microsoft.Network/publicIPAddresses/insecure-pip",
                        "description": "Public IP entry point",
                        "finding_ids": [],
                        "evidence": [],
                        "preconditions": []
                    }
                ],
                "impact": "Exposure",
                "evidence_strength": "CONFIGURATION_SUPPORTED",
                "confidence": "HIGH"
            }
        ]
    }

    with patch.dict("os.environ", {"AI_PROVIDER": "ollama", "OLLAMA_MODEL": "llama3.2"}):
        with patch("app.services.ai.ollama_provider.OllamaProvider.health_check", return_value={"status": "configured", "provider": "ollama", "model": "llama3.2"}):
            with patch("app.services.ai.ollama_provider.OllamaProvider.generate_structured_response", return_value=mock_llm_json):
                response = client.post(f'/api/ai/threat-model/{sample_insecure_id}')
                assert response.status_code == 200
                data = response.get_json()
                assert data["success"] is True
                assert len(data["attack_paths"]) == 1
                assert data["attack_paths"][0]["id"] == "ollama-path-01"



