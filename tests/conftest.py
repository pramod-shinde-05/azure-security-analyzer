import os
import sys
import json
import pytest
from pathlib import Path

# Ensure root of azure-security-analyzer is in sys.path
project_root = str(Path(__file__).resolve().parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app import create_app

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

@pytest.fixture
def app():
    """Create and configure a Flask test application instance."""
    app_instance = create_app('testing')
    yield app_instance

@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()

@pytest.fixture
def load_fixture():
    """Helper function to load a fixture JSON string."""
    def _loader(filename: str) -> str:
        with open(FIXTURES_DIR / filename, 'r', encoding='utf-8') as f:
            return f.read()
    return _loader

@pytest.fixture
def load_fixture_json():
    """Helper function to load a fixture parsed JSON dictionary."""
    def _loader(filename: str) -> dict:
        with open(FIXTURES_DIR / filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    return _loader

@pytest.fixture
def sample_insecure_id(app, load_fixture):
    """Creates a temporary uploaded insecure template session and returns its file_id."""
    from app.utils.sanitization import generate_secure_storage_id, get_storage_path
    upload_dir = app.config['UPLOAD_FOLDER']
    os.makedirs(upload_dir, exist_ok=True)
    file_id = generate_secure_storage_id()
    dest = get_storage_path(upload_dir, file_id)
    with open(dest, 'w', encoding='utf-8') as f:
        f.write(load_fixture('insecure_template.json'))
    meta_path = Path(upload_dir) / f"{file_id}.meta.json"
    with open(meta_path, 'w', encoding='utf-8') as mf:
        json.dump({"file_id": file_id, "original_filename": "insecure_template.json"}, mf)
    return file_id
