import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def load_dotenv_if_present(env_path: Path):
    """Safely loads key-value pairs from .env file into os.environ without requiring external packages."""
    if not env_path.is_file():
        return
    try:
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, val = line.split('=', 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    if key:
                        os.environ[key] = val
    except Exception:
        pass

# Automatically load .env from project directory
load_dotenv_if_present(BASE_DIR / '.env')

class Config:
    # All secrets, keys, and provider settings are strictly imported from the .env file
    SECRET_KEY = os.environ.get('SECRET_KEY')
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', str(BASE_DIR / 'instance' / 'uploads'))
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 10 * 1024 * 1024))
    ALLOWED_EXTENSIONS = {'json'}
    DEBUG = False
    TESTING = False

    # AI Provider & Model Configuration (Imported strictly from .env)
    AI_ENABLED = os.environ.get('AI_ENABLED', '').lower() in ('true', '1', 'yes')
    AI_PROVIDER = os.environ.get('AI_PROVIDER', '').strip().lower()

    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '').strip()
    GEMINI_MODEL = os.environ.get('GEMINI_MODEL', '').strip()

    OLLAMA_BASE_URL = os.environ.get('OLLAMA_BASE_URL', '').strip()
    OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', '').strip()

    AI_REQUEST_TIMEOUT = int(os.environ.get('AI_REQUEST_TIMEOUT', 60))
    AI_MAX_RETRIES = int(os.environ.get('AI_MAX_RETRIES', 2))
    AI_CACHE_ENABLED = os.environ.get('AI_CACHE_ENABLED', 'true').lower() in ('true', '1', 'yes')
    AI_CACHE_TTL_SECONDS = int(os.environ.get('AI_CACHE_TTL_SECONDS', 3600))
    AI_MAX_CONTEXT_SIZE = int(os.environ.get('AI_MAX_CONTEXT_SIZE', 32000))

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True
    UPLOAD_FOLDER = str(BASE_DIR / 'instance' / 'test_uploads')

class ProductionConfig(Config):
    DEBUG = False

config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

