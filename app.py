import os
import sys
from pathlib import Path

# Ensure the project root is in sys.path
base_path = Path(__file__).resolve().parent
base_dir = str(base_path)
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

# Safely load .env from project root if present
env_file = base_path / '.env'
if env_file.is_file():
    try:
        with open(env_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k:
                        os.environ[k] = v
    except Exception:
        pass

from app import create_app

app = create_app(os.environ.get('FLASK_CONFIG', 'default'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='127.0.0.1', port=port, debug=True)
