import os
import uuid
import re
from pathlib import Path

SENSITIVE_KEY_PATTERNS = [
    re.compile(r'password', re.IGNORECASE),
    re.compile(r'secret', re.IGNORECASE),
    re.compile(r'connectionstring', re.IGNORECASE),
    re.compile(r'privatekey', re.IGNORECASE),
    re.compile(r'certkey', re.IGNORECASE),
    re.compile(r'apikey', re.IGNORECASE),
    re.compile(r'adminpassword', re.IGNORECASE),
]

def generate_secure_storage_id() -> str:
    """Generate a collision-free UUID4-based internal identifier."""
    return str(uuid.uuid4())

def get_storage_path(upload_dir: str, file_id: str) -> Path:
    """
    Get full storage path for a file ID in the upload directory.
    Guards strictly against directory traversal by verifying resolved parent path.
    """
    if not file_id or not isinstance(file_id, str):
        raise ValueError("Invalid file ID provided.")

    if re.search(r'[^a-zA-Z0-9_-]', file_id) or ".." in file_id or "/" in file_id or "\\" in file_id:
        raise ValueError("Invalid file ID causing directory traversal attempt.")

    base = Path(upload_dir).resolve()
    target = (base / f"{file_id}.json").resolve()
    
    if not str(target).startswith(str(base)):
        raise ValueError("Invalid file ID causing directory traversal attempt.")
    
    return target

def mask_sensitive_data(data):
    """
    Recursively traverse dictionary/list structures and mask known secret values.
    Returns a sanitized copy.
    """
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            if any(pattern.search(str(key)) for pattern in SENSITIVE_KEY_PATTERNS):
                sanitized[key] = "********"
            else:
                sanitized[key] = mask_sensitive_data(value)
        return sanitized
    elif isinstance(data, list):
        return [mask_sensitive_data(item) for item in data]
    return data

