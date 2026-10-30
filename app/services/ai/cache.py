import os
import json
import time
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional

class AIResponseCache:
    """
    Deterministic response cache for AI analysis results.
    Prevents duplicate calls, optimizes latency, and protects user API quotas.
    Keyed by SHA-256 hash of (file_id, feature_name, params).
    """

    def __init__(self, cache_dir: Optional[str] = None, ttl_seconds: int = 3600, enabled: bool = True):
        self.enabled = enabled
        self.ttl_seconds = ttl_seconds
        self.memory_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_dir = Path(cache_dir) if cache_dir else None

        if self.cache_dir:
            try:
                os.makedirs(self.cache_dir, exist_ok=True)
            except Exception:
                pass

    def get(
        self,
        file_id: str,
        feature: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """Retrieves cached response if available and not expired."""
        if not self.enabled:
            return None

        key = self._generate_key(file_id, feature, params)
        now = time.time()

        # 1. Check in-memory cache
        if key in self.memory_cache:
            entry = self.memory_cache[key]
            if now - entry["timestamp"] <= self.ttl_seconds:
                return entry["data"]
            else:
                del self.memory_cache[key]

        # 2. Check disk cache
        if self.cache_dir:
            file_path = self.cache_dir / f"{key}.json"
            if file_path.exists():
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        entry = json.load(f)
                    if now - entry.get("timestamp", 0) <= self.ttl_seconds:
                        self.memory_cache[key] = entry
                        return entry.get("data")
                    else:
                        file_path.unlink(missing_ok=True)
                except Exception:
                    pass

        return None

    def set(
        self,
        file_id: str,
        feature: str,
        data: Dict[str, Any],
        params: Optional[Dict[str, Any]] = None
    ):
        """Stores response in memory and disk cache."""
        if not self.enabled:
            return

        key = self._generate_key(file_id, feature, params)
        now = time.time()
        entry = {
            "file_id": file_id,
            "feature": feature,
            "timestamp": now,
            "data": data
        }

        self.memory_cache[key] = entry

        if self.cache_dir:
            try:
                file_path = self.cache_dir / f"{key}.json"
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(entry, f)
            except Exception:
                pass

    def clear(self, file_id: Optional[str] = None):
        """Clears memory cache and disk cache for a specific file or completely."""
        if file_id:
            keys_to_remove = [k for k, v in self.memory_cache.items() if v.get("file_id") == file_id]
            for k in keys_to_remove:
                del self.memory_cache[k]
        else:
            self.memory_cache.clear()

    def _generate_key(self, file_id: str, feature: str, params: Optional[Dict[str, Any]]) -> str:
        param_str = json.dumps(params or {}, sort_keys=True)
        raw = f"{file_id}:{feature}:{param_str}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

