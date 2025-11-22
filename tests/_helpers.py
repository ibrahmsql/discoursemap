# Shared testing helpers for DiscourseMap

import os
import sys
import types
import importlib.util

class _Elapsed:
    def __init__(self, seconds: float = 0.05):
        self._s = seconds
    def total_seconds(self):
        return self._s

class ResponseStub:
    def __init__(self, status_code=200, text="", headers=None, cookies=None, json_data=None, elapsed=0.05, content=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.cookies = cookies or {}
        self._json_data = json_data
        self.elapsed = _Elapsed(elapsed)
        self.content = content if content is not None else (text.encode("utf-8") if isinstance(text, str) else b"")

    def json(self):
        if self._json_data is None:
            raise ValueError()
        return self._json_data

class FakeScanner:
    def __init__(self, target_url, responder=None):
        self.target_url = target_url.rstrip("/")
        self._responder = responder

    def make_request(self, url, method="GET", params=None, json=None, timeout=10, **kwargs):
        if self._responder:
            return self._responder(url=url, method=method, params=params, json=json, timeout=timeout, **kwargs)
        # Default: 404 Not Found to force code paths
        return ResponseStub(status_code=404, text="Not Found")

def load_module_by_path(mod_name: str, rel_path: str):
    """Load a module directly from a repository-relative file path without importing the top-level package."""
    repo_root = os.path.abspath(os.getcwd())
    abs_path = os.path.join(repo_root, rel_path)
    spec = importlib.util.spec_from_file_location(mod_name, abs_path)
    if spec is None or spec.loader is None:
        raise ImportError()
    module = importlib.util.module_from_spec(spec)
    # Ensure module package context is sane enough for standard imports (no relative sibling imports supported)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module