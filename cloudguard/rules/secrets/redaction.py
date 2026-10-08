"""Remove sensitive-looking values before errors, evidence or reports are surfaced."""
import re
from typing import Any

FIELD = re.compile(r'(?i)(password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key|credential)')
VALUE = re.compile(r'(?i)(AKIA[A-Z0-9_-]{8,}|ASIA[A-Z0-9_-]{8,}|ghp_[A-Za-z0-9_-]{8,}|'
                   r'github_pat_[A-Za-z0-9_]{8,}|sk-(?:proj-)?[A-Za-z0-9_-]{8,}|'
                   r'-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----|'
                   r'(?:password|token|secret)\s*[=:]\s*[^\s,;]+)')

def mask(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: ('[REDACTED]' if FIELD.search(str(key)) and item not in ('', None)
                      else mask(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [mask(item) for item in value]
    if isinstance(value, str):
        return VALUE.sub('[REDACTED]', value)
    return value

def secret_paths(value: Any, path: str = '') -> list[str]:
    results = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f'{path}.{key}' if path else str(key)
            if FIELD.search(str(key)) and item not in ('', None):
                results.append(child)
            else:
                results.extend(secret_paths(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            results.extend(secret_paths(item, f'{path}[{index}]'))
    elif isinstance(value, str) and (VALUE.search(value) or '[REDACTED]' in value):
        results.append(path)
    return results
