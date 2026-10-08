import json
from pathlib import Path
import yaml
from pydantic import ValidationError
from cloudguard.config import MAX_INPUT_BYTES
from cloudguard.models.resources import Environment
from cloudguard.rules.secrets.redaction import mask

def load_environment(path: Path) -> Environment:
    """Safe JSON/YAML loading with size limits and errors that do not echo input."""
    if path.suffix.lower() not in {'.json', '.yaml', '.yml'}:
        raise ValueError('Use a JSON or YAML environment file.')
    with path.open('rb') as handle:
        payload = handle.read(MAX_INPUT_BYTES + 1)
    if len(payload) > MAX_INPUT_BYTES:
        raise ValueError('Environment exceeds the 5 MB input limit.')
    try:
        text = payload.decode('utf-8-sig')
        raw = json.loads(text) if path.suffix.lower() == '.json' else yaml.safe_load(text)
        # Redaction before normalization also prevents secrets in names/tags leaking into output.
        return Environment.model_validate(mask(raw))
    except (ValidationError, yaml.YAMLError, ValueError, TypeError, RecursionError):
        raise ValueError('Invalid environment schema or syntax; input values omitted for safety.') from None
