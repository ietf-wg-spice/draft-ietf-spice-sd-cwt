"""Fail closed if a run's normative sources differ from its declared spec pin."""
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent


def spec_manifest(root=None):
    root = Path(root) if root is not None else BASE.parent
    manifest = json.loads((BASE / 'spec-version.json').read_text())
    for name, expected in manifest['source_sha256'].items():
        path = root / name
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError(f'Spec pin mismatch: {name}; review and update spec-version.json before testing')
    return manifest
