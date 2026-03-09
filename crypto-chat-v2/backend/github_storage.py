"""
github_storage.py — Persistent storage backed by GitHub API.

When GITHUB_TOKEN + GITHUB_REPO are set (Railway production), every
load/save goes through the GitHub Contents API so state survives restarts.
Falls back to local filesystem for development (no env vars needed).

Env vars:
  GITHUB_TOKEN        Personal access token with repo write access
  GITHUB_REPO         e.g. "rahuldutta05/Crypto-project"
  GITHUB_BRANCH       Branch to read/write (default: main)
  GITHUB_STORAGE_PATH Repo-relative folder for storage files
                      (default: crypto-chat-v2/backend/storage)
"""
import os
import json
import base64
import threading
import requests

GITHUB_TOKEN        = os.environ.get('GITHUB_TOKEN')
GITHUB_REPO         = os.environ.get('GITHUB_REPO')
GITHUB_BRANCH       = os.environ.get('GITHUB_BRANCH', 'main')
GITHUB_STORAGE_PATH = os.environ.get('GITHUB_STORAGE_PATH', 'crypto-chat-v2/backend/storage')

_BASE = 'https://api.github.com'
_HEADERS = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept':        'application/vnd.github.v3+json',
} if GITHUB_TOKEN else {}

# ── internal helpers ────────────────────────────────────────────────────────

def _enabled():
    return bool(GITHUB_TOKEN and GITHUB_REPO)


def _url(filename):
    return f'{_BASE}/repos/{GITHUB_REPO}/contents/{GITHUB_STORAGE_PATH}/{filename}'


def _gh_get(filename):
    """Fetch file from GitHub. Returns (parsed_content, sha) or (None, None)."""
    try:
        r = requests.get(_url(filename), headers=_HEADERS,
                         params={'ref': GITHUB_BRANCH}, timeout=10)
        if r.status_code == 200:
            body = r.json()
            content = json.loads(base64.b64decode(body['content']).decode())
            return content, body['sha']
    except Exception:
        pass
    return None, None


def _gh_put(filename, data, sha=None):
    """Create or update a file on GitHub (always fetches fresh sha first)."""
    try:
        # Always fetch current sha to avoid 409 conflicts
        _, current_sha = _gh_get(filename)
        payload = {
            'message': f'storage: update {filename}',
            'content': base64.b64encode(
                json.dumps(data, indent=2).encode()
            ).decode(),
            'branch': GITHUB_BRANCH,
        }
        if current_sha:
            payload['sha'] = current_sha
        r = requests.put(_url(filename), headers=_HEADERS,
                         json=payload, timeout=15)
        return r.status_code in (200, 201)
    except Exception:
        return False

# ── public API ──────────────────────────────────────────────────────────────

def load_json(filename, default=None):
    """
    Load a JSON file.
    • If GitHub is enabled: read from GitHub (source of truth), cache locally.
    • Otherwise: read from local storage/ directory.
    """
    if default is None:
        default = {}

    if _enabled():
        content, _ = _gh_get(filename)
        if content is not None:
            # Cache to local disk so same-request reads are instant
            _write_local(filename, content)
            return content

    # Local fallback (dev or GitHub read failed)
    return _read_local(filename, default)


def save_json(filename, data):
    """
    Save a JSON file locally, then push to GitHub asynchronously.
    The local write is synchronous so the calling route gets consistent reads.
    The GitHub push is non-blocking so requests aren't delayed.
    """
    _write_local(filename, data)

    if _enabled():
        def _push():
            _gh_put(filename, data)
        threading.Thread(target=_push, daemon=True).start()


def sync_from_github():
    """
    On startup: pull all known storage files from GitHub to local disk.
    This ensures the app has a warm local cache even before the first request.
    """
    if not _enabled():
        print('[Storage] GitHub storage disabled — using local filesystem')
        return

    storage_files = [
        'devices.json', 'messages.json', 'proof.json', 'nonces.json',
        'security_events.json', 'merkle_state.json',
        'deleted_commitments.json', 'blind_signing_key.json',
        'keys.json', 'tokens.json',
    ]
    os.makedirs('storage', exist_ok=True)
    synced, missing = 0, 0
    for f in storage_files:
        content, _ = _gh_get(f)
        if content is not None:
            _write_local(f, content)
            synced += 1
        else:
            missing += 1  # file doesn't exist on GitHub yet — first run

    print(f'[Storage] Synced {synced} files from GitHub '
          f'({GITHUB_REPO}@{GITHUB_BRANCH}/{GITHUB_STORAGE_PATH}). '
          f'{missing} not found (will be created on first write).')

# ── local helpers ───────────────────────────────────────────────────────────

def _write_local(filename, data):
    os.makedirs('storage', exist_ok=True)
    with open(f'storage/{filename}', 'w') as f:
        json.dump(data, f, indent=2)


def _read_local(filename, default):
    try:
        with open(f'storage/{filename}', 'r') as f:
            return json.load(f)
    except Exception:
        return default
