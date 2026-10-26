"""Read-only full-profile capabilities and truthful server version metadata.

These helpers never change proxy identities. A version describes the server's
YAML content; fetching that YAML cannot establish whether a client imported it.
The module deliberately uses only Python 3.6 standard-library APIs.
"""

import hashlib
import re
import secrets
from datetime import datetime, timezone


TOKEN = re.compile(r"[A-Za-z0-9_-]{43,128}\Z")
FIELDS = ("profile_token", "profile_version", "profile_hash", "profile_updated")


def _now():
    return datetime.now(timezone.utc).isoformat()


def valid_token(token):
    return isinstance(token, str) and bool(TOKEN.fullmatch(token))


def update_metadata(state, previous=None):
    """Update metadata in place; return whether any metadata changed.

    Pass the prior persisted state from Manager.save. The stored hash also
    supports callers migrating the same object that is already in memory.
    """
    before = {key: state.get(key) for key in FIELDS}
    token = state.get("profile_token")
    if token is None:
        state["profile_token"] = secrets.token_urlsafe(32)
    elif not valid_token(token):
        raise ValueError("Invalid profile capability in private state")
    profile = state.get("profile")
    if profile is not None and not isinstance(profile, str):
        raise ValueError("Invalid full profile in private state")
    content_hash = hashlib.sha256(profile.encode("utf-8")).hexdigest() if profile else None
    prior = previous if previous is not None else state
    version = prior.get("profile_version", 0)
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise ValueError("Invalid profile version in private state")
    changed_content = content_hash != prior.get("profile_hash")
    state["profile_version"] = version + 1 if changed_content else version
    state["profile_hash"] = content_hash
    state["profile_updated"] = _now() if changed_content else prior.get("profile_updated")
    return before != {key: state.get(key) for key in FIELDS}


def ensure_metadata(state):
    """Migrate metadata without rotating existing UUIDs, keys or rule tokens."""
    return update_metadata(state)


def metadata(state, origin, base_path, include_url=True):
    result = {"version": state["profile_version"], "hash": state["profile_hash"],
              "updated": state["profile_updated"], "download_ready": bool(state.get("profile"))}
    if include_url:
        result["url"] = (origin.rstrip("/") + "/" + base_path.strip("/") + "/"
                         if base_path.strip("/") else origin.rstrip("/") + "/")
        result["url"] += "subscription/" + state["profile_token"] + ".yaml"
    return result
