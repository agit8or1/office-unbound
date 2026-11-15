"""Credential loading. Secrets come only from environment variables or files; never from argv,
never logged. Tokens live in memory only (see auth.py)."""
from __future__ import annotations

import os
import stat


class SecretError(Exception):
    pass


def read_secret_file(path: str) -> str:
    """Read a secret file. Refuses symlinks, non-regular files and group/world-accessible files
    (same rule as the ICS vault key files)."""
    try:
        st = os.lstat(path)
    except OSError as e:
        raise SecretError(f"cannot stat secret file: {e.strerror}") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise SecretError("secret file must be a regular file (no symlinks)")
    if st.st_mode & 0o077:
        raise SecretError("secret file must not be group/world accessible (chmod 600)")
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def load_secret(env_name: str, file_env_name: str | None = None, environ=None) -> str:
    """``NAME`` holds the secret, or ``NAME_FILE`` holds a path to it. Error messages never contain values."""
    environ = os.environ if environ is None else environ
    file_env_name = file_env_name or env_name + "_FILE"
    if environ.get(file_env_name):
        return read_secret_file(environ[file_env_name])
    if environ.get(env_name):
        return environ[env_name]
    raise SecretError(f"missing credential: set {env_name} or {file_env_name}")


class Redacted(str):
    """A string whose repr/str never reveals content (guards accidental logging)."""

    def __repr__(self):
        return "<redacted>"

    __str__ = __repr__

    def reveal(self) -> str:
        return str.__str__(self)
