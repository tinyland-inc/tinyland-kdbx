"""Core KDBX database reading logic using pykeepass.

This module provides the in-process KDBX reader that replaces
keepassxc-cli subprocess calls. It handles:
  - Opening KDBX databases (password and/or keyfile)
  - Retrieving entries by slash-separated path
  - Listing all entries in the database
  - Extracting password, username, URL, notes, and custom attributes
"""

import os
from pathlib import Path
from typing import Optional

from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError


class KDBXError(Exception):
    """Base exception for KDBX operations."""


class DatabaseNotFoundError(KDBXError):
    """Raised when the KDBX database file does not exist."""


class AuthenticationError(KDBXError):
    """Raised when database credentials are invalid."""


class EntryNotFoundError(KDBXError):
    """Raised when a requested entry path does not exist."""


def open_database(
    database_path: Optional[str] = None,
    password: Optional[str] = None,
    keyfile: Optional[str] = None,
) -> PyKeePass:
    """Open a KeePassXC database.

    Args:
        database_path: Path to the .kdbx file. Defaults to
            KEEPASS_DATABASE_PATH environment variable.
        password: Master password. Defaults to KEEPASS_PASSWORD
            environment variable.
        keyfile: Optional path to a key file.

    Returns:
        An opened PyKeePass database instance.

    Raises:
        DatabaseNotFoundError: If the database file does not exist.
        AuthenticationError: If the credentials are invalid.
        KDBXError: For other database errors.
    """
    if database_path is None:
        database_path = os.environ.get("KEEPASS_DATABASE_PATH", "")
    if password is None:
        password = os.environ.get("KEEPASS_PASSWORD")

    if not database_path:
        raise KDBXError(
            "No database path provided. Set KEEPASS_DATABASE_PATH or pass database_path."
        )

    db_path = Path(database_path).expanduser().resolve()
    if not db_path.is_file():
        raise DatabaseNotFoundError(f"Database not found: {db_path}")

    try:
        return PyKeePass(str(db_path), password=password, keyfile=keyfile)
    except CredentialsError:
        # Intentionally vague -- do NOT leak password or pykeepass internals
        raise AuthenticationError(
            "Failed to open database (wrong password or corrupted file?)"
        )
    except Exception as exc:
        raise KDBXError(f"Failed to open database: {exc}") from exc


def _find_entry(kp: PyKeePass, entry_path: str):
    """Find an entry by its slash-separated path.

    KeePass entries live inside groups. A path like
    ``tinyland/api/gitlab/token`` means group=tinyland/api/gitlab,
    title=token.

    Returns the pykeepass Entry or None.
    """
    parts = [p for p in entry_path.strip("/").split("/") if p]
    if not parts:
        return None

    title = parts[-1]
    group_parts = parts[:-1]

    # Navigate to the target group
    group = kp.root_group
    for gname in group_parts:
        found = None
        for sub in group.subgroups:
            if sub.name == gname:
                found = sub
                break
        if found is None:
            return None
        group = found

    # Find the entry by title within the group
    for entry in group.entries:
        if entry.title == title:
            return entry

    return None


def _get_entry_attribute(entry, attr: str) -> Optional[str]:
    """Return the requested attribute from a pykeepass Entry."""
    attr_lower = attr.lower()
    if attr_lower == "password":
        return entry.password
    elif attr_lower == "username":
        return entry.username
    elif attr_lower == "url":
        return entry.url
    elif attr_lower == "notes":
        return entry.notes
    elif attr_lower == "title":
        return entry.title
    else:
        # Try custom string field
        return entry.get_custom_property(attr)


def get_entry(
    entry_path: str,
    database_path: Optional[str] = None,
    password: Optional[str] = None,
    keyfile: Optional[str] = None,
    attribute: str = "password",
) -> str:
    """Retrieve a single entry's attribute from the database.

    The entry_path uses forward-slash notation matching KeePassXC CLI:
        tinyland/api/gitlab/token

    Args:
        entry_path: Path to the entry (e.g., "tinyland/api/gitlab/token").
        database_path: Path to the .kdbx file.
        password: Master password.
        keyfile: Optional key file path.
        attribute: Which attribute to return. One of:
            "password" (default), "username", "url", "notes", "title",
            or a custom attribute name.

    Returns:
        The requested attribute value as a string.

    Raises:
        EntryNotFoundError: If no entry exists at the given path.
        KDBXError: For database errors.
    """
    kp = open_database(database_path, password, keyfile)

    entry = _find_entry(kp, entry_path)
    if entry is None:
        raise EntryNotFoundError(f"Entry not found: {entry_path}")

    value = _get_entry_attribute(entry, attribute)
    if value is None:
        raise EntryNotFoundError(
            f"Attribute '{attribute}' not found on entry '{entry_path}'"
        )
    return value


def list_entries(
    database_path: Optional[str] = None,
    password: Optional[str] = None,
    keyfile: Optional[str] = None,
) -> list[str]:
    """List all entry paths in the database.

    Args:
        database_path: Path to the .kdbx file.
        password: Master password.
        keyfile: Optional key file path.

    Returns:
        A sorted list of entry paths as strings.
    """
    kp = open_database(database_path, password, keyfile)

    paths: list[str] = []

    def _walk(group, prefix: str) -> None:
        for entry in group.entries:
            path = f"{prefix}{entry.title}" if prefix else entry.title
            paths.append(path)
        for sub in group.subgroups:
            sub_prefix = f"{prefix}{sub.name}/"
            _walk(sub, sub_prefix)

    _walk(kp.root_group, "")
    return sorted(paths)
