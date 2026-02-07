"""Tinyland KDBX Reader - Native KDBX database access via pykeepass.

Replaces fragile keepassxc-cli subprocess piping with in-process Python.
Provides a CLI tool and importable library for reading KeePassXC databases.
Includes base58 transport encoding for secure credential passing.
"""

__version__ = "0.1.0"

from tinyland_kdbx.reader import (  # noqa: F401
    get_entry,
    list_entries,
    open_database,
    KDBXError,
    DatabaseNotFoundError,
    AuthenticationError,
    EntryNotFoundError,
)
from tinyland_kdbx.base58 import (  # noqa: F401
    b58encode,
    b58decode,
    b58encode_str,
    b58decode_str,
)
from tinyland_kdbx.cli import main  # noqa: F401
