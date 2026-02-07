"""Command-line interface for tinyland-kdbx.

Provides subcommands:
  get        - Retrieve an entry attribute from a KDBX database
  list       - List all entry paths in a KDBX database
  encode-b58 - Base58-encode data from stdin
  decode-b58 - Base58-decode data from stdin
  sudo-pipe  - Output entry password for piping to sudo -S

Exit codes:
    0 - Success
    1 - Entry not found
    2 - Database open failed
    3 - Invalid arguments
"""

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

from tinyland_kdbx.base58 import b58decode, b58decode_str, b58encode
from tinyland_kdbx.reader import (
    KDBXError,
    _find_entry,
    _get_entry_attribute,
    open_database,
)


def _resolve_password(args) -> str:
    """Resolve the database master password from CLI arguments.

    Supports --password-env (environment variable name) and --password-b58
    (base58-encoded password supplied directly).

    Returns the plaintext password. Never prints the password to stderr.
    """
    if getattr(args, "password_b58", None):
        try:
            return b58decode_str(args.password_b58)
        except Exception:
            print("error: failed to decode base58 password", file=sys.stderr)
            sys.exit(3)

    env_var = getattr(args, "password_env", None) or "KEEPASS_PASSWORD"
    password = os.environ.get(env_var)
    if not password:
        print(
            f"error: environment variable {env_var} is not set or empty",
            file=sys.stderr,
        )
        sys.exit(3)
    return password


def _open_db(db_path: str, password: str):
    """Open a KDBX database, exiting with code 2 on failure."""
    resolved = Path(db_path).expanduser().resolve()
    if not resolved.is_file():
        print(f"error: database not found: {resolved}", file=sys.stderr)
        sys.exit(2)

    try:
        return open_database(str(resolved), password=password)
    except KDBXError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def cmd_get(args) -> int:
    """Handle the 'get' subcommand."""
    password = _resolve_password(args)
    kp = _open_db(args.db_path, password)

    entry = _find_entry(kp, args.entry_path)
    if entry is None:
        print(f"error: entry not found: {args.entry_path}", file=sys.stderr)
        return 1

    value = _get_entry_attribute(entry, args.attr)
    if value is None:
        print(
            f"error: attribute '{args.attr}' not found on entry", file=sys.stderr
        )
        return 1

    sys.stdout.write(value)
    return 0


def cmd_list(args) -> int:
    """Handle the 'list' subcommand."""
    password = _resolve_password(args)
    kp = _open_db(args.db_path, password)

    paths: list[str] = []

    def _walk(group, prefix: str) -> None:
        for entry in group.entries:
            path = f"{prefix}{entry.title}" if prefix else entry.title
            paths.append(path)
        for sub in group.subgroups:
            _walk(sub, f"{prefix}{sub.name}/")

    _walk(kp.root_group, "")
    for p in sorted(paths):
        print(p)
    return 0


def cmd_encode_b58(args) -> int:
    """Handle the 'encode-b58' subcommand -- reads stdin, writes base58."""
    raw = sys.stdin.buffer.read()
    encoded = b58encode(raw)
    sys.stdout.write(encoded)
    return 0


def cmd_decode_b58(args) -> int:
    """Handle the 'decode-b58' subcommand -- reads stdin, writes decoded."""
    encoded = sys.stdin.read().strip()
    if not encoded:
        return 0
    try:
        decoded = b58decode(encoded)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    sys.stdout.buffer.write(decoded)
    return 0


def cmd_sudo_pipe(args) -> int:
    """Handle the 'sudo-pipe' subcommand.

    Identical to 'get' but appends a newline so the output can be piped
    directly into ``sudo -S``.
    """
    password = _resolve_password(args)
    kp = _open_db(args.db_path, password)

    entry = _find_entry(kp, args.entry_path)
    if entry is None:
        print(f"error: entry not found: {args.entry_path}", file=sys.stderr)
        return 1

    value = _get_entry_attribute(entry, "password")
    if value is None:
        print("error: password attribute not found on entry", file=sys.stderr)
        return 1

    # Write with trailing newline for sudo -S consumption
    sys.stdout.write(value + "\n")
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _add_db_args(parser: argparse.ArgumentParser) -> None:
    """Add common database/password arguments to a subparser."""
    parser.add_argument("db_path", help="Path to the .kdbx database file")
    parser.add_argument(
        "--password-env",
        default="KEEPASS_PASSWORD",
        help="Environment variable holding the DB master password (default: KEEPASS_PASSWORD)",
    )
    parser.add_argument(
        "--password-b58",
        default=None,
        help="Base58-encoded master password (alternative to env var)",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="tinyland-kdbx",
        description="Native KeePassXC KDBX reader with base58 transport",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__import__('tinyland_kdbx').__version__}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # -- get --
    p_get = sub.add_parser(
        "get", help="Retrieve an entry attribute from a KDBX database"
    )
    _add_db_args(p_get)
    p_get.add_argument(
        "entry_path",
        help="Slash-separated entry path (e.g. tinyland/api/gitlab/token)",
    )
    p_get.add_argument(
        "--attr",
        default="password",
        help="Attribute to retrieve (default: password)",
    )
    p_get.set_defaults(func=cmd_get)

    # -- list --
    p_list = sub.add_parser(
        "list", help="List all entry paths in a KDBX database"
    )
    _add_db_args(p_list)
    p_list.set_defaults(func=cmd_list)

    # -- encode-b58 --
    p_enc = sub.add_parser("encode-b58", help="Base58-encode data from stdin")
    p_enc.set_defaults(func=cmd_encode_b58)

    # -- decode-b58 --
    p_dec = sub.add_parser("decode-b58", help="Base58-decode data from stdin")
    p_dec.set_defaults(func=cmd_decode_b58)

    # -- sudo-pipe --
    p_sudo = sub.add_parser(
        "sudo-pipe",
        help="Output entry password to stdout for piping to sudo -S",
    )
    _add_db_args(p_sudo)
    p_sudo.add_argument(
        "entry_path", help="Slash-separated entry path"
    )
    p_sudo.set_defaults(func=cmd_sudo_pipe)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
