"""Tests for CLI argument parsing and subcommand dispatch.

These tests exercise the argument parser and the encode/decode subcommands
that do not require a KDBX database file.
"""

import io
import os
from unittest import mock

import pytest

from tinyland_kdbx.base58 import b58encode, b58encode_str
from tinyland_kdbx.cli import (
    _resolve_password,
    build_parser,
    cmd_decode_b58,
    cmd_encode_b58,
    main,
)


# ---------------------------------------------------------------------------
# Parser construction tests
# ---------------------------------------------------------------------------


class TestParser:
    """Verify that the argument parser accepts valid inputs and rejects bad ones."""

    def test_get_minimal(self):
        parser = build_parser()
        args = parser.parse_args(["get", "/tmp/test.kdbx", "group/entry"])
        assert args.command == "get"
        assert args.db_path == "/tmp/test.kdbx"
        assert args.entry_path == "group/entry"
        assert args.attr == "password"
        assert args.password_env == "KEEPASS_PASSWORD"
        assert args.password_b58 is None

    def test_get_with_attr(self):
        parser = build_parser()
        args = parser.parse_args(["get", "db.kdbx", "entry", "--attr", "username"])
        assert args.attr == "username"

    def test_get_with_password_b58(self):
        parser = build_parser()
        args = parser.parse_args(
            ["get", "db.kdbx", "entry", "--password-b58", "abc123"]
        )
        assert args.password_b58 == "abc123"

    def test_get_with_password_env(self):
        parser = build_parser()
        args = parser.parse_args(
            ["get", "db.kdbx", "entry", "--password-env", "MY_PW"]
        )
        assert args.password_env == "MY_PW"

    def test_list_minimal(self):
        parser = build_parser()
        args = parser.parse_args(["list", "/tmp/test.kdbx"])
        assert args.command == "list"
        assert args.db_path == "/tmp/test.kdbx"

    def test_list_with_password_b58(self):
        parser = build_parser()
        args = parser.parse_args(["list", "db.kdbx", "--password-b58", "encoded"])
        assert args.password_b58 == "encoded"

    def test_encode_b58(self):
        parser = build_parser()
        args = parser.parse_args(["encode-b58"])
        assert args.command == "encode-b58"

    def test_decode_b58(self):
        parser = build_parser()
        args = parser.parse_args(["decode-b58"])
        assert args.command == "decode-b58"

    def test_sudo_pipe(self):
        parser = build_parser()
        args = parser.parse_args(["sudo-pipe", "db.kdbx", "tinyland/sudo/root"])
        assert args.command == "sudo-pipe"
        assert args.db_path == "db.kdbx"
        assert args.entry_path == "tinyland/sudo/root"

    def test_sudo_pipe_with_password_env(self):
        parser = build_parser()
        args = parser.parse_args(
            ["sudo-pipe", "db.kdbx", "entry", "--password-env", "MY_PASS"]
        )
        assert args.password_env == "MY_PASS"

    def test_no_subcommand_raises(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_unknown_subcommand_raises(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["bogus"])

    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "0.1.0" in captured.out


# ---------------------------------------------------------------------------
# encode-b58 subcommand
# ---------------------------------------------------------------------------


class TestEncodeB58Subcommand:
    """Test the encode-b58 subcommand end-to-end via stdin/stdout."""

    def test_encode_hello(self):
        parser = build_parser()
        args = parser.parse_args(["encode-b58"])

        with mock.patch("sys.stdin", new=io.TextIOWrapper(io.BytesIO(b"hello"))):
            with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                rc = cmd_encode_b58(args)

        assert rc == 0
        assert mock_out.getvalue() == b58encode(b"hello")

    def test_encode_empty(self):
        parser = build_parser()
        args = parser.parse_args(["encode-b58"])

        with mock.patch("sys.stdin", new=io.TextIOWrapper(io.BytesIO(b""))):
            with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                rc = cmd_encode_b58(args)

        assert rc == 0
        assert mock_out.getvalue() == ""

    def test_encode_binary(self):
        parser = build_parser()
        args = parser.parse_args(["encode-b58"])
        data = bytes(range(256))

        with mock.patch("sys.stdin", new=io.TextIOWrapper(io.BytesIO(data))):
            with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                rc = cmd_encode_b58(args)

        assert rc == 0
        assert mock_out.getvalue() == b58encode(data)

    def test_encode_via_main(self):
        with mock.patch("sys.stdin", new=io.TextIOWrapper(io.BytesIO(b"test"))):
            with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                rc = main(["encode-b58"])

        assert rc == 0
        assert mock_out.getvalue() == b58encode(b"test")


# ---------------------------------------------------------------------------
# decode-b58 subcommand
# ---------------------------------------------------------------------------


class TestDecodeB58Subcommand:
    """Test the decode-b58 subcommand end-to-end via stdin/stdout."""

    def test_decode_known_value(self):
        parser = build_parser()
        args = parser.parse_args(["decode-b58"])
        encoded = b58encode_str("hello")

        with mock.patch("sys.stdin", new=io.StringIO(encoded + "\n")):
            with mock.patch("sys.stdout", new=mock.MagicMock()) as mock_out:
                mock_out.buffer = io.BytesIO()
                rc = cmd_decode_b58(args)

        assert rc == 0
        mock_out.buffer.seek(0)
        assert mock_out.buffer.read() == b"hello"

    def test_decode_empty(self):
        parser = build_parser()
        args = parser.parse_args(["decode-b58"])

        with mock.patch("sys.stdin", new=io.StringIO("")):
            rc = cmd_decode_b58(args)

        assert rc == 0

    def test_decode_strips_whitespace(self):
        """Trailing newlines and spaces should be stripped before decoding."""
        parser = build_parser()
        args = parser.parse_args(["decode-b58"])
        encoded = b58encode_str("data")

        with mock.patch("sys.stdin", new=io.StringIO(f"  {encoded}  \n\n")):
            with mock.patch("sys.stdout", new=mock.MagicMock()) as mock_out:
                mock_out.buffer = io.BytesIO()
                rc = cmd_decode_b58(args)

        assert rc == 0
        mock_out.buffer.seek(0)
        assert mock_out.buffer.read() == b"data"

    def test_decode_invalid_char(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["decode-b58"])

        with mock.patch("sys.stdin", new=io.StringIO("0OIl")):
            rc = cmd_decode_b58(args)

        assert rc == 3
        captured = capsys.readouterr()
        assert "error" in captured.err.lower()


# ---------------------------------------------------------------------------
# Password resolution tests
# ---------------------------------------------------------------------------


class TestPasswordResolution:
    """Verify password resolution from env var and base58 argument."""

    def test_password_from_env(self):
        parser = build_parser()
        args = parser.parse_args(
            ["get", "db.kdbx", "entry", "--password-env", "TEST_KDBX_PW"]
        )
        with mock.patch.dict("os.environ", {"TEST_KDBX_PW": "secret123"}):
            pw = _resolve_password(args)
        assert pw == "secret123"

    def test_password_from_default_env(self, monkeypatch):
        """When --password-env is not specified, defaults to KEEPASS_PASSWORD."""
        parser = build_parser()
        args = parser.parse_args(["get", "db.kdbx", "entry"])
        monkeypatch.setenv("KEEPASS_PASSWORD", "default-pw")
        pw = _resolve_password(args)
        assert pw == "default-pw"

    def test_password_from_b58(self):
        encoded_pw = b58encode_str("my-secret")
        parser = build_parser()
        args = parser.parse_args(
            ["get", "db.kdbx", "entry", "--password-b58", encoded_pw]
        )
        pw = _resolve_password(args)
        assert pw == "my-secret"

    def test_b58_takes_precedence_over_env(self, monkeypatch):
        """When both --password-b58 and env are present, b58 wins."""
        encoded_pw = b58encode_str("b58-password")
        monkeypatch.setenv("KEEPASS_PASSWORD", "env-password")
        parser = build_parser()
        args = parser.parse_args(
            ["get", "db.kdbx", "entry", "--password-b58", encoded_pw]
        )
        pw = _resolve_password(args)
        assert pw == "b58-password"

    def test_missing_env_exits(self):
        parser = build_parser()
        args = parser.parse_args(
            ["get", "db.kdbx", "entry", "--password-env", "NONEXISTENT_VAR_XYZ"]
        )
        env = {k: v for k, v in os.environ.items() if k != "NONEXISTENT_VAR_XYZ"}
        with mock.patch.dict("os.environ", env, clear=True):
            with pytest.raises(SystemExit) as exc_info:
                _resolve_password(args)
        assert exc_info.value.code == 3

    def test_bad_b58_password_exits(self):
        parser = build_parser()
        args = parser.parse_args(
            ["get", "db.kdbx", "entry", "--password-b58", "0OIl"]
        )
        with pytest.raises(SystemExit) as exc_info:
            _resolve_password(args)
        assert exc_info.value.code == 3


# ---------------------------------------------------------------------------
# Database error handling (no real KDBX needed)
# ---------------------------------------------------------------------------


class TestDatabaseErrors:
    """Test error handling when database operations fail."""

    def test_get_missing_database(self, capsys, monkeypatch):
        monkeypatch.setenv("KEEPASS_PASSWORD", "test")
        with pytest.raises(SystemExit) as exc_info:
            main(["get", "/nonexistent/path.kdbx", "test/path"])
        assert exc_info.value.code == 2
        captured = capsys.readouterr()
        assert "error" in captured.err.lower()

    def test_get_missing_password(self, monkeypatch):
        monkeypatch.delenv("KEEPASS_PASSWORD", raising=False)
        with pytest.raises(SystemExit) as exc_info:
            main(["get", "/nonexistent/path.kdbx", "test/path"])
        assert exc_info.value.code == 3

    def test_list_missing_database(self, capsys, monkeypatch):
        monkeypatch.setenv("KEEPASS_PASSWORD", "test")
        with pytest.raises(SystemExit) as exc_info:
            main(["list", "/nonexistent/path.kdbx"])
        assert exc_info.value.code == 2

    def test_sudo_pipe_missing_database(self, capsys, monkeypatch):
        monkeypatch.setenv("KEEPASS_PASSWORD", "test")
        with pytest.raises(SystemExit) as exc_info:
            main(["sudo-pipe", "/nonexistent/path.kdbx", "entry"])
        assert exc_info.value.code == 2


# ---------------------------------------------------------------------------
# main() dispatch
# ---------------------------------------------------------------------------


class TestMainDispatch:
    """Verify that main() correctly dispatches to subcommand handlers."""

    def test_encode_via_main(self):
        with mock.patch("sys.stdin", new=io.TextIOWrapper(io.BytesIO(b"test"))):
            with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                rc = main(["encode-b58"])

        assert rc == 0
        assert mock_out.getvalue() == b58encode(b"test")

    def test_missing_env_var_exits_3(self):
        """get subcommand should exit 3 when the password env var is unset."""
        env = {k: v for k, v in os.environ.items() if k != "KEEPASS_PASSWORD"}
        with mock.patch.dict("os.environ", env, clear=True):
            with pytest.raises(SystemExit) as exc_info:
                main(
                    [
                        "get",
                        "/tmp/fake.kdbx",
                        "some/entry",
                        "--password-env",
                        "KEEPASS_PASSWORD",
                    ]
                )
        assert exc_info.value.code == 3
