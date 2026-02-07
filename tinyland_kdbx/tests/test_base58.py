"""Comprehensive tests for the base58 encode/decode functions."""

import pytest

from tinyland_kdbx.base58 import (
    BITCOIN_ALPHABET,
    b58decode,
    b58decode_str,
    b58encode,
    b58encode_str,
)


# ---------------------------------------------------------------------------
# Round-trip tests
# ---------------------------------------------------------------------------


class TestBase58RoundTrip:
    """Verify that encode -> decode is identity for various inputs."""

    def test_empty_bytes(self):
        assert b58encode(b"") == ""
        assert b58decode("") == b""

    def test_single_byte(self):
        for i in range(256):
            data = bytes([i])
            assert b58decode(b58encode(data)) == data

    def test_ascii_string(self):
        text = "hello world"
        encoded = b58encode_str(text)
        assert b58decode_str(encoded) == text

    def test_unicode_string(self):
        text = "cafe\u0301 \u2603 \U0001f600"
        encoded = b58encode_str(text)
        assert b58decode_str(encoded) == text

    def test_binary_blob(self):
        data = bytes(range(256))
        assert b58decode(b58encode(data)) == data

    def test_leading_null_bytes(self):
        data = b"\x00\x00\x00abc"
        encoded = b58encode(data)
        # Leading null bytes map to leading '1' characters
        assert encoded.startswith("111")
        assert b58decode(encoded) == data

    def test_all_null_bytes(self):
        data = b"\x00" * 5
        encoded = b58encode(data)
        assert encoded == "1" * 5
        assert b58decode(encoded) == data

    def test_long_payload(self):
        data = b"A" * 10_000
        assert b58decode(b58encode(data)) == data

    def test_single_null_byte(self):
        data = b"\x00"
        assert b58encode(data) == "1"
        assert b58decode("1") == b"\x00"

    def test_password_like_strings(self):
        """Test with strings that look like real passwords."""
        passwords = [
            "P@ssw0rd!",
            "correct-horse-battery-staple",
            "\u00e9\u00e0\u00fc\u00f6",
            "a" * 256,
            "!@#$%^&*()_+-=[]{}|;':\",./<>?",
        ]
        for pw in passwords:
            encoded = b58encode_str(pw)
            assert b58decode_str(encoded) == pw


# ---------------------------------------------------------------------------
# Known-value tests (Bitcoin-style vectors)
# ---------------------------------------------------------------------------


class TestBase58KnownValues:
    """Test against well-known base58 values."""

    @pytest.mark.parametrize(
        "raw, expected",
        [
            (b"", ""),
            (b"\x00", "1"),
            (b"\x00\x00", "11"),
            (b"a", "2g"),
            (b"abc", "ZiCa"),
            (b"Hello World", "JxF12TrwUP45BMd"),
        ],
    )
    def test_known_encode(self, raw, expected):
        assert b58encode(raw) == expected

    @pytest.mark.parametrize(
        "encoded, expected",
        [
            ("", b""),
            ("1", b"\x00"),
            ("11", b"\x00\x00"),
            ("2g", b"a"),
            ("ZiCa", b"abc"),
            ("JxF12TrwUP45BMd", b"Hello World"),
        ],
    )
    def test_known_decode(self, encoded, expected):
        assert b58decode(encoded) == expected


# ---------------------------------------------------------------------------
# Error handling tests
# ---------------------------------------------------------------------------


class TestBase58Errors:
    """Verify that invalid inputs raise the expected exceptions."""

    def test_encode_rejects_non_bytes(self):
        with pytest.raises(TypeError):
            b58encode("not bytes")  # type: ignore[arg-type]

    def test_encode_rejects_int(self):
        with pytest.raises(TypeError):
            b58encode(42)  # type: ignore[arg-type]

    def test_decode_rejects_non_string(self):
        with pytest.raises(TypeError):
            b58decode(b"not a string")  # type: ignore[arg-type]

    def test_decode_rejects_int(self):
        with pytest.raises(TypeError):
            b58decode(123)  # type: ignore[arg-type]

    def test_decode_rejects_invalid_char(self):
        # '0' (zero), 'O', 'I', 'l' are not in the Bitcoin alphabet
        for bad_char in ["0", "O", "I", "l"]:
            with pytest.raises(ValueError, match="Invalid base58 character"):
                b58decode(bad_char)

    def test_decode_rejects_space(self):
        with pytest.raises(ValueError):
            b58decode("abc def")

    def test_decode_rejects_newline(self):
        with pytest.raises(ValueError):
            b58decode("abc\ndef")

    def test_decode_str_bad_utf8(self):
        """Encode raw bytes that are not valid UTF-8, then fail to decode as string."""
        data = b"\xff\xfe"
        encoded = b58encode(data)
        with pytest.raises(UnicodeDecodeError):
            b58decode_str(encoded)


# ---------------------------------------------------------------------------
# Alphabet sanity
# ---------------------------------------------------------------------------


class TestAlphabet:
    """Verify alphabet properties."""

    def test_length(self):
        assert len(BITCOIN_ALPHABET) == 58

    def test_no_duplicates(self):
        assert len(set(BITCOIN_ALPHABET)) == 58

    def test_no_confusing_chars(self):
        for ch in "0OIl":
            assert ch not in BITCOIN_ALPHABET

    def test_all_printable(self):
        for ch in BITCOIN_ALPHABET:
            assert ch.isprintable()
            assert not ch.isspace()
