"""Base58 codec (Bitcoin alphabet) for secure credential transport.

Extracted from plugins/module_utils/become/base58.py, simplified for CLI use.
Provides encoding/decoding of arbitrary bytes and text strings.
"""

BITCOIN_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_MAP = {char: idx for idx, char in enumerate(BITCOIN_ALPHABET)}


def b58encode(data: bytes) -> str:
    """Encode bytes to a base58 string using the Bitcoin alphabet."""
    if not isinstance(data, bytes):
        raise TypeError("Input must be bytes")
    if not data:
        return ""

    leading_zeros = 0
    for byte in data:
        if byte == 0:
            leading_zeros += 1
        else:
            break

    num = int.from_bytes(data, byteorder="big")
    if num == 0:
        return BITCOIN_ALPHABET[0] * leading_zeros

    encoded = []
    while num > 0:
        num, rem = divmod(num, 58)
        encoded.append(BITCOIN_ALPHABET[rem])

    return BITCOIN_ALPHABET[0] * leading_zeros + "".join(reversed(encoded))


def b58decode(encoded: str) -> bytes:
    """Decode a base58 string to bytes using the Bitcoin alphabet."""
    if not isinstance(encoded, str):
        raise TypeError("Input must be a string")
    if not encoded:
        return b""

    for ch in encoded:
        if ch not in _B58_MAP:
            raise ValueError(f"Invalid base58 character: {ch!r}")

    leading_zeros = 0
    for ch in encoded:
        if ch == BITCOIN_ALPHABET[0]:
            leading_zeros += 1
        else:
            break

    num = 0
    for ch in encoded[leading_zeros:]:
        num = num * 58 + _B58_MAP[ch]

    if num == 0:
        return b"\x00" * leading_zeros

    byte_len = (num.bit_length() + 7) // 8
    return b"\x00" * leading_zeros + num.to_bytes(byte_len, byteorder="big")


def b58encode_str(text: str, encoding: str = "utf-8") -> str:
    """Encode a text string to base58."""
    return b58encode(text.encode(encoding))


def b58decode_str(encoded: str, encoding: str = "utf-8") -> str:
    """Decode a base58 string to text."""
    return b58decode(encoded).decode(encoding)
