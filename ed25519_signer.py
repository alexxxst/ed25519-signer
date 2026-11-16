#!/usr/bin/env python3
"""MeshCore-compatible Ed25519 signer with a compact command dictionary."""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Sequence

import nacl.bindings as sodium
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

PRIVATE_KEY_SIZE = 64
PUBLIC_KEY_SIZE = 32
SIGNATURE_SIZE = 64
MAX_TOKENS = 254
LITERAL_CODE = 254
HEX_CODE = 255
MASK_LABEL = b"MC1-mask"
DICTIONARY_NAME = "dictionary.txt"
MAX_BLOB_SIZE = 160
HEX_CHARS = b"0123456789abcdef"


class SignerError(Exception):
    pass


class DictionaryError(SignerError):
    pass


class CompressionError(SignerError):
    pass


class BlobError(SignerError):
    pass


def _clamp(h: bytes) -> bytes:
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 63
    a[31] |= 64
    return bytes(a)


def keypair_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = _clamp(h)
    private_key = a + h[32:]
    public_key = sodium.crypto_scalarmult_ed25519_base_noclamp(a)
    return private_key, public_key


def generate_keypair() -> tuple[bytes, bytes]:
    return keypair_from_seed(secrets.token_bytes(32))


def derive_public_key(private_key: bytes) -> bytes:
    if len(private_key) != PRIVATE_KEY_SIZE:
        raise ValueError("private key must be 64 bytes")
    return sodium.crypto_scalarmult_ed25519_base_noclamp(private_key[:32])


def sign_message(
    message: bytes, private_key: bytes, public_key: bytes | None = None
) -> bytes:
    if len(private_key) != PRIVATE_KEY_SIZE:
        raise ValueError("private key must be 64 bytes")
    if public_key is None:
        public_key = derive_public_key(private_key)
    if len(public_key) != PUBLIC_KEY_SIZE:
        raise ValueError("public key must be 32 bytes")

    r = sodium.crypto_core_ed25519_scalar_reduce(
        hashlib.sha512(private_key[32:] + message).digest()
    )
    r_point = sodium.crypto_scalarmult_ed25519_base_noclamp(r)
    h = sodium.crypto_core_ed25519_scalar_reduce(
        hashlib.sha512(r_point + public_key + message).digest()
    )
    s = sodium.crypto_core_ed25519_scalar_add(
        r, sodium.crypto_core_ed25519_scalar_mul(h, private_key[:32])
    )
    return r_point + s


def verify_message(signature: bytes, message: bytes, public_key: bytes) -> bool:
    if len(signature) != SIGNATURE_SIZE or len(public_key) != PUBLIC_KEY_SIZE:
        return False
    try:
        VerifyKey(public_key).verify(message, signature)
    except (BadSignatureError, ValueError):
        return False
    return True


def parse_hex(text: str | bytes, size: int) -> bytes:
    if isinstance(text, bytes):
        text = text.decode("ascii")
    compact = "".join(text.split())
    if len(compact) != size * 2:
        raise ValueError(f"expected {size * 2} hex characters, got {len(compact)}")
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise ValueError("invalid hex") from exc


def decode_hex(data: bytes) -> bytes:
    compact = b"".join(data.split())
    if len(compact) % 2:
        raise ValueError("hex input has odd length")
    try:
        return bytes.fromhex(compact.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("invalid hex input") from exc


def _unescape(line: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(line):
        ch = line[i]
        if ch != "\\":
            out.extend(ch.encode("utf-8"))
            i += 1
            continue
        i += 1
        if i >= len(line):
            raise DictionaryError("trailing backslash in dictionary")
        esc = line[i]
        if esc == "s":
            out.append(32)
        elif esc == "t":
            out.append(9)
        elif esc == "n":
            out.append(10)
        elif esc == "r":
            out.append(13)
        elif esc == "\\":
            out.append(92)
        elif esc == "x":
            if i + 2 >= len(line):
                raise DictionaryError("bad \\x escape in dictionary")
            try:
                out.append(int(line[i + 1 : i + 3], 16))
            except ValueError as exc:
                raise DictionaryError("bad \\x escape in dictionary") from exc
            i += 2
        else:
            raise DictionaryError(f"unknown dictionary escape \\{esc}")
        i += 1
    return bytes(out)


class Dictionary:
    def __init__(self, tokens: Sequence[bytes]):
        if not tokens:
            raise DictionaryError("dictionary is empty")
        if len(tokens) > MAX_TOKENS:
            raise DictionaryError(f"dictionary has more than {MAX_TOKENS} tokens")
        seen = set()
        clean = []
        for token in tokens:
            if not token:
                raise DictionaryError("empty token in dictionary")
            if b"\x00" in token:
                raise DictionaryError("NUL byte in dictionary token")
            if token in seen:
                raise DictionaryError(f"duplicate token {token!r}")
            seen.add(token)
            clean.append(token)
        self.tokens = tuple(clean)
        self.dict_id = hashlib.sha256(b"\x00".join(self.tokens)).digest()[0]
        self._trie: dict[int, dict] = {}
        for token_id, token in enumerate(self.tokens):
            node = self._trie
            for byte in token:
                node = node.setdefault(byte, {})
            node[-1] = token_id

    @classmethod
    def load(cls, path: str | Path) -> "Dictionary":
        tokens = []
        text = Path(path).read_text(encoding="utf-8")
        for line in text.splitlines():
            if line:
                tokens.append(_unescape(line))
        return cls(tokens)

    def _match(self, data: bytes, pos: int) -> tuple[int, int | None]:
        node = self._trie
        j = pos
        best_len = 0
        best_id = None
        n = len(data)
        while j < n and data[j] in node:
            node = node[data[j]]
            j += 1
            if -1 in node:
                best_len = j - pos
                best_id = node[-1]
        return best_len, best_id

    @staticmethod
    def _hex_run(data: bytes, pos: int) -> int:
        j = pos
        n = len(data)
        while j < n and data[j] in HEX_CHARS:
            j += 1
        return j - pos

    def _encode_literal(self, data: bytes) -> bytes:
        out = bytearray()
        for i in range(0, len(data), 255):
            chunk = data[i : i + 255]
            out.extend((LITERAL_CODE, len(chunk)))
            out.extend(chunk)
        return bytes(out)

    def _encode_tokens(self, data: bytes) -> bytes:
        out = bytearray()
        i = 0
        n = len(data)
        while i < n:
            match_len, token_id = self._match(data, i)
            hex_len = self._hex_run(data, i)
            hex_save = hex_len - (2 + (hex_len + 1) // 2) if hex_len >= 4 else -1
            token_save = match_len - 1 if match_len else -1

            if hex_len >= 4 and hex_save > token_save:
                out.extend((HEX_CODE, hex_len))
                for k in range(0, hex_len, 2):
                    hi = int(chr(data[i + k]), 16)
                    lo = int(chr(data[i + k + 1]), 16) if k + 1 < hex_len else 0
                    out.append((hi << 4) | lo)
                i += hex_len
            elif token_id is not None:
                out.append(token_id)
                i += match_len
            else:
                j = i + 1
                while j < n:
                    _, next_id = self._match(data, j)
                    if next_id is not None or self._hex_run(data, j) >= 4:
                        break
                    j += 1
                chunk = data[i:j]
                for k in range(0, len(chunk), 255):
                    part = chunk[k : k + 255]
                    out.extend((LITERAL_CODE, len(part)))
                    out.extend(part)
                i = j
        return bytes(out)

    def encode(self, data: bytes) -> bytes:
        tokenized = self._encode_tokens(data)
        literal = self._encode_literal(data)
        return tokenized if len(tokenized) <= len(literal) else literal

    def decode(self, data: bytes) -> bytes:
        out = bytearray()
        i = 0
        n = len(data)
        while i < n:
            code = data[i]
            i += 1
            if code < len(self.tokens):
                out.extend(self.tokens[code])
            elif code == LITERAL_CODE:
                if i >= n:
                    raise CompressionError("truncated literal run")
                length = data[i]
                i += 1
                if i + length > n:
                    raise CompressionError("truncated literal run")
                out.extend(data[i : i + length])
                i += length
            elif code == HEX_CODE:
                if i >= n:
                    raise CompressionError("truncated hex run")
                length = data[i]
                i += 1
                if length == 0:
                    raise CompressionError("empty hex run")
                packed = (length + 1) // 2
                if i + packed > n:
                    raise CompressionError("truncated hex run")
                for byte in data[i : i + packed]:
                    out.extend(f"{byte:02x}".encode())
                i += packed
                if length % 2:
                    del out[-1]
            else:
                raise CompressionError(f"invalid code {code}")
        return bytes(out)


def _keystream(seed: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(
            hashlib.sha512(MASK_LABEL + seed + counter.to_bytes(4, "little")).digest()
        )
        counter += 1
    return bytes(out[:length])


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def build_blob(
    text: bytes,
    private_key: bytes,
    public_key: bytes,
    dictionary: Dictionary,
    timestamp: int,
) -> bytes:
    if not 0 <= timestamp <= 0xFFFFFFFF:
        raise ValueError("timestamp must fit in uint32")
    payload = (
        timestamp.to_bytes(4, "little")
        + bytes([dictionary.dict_id])
        + dictionary.encode(text)
    )
    signature = sign_message(payload, private_key, public_key)
    mask = _keystream(signature[:32], len(payload))
    return _xor(payload, mask) + signature


def open_blob(
    blob: bytes, public_key: bytes, dictionary: Dictionary
) -> tuple[bytes, int]:
    if len(blob) < 4 + 1 + SIGNATURE_SIZE:
        raise BlobError("blob is too short")
    ciphertext = blob[:-SIGNATURE_SIZE]
    signature = blob[-SIGNATURE_SIZE:]
    payload = _xor(ciphertext, _keystream(signature[:32], len(ciphertext)))
    if not verify_message(signature, payload, public_key):
        raise BlobError("invalid signature")
    if len(payload) < 5:
        raise BlobError("payload is too short")
    timestamp = int.from_bytes(payload[:4], "little")
    dict_id = payload[4]
    if dict_id != dictionary.dict_id:
        raise BlobError(
            f"dictionary mismatch (blob {dict_id:02x}, local {dictionary.dict_id:02x})"
        )
    try:
        text = dictionary.decode(payload[5:])
    except CompressionError as exc:
        raise BlobError(f"cannot decompress: {exc}") from exc
    return text, timestamp


def load_private_key(path: str | Path) -> bytes:
    return parse_hex(Path(path).read_text(encoding="utf-8"), PRIVATE_KEY_SIZE)


def load_public_key(path: str | Path) -> bytes:
    return parse_hex(Path(path).read_text(encoding="utf-8"), PUBLIC_KEY_SIZE)


def write_key_files(
    prefix: str | Path, private_key: bytes, public_key: bytes, force: bool = False
) -> tuple[Path, Path]:
    private_path = Path(f"{prefix}.priv")
    public_path = Path(f"{prefix}.pub")
    if not force:
        for path in (private_path, public_path):
            if path.exists():
                raise FileExistsError(f"{path} already exists (use --force)")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_text(private_key.hex() + "\n", encoding="ascii")
    os.chmod(private_path, 0o600)
    public_path.write_text(public_key.hex() + "\n", encoding="ascii")
    return private_path, public_path


def default_dictionary_path() -> Path:
    env = os.environ.get("ED25519_SIGNER_DICTIONARY")
    if env:
        return Path(env)
    cwd = Path.cwd() / DICTIONARY_NAME
    if cwd.is_file():
        return cwd
    local = Path(__file__).resolve().parent / DICTIONARY_NAME
    if local.is_file():
        return local
    raise FileNotFoundError(f"{DICTIONARY_NAME} not found; pass --dictionary")


def _read_input(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    return Path(path).read_bytes()


def _read_message(path: str, fmt: str) -> bytes:
    data = _read_input(path)
    return decode_hex(data) if fmt == "hex" else data


def _write_blob(path: str, blob: bytes, fmt: str) -> None:
    data = blob.hex().encode("ascii") + b"\n" if fmt == "hex" else blob
    if path == "-":
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        Path(path).write_bytes(data)


def _write_text(path: str, text: bytes) -> None:
    if text and not text.endswith(b"\n"):
        text += b"\n"
    if path == "-":
        sys.stdout.buffer.write(text)
        sys.stdout.buffer.flush()
    else:
        Path(path).write_bytes(text)


def cmd_keygen(args: argparse.Namespace) -> int:
    private_key, public_key = generate_keypair()
    print(f"private_key: {private_key.hex()}")
    print(f"public_key: {public_key.hex()}")
    if args.out:
        private_path, public_path = write_key_files(
            args.out, private_key, public_key, args.force
        )
        print(f"wrote {private_path} and {public_path}", file=sys.stderr)
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    dictionary = Dictionary.load(args.dictionary or default_dictionary_path())
    private_key = load_private_key(args.key)
    public_key = derive_public_key(private_key)
    message = _read_message(args.input, args.format)
    timestamp = (
        int(time.time()) & 0xFFFFFFFF if args.timestamp is None else args.timestamp
    )
    blob = build_blob(message, private_key, public_key, dictionary, timestamp)
    if args.max_size and len(blob) > args.max_size:
        raise ValueError(f"blob is {len(blob)} bytes, limit is {args.max_size}")
    _write_blob(args.out, blob, args.out_format)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    dictionary = Dictionary.load(args.dictionary or default_dictionary_path())
    public_key = load_public_key(args.pub)
    blob = _read_message(args.input, args.format)
    text, timestamp = open_blob(blob, public_key, dictionary)
    if args.max_age is not None:
        now = int(time.time()) & 0xFFFFFFFF
        age = now - timestamp
        if age > args.max_age or age < -300:
            raise BlobError(f"timestamp outside allowed window (age {age}s)")
    _write_text(args.out, text)
    if args.show_timestamp:
        print(f"timestamp: {timestamp}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ed25519-signer",
        description="MeshCore-compatible Ed25519 signer with a compact command dictionary.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    keygen = sub.add_parser("keygen", help="generate a MeshCore-compatible keypair")
    keygen.add_argument("--out", metavar="PREFIX", help="write PREFIX.priv and PREFIX.pub")
    keygen.add_argument("--force", action="store_true", help="overwrite existing key files")
    keygen.set_defaults(func=cmd_keygen)

    sign = sub.add_parser("sign", help="compress, timestamp, and sign text")
    sign.add_argument("--key", required=True, metavar="FILE", help="private key file")
    sign.add_argument("--in", dest="input", default="-", metavar="FILE", help="input text or hex (default: stdin)")
    sign.add_argument("--format", choices=("bin", "hex"), default="bin", help="input format")
    sign.add_argument("--out", default="-", metavar="FILE", help="output blob (default: stdout)")
    sign.add_argument("--out-format", choices=("bin", "hex"), default="hex", help="output format")
    sign.add_argument("--timestamp", type=int, help="Unix UTC seconds (default: now)")
    sign.add_argument("--max-size", type=int, default=MAX_BLOB_SIZE, help="maximum blob size, 0 disables")
    sign.add_argument("--dictionary", metavar="FILE", help="dictionary file")
    sign.set_defaults(func=cmd_sign)

    verify = sub.add_parser("verify", help="verify a blob and decompress its text")
    verify.add_argument("--pub", required=True, metavar="FILE", help="public key file")
    verify.add_argument("--in", dest="input", default="-", metavar="FILE", help="blob or hex (default: stdin)")
    verify.add_argument("--format", choices=("bin", "hex"), default="bin", help="input format")
    verify.add_argument("--out", default="-", metavar="FILE", help="output text (default: stdout)")
    verify.add_argument("--max-age", type=int, help="maximum allowed age in seconds")
    verify.add_argument("--show-timestamp", action="store_true", help="print timestamp to stderr")
    verify.add_argument("--dictionary", metavar="FILE", help="dictionary file")
    verify.set_defaults(func=cmd_verify)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BlobError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (SignerError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
