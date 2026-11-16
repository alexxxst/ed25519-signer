import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ed25519_signer as signer

DICTIONARY = ROOT / "dictionary.txt"

MESHCORE_PRIVATE = bytes.fromhex(
    "7065e18fd9fabb70c1ed90dca19907de698c88b709ea146eafd93d9b830c7b60"
    "c4681193c79bbc39945ba8064104bb618f8fd7a84a0af6f57033d6e8ddcd6471"
)
MESHCORE_PUBLIC = bytes.fromhex(
    "1ec77175b0918ed206f9ae04ec136d6d5d4315bb26305427f645b492e9350c10"
)
MESHCORE_MESSAGE = b"meshcore-test-vector"
MESHCORE_SIGNATURE = bytes.fromhex(
    "6fe52b003b2ea749663bf50f6476bf2e495634e2c54f3af38ddb518c59c75dd1"
    "aa25ae4f740422e9e2941380cab400057e6f53cab411db076381f3b6fbf7aa08"
)
# Cross-checked with a C program using MeshCore's lib/ed25519 and SHA-512,
# for the fixed 3-token dictionary below.
GOLDEN_BLOB = bytes.fromhex(
    "14f2cebc2ee880c9c3c9802fc0694a9d57184392dffad6f63964bccb4dd0f303"
    "dd34e09f6fcb028f213bb1993d24f63d28a546060765c0cc6e98a5a3e93c32bb"
    "e0d8901cdfa2235a0a"
)


def run_cli(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = ""
    return subprocess.run(
        [sys.executable, str(ROOT / "ed25519_signer.py"), *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
    )


class KeyTests(unittest.TestCase):
    def test_meshcore_public_key(self):
        self.assertEqual(
            signer.derive_public_key(MESHCORE_PRIVATE).hex(), MESHCORE_PUBLIC.hex()
        )

    def test_meshcore_signature_vector(self):
        signature = signer.sign_message(
            MESHCORE_MESSAGE, MESHCORE_PRIVATE, MESHCORE_PUBLIC
        )
        self.assertEqual(signature, MESHCORE_SIGNATURE)
        self.assertTrue(
            signer.verify_message(signature, MESHCORE_MESSAGE, MESHCORE_PUBLIC)
        )

    def test_keypair_roundtrip(self):
        private_key, public_key = signer.generate_keypair()
        self.assertEqual(len(private_key), 64)
        self.assertEqual(len(public_key), 32)
        self.assertEqual(signer.derive_public_key(private_key), public_key)
        message = b"get name"
        signature = signer.sign_message(message, private_key, public_key)
        self.assertTrue(signer.verify_message(signature, message, public_key))
        self.assertFalse(signer.verify_message(signature, b"get role", public_key))

    def test_seed_is_deterministic(self):
        first = signer.keypair_from_seed(bytes(range(32)))
        second = signer.keypair_from_seed(bytes(range(32)))
        self.assertEqual(first, second)

    def test_keygen_skips_meshcore_rejected_prefix(self):
        bad_seed = bytes.fromhex(
            "6301000000000000000000000000000000000000000000000000000000000000"
        )
        good_seed = bytes(32)
        self.assertEqual(signer.keypair_from_seed(bad_seed)[1][0], 0)
        with mock.patch(
            "ed25519_signer.secrets.token_bytes",
            side_effect=[bad_seed, good_seed],
        ):
            private_key, public_key = signer.generate_keypair()
        self.assertEqual((private_key, public_key), signer.keypair_from_seed(good_seed))
        self.assertNotIn(public_key[0], (0x00, 0xFF))


class DictionaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dictionary = signer.Dictionary.load(DICTIONARY)

    def test_dictionary_loads(self):
        self.assertLessEqual(len(self.dictionary.tokens), 254)
        self.assertGreaterEqual(self.dictionary.dict_id, 0)
        self.assertLessEqual(self.dictionary.dict_id, 0xFFFF)
        self.assertEqual(len(set(self.dictionary.tokens)), len(self.dictionary.tokens))

    def test_roundtrip(self):
        samples = [
            b"",
            b"get name",
            b"set radio 869.618,62.5,8,5",
            b"set prv.key " + b"a" * 128,
            b"BLACKLIST PATH ADD 1A2B3C4D",
            bytes(range(256)) * 2,
            b"x" * 1000,
        ]
        for sample in samples:
            encoded = self.dictionary.encode(sample)
            self.assertEqual(self.dictionary.decode(encoded), sample, sample[:40])

    def test_commands_get_smaller(self):
        self.assertLess(
            len(self.dictionary.encode(b"blacklist chan add 81")),
            len(b"blacklist chan add 81"),
        )
        self.assertLess(
            len(self.dictionary.encode(b"set radio 868.856,62.5,7,7")),
            len(b"set radio 868.856,62.5,7,7"),
        )

    def test_long_hex_gets_smaller(self):
        text = b"set prv.key " + b"a" * 128
        self.assertLess(len(self.dictionary.encode(text)), len(text))

    def test_hex_runs_above_255(self):
        for length in (255, 256, 510):
            text = b"a" * length
            encoded = self.dictionary.encode(text)
            self.assertEqual(self.dictionary.decode(encoded), text)

    def test_duplicate_token_rejected(self):
        with self.assertRaises(signer.DictionaryError):
            signer.Dictionary([b"a", b"a"])

    def test_token_limit(self):
        signer.Dictionary([bytes([i]) for i in range(1, 255)])
        with self.assertRaises(signer.DictionaryError):
            signer.Dictionary([bytes([i]) for i in range(1, 256)])

    def test_bad_escape_rejected(self):
        with self.assertRaises(signer.DictionaryError):
            signer._unescape("\\q")

    def test_dict_id_changes_with_tokens(self):
        changed = signer.Dictionary(self.dictionary.tokens[:-1] + (b"zzz",))
        self.assertNotEqual(self.dictionary.dict_id, changed.dict_id)


class BlobTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dictionary = signer.Dictionary.load(DICTIONARY)
        cls.private_key, cls.public_key = signer.keypair_from_seed(bytes(range(32)))

    def make_blob(self, text=b"get name", timestamp=1700000000):
        return signer.build_blob(
            text, self.private_key, self.public_key, self.dictionary, timestamp
        )

    def test_roundtrip(self):
        blob = self.make_blob()
        self.assertLessEqual(len(blob), 160)
        text, timestamp = signer.open_blob(blob, self.public_key, self.dictionary)
        self.assertEqual(text, b"get name")
        self.assertEqual(timestamp, 1700000000)

    def test_deterministic_for_same_timestamp(self):
        self.assertEqual(self.make_blob(), self.make_blob())

    def test_different_timestamp_changes_blob(self):
        self.assertNotEqual(self.make_blob(), self.make_blob(timestamp=1700000001))

    def test_tampered_ciphertext_fails(self):
        blob = bytearray(self.make_blob())
        blob[0] ^= 1
        with self.assertRaises(signer.BlobError):
            signer.open_blob(bytes(blob), self.public_key, self.dictionary)

    def test_tampered_signature_fails(self):
        blob = bytearray(self.make_blob())
        blob[-1] ^= 1
        with self.assertRaises(signer.BlobError):
            signer.open_blob(bytes(blob), self.public_key, self.dictionary)

    def test_short_blob_fails(self):
        with self.assertRaises(signer.BlobError):
            signer.open_blob(b"short", self.public_key, self.dictionary)

    def test_dictionary_mismatch_fails(self):
        other = signer.Dictionary(self.dictionary.tokens[:-1] + (b"zzz",))
        blob = self.make_blob()
        with self.assertRaises(signer.BlobError):
            signer.open_blob(blob, self.public_key, other)

    def test_long_text_exceeds_packet(self):
        blob = self.make_blob(b"A" * 200)
        self.assertGreater(len(blob), 160)

    def test_open_blob_rejects_oversize_by_default(self):
        blob = self.make_blob(b"A" * 200)
        with self.assertRaises(signer.BlobError):
            signer.open_blob(blob, self.public_key, self.dictionary)
        text, timestamp = signer.open_blob(
            blob, self.public_key, self.dictionary, max_size=0
        )
        self.assertEqual(text, b"A" * 200)
        self.assertEqual(timestamp, 1700000000)

    def test_golden_blob(self):
        dictionary = signer.Dictionary([b"get", b" ", b"name"])
        blob = signer.build_blob(
            b"get name",
            MESHCORE_PRIVATE,
            MESHCORE_PUBLIC,
            dictionary,
            1700000000,
        )
        self.assertEqual(blob, GOLDEN_BLOB)
        self.assertEqual(
            signer.open_blob(blob, MESHCORE_PUBLIC, dictionary),
            (b"get name", 1700000000),
        )

    def test_empty_text(self):
        blob = self.make_blob(b"")
        self.assertEqual(len(blob), 70)
        self.assertEqual(
            signer.open_blob(blob, self.public_key, self.dictionary),
            (b"", 1700000000),
        )


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.prefix = self.dir / "identity"

    def keygen(self):
        result = run_cli("keygen", "--out", str(self.prefix))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return Path(f"{self.prefix}.priv"), Path(f"{self.prefix}.pub")

    def test_keygen_writes_files(self):
        private_path, public_path = self.keygen()
        self.assertTrue(private_path.is_file())
        self.assertTrue(public_path.is_file())
        self.assertEqual(len(signer.load_private_key(private_path)), 64)
        self.assertEqual(len(signer.load_public_key(public_path)), 32)
        self.assertEqual(stat.S_IMODE(private_path.stat().st_mode), 0o600)

    def test_sign_verify_binary(self):
        private_path, public_path = self.keygen()
        command = self.dir / "command.txt"
        command.write_bytes(b"get name\n")
        blob_path = self.dir / "blob.bin"
        result = run_cli(
            "sign",
            "--key",
            str(private_path),
            "--in",
            str(command),
            "--format",
            "bin",
            "--out",
            str(blob_path),
            "--out-format",
            "bin",
            "--timestamp",
            "1700000000",
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertLessEqual(blob_path.stat().st_size, 160)
        result = run_cli(
            "verify",
            "--pub",
            str(public_path),
            "--in",
            str(blob_path),
            "--format",
            "bin",
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"get name\n")

    def test_sign_verify_hex(self):
        private_path, public_path = self.keygen()
        command = self.dir / "command.txt"
        command.write_bytes(b"get name")
        blob_path = self.dir / "blob.hex"
        result = run_cli(
            "sign",
            "--key",
            str(private_path),
            "--in",
            str(command),
            "--out",
            str(blob_path),
            "--out-format",
            "hex",
            "--timestamp",
            "1700000000",
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue(blob_path.read_text().strip())
        result = run_cli(
            "verify",
            "--pub",
            str(public_path),
            "--in",
            str(blob_path),
            "--format",
            "hex",
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"get name")

    def test_sign_verify_defaults(self):
        private_path, public_path = self.keygen()
        command = self.dir / "command.txt"
        command.write_bytes(b"get name")
        blob_path = self.dir / "blob.hex"
        result = run_cli(
            "sign",
            "--key",
            str(private_path),
            "--in",
            str(command),
            "--out",
            str(blob_path),
            "--timestamp",
            "1700000000",
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        result = run_cli(
            "verify",
            "--pub",
            str(public_path),
            "--in",
            str(blob_path),
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"get name")

    def test_verify_output_is_exact(self):
        private_path, public_path = self.keygen()
        command = self.dir / "command.txt"
        command.write_bytes(b"get name")
        blob_path = self.dir / "blob.bin"
        text_path = self.dir / "text.out"
        result = run_cli(
            "sign",
            "--key",
            str(private_path),
            "--in",
            str(command),
            "--out",
            str(blob_path),
            "--out-format",
            "bin",
            "--timestamp",
            "1700000000",
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        result = run_cli(
            "verify",
            "--pub",
            str(public_path),
            "--in",
            str(blob_path),
            "--format",
            "bin",
            "--out",
            str(text_path),
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(text_path.read_bytes(), b"get name")

    def test_verify_rejects_oversize_blob(self):
        private_path, public_path = self.keygen()
        command = self.dir / "command.txt"
        command.write_bytes(b"A" * 200)
        blob_path = self.dir / "blob.bin"
        result = run_cli(
            "sign",
            "--key",
            str(private_path),
            "--in",
            str(command),
            "--out",
            str(blob_path),
            "--out-format",
            "bin",
            "--max-size",
            "0",
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertGreater(blob_path.stat().st_size, 160)
        result = run_cli(
            "verify",
            "--pub",
            str(public_path),
            "--in",
            str(blob_path),
            "--format",
            "bin",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"limit", result.stderr)
        result = run_cli(
            "verify",
            "--pub",
            str(public_path),
            "--in",
            str(blob_path),
            "--format",
            "bin",
            "--max-size",
            "0",
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"A" * 200)

    def test_malformed_hex_input(self):
        private_path, _ = self.keygen()
        command = self.dir / "command.txt"
        command.write_bytes(b"abc")
        result = run_cli(
            "sign",
            "--key",
            str(private_path),
            "--in",
            str(command),
            "--format",
            "hex",
            "--out",
            str(self.dir / "blob.bin"),
            "--out-format",
            "bin",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"hex", result.stderr)

    def test_invalid_timestamp(self):
        private_path, _ = self.keygen()
        command = self.dir / "command.txt"
        command.write_bytes(b"get name")
        for timestamp in ("-1", "4294967296"):
            result = run_cli(
                "sign",
                "--key",
                str(private_path),
                "--in",
                str(command),
                "--out",
                str(self.dir / "blob.bin"),
                "--out-format",
                "bin",
                "--timestamp",
                timestamp,
            )
            self.assertEqual(result.returncode, 2)

    def test_max_age(self):
        private_path, public_path = self.keygen()
        command = self.dir / "command.txt"
        command.write_bytes(b"get name")
        blob_path = self.dir / "blob.bin"
        result = run_cli(
            "sign",
            "--key",
            str(private_path),
            "--in",
            str(command),
            "--out",
            str(blob_path),
            "--out-format",
            "bin",
            "--timestamp",
            "1700000000",
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        result = run_cli(
            "verify",
            "--pub",
            str(public_path),
            "--in",
            str(blob_path),
            "--format",
            "bin",
            "--max-age",
            "0",
        )
        self.assertEqual(result.returncode, 1)
        result = run_cli(
            "verify",
            "--pub",
            str(public_path),
            "--in",
            str(blob_path),
            "--format",
            "bin",
            "--max-age",
            "999999999",
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_verify_rejects_tampering(self):
        private_path, public_path = self.keygen()
        command = self.dir / "command.txt"
        command.write_bytes(b"get name")
        blob_path = self.dir / "blob.bin"
        result = run_cli(
            "sign",
            "--key",
            str(private_path),
            "--in",
            str(command),
            "--out",
            str(blob_path),
            "--out-format",
            "bin",
            "--timestamp",
            "1700000000",
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        blob = bytearray(blob_path.read_bytes())
        blob[0] ^= 1
        blob_path.write_bytes(blob)
        result = run_cli(
            "verify",
            "--pub",
            str(public_path),
            "--in",
            str(blob_path),
            "--format",
            "bin",
        )
        self.assertEqual(result.returncode, 1)

    def test_max_size(self):
        private_path, _ = self.keygen()
        command = self.dir / "command.txt"
        command.write_bytes(b"A" * 200)
        result = run_cli(
            "sign",
            "--key",
            str(private_path),
            "--in",
            str(command),
            "--out",
            str(self.dir / "blob.bin"),
            "--out-format",
            "bin",
            "--max-size",
            "160",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"limit", result.stderr)

    def test_keygen_prints_keys(self):
        result = run_cli("keygen")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        lines = result.stdout.decode().splitlines()
        self.assertTrue(lines[0].startswith("private_key: "))
        self.assertTrue(lines[1].startswith("public_key: "))
        self.assertEqual(len(lines[0].split(": ", 1)[1]), 128)
        self.assertEqual(len(lines[1].split(": ", 1)[1]), 64)


if __name__ == "__main__":
    unittest.main()
