"""Tests for the encrypted keystore and CLI argument handling."""

from __future__ import annotations

import tempfile
import unittest
import contextlib
import io
import os
from pathlib import Path
from unittest.mock import patch

from cryptography import x509

from keystore import (
    StoreCorruptedError,
    StorePasswordError,
    load_store,
    save_store,
    validate_alias,
)
from mykeytool import main


class KeystoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.store_path = Path(self.temporary_directory.name) / "store.pystore"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_round_trip_and_wrong_password(self) -> None:
        contents = {"aliases": {"demo": {"subject": [["CN", "Example"]]}}}
        save_store(self.store_path, "correct-password", contents)

        self.assertEqual(load_store(self.store_path, "correct-password"), contents)
        with self.assertRaises(StorePasswordError):
            load_store(self.store_path, "wrong-password")

    def test_missing_and_malformed_store_are_reported(self) -> None:
        with self.assertRaises(StoreCorruptedError):
            load_store(self.store_path, "correct-password")

        self.store_path.write_text("not-json", encoding="utf-8")
        with self.assertRaises(StoreCorruptedError):
            load_store(self.store_path, "correct-password")

    def test_alias_rejects_path_separators(self) -> None:
        self.assertEqual(validate_alias("team-key_1"), "team-key_1")
        with self.assertRaises(ValueError):
            validate_alias("../outside")

    def test_genkey_allows_empty_optional_distinguished_name_fields(self) -> None:
        answers = [
            "demo",
            "Example CN",
            "",
            "",
            "",
            "",
            "",
        ]
        passwords = ["store-password", "store-password", "alias-password", "alias-password"]
        with patch("builtins.input", side_effect=answers), patch("getpass.getpass", side_effect=passwords):
            self.assertEqual(main(["--genkey", "--store", str(self.store_path)]), 0)

        contents = load_store(self.store_path, "store-password")
        self.assertEqual(contents["aliases"]["demo"]["subject"], [["CN", "Example CN"]])

    def test_genkey_rejects_duplicate_alias(self) -> None:
        answers = ["demo", "Example CN", "Unit", "Example Org", "Madrid", "Madrid", "ES"]
        passwords = ["store-password", "store-password", "alias-password", "alias-password"]
        with patch("builtins.input", side_effect=answers), patch("getpass.getpass", side_effect=passwords):
            self.assertEqual(main(["--genkey", "--store", str(self.store_path)]), 0)

        with patch("builtins.input", return_value="demo"), patch(
            "getpass.getpass", return_value="store-password"
        ), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--genkey", "--store", str(self.store_path)]), 1)

    def test_genkey_and_certreq_create_valid_rsa_csr(self) -> None:
        answers = ["demo", "Example CN", "Unit", "Example Org", "Madrid", "Madrid", "ES"]
        passwords = ["store-password", "store-password", "alias-password", "alias-password"]
        original_directory = Path.cwd()
        os.chdir(self.temporary_directory.name)
        try:
            with patch("builtins.input", side_effect=answers), patch("getpass.getpass", side_effect=passwords):
                self.assertEqual(main(["--genkey", "--store", str(self.store_path)]), 0)

            with patch("builtins.input", return_value="demo"), patch(
                "getpass.getpass", side_effect=["store-password", "alias-password"]
            ):
                self.assertEqual(main(["--certreq", "--store", str(self.store_path)]), 0)

            request = x509.load_pem_x509_csr(Path("demo.csr").read_bytes())
            self.assertEqual(request.public_key().key_size, 2048)
            self.assertEqual(
                request.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
                "Example CN",
            )
            self.assertNotIn(b"PRIVATE KEY", self.store_path.read_bytes())
            Path("demo.csr").unlink()
            with patch("builtins.input", return_value="demo"), patch(
                "getpass.getpass", side_effect=["store-password", "wrong-password"]
            ), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--certreq", "--store", str(self.store_path)]), 1)
            self.assertFalse(Path("demo.csr").exists())
        finally:
            os.chdir(original_directory)


if __name__ == "__main__":
    unittest.main()