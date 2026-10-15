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

    def test_genkeypair_and_keystore_flag_aliases(self) -> None:
        answers = ["webserver", "WebServer CN", "IT", "Company", "BCN", "BCN", "ES"]
        passwords = ["store-pass123", "store-pass123", "alias-pass123", "alias-pass123"]
        with patch("builtins.input", side_effect=answers), patch("getpass.getpass", side_effect=passwords):
            self.assertEqual(main(["--genkeypair", "--keystore", str(self.store_path)]), 0)

        contents = load_store(self.store_path, "store-pass123")
        self.assertIn("webserver", contents["aliases"])
        self.assertIn("certificate", contents["aliases"]["webserver"])
        self.assertIn("public_key", contents["aliases"]["webserver"])

    def test_list_and_exportcert_and_printcert(self) -> None:
        answers = ["srv1", "Server 1", "Dev", "Monlau", "Barcelona", "Barcelona", "ES"]
        passwords = ["keystore-pass", "keystore-pass", "alias-pass-ok", "alias-pass-ok"]
        with patch("builtins.input", side_effect=answers), patch("getpass.getpass", side_effect=passwords):
            self.assertEqual(main(["--genkeypair", "--store", str(self.store_path)]), 0)

        # Test --list
        stdout_buf = io.StringIO()
        with patch("getpass.getpass", return_value="keystore-pass"), contextlib.redirect_stdout(stdout_buf):
            self.assertEqual(main(["--list", "--store", str(self.store_path)]), 0)
        output = stdout_buf.getvalue()
        self.assertIn("srv1", output)
        self.assertIn("PrivateKeyEntry", output)
        self.assertIn("Huella digital SHA-256", output)

        # Test --exportcert
        cert_file = Path(self.temporary_directory.name) / "srv1.crt"
        with patch("getpass.getpass", return_value="keystore-pass"):
            self.assertEqual(
                main(["--exportcert", "--store", str(self.store_path), "--alias", "srv1", "--file", str(cert_file)]),
                0,
            )
        self.assertTrue(cert_file.exists())
        cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
        self.assertEqual(cert.public_key().key_size, 2048)

        # Test --printcert on the exported certificate
        stdout_buf = io.StringIO()
        with contextlib.redirect_stdout(stdout_buf):
            self.assertEqual(main(["--printcert", "--file", str(cert_file)]), 0)
        print_out = stdout_buf.getvalue()
        self.assertIn("Propietario", print_out)
        self.assertIn("Server 1", print_out)
        self.assertIn("SHA-256", print_out)

    def test_delete_alias(self) -> None:
        answers = ["demo-del", "Delete Me", "", "", "", "", ""]
        passwords = ["store-pass-del", "store-pass-del", "alias-pass-del", "alias-pass-del"]
        with patch("builtins.input", side_effect=answers), patch("getpass.getpass", side_effect=passwords):
            self.assertEqual(main(["--genkey", "--store", str(self.store_path)]), 0)

        # Test cancellation ('n')
        with patch("getpass.getpass", return_value="store-pass-del"), patch("builtins.input", return_value="n"):
            self.assertEqual(main(["--delete", "--store", str(self.store_path), "--alias", "demo-del"]), 0)
        contents = load_store(self.store_path, "store-pass-del")
        self.assertIn("demo-del", contents["aliases"])

        # Test confirmation ('s')
        with patch("getpass.getpass", return_value="store-pass-del"), patch("builtins.input", return_value="s"):
            self.assertEqual(main(["--delete", "--store", str(self.store_path), "--alias", "demo-del"]), 0)
        contents = load_store(self.store_path, "store-pass-del")
        self.assertNotIn("demo-del", contents["aliases"])


if __name__ == "__main__":
    unittest.main()