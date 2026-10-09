from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from bagoeswp.models import SiteSpec
from bagoeswp.validation import ValidationError, normalize_domain, read_sites_csv, validate_sites


class ValidationTests(unittest.TestCase):
    def test_normalizes_scheme_www_and_path(self) -> None:
        self.assertEqual(normalize_domain("HTTPS://WWW.Example.COM/path"), "example.com")

    def test_rejects_duplicate_domains(self) -> None:
        sites = [
            SiteSpec("example.com", "A", "admin", "a@example.com", "abcdefghijkl"),
            SiteSpec("www.example.com", "B", "admin", "b@example.com", "abcdefghijkl"),
        ]
        with self.assertRaises(ValidationError):
            validate_sites(sites)

    def test_csv_keeps_password_as_text(self) -> None:
        content = (
            "domain,title,admin_user,admin_email,admin_password,locale,ssl,www\n"
            "example.com,Title,admin,admin@example.com,001234567890,en_US,true,true\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sites.csv"
            path.write_text(content, encoding="utf-8")
            sites = read_sites_csv(path)
        self.assertEqual(sites[0].admin_password, "001234567890")

    def test_validated_fields_match_remote_payload_without_changing_password(self) -> None:
        site = SiteSpec(" example.com ", " Title ", " admin ", " a@example.com ", " password with spaces ", " en_US ")
        checked = validate_sites([site])[0]
        self.assertEqual(checked.admin_user, "admin")
        self.assertEqual(checked.admin_email, "a@example.com")
        self.assertEqual(checked.locale, "en_US")
        self.assertEqual(checked.title, "Title")
        self.assertEqual(checked.admin_password, " password with spaces ")


if __name__ == "__main__":
    unittest.main()

