import unittest
from pydantic import ValidationError

from lockbox.config import ServiceConfig


class TestBaseUrlValidation(unittest.TestCase):
    """Test base_url validation and normalization in ServiceConfig."""

    def test_url_with_https_scheme(self):
        """URLs with https:// should be accepted as-is."""
        config = ServiceConfig(base_url="https://api.github.com")
        self.assertEqual(config.base_url, "https://api.github.com")

    def test_url_with_http_scheme(self):
        """URLs with http:// should be accepted (with warning)."""
        config = ServiceConfig(base_url="http://localhost:8000")
        self.assertEqual(config.base_url, "http://localhost:8000")

    def test_url_without_scheme_defaults_to_https(self):
        """URLs without scheme should default to https://."""
        config = ServiceConfig(base_url="api.github.com")
        self.assertEqual(config.base_url, "https://api.github.com")

    def test_url_with_trailing_slash_stripped(self):
        """Trailing slashes should be stripped."""
        config = ServiceConfig(base_url="https://api.github.com/")
        self.assertEqual(config.base_url, "https://api.github.com")

        config = ServiceConfig(base_url="api.github.com/")
        self.assertEqual(config.base_url, "https://api.github.com")

    def test_url_with_multiple_trailing_slashes_stripped(self):
        """Multiple trailing slashes should be stripped."""
        config = ServiceConfig(base_url="https://api.github.com///")
        self.assertEqual(config.base_url, "https://api.github.com")

    def test_url_with_port(self):
        """URLs with ports should be handled correctly."""
        config = ServiceConfig(base_url="https://api.example.com:8443")
        self.assertEqual(config.base_url, "https://api.example.com:8443")

        config = ServiceConfig(base_url="api.example.com:8443")
        self.assertEqual(config.base_url, "https://api.example.com:8443")

    def test_url_with_path_preserved(self):
        """URLs with paths should preserve the path."""
        config = ServiceConfig(base_url="https://api.example.com/v1")
        self.assertEqual(config.base_url, "https://api.example.com/v1")

        config = ServiceConfig(base_url="api.example.com/v1")
        self.assertEqual(config.base_url, "https://api.example.com/v1")

    def test_localhost_urls(self):
        """localhost URLs should work correctly."""
        config = ServiceConfig(base_url="http://localhost:8000")
        self.assertEqual(config.base_url, "http://localhost:8000")

        config = ServiceConfig(base_url="localhost:8000")
        self.assertEqual(config.base_url, "https://localhost:8000")

    def test_ip_address_urls(self):
        """IP address URLs should work correctly."""
        config = ServiceConfig(base_url="http://127.0.0.1:8000")
        self.assertEqual(config.base_url, "http://127.0.0.1:8000")

        config = ServiceConfig(base_url="192.168.1.100:8000")
        self.assertEqual(config.base_url, "https://192.168.1.100:8000")

    def test_invalid_scheme_raises_error(self):
        """Invalid URL schemes should raise ValidationError."""
        with self.assertRaises(ValidationError) as ctx:
            ServiceConfig(base_url="ftp://example.com")

        self.assertIn("Invalid URL scheme 'ftp'", str(ctx.exception))
        self.assertIn("Only 'http' and 'https' are supported", str(ctx.exception))

    def test_empty_url_raises_error(self):
        """Empty URL should raise ValidationError."""
        with self.assertRaises(ValidationError):
            ServiceConfig(base_url="")

    def test_url_with_just_scheme_raises_error(self):
        """URL with just scheme (no domain) should raise ValidationError."""
        with self.assertRaises(ValidationError) as ctx:
            ServiceConfig(base_url="https://")

        self.assertIn("missing domain name", str(ctx.exception))

    def test_complex_url_with_auth_and_query(self):
        """Complex URLs with auth and query params should work."""
        config = ServiceConfig(
            base_url="https://user:pass@api.example.com:8443/v1/path"
        )
        self.assertEqual(
            config.base_url, "https://user:pass@api.example.com:8443/v1/path"
        )


if __name__ == "__main__":
    unittest.main()
