import os
import tempfile
import unittest
from pathlib import Path

from lockbox.audit_log import _validate_and_sanitize_path


class TestPathValidationSimple(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for testing
        self.temp_dir = tempfile.mkdtemp()
        self.root_dir = os.path.join(self.temp_dir, "audit_logs")
        os.makedirs(self.root_dir, exist_ok=True)

    def tearDown(self):
        # Clean up the temporary directory
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_validate_service_name_valid(self):
        """Test that valid service names pass validation."""
        # Should not raise an exception
        _validate_and_sanitize_path(self.root_dir, "my_service", "dummy", "dummy")
        _validate_and_sanitize_path(self.root_dir, "service-123", "dummy", "dummy")
        _validate_and_sanitize_path(self.root_dir, "service_123", "dummy", "dummy")
        _validate_and_sanitize_path(self.root_dir, "服务_测试-123", "dummy", "dummy")

    def test_validate_service_name_invalid(self):
        """Test that invalid service names raise exceptions."""
        malicious_names = [
            "../../../etc/passwd",
            "/etc/passwd", 
            "service/../../../etc/passwd",
            "",
            None,
        ]
        
        for malicious_name in malicious_names:
            with self.subTest(service_name=malicious_name):
                with self.assertRaises(ValueError):
                    _validate_and_sanitize_path(self.root_dir, malicious_name, "dummy", "dummy")

    def test_valid_service_name(self):
        """Test that valid service names work correctly."""
        result = _validate_and_sanitize_path(
            self.root_dir, "my_service", "2024-01-15", "event.json"
        )
        # Check that the result is within the root directory
        result_path = Path(result).resolve()
        root_path = Path(self.root_dir).resolve()
        self.assertTrue(str(result_path).startswith(str(root_path)))
        self.assertIn("my_service", result)

    def test_path_traversal_prevention(self):
        """Test that path traversal attacks raise exceptions."""
        malicious_names = [
            "../../../etc/passwd",
            "/etc/passwd",
            "service/../../../etc/passwd",
        ]
        
        for malicious_name in malicious_names:
            with self.subTest(service_name=malicious_name):
                with self.assertRaises(ValueError) as context:
                    _validate_and_sanitize_path(
                        self.root_dir, malicious_name, "2024-01-15", "event.json"
                    )
                # Check that the error message mentions path traversal
                self.assertIn("path traversal", str(context.exception).lower())

    def test_unicode_service_name(self):
        """Test that Unicode service names work correctly."""
        unicode_name = "服务_测试-123"
        result = _validate_and_sanitize_path(
            self.root_dir, unicode_name, "2024-01-15", "event.json"
        )
        # Should work normally
        result_path = Path(result).resolve()
        root_path = Path(self.root_dir).resolve()
        self.assertTrue(str(result_path).startswith(str(root_path)))
        self.assertIn(unicode_name, result)

    def test_multiple_path_parts(self):
        """Test that multiple path parts are handled correctly."""
        result = _validate_and_sanitize_path(
            self.root_dir, "service", "year", "month", "day", "event.json"
        )
        result_path = Path(result).resolve()
        root_path = Path(self.root_dir).resolve()
        self.assertTrue(str(result_path).startswith(str(root_path)))
        self.assertIn("service", result)
        self.assertIn("year", result)
        self.assertIn("month", result)
        self.assertIn("day", result)


if __name__ == "__main__":
    unittest.main()
