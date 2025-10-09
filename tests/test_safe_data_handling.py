import unittest
from lockbox.utils import _safe_decode_text_data


class TestSafeDataHandling(unittest.TestCase):
    def test_empty_data(self):
        """Test that empty data is handled correctly."""
        decoded, is_text = _safe_decode_text_data(b"")
        self.assertEqual(decoded, "")
        self.assertTrue(is_text)

    def test_text_data(self):
        """Test that valid UTF-8 text is decoded correctly."""
        text_data = "Hello, world! 你好世界"
        decoded, is_text = _safe_decode_text_data(text_data.encode("utf-8"))
        self.assertEqual(decoded, text_data)
        self.assertTrue(is_text)

    def test_binary_data(self):
        """Test that binary data is handled safely."""
        binary_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        decoded, is_text = _safe_decode_text_data(binary_data)
        self.assertEqual(decoded, "")
        self.assertFalse(is_text)

    def test_mixed_data(self):
        """Test various types of data."""
        test_cases = [
            (b"", ("", True)),  # Empty data
            (b"simple text", ("simple text", True)),  # Valid UTF-8
            (b"\x00\x01\x02\x03", ("\x00\x01\x02\x03", True)),  # Valid UTF-8 with null bytes
            (b"text with \x00 null", ("text with \x00 null", True)),  # Valid UTF-8 with null bytes
            ("valid utf8: café".encode("utf-8"), ("valid utf8: café", True)),  # Valid UTF-8 with accents
            (b"\xff\xfe\xfd", ("", False)),  # Invalid UTF-8 sequence
        ]
        
        for input_data, (expected_decoded, expected_is_text) in test_cases:
            with self.subTest(data=input_data):
                decoded, is_text = _safe_decode_text_data(input_data)
                self.assertEqual(decoded, expected_decoded)
                self.assertEqual(is_text, expected_is_text)


if __name__ == "__main__":
    unittest.main()
