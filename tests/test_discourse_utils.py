#!/usr/bin/env python3
"""
Unit tests for discourse_utils.py
"""

import unittest
from unittest.mock import patch, MagicMock
from discoursemap.lib.discourse_utils import is_discourse_site, validate_url, clean_url

class TestDiscourseUtils(unittest.TestCase):

    def test_clean_url(self):
        self.assertEqual(clean_url("example.com"), "https://example.com")
        self.assertEqual(clean_url("http://example.com/"), "http://example.com")
        self.assertEqual(clean_url("https://example.com/path/"), "https://example.com/path")
        self.assertEqual(clean_url(""), "")

    def test_validate_url(self):
        self.assertTrue(validate_url("https://example.com"))
        self.assertTrue(validate_url("http://example.com"))
        self.assertFalse(validate_url("not_a_url"))
        self.assertFalse(validate_url("ftp://example.com")) # Scheme handled by urlparse but let's see usage
        # Actually validate_url checks scheme and netloc. "ftp" has scheme.
        # Let's check implementation: "all([result.scheme, result.netloc])"
        self.assertFalse(validate_url("ftp://example.com")) 

    @patch('requests.get')
    def test_is_discourse_site_header(self, mock_get):
        # Setup mock response
        mock_response = MagicMock()
        mock_response.headers = {'X-Generator': 'Discourse 2.8.0'}
        mock_response.text = '<html></html>'
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        self.assertTrue(is_discourse_site("https://example.com"))

    @patch('requests.get')
    def test_is_discourse_site_content(self, mock_get):
        # Setup mock response
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.text = '<html><script>Discourse.start();</script></html>'
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        self.assertTrue(is_discourse_site("https://example.com"))

    @patch('requests.get')
    def test_is_discourse_site_negative(self, mock_get):
        # Setup mock response
        mock_response = MagicMock()
        mock_response.headers = {'Server': 'Nginx'}
        mock_response.text = '<html>WordPress</html>'
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        self.assertFalse(is_discourse_site("https://example.com"))

    @patch('requests.get')
    def test_is_discourse_site_with_kwargs(self, mock_get):
        """Test that extra kwargs don't cause a crash (Fix for Issue #47)"""
        mock_response = MagicMock()
        mock_response.headers = {'X-Generator': 'Discourse'}
        mock_get.return_value = mock_response

        # This call should not raise TypeError
        result = is_discourse_site("https://example.com", timeout=5, custom_arg="test")
        self.assertTrue(result)
        
        # Verify mock called with kwargs
        mock_get.assert_called_with("https://example.com", timeout=5, verify=False, custom_arg="test")

if __name__ == '__main__':
    unittest.main()
