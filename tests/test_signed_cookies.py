from unittest import TestCase

from cognito_code_grant.signed_cookies import get_domain_from_header


class FetchKeysTestCase(TestCase):
    def test_gets_url_properly(self):
        self.assertEqual(get_domain_from_header('http://test.me.com'), '.me.com')

    def test_gets_url_properly_no_http(self):
        self.assertEqual(get_domain_from_header('test.me.com'), '.me.com')