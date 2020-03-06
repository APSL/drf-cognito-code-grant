from unittest import TestCase
from unittest import mock

from cognito_code_grant.signed_cookies import get_domain_from_header
from cognito_code_grant.helpers import get_assets_v2_domain


class FetchKeysTestCase(TestCase):
    def test_gets_url_properly(self):
        self.assertEqual(get_domain_from_header('http://test.me.com'), '.me.com')

    def test_gets_url_properly_no_http(self):
        self.assertEqual(get_domain_from_header('test.me.com'), '.me.com')

    def test_get_assets_v2_url(self):
        request = mock.MagicMock()
        request.META = {
            'HTTP_HOST': 'boards.stitch.fashion',
        }
        self.assertEqual(get_assets_v2_domain(request), 'assets-v2.stitch.fashion')
        request.META = {
            'HTTP_HOST': 'boards.stitchdesignlab.com',
        }
        self.assertEqual(get_assets_v2_domain(request), 'assets-v2.stitchdesignlab.com')