from rest_framework.test import APITestCase
from unittest import mock
from django.conf import settings
from requests.exceptions import HTTPError
from http.cookies import SimpleCookie
from requests import Response

class TestLogin(APITestCase):
    @mock.patch("cognito_code_grant.views.requests.post")
    def test_queries_cognito_with_recieved_code(self, requests_mock):
        mock_cognito_reply = mock.MagicMock()
        mock_cognito_reply.json.return_value = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'id_token': 'test_id_token',
        }
        requests_mock.return_value = mock_cognito_reply
        self.client.get('/auth/login/?code=testCode')

        requests_mock.assert_called_once_with(settings.AUTH_COGNITO_CODE_GRANT_URL, data={
            'grant_type': 'authorization_code',
            'code': 'testCode',
            'client_id': settings.AUTH_COGNITO_CLIENT_ID,
            'redirect_uri': 'https://testserver/auth/login/'
        })

    @mock.patch("cognito_code_grant.views.requests.post")
    def test_queries_sets_received_cookies_to_response(self, requests_mock):
        mock_cognito_reply = mock.MagicMock()
        mock_cognito_reply.json.return_value = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'id_token': 'test_id_token',
        }
        requests_mock.return_value = mock_cognito_reply

        response = self.client.get('/auth/login/?code=testCode')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session['access_token'], 'test_access_token')
        self.assertEqual(self.client.session['refresh_token'], 'test_refresh_token')
        self.assertEqual(self.client.session['id_token'], 'test_id_token')


    @mock.patch("cognito_code_grant.views.requests.post")
    def test_queries_sets_received_cookies_to_response_with_shared_cookies(self, requests_mock):
        mock_cognito_reply = mock.MagicMock()
        mock_cognito_reply.json.return_value = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'id_token': 'test_id_token',
        }
        settings.SHARED_TOKENS = True
        settings.SHARED_TOKENS_DOMAIN = '.test.com'

        requests_mock.return_value = mock_cognito_reply

        response = self.client.get('/auth/login/?code=testCode')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session['access_token'], 'test_access_token')
        self.assertEqual(self.client.session['refresh_token'], 'test_refresh_token')
        self.assertEqual(self.client.session['id_token'], 'test_id_token')
        self.assertEqual(response.client.cookies['access_token'].value, 'test_access_token')
        self.assertEqual(response.client.cookies['refresh_token'].value, 'test_refresh_token')
        self.assertEqual(response.client.cookies['id_token'].value, 'test_id_token')

    @mock.patch("cognito_code_grant.views.requests.post")
    def test_redirects_to_url_provided_in_state(self, requests_mock):
        mock_cognito_reply = mock.MagicMock()
        mock_cognito_reply.json.return_value = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'id_token': 'test_id_token',
        }
        requests_mock.return_value = mock_cognito_reply

        response = self.client.get('/auth/login/?code=testCode&state=https://example.com')

        self.assertRedirects(response, 'https://example.com', status_code=302, fetch_redirect_response=False)

    @mock.patch("cognito_code_grant.views.requests.post")
    def test_401_on_bad_request_from_cognito(self, requests_mock):
        mock_cognito_response = Response()
        mock_cognito_response.status_code = 401
        mock_cognito_response._content = 'Fake unauthorized response'
        mock_cognito_reply = mock.MagicMock()
        mock_cognito_reply.raise_for_status.side_effect = HTTPError('boom', response=mock_cognito_response)
        requests_mock.return_value = mock_cognito_reply

        response = self.client.get('/auth/login/?code=testCode&state=https://example.com')

        self.assertEqual(response.status_code, 401)


class TestLogout(APITestCase):
    @mock.patch("cognito_code_grant.views.requests.post")
    def test_redirects_to_url_provided_in_state(self, requests_mock):
        response = self.client.get('/auth/logout/?state=https://example.com')

        self.assertRedirects(response, 'https://example.com', status_code=302, fetch_redirect_response=False)

    @mock.patch("cognito_code_grant.views.requests.post")
    def test_removes_auth_cookies(self, requests_mock):
        session = self.client.session
        session['id_token'] = 'test'
        session.save()

        response = self.client.get('/auth/logout/?state=https://example.com')
        session = self.client.session

        self.assertNotIn('id_token', session)

    @mock.patch("cognito_code_grant.views.requests.post")
    def test_removes_auth_cookies_with_shared_tokens(self, requests_mock):
        session = self.client.session
        session['id_token'] = 'test'
        session.save()
        self.client.cookies = SimpleCookie({'id_token': 'test'})
        settings.SHARED_TOKENS = True
        settings.SHARED_TOKENS_DOMAIN = '.test.com'

        response = self.client.get('/auth/logout/?state=https://example.com')
        session = self.client.session

        self.assertNotIn('id_token', session)
        self.assertEqual('', response.client.cookies['id_token'].value)
