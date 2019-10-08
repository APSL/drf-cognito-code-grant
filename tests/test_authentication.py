import copy
from unittest import mock
from collections import defaultdict

import django
from django.conf import settings

django.setup()

from django.test import TestCase as DjangoTestCase
from django.contrib.auth.models import User, Group

from unittest import TestCase


from rest_framework import exceptions
from jose.jwt import ExpiredSignatureError, JWTError

from cognito_code_grant.authentication import \
    CognitoAuthentication, _verify_token_and_decode, _fetch_cognito_keys, _refresh_tokens

TEST_COGNITO_RESPONSE = {'email': 'test@email.com', 'cognito:username': 'test_cognito_id', 'cognito:groups': ['test_group']}

TEST_GROUPS = [
    'group_1',
    'group_2',
]

class CognitoAuthTestCase(DjangoTestCase):
    @mock.patch('cognito_code_grant.authentication._verify_token_and_decode')
    def test_valid_access_token_and_id_token_creates_user(self, mock_verify_token):
        auth = CognitoAuthentication()
        request = mock.MagicMock()
        request.session = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'id_token': 'test_id_token',
        }
        mock_verify_token.side_effect = ['some_token', TEST_COGNITO_RESPONSE]

        self.assertEqual(Group.objects.count(), 0)

        set_user, auth = auth.authenticate(request)

        mock_verify_token.assert_has_calls([
            mock.call('test_access_token'),
            mock.call('test_id_token')
            ])
        user = User.objects.get(email='test@email.com')
        group = Group.objects.get(name='test_group')
        self.assertEqual(user.email, 'test@email.com')
        self.assertEqual(user.username, 'test_cognito_id')
        self.assertEqual(user.username, set_user.username)
        self.assertEqual(Group.objects.count(), 1)
        self.assertEqual(user.groups.count(), 1)
        self.assertEqual(group.id, user.groups.all()[0].id)

    @mock.patch('cognito_code_grant.authentication._verify_token_and_decode')
    def test_valid_access_token_and_id_token_sets_existing_user(self, mock_verify_token):
        auth = CognitoAuthentication()
        request = mock.MagicMock()
        request.session = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'id_token': 'test_id_token',
        }
        mock_verify_token.side_effect = ['some_token', TEST_COGNITO_RESPONSE]
        existing_user = User.objects.create(username='test_cognito_id', email='test@email.com')

        set_user, auth = auth.authenticate(request)

        mock_verify_token.assert_has_calls([
            mock.call('test_access_token'),
            mock.call('test_id_token')
            ])
        self.assertEqual(set_user.username, existing_user.username)

    @mock.patch('cognito_code_grant.authentication._refresh_tokens')
    @mock.patch('cognito_code_grant.authentication._verify_token_and_decode')
    def test_invalid_access_token_401(self, mock_verify_token, mock_refresh_token):
        auth = CognitoAuthentication()
        request = mock.MagicMock()
        request.session = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'id_token': 'test_id_token',
        }
        mock_verify_token.side_effect = [JWTError]
        mock_refresh_token.return_value = {
            'reason': 'bad refresh token'
        }

        with self.assertRaises(exceptions.AuthenticationFailed):
            set_user, auth = auth.authenticate(request)

    @mock.patch('cognito_code_grant.authentication._verify_token_and_decode')
    def test_valid_access_token_and_id_token_dont_update_existing_groups(self, mock_verify_token):
        auth = CognitoAuthentication()
        request = mock.MagicMock()
        request.session = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'id_token': 'test_id_token',
        }

        mod_test_cognito_response = copy.deepcopy(TEST_COGNITO_RESPONSE)
        mod_test_cognito_response['cognito:groups'] = TEST_GROUPS
        mock_verify_token.side_effect = ['some_token', mod_test_cognito_response]
        existing_user = User.objects.create(username='test_cognito_id', email='test@email.com')
        for test_group in TEST_GROUPS:
            existing_group = Group.objects.create(name=test_group)
            #existing_group.user_set.add(existing_user)
            existing_user.groups.add(existing_group)

        self.assertEqual(Group.objects.count(), len(TEST_GROUPS))
        self.assertEqual(set(existing_user.groups.values_list('name', flat=True)) - set(TEST_GROUPS), set())
        set_user, auth_ret = auth.authenticate(request)
        self.assertEqual(Group.objects.count(), len(TEST_GROUPS))
        self.assertEqual(set(existing_user.groups.values_list('name', flat=True)) - set(TEST_GROUPS), set())

        mock_verify_token.assert_has_calls([
            mock.call('test_access_token'),
            mock.call('test_id_token')
            ])
        self.assertEqual(set_user.username, existing_user.username)


    @mock.patch('cognito_code_grant.authentication._verify_token_and_decode')
    @mock.patch('cognito_code_grant.authentication._refresh_tokens')
    def test_fetches_new_tokens_if_expired(self, mock_refresh_token, mock_verify_token):
        auth = CognitoAuthentication()
        request = mock.MagicMock()
        request.session = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'id_token': 'test_id_token',
        }
        mock_verify_token.side_effect = [ExpiredSignatureError, TEST_COGNITO_RESPONSE]

        mock_refresh_token.return_value = {
            'id_token': 'new_id_token',
            'access_token': 'new_access_token',
        }

        set_user, auth = auth.authenticate(request)
        self.assertEqual(set_user.email, 'test@email.com')

        self.assertEqual(request.session['access_token'], 'new_access_token')
        self.assertEqual(request.session['refresh_token'], 'test_refresh_token')
        self.assertEqual(request.session['id_token'], 'new_id_token')


    @mock.patch('cognito_code_grant.authentication._verify_token_and_decode')
    @mock.patch('cognito_code_grant.authentication._refresh_tokens')
    def test_401_if_bad_refresh_token(self, mock_refresh_token, mock_verify_token):
        auth = CognitoAuthentication()
        request = mock.MagicMock()
        request.session = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'id_token': 'test_id_token',
        }
        mock_verify_token.side_effect = [ExpiredSignatureError, {'email': 'test@email.com'}]

        mock_refresh_token.return_value = {}

        with self.assertRaises(exceptions.AuthenticationFailed):
            set_user, auth = auth.authenticate(request)


class VerifyTokenTestCase(TestCase):
    @mock.patch('cognito_code_grant.authentication.jwt')
    def test_decodes_token_with_provided_keys(self, jwt_mock):
        jwt_mock.get_unverified_header.return_value = {'kid': '1'}
        jwt_mock.decode.return_value = 'test_token'

        key_1 = defaultdict(lambda: '', {'kid': '1', 'alg':  'rs256'})
        key_2 = defaultdict(lambda: '', {'kid': '2', 'alg':  'rs256'})


        decoded_token = _verify_token_and_decode('test_token', {'keys': [
            key_1, key_2
        ]})

        self.assertEqual('test_token', decoded_token)
        jwt_mock.decode.assert_called_once_with('test_token', key_1, algorithms=['rs256'],
                                                audience=settings.AUTH_COGNITO_CLIENT_ID,
                                                options={'verify_at_hash': False})

    @mock.patch('cognito_code_grant.authentication.cache')
    @mock.patch('cognito_code_grant.authentication._fetch_cognito_keys')
    @mock.patch('cognito_code_grant.authentication.jwt')
    def test_fetches_keys_if_not_provided(self, jwt_mock, fetch_keys_mock, cache_mock):
        jwt_mock.get_unverified_header.return_value = {'kid': '1'}
        jwt_mock.decode.return_value = 'test_token'
        fetch_keys_mock.return_value = {'keys': [defaultdict(lambda: '', {'kid': '1', 'alg':  'rs256'})]}
        cache_mock.get.return_value = None

        _verify_token_and_decode('test_token')
        fetch_keys_mock.assert_called_once()

    @mock.patch('cognito_code_grant.authentication.cache')
    @mock.patch('cognito_code_grant.authentication.jwt')
    def test_uses_from_cache_keys_if_not_provided(self, jwt_mock, cache_mock):
        jwt_mock.get_unverified_header.return_value = {'kid': '1'}
        jwt_mock.decode.return_value = 'test_token'
        cache_mock.get.return_value = {'keys': [defaultdict(lambda: '', {'kid': '1', 'alg':  'rs256'})]}

        _verify_token_and_decode('test_token')
        cache_mock.get.assert_called_once()


class FetchKeysTestCase(TestCase):
    @mock.patch('cognito_code_grant.authentication.cache')
    @mock.patch('cognito_code_grant.authentication.requests')
    def test_gets_tokens_from_configured_url_and_sets_cache(self, requests_mock, cache_mock):
        mock_reply = mock.MagicMock()
        mock_reply.json.return_value = {'some':'json'}
        requests_mock.get.return_value = mock_reply

        keys = _fetch_cognito_keys()

        cache_mock.set.assert_called_once_with('jwks', {'some': 'json'}, timeout=None)
        assert keys == {'some': 'json'}


class RefreshTokensTestCase(TestCase):
    @mock.patch('cognito_code_grant.authentication.requests')
    def test_gets_new_tokens_from_cognito(self, requests_mock):
        mock_reply = mock.MagicMock()
        mock_reply.json.return_value = {'some':'json'}
        requests_mock.post.return_value = mock_reply

        _refresh_tokens('mock_refresh_token')

        requests_mock.post.assert_called_once_with(settings.AUTH_COGNITO_CODE_GRANT_URL, data={
            'grant_type': 'refresh_token',
            'refresh_token': 'mock_refresh_token',
            'client_id': settings.AUTH_COGNITO_CLIENT_ID
        })


