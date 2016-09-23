# -*- coding: utf-8; -*-
#
# This file is part of Superdesk.
#
# Copyright 2013, 2014 Sourcefabric z.u. and contributors.
#
# For the full copyright and license information, please see the
# AUTHORS and LICENSE files distributed with this source code, or
# at https://www.sourcefabric.org/superdesk/license

from apps.auth.service import AuthService
from superdesk import get_resource_service
from superdesk.resource import Resource
from apps.auth.errors import UserDisabledError, CredentialsAuthError
from superdesk.users.errors import UserInactiveError
from superdesk import utils
import requests
import superdesk


class XMPPAuthResource(Resource):
    schema = {
        'jid': {
            'type': 'string',
            'required': True
        },
        'transactionId': {
            'type': 'string',
            'required': True
        },
        'token': {
            'type': 'string'
        },
        'user': Resource.rel('users', True)
    }
    resource_methods = ['POST']
    item_methods = ['GET', 'DELETE']
    public_methods = ['POST', 'DELETE']
    extra_response_fields = ['user', 'token', 'username']


superdesk.intrinsic_privilege('auth', method=['DELETE'])


class XMPPAuthService(AuthService):

    def authenticate(self, credentials):
        jid = credentials.get('jid')
        if not jid:
            raise CredentialsAuthError(credentials)
        user = get_resource_service('auth_users').find_one(req=None, jid=jid)
        if not user:
            raise CredentialsAuthError(credentials)

        if 'is_enabled' in user and not user.get('is_enabled', False):
            raise UserDisabledError()

        if not user.get('is_active', False):
            raise UserInactiveError()

        try:
            r = requests.post("http://localhost:9999/auth", data={"jid": jid, "domain": "Superdesk", "transaction_id": credentials.get('transactionId')})
        except Exception:
            raise CredentialsAuthError(credentials)
        else:
            if r.status_code != 200:
                raise CredentialsAuthError(credentials)

        return user

    def set_auth_default(self, doc, user_id):
        doc['user'] = user_id
        doc['token'] = utils.get_random_string(40)
