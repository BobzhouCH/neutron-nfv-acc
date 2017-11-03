# Copyright 2011 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import webob

from oslo_config import cfg
from keystoneclient.auth.identity.generic import token
from keystoneclient import client
from keystoneclient import session

CONF = cfg.CONF


def check_valid(context, target_project_id, valid_quotas, project_quotas):
    for k in valid_quotas.keys():
        if valid_quotas[k] == int(project_quotas[k]):
            valid_quotas.pop(k)
    if valid_quotas:
        try:
            auth_uri = ("%s/v3" % CONF.keystone_authtoken.
                        identity_uri)
            auth_plugin = token.Token(
                auth_url=auth_uri,
                token=context.auth_token,
                project_id=context.project_id)
            client_session = session.Session(auth=auth_plugin)
            keystone = client.Client(auth_url=auth_uri,
                                     session=client_session)
            if keystone.version == 'v3':
                kwargs = {}
                kwargs['project_id'] = target_project_id
                # get region name
                kwargs['region'] = CONF.nova.region_name
                kwargs['project_quotas'] = project_quotas
                kwargs['valid_quotas'] = valid_quotas
                keystone.domain_quotas.domain_usage_sync(**kwargs)
        except Exception as e:
            msg = e.message
            raise webob.exc.HTTPBadRequest(explanation=msg)
