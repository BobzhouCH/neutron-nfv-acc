# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 UnitedStack, Inc.
# All rights reserved.
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
#
# @author: Jianing Yang, UnitedStack, Inc

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.common import exceptions as nexception


# Duplicated Outside Port Exceptions
class DuplicatedOutsidePort(nexception.InvalidInput):
    message = _("Duplicate outside port %(port)s has been used.")


class InvalidInsideAddress(nexception.InvalidInput):
    message = _("inside address %(inside_addr)s does not match "
                "any subnets in this router.")

# Attribute Map
EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        'portforwardings': {
            'allow_post': False, 'allow_put': True,
            'validate': {'type:portforwardings': None},
            'convert_to': attributes.convert_none_to_empty_list,
            'is_visible': True, 'default': attributes.ATTR_NOT_SPECIFIED
        },
    }
}


class Portforwardings(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Port Forwarding"

    @classmethod
    def get_alias(cls):
        return "portforwarding"

    @classmethod
    def get_description(cls):
        return "Expose internal TCP/UDP port to external network"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/neutron/portforwarding/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2013-12-04T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            attributes.PLURALS.update({'portforwardings': 'portforwarding'})
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
