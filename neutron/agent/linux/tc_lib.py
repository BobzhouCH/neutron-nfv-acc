# Copyright 2016 OVH SAS
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

import re

from neutron._i18n import _
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import exceptions
from neutron.services.qos import qos_consts

from oslo_log import log as logging
from oslo_utils import excutils

LOG = logging.getLogger(__name__)

INGRESS_QDISC_ID = "ffff:"
MAX_MTU_VALUE = 65535

SI_BASE = 1000
IEC_BASE = 1024

LATENCY_UNIT = "ms"
BW_LIMIT_UNIT = "kbit"  # kilobits per second in tc's notation
BURST_UNIT = "kbit"  # kilobits in tc's notation

# Those are RATES (bits per second) and SIZE (bytes) unit names from tc manual
UNITS = {
    "k": 1,
    "m": 2,
    "g": 3,
    "t": 4
}

filters_pattern = re.compile(r"police \w+ rate (\w+) burst (\w+)")
tbf_pattern = re.compile(
    r"qdisc (\w+) \w+: \w+ refcnt \d rate (\w+) burst (\w+) \w*")


class InvalidKernelHzValue(exceptions.NeutronException):
    message = _("Kernel HZ value %(value)s is not valid. This value must be "
                "greater than 0.")


class InvalidUnit(exceptions.NeutronException):
    message = _("Unit name '%(unit)s' is not valid.")


def convert_to_kilobits(value, base):
    value = value.lower()
    if "bit" in value:
        input_in_bits = True
        value = value.replace("bit", "")
    else:
        input_in_bits = False
        value = value.replace("b", "")
    # if it is now bare number then it is in bits, so we return it simply
    if value.isdigit():
        value = int(value)
        if input_in_bits:
            return bits_to_kilobits(value, base)
        else:
            bits_value = bytes_to_bits(value)
            return bits_to_kilobits(bits_value, base)
    unit = value[-1:]
    if unit not in UNITS.keys():
        raise InvalidUnit(unit=unit)
    val = int(value[:-1])
    if input_in_bits:
        bits_value = val * (base ** UNITS[unit])
    else:
        bits_value = bytes_to_bits(val * (base ** UNITS[unit]))
    return bits_to_kilobits(bits_value, base)


def bytes_to_bits(value):
    return value * 8


def bits_to_kilobits(value, base):
    #NOTE(slaweq): round up that even 1 bit will give 1 kbit as a result
    return int((value + (base - 1)) / base)


class TcCommand(ip_lib.IPDevice):

    def __init__(self, name, kernel_hz, namespace=None):
        if kernel_hz <= 0:
            raise InvalidKernelHzValue(value=kernel_hz)
        super(TcCommand, self).__init__(name, namespace=namespace)
        self.kernel_hz = kernel_hz

    def _execute_tc_cmd(self, cmd, **kwargs):
        cmd = ['tc'] + cmd
        ip_wrapper = ip_lib.IPWrapper(self.namespace)
        return ip_wrapper.netns.execute(cmd, run_as_root=True, **kwargs)

    @staticmethod
    def get_ingress_qdisc_burst_value(bw_limit, burst_limit):
        """Return burst value used in ingress qdisc.

        If burst value is not specified given than it will be set to default
        rate to ensure that limit for TCP traffic will work well
        """
        if not burst_limit:
            return float(bw_limit) * qos_consts.DEFAULT_BURST_RATE
        return burst_limit

    def get_filters_bw_limits(self, qdisc_id=INGRESS_QDISC_ID):
        cmd = ['filter', 'show', 'dev', self.name, 'parent', qdisc_id]
        cmd_result = self._execute_tc_cmd(cmd)
        if not cmd_result:
            return None, None
        for line in cmd_result.split("\n"):
            m = filters_pattern.match(line.strip())
            if m:
                #NOTE(slaweq): because tc is giving bw limit in SI units
                # we need to calculate it as 1000bit = 1kbit:
                bw_limit = convert_to_kilobits(m.group(1), SI_BASE)
                #NOTE(slaweq): because tc is giving burst limit in IEC units
                # we need to calculate it as 1024bit = 1kbit:
                burst_limit = convert_to_kilobits(m.group(2), IEC_BASE)
                return bw_limit, burst_limit
        return None, None

    def get_tbf_bw_limits(self):
        cmd = ['qdisc', 'show', 'dev', self.name]
        cmd_result = self._execute_tc_cmd(cmd)
        if not cmd_result:
            return None, None
        m = tbf_pattern.match(cmd_result)
        if not m:
            return None, None
        qdisc_name = m.group(1)
        if qdisc_name != "tbf":
            return None, None
        #NOTE(slaweq): because tc is giving bw limit in SI units
        # we need to calculate it as 1000bit = 1kbit:
        bw_limit = convert_to_kilobits(m.group(2), SI_BASE)
        #NOTE(slaweq): because tc is giving burst limit in IEC units
        # we need to calculate it as 1024bit = 1kbit:
        burst_limit = convert_to_kilobits(m.group(3), IEC_BASE)
        return bw_limit, burst_limit

    def set_filters_bw_limit(self, bw_limit, burst_limit):
        """Set ingress qdisc and filter for police ingress traffic on device

        This will allow to police traffic incoming to interface. It
        means that it is fine to limit egress traffic from instance point of
        view.
        """
        #because replace of tc filters is not working properly and it's adding
        # new filters each time instead of replacing existing one first old
        # ingress qdisc should be deleted and then added new one so update will
        # be called to do that:
        return self.update_filters_bw_limit(bw_limit, burst_limit)

    def set_tbf_bw_limit(self, bw_limit, burst_limit, latency_value):
        """Set token bucket filter qdisc on device

        This will allow to limit speed of packets going out from interface. It
        means that it is fine to limit ingress traffic from instance point of
        view.
        """
        return self._replace_tbf_qdisc(bw_limit, burst_limit, latency_value)

    def update_filters_bw_limit(self, bw_limit, burst_limit,
                                qdisc_id=INGRESS_QDISC_ID):
        self.delete_filters_bw_limit()
        return self._set_filters_bw_limit(bw_limit, burst_limit, qdisc_id)

    def update_tbf_bw_limit(self, bw_limit, burst_limit, latency_value):
        return self._replace_tbf_qdisc(bw_limit, burst_limit, latency_value)

    def delete_filters_bw_limit(self):
        #NOTE(slaweq): For limit traffic egress from instance we need to use
        # qdisc "ingress" because it is ingress traffic from interface POV:
        self._delete_qdisc("ingress")

    def delete_tbf_bw_limit(self):
        self._delete_qdisc("root")

    def _set_filters_bw_limit(self, bw_limit, burst_limit,
                              qdisc_id=INGRESS_QDISC_ID):
        cmd = ['qdisc', 'add', 'dev', self.name, 'ingress',
               'handle', qdisc_id]
        self._execute_tc_cmd(cmd)
        return self._add_policy_filter(bw_limit, burst_limit)

    def _delete_qdisc(self, qdisc_name):
        cmd = ['qdisc', 'del', 'dev', self.name, qdisc_name]
        # Return_code=2 is fine because it means
        # "RTNETLINK answers: No such file or directory" what is fine when we
        # are trying to delete qdisc
        return self._execute_tc_cmd(cmd, extra_ok_codes=[2])

    def _get_tbf_burst_value(self, bw_limit, burst_limit):
        min_burst_value = float(bw_limit) / float(self.kernel_hz)
        return max(min_burst_value, burst_limit)

    def _replace_tbf_qdisc(self, bw_limit, burst_limit, latency_value):
        burst = "%s%s" % (
            self._get_tbf_burst_value(bw_limit, burst_limit), BURST_UNIT)
        latency = "%s%s" % (latency_value, LATENCY_UNIT)
        rate_limit = "%s%s" % (bw_limit, BW_LIMIT_UNIT)
        cmd = [
            'qdisc', 'replace', 'dev', self.name,
            'root', 'tbf',
            'rate', rate_limit,
            'latency', latency,
            'burst', burst
        ]
        return self._execute_tc_cmd(cmd)

    def _add_policy_filter(self, bw_limit, burst_limit,
                           qdisc_id=INGRESS_QDISC_ID):
        rate_limit = "%s%s" % (bw_limit, BW_LIMIT_UNIT)
        burst = "%s%s" % (
            self.get_ingress_qdisc_burst_value(bw_limit, burst_limit),
            BURST_UNIT
        )
        #NOTE(slaweq): it is made in exactly same way how openvswitch is doing
        # it when configuing ingress traffic limit on port. It can be found in
        # lib/netdev-linux.c#L4698 in openvswitch sources:
        cmd = [
            'filter', 'add', 'dev', self.name,
            'parent', qdisc_id, 'protocol', 'all',
            'prio', '49', 'basic', 'police',
            'rate', rate_limit,
            'burst', burst,
            'mtu', MAX_MTU_VALUE,
            'drop']
        return self._execute_tc_cmd(cmd)

def check_root_htb_qdisc(physical_nic):
    args = ["tc", "qdisc", "show", "dev", "%s" % physical_nic]
    try:
        result = utils.execute(args, run_as_root=True).strip().split("\n")
        LOG.info(_("result in check_root_htb_qdisc %s") % result)
        return "htb" in " ".join(result) if result else False
    except Exception as e:
        with excutils.save_and_reraise_exception():
            LOG.exception(_("Unable to retrieve root htb qdisc. "
                            "Exception: %s"), e)

def check_root_ingress_qdisc(physical_nic, tc_ingress_root_class_id):
    args = ["tc", "qdisc", "show", "dev", "%s" % physical_nic]
    try:
        result = utils.execute(args, run_as_root=True).strip().split("\n")
        return "ingress" in " ".join(result) if result else False
    except Exception as e:
        with excutils.save_and_reraise_exception():
            LOG.exception(_("Unable to retrieve root ingress qdisc. Exception: "
                            "%s"), e)

def check_class(physical_nic, bandwidth, parent):
    args = ["tc", "class", "show", "dev", "%s" % physical_nic]
    try:
        result = utils.execute(args, run_as_root=True).strip().split("\n")
        class_id = str(parent) + ":" + str(bandwidth) + " "
        return class_id in " ".join(result) if result else False
    except Exception as e:
        with excutils.save_and_reraise_exception():
            LOG.exception(_("Unable to retrieve tc class. Exception: %s"), e)

def get_tc_filter_handle(fip_address, nic, parent):
    args = ["tc", "filter", "show", "dev", "%s" % nic, "parent", "%s:" % parent]
    try:
        result = utils.execute(args, run_as_root=True).strip().split("filter")
        fip_hex = ip_hex_repr(fip_address)
        handles = []
        for r in result:
            if fip_hex in r:
                handles.append(r.split(" ")[7])
        return handles
    except Exception as e:
        with excutils.save_and_reraise_exception():
            LOG.exception(_("Unable to retrieve tc class. Exception: %s"), e)

def clear_tc_filter(fip_address, nic, parent):
    try:
        handles = get_tc_filter_handle(fip_address, nic, parent)
        for handle in handles:
            args = ["tc", "filter", "del", "dev", "%s" % nic,
            "protocol", "ip", "parent", "%s:" % parent, "prio",
            "1", "handle", "%s" % handle, "u32"]
            utils.execute(args, run_as_root=True).strip().split("\n")
    except Exception as e:
        with excutils.save_and_reraise_exception():
            LOG.exception(_("Unable to clear former filer on ip %(ip)s."
                            " Exception: %(e)s"), {'ip': fip_address, 'e': e})

def ip_hex_repr(ip):
    return '{0:02x}{1:02x}{2:02x}{3:02x}'.format(*map(int, ip.split('.')))

def check_filter(physical_nic, parent, bandwidth, fip_address):
    args = ["tc", "filter", "show", "dev", "%s" % physical_nic]
    try:
        result = utils.execute(args, run_as_root=True).strip().split("\n")
        class_id = "%s:%s " % (str(parent), str(bandwidth))
        ip_hex = ip_hex_repr(fip_address)
        result = " ".join(result)
        pattern = class_id + " match " + ip_hex
        if pattern in result:
            return True

        # try to clear previous filter of this floating ip
        if ip_hex in result:
            clear_tc_filter(fip_address, physical_nic, parent)

        return False
    except Exception as e:
        with excutils.save_and_reraise_exception():
            LOG.exception(_("Unable to retrieve tc class. Exception: %s"), e)

def check_root_redirect_filter(physical_nic, ifb, tc_ingress_root_class_id):
    args = ["tc", "filter", "show", "dev", "%s" % physical_nic, "parent",
            "%s:" % tc_ingress_root_class_id, "protocol", "all"]
    try:
        result = utils.execute(args, run_as_root=True).strip().split("\n")
        result = " ".join(result)
        return ifb in result if result else False
    except Exception as e:
        with excutils.save_and_reraise_exception():
            LOG.exception(_("Unable to retrieve tc filter. Exception: %s"), e)

def ensure_root_htb_qdisc(physical_nic, class_id):
    if check_root_htb_qdisc(physical_nic):
        LOG.info(_("root htb qdisc exists"))
        return
    args = ["tc", "qdisc", "add", "dev", "%s" % physical_nic, "root", "handle",
            "%s:" % class_id, "htb"]
    try:
        utils.execute(args, run_as_root=True).strip().split("\n")
    except Exception as e:
        with excutils.save_and_reraise_exception():
            LOG.exception(_("Unable to add root qdisc for physical nic. Exception: %s"), e)

def ensure_root_ingress_qdisc(physical_nic, ifb, tc_ingress_root_class_id):
    if not check_root_ingress_qdisc(physical_nic, tc_ingress_root_class_id):
        args = ["tc", "qdisc", "add", "dev", "%s" % physical_nic, "handle",
                "%s:" % tc_ingress_root_class_id, "ingress"]
        try:
            utils.execute(args, run_as_root=True).strip().split("\n")
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Unable to add root ingress qdisc for physical nic. Exception: %s"), e)

    if not check_root_redirect_filter(physical_nic, ifb, tc_ingress_root_class_id):
        args = ["tc", "filter", "add", "dev", "%s" % physical_nic, "parent",
            "%s:" % tc_ingress_root_class_id, "protocol", "all", "u32",
            "match", "u32", "0", "0", "action", "mirred", "egress",
            "redirect", "dev", "%s" % ifb]
        LOG.info(_("args for filter ifb0 %s") % args)
        try:
            utils.execute(args, run_as_root=True).strip().split("\n")
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Unable to add root ingress filter for physical nic. Exception: %s"), e)

    ensure_root_htb_qdisc(ifb, tc_ingress_root_class_id)

def ensure_tc_class(physical_nic, bandwidth, parent):
    if int(bandwidth) == 0:
        return
    if check_class(physical_nic, bandwidth, parent):
        return
    args = ["tc", "class", "add", "dev", "%s" % physical_nic, "parent",
            "%s:" % parent, "classid", "%s:%s" % (str(parent), str(bandwidth)),
            "htb", "rate", "%smbit" % bandwidth]
    try:
        utils.execute(args, run_as_root=True).strip().split("\n")
    except Exception as e:
        with excutils.save_and_reraise_exception():
            LOG.exception(_("Unable to add tc class. Exception: %s"), e)

def ensure_tc_filter(physical_nic, bandwidth, parent, fip_address, is_egress):
    if check_filter(physical_nic, parent, bandwidth, fip_address):
        return
    clear_tc_filter(fip_address, physical_nic, parent)
    if int(bandwidth) == 0:
        return
    if is_egress:
        match = 'src'
    else:
        match = 'dst'
    args = ["tc", "filter", "add", "dev", "%s" % physical_nic, "protocol",
            "ip", "parent", "%s:" % parent, "prio", "1", "u32", "match", "ip",
            "%s" % match, "%s" % fip_address, "flowid", "%s:%s" % (str(parent), str(bandwidth))]
    try:
        utils.execute(args, run_as_root=True).strip().split("\n")
    except Exception as e:
        with excutils.save_and_reraise_exception():
            LOG.exception(_("Unable to add tc filter. Exception: %s"), e)

def clear_tc_root_qdisc(nic, class_id):
    if not check_root_htb_qdisc(nic):
        return
    args = ["tc", "qdisc", "delete", "dev", "%s" % nic, "root", "handle",
            "%s:" % class_id]
    try:
        utils.execute(args, run_as_root=True).strip().split("\n")
    except Exception as e:
        with excutils.save_and_reraise_exception():
            LOG.exception(_("Unable to delete tc root qdisc. Exception: %s"), e)

def clear_tc_ingress_qdisc(nic, class_id):
    if not check_root_ingress_qdisc(nic, class_id):
        return
    args = ["tc", "qdisc", "delete", "dev", "%s" % nic, "handle",
            "%s:" % class_id, "ingress"]
    try:
        utils.execute(args, run_as_root=True).strip().split("\n")
    except Exception as e:
        with excutils.save_and_reraise_exception():
            LOG.exception(_("Unable to delete tc ingress qdisc. Exception: %s"), e)


def clear_egress(physical_nic, class_id):
    clear_tc_root_qdisc(physical_nic, class_id)

def clear_ingress(physical_nic, ifb_nic, class_id):
    clear_tc_root_qdisc(ifb_nic, class_id)
    clear_tc_ingress_qdisc(physical_nic, class_id)

def ensure_tc_filter_u32(nic, bandwidth, parent, match, mask, offset='0'):
    args = ["tc", "filter", "add", "dev", "%s" % nic, "protocol",
            "ip", "parent", "%s:" % parent, "prio", "1", "u32", "match", "u32",
            "%s" % match, "%s" % mask, "at", "%s" % offset, "flowid",
            "%s:%s" % (str(parent), str(bandwidth))]
    try:
        utils.execute(args, run_as_root=True).strip().split("\n")
    except Exception as e:
        with excutils.save_and_reraise_exception():
            LOG.exception(_("Unable to add tc filter. Exception: %s"), e)
