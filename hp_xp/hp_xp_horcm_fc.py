# Copyright (C) 2015, Hitachi, Ltd.
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

from oslo_log import log as logging

from cinder.i18n import _LI
from cinder.volume.drivers.san.hp import hp_xp_exception as exception
from cinder.volume.drivers.san.hp import hp_xp_horcm as horcm
from cinder.volume.drivers.san.hp import hp_xp_horcm_ext as horcm_ext
from cinder.volume.drivers.san.hp import hp_xp_traceutils as traceutils
from cinder.volume.drivers.san.hp import hp_xp_utils as utils

_HOST_GROUPS_PATTERN = re.compile(
    r"^CL\w-\w+ +(?P<gid>\d+) +%s(?!pair00 )\S* +\d+ " % utils.TARGET_PREFIX,
    re.M)
_FC_PORT_PATTERN = re.compile(
    (r"^(CL\w-\w)\w* +(?:FIBRE|FCoE) +TAR +\w+ +\w+ +\w +\w+ +Y +"
     r"\d+ +\d+ +(\w{16})"), re.M)

HLOG = logging.getLogger(traceutils.HLOG_NAME)


class HPXPHORCMFC(horcm_ext.HPXPHORCMExtension):

    @traceutils.trace_function()
    def connect_storage(self):
        target_ports = self.conf.hpxp_target_ports
        compute_target_ports = self.conf.hpxp_compute_target_ports

        super(HPXPHORCMFC, self).connect_storage()

        result = self.run_raidcom('get', 'port')
        for port, wwn in _FC_PORT_PATTERN.findall(result[1]):
            if port in target_ports:
                self.storage_info['ports'].append(port)
                self.storage_info['wwns'][port] = wwn
            if compute_target_ports and port in compute_target_ports:
                self.storage_info['compute_ports'].append(port)
                self.storage_info['wwns'][port] = wwn

        if not self.storage_info['ports']:
            msg = utils.output_log(650, resource="Target ports")
            raise exception.HPXPError(data=msg)
        HLOG.info(_LI('Setting target_ports: %s'), self.storage_info['ports'])
        HLOG.info(
            _LI('Setting compute_target_ports: %s'),
            self.storage_info['compute_ports'])
        HLOG.info(_LI('Setting target wwns: %s'), self.storage_info['wwns'])

    @traceutils.trace_function()
    def create_target_to_storage(self, port, target_name, dummy_hba_ids):
        result = self.run_raidcom(
            'add', 'host_grp', '-port', port, '-host_grp_name', target_name)
        return horcm.find_value(result[1], 'gid')

    @traceutils.trace_function()
    def set_hba_ids(self, port, gid, hba_ids):
        registered_wwns = []
        for wwn in hba_ids:
            try:
                self.run_raidcom(
                    'add', 'hba_wwn', '-port',
                    '-'.join([port, gid]), '-hba_wwn', wwn)
                registered_wwns.append(wwn)
            except exception.HPXPError:
                utils.output_log(317, port=port, gid=gid, wwn=wwn)
        if not registered_wwns:
            msg = utils.output_log(614, port=port, gid=gid)
            raise exception.HPXPError(msg)

    def set_target_mode(self, port, gid):
        pass

    @traceutils.trace_function()
    def find_targets_from_storage(self, targets, connector, target_ports):
        nr_not_found = 0
        target_name = '-'.join([utils.DRIVER_PREFIX, connector['ip']])
        success_code = horcm.HORCM_EXIT_CODE.union([horcm.EX_ENOOBJ])
        wwpns = self.get_hba_ids_from_connector(connector)
        wwpns_pattern = re.compile(
            r'^CL\w-\w+ +\d+ +\S+ +(%s) ' % '|'.join(wwpns), re.M)

        for port in target_ports:
            targets['info'][port] = False

            result = self.run_raidcom(
                'get', 'hba_wwn', '-port', port, target_name,
                success_code=success_code)
            wwpns = wwpns_pattern.findall(result[1])
            if wwpns:
                gid = result[1].splitlines()[1].split()[1]
                targets['info'][port] = True
                targets['list'].append((port, gid))
                HLOG.info(
                    _LI('Found wwpns in host group. '
                        '(port: %(port)s, gid: %(gid)s, wwpns: %(wwpns)s)'),
                    {'port': port, 'gid': gid, 'wwpns': wwpns})
                continue
            if self.conf.hpxp_horcm_name_only_discovery:
                nr_not_found += 1
                continue

            result = self.run_raidcom(
                'get', 'host_grp', '-port', port)
            for gid in _HOST_GROUPS_PATTERN.findall(result[1]):
                result = self.run_raidcom(
                    'get', 'hba_wwn', '-port', '-'.join([port, gid]))
                wwpns = wwpns_pattern.findall(result[1])
                if wwpns:
                    targets['info'][port] = True
                    targets['list'].append((port, gid))
                    HLOG.info(
                        _LI('Found wwpns in host group. (port: %(port)s, '
                            'gid: %(gid)s, wwpns: %(wwpns)s)'),
                        {'port': port, 'gid': gid, 'wwpns': wwpns})
                    break
            else:
                nr_not_found += 1

        return nr_not_found
