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

from cinder.volume.drivers.hpe import hpe_xp_exception as exception
from cinder.volume.drivers.hpe import hpe_xp_horcm as horcm
from cinder.volume.drivers.hpe import hpe_xp_utils as utils

_HOST_GROUPS_PATTERN = re.compile(
    r"^CL\w-\w+ +(?P<gid>\d+) +%s(?!pair00 )\S* +\d+ " % utils.TARGET_PREFIX,
    re.M)
_FC_PORT_PATTERN = re.compile(
    (r"^(CL\w-\w)\w* +(?:FIBRE|FCoE) +TAR +\w+ +\w+ +\w +\w+ +Y +"
     r"\d+ +\d+ +(\w{16})"), re.M)

LOG = logging.getLogger(__name__)


class HPEXPHORCMFC(horcm.HPEXPHORCM):

    def connect_storage(self):
        target_ports = self.conf.hpexp_target_ports
        compute_target_ports = self.conf.hpexp_compute_target_ports

        super(HPEXPHORCMFC, self).connect_storage()

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
            raise exception.HPEXPError(data=msg)
        LOG.debug('Setting target_ports: %s', self.storage_info['ports'])
        LOG.debug(
            'Setting compute_target_ports: %s',
            self.storage_info['compute_ports'])
        LOG.debug('Setting target wwns: %s', self.storage_info['wwns'])

    def create_target_to_storage(self, port, target_name, dummy_hba_ids):
        result = self.run_raidcom(
            'add', 'host_grp', '-port', port, '-host_grp_name', target_name)
        return horcm.find_value(result[1], 'gid')

    def set_hba_ids(self, port, gid, hba_ids):
        registered_wwns = []
        for wwn in hba_ids:
            try:
                self.run_raidcom(
                    'add', 'hba_wwn', '-port',
                    '-'.join([port, gid]), '-hba_wwn', wwn)
                registered_wwns.append(wwn)
            except exception.HPEXPError:
                utils.output_log(317, port=port, gid=gid, wwn=wwn)
        if not registered_wwns:
            msg = utils.output_log(614, port=port, gid=gid)
            raise exception.HPEXPError(msg)

    def set_target_mode(self, port, gid):
        pass

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
                LOG.debug(
                    'Found wwpns in host group. '
                    '(port: %s, gid: %s, wwpns: %s)', port, gid, wwpns)
                continue
            if self.conf.hpexp_horcm_name_only_discovery:
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
                    LOG.debug(
                        'Found wwpns in host group. '
                        '(port: %s, gid: %s, wwpns: %s)',
                        port, gid, wwpns)
                    break
            else:
                nr_not_found += 1

        return nr_not_found
