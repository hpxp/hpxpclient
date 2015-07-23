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

from cinder.volume.drivers.san.hp import hp_xp_horcm as horcm
from cinder.volume.drivers.san.hp import hp_xp_traceutils as traceutils
from cinder.volume.drivers.san.hp import hp_xp_utils as utils


class HPXPHORCMExtension(horcm.HPXPHORCM):

    @traceutils.trace_function()
    def restore_ldev(self, pvol, svol):
        timeout = utils.MAX_PROCESS_WAITTIME
        interval = self.conf.hpxp_async_copy_check_interval
        self._run_modify_snapshot(svol, 'restore')
        self.wait_thin_copy(
            svol, horcm.PAIR, timeout=timeout, interval=interval)
        self._run_modify_snapshot(svol, 'create')
        self.wait_thin_copy(
            svol, horcm.PSUS, timeout=timeout, interval=interval)

    @traceutils.trace_function()
    @utils.synchronized('create_pair')
    def _run_modify_snapshot(self, ldev, op):
        self.run_raidcom(
            'modify', 'snapshot', '-ldev_id', ldev, '-snapshot_data', op)

    @traceutils.trace_function()
    def has_thin_copy_pair(self, pvol, svol):
        ldev_info = self.get_ldev_info(['sts', 'vol_attr'], '-ldev_id', svol)
        if (ldev_info['sts'] != horcm.NORMAL_STS or
                horcm.THIN_ATTR not in ldev_info['vol_attr']):
            return False
        result = self.run_raidcom(
            'get', 'snapshot', '-ldev_id', svol)
        line = result[1].splitlines()[1].split()
        return line[1] == "S-VOL" and int(line[6]) == pvol
