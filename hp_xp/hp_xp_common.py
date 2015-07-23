# Copyright (C) 2014, 2015, Hitachi, Ltd.
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
"""
Common class for Hewlett-Packard storage drivers.

"""

import re
#want to remove the code
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import units
import six

from cinder import utils as cinder_utils
from cinder.i18n import _, _LI
from cinder.volume.drivers.san.hp import hp_xp_exception as exception
from cinder.volume.drivers.san.hp import hp_xp_opts as opts
from cinder.volume.drivers.san.hp import hp_xp_traceutils as traceutils
from cinder.volume.drivers.san.hp import hp_xp_utils as utils
from cinder.volume import utils as volume_utils
from cinder.zonemanager import utils as fczm_utils

VERSION = '1.3.0-0_2015.1'

_COPY_METHOD = set(['FULL', 'THIN'])

_INHERITED_VOLUME_OPTS = [
    'volume_backend_name',
    'volume_driver',
    'reserved_percentage',
    'use_multipath_for_image_xfer',
    'num_volume_device_scan_tries',
]

_COMMON_VOLUME_OPTS = [
    cfg.BoolOpt(
        'hpxp_driver_cert_mode',
        default=False,
        secret=True,
        help='Driver cert mode'),
]

_FC_VOLUME_OPTS = [
    cfg.BoolOpt(
        'hpxp_zoning_request',
        default=False,
        help='Request for FC Zone creating host group'),
]

_DRIVER_INFO = {
    'FC': {
        'hba_id': 'wwpns',
        'hba_id_type': 'World Wide Name',
        'msg_id': {
            'target': 308,
        },
        'volume_backend_name': utils.DRIVER_PREFIX + 'FC',
        'volume_opts': _FC_VOLUME_OPTS,
        'volume_type': 'fibre_channel',
    },
}

CONF = cfg.CONF
CONF.register_opts(_COMMON_VOLUME_OPTS)
CONF.register_opts(_FC_VOLUME_OPTS)

LOG = logging.getLogger(__name__)
HLOG = logging.getLogger(traceutils.HLOG_NAME)


def _str2int(num):
    if not num:
        return None
    if num.isdigit():
        return int(num)
    if not re.match(r'\w\w:\w\w:\w\w', num):
        return None
    try:
        return int(num.replace(':', ''), 16)
    except ValueError:
        return None


class HPXPCommon(object):

    def __init__(self, conf, storage_protocol, **kwargs):
        self.conf = conf
        self.conf.append_config_values(_COMMON_VOLUME_OPTS)

        self.db = kwargs.get('db')
        self.ctxt = None
        self.lock = {
            'do_setup': 'do_setup',
        }
        self.driver_info = _DRIVER_INFO[storage_protocol]
        self.storage_info = {
            'protocol': storage_protocol,
            'pool_id': None,
            'ldev_range': None,
            'ports': [],
            'compute_ports': [],
            'wwns': {},
            'output_first': True
        }

        self._stats = {}
        self._lookup_service = fczm_utils.create_lookup_service()

    @traceutils.trace_function(loglevel=traceutils.DEBUG)
    def run_and_verify_storage_cli(self, *cmd, **kwargs):
        do_raise = kwargs.pop('do_raise', True)
        ignore_error = kwargs.get('ignore_error')
        success_code = kwargs.get('success_code', set([0]))
        (ret, stdout, stderr) = self.run_storage_cli(*cmd, **kwargs)
        if (ret not in success_code and
                not utils.check_ignore_error(ignore_error, stderr)):
            msg = utils.output_log(
                600, cmd=' '.join([six.text_type(c) for c in cmd]),
                ret=ret, out=' '.join(stdout.splitlines()),
                err=' '.join(stderr.splitlines()))
            if do_raise:
                raise exception.HPXPError(data=msg)
        return ret, stdout, stderr

    def run_storage_cli(self, *cmd, **kwargs):
        raise NotImplementedError()

    @traceutils.trace_function()
    def get_copy_method(self, metadata):
        method = metadata.get(
            'copy_method', self.conf.hpxp_default_copy_method)
        if method not in _COPY_METHOD:
            msg = utils.output_log(602, meta='copy_method')
            raise exception.HPXPError(data=msg)
        if method == 'THIN' and not self.conf.hpxp_thin_pool:
            msg = utils.output_log(601, param='hpxp_thin_pool')
            raise exception.HPXPError(data=msg)
        return method

    @traceutils.measure_exec_time
    @traceutils.trace_function()
    @traceutils.logging_basemethod_exec
    def create_volume(self, volume):
        try:
            ldev = self.create_ldev(volume['size'])
        except Exception:
            with excutils.save_and_reraise_exception():
                utils.output_log(636)
        metadata = utils.get_volume_metadata(volume)
        return {
            'provider_location': six.text_type(ldev),
            'metadata': dict(
                metadata, ldev=ldev, type=utils.NORMAL_LDEV_TYPE),
        }

    @traceutils.trace_function()
    def create_ldev(self, size, is_vvol=False):
        ldev = self.get_unused_ldev()
        self.create_ldev_on_storage(ldev, size, is_vvol)
        HLOG.info(_LI('Created logical device. (LDEV: %s)'), ldev)
        return ldev

    def create_ldev_on_storage(self, ldev, size, is_vvol):
        raise NotImplementedError()

    def get_unused_ldev(self):
        raise NotImplementedError()

    @traceutils.measure_exec_time
    @traceutils.trace_function()
    @traceutils.logging_basemethod_exec
    def create_volume_from_snapshot(self, volume, snapshot):
        ldev = utils.get_ldev(snapshot)
        # When 'ldev' is 0, it should be true.
        # Therefore, it cannot remove 'is None'.
        if ldev is None:
            msg = utils.output_log(
                624, type='snapshot', id=snapshot['id'])
            raise exception.HPXPError(data=msg)
        size = volume['size']
        if size != snapshot['volume_size']:
            msg = utils.output_log(
                617, type='snapshot', volume_id=volume['id'])
            raise exception.HPXPError(data=msg)
        metadata = utils.get_volume_metadata(volume)
        new_ldev, ldev_type = self._copy_ldev(ldev, size, metadata)
        return {
            'provider_location': six.text_type(new_ldev),
            'metadata': dict(
                metadata, ldev=new_ldev, type=ldev_type,
                snapshot=snapshot['id']),
        }

    @traceutils.trace_function()
    def _copy_ldev(self, ldev, size, metadata):
        try:
            return self.copy_on_storage(ldev, size, metadata)
        except exception.HPXPNotImplementedError:
            return self._copy_on_host(ldev, size)

    @traceutils.trace_function()
    def _copy_on_host(self, src_ldev, size):
        dest_ldev = self.create_ldev(size)
        try:
            self._copy_with_dd(src_ldev, dest_ldev, size)
        except Exception:
            with excutils.save_and_reraise_exception():
                try:
                    self._delete_ldev(dest_ldev)
                except exception.HPXPError:
                    utils.output_log(313, ldev=dest_ldev)
        return dest_ldev, utils.NORMAL_LDEV_TYPE

    @traceutils.trace_function()
    def _copy_with_dd(self, src_ldev, dest_ldev, size):
        src_info = None
        dest_info = None
        properties = cinder_utils.brick_get_connector_properties()
        try:
            dest_info = self._attach_ldev(dest_ldev, properties)
            src_info = self._attach_ldev(src_ldev, properties)
            volume_utils.copy_volume(
                src_info['device']['path'], dest_info['device']['path'],
                size * units.Ki, self.conf.volume_dd_blocksize)
        finally:
            if src_info:
                self._detach_ldev(src_info, src_ldev, properties)
            if dest_info:
                self._detach_ldev(dest_info, dest_ldev, properties)
        self.discard_zero_page({'provider_location': six.text_type(dest_ldev)})

    @traceutils.trace_function()
    def _attach_ldev(self, ldev, properties):
        volume = {
            'provider_location': six.text_type(ldev),
        }
        conn = self.initialize_connection(volume, properties)
        try:
            connector = cinder_utils.brick_get_connector(
                conn['driver_volume_type'],
                use_multipath=self.conf.use_multipath_for_image_xfer,
                device_scan_attempts=self.conf.num_volume_device_scan_tries,
                conn=conn)
            device = connector.connect_volume(conn['data'])
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                utils.output_log(634, ldev=ldev, reason=six.text_type(ex))
                self._terminate_connection(volume, properties)
        return {
            'conn': conn,
            'device': device,
            'connector': connector,
        }

    @traceutils.trace_function()
    def _detach_ldev(self, attach_info, ldev, properties):
        volume = {
            'provider_location': six.text_type(ldev),
        }
        connector = attach_info['connector']
        try:
            connector.disconnect_volume(
                attach_info['conn']['data'], attach_info['device'])
        except Exception as ex:
            utils.output_log(329, ldev=ldev, reason=six.text_type(ex))
        self._terminate_connection(volume, properties)

    @traceutils.trace_function()
    def _terminate_connection(self, volume, connector):
        try:
            self.terminate_connection(volume, connector)
        except exception.HPXPError:
            utils.output_log(310, ldev=utils.get_ldev(volume))

    @traceutils.trace_function()
    def copy_on_storage(self, pvol, size, metadata):
        is_thin = self.get_copy_method(metadata) == "THIN"
        ldev_type = utils.VVOL_LDEV_TYPE if is_thin else utils.NORMAL_LDEV_TYPE
        svol = self.create_ldev(size, is_vvol=is_thin)
        try:
            self.create_pair_on_storage(pvol, svol, is_thin)
        except Exception:
            with excutils.save_and_reraise_exception():
                try:
                    self._delete_ldev(svol)
                except exception.HPXPError:
                    utils.output_log(313, ldev=svol)
        return svol, ldev_type

    def create_pair_on_storage(self, pvol, svol, is_thin):
        raise NotImplementedError()

    @traceutils.trace_function()
    def _delete_ldev(self, ldev):
        self.delete_pair(ldev)
        self.delete_ldev_from_storage(ldev)

    @traceutils.trace_function()
    def delete_pair(self, ldev, all_split=True):
        pair_info = self.get_pair_info(ldev)
        if not pair_info:
            return
        if pair_info['pvol'] == ldev:
            self.delete_pair_based_on_pvol(pair_info, all_split)
        else:
            self.delete_pair_based_on_svol(
                pair_info['pvol'], pair_info['svol_info'][0])

    def get_pair_info(self, ldev):
        raise NotImplementedError()

    @traceutils.trace_function()
    def delete_pair_based_on_pvol(self, pair_info, all_split):
        svols = []

        for svol_info in pair_info['svol_info']:
            if svol_info['is_thin'] or not svol_info['is_psus']:
                svols.append(six.text_type(svol_info['ldev']))
                continue
            self.delete_pair_from_storage(
                pair_info['pvol'], svol_info['ldev'], False)
        if all_split and svols:
            msg = utils.output_log(
                616, pvol=pair_info['pvol'], svol=', '.join(svols))
            raise exception.HPXPBusy(message=msg)

    def delete_pair_from_storage(self, pvol, svol, is_thin):
        raise NotImplementedError()

    @traceutils.trace_function()
    def delete_pair_based_on_svol(self, pvol, svol_info):
        if not svol_info['is_psus']:
            msg = utils.output_log(616, pvol=pvol, svol=svol_info['ldev'])
            raise exception.HPXPBusy(message=msg)
        self.delete_pair_from_storage(
            pvol, svol_info['ldev'], svol_info['is_thin'])

    def delete_ldev_from_storage(self, ldev):
        raise NotImplementedError()

    @traceutils.measure_exec_time
    @traceutils.trace_function()
    @traceutils.logging_basemethod_exec
    def create_cloned_volume(self, volume, src_vref):
        ldev = utils.get_ldev(src_vref)
        # When 'ldev' is 0, it should be true.
        # Therefore, it cannot remove 'is not None'.
        if ldev is None:
            msg = utils.output_log(624, type='volume', id=src_vref['id'])
            raise exception.HPXPError(data=msg)
        size = volume['size']
        if size != src_vref['size']:
            msg = utils.output_log(617, type='volume', volume_id=volume['id'])
            raise exception.HPXPError(data=msg)
        metadata = utils.get_volume_metadata(volume)
        new_ldev, ldev_type = self._copy_ldev(ldev, size, metadata)
        return {
            'provider_location': six.text_type(new_ldev),
            'metadata': dict(
                metadata, ldev=new_ldev,
                type=ldev_type, volume=src_vref['id']),
        }

    @traceutils.measure_exec_time
    @traceutils.trace_function()
    @traceutils.logging_basemethod_exec
    def delete_volume(self, volume):
        ldev = utils.get_ldev(volume)
        # When 'ldev' is 0, it should be true.
        # Therefore, it cannot remove 'is not None'.
        if ldev is None:
            utils.output_log(304, method='delete_volume', id=volume['id'])
            return
        try:
            self._delete_ldev(ldev)
        except exception.HPXPBusy:
            raise exception.HPXPVolumeIsBusy(volume_name=volume['name'])

    @traceutils.measure_exec_time
    @traceutils.trace_function()
    @traceutils.logging_basemethod_exec
    def create_snapshot(self, snapshot):
        src_vref = self.db.volume_get(self.ctxt, snapshot['volume_id'])
        ldev = utils.get_ldev(src_vref)
        # When 'ldev' is 0, it should be true.
        # Therefore, it cannot remove 'is None'.
        if ldev is None:
            msg = utils.output_log(624, type='volume', id=src_vref['id'])
            raise exception.HPXPError(data=msg)
        size = snapshot['volume_size']
        metadata = utils.get_volume_metadata(src_vref)
        new_ldev, ldev_type = self._copy_ldev(ldev, size, metadata)
        if not self.conf.hpxp_driver_cert_mode:
            self.db.snapshot_metadata_update(
                self.ctxt, snapshot['id'],
                dict(ldev=new_ldev, type=ldev_type), False)
        return {
            'provider_location': six.text_type(new_ldev),
        }

    @traceutils.measure_exec_time
    @traceutils.trace_function()
    @traceutils.logging_basemethod_exec
    def delete_snapshot(self, snapshot):
        ldev = utils.get_ldev(snapshot)
        # When 'ldev' is 0, it should be true.
        # Therefore, it cannot remove 'is None'.
        if ldev is None:
            utils.output_log(
                304, method='delete_snapshot', id=snapshot['id'])
            return
        try:
            self._delete_ldev(ldev)
        except exception.HPXPBusy:
            raise exception.HPXPSnapshotIsBusy(snapshot_name=snapshot['name'])

    @traceutils.trace_function(loglevel=traceutils.DEBUG)
    def get_volume_stats(self, refresh=False):
        if refresh:
            if self.storage_info['output_first']:
                self.storage_info['output_first'] = False
                utils.output_log(3, config_group=self.conf.config_group)
            self._update_volume_stats()
        return self._stats

    @traceutils.trace_function(loglevel=traceutils.DEBUG)
    def _update_volume_stats(self):
        d = {}
        backend_name = self.conf.safe_get('volume_backend_name')
        d['volume_backend_name'] = (
            backend_name or self.driver_info['volume_backend_name'])
        d['vendor_name'] = 'Hewlett-Packard'
        d['driver_version'] = VERSION
        d['storage_protocol'] = self.storage_info['protocol']
        try:
            total_gb, free_gb = self.get_pool_info()
        except exception.HPXPError:
            utils.output_log(620, pool=self.conf.hpxp_pool)
            return
        d['total_capacity_gb'] = total_gb
        d['free_capacity_gb'] = free_gb
        d['allocated_capacity_gb'] = 0 if total_gb == 'infinite' else (
            total_gb - free_gb)
        d['reserved_percentage'] = self.conf.safe_get('reserved_percentage')
        d['QoS_support'] = False
        HLOG.debug(_("Updating volume status. (%s)"), d)
        self._stats = d

    def get_pool_info(self):
        raise NotImplementedError()

    @traceutils.trace_function()
    def copy_dest_vol_meta_to_src_vol(self, src_vol, dest_vol):
        metadata = utils.get_volume_metadata(dest_vol)
        try:
            self.db.volume_metadata_update(
                self.ctxt, src_vol['id'], metadata, True)
        except Exception as ex:
            utils.output_log(
                318, src_vol_id=src_vol['id'], dest_vol_id=dest_vol['id'],
                reason=six.text_type(ex))

    def discard_zero_page(self, volume):
        raise NotImplementedError()

    @traceutils.measure_exec_time
    @traceutils.trace_function()
    @traceutils.logging_basemethod_exec
    def extend_volume(self, volume, new_size):
        ldev = utils.get_ldev(volume)
        # When 'ldev' is 0, it should be true.
        # Therefore, it cannot remove 'is None'.
        if ldev is None:
            msg = utils.output_log(613, volume_id=volume['id'])
            raise exception.HPXPError(data=msg)
        if self.check_vvol(ldev):
            msg = utils.output_log(618, volume_id=volume['id'])
            raise exception.HPXPError(data=msg)
        self.delete_pair(ldev)
        self.extend_ldev(ldev, volume['size'], new_size)

    def check_vvol(self, ldev):
        raise NotImplementedError()

    def extend_ldev(self, ldev, old_size, new_size):
        raise NotImplementedError()

    @traceutils.measure_exec_time
    @traceutils.trace_function()
    @traceutils.logging_basemethod_exec
    def manage_existing(self, volume, existing_ref):
        ldev = _str2int(existing_ref.get('ldev'))
        metadata = utils.get_volume_metadata(volume)
        return {
            'provider_location': six.text_type(ldev),
            'metadata': dict(
                metadata, ldev=ldev, type=utils.NORMAL_LDEV_TYPE),
        }

    @traceutils.measure_exec_time
    @traceutils.trace_function()
    @traceutils.logging_basemethod_exec
    def manage_existing_get_size(self, dummy_volume, existing_ref):
        if existing_ref.get('storage_id') != self.conf.hpxp_storage_id:
            msg = utils.output_log(700, param='storage_id')
            raise exception.ManageExistingInvalidReference(
                existing_ref=existing_ref, reason=msg)
        ldev = _str2int(existing_ref.get('ldev'))
        # When 'ldev' is 0, it should be true.
        # Therefore, it cannot remove 'is None'.
        if ldev is None:
            msg = utils.output_log(701)
            raise exception.ManageExistingInvalidReference(
                existing_ref=existing_ref, reason=msg)
        return self.get_ldev_size_in_gigabyte(ldev, existing_ref)

    def get_ldev_size_in_gigabyte(self, ldev, existing_ref):
        raise NotImplementedError()

    @traceutils.measure_exec_time
    @traceutils.trace_function()
    @traceutils.logging_basemethod_exec
    def unmanage(self, volume):
        ldev = utils.get_ldev(volume)
        # When 'ldev' is 0, it should be true.
        # Therefore, it cannot remove 'is None'.
        if ldev is None:
            utils.output_log(304, method='unmanage', id=volume['id'])
            return
        if self.check_vvol(ldev):
            utils.output_log(
                706, volume_id=volume['id'],
                volume_type=utils.NORMAL_LDEV_TYPE)
            raise exception.HPXPVolumeIsBusy(volume_name=volume['name'])
        try:
            self.delete_pair(ldev)
        except exception.HPXPBusy:
            raise exception.HPXPVolumeIsBusy(volume_name=volume['name'])

    @traceutils.measure_exec_time
    @traceutils.trace_function()
    @traceutils.logging_basemethod_exec
    @utils.synchronized('do_setup')
    def do_setup(self, context):
        self.ctxt = context

        self.check_param()
        self.config_lock()
        self.connect_storage()
        self.init_cinder_hosts()
        self.output_param_to_log()

    @traceutils.trace_function()
    def check_param(self):
        utils.check_opt_value(self.conf, _INHERITED_VOLUME_OPTS)
        utils.check_opts(self.conf, opts.COMMON_VOLUME_OPTS)
        utils.check_opts(self.conf, _COMMON_VOLUME_OPTS)
        utils.check_opts(self.conf, self.driver_info['volume_opts'])
        if self.conf.hpxp_default_copy_method not in _COPY_METHOD:
            msg = utils.output_log(
                601, param='hpxp_default_copy_method')
            raise exception.HPXPError(data=msg)
        if (self.conf.hpxp_default_copy_method == 'THIN' and
                not self.conf.hpxp_thin_pool):
            msg = utils.output_log(601, param='hpxp_thin_pool')
            raise exception.HPXPError(data=msg)
        if self.conf.hpxp_ldev_range:
            self.storage_info['ldev_range'] = self._range2list(
                'hpxp_ldev_range')

    @traceutils.trace_function()
    def _range2list(self, param):
        values = [_str2int(x) for x in self.conf.safe_get(param).split('-')]
        if (len(values) != 2 or
                values[0] is None or values[1] is None or
                values[0] > values[1]):
            msg = utils.output_log(601, param=param)
            raise exception.HPXPError(data=msg)
        return values

    def config_lock(self):
        raise NotImplementedError()

    @traceutils.trace_function()
    def connect_storage(self):
        self.storage_info['pool_id'] = self.get_pool_id()
        # When 'pool_id' is 0, it should be true.
        # Therefore, it cannot remove 'is None'.
        if self.storage_info['pool_id'] is None:
            msg = utils.output_log(640, pool=self.conf.hpxp_pool)
            raise exception.HPXPError(data=msg)
        HLOG.info(_LI('Setting pool id: %s'), self.storage_info['pool_id'])

    @traceutils.trace_function()
    def get_pool_id(self):
        pool = self.conf.hpxp_pool
        if pool.isdigit():
            return int(pool)
        return None

    @traceutils.trace_function()
    def init_cinder_hosts(self, **kwargs):
        targets = kwargs.pop('targets', {'info': {}, 'list': []})
        connector = cinder_utils.brick_get_connector_properties()
        target_ports = self.storage_info['ports']

        if (self.find_targets_from_storage(
                targets, connector, target_ports) and
                self.conf.hpxp_group_request):
            self.create_mapping_targets(targets, connector)

        utils.require_target_existed(targets)

    def find_targets_from_storage(self, targets, connector, target_ports):
        raise NotImplementedError()

    @traceutils.trace_function()
    def create_mapping_targets(self, targets, connector):
        hba_ids = self.get_hba_ids_from_connector(connector)
        for port in targets['info'].keys():
            if targets['info'][port]:
                continue

            try:
                self._create_target(targets, port, connector['ip'], hba_ids)
            except exception.HPXPError:
                utils.output_log(
                    self.driver_info['msg_id']['target'], port=port)

        if not targets['list']:
            self.find_targets_from_storage(
                targets, connector, targets['info'].keys())

    @traceutils.trace_function(loglevel=traceutils.DEBUG)
    def get_hba_ids_from_connector(self, connector):
        if self.driver_info['hba_id'] in connector:
            return connector[self.driver_info['hba_id']]
        msg = utils.output_log(650, resource=self.driver_info['hba_id_type'])
        raise exception.HPXPError(data=msg)

    @traceutils.trace_function()
    def _create_target(self, targets, port, ip, hba_ids):
        target_name = '-'.join([utils.DRIVER_PREFIX, ip])
        gid = self.create_target_to_storage(port, target_name, hba_ids)
        HLOG.info(
            _LI('Created target. (port: %(port)s, gid: %(gid)s, '
                'target_name: %(target)s)'),
            {'port': port, 'gid': gid, 'target': target_name})
        try:
            self.set_target_mode(port, gid)
            self.set_hba_ids(port, gid, hba_ids)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.delete_target_from_storage(port, gid)
        targets['info'][port] = True
        targets['list'].append((port, gid))

    def create_target_to_storage(self, port, target_name, hba_ids):
        raise NotImplementedError()

    def set_target_mode(self, port, gid):
        raise NotImplementedError()

    def set_hba_ids(self, port, gid, hba_ids):
        raise NotImplementedError()

    def delete_target_from_storage(self, port, gid):
        raise NotImplementedError()

    @traceutils.trace_function()
    def output_param_to_log(self):
        utils.output_log(1, config_group=self.conf.config_group)
        name, version = self.get_storage_cli_info()
        utils.output_storage_cli_info(name, version)
        utils.output_opt_info(self.conf, _INHERITED_VOLUME_OPTS)
        utils.output_opts(self.conf, opts.COMMON_VOLUME_OPTS)
        utils.output_opts(self.conf, self.driver_info['volume_opts'])

    def get_storage_cli_info(self):
        raise NotImplementedError()

    @traceutils.measure_exec_time
    @traceutils.trace_function()
    @traceutils.logging_basemethod_exec
    def initialize_connection(self, volume, connector):
        targets = {
            'info': {},
            'list': [],
        }
        ldev = utils.get_ldev(volume)
        # When 'ldev' is 0, it should be true.
        # Therefore, it cannot remove 'is None'.
        if ldev is None:
            msg = utils.output_log(619, volume_id=volume['id'])
            raise exception.HPXPError(data=msg)

        target_ports = self.get_target_ports(connector)
        if (self.find_targets_from_storage(
                targets, connector, target_ports) and
                self.conf.hpxp_group_request):
            self.create_mapping_targets(targets, connector)

        utils.require_target_existed(targets)

        targets['list'].sort()
        self.modify_target_mode(volume, targets)
        target_lun = self.map_ldev(targets, ldev)

        conn_info = {
            'driver_volume_type': self.driver_info['volume_type'],
            'data': self.get_properties(volume, targets, target_lun,
                                        connector),
        }

        if self.conf.hpxp_zoning_request:
            init_targ_map = self._build_initiator_target_map(
                connector, conn_info['data']['target_wwn'])
            if init_targ_map:
                conn_info['data']['initiator_target_map'] = init_targ_map

        return conn_info

    @traceutils.trace_function()
    def _build_initiator_target_map(self, connector, target_wwns):
        init_targ_map = {}
        initiator_wwns = connector['wwpns']
        if self._lookup_service:
            dev_map = self._lookup_service.get_device_mapping_from_network(
                initiator_wwns, target_wwns)
            for fabric_name in dev_map:
                fabric = dev_map[fabric_name]
                for initiator in fabric['initiator_port_wwn_list']:
                    init_targ_map[initiator] = fabric['target_port_wwn_list']
        else:
            for initiator in initiator_wwns:
                init_targ_map[initiator] = target_wwns
        return init_targ_map

    @traceutils.trace_function(loglevel=traceutils.DEBUG)
    def get_target_ports(self, connector):
        if connector['ip'] == CONF.my_ip:
            return self.storage_info['ports']
        return (self.storage_info['compute_ports'] or
                self.storage_info['ports'])

    def modify_target_mode(self, volume, targets):
        pass

    def map_ldev(self, targets, ldev):
        raise NotImplementedError()

    @traceutils.trace_function()
    def get_properties(self, volume, targets, target_lun, connector):
        multipath = connector.get('multipath', False)
        if self.storage_info['protocol'] == 'FC':
            d = self.get_properties_fc(targets)
        d['target_discovered'] = False
        d['access_mode'] = self._get_access_mode(volume)
        if not multipath:
            d['target_lun'] = target_lun
        else:
            d['target_luns'] = [target_lun] * len(targets['list'])
        return d

    @traceutils.trace_function()
    def get_properties_fc(self, targets):
        d = {}
        d['target_wwn'] = [
            self.storage_info['wwns'][x] for x in targets['info'].keys()
            if targets['info'][x]]
        return d

    @traceutils.trace_function()
    def _get_access_mode(self, volume):
        if 'id' not in volume:
            return 'rw'
        rv = self.db.volume_admin_metadata_get(self.ctxt, volume['id'])
        admin_metadata = dict(six.iteritems(rv))
        access_mode = admin_metadata.get('attached_mode')
        if not access_mode:
            access_mode = (
                'ro' if admin_metadata.get('readonly') == 'True' else 'rw')
        return access_mode

    @traceutils.measure_exec_time
    @traceutils.trace_function()
    @traceutils.logging_basemethod_exec
    def terminate_connection(self, volume, connector, **dummy_kwargs):
        targets = {
            'info': {},
            'list': [],
        }
        mapped_targets = {
            'list': [],
        }
        unmap_targets = {}

        ldev = utils.get_ldev(volume)
        if ldev is None:
            utils.output_log(302, volume_id=volume['id'])
            return
        target_ports = self.get_target_ports(connector)
        self.find_targets_from_storage(targets, connector, target_ports)
        self.find_mapped_targets_from_storage(
            mapped_targets, ldev, target_ports)

        unmap_targets['list'] = self.get_unmap_targets_list(
            targets['list'], mapped_targets['list'])
        unmap_targets['list'].sort(reverse=True)
        self.unmap_ldev(unmap_targets, ldev)

    def find_mapped_targets_from_storage(self, targets, ldev, target_ports):
        raise NotImplementedError()

    def get_unmap_targets_list(self, target_list, mapped_list):
        raise NotImplementedError()

    def unmap_ldev(self, targets, ldev):
        raise NotImplementedError()

    @traceutils.measure_exec_time
    @traceutils.trace_function()
    @traceutils.logging_basemethod_exec
    def copy_volume_data(self, context, src_vol, dest_vol, remote=None):
        self.copy_dest_vol_meta_to_src_vol(src_vol, dest_vol)
        self.discard_zero_page(dest_vol)

    @traceutils.measure_exec_time
    @traceutils.trace_function()
    @traceutils.logging_basemethod_exec
    def copy_image_to_volume(self, context, volume, image_service, image_id):
        self.discard_zero_page(volume)

    @traceutils.measure_exec_time
    @traceutils.trace_function()
    @traceutils.logging_basemethod_exec
    def restore_backup(self, context, backup, volume, backup_service):
        self.discard_zero_page(volume)
