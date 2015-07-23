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
"""
Extension class for Hewlett-Packard storage drivers.

"""

import logging as base_logging

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
import six

from cinder import exception as cinder_exception
from cinder import utils as cinder_utils
from cinder.volume.drivers.san.hp import hp_xp_common as common
from cinder.volume.drivers.san.hp import hp_xp_exception as exception
from cinder.volume.drivers.san.hp import hp_xp_traceutils as traceutils
from cinder.volume.drivers.san.hp import hp_xp_utils as utils

_ACCESS_MODE = set(['rw', 'ro'])

_INVALID_LDEV_NUM = '-1'

_HLOG_FILENAME = '/var/log/hpxp/debug.log'
_HLOG_FORMAT_STRING = '%(asctime)s %(process)d %(thread)s %(message)s'

_MSG_LEVEL = {
    'critical': base_logging.CRITICAL,
    'error': base_logging.ERROR,
    'warning': base_logging.WARNING,
    'info': base_logging.INFO,
    'debug': base_logging.DEBUG,
}

_VOLUME_OPTS = [
    cfg.StrOpt('hpxp_debug_level',
               default="info",
               secret=True,
               help='Debug level for the storage backend'),
]

CONF = cfg.CONF
CONF.register_opts(_VOLUME_OPTS)

HLOG = logging.getLogger(traceutils.HLOG_NAME)


@traceutils.trace_function()
def _get_access_mode(volume):
    metadata = utils.get_volume_metadata(volume)
    access_mode = metadata.get('access_mode', 'rw')

    if access_mode not in _ACCESS_MODE:
        msg = utils.output_log(602, meta='access_mode')
        raise exception.HPXPError(data=msg)

    return access_mode


@traceutils.trace_function()
def _get_snapshot_metadata(snapshot):
    snapshot_metadata = snapshot.get('metadata', {})
    return {item['key']: item['value'] for item in snapshot_metadata}


class HPXPCommonExtension(common.HPXPCommon):

    def __init__(self, conf, storage_protocol, **kwargs):
        super(HPXPCommonExtension, self).__init__(
            conf, storage_protocol, **kwargs)
        self.conf.append_config_values(_VOLUME_OPTS)

    @traceutils.trace_function()
    def create_volume_from_snapshot(self, volume, snapshot):
        ldev = utils.get_ldev(snapshot)

        # When 'ldev' is 0, it should be true.
        # Therefore, it cannot remove 'is not None'.
        if (ldev is not None and self.check_vvol(ldev) and
                _get_access_mode(volume) == 'ro'):

            if 'ro_vol' in _get_snapshot_metadata(snapshot):
                msg = utils.output_log(657, snapshot_id=snapshot['id'])
                raise exception.HPXPError(data=msg)

            self.db.snapshot_metadata_update(
                self.ctxt, snapshot['id'], dict(ro_vol=volume['id']), False)

            metadata = utils.get_volume_metadata(volume)

            return {
                'provider_location': six.text_type(ldev),
                'metadata': dict(
                    metadata, ldev=ldev, type=utils.VVOL_LDEV_TYPE,
                    snapshot=snapshot['id']),
            }

        return super(
            HPXPCommonExtension, self).create_volume_from_snapshot(
                volume, snapshot)

    @traceutils.trace_function()
    def create_cloned_volume(self, volume, src_vref):
        ldev = utils.get_ldev(src_vref)
        metadata = utils.get_volume_metadata(volume)
        # When 'ldev' is 0, it should be true.
        # Therefore, it cannot remove 'is not None'.
        method = (
            self.get_copy_method(metadata)
            if ldev is not None and not self.check_vvol(ldev) else None)

        if 'restore_from' in metadata and method == 'THIN':
            self._restore_volume_from_volume(
                src_vref, metadata['restore_from'])

            return {
                'provider_location': _INVALID_LDEV_NUM,
            }

        return super(
            HPXPCommonExtension, self).create_cloned_volume(volume, src_vref)

    @traceutils.trace_function()
    def _restore_volume_from_snapshot(self, volume, snapshot_id):
        # Make sure the snapshot is not deleted until we are done with it.
        locked_action = '-'.join([snapshot_id, 'delete_snapshot'])

        @cinder_utils.synchronized(locked_action, external=True)
        def _run_locked_restore(volume, snapshot_id):
            try:
                snapshot = self.db.snapshot_get(self.ctxt, snapshot_id)
            except cinder_exception.SnapshotNotFound:
                with excutils.save_and_reraise_exception():
                    utils.output_log(
                        656, volume_id=volume['id'],
                        reason='Invalid input: %s' % snapshot_id)
            pvol = utils.get_ldev(volume)
            svol = utils.get_ldev(snapshot)
            # When 'ldev' is 0, it should be true.
            # Therefore, it cannot remove 'is None'.
            if svol is None or not self.has_thin_copy_pair(pvol, svol):
                msg = utils.output_log(
                    656, volume_id=volume['id'],
                    reason='Invalid input: %s' % snapshot_id)
                raise exception.HPXPError(data=msg)
            if volume['status'] != 'available':
                msg = utils.output_log(
                    656, volume_id=volume['id'],
                    reason='Status of target volume %(volume_id)s '
                           'is not available: %(status)s' % {
                               'volume_id': volume['id'],
                               'status': volume['status']})
                raise exception.HPXPError(data=msg)
            if snapshot['status'] != 'available':
                msg = utils.output_log(
                    656, volume_id=volume['id'],
                    reason='Status of source snapshot %(snapshot_id)s '
                           'is not available: %(status)s' % {
                               'snapshot_id': snapshot_id,
                               'status': snapshot['status']})
                raise exception.HPXPError(data=msg)

            self.restore_ldev(pvol, svol)

        _run_locked_restore(volume, snapshot_id)

    @traceutils.trace_function()
    def _restore_volume_from_volume(self, volume, volume_id):
        if volume['id'] == volume_id:
            msg = utils.output_log(
                656, volume_id=volume['id'],
                reason='Invalid input: %s' % volume_id)
            raise exception.HPXPError(data=msg)

        # Make sure the volume is not deleted until we are done with it.
        locked_action = '-'.join([volume_id, 'delete_volume'])

        @cinder_utils.synchronized(locked_action, external=True)
        def _run_locked_restore(volume, volume_id):
            try:
                src_vref = self.db.volume_get(self.ctxt, volume_id)
            except cinder_exception.VolumeNotFound:
                with excutils.save_and_reraise_exception():
                    utils.output_log(
                        656, volume_id=volume['id'],
                        reason='Invalid input: %s' % volume_id)
            pvol = utils.get_ldev(volume)
            svol = utils.get_ldev(src_vref)
            # When 'ldev' is 0, it should be true.
            # Therefore, it cannot remove 'is None'.
            if (volume['id'] == volume_id or svol is None or
                    not self.has_thin_copy_pair(pvol, svol)):
                msg = utils.output_log(
                    656, volume_id=volume['id'],
                    reason='Invalid input: %s' % volume_id)
                raise exception.HPXPError(data=msg)
            if volume['status'] != 'available':
                msg = utils.output_log(
                    656, volume_id=volume['id'],
                    reason='Status of target volume %(volume_id)s '
                           'is not available: %(status)s' % {
                               'volume_id': volume['id'],
                               'status': volume['status']})
                raise exception.HPXPError(data=msg)
            if src_vref['status'] != 'available':
                msg = utils.output_log(
                    656, volume_id=volume['id'],
                    reason='Status of source volume %(volume_id)s '
                           'is not available: %(status)s' % {
                               'volume_id': volume_id,
                               'status': src_vref['status']})
                raise exception.HPXPError(data=msg)

            self.restore_ldev(pvol, svol)

        _run_locked_restore(volume, volume_id)

    def has_thin_copy_pair(self, pvol, svol):
        raise NotImplementedError()

    def restore_ldev(self, pvol, svol):
        raise NotImplementedError()

    @traceutils.trace_function()
    def delete_volume(self, volume):
        if volume['snapshot_id'] and self._get_ro_vol(volume) == volume['id']:
            self.db.snapshot_metadata_delete(
                self.ctxt, volume['snapshot_id'], 'ro_vol')
            return

        super(HPXPCommonExtension, self).delete_volume(volume)

    @traceutils.trace_function()
    def _get_ro_vol(self, volume):
        ldev = utils.get_ldev(volume)

        # When 'ldev' is 0, it should be true.
        # Therefore, it cannot remove 'is None'.
        if ldev is None or not self.check_vvol(ldev):
            return None

        try:
            snapshot = self.db.snapshot_get(self.ctxt, volume['snapshot_id'])
        except cinder_exception.SnapshotNotFound:
            return None

        return _get_snapshot_metadata(snapshot).get('ro_vol')

    @traceutils.trace_function()
    def create_snapshot(self, snapshot):
        src_vref = self.db.volume_get(self.ctxt, snapshot['volume_id'])
        ldev = utils.get_ldev(src_vref)
        metadata = utils.get_volume_metadata(src_vref)
        # When 'ldev' is 0, it should be true.
        # Therefore, it cannot remove 'is not None'.
        method = (
            self.get_copy_method(metadata)
            if ldev is not None and not self.check_vvol(ldev) else None)

        if 'restore_from' in metadata and method == 'THIN':
            self._restore_volume_from_snapshot(
                src_vref, metadata['restore_from'])
            return {
                'provider_location': _INVALID_LDEV_NUM,
            }

        return super(HPXPCommonExtension, self).create_snapshot(snapshot)

    @traceutils.trace_function()
    def delete_snapshot(self, snapshot):
        ldev = utils.get_ldev(snapshot)

        # When 'ldev' is 0, it should be true.
        # Therefore, it cannot remove 'is not None'.
        if (ldev is not None and self.check_vvol(ldev) and
                'ro_vol' in _get_snapshot_metadata(snapshot)):
            utils.output_log(606, snapshot_id=snapshot['id'])
            raise exception.HPXPSnapshotIsBusy(
                snapshot_name=snapshot['name'])

        super(HPXPCommonExtension, self).delete_snapshot(snapshot)

    @traceutils.trace_function()
    def unmanage(self, volume):
        if self._get_ro_vol(volume) == volume['id']:
            self.db.snapshot_metadata_delete(
                self.ctxt, volume['snapshot_id'], 'ro_vol')
        else:
            super(HPXPCommonExtension, self).unmanage(volume)

    def do_setup(self, context):
        self._init_hlog()
        super(HPXPCommonExtension, self).do_setup(context)

    @utils.synchronized('do_setup')
    def _init_hlog(self):
        if not HLOG.logger.propagate:
            return
        HLOG.logger.propagate = False

        try:
            open(_HLOG_FILENAME, 'a+')
        except EnvironmentError as ex:
            utils.output_log(300, ret=ex.errno, err=ex.strerror)
            return

        msg_level = _MSG_LEVEL.get(
            self.conf.hpxp_debug_level, base_logging.DEBUG)

        handler = base_logging.handlers.WatchedFileHandler(
            _HLOG_FILENAME, delay=True)
        handler.setFormatter(base_logging.Formatter(_HLOG_FORMAT_STRING))

        HLOG.logger.setLevel(msg_level)
        HLOG.logger.addHandler(handler)

    @traceutils.trace_function()
    def get_properties(self, volume, targets, target_lun, connector):
        d = super(
            HPXPCommonExtension, self).get_properties(
                volume, targets, target_lun, connector)
        if _get_access_mode(volume) == 'ro':
            d['access_mode'] = 'ro'
        return d
