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

import functools
import inspect
import logging as base_logging
import os
import re

from oslo_concurrency import processutils as putils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import timeutils
from oslo_utils import units
import six

from cinder.i18n import _
from cinder import utils as cinder_utils
from cinder.volume.drivers.hpe import hpe_xp_exception as exception

_DRIVER_DIR = 'cinder.volume.drivers.hpe'

_DRIVERS = {
    'HORCM': {
        'FC': 'hpe_xp_horcm_fc.HPEXPHORCMFC',
    },
}

DRIVER_PREFIX = 'HPEXP'
TARGET_PREFIX = DRIVER_PREFIX + '-'
GIGABYTE_PER_BLOCK_SIZE = units.Gi / 512

DEFAULT_TRY_RANGE = xrange(3)
MAX_PROCESS_WAITTIME = 24 * 60 * 60
DEFAULT_PROCESS_WAITTIME = 15 * 60

NORMAL_LDEV_TYPE = 'Normal'
NVOL_LDEV_TYPE = 'THP V-VOL'
VVOL_LDEV_TYPE = 'V-VOL'

FULL = 'Full copy'
THIN = 'Thin copy'
LOGLEVEL = base_logging.WARNING

INFO_SUFFIX = 'I'
WARNING_SUFFIX = 'W'
ERROR_SUFFIX = 'E'

MSG_TABLE = {
    1: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'The parameter of the storage backend. '
            '(config_group: %(config_group)s)'),
        'suffix': INFO_SUFFIX,
    },
    3: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'The storage backend can be used. '
            '(config_group: %(config_group)s)'),
        'suffix': INFO_SUFFIX,
    },
    300: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'Failed to configure the internal logging. '
            '(ret: %(ret)s, stderr: %(err)s)'),
        'suffix': WARNING_SUFFIX,
    },
    302: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'Failed to specify a logical device '
            'for the volume %(volume_id)s to be unmapped.'),
        'suffix': WARNING_SUFFIX,
    },
    304: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'Failed to specify a logical device to be deleted. '
            '(method: %(method)s, id: %(id)s)'),
        'suffix': WARNING_SUFFIX,
    },
    306: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'A host group could not be deleted. '
            '(port: %(port)s, gid: %(id)s)'),
        'suffix': WARNING_SUFFIX,
    },
    307: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'An iSCSI target could not be deleted. '
            '(port: %(port)s, tno: %(id)s)'),
        'suffix': WARNING_SUFFIX,
    },
    308: {
        'loglevel': base_logging.WARNING,
        'msg': _('A host group could not be added. (port: %(port)s)'),
        'suffix': WARNING_SUFFIX,
    },
    309: {
        'loglevel': base_logging.WARNING,
        'msg': _('An iSCSI target could not be added. (port: %(port)s)'),
        'suffix': WARNING_SUFFIX,
    },
    310: {
        'loglevel': base_logging.WARNING,
        'msg': _('Failed to unmap a logical device. (LDEV: %(ldev)s)'),
        'suffix': WARNING_SUFFIX,
    },
    312: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'Failed to get a storage resource. The system will attempt '
            'to get the storage resource again. (resource: %(resource)s)'),
        'suffix': WARNING_SUFFIX,
    },
    313: {
        'loglevel': base_logging.WARNING,
        'msg': _('Failed to delete a logical device. (LDEV: %(ldev)s)'),
        'suffix': WARNING_SUFFIX,
    },
    314: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'Failed to map a logical device. (LDEV: %(ldev)s, '
            'port: %(port)s, id: %(id)s, lun: %(lun)s)'),
        'suffix': WARNING_SUFFIX,
    },
    315: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'Failed to perform a zero-page reclamation. (LDEV: %(ldev)s)'),
        'suffix': WARNING_SUFFIX,
    },
    317: {
        'loglevel': base_logging.WARNING,
        'msg': _('Failed to assign the WWN. '
                 '(port: %(port)s, gid: %(gid)s, wwn: %(wwn)s)'),
        'suffix': WARNING_SUFFIX,
    },
    318: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'Failed to copy meta data of destination volume %(dest_vol_id)s '
            'to source volume %(src_vol_id)s. (reason: %(reason)s)'),
        'suffix': WARNING_SUFFIX,
    },
    319: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'The logical device does not exist in the storage system. '
            '(LDEV: %(ldev)s)'),
        'suffix': WARNING_SUFFIX,
    },
    320: {
        'loglevel': base_logging.WARNING,
        'msg': _('Failed to start HORCM. (inst: %(inst)s)'),
        'suffix': WARNING_SUFFIX,
    },
    322: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'Failed to reload the configuration of full copy pair. '
            '(inst: %(inst)s)'),
        'suffix': WARNING_SUFFIX,
    },
    323: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'Failed to perform user authentication of HORCM. '
            '(user: %(user)s)'),
        'suffix': WARNING_SUFFIX,
    },
    324: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'Failed to delete full copy pair. '
            '(P-VOL: %(pvol)s, S-VOL: %(svol)s)'),
        'suffix': WARNING_SUFFIX,
    },
    325: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'Failed to delete thin copy pair. '
            '(P-VOL: %(pvol)s, S-VOL: %(svol)s)'),
        'suffix': WARNING_SUFFIX,
    },
    326: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'Failed to change the status of full copy pair. '
            '(P-VOL: %(pvol)s, S-VOL: %(svol)s)'),
        'suffix': WARNING_SUFFIX,
    },
    327: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'Failed to delete the configuration of full copy pair. '
            '(P-VOL: %(pvol)s, S-VOL: %(svol)s)'),
        'suffix': WARNING_SUFFIX,
    },
    329: {
        'loglevel': base_logging.WARNING,
        'msg': _(
            'Failed to detach the logical device. '
            '(LDEV: %(ldev)s, reason: %(reason)s)'),
        'suffix': WARNING_SUFFIX,
    },
    600: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'The command %(cmd)s failed. '
            '(ret: %(ret)s, stdout: %(out)s, stderr: %(err)s)'),
        'suffix': ERROR_SUFFIX,
    },
    601: {
        'loglevel': base_logging.ERROR,
        'msg': _('A parameter is invalid. (%(param)s)'),
        'suffix': ERROR_SUFFIX,
    },
    602: {
        'loglevel': base_logging.ERROR,
        'msg': _('A parameter value is invalid. (%(meta)s)'),
        'suffix': ERROR_SUFFIX,
    },
    606: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'The snapshot %(snapshot_id)s cannot be deleted, '
            'because a read-only volume for the snapshot exists.'),
        'suffix': ERROR_SUFFIX,
    },
    608: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'Failed to shutdown HORCM. (inst: %(inst)s)'),
        'suffix': ERROR_SUFFIX,
    },
    609: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'Failed to restart HORCM. (inst: %(inst)s)'),
        'suffix': ERROR_SUFFIX,
    },
    610: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'The status change of full copy pair could not be completed. '
            '(S-VOL: %(svol)s)'),
        'suffix': ERROR_SUFFIX,
    },
    611: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'The status change of thin copy pair could not be completed. '
            '(S-VOL: %(svol)s)'),
        'suffix': ERROR_SUFFIX,
    },
    612: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'The source logical device to be replicated does not exist '
            'in the storage system. (LDEV: %(ldev)s)'),
        'suffix': ERROR_SUFFIX,
    },
    613: {
        'loglevel': base_logging.ERROR,
        'msg': _('The volume %(volume_id)s to be extended was not found.'),
        'suffix': ERROR_SUFFIX,
    },
    614: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'No WWN is assigned. '
            '(port: %(port)s, gid: %(gid)s)'),
        'suffix': ERROR_SUFFIX,
    },
    615: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'A pair could not be created. '
            'The maximum number of pair is exceeded. '
            '(copy method: %(copy_method)s, P-VOL: %(pvol)s)'),
        'suffix': ERROR_SUFFIX,
    },
    616: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'A pair cannot be deleted. '
            '(P-VOL: %(pvol)s, S-VOL: %(svol)s)'),
        'suffix': ERROR_SUFFIX,
    },
    617: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'The specified operation is not supported. '
            'The volume size must be the same as the source %(type)s. '
            '(volume: %(volume_id)s)'),
        'suffix': ERROR_SUFFIX,
    },
    618: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'The volume %(volume_id)s could not be extended. '
            'The volume type must be Normal.'),
        'suffix': ERROR_SUFFIX,
    },
    619: {
        'loglevel': base_logging.ERROR,
        'msg': _('The volume %(volume_id)s to be mapped was not found.'),
        'suffix': ERROR_SUFFIX,
    },
    620: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'Failed to provide information about a pool. (pool: %(pool)s)'),
        'suffix': ERROR_SUFFIX,
    },
    624: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'The %(type)s %(id)s source to be replicated was not found.'),
        'suffix': ERROR_SUFFIX,
    },
    632: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'Failed to open a file. (file: %(file)s, ret: %(ret)s, '
            'stderr: %(err)s)'),
        'suffix': ERROR_SUFFIX,
    },
    634: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'Failed to attach the logical device. '
            '(LDEV: %(ldev)s, reason: %(reason)s)'),
        'suffix': ERROR_SUFFIX,
    },
    636: {
        'loglevel': base_logging.ERROR,
        'msg': _('Failed to add the logical device.'),
        'suffix': ERROR_SUFFIX,
    },
    638: {
        'loglevel': base_logging.ERROR,
        'msg': _('Failed to add the pair target.'),
        'suffix': ERROR_SUFFIX,
    },
    639: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'Failed to map a logical device to any pair targets. '
            '(LDEV: %(ldev)s)'),
        'suffix': ERROR_SUFFIX,
    },
    640: {
        'loglevel': base_logging.ERROR,
        'msg': _('A pool could not be found. (pool: %(pool)s)'),
        'suffix': ERROR_SUFFIX,
    },
    648: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'There are no resources available for use. '
            '(resource: %(resource)s)'),
        'suffix': ERROR_SUFFIX,
    },
    649: {
        'loglevel': base_logging.ERROR,
        'msg': _('The host group or iSCSI target was not found.'),
        'suffix': ERROR_SUFFIX,
    },
    650: {
        'loglevel': base_logging.ERROR,
        'msg': _('The resource %(resource)s was not found.'),
        'suffix': ERROR_SUFFIX,
    },
    652: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'Failed to delete a logical device. '
            '(LDEV: %(ldev)s)'),
        'suffix': ERROR_SUFFIX,
    },
    653: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'The creation of a logical device could not be '
            'completed. (LDEV: %(ldev)s)'),
        'suffix': ERROR_SUFFIX,
    },
    656: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'The volume %(volume_id)s could not be restored. '
            '(reason: %(reason)s)'),
        'suffix': ERROR_SUFFIX,
    },
    657: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'A read-only volume cannot be created from the snapshot '
            '%(snapshot_id)s. A read-only volume already exists.'),
        'suffix': ERROR_SUFFIX,
    },
    700: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'No valid value is specified for \"%(param)s\". A valid value '
            'must be specified for \"%(param)s\" to manage the volume.'),
        'suffix': ERROR_SUFFIX,
    },
    701: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'No valid value is specified for \"ldev\". A valid value '
            'must be specified for \"ldev\" to manage the volume.'),
        'suffix': ERROR_SUFFIX,
    },
    702: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'Failed to manage the specified LDEV (%(ldev)s). '
            'The LDEV must be an unpaired %(ldevtype)s.'),
        'suffix': ERROR_SUFFIX,
    },
    703: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'Failed to manage the specified LDEV (%(ldev)s). '
            'The LDEV size must be expressed in gigabytes.'),
        'suffix': ERROR_SUFFIX,
    },
    704: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'Failed to manage the specified LDEV (%(ldev)s). '
            'The LDEV must not be mapped.'),
        'suffix': ERROR_SUFFIX,
    },
    706: {
        'loglevel': base_logging.ERROR,
        'msg': _(
            'Failed to unmanage the volume %(volume_id)s. '
            'The volume type must be %(volume_type)s.'),
        'suffix': ERROR_SUFFIX,
    },
}

LOG = logging.getLogger(__name__)


def synchronized(key):
    def wrap(func):
        @functools.wraps(func)
        def inner(self, *args, **kwargs):
            @cinder_utils.synchronized(self.lock[key], external=True)
            def _inner(*_args, **_kargs):
                return func(*_args, **_kargs)
            return _inner(self, *args, **kwargs)
        return inner
    return wrap


def output_log(msg_id, **kwargs):
    msgs = MSG_TABLE.get(msg_id)
    msg = msgs['msg'] % kwargs
    LOG.log(msgs['loglevel'], "MSGID%04d-%s: %s", msg_id, msgs['suffix'], msg)
    return msg


def get_ldev(obj):
    if not obj:
        return None
    ldev = obj.get('provider_location')
    if not ldev or not ldev.isdigit():
        return None
    return int(ldev)


def check_timeout(start_time, timeout):
    if timeutils.is_older_than(start_time, timeout):
        return True
    return False


def execute(*cmd, **kwargs):
    process_input = kwargs.pop('process_input', None)
    run_as_root = kwargs.pop('run_as_root', True)
    ret = 0
    try:
        stdout, stderr = cinder_utils.execute(
            *cmd, process_input=process_input, run_as_root=run_as_root)[:2]
    except putils.ProcessExecutionError as ex:
        ret = ex.exit_code
        stdout = ex.stdout
        stderr = ex.stderr
        LOG.debug('cmd: %s', ' '.join([six.text_type(c) for c in cmd]))
        LOG.debug('from: %s', inspect.stack()[2])
        LOG.debug('ret: %s', ret)
        LOG.debug('stdout: %s', ' '.join(stdout.splitlines()))
        LOG.debug('stderr: %s', ' '.join(stderr.splitlines()))
    return ret, stdout, stderr


def import_object(conf, storage_protocol, **kwargs):
    os.environ['LANG'] = 'C'
    cli = _DRIVERS.get(conf.hpexp_storage_cli)
    if not cli:
        msg = output_log(601, param='hpexp_storage_cli')
        raise exception.HPEXPError(data=msg)
    return importutils.import_object(
        '.'.join([_DRIVER_DIR, cli[storage_protocol]]),
        conf, storage_protocol, **kwargs)


def check_ignore_error(ignore_error, stderr):
    if not ignore_error or not stderr:
        return False
    if not isinstance(ignore_error, six.string_types):
        ignore_error = '|'.join(ignore_error)

    if re.search(ignore_error, stderr):
        return True
    return False


def check_opts(conf, opts):
    names = []
    for opt in opts:
        # @ (#) Check that opts marked as required have values specified.
        if opt.required and not conf.safe_get(opt.name):
            msg = output_log(601, param=opt.name)
            raise exception.HPEXPError(data=msg)
        names.append(opt.name)
    # @ (#) Check whether there are the valid value of options.
    check_opt_value(conf, names)


def check_opt_value(conf, names):
    for name in names:
        try:
            getattr(conf, name)
        except (cfg.NoSuchOptError, cfg.ConfigFileValueError):
            with excutils.save_and_reraise_exception():
                output_log(601, param=name)


def output_storage_cli_info(name, version):
    LOG.log(LOGLEVEL, '\t%-35s%s', name + ' version: ', version)


def output_opt_info(conf, names):
    for name in names:
        LOG.log(LOGLEVEL, '\t%-35s%s', name + ': ', getattr(conf, name))


def output_opts(conf, opts):
    names = [opt.name for opt in opts if not opt.secret]
    output_opt_info(conf, names)


def require_target_existed(targets):
    if not targets['list']:
        msg = output_log(649)
        raise exception.HPEXPError(data=msg)


def get_volume_metadata(volume):
    volume_metadata = volume.get('volume_metadata', {})
    return {item['key']: item['value'] for item in volume_metadata}
