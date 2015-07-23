# Copyright (C) 2014, Hitachi, Ltd.
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

from oslo_utils import timeutils

from cinder.i18n import _, _LI
from oslo_log import log as logging

_MSG = {
    0: _('The method %(method)s was called. (config_group: %(config_group)s)'),
    2: _(
        'The method %(method)s completed successfully. '
        '(config_group: %(config_group)s)'),
}

HLOG_NAME = 'hpxp_debug'
DEBUG = base_logging.DEBUG

LOG = logging.getLogger(__name__)
HLOG = logging.getLogger(HLOG_NAME)


def trace_function(loglevel=base_logging.ERROR):
    def wrap(func):
        @functools.wraps(func)
        def inner(*args, **kwargs):
            _args = inspect.getargvalues(inspect.stack()[0][0])
            line_num = inspect.stack()[1][2]
            HLOG.log(loglevel, "(%s) from: %s", line_num, inspect.stack()[1])
            HLOG.log(loglevel, "(%s) args: %s",
                     line_num, _args.locals["args"])
            ret = func(*args, **kwargs)
            HLOG.log(loglevel, "(%s) ret : %s", line_num, ret)
            return ret
        return inner
    return wrap


def measure_exec_time(func):
    @functools.wraps(func)
    def wrap(*args, **kwargs):
        start_time = timeutils.utcnow()
        ret = func(*args, **kwargs)
        duration = timeutils.delta_seconds(start_time, timeutils.utcnow())
        HLOG.info(_LI("processing time %(name)s: %(time)f [s]"),
                  {'name': func.__name__, 'time': duration})
        return ret
    return wrap


def logging_basemethod_exec(func):
    @functools.wraps(func)
    def wrap(self, *args, **kwargs):
        def inner(*_args, **_kwargs):
            msg_kwargs = {
                'method': func.func_name,
                'config_group': self.conf.config_group,
            }
            LOG.info(_LI("MSGID%(msgid)04d-I: %(msg)s"),
                     {'msgid': 0, 'msg': _MSG[0] % msg_kwargs})
            ret = func(*_args, **_kwargs)
            LOG.info(_LI("MSGID%(msgid)04d-I: %(msg)s"),
                     {'msgid': 2, 'msg': _MSG[2] % msg_kwargs})
            return ret
        return inner(self, *args, **kwargs)
    return wrap
