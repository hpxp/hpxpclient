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
Exception class for Hewlett Packard Enterprise storage drivers.

"""

from cinder import exception
from cinder.i18n import _

ManageExistingInvalidReference = exception.ManageExistingInvalidReference


class HPEXPError(exception.VolumeBackendAPIException):
    pass


class HPEXPBusy(HPEXPError):
    message = _("Device or resource is busy.")


class HPEXPNotImplementedError(NotImplementedError):
    message = _("Specified storage function is not implemented.")


class HPEXPNotFound(exception.NotFound):
    message = _("Storage resource could not be found.")


class HPEXPVolumeIsBusy(exception.VolumeIsBusy):
    message = _("Volume %(volume_name)s is busy.")


class HPEXPSnapshotIsBusy(exception.SnapshotIsBusy):
    message = _("Snapshot %(snapshot_name)s is busy.")
