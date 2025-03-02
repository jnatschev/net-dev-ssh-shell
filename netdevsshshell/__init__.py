# -*- coding: utf-8 -*-
# netdevsshshell: a python ssh interactive shell.
# Copyright (C) 2021 John Natschev <jnatschev@icloud.com>
#
# This file is part of netdevsshshell. netdevsshshell is free software:
# you can redistribute it and / or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version.
#
# netdevsshshell is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# netdevsshshell.If not, see < https:// www.gnu.org / licenses / >.
#
# paramiko:
# see https://github.com/paramiko/paramiko/blob/main/LICENSE
# regex:
# see https://github.com/mrabarnett/mrab-regex/blob/hg/LICENSE.txt
#
"""
netdevsshshell is a python ssh interactive shell.

The idea behind the creation of this program is:
- simplicity of use:
  in essence, a secure shell client replacement. This program does provide minor
  enhancements to enable users of this program to:
  - preset the shell prompt regular expression;
    regex is used as the regular expression engine to enable the use of POSIX
    character classes.
  - execute a network device "no pagination" command;
  - use a secure shell jump host to reach the target ssh server. The equivalent
    of the OpenSSH -J option.
- change management governance:
  all ssh shell output is stored in an attribute. The ssh shell output may then
  be written to a file and this file may be added to a change record as a
  transcript of the ssh shell session, demonstrating adherence to a change
  record implementation plan.

netdevsshshell depends on paramiko and regex.
- Paramiko provides netdevsshshell the ssh shell capability.
  https://paramiko.org

- Regex provides alternative regular expression processing capability. Namely,
  the use of POSIX regular expression character classes.
  https://github.com/mrabarnett/mrab-regex
"""
import paramiko
import regex as re

from .devicetype import DeviceTypeIos, DeviceTypeJunos, DeviceTypeNix
from .netdevsshshell import (NetDevSshShell, ShellCliTypeError,
                             ShellClosedError, ShellSendError,
                             ShellTimeoutError)

__all__ = [
    'paramiko',
    're',
    'DeviceTypeNix',
    'DeviceTypeIos',
    'DeviceTypeJunos',
    'NetDevSshShell',
    'ShellCliTypeError',
    'ShellClosedError',
    'ShellSendError',
    'ShellTimeoutError',
]

__version_info__ = (0, 1, 0)
__version__ = '{}.{}.{}'.format(*__version_info__)
__author__ = 'John Natschev <jnatschev@icloud.com>'
__copying__ = 'GPL-3.0-or-later'
__license__ = __copying__
