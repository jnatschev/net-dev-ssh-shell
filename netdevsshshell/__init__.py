# -*- coding: utf-8 -*-
# netdevsshshell: a python interactive ssh shell depending on paramiko for the
# ssh shell and regex for determining the ssh shell prompt signifying the end
# of the full output of an executed command.
# Copyright (C) 2021 John Natschev <jnatschev@icloud.com>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# paramiko:
# see https://github.com/paramiko/paramiko/blob/main/LICENSE
# regex:
# see https://github.com/mrabarnett/mrab-regex/blob/hg/LICENSE.txt
#
"""
netdevsshshell is a python interactive ssh shell depending on paramiko for the
ssh shell and regex for determining the ssh shell prompt signifying the end of
the full output of an executed command.

The idea behind the creation of this program is
- simplicity of use:
  in essence, a secure shell client replacement. This program does provide minor
  enhancements to enable users of this program to:
  - preset the shell prompt regualar expression;
  - execute a network device "no pagination" command.
- change management governance:
  all ssh shell output is stored in an attribute. The ssh shell output may then
  be written to a file and this file may be added to a change record as a
  transcript of the ssh shell session, demonstrating adherence to a change
  record implementation plan.

netdevsshshell depends on paramiko and regex.
- Paramiko provides netdevsshshell the ssh shell capability.
  https://paramiko.org

- Regex provides alternative regular expression processing capability. Namely
  the use of POSIX regular expression character classes.
  https://github.com/mrabarnett/mrab-regex
"""
import paramiko
import regex as re
from .netdevsshshell import (
    NetDevSshShell, ShellCliTypeError, ShellClosedError,
    ShellSendError, ShellTimeoutError
)

__all__ = [
    'NetDevSshShell',
    'ShellCliTypeError',
    'ShellClosedError',
    'ShellSendError',
    'ShellTimeoutError',
    'paramiko',
    're'
]

__version_info__ = (2, 0, 0)
__version__ = '{}.{}.{}'.format(*__version_info__)
__author__ = 'John Natschev <jnatschev@icloud.com>'
__copying__ = 'LGPL-3.0-or-later'
__license__ = __copying__
