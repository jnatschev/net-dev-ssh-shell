# -*- coding: utf-8 -*-
# netdevsshshell: a python ssh shell that uses paramiko and regex for accessing
# the command-line shell of a network device; a network device such as a router
# or switch.
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
netdevsshshell is a python program with the intent that is a portable
replacement for a an operating system dependent ssh client for accessing network
devices with a command-line interface (CLI) "shell". For example:
- Arista switches
- Aruba switches
- Cisco routers
- Cisco switches
- Cisco Wireless LAN Controllers (WLCs)
- Juniper routers
- Juniper switches

NOTE:
    As an SSH client, this program will work with *nix-like CLI shells, such as
    bash and zsh. Other CLI shells will probably work too, however bash and zsh
    are the only two CLI shells tested against.

In fact, any network device that supports the following shell CLI commands:
- show version
  'show version' is used to determine the Shell CLI Type.
- terminal length 0 or set cli screen-length
  Dependant on the shell CLI type, the purpose of these commands is to turn
  off pagination. If a device has a different command to turn off pagination,
  then this program may be extended to support that.

Another reason for the development of this program is Change Governance. That
is, the received bytes of shell output is stored. This provides the user the
capability saving the ssh session transcript to a file and the file may be
attached to a change record as evidence of the configuration change. Therefore,
it is down to the user of this program to manage the size of the attribute
storing the received bytes.

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
