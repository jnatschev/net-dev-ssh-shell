# -*- coding: utf-8 -*-
# Copyright (C) 2021 John Natschev <jnatschev@icloud.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
netdevsshshell is a Python module to establish a ssh shell with a network
device. A network device is a Cisco-like and JunOs-like network device, such as
routers and switches.

This programming is based on:
`paramiko.SSHClient`
and more particularly:
`paramiko.SSHClient().connect().invoke_shell()`

The purpose of this program is to provide a ssh shell to network devices and
execute (send) a number of commands to the network device. It was found that
other `ssh` implementations will `ssh` connect to a network device, execute
(run) a command and close.

The programming is like a wrapper, I suppose, around:
`paramiko.SSHClient().connect().invoke_shell()`

    DEFAULTS:
    `paramiko.SSHClient().connect().invoke_shell` width: 132
        Exposed when instantiating with the parameter `terminal_width`

    `paramiko.SSHClient().connect().invoke_shell` height: 128
        Exposed when instantiating with the parameter `terminal_height`

    `.shell_receive_bytes`: terminal_width * terminal_height
        Indirectly exposed through:
          -   `terminal_width`
          -   `terminal_height`

This implementation of will capture all shell output to:
    `<instance>.shell_received_bytes`

In turn, `<instance>.shell_received_bytes` has a `str` representation through
a `@property` decorated attribute: `<instance>.shell_transcript`.

The program uses a `str` object representing the shell prompt pattern. The
`<instance>.shell_receive()` method continues to receive bytes from the SSH
server until the shell prompt pattern is detected before the specified
`float` timeout value. The default `timeout` value is ninety (90/90.0) seconds.

This programming includes Jump Host capability, a la the OpenSSH
`-J destination` command-line option or `ProxyJump` ssh_config option.

    PRE-CONDITIONS:
    - After authenticating to a Cisco-like network device the user *MUST* be
      presented with a `privileged exec` prompt "<prompt_string>#". The
      programming has no capability for working out whether the `enable`
      command ought to be used or not.

    DURING-CONDITIONS:
    - SHELL RECEIVED BYTES
      Retrieved command output is stored by the attribute:
      `<instance>.shell_received_bytes`

    - NETWORK DEVICE SHELL PAGING
      Network device shell paging is disabled.

    EXAMPLES:
    NON JUMP HOST Cisco IOS-like or Juniper JunOS-like
    (auto discovery `cli_type`):
    from netdevsshshell import NetDevSshShell
    ndss = NetDevSshShell('hostname', username='username', password='password)
    # PROCESS COMMANDS
    ndss.shell_send_and_receive('show running-config')
    print(ndss.shell_transcript)

    # WHEN COMPLETE
    del ndss           # This will explicitly close both the shell and client

    OR
    from netdevsshshell import NetDevSshShell
    ndss = NetDevSshShell('hostname', username='username', password='password)
    with ndss:
        ndss.shell_send_and_receive('show tech-support', timeout=100.0)
        ndss.shell_send_and_receive('show ip interface brief', timeout=1.5)
        ndss.shell_send_and_receive('show inventory', timeout=2.6)
        ndss.shell_send_and_receive('exit', timeout=1.0)
        print(ndss.shell_transcript)

    NON JUMP HOST Cisco IOS-like:
    from netdevsshshell import NetDevSshShell
    ndss = NetDevSshShell('hostname', username='username', password='password,
                          cli_type='ios')
    # PROCESS COMMANDS
    ndss.shell_send_and_receive('show running-config')
    print(ssh.shell_transcript)

    # WHEN COMPLETE
    del ndss           # This will explicitly close both the shell and client

    OR
    from netdevsshshell import NetDevSshShell
    ndss = NetDevSshShell('hostname', username='username', password='password,
                          cli_type='ios')
    with ndss:
        ndss.shell_send_and_receive('show tech-support', timeout=100.0)
        ndss.shell_send_and_receive('show ip interface brief', timeout=1.5)
        ndss.shell_send_and_receive('show inventory', timeout=2.6)
        ndss.shell_send_and_receive('exit', timeout=1.0)
    print(ssh.shell_transcript)

    NON JUMP HOST Juniper JunOS-like:
    from netdevsshshell import NetDevSshShell
    ndss = NetDevSshShell('hostname', username='username', password='password',
                          cli_type='junos')

    # PROCESS COMMANDS
    ndss.shell_send_and_receive('show configuration | display set')
    print(ndss.shell_transcript)

    # WHEN COMPLETE
    del ndss           # This will explicitly close both the shell and client

    OR
    from netdevsshshell import NetDevSshShell
    ndss = NetDevSshShell('hostname', username='username', password='password',
                          cli_type='junos')
    with ndss:
        # PROCESS COMMANDS
        ndss.shell_send_and_receive('show configuration', timeout=20.0)
        ndss.shell_send_and_receive('show configuration | display set',
                                    timeout=15.0)
        ndss.shell_send_and_receive('quit', timeout=2.0)
    print(ndss.shell_transcript)

    JUMP HOST Cisco IOS-like:
    from netdevsshshell import NetDevSshShell
    ndss = NetDevSshShell('hostname', username='username', password='password',
                          cli_type='ios', jump_hostname='jump_hostname',
                          jump_username='jump_username',
                          jump_password='jump_password')
    # PROCESS COMMANDS
    ndss.shell_send_and_receive('show running-config')
    ndss.shell_send_and_receive('show startup-config')
    print(ndss.shell_transcript)

    OR
    from netdevsshshell import NetDevSshShell
    ndss = NetDevSshShell('hostname', username='username', password='password',
                          cli_type='ios', jump_hostname='jump_hostname',
                          jump_username='jump_username',
                          jump_password='jump_password')
    with ndss:
        ndss.shell_send_and_receive('show running-config')
        ndss.shell_send_and_receive('show startup-config')
    print(ndss.shell_transcript)

    JUMP HOST Juniper JunOS-like:
    from netdevsshshell import NetDevSshShell
    ndss = NetDevSshShell('hostname', username='username', password='password',
                          cli_type='junos', jump_hostname='jump_hostname',
                          jump_username='jump_username',
                          jump_password='jump_password')
    # PROCESS COMMANDS
    ndss.shell_send_and_receive('show configuration | display set')
    print(ndss.shell_transcript)

    # WHEN COMPLETE
    del ndss                  # This will explicitly close both the shell and
                              # client

    OR
    with ndss:
        ndss.shell_send_and_receive('show configuration', timeout=20.0)
        ndss.shell_send_and_receive('show configuration | display set',
                                   timeout=15.0)
    print(ndss.shell_transcript)
"""
import paramiko
import regex as re
from .netdevsshshell import (
    NetDevSshShell, ShellCliTypeError, ShellClosedError,
    ShellReceiveTimeoutError
)

__all__ = [
    'NetDevSshShell',
    'ShellCliTypeError',
    'ShellClosedError',
    'ShellReceiveTimeoutError',
    'paramiko',
    're'
]

__version_info__ = (1, 0, 5)
__version__ = '{}.{}.{}'.format(*__version_info__)
__author__ = 'John Natschev <jnatschev@icloud.com>'
__license__ = 'GNU General Public License v3.0 (GNU GPLv3)'
