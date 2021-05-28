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

    `paramiko.SSHClient().connect().invoke_shell` height: 132
        Exposed when instantiating with the parameter `terminal_height`

    `.shell_receive_bytes`: terminal_width * terminal_height
        Indirectly exposed through:
            -   `terminal_width`
            -   `terminal_height`

This implementation of will capture all shell output, as `str`, to an
attribute: `.shell_transcript`

The program uses a regular expression, `.shell_prompt_regexp` to search for the
network device's shell prompt; easing the retrieval of a command's output. There
is no validation of a command's success or failure.

The reason for using a regular expression to determine the return of the shell
prompt when retrieving a command's output (compared to using an exact match with
something like `str.endswith('<EXACT_PROMPT>')` is because a Cisco IOS-like
shell prompt changes when moving from "privileged exec" mode to "configure"
mode.

The retrieval of a command's output may be provided its own timeout. The default
timeout is 90.0 seconds. The timeout of 90.0 seconds was found to be the most
appropriate timeout when retrieving the output of the Cisco IOS-like command:
`show tech-support`
N.B.    The ssh shell's timeout is reset back to the supplied timeout during
        instantiation with the exposed parameter:
        `shell_receive_timeout`
        Again, the default being 90.0 seconds.

This programming includes Jump Host capability, a la the OpenSSH
`-J destination` command-line option or `ProxyJump` ssh_config option.

    PRE-CONDITIONS:
    -   After authenticating to a Cisco-like network device the user *MUST* be
        presented with a `privileged exec` prompt "<prompt_string>#". The
        programming has no capability for working out whether the `enable`
        command ought to be used or not.

    DURING-CONDITIONS:
    -   RETRIEVED COMMAND OUTPUT
        Retrieved command output is stored by the attribute:
        `.shell_received_output`

        `.shell_received_output` is reset to '' with each call to:
        `.shell_receive_command_output()`

    POST-CONDITIONS:
    -   SSH SHELL PAGING IS DISABLED
        During initialisation of the object shell command output paging is
        disabled. That is:
            Cisco IOS-like:
                `terminal length 0` is executed
            Juniper JunOS-like:
                `set cli screen-length 0` is executed

        Rationale:
        Since this programming turns an interactive ssh shell into a relatively
        non-interactive ssh shell, processing `--MORE--` in output is silly.

        Therefore when instantiating, one needs to be mindful of supplying a
        value to the initialisation parameter `cli_type`. `cli_type` does have
        a default value of 'auto'.

    EXAMPLES:
    NON JUMP HOST Cisco IOS-like or Juniper JunOS-like
    (auto discovery `cli_type`):
        from netdevsshshell import NetDevSshShell
        ssh = NetDevSshShell('hostname',
                             username='username',
                             password='password,
                             cli_type='auto'            #may be omitted; default
                             )
        # PROCESS COMMANDS
        ssh.shell_send_and_receive('show running-config')
        print(ssh.shell_transcript)

        # WHEN COMPLETE
        del ssh           # This will explicitly close both the shell and client

        OR
        with ssh:
            ssh.shell_send_and_receive('show tech-support', timeout=100.0)
            ssh.shell_send_and_receive('show ip interface brief', timeout=1.5)
            ssh.shell_send_and_receive('show inventory', timeout=2.6)
            ssh.shell_send_and_receive('exit', timeout=1.0)
            print(ssh.shell_transcript)

    NON JUMP HOST Cisco IOS-like:
        from netdevsshshell import NetDevSshShell
        ssh = NetDevSshShell('hostname',
                             username='username',
                             password='password,
                             cli_type='ios'
                             )
        # PROCESS COMMANDS
        ssh.shell_send_and_receive('show running-config')
        print(ssh.shell_transcript)

        # WHEN COMPLETE
        del ssh           # This will explicitly close both the shell and client

        OR
        with ssh:
            ssh.shell_send_and_receive('show tech-support', timeout=100.0)
            ssh.shell_send_and_receive('show ip interface brief', timeout=1.5)
            ssh.shell_send_and_receive('show inventory', timeout=2.6)
            ssh.shell_send_and_receive('exit', timeout=1.0)
            print(ssh.shell_transcript)

    NON JUMP HOST Juniper JunOS-like:
        from netdevsshshell import NetDevSshShell
        ssh = NetDevSshShell('hostname',
                             username='username',
                             password='password',
                             cli_type='junos')
        # PROCESS COMMANDS
        ssh.shell_send_and_receive('show configuration | display set')
        print(ssh.shell_transcript)

        # WHEN COMPLETE
        del ssh           # This will explicitly close both the shell and client

        OR
        with ssh:
            # PROCESS COMMANDS
            ssh.shell_send_and_receive('show configuration', timeout=20.0)
            ssh.shell_send_and_receive(
                    'show configuration | display set', timeout=15.0
            )
            ssh.shell_send_and_receive('quit', timeout=2.0)
            print(ssh.shell_transcript)

    JUMP HOST Cisco IOS-like:
        from netdevsshshell import NetDevSshShell
        ssh = NetDevSshShell('hostname',
                             username='username',
                             password='password',
                             cli_type='ios',
                             jump_hostname='jump_hostname',
                             jump_username='jump_username',
                             jump_password='jump_password'
                             )
        # PROCESS COMMANDS
        ssh.shell_send_and_receive('show running-config')
        ssh.shell_send_and_receive('show startup-config')
        print(ssh.shell_transcript)

        OR
        with ssh:
            ssh.shell_send_and_receive('show running-config')
            ssh.shell_send_and_receive('show startup-config')
        print(ssh.shell_transcript)

    JUMP HOST Juniper JunOS-like:
        from netdevsshshell import NetDevSshShell
        ssh = NetDevSshShell('hostname',
                             username='username',
                             password='password',
                             cli_type='junos',
                             jump_hostname='jump_hostname',
                             jump_username='jump_username',
                             jump_password='jump_password'
                             )
        # PROCESS COMMANDS
        ssh.shell_send_and_receive('show configuration | display set')
        print(ssh.shell_transcript)

        # WHEN COMPLETE
        del ssh                  # This will explicitly close both the shell and
                                 # client

        OR
        with ssh:
            ssh.shell_send_and_receive('show configuration', timeout=20.0)
            ssh.shell_send_and_receive(
                'show configuration | display set',
                timeout=15.0)
        print(ssh.shell_transcript)
"""
import os as os
import sys as sys
import paramiko

module_path = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(1, module_path)

import regex as re
from .netdevsshshell import NetDevSshShell, SshShellConnectionError

__all__ = [
    'NetDevSshShell',
    'SshShellConnectionError',
    'paramiko',
    're'
]

__version_info__ = (1, 0, 0)
__version__ = '{}.{}.{}'.format(*__version_info__)
__author__ = 'John Natschev <jnatschev@icloud.com>'
__license__ = 'GNU General Public License v3.0 (GNU GPLv3)'
