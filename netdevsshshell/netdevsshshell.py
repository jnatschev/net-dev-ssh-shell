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
from time import sleep

import socket
import paramiko
import regex as re


class SshShellConnectionError(ConnectionError):
    """
    `SshShellConnectionError` primarily used when there is a problem with the
    ssh shell.

    One instance of a ssh shell connection error is when the ssh shell is closed
    for some reason yet is expected to be open.

    Example:
    `self._shell.closed` is True when one expects `self._shell.closed` is False
        raise `SshShellConnectionError`

    `SshShellConnectionError` is a subclass of `ConnectionError`
    """


class NetDevSshShell:
    """
    NetDevSshShell Object Definition
    """
    shell_cli_types = (
        'auto',
        'ios',
        'cwlc',
        'junos',
        'nix'
    )

    shell_initial_command = {
        'ios': 'terminal length 0',
        'cwlc': 'config paging disable',
        'junos': 'set cli screen-length 0',
        'nix': 'unalias -a && export PS1="shellprompt$ "'
    }

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._shell.close()
        self._client.close()

    def __del__(self):
        if hasattr(self, '_shell'):
            self._shell.close()
            self._client.close()

    def __init__(self, hostname: str, username: str, password: str,
                 port: int = 22, terminal_width: int = 132,
                 terminal_height: int = 132, cli_type: str = 'auto',
                 shell_receive_timeout: float = 90.0, jump_hostname=None,
                 jump_username=None, jump_password=None):
        """
        `NetDevSshShell` initialisation method definition

        :param hostname:
            `str` object of the remote SSH Server's IP address or host name.

        :param username:
            `str` object of the user name to use to authenticate to the SSH
            Server.

        :keyword port:
            `int` object of the remote SSH Server port number.
            Default: 22

        :keyword password:
            `str` object of the password associated with the user name used to
            authenticate to the remote SSH Server.

        :keyword terminal_width:
            `int` object defining the width of the SSH Shell's terminal width.
            Default: 132

        :keyword terminal_height:
            `int` object defining the height of the SSH Shell's terminal
            height.
            Default: 25

        :keyword cli_type:
            `str` object of the SSH Shell's Command Line Interface (CLI) type.
            Supported values:
            - 'auto':   `cli_type` Auto Discovery
            - 'ios':    Cisco IOS-like CLI
            - 'cwlc':   Cisco Wireless LAN Controller (CWLC)
            - 'junos':  Juniper JunOS-like CLI
            - 'nix':    Unix-like CLI - the shell will be standard `sh`

        :keyword jump_hostname:
            `str` object representing a SSH Jump Host hostname or IP address.
            Equivalent to OpenSSH option `-J`.

        :keyword jump_username:
            `str` object representing the SSH Jump Host user name for
            username based authentication

        :keyword jump_password:
            `str` object representing the SSH Jump Host user password for
            username based authentication
        """
        super().__init__()
        self._jump_channel = None
        self.receive_encoding = 'cp1252'
        self.shell_cli_type = self.set_shell_cli_type(cli_type)

        self.shell_prompt_regexp = re.compile(
            br'(?=[\r\n]{1}[[:alpha:]{1,}[:digit:]{0,}[:punct:]{0,} {0,}]{1,50}[#$%>]{1} {0,1}$)',
            flags=re.I
        )

        self.ansi_escape_regexp = re.compile(
            br'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]',
            flags=re.IGNORECASE
        )

        self.shell_receive_timeout: float = shell_receive_timeout
        self.shell_transcript: str = ''
        self.shell_terminal_width: int = terminal_width
        self.shell_terminal_height: int = terminal_height
        self.shell_receive_bytes: int = (
                self.shell_terminal_width *
                self.shell_terminal_height
        )
        self.shell_received_bytes: bytes = b''
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()
        )

        if jump_hostname and jump_username and jump_password:
            self._jump_channel = self._return_jump_channel(
                hostname,
                jump_hostname=jump_hostname,
                jump_username=jump_username,
                jump_password=jump_password
            )

        self._client.connect(
            hostname,
            port=port,
            username=username,
            password=password,
            allow_agent=False,
            look_for_keys=False,
            sock=self._jump_channel
        )

        self._shell = self._client.invoke_shell(
                term='vt100',
                width=self.shell_terminal_width,
                height=self.shell_terminal_height,
        )

        self._shell.settimeout(self.shell_receive_timeout)

        if not self._shell.recv_ready():
            sleep(1.0)

        if self._shell.recv_ready():
            self.shell_receive_command_output()
            # while self._shell.recv_ready():
            #     self.shell_received_bytes += self.ansi_escape_regexp.sub(
            #         b'',
            #         self._shell.recv(
            #             self.shell_receive_bytes
            #         )
            #     )

        if self.shell_cli_type == 'auto':
            self.shell_send_and_receive('show version', timeout=5.0)

            self.shell_transcript += self.shell_received_bytes.decode(
                self.receive_encoding
            )

            if 'ios' in self.shell_transcript.lower():
                self.shell_cli_type = 'ios'
            
            elif 'junos' in self.shell_transcript.lower():
                self.shell_cli_type = 'junos'
            
            elif ('incorrect usage' in self.shell_transcript.lower() or
                    'key to list commands' in self.shell_transcript.lower()):
                self.shell_cli_type = 'cwlc'
            else:
                self.shell_cli_type = 'nix'

        self.shell_send_and_receive(
            command=self.shell_initial_command[self.shell_cli_type],
            timeout=3.0
        )

    def set_shell_cli_type(self, cli_type: str):
        """
        `set_shell_cli_type` definition
        :param cli_type:
             `str` object of the network device's cli_type
             Supported cli types are:
             - 'ios'
             - 'junos'
             - 'nix'

                The cli type `'ios'` is used when the remote SSH Server has a
                Cisco-like IOS shell. Default.

                The cli type `'junos'` is used when the remote SSH Server has a
                Juniper-like JunOS shell

                The purpose behind requiring a value for this attribute is to
                execute the `'ios'` command `terminal length 0` or the `'junos'`
                command `set cli screen-length 0`. Because this object is meant
                to work on a `shell`, turning paging off avoids looking for
                `--More--`.

        :return cli_type:
            `str` object validated as a supported `cli_type` value
        """
        if cli_type not in self.shell_cli_types:
            raise ValueError(
                'VALUE ERROR: Supplied `cli_type` value {} is unsupported'.format(
                    cli_type
                )
            )
        else:
            return cli_type

    def shell_send_command(self, command: str) -> None:
        """
        `shell_send_command` definition

        Send a command to the ssh shell to execute. This method uses the
        `paramiko.SSHClient().invoke_shell().sendall` method.

        :param command:
            `str` object representing the command to be sent to and executed on
            the remote ssh shell for execution. The `command` string does not
            require a line ending; though it may be included if it is seen fit
            to do so (like if executing a Cisco IOS-like command:
            `copy running-config startup-config` where additional user input is
            required

        :return None:

        :raises `SshShellConnectionError`:
            Raised if `self._shell.closed` is `True`.
        """
        if not self._shell.closed:
            self._shell.sendall('{}\r'.format(command).encode())
        else:
            error_text = 'SHELL CONNECTION ERROR: Unable to send command,' \
                         '`{}`, to remote SSH server because it seems that' \
                         'the shell is closed'.format(command)
            raise SshShellConnectionError(error_text)

    def shell_receive_command_output(self, timeout: float = -1.0) -> None:
        """
        shell_receive_command_output Method Definition

        `shell_receive_command_output` is a method for retrieving the ssh shell
        output of an executed ssh shell command.

        The default receive timeout is the default `self._shell` timeout of
        ninety (90) seconds. The value for timeout *MUST* be greater than zero:
        timeout > 0

        :keyword timeout:
            `int` or `float` object greater than zero representing how long to
            wait while not receiving data before raising a `socket.timeout`
            exception. The default is 90.0 seconds. 90.0 seconds seems to be
            a good timeout value especially for the Cisco-like command:
            `show tech-support`.

        :return None:
            `NoneType`

        :raises socket.timeout:
            From `paramiko.SSHClient().invoke_shell().recv()`
        """
        timeout_values = (-1, -1.0, 90, 90.0, 0, 0.0)
        original_timeout = self.shell_receive_timeout

        if timeout not in timeout_values:
            self._shell.settimeout(timeout)

        self.shell_received_bytes = b''

        while not self.shell_prompt_regexp.search(self.shell_received_bytes):
            try:
                self.shell_received_bytes += self.ansi_escape_regexp.sub(
                    b'',
                    self._shell.recv(
                        self.shell_receive_bytes
                    )
                )
                sleep(0.2)
            except socket.timeout:
                self.shell_transcript += self.shell_received_bytes.decode(
                    self.receive_encoding
                )
                raise

            if self._shell.closed:
                break

        self.shell_transcript += self.shell_received_bytes.decode(
            self.receive_encoding
        )

        self._shell.settimeout(original_timeout)

    def shell_send_and_receive(self, command: str, timeout: float = -1.0) -> None:
        """
        shell_send_and_receive Method Definition

        This method combines the methods:
            `.shell_send_command()` and `.shell_receive_command_output()`

        :keyword command:
            `str` object representing a command to be sent to and executed by
            the remote ssh shell

        :keyword timeout:
            `int` or `float` object greater than zero representing how long to
            wait while not receiving data before raising a `socket.timeout`
            exception. The default is 90.0 seconds. 90.0 seconds seems to be
            a good timeout value especially for the Cisco-like command:
            `show tech-support`.

        :return None:

        :raises SshShellConnectionError:
            If a command cannot be sent to the remote ssh shell

        :raises socket.timeout:
            If the set timeout is hit without receiving data prior to detecting
            the remote ssh shell prompt
        """
        self.shell_send_command(command=command)
        self.shell_receive_command_output(timeout=timeout)

    @staticmethod
    def _return_jump_channel(destination: str,
                             jump_hostname: str,
                             jump_username: str,
                             jump_password: str) -> paramiko.channel.Channel:
        """
        Establish a connection with a Jump Host and return its
        `paramiko.channel.Channel`

        :param jump_hostname:
            `str` object representing a ssh jump host hostname or IP address

        :param jump_username:
            `str` object representing the ssh jump host user name for
            authenticating to the ssh jump host

        :param jump_password:
            `str` object representing the ssh jump host user password for
            authenticating to the ssh jump host

        :return:
            `paramiko.channel.Channel` object
        """
        client = paramiko.SSHClient()

        client.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())

        source = ('127.0.0.1', 22)
        destination = (destination, 22)

        client.connect(
            jump_hostname,
            username=jump_username,
            password=jump_password,
            allow_agent=False,
            look_for_keys=False
        )

        transport = client.get_transport()
        channel = transport.open_channel(
            'direct-tcpip',
            dest_addr=destination,
            src_addr=source
        )

        return channel
