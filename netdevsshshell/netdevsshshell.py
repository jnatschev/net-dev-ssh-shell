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
from time import sleep

import socket
import paramiko
import regex as re


class ShellCliTypeError(ValueError):
    """
    Used if the supplied `cli_type` value is unsupported.
    """


class ShellClosedError(EOFError):
    """
    Used if the `<instance>._shell.closed` is True.

    `ShellClosedError` is a subclass of `EOFError`
    """


class ShellReceiveTimeoutError(TimeoutError):
    """
    Used if the shell prompt has not been received before a specified timeout.
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
            delattr(self, '_shell')
            delattr(self, '_client')

    def __init__(self, hostname: str, username: str, password: str,
                 port: int = 22, terminal_type: str = 'xterm',
                 terminal_width: int = 132, terminal_height: int = 128,
                 cli_type: str = 'auto', shell_receive_timeout: float = 90.0,
                 jump_hostname=None, jump_username=None,
                 jump_password=None) -> None:
        """
        `NetDevSshShell` initialisation

        Args:
            hostname:
                `str` object representing the hostname or IP Address of the
                target SSH server.

            username:
                `str` object representing the username used to authenticate to
                the SSH server.

            password:
                `str` object representing the password of the username used
                to authenticate to the SSH server.

            port:
                `int` object representing the port number of the SSH server.

            terminal_type:
                `str` object representing the shell terminal type:
                  - vt100
                  - xterm (Default)
                  - xterm-256color

            terminal_width:
                `str` object representing the shell terminal width.
                Default value: 132

            terminal_height:
                `str` object representing the shell terminal height.
                Default value: 128

            cli_type:
                `str` object representing the command-line interface type:
                  - auto (Default)
                  - ios (Cisco IOS-like shells)
                  - cwlc (Cisco Wireless LAN Controller)
                  - junos (Juniper Junos-like shells)
                  - 'nix' (Linux/Unix shells)

            shell_receive_timeout:
                `float` object representing the period to wait for the shell
                prompt before raising a `socket.timeout`

            jump_hostname:
                `str` object representing the hostname or IP Address of a SSH
                server used as a jump host to establish a connection with the
                target SSH server. Equivalent to openssh "ssh -J".

            jump_username:
                `str` object representing the username used to authenticate to
                the jump host.

            jump_password:
                `str` object representing the password of the username used to
                authenticate to the jump host.

        Raises:
            `ShellCliTypeError`
                If the supplied value for `cli_type` is invalid.

            `paramiko.ssh_exception.SSHException`:
                If there was an error connecting or establishing an SSH session.

            `paramiko.ssh_exception.AuthenticationException`
                If authentication fails.

            `socket.error`
                if a socket error was detected during connection.
        """
        super().__init__()
        self.hostname: str = hostname
        self.username: str = username
        self.password: str = password
        self.shell_terminal_type: str = terminal_type
        self.shell_terminal_width: int = terminal_width
        self.shell_terminal_height: int = terminal_height
        self._jump_channel = None
        self.shell_cli_type: str = self._validate_supplied_cli_type(cli_type)
        self.shell_receive_timeout: float = shell_receive_timeout
        self.shell_receive_number_of_bytes: int = (
                self.shell_terminal_width * self.shell_terminal_height
        )
        self.shell_received_bytes: bytes = ''.encode()
        self._client: paramiko.SSHClient = paramiko.SSHClient()
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
                term=self.shell_terminal_type,
                width=self.shell_terminal_width,
                height=self.shell_terminal_height
        )

        self._shell.settimeout(self.shell_receive_timeout)

        self._shell_receive()

        if self.shell_cli_type == 'auto':
            self.shell_send('show version')
            self._shell_receive()

            if (
                    'ios' in self.shell_transcript.lower()
                    or
                    'eos' in self.shell_transcript.lower()
            ):
                self.shell_cli_type = 'ios'
            elif 'junos' in self.shell_transcript.lower():
                self.shell_cli_type = 'junos'
            elif ('incorrect usage' in self.shell_transcript.lower() or
                    'key to list commands' in self.shell_transcript.lower()):
                self.shell_cli_type = 'cwlc'
            else:
                self.shell_cli_type = 'nix'

        self.shell_send(command=self.shell_initial_command[self.shell_cli_type])
        self._shell_receive()

        self.shell_prompt_pattern = self.shell_received_bytes.splitlines()[-1]

    def _validate_supplied_cli_type(self, cli_type: str) -> str:
        """
        Validate the value of the supplied CLI Type.

        Args:
            cli_type:
                `str` object representing the shell cli type of the SSH server.
                - auto (Default)
                - ios
                - cwlc
                - junos
                - nix
        Returns:
            `str` object representing a valid shell cli type.
        """
        if cli_type not in self.shell_cli_types:
            error_text = 'The supplied value of `cli_type` is unsupported.'
            raise ShellCliTypeError(error_text)
        else:
            return cli_type

    @property
    def _is_shell_closed(self) -> False:
        """

        Returns:
            `NoneType`

        Raises:
            `ShellClosedError`
        """
        if self._shell.closed:
            raise ShellClosedError()
        else:
            return False

    @property
    def _remove_ansi_escape_sequences(self) -> bytes:
        """
        Remove unnecessary shell prompt escape sequences.

        Returns:
            `bytes`
        """
        escape_sequence_patterns = br'''
            \x1b
            [[:punct:]]
            [[:print:]]{1,}?
            \x07
            |
            \x1b
            [[:punct:]]
            [[:digit:]]
            [[:lower:]]
            [[:punct:]]{0,1}
            |
            \x1b
            [[:punct:]]
            [[:lower:]]
            |
            \x1b
            [[:punct:]]
            [[:upper:]]
            |
            \x1b
            [[:punct:]]{2}
            [[:graph:]]{4,6}
            [\x08]{0,1}
            |
            [ ]*\r[ ]*
        '''
        escape_sequence_regexp = re.compile(
            escape_sequence_patterns,
            flags=re.VERBOSE | re.VERSION0
        )
        return escape_sequence_regexp.sub(b'', self.shell_received_bytes)

    def _shell_receive(self) -> None:
        """
        Used during instance initialisation to receive shell output from the
        SSH server.

        The reason it is used instead of the exposed
        `<instance>.shell_receive()` method is because the shell prompt hasn't
        been determined yet.

        Returns:
            `NoneType`
        """
        if not self._shell.recv_ready():
            sleep(1.0)

        if self._shell.recv_ready():
            while self._shell.recv_ready():
                self.shell_received_bytes += self._shell.recv(
                    self.shell_receive_number_of_bytes
                )
                sleep(1.0)

    @property
    def shell_transcript(self) -> str:
        """
        Return a `str` representation of `<instance>.shell_received_bytes`,
        where `<instance>.shell_received_bytes` is a `bytes` representation.

        Returns:
            `str`
        """
        return '\n'.join(
            [
                v.decode() for v in
                self._remove_ansi_escape_sequences.splitlines()
            ]
        )

    def shell_send(self, command: str) -> None:
        """
        Send a command to the connected SSH server for execution.

        Args:
            command:
                `str` object representing the command to be sent to the SSH
                server.

        Returns:
            `NoneType`

        Raises:
            `ShellClosedError`
        """
        command_plus_cr_as_bytes = '{}\r'.format(command).encode()

        if not self._is_shell_closed:
            self._shell.sendall(command_plus_cr_as_bytes)
        else:
            error_text = 'SHELL CLOSED ERROR: Unable to send command,' \
                         '`{}`, to remote SSH server because the shell is ' \
                         'closed.'.format(command)
            raise ShellClosedError(error_text)

    def shell_receive(self, timeout: float = -1.0) -> None:
        """
        Receive the output of a command executed on the SSH server.

        Args:
            timeout:
                `float` object representing the period to wait for the shell
                prompt before a socket.timeout is raised
        Returns:
            `NoneType`

        Raises:
            `ShellClosedError`
            `ShellReceiveTimeoutError`
        """
        timeout_values = (-1, -1.0, 90, 90.0, 0, 0.0)
        original_timeout = self.shell_receive_timeout

        if timeout not in timeout_values:
            self._shell.settimeout(timeout)

        received_bytes = ''.encode()

        while not received_bytes.endswith(self.shell_prompt_pattern):
            if not self._is_shell_closed:
                sleep(1.0)
            else:
                raise ShellClosedError('SHELL CLOSED ERROR')

            try:
                received_bytes += self._shell.recv(self.shell_receive_number_of_bytes)
            except socket.timeout:
                error_text = 'SHELL TIMEOUT ERROR: shell prompt pattern not ' \
                             'received before timeout value.'
                raise ShellReceiveTimeoutError(error_text)

        self.shell_received_bytes += received_bytes

        self._shell.settimeout(original_timeout)

    def shell_send_and_receive(self, command: str, timeout: float = -1) -> None:
        """
        A method that uses both `<instance>.shell_send()` and
        `<instance>.shell_receive()`

        Args:
            command:
                see `shell_send()` docstring

            timeout:
                see `shell_received()` docstring

        Returns:
            `NoneType`

        Raises:
            see `shell_send()` docstring
            see `shell_receive()` docstring
        """
        self.shell_send(command=command)
        self.shell_receive(timeout=timeout)

    @staticmethod
    def _return_jump_channel(destination: str,
                             jump_hostname: str,
                             jump_username: str,
                             jump_password: str) -> paramiko.channel.Channel:
        """
        Return a `paramiko.channel.Channel` object representing the SSH server
        used as a jump host to establish a connection with the target SSH
        server.

        Args:
            destination:
                `str` object representing the hostname or IP Address of the
                target SSH server

            jump_hostname:
                `str` object representing the hostname or IP Address of the
                SSH server to be used as the jump host.

            jump_username:
                `str` object representing the username used to authenticate to
                the SSH server to be used as the jump host.

            jump_password:
                `str` object representing the password of the username used to
                authenticate to the SSH server to be used as the jump host.

        Returns:
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
