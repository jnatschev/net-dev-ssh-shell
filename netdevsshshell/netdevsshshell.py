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
from time import sleep

import socket
import paramiko
import regex as re


class ShellCliTypeError(ValueError):
    """
    Used if the supplied `shell_cli_type` value is unsupported.

    `ShellCliTypeError` is a sublass of `ValueError`
    """


class ShellClosedError(EOFError):
    """
    Used if the `<instance>._shell.closed` is True.

    `ShellClosedError` is a subclass of `EOFError`
    """


class ShellSendError(Exception):
    """
    Used during `<instance>.shell_send(<command>)`
    """


class ShellTimeoutError(TimeoutError):
    """
    Used if a `<instance>.shell_send()` or `<instance>.shell_receive()`
    encounter a shell socket.timeout error.
    """


class NetDevSshShell:
    """
    NetDevSshShell Object Definition
    """
    shell_cli_types = (
        'auto',
        'cwlc',
        'ios',
        'junos',
        'nix'
    )

    no_pagination_command = {
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
                 port: int = 22, shell_terminal_type: str = 'xterm',
                 shell_terminal_width: int = 132,
                 shell_terminal_height: int = 128, shell_cli_type: str = 'auto',
                 shell_timeout: float = 90.0, jump_hostname=None,
                 jump_username=None, jump_password=None) -> None:
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

            shell_terminal_type:
                `str` object representing the shell terminal type:
                  - vt100
                  - xterm (Default)
                  - xterm-256color

            shell_terminal_width:
                `str` object representing the shell terminal width.
                Default value: 132

            shell_terminal_height:
                `str` object representing the shell terminal height.
                Default value: 128

            shell_cli_type:
                `str` object representing the command-line interface type:
                  - auto (Default)
                  - ios (Cisco IOS-like shells)
                  - cwlc (Cisco Wireless LAN Controller)
                  - junos (Juniper Junos-like shells)
                  - 'nix' (Linux/Unix shells)

            shell_timeout:
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
                If the supplied value for `shell_cli_type` is invalid.

            `paramiko.ssh_exception.SSHException`:
                If there was an error connecting or establishing an SSH session.

            `paramiko.ssh_exception.AuthenticationException`
                If authentication fails.

            `socket.error`
                if a socket error was detected during connection.
        """
        super().__init__()
        self.hostname: str = hostname
        self.port: int = port
        self.username: str = username
        self.password: str = password
        self.shell_terminal_type: str = shell_terminal_type
        self.shell_terminal_width: int = shell_terminal_width
        self.shell_terminal_height: int = shell_terminal_height
        self._jump_channel = None
        self.shell_timeout: float = shell_timeout
        self.shell_receive_number_of_bytes: int = (
                self.shell_terminal_width * self.shell_terminal_height
        )
        self.shell_received_bytes: bytes = ''.encode()
        self._client: paramiko.SSHClient = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()
        )

        self._set_jump_channel(jump_hostname, jump_username, jump_password)
        self._ssh_client_connect()

        self._shell = self._return_ssh_shell()

        self._shell.settimeout(self.shell_timeout)
        self.shell_cli_type: str = self._validate_supplied_shell_cli_type(
            shell_cli_type
        )
        self._process_no_pagination_command()
        self._get_and_set_shell_prompt_pattern_and_regexp()

    def _return_ssh_shell(self):
        ssh_shell = self._client.invoke_shell(
            term=self.shell_terminal_type,
            width=self.shell_terminal_width,
            height=self.shell_terminal_height
        )
        ssh_shell.settimeout(self.shell_timeout)
        return ssh_shell

    def _ssh_client_connect(self):
        self._client.connect(
            self.hostname,
            port=self.port,
            username=self.username,
            password=self.password,
            allow_agent=False,
            look_for_keys=False,
            sock=self._jump_channel
        )

    def _set_jump_channel(self, jump_hostname, jump_username, jump_password):
        if jump_hostname and jump_username and jump_password:
            self._jump_channel = self._return_jump_channel(
                self.hostname,
                jump_hostname=jump_hostname,
                jump_username=jump_username,
                jump_password=jump_password
            )

    def _return_shell_cli_type(self, shell_cli_type):
        self.shell_send('\r')
        self._shell_receive()

        if shell_cli_type == 'auto':
            self.shell_send(command='show version')
            self._shell_receive()

            if ('ios' in self.shell_transcript.lower()
                    or 'eos' in self.shell_transcript.lower()
                    or 'aos' in self.shell_transcript.lower()):
                return 'ios'
            elif 'junos' in self.shell_transcript.lower():
                return 'junos'
            elif ('incorrect usage' in self.shell_transcript.lower() or
                  'key to list commands' in self.shell_transcript.lower()):
                return 'cwlc'
            else:
                return 'nix'
        else:
            return shell_cli_type

    def _process_no_pagination_command(self):
        self.shell_send(command=self.no_pagination_command[self.shell_cli_type])
        # self.shell_send('\r')
        self._shell_receive()

    def _get_and_set_shell_prompt_pattern_and_regexp(self) -> None:
        self.shell_send('\r')
        self._shell_receive()

        if self.shell_cli_type == 'nix':
            self.shell_prompt_pattern = self.shell_received_bytes.splitlines()[-1]
            self.shell_prompt_regexp = re.compile(br'[[:space:]]{132}')
        else:
            self.shell_prompt_pattern = b'[\r\n][[:graph:]]{1,}?[#$%>]{1}[ ]{0,1}$'
            self.shell_prompt_regexp = re.compile(self.shell_prompt_pattern)

    def _validate_supplied_shell_cli_type(self, shell_cli_type: str) -> str:
        """
        Validate the value of the supplied CLI Type.

        Args:
            shell_cli_type:
                `str` object representing the shell cli type of the SSH server.
                - auto (Default)
                  Attempt automatic detection of the shell cli type.
                  While this is the default, users of this program are
                  encouraged to explicitly provide the correct shell cli type
                  at instance initialisation.
                - ios
                  - arista
                  - aruba
                  - cisco
                - cwlc
                  cisco wireless lan controller
                - junos
                  - juniper networks
                - nix
                  - Linux
                  - Unix
        Returns:
            `str` object representing a valid shell cli type.
        """
        if shell_cli_type not in self.shell_cli_types:
            error_text = 'The supplied value of `shell_cli_type` is unsupported.'
            raise ShellCliTypeError(error_text)
        else:
            return self._return_shell_cli_type(shell_cli_type)

    @property
    def _shell_is_closed(self) -> bool:
        """
        Is `<instance>._shell.closed` True or False

        Returns:
            `bool`
        """
        return self._shell.closed

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
            [[:digit:]]{1,4}
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
        if not self._shell_is_closed:
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
            `ShellSendError`
            `ShellClosedError`
        """
        send_sleep_time = 0.17
        command_to_send = '{}\r'.format(command)
        command_to_send_length = len(command_to_send)
        original_shell_timeout = self._shell.gettimeout()
        new_shell_timeout = command_to_send_length * send_sleep_time + 5.0

        self._shell.settimeout(new_shell_timeout)

        if not self._shell_is_closed:
            try:
                shell_sent_count = 0

                for character in command_to_send:
                    self._shell.send(character.encode())
                    shell_sent_count = shell_sent_count + 1
                    sleep(send_sleep_time)

                if not shell_sent_count == command_to_send_length:
                    raise ShellSendError(
                        'SHELL SEND ERROR: `shell_send_count` and'
                        '`command_to_send_length` are not equal.'
                    )
            except socket.timeout as socket_timeout:
                raise ShellTimeoutError(
                    'SHELL TIMEOUT ERROR: Unable to send command, {}, within '
                    'shell timeout {} seconds'.format(
                        command_to_send, new_shell_timeout
                    )
                ) from socket_timeout
        else:
            error_text = 'SHELL CLOSED ERROR: Unable to send command,' \
                         '`{}`, to remote SSH server because the shell is ' \
                         'closed.'.format(command)
            raise ShellClosedError(error_text)

        self._shell.settimeout(original_shell_timeout)
        sleep(1.0)

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
            `ShellTimeoutError`
        """
        timeout_values = (-1, -1.0, 90, 90.0, 0, 0.0)
        original_shell_timeout = self.shell_timeout

        if timeout not in timeout_values:
            self._shell.settimeout(timeout)

        received_bytes = ''.encode()

        while not (self.shell_prompt_regexp.search(received_bytes) or
                   received_bytes.endswith(self.shell_prompt_pattern)):
            try:
                received_bytes += self._shell.recv(
                    self.shell_receive_number_of_bytes
                )

                if not self._shell.recv_ready():
                    sleep(1.0)
            except socket.timeout as socket_timeout:
                error_text = 'SHELL TIMEOUT ERROR: shell prompt pattern ' \
                             'not received before timeout {}'.format(timeout)
                raise ShellTimeoutError(error_text) from socket_timeout

            if self._shell_is_closed:
                break

        self.shell_received_bytes += received_bytes

        self._shell.settimeout(original_shell_timeout)

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

    def __str__(self):
        return self.shell_transcript

    def __repr__(self):
        repr_text = '<{}(Hostname={}, ' \
                    'Port Number={}, ' \
                    'Shell Terminal Type={}, ' \
                    'Shell Terminal Width={}, ' \
                    'Shell Terminal Height={}, ' \
                    'Shell CLI Type={}, ' \
                    'Shell Timeout={}, ' \
                    'Shell Receive Number of Bytes={})>'
        return repr_text.format(
            self.__class__.__name__,
            self.hostname,
            self.port,
            self.shell_terminal_type,
            self.shell_terminal_width,
            self.shell_terminal_height,
            self.shell_cli_type,
            self.shell_timeout,
            self.shell_receive_number_of_bytes
        )
