# -*- coding: utf-8 -*-
<<<<<<< HEAD
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
=======
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
>>>>>>> 2.0
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
=======
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

>>>>>>> 2.0
"""
from __future__ import annotations

import ipaddress
import socket
from time import sleep

import paramiko
import regex as re

from .devicetype import DeviceTypeIos, DeviceTypeJunos, DeviceTypeNix


class ShellCliTypeError(ValueError):
    """
    Used if the supplied `shell_cli_type` value is unsupported.

<<<<<<< HEAD
    `ShellCliTypeError` is a subclass of `ValueError`
=======
    `ShellCliTypeError` is a sublass of `ValueError`
>>>>>>> 2.0
    """


class ShellClosedError(EOFError):
    """
    Used if the `<instance>._shell.closed` is True.

    `ShellClosedError` is a subclass of `EOFError`
    """


class ShellSendError(Exception):
    """
    Used during `<instance>.shell_send(<command>)`
<<<<<<< HEAD

    `ShellSendError` is a subclass of `Exception`
=======
    """


class ShellTimeoutError(TimeoutError):
    """
    Used if a `<instance>.shell_send()` or `<instance>.shell_receive()`
    encounter a shell socket.timeout error.
>>>>>>> 2.0
    """


class ShellTimeoutError(TimeoutError):
    """
    Used if a `<instance>.shell_send()` or `<instance>.shell_receive()`
    encounter a shell socket.timeout error.
    """


class ShellReceiveNumberOfBytes(int):
    """
    ShellReceiveNumberOfBytes Object Definition
    
    `ShellReceiveNumberOfBytes` is a subclass of type `int`
    """
    def __new__(cls, shell_terminal_width=132, shell_terminal_height=30):
        """
        
        :param shell_terminal_width:
            `int` object representing a shell's terminal width.
            Default: 132
            
        :param shell_terminal_height:
            `int` object representing a shell's terminal height.
            Default: 30
        """
        cls.shell_terminal_width = shell_terminal_width
        cls.shell_terminal_height = shell_terminal_height
        return super(ShellReceiveNumberOfBytes, cls).__new__(
            cls,
            shell_terminal_width * shell_terminal_height
        )


class NetDevSshShell:
    """
    NetDevSshShell Object Definition
    """
<<<<<<< HEAD
    def __init__(self,
                 hostname: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
                 username: str,
                 password: str,
                 device_type: str,
                 port: int = 22,
                 shell_terminal_type: str = 'xterm',
                 shell_terminal_width: int = 132,
                 shell_terminal_height: int = 30,
                 shell_timeout: float | int = 5.0,
                 jump_hostname: str | ipaddress.IPv4Address | ipaddress.IPv6Address | None = None,
                 jump_username: str | None = None,
                 jump_password: str | None = None) -> None:
=======
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
>>>>>>> 2.0
        """
        `NetDevSshShell` instance initialisation method
        
        :param hostname:
            Object representing the target ssh server hostname or IP Address.
        :type hostname:
            `str` | `ipaddress.IPv4Address` | `ipaddress.IPv6Address`

        :param username:
            Object representing the username to authenticate to the target
            ssh server.
        :type username:
            `str`

        :param password:
            Object representing the password of the username to authenticate to
            the target ssh server.
        :type password:
            `str`

        :param device_type:
            Object representing the target device type.
            Possible values:
            - 'nix'
              for Linux/Unix-like devices
            - 'ios'
              for Cisco IOS-like devices
            - 'junos'
              for Juniper JunOS-like devices
        :type device_type:
            `str`

        :param port:
            Object representing the port number of the target ssh server.
        :type port:
            `int`

<<<<<<< HEAD
        :param shell_terminal_type:
            Object representing the shell terminal type. For example:
            - vt100
            - xterm (default)
            - xterm-256color
        :type shell_terminal_type:
            `str`

        :param shell_terminal_width:
            Object representing the shell terminal width.
            Default: 132
        :type shell_terminal_width:
            `int`

        :param shell_terminal_height:
            Object representing the shell terminal height.
            Default: 30
        :type shell_terminal_height:
            `int`

        :param shell_timeout:
            Object representing a shell timeout in seconds. This is the timeout
            value waiting for data during the
            <instace>._shell.recv(`number_of_bytes`) process defined in the
            <instance>.shell_receive() method.
            Default: 5.0
        :type shell_timeout:
            `float` | `int`

        :param jump_hostname:
            Object representing the hostname or IP Address of a jump ssh
            server used to get to the target ssh server. Equivalent to OpenSSH
            option -J.
            Default: None
        :type jump_hostname:
            `str` | `ipaddress.IPv4Address` | `ipaddress.IPv6Address`
=======
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
>>>>>>> 2.0

        :param jump_username:
            Object representing the username to authenticate to the jump ssh
            host.
            Default: None
        :type jump_username:
            `str`

<<<<<<< HEAD
        :param jump_password:
            Object representing the password of the username to authenticate to
            the jump ssh host.
            Default: None
        :type jump_password:
            `str`
        """
        super().__init__()
        self.hostname: str = str(hostname)
        self.port: int = port
        self.username: str = username
        self.password: str = password
        self.device_type = globals()[
            'DeviceType' + device_type.lower().capitalize()
        ]()
        self.shell_terminal_type: str = shell_terminal_type
        self.shell_receive_number_of_bytes = ShellReceiveNumberOfBytes(
            shell_terminal_width=shell_terminal_width,
            shell_terminal_height=shell_terminal_height
=======
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
>>>>>>> 2.0
        )
        self._jump_channel: paramiko.channel.Channel | None = None
        self.shell_received_bytes: bytes = ''.encode()
        self._client: paramiko.SSHClient = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()
        )

        self._set_jump_channel(jump_hostname, jump_username, jump_password)
        self._ssh_client_connect()

        self._shell = self._return_ssh_shell()

<<<<<<< HEAD
        self._shell.settimeout(shell_timeout)

        if self.device_type.set_shell_prompt_command:
            self.shell_send_and_receive(
                self.device_type.set_shell_prompt_command
            )

        if self.device_type.no_pagination_command:
            self.shell_send_and_receive(self.device_type.no_pagination_command)

    def _shell_execute_no_pagination_command(self, no_pagination_command: str) -> None:
        """

        :param no_pagination_command:
            Object representing a no pagination command. That is, for example,
            "terminal length 0" for Cisco IOS shell-like platforms
            or
            "set cli screen-length 0" for Juniper JunOS shell-like platforms.
        :type no_pagination_command:
            `str`

        :returns:
            `NoneType`
        """
        if no_pagination_command:
            self.shell_send_and_receive(no_pagination_command, timeout=1.0)

    def _return_ssh_shell(self) -> paramiko.channel.Channel:
        """
        Invoke an ssh shell with its parameter (term, width, height), set the
        ssh shell timeout, and return the ssh shell.

        :returns:
            `paramiko.channel.Channel` object representing an ssh shell.
        """
        ssh_shell = self._client.invoke_shell(
            term=self.shell_terminal_type,
            width=self.shell_receive_number_of_bytes.shell_terminal_width,
            height=self.shell_receive_number_of_bytes.shell_terminal_height
        )

        sleep(1.0)

        if ssh_shell.recv_ready():
            while ssh_shell.recv_ready():
                self.shell_received_bytes += ssh_shell.recv(
                    self.shell_receive_number_of_bytes
                )

        sleep(1.0)

        return ssh_shell

    def _ssh_client_connect(self) -> None:
        """
        Perform a paramiko.SSHClient instance connect.

        :returns:
            `NoneType`
        """
=======
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
>>>>>>> 2.0
        self._client.connect(
            self.hostname,
            port=self.port,
            username=self.username,
            password=self.password,
            allow_agent=False,
            look_for_keys=False,
            sock=self._jump_channel
        )

<<<<<<< HEAD
    def _set_jump_channel(
            self,
            jump_hostname: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
            jump_username: str,
            jump_password: str) -> None:
        """
        If values for jump_hostname and jump_username and jump_password were
        supplied, then set the jump channel.

        :param jump_hostname:
            Object representing the jump ssh server hostname
        :type jump_hostname:
            `str`

        :param jump_username:
            Object representing the jump ssh server username to authenticate
            with.
        :type jump_username:
            `str`

        :param jump_password:
            Object representing the jump ssh server username password to
            authenticate with.
        :type jump_password:
            `str`

        :returns:
            `NoneType`
        """
=======
    def _set_jump_channel(self, jump_hostname, jump_username, jump_password):
>>>>>>> 2.0
        if jump_hostname and jump_username and jump_password:
            self._jump_channel = self._return_jump_channel(
                self.hostname,
                jump_hostname=jump_hostname,
                jump_username=jump_username,
                jump_password=jump_password
            )

<<<<<<< HEAD
    @staticmethod
    def _remove_ansi_escape_sequences(string_as_bytes: bytes) -> bytes:
=======
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
>>>>>>> 2.0
        """
        Remove ANSI Escape characters.

<<<<<<< HEAD
        :param string_as_bytes:
            Object representing the string to have ANSI escape characters
            removed.
        :type string_as_bytes:
            `bytes`

        :returns:
=======
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
>>>>>>> 2.0
            `bytes`
        """
        ansi_escape_pattern = br'''
            \x1b
            [[:punct:]]
            [[:print:]]{1,}
            \x07
            |
            \x1b
            [[:punct:]]
<<<<<<< HEAD
            [[:digit:]]{1,2}
            (?:
                [[:upper]]
                |
                [[:lower:]]
            )
=======
            [[:digit:]]{1,4}
            [[:lower:]]
>>>>>>> 2.0
            [[:punct:]]{0,1}
            |
            \x1b
            [[:punct:]]
            [
                [:upper:]
                [:lower:]
            ]
            |
            \x1b
            [[:punct:]]{1,2}
            [[:graph:]]{4,5}
            |
            [[:alpha:]]\x08
            |
            [ ]*\r[ ]*
        '''
        escape_sequence_regexp = re.compile(
            ansi_escape_pattern,
            flags=re.VERSION1 | re.VERBOSE
        )
        return escape_sequence_regexp.sub(b'', string_as_bytes)

    @property
    def shell_timeout(self) -> float | int:
        """
        The configured `<instance>._shell.timeout value.

        :returns:
            `float` or `int`
        """
<<<<<<< HEAD
        return self._shell.gettimeout()

    @property
    def shell_is_closed(self) -> bool:
        """
        `<instance>.shell_is_closed` @property decorated method representing
        `<instance>._shell.closed`

        :returns:
            `bool`
        """
        return self._shell.closed
=======
        if not self._shell_is_closed:
            while self._shell.recv_ready():
                self.shell_received_bytes += self._shell.recv(
                    self.shell_receive_number_of_bytes
                )
                sleep(1.0)
>>>>>>> 2.0

    @property
    def shell_transcript(self) -> str:
        """
        Return a `str` representation of `<instance>.shell_received_bytes`,
        where `<instance>.shell_received_bytes` is a `bytes` representation of
        the whole ssh shell session.

        :returns:
            `str`
        """
        return '\n'.join(
            [
                i.decode('utf-8') for i in
                [
                    self._remove_ansi_escape_sequences(v)
                    for v in self.shell_received_bytes.splitlines()
                ]
                if not re.search(br'^ {0,}$', i)
            ]
        )

    def shell_send(self, command: str) -> None:
        """
        Send a command to the connected SSH server for execution.

        :param command:
            Object representing the command to be sent to the SSH server.
        :type command:
            `str`

        :returns:
            `NoneType`

<<<<<<< HEAD
        :raises:
            `ShellSendError`
            `ShellClosedError`
        """
        if '\r' in command or '\n' in command:
            raise ValueError(
                'Command, `{}`, contains "\\r" or "\\n".'.format(
                    command.encode('unicode_escape').decode()
                )
            )

        command_to_send: str = '{}\r'.format(command)

        if not self.shell_is_closed:
            try:
                self._shell.sendall(command_to_send.encode())
            except socket.timeout as socket_timeout:
                raise ShellTimeoutError(
                    'SHELL TIMEOUT ERROR: Unable to send command, `{}`, within '
                    'shell timeout of {} seconds'.format(
                        command,
                        self.shell_timeout
=======
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
>>>>>>> 2.0
                    )
                ) from socket_timeout
        else:
            error_text: str = 'SHELL CLOSED ERROR: Unable to send command, ' \
                         '`{}`, to remote SSH server because the shell is ' \
                         'closed.'.format(command)
            raise ShellClosedError(error_text)

<<<<<<< HEAD
        if not self._shell.recv_ready():
            sleep(1.0)

    def shell_receive(self, timeout: float | int | None = None) -> None:
=======
        self._shell.settimeout(original_shell_timeout)
        sleep(1.0)

    def shell_receive(self, timeout: float = -1.0) -> None:
>>>>>>> 2.0
        """
        Receive the output of a command executed on the SSH server.

        :param timeout:
            Object representing a time period, in seconds, to wait, during
            `<instance>._shell.recv(`<number_of_bytes>`)`, before a
            `socket.timeout` error is raised.
        :type timeout:
            `float` | `int` | `NoneType`

        :returns:
            `NoneType`

        :raises:
            `ShellClosedError`
            `ShellTimeoutError`
        """
<<<<<<< HEAD
        original_shell_timeout: float | int = self._shell.gettimeout()
=======
        timeout_values = (-1, -1.0, 90, 90.0, 0, 0.0)
        original_shell_timeout = self.shell_timeout
>>>>>>> 2.0

        if timeout not in (None, -1, -1.0, 0) and timeout != self.shell_timeout:
            self._shell.settimeout(timeout)

<<<<<<< HEAD
        received_bytes: bytes = ''.encode()

        while not self.device_type.shell_prompt_regexp.search(
                self._remove_ansi_escape_sequences(received_bytes)):
=======
        received_bytes = ''.encode()

        while not (self.shell_prompt_regexp.search(received_bytes) or
                   received_bytes.endswith(self.shell_prompt_pattern)):
>>>>>>> 2.0
            try:
                received_bytes += self._shell.recv(
                    self.shell_receive_number_of_bytes
                )
<<<<<<< HEAD
                # print(received_bytes)
                # print(self._remove_ansi_escape_sequences(received_bytes))
                if not self._shell.recv_ready():
                    sleep(1.0)
            except socket.timeout as socket_timeout:
                self.shell_received_bytes += received_bytes
                error_text: str = 'SHELL TIMEOUT ERROR: shell prompt pattern ' \
                                  'not received before timeout of {} seconds'
                raise ShellTimeoutError(
                    error_text.format(self._shell.gettimeout())
                ) from socket_timeout

            if self.shell_is_closed:
=======

                if not self._shell.recv_ready():
                    sleep(1.0)
            except socket.timeout as socket_timeout:
                error_text = 'SHELL TIMEOUT ERROR: shell prompt pattern ' \
                             'not received before timeout {}'.format(timeout)
                raise ShellTimeoutError(error_text) from socket_timeout

            if self._shell_is_closed:
>>>>>>> 2.0
                break

        self.shell_received_bytes += received_bytes

        self._shell.settimeout(original_shell_timeout)

    def shell_send_and_receive(self, command: str,
                               timeout: float | int | None = None) -> None:
        """
        A method that uses both `<instance>.shell_send()` and
        `<instance>.shell_receive()`

        :param command:
            see `shell_send()` docstring
        :type command:
            `str`

        :param timeout:
            see `shell_received()` docstring
        :type timeout:
            `float` | `int` | `NoneType`

        :returns:
            `NoneType`

        :raises:
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

        :param destination:
            Object representing the hostname or IP Address of the target SSH
            server.
        :type destination:
            `str`

        :param jump_hostname:
            Object representing the hostname or IP Address of the SSH server to
            be used as the jump host.
        :type jump_hostname:
            `str`

        :param jump_username:
            Object representing the username used to authenticate to the SSH
            server to be used as the jump host.
        :type jump_username:
            `str`

        :param jump_password:
            Object representing the password of the username used to
            authenticate to the SSH server to be used as the jump host.
        :type jump_password:
            `str`

        :returns:
            `paramiko.channel.Channel` object
        """
        client = paramiko.SSHClient()

        client.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())

        source: tuple = ('127.0.0.1', 22)
        destination: tuple = (destination, 22)

        client.connect(
            jump_hostname,
            username=jump_username,
            password=jump_password,
            allow_agent=False,
            look_for_keys=False
        )

        transport: paramiko.transport.Transport = client.get_transport()
        channel: paramiko.channel.Channel = transport.open_channel(
            'direct-tcpip',
            dest_addr=destination,
            src_addr=source
        )

        return channel

    def __str__(self):
        return self.shell_transcript

    def __repr__(self):
<<<<<<< HEAD
        repr_text: str = '<{}(Hostname={}, ' \
                         'Port Number={}, ' \
                         'Shell Terminal Type={}, ' \
                         'Shell Terminal Width={}, ' \
                         'Shell Terminal Height={}, ' \
                         'Shell Receive Number of Bytes={}, ' \
                         'Shell Timeout={})>'
=======
        repr_text = '<{}(Hostname={}, ' \
                    'Port Number={}, ' \
                    'Shell Terminal Type={}, ' \
                    'Shell Terminal Width={}, ' \
                    'Shell Terminal Height={}, ' \
                    'Shell CLI Type={}, ' \
                    'Shell Timeout={}, ' \
                    'Shell Receive Number of Bytes={})>'
>>>>>>> 2.0
        return repr_text.format(
            self.__class__.__name__,
            self.hostname,
            self.port,
            self.shell_terminal_type,
<<<<<<< HEAD
            self.shell_receive_number_of_bytes.shell_terminal_width,
            self.shell_receive_number_of_bytes.shell_terminal_height,
            self.shell_receive_number_of_bytes,
            self.shell_timeout
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._shell.close()
        self._client.close()

    def __del__(self):
        if hasattr(self, '_shell'):
            delattr(self, '_shell')
            delattr(self, '_client')
=======
            self.shell_terminal_width,
            self.shell_terminal_height,
            self.shell_cli_type,
            self.shell_timeout,
            self.shell_receive_number_of_bytes
        )
>>>>>>> 2.0
