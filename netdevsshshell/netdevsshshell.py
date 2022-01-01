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

- Regex provides alternative regular expression processing capability. Namely
  the use of POSIX regular expression character classes.
  https://github.com/mrabarnett/mrab-regex
"""
from __future__ import annotations
from time import sleep
import ipaddress
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
    ShellPromptPattern: str = '[\r\n]' \
                              '[' \
                              '[:alnum:]{1,}' \
                              '[:punct:]{1,}' \
                              '[:blank:]{0,}' \
                              ']{1,50}?' \
                              '[#$%>]{1}' \
                              '[[:blank:]]{0,1}' \
                              '$'
    
    def __init__(self,
                 hostname: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
                 username: str,
                 password: str,
                 port: int = 22,
                 shell_terminal_type: str = 'xterm',
                 shell_terminal_width: int = 132,
                 shell_terminal_height: int = 30,
                 shell_timeout: float | int = 15.0,
                 shell_prompt_pattern: str = ShellPromptPattern,
                 no_pagination_command: str | None = None,
                 jump_hostname: str | ipaddress.IPv4Address | ipaddress.IPv6Address | None = None,
                 jump_username: str | None = None,
                 jump_password: str | None = None) -> None:
        """
        `NetDevSshShell` instance initialisation method
        
        :param hostname:
            `str` object representing the target ssh server hostname or IP
            Address.

        :param username:
            `str` object representing the username to authenticate to the target
            ssh server.

        :param password:
            `str` object representing the password of the username to
            authenticate to the target ssh server.

        :param port:
            `int` object representing the port number of the target ssh server.

        :param shell_terminal_type:
            `str` object representing the shell terminal type. For example:
            - vt100
            - xterm (default)
            - xterm-256color

        :param shell_terminal_width:
            `int` object representing the shell terminal width.
            Default: 132

        :param shell_terminal_height:
            `int` object representing the shell terminal height.
            Default: 30

        :param shell_timeout:
            `float` or `int` object representing a shell timeout in seconds.
            Default: 15.0
        
        :param shell_prompt_pattern:
            `str` object representing a regex compatible regular expression
            representing an expected ssh shell prompt.
            Default: None

        :param no_pagination_command:
            `str` object representing a command to be used to turn shell
            pagination off. Examples of such a command are:
            - Cisco-like network devices:
              'terminal length 0'
            - Juniper JunOS network devices:
              'set cli screen-length 0'
            Default: None

        :param jump_hostname:
            `str` object representing the hostname or IP Address of a jump ssh
            server used to get to the target ssh server. Equivalent to OpenSSH
            option -J.
            Default: None

        :param jump_username:
            `str` object representing the username to authenticate to the jump
            ssh host.
            Default: None

        :param jump_password:
            `str` object representing the password of the username to
            authenticate to the jump ssh host.
            Default: None
        """
        super().__init__()
        self.hostname: str = str(hostname)
        self.port: int = port
        self.username: str = username
        self.password: str = password

        self.shell_prompt_pattern = '{}'.format(
            shell_prompt_pattern
        ).encode(
            'unicode_escape'
        )

        self.shell_prompt_regexp = re.compile(
            self.shell_prompt_pattern,
            flags=re.VERSION1
        )
        self.shell_terminal_type: str = shell_terminal_type
        self.shell_receive_number_of_bytes = ShellReceiveNumberOfBytes(
            shell_terminal_width=shell_terminal_width,
            shell_terminal_height=shell_terminal_height
        )
        self._jump_channel = None
        self.shell_timeout: float = shell_timeout
        self.shell_received_bytes: bytes = ''.encode()
        self._client: paramiko.SSHClient = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()
        )

        self._set_jump_channel(jump_hostname, jump_username, jump_password)
        self._ssh_client_connect()

        self._shell = self._return_ssh_shell()

        self._shell.settimeout(self.shell_timeout)
        self.shell_receive()
        self._shell_execute_no_pagination_command(no_pagination_command)

    def _shell_execute_no_pagination_command(self,
                                             no_pagination_command: str
                                             ) -> None:
        """

        :param no_pagination_command:
            `str` object representing a no pagination command. That is, for
            example, "terminal length 0" for Cisco IOS shell-like platforms or
            "set cli screen-length 0" for Juiper JunOS shell-like platforms.

        :return:
            `NoneType`
        """
        if no_pagination_command:
            self.shell_send_and_receive(no_pagination_command, timeout=1.0)

    def _return_ssh_shell(self) -> paramiko.channel.Channel:
        """
        Invoke an ssh shell with its parameter (term, width, height), set the
        ssh shell timeout, and return the ssh shell.

        :return:
            `paramiko.channel.Channel` object representing a ssh shell.
        """
        ssh_shell = self._client.invoke_shell(
            term=self.shell_terminal_type,
            width=self.shell_receive_number_of_bytes.shell_terminal_width,
            height=self.shell_receive_number_of_bytes.shell_terminal_height
        )
        ssh_shell.settimeout(self.shell_timeout)
        return ssh_shell

    def _ssh_client_connect(self) -> None:
        """
        Perform a paramiko.SSHClient object connect.

        :return:
            `NoneType`
        """
        self._client.connect(
            self.hostname,
            port=self.port,
            username=self.username,
            password=self.password,
            allow_agent=False,
            look_for_keys=False,
            sock=self._jump_channel
        )

    def _set_jump_channel(
            self,
            jump_hostname: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
            jump_username: str,
            jump_password: str) -> None:
        """
        If values for jump_hostname and jump_username and jump_password were
        supplied, then set the jump channel.

        :param jump_hostname:
            `str` object representing the jump ssh server hostname

        :param jump_username:
            `str` object representing the jump ssh server username to
            authenticate with.

        :param jump_password:
            `str` object representing the jump ssh server username password to
            authenticate with.

        :return:
            `NoneType`
        """
        if jump_hostname and jump_username and jump_password:
            self._jump_channel = self._return_jump_channel(
                self.hostname,
                jump_hostname=jump_hostname,
                jump_username=jump_username,
                jump_password=jump_password
            )

    @property
    def shell_is_closed(self) -> bool:
        """
        `<instance>.shell_is_closed` @property decorated method representing
        `<instance>._shell.closed`

        :return:
            `bool`
        """
        return self._shell.closed

    @staticmethod
    def _remove_ansi_escape_sequences(string_as_bytes: bytes) -> bytes:
        """
        Remove ANSI Escape characters.

        :param string_as_bytes:
            `bytes` object representing the string to have ANSI Escape
            characters removed.

        :return:
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
            [[:digit:]]{1,2}
            (?:
                [[:upper]]
                |
                [[:lower:]]
            )
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
            flags=re.VERBOSE | re.VERSION0
        )
        return escape_sequence_regexp.sub(b'', string_as_bytes)

    @property
    def shell_transcript(self) -> str:
        """
        Return a `str` representation of `<instance>.shell_received_bytes`,
        where `<instance>.shell_received_bytes` is a `bytes` representation of
        the whole ssh shell session.

        Returns:
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
        send_sleep_time: float = 0.17
        command_to_send: str = '{}\r'.format(command)
        command_to_send_length: int = len(command_to_send)
        original_shell_timeout: float | int = self._shell.gettimeout()
        new_shell_timeout: float | int = command_to_send_length * send_sleep_time + 5.0

        self._shell.settimeout(new_shell_timeout)

        if not self.shell_is_closed:
            try:
                self._shell.sendall(command_to_send.encode())
            except socket.timeout as socket_timeout:
                raise ShellTimeoutError(
                    'SHELL TIMEOUT ERROR: Unable to send command, {}, within '
                    'shell timeout {} seconds'.format(
                        command_to_send, new_shell_timeout
                    )
                ) from socket_timeout
        else:
            error_text: str = 'SHELL CLOSED ERROR: Unable to send command,' \
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
        timeout_values: tuple = (-1, -1.0, 90, 90.0, 0, 0.0)
        original_shell_timeout: float | int = self.shell_timeout

        if timeout not in timeout_values:
            self._shell.settimeout(timeout)

        received_bytes: bytes = ''.encode()

        while not self.shell_prompt_regexp.search(
            self._remove_ansi_escape_sequences(received_bytes)
        ):
            try:
                received_bytes += self._shell.recv(1024)
                # print(received_bytes)
                # print(self._remove_ansi_escape_sequences(received_bytes))
                if not self._shell.recv_ready():
                    sleep(1.0)
            except socket.timeout as socket_timeout:
                error_text: str = 'SHELL TIMEOUT ERROR: shell prompt pattern ' \
                             'not received before timeout {}'.format(timeout)
                raise ShellTimeoutError(error_text) from socket_timeout

            if self.shell_is_closed:
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
        repr_text: str = '<{}(Hostname={}, ' \
                         'Port Number={}, ' \
                         'Shell Terminal Type={}, ' \
                         'Shell Terminal Width={}, ' \
                         'Shell Terminal Height={}, ' \
                         'Shell Receive Number of Bytes={}, ' \
                         'Shell Timeout={})>'
        return repr_text.format(
            self.__class__.__name__,
            self.hostname,
            self.port,
            self.shell_terminal_type,
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
