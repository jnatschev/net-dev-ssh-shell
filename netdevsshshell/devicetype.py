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
  - preset the shell prompt regular expression;
    regex is used as the regular expression engine to enable the use of POSIX
    character classes.
  - execute a network device "no pagination" command;
  - use a secure shell jump host to reach the target ssh server. The equivalent
    of the OpenSSH -J option.
- change management governance:
  All ssh shell output is stored in an attribute. The ssh shell output may then
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
from __future__ import annotations
import regex as re


class DeviceTypeBase:
    """
    Base Device Type Class
    """
    no_pagination_command: str = ''
    shell_prompt_pattern: bytes = br''
    shell_prompt_regexp: re.Regex = re.compile(
        shell_prompt_pattern,
        flags=re.VERSION1 | re.VERBOSE
    )

    def __repr__(self):
        repr_text = '<{}(no_pagination_command={}, ' \
                    'shell_prompt_pattern={}, ' \
                    'shell_prompt_regexp={})>'
        return repr_text.format(
            self.__class__.__name__,
            self.no_pagination_command,
            self.shell_prompt_pattern,
            self.shell_prompt_regexp
        )


class DeviceTypeNix(DeviceTypeBase):
    """
    Linux/Unix Device Type Class
    """
    shell_prompt_pattern = br'''
        [\r\n]
        [
            [~]{0,1}
            [@]{0,1}
            [:]{0,1}
            [:blank:]{0,}
            [-]{0,}
            [/]{0,}
            [:alnum:]{1,}
        ]{0,50}
        [#$%]
        [[:blank:]]{0,1}
        $
    '''
    shell_prompt_regexp = re.compile(
        shell_prompt_pattern,
        flags=re.VERSION1 | re.VERBOSE
    )


class DeviceTypeIos(DeviceTypeBase):
    """
    Cisco IOS-like Device Type Class
    """
    no_pagination_command = 'terminal length 0'
    shell_prompt_pattern = br'''
        [\r\n]
        [
            [-]{0,}
            [(]{0,1}
            [)]{0,1}
            [:alnum:]{1,}
        ]{1,50}
        [#>]
        [[:blank:]]{0,1}
        $
    '''
    shell_prompt_regexp = re.compile(
        shell_prompt_pattern,
        flags=re.VERSION1 | re.VERBOSE
    )


class DeviceTypeJunos(DeviceTypeBase):
    """
    Juniper JunOS-like Device Type Class
    """
    no_pagination_command = 'set cli screen-length 0'
    shell_prompt_pattern = br'''
        [\r\n]
        ['
            [:blank:]{0,}
            [@]{0,1}
            [-]{0,}
            [:alnum:]{1,}
        ]{0,50}
        [#$>]
        [[:blank:]]{0,1}
        $
    '''
    shell_prompt_regexp = re.compile(
        shell_prompt_pattern,
        flags=re.VERSION1 | re.VERBOSE
    )
