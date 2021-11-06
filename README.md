netdevsshshell is a cross-platform Python project providing a non-interactive
ssh shell capability. The reason for this project's development is it was
difficult to find an existing python ssh shell project that met requirements
and the fact that there is never a guarantee that a computer system has access
to a native ssh client. 
### SUPPORTED PLATFORMS
  - Darwin  
  - Linux  
  - Windows  
### SUPPORTED PYTHON VERSIONS 
  - 3.7  
  - 3.8  
  - 3.9  
### SUPPORTED SSH AUTHENTICATION  
  - Password  
### SUPPORT SSH JUMP  
  - True  
   > Equivalent of openssh -J option  
### SUPPORTED SHELL TYPES  
  - auto
  - ios-like as ios
  - cisco wireless lan controller as cwlc
  - junos-like as junos
  - sh, bash, and zsh as nix
### INITIAL SHELL COMMAND PROCESSED BEFORE SHELL IS AVAIALBE
  - ios: `terminal length 0`
  - cwlc: `config paging disable`
  - junos: `set cli screen-length 0`
  - nix: `unalias -a && export PS1="shellprompt$ "`
### DEPENDENCIES  
  - paramiko>=2.7.2 
  - regex>=2021.3.17  
### EXPOSURES
The two dependencies, ***paramiko*** and ***regex*** are exposed when this
package is imported as a module:
~~~
import netdevsshshell
netdevsshshell.paramiko.SSHClient()
netdevsshshell.re.search(r"^[[:alpha:]]{1,}$", "hownowbrowncow")
~~~
### DEFAULTS
#### class NetDevSshShell
##### __init__()
- port: 22
- terminal_width: 132
- terminal_height: 132
- cli_type: auto
***auto*** attempts to determine the shell type automagically
- shell_receive_timeout: 90s  
***90***s was chosen to ensure this program receives all command output.  
For instance, the output of the ios-like command `show tech-support` has
  moments where no output is being received because the network device is
  processing data to output. With a short timeout value this program will raise
  a python socket.timeout exception. This timeout value may be provided on a
  per command basis after this program has been initialised/instantiated.
- jump_hostname: None
- jump_username: None
- jump_password: None
##### ATTRIBUTES
- receive_encoding: 'cp1252'
- shell_prompt_pattern:
```
br'''
    [
        [:alpha:]{1,}
        [:digit:]{0,}
        [:punct:]{0,}
        [:space:]{0,}
    ]{1,50}?
    [#$%>]{1}
    [[:space:]]{0,1}
    $
'''
```
shell_prompt_pattern may altered to suit other requirements after the shell
has been initialised/instantiated. NOTE: MUST BE BYTES AND IS COMPILED BY
REGEX (as re) with flags VERSION1 | VERBOSE
- ansi_escape_pattern:
```
br'''
    (?:
        [[:cntrl:]]
        \]
        [[:graph:]]{1,}?
        [[:cntrl:]]
        |
        [[:cntrl:]]
        \[
        [[:digit:]]
        [[:alpha:]]
        [[:punct:]]{0,1}
        |
        [[:cntrl:]]
        \[
        [[:alpha:]]
        |
        [[:cntrl:]]
        \[
        [[:punct:]]
        [[:digit:]]{1,4}
        [[:alpha:]]
        |
        [[:alpha:]]
        [[:cntrl:]]
    )
'''
```
The purpose of this regular expression is to remove ansi escape sequences  
from the output of some commands that interfere with this program's  
normal processing.  

### USAGE
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

### EXAMPLES:
NON JUMP HOST Cisco IOS-like or Juniper JunOS-like (auto discovery `cli_type`):
```
from netdevsshshell import NetDevSshShell

# cli_type='auto' MAY BE OMITTED BECAUSE IT IS DEFAULT
ssh = NetDevSshShell('hostname', username='username', password='password, cli_type='auto')

# PROCESS COMMANDS
ssh.shell_send_and_receive('show running-config')
print(ssh.shell_transcript)

# WHEN COMPLETE
# THIS WILL EXPLICITLY CLOSE BOTH SHELL AND CLIENT
del ssh
```
OR
```
from netdevsshshell import NetDevSshShell

# cli_type='auto' MAY BE OMITTED BECAUSE IT IS DEFAULT
ssh = NetDevSshShell('hostname', username='username', password='password, cli_type='auto')
with ssh:
    ssh.shell_send_and_receive('show tech-support', timeout=100.0)
    ssh.shell_send_and_receive('show ip interface brief', timeout=1.5)
    ssh.shell_send_and_receive('show inventory', timeout=2.6)
    ssh.shell_send_and_receive('exit', timeout=1.0)
    print(ssh.shell_transcript)
```

NON JUMP HOST Cisco IOS-like:
```
from netdevsshshell import NetDevSshShell
ssh = NetDevSshShell('hostname', username='username', password='password, cli_type='ios')

# PROCESS COMMANDS
ssh.shell_send_and_receive('show running-config')
print(ssh.shell_transcript)

# WHEN COMPLETE
# THIS WILL EXPLICITLY CLOSE BOTH SHELL AND CLIENT
del ssh
```
OR
```
from netdevsshshell import NetDevSshShell
ssh = NetDevSshShell('hostname', username='username', password='password, cli_type='ios')
with ssh:
    ssh.shell_send_and_receive('show tech-support', timeout=100.0)
    ssh.shell_send_and_receive('show ip interface brief', timeout=1.5)
    ssh.shell_send_and_receive('show inventory', timeout=2.6)
    ssh.shell_send_and_receive('exit', timeout=1.0)
    print(ssh.shell_transcript)
```

NON JUMP HOST Juniper JunOS-like:
```
from netdevsshshell import NetDevSshShell
ssh = NetDevSshShell('hostname',username='username', password='password', cli_type='junos')

# PROCESS COMMANDS
ssh.shell_send_and_receive('show configuration | display set')
print(ssh.shell_transcript)

# WHEN COMPLETE
# THIS WILL EXPLICITY CLOST BOTH SHELL AND CLIENT
del ssh
```
OR
```
from netdevsshshell import NetDevSshShell
ssh = NetDevSshShell('hostname',username='username', password='password', cli_type='junos')
with ssh:
    ssh.shell_send_and_receive('show configuration', timeout=20.0)
    ssh.shell_send_and_receive('show configuration | display set', timeout=15.0)
    ssh.shell_send_and_receive('quit', timeout=2.0)
    print(ssh.shell_transcript)
```

JUMP HOST Cisco IOS-like:
```
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
```
OR
```
from netdevsshshell import NetDevSshShell
ssh = NetDevSshShell('hostname',
                     username='username',
                     password='password',
                     cli_type='ios',
                     jump_hostname='jump_hostname',
                     jump_username='jump_username',
                     jump_password='jump_password'
)

with ssh:
    ssh.shell_send_and_receive('show running-config')
    ssh.shell_send_and_receive('show startup-config')
    print(ssh.shell_transcript)
```

JUMP HOST Juniper JunOS-like:
```
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
    # THIS WILL EXPLICITLY CLOSE BOTH SHELL AND CLIENT
    del ssh
```
OR
```
from netdevsshshell import NetDevSshShell
ssh = NetDevSshShell('hostname',
                     username='username',
                     password='password',
                     cli_type='junos',
                     jump_hostname='jump_hostname',
                     jump_username='jump_username',
                     jump_password='jump_password'
)

with ssh:
    ssh.shell_send_and_receive('show configuration', timeout=20.0)
    ssh.shell_send_and_receive('show configuration | display set', timeout=15.0)
    print(ssh.shell_transcript)
 ```
 
