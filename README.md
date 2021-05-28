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
- shell_prompt_regexp:
`br'(?=[\r\n]{1}[[:alpha:]{1,}[:digit:]{0,}[:punct:]{0,} {0,}]{1,50}[#$%>]{1} {0,1}$)'`
shell_prompt_regexp may altered to suit other requirements after the shell
has been initialised/instantiated.
- ansi_escape_regexp:
`br'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]'`  
The purpose of this regular expression is to remove ansi escape sequences  
from the output of some commands that interfere with this program's  
normal processing.
###USAGE
