import paramiko
import regex as re
shell_prompt_regexp = re.compile(
    br'(?=[\r\n]{1}[[:alpha:]{1,}[:digit:]{0,}[:punct:]{0,} {0,}]{1,50}[#$%>]{1} {0,1}$)',
    flags=re.I
)
ansi_escape_regexp = re.compile(
    br'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]',
    flags=re.IGNORECASE
)

client = paramiko.SSHClient()
client.set_missing_host_key_policy(
    paramiko.AutoAddPolicy()
)
client.connect('localhost', username='jnatschev', password='Fl0r1552nt5', allow_agent=False, look_for_keys=False)
shell = client.invoke_shell(term='vt100', width=132, height=132)
shell.settimeout(2.0)
shell_receive_bytes = 132*132
shell.sendall('unalias -a && export PS1="shellprompt$ "\r')

shell_received_bytes = b''
while not shell_prompt_regexp.search(shell_received_bytes):
    shell_received_bytes += ansi_escape_regexp.sub(
        b'',
        shell.recv(shell_receive_bytes)
    )

print(shell_received_bytes.decode('ascii'))


while shell.recv_ready():
    shell_received_bytes += ansi_escape_regexp.sub(
        b'',
        shell.recv(shell_receive_bytes)
    )

shell_prompt_regexp.search(shell_received_bytes)
