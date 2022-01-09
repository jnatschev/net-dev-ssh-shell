"netdevsshshelltest.sh" and "netdevsshshelltest.py" are used together to perform
testing of the netdevsshshell program.

The two test files are used in a Docker container running in a GNS3
(https://gns3.com/) topology. The GNS3 topology has four devices, a(n):
- Arista vEOS (4.25.5M)
- Cisco CSR1000v (17.02.01r)
- Juniper vSRX (20.3R1.8)

The two test files run through a set of conda/mamba environments. The
conda/mamba environments are:
python>=3.7,<3.8
python>=3.8,<3.9
python>=3.9,<3.10
python>=3.10,<3.11

Each conda/mamba environment satisfies the netdevsshshell dependencies.

"netdevsshshelltest.sh" is used to start the testing, it:
- activates each conda/mamba environment;
  while in each environment:
  - executes "netdevsshshelltest.py";
  - "netdevsshshell.py" connects to each network device;
  - "netdevsshshell.py" finds and stores the value of the network device's shell
    prompt, pre-command execution;
  - once connected, executes a command on the network device;
  - if the program determines that all the command output has been received, then
    finds and stores the value of the network device's shell prompt, post-command
    execution;
  - compares pre-command execution shell prompt and post-command execution shell
    prompt
  - if comparison fails, prints the pre-command execution shell prompt and the
    post-command execution shell prompt for visual comparison.

