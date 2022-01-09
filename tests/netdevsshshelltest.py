from netdevsshshell import NetDevSshShell
devices = {
    'cisco': {
        'hostname': '10.0.2.3',
        'username': 'cisco',
        'password': 'cisco',
        'device_type': 'ios'
    },
    'arista': {
        'hostname': '10.0.2.5',
        'username': 'arista',
        'password': 'arista',
        'device_type': 'ios'
    },
    'juniper': {
        'hostname': '10.0.2.1',
        'username': 'juniper',
        'password': 'Jun1p3r',
        'device_type': 'junos'
    }
}


def test():
    for brand, device_elements in devices.items():
        ndss = NetDevSshShell(*device_elements.values())
        pre_shell_prompt = ndss.shell_transcript.splitlines()[-1]

        if 'cisco' in brand:
            print('Executing Cisco `show tech-support` command.')
            with ndss:
                try:
                    ndss.shell_send_and_receive('show tech-support', timeout=10.0)
                except Exception as exception:
                    print(exception)
            print('Execution of Cisco `show tech-support` command complete.')
        elif 'arista' in brand:
            print('Executing Arista `show tech-support` command.')
            with ndss:
                try:
                    ndss.shell_send_and_receive('show tech-support', timeout=10.0)
                except Exception as exception:
                    print(exception)
            print('Execution of Arista `show tech-support` command complete.')
        elif 'juniper' in brand:
            print('Executing Juniper `request support information` command.')
            with ndss:
                try:
                    ndss.shell_send_and_receive(
                        'request support information',
                        timeout=10.0
                    )
                except Exception as exception:
                    print(exception)
            print('Execution of Juniper `request support information` command complete.')

        post_shell_prompt = ndss.shell_transcript.splitlines()[-1]

        if not pre_shell_prompt == post_shell_prompt:
            print('''
Hostname: {}
Pre shell prompt: {}
Post shell prompt: {}
'''.format(ndss.hostname, pre_shell_prompt, post_shell_prompt)
            )


def main():
    test()


if __name__ == '__main__':
    main()
