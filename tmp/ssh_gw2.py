import paramiko

def ssh_exec(host, user, pwd, cmds):
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(host, port=22, username=user, password=pwd, timeout=10)
    for c in cmds:
        stdin, stdout, stderr = cli.exec_command(c, timeout=25)
        out = stdout.read().decode('utf-8', 'replace')
        err = stderr.read().decode('utf-8', 'replace')
        print(f'>>> {c}\n{out}{err}')
    cli.close()

ssh_exec('10.255.228.225', 'root', 'root', [
    'journalctl -u strongswan --since "17:20" -n 60 --no-pager 2>/dev/null | tail -60',
    'ipsec status 2>/dev/null | tail -20',
])
