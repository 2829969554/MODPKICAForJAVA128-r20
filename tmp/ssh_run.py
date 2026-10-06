# -*- coding: utf-8 -*-
"""SSH 辅助脚本：以 wxg 用户连接 192.168.1.42，需要 root 权限的命令自动 sudo。
用法: python ssh_run.py "命令1" "命令2" ...   (每个命令独立会话)
      python ssh_run.py --root "需要root的命令"
"""
import sys
import paramiko

HOST = "192.168.1.42"
PORT = 22
USER = "wxg"
PASS = "wanggang"
SUDO_PASS = "wanggang"

def _sudo_cmd(cmd):
    # 非交互 sudo：-S 从 stdin 读密码
    return "echo '%s' | sudo -S -p '' %s" % (SUDO_PASS, cmd)

def run(cmd, use_sudo=False):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, PORT, USER, PASS, timeout=15, banner_timeout=15, auth_timeout=15)
    full = _sudo_cmd(cmd) if use_sudo else cmd
    stdin, stdout, stderr = client.exec_command(full, timeout=120)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    client.close()
    return out, err

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print("usage: python ssh_run.py [--root] 'cmd1' 'cmd2' ...")
        sys.exit(1)
    use_sudo = False
    if args[0] == "--root":
        use_sudo = True
        args = args[1:]
    for cmd in args:
        print("=" * 20)
        print("$ " + ("sudo " if use_sudo else "") + cmd)
        print("=" * 20)
        try:
            out, err = run(cmd, use_sudo)
        except Exception as e:
            print("SSH ERROR: %r" % (e,))
            continue
        if out.strip():
            print(out.rstrip())
        if err.strip():
            print("[stderr] " + err.rstrip())
