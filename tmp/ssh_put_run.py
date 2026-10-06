# -*- coding: utf-8 -*-
"""上传文件到网关并执行命令（用于部署抓包/调试）。"""
import sys
import paramiko

HOST = "192.168.1.42"
PORT = 22
USER = "wxg"
PASS = "wanggang"

def main():
    local = sys.argv[1]
    remote = sys.argv[2]
    cmds = sys.argv[3:]
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, PORT, USER, PASS, timeout=15)
    sftp = c.open_sftp()
    sftp.put(local, remote)
    sftp.close()
    print("uploaded %s -> %s" % (local, remote))
    for cmd in cmds:
        i, o, e = c.exec_command("echo '%s' | sudo -S -p '' %s" % (PASS, cmd), timeout=120)
        out = o.read().decode("utf-8", "replace")
        err = e.read().decode("utf-8", "replace")
        print("$ " + cmd)
        if out.strip():
            print(out.rstrip())
        if err.strip():
            print("[stderr] " + err.rstrip())
    c.close()

if __name__ == "__main__":
    main()
