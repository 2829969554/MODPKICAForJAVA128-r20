# -*- coding: utf-8 -*-
"""Download remote files via paramiko (wxg@192.168.1.42)."""
import sys, os
import paramiko

HOST, PORT, USER, PASS = "192.168.1.42", 22, "wxg", "wanggang"

def main():
    pairs = []  # (remote_path, local_path)
    for a in sys.argv[1:]:
        if "->" in a:
            r, l = a.split("->", 1)
            pairs.append((r.strip(), l.strip()))
        else:
            pairs.append((a, os.path.basename(a)))
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, PORT, USER, PASS, timeout=15, banner_timeout=15, auth_timeout=15)
    sftp = client.open_sftp()
    for r, l in pairs:
        try:
            sftp.get(r, l)
            print("saved %s -> %s (%d bytes)" % (r, l, os.path.getsize(l)))
        except Exception as e:
            print("FAIL %s: %r" % (r, e))
    sftp.close()
    client.close()

if __name__ == "__main__":
    main()
