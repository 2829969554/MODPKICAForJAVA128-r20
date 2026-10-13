# -*- coding: utf-8 -*-
"""修正 .config 只保留 DBUS_NONE 后编译。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=300):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("=== 修正 .config ===")
print(run("cd /tmp/wpa_supplicant-2.10/wpa_supplicant && sed -i 's/^CONFIG_CTRL_IFACE_DBUS_NEW=y/#CONFIG_CTRL_IFACE_DBUS_NEW=y/; s/^CONFIG_CTRL_IFACE_DBUS_INTRO=y/#CONFIG_CTRL_IFACE_DBUS_INTRO=y/; s/^CONFIG_CTRL_IFACE_DBUS=y/#CONFIG_CTRL_IFACE_DBUS=y/' .config && grep CONFIG_CTRL_IFACE_DBUS .config"))
print("=== 编译 ===")
print(run("cd /tmp/wpa_supplicant-2.10/wpa_supplicant && make clean >/dev/null 2>&1; make eapol_test 2>&1 | tail -5"))
print("=== 安装 ===")
print(run("ls -la /tmp/wpa_supplicant-2.10/wpa_supplicant/eapol_test 2>/dev/null && cp /tmp/wpa_supplicant-2.10/wpa_supplicant/eapol_test /usr/local/bin/ && eapol_test --help 2>&1 | head -4"))
cli.close()
