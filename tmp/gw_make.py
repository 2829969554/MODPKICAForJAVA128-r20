# -*- coding: utf-8 -*-
"""解压、配置、编译 eapol_test。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=300):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("=== 解压 ===")
print(run("cd /tmp && tar xzf wpa_supplicant-2.10.tar.gz && ls -d wpa_supplicant-2.10"))
print("=== 配置 .config ===")
cfg = ("cd /tmp/wpa_supplicant-2.10/wpa_supplicant && cp defconfig .config && "
       "sed -i 's/#CONFIG_EAP_TLS=y/CONFIG_EAP_TLS=y/; s/#CONFIG_EAP_PEAP=y/CONFIG_EAP_PEAP=y/; s/#CONFIG_EAP_MSCHAPV2=y/CONFIG_EAP_MSCHAPV2=y/; s/#CONFIG_EAP_TTLS=y/CONFIG_EAP_TTLS=y/; s/#CONFIG_EAP_GTC=y/CONFIG_EAP_GTC=y/' .config && "
       "grep -E 'CONFIG_EAP_TLS|CONFIG_EAP_MSCHAPV2|CONFIG_DRIVER' .config | head -6")
print(run(cfg))
print("=== 编译 ===")
print(run("cd /tmp/wpa_supplicant-2.10/wpa_supplicant && make eapol_test 2>&1 | tail -8"))
print("=== 安装确认 ===")
print(run("ls -la /tmp/wpa_supplicant-2.10/wpa_supplicant/eapol_test 2>/dev/null; cp /tmp/wpa_supplicant-2.10/wpa_supplicant/eapol_test /usr/local/bin/ 2>/dev/null; eapol_test --help 2>&1 | head -3"))
cli.close()
