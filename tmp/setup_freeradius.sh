#!/bin/bash
# FreeRADIUS 参考实现配置：EAP-MSCHAPv2 对照实验
set -e

# 1) clients.conf：新增本机客户端（secret=mytestkey）
cat >> /etc/freeradius/3.0/clients.conf <<'EOF'

client modpkica_test {
    ipaddr = 127.0.0.1
    secret = mytestkey
    shortname = modpkica-test
}
EOF

# 2) users：admin666 / admin666
cat >> /etc/freeradius/3.0/users <<'EOF'

admin666 Cleartext-Password := "admin666"
EOF

# 3) 检查 mschapv2 已启用
grep -A4 'mschapv2' /etc/freeradius/3.0/mods-available/eap | head -20

# 4) 启动 FreeRADIUS
systemctl restart freeradius
sleep 1
systemctl is-active freeradius
