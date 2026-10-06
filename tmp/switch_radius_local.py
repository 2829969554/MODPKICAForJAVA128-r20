#!/usr/bin/env python3
# 切换 strongSwan eap-radius 指向本机 FreeRADIUS（对照实验）
import re
p = "/etc/strongswan.d/charon/eap-radius.conf"
s = open(p).read()
s = s.replace("address = 192.168.1.6", "address = 127.0.0.1")
s = s.replace("secret = mytestkey", "secret = testing123")
open(p, "w").write(s)
print(s)
