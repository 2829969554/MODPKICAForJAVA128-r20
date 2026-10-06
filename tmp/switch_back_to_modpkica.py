#!/usr/bin/env python3
# 把 strongSwan eap-radius 指回 MODPKICA RADIUS（192.168.1.6 / mytestkey）
p = "/etc/strongswan.d/charon/eap-radius.conf"
s = open(p).read()
s = s.replace("address = 127.0.0.1", "address = 192.168.1.6")
s = s.replace("secret = testing123", "secret = mytestkey")
open(p, "w").write(s)
print(s)
