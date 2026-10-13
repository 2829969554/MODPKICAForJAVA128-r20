# -*- coding: utf-8 -*-
"""更新 README 特性表 EAP-TLS 行（r20 事务化重传说明）。"""
p = 'README.md'
s = open(p, encoding='utf-8').read()
old = ('**EAP 层重传检测（RFC 3748 §5.1）**：NAS/网关 UDP 重传同一 EAP 事务（EAP-Id 与数据相同）时'
       '重发上次响应而非重复喂给 TLS，兼容 iOS 原生 IKEv2 经 strongSwan eap-radius 网关拨号'
       '（实测修复 `unexpected_message(10)`）')
new = ('**EAP 层重传检测（RFC 3748 §5.1，v1.28-r20 事务化）**：NAS/网关 UDP 重传同一 EAP 事务'
       '（EAP-Id 与数据相同）时，按「入包 EAP-Id + 数据指纹 → 当时下发的 EAP-Id + 响应快照 + 片内偏移」'
       '重放该笔响应（而非旧实现的「最近一次响应体」——拉片阶段那是末片，客户端永远解析不出 ServerHello → 死循环）；'
       '空拉取片同样纳入判定（重传→回放上一片，不再跳片）；服务端 Request Identifier 按 §4.1 自增，'
       '与客户端回显配合可精确区分「下一片 / 重传上一片」；握手推进中收到新的 ClientHello 视为客户端重启并重建握手'
       '（不再喂旧状态机 → `unexpected_message(10)`）。兼容 iOS/Windows 原生 IKEv2 经 strongSwan eap-radius 网关拨号')
assert old in s, 'README 特性表未匹配'
s = s.replace(old, new, 1)
open(p, 'w', encoding='utf-8').write(s)
print('README 特性表已更新')
