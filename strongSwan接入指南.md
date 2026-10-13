# MODPKICA RADIUS × strongSwan 网关接入指南

> 用途：在 Linux 服务器上部署 **strongSwan IKEv2 网关**，把手机 / Windows / macOS 的 VPN 认证（EAP-MSCHAPv2 用户名密码、EAP-TLS 客户端证书）转发到 Windows 主机上的 **MODPKICA Java RADIUS**（UDP 1812/1813）。
>
> 适用版本：MODPKICA **v1.28-r20**（2026-10-13）· strongSwan **5.9 / 6.0** · Debian 12/13 · Ubuntu 24.04+
>
> 一句话现状：**用户名密码（EAP-MSCHAPv2）四端全通；客户端证书（EAP-TLS）四端全通**——安卓 strongSwan App、iPhone 原生 VPN、Windows 10/11 自带 VPN（证书模式）、macOS 系统 VPN。r20 修复了"网关整包重传导致 iPhone/Windows 证书登录死循环"的问题（见第 13 节）。

---

## 目录

1. [架构与前提](#一架构与前提)
2. [方式一：一键脚本部署（推荐）](#二方式一一键脚本部署推荐)
3. [方式二：手工部署](#三方式二手工部署)
4. [用 MODPKICA 签发网关证书](#四用-modpkica-签发网关证书)
5. [签发 EAP-TLS 客户端证书](#五签发-eap-tls-客户端证书)
6. [证书部署与权限](#六证书部署与权限)
7. [swanctl.conf 逐字段详解](#七swanctlconf-逐字段详解)
8. [eap-radius.conf 逐字段详解](#八eap-radiusconf-逐字段详解)
9. [内核转发、NAT 与 TCP MSS](#九内核转发nat-与-tcp-mss)
10. [Windows 主机防火墙放行](#十windows-主机防火墙放行)
11. [启动与验证](#十一启动与验证)
12. [客户端拨号配置（iOS / 安卓 / Windows / macOS）](#十二客户端拨号配置ios--安卓--windows--macos)
13. [故障排查](#十三故障排查)
14. [兼容性与协议要点（重传 / 重启 / MSK）](#十四兼容性与协议要点重传--重启--msk)
15. [版本差异（strongSwan 5.9 ↔ 6.0）](#十五版本差异strongswan-59--60)
16. [附录：报文时序与日志样例](#十六附录报文时序与日志样例)

---

## 一、架构与前提

```
手机 / Windows / macOS          （IKEv2 拨号：EAP-MSCHAPv2 用户名密码 或 EAP-TLS 客户端证书）
   │  IKEv2  UDP 500 / 4500
   ▼
Linux strongSwan 网关            （网关证书证明服务器身份；EAP 报文整包转发）
   │  RADIUS UDP 1812 认证 / 1813 计费
   ▼
Windows 主机 MODPKICA Java RADIUS（modpkica.MAIN，配置文件 PKI/CONFIG.txt，用户库 PKI/USERS.txt）
   │  认证通过 → Access-Accept + MS-MPPE-Recv/Send-Key（EAP MSK）
   ▼
strongSwan 用 64B MSK 完成 IKEv2 AUTH（RFC 7296 §2.16）→ 协商 IPsec SA → 客户端拿到地址池 IP
```

**前提清单**

- Linux 服务器已装好（Debian 12/13、Ubuntu 24.04+），与 Windows 主机同网段可达，**静态 IP**（下文示例 `10.255.228.225`）
- Windows 主机局域网 IP（RADIUS 所在，下文示例 `10.255.228.55`）
- Java RADIUS 已运行（MAIN 服务），**共享密钥** = WebAdmin → Radius服务管理 的配置值（默认 `mytestkey`，即 `PKI/CONFIG.txt` 的 `RADIUSKEY`）
- 用户库里有测试账号（`PKI/USERS.txt`，WebAdmin → 用户管理 中添加；证书登录不需要建账号）
- 已签发**网关证书**（EKU serverAuth，SAN 同时含域名与服务器 IP）与**根证书**（见第四节）
- 根证书已安装到所有拨号客户端（见第十二节）

**认证方式与客户端支持对照**

| 认证方式 | 安卓 strongSwan App | iPhone 原生 VPN | Windows 10/11 自带 VPN | macOS 系统 VPN |
|---|---|---|---|---|
| EAP-MSCHAPv2（用户名密码） | ✅ | ✅（鉴定方式"用户名"） | ✅（登录信息"用户名和密码"） | ✅ |
| EAP-TLS（客户端证书） | ✅（IKEv2 Certificate） | ✅（鉴定方式"证书"） | ✅（登录信息"证书"） | ✅ |

> iOS / Windows 的"证书"模式底层就是 **EAP-TLS**（客户端证书放在 EAP 隧道里），不是 IKEv2 公钥签名认证——所以 RADIUS 侧看到的就是本指南描述的 EAP-TLS 报文。

---

## 二、方式一：一键脚本部署（推荐）

脚本：`linux/install_strongswan.sh`（已按 v1.28-r20 重写：证书逐项校验、幂等、失败即时报错）

```bash
# ① 在 Windows 主机（项目根）准备证书：网关证书 + 私钥 + 根证书
#    （证书怎么签见第四节；文件名用"序列号"）
scp PKI/CERT/{网关序列号}.crt   root@10.255.228.225:/tmp/gw.crt
scp PKI/KEY/{网关序列号}.key    root@10.255.228.225:/tmp/gw.key
scp PKI/ROOT/{根序列号}.crt     root@10.255.228.225:/tmp/root.crt

# ② 拷脚本并执行（参数：RADIUS服务器IP  共享密钥  网关ID）
scp linux/install_strongswan.sh root@10.255.228.225:/tmp/
ssh root@10.255.228.225 "bash /tmp/install_strongswan.sh 10.255.228.55 mytestkey vpn.local"
```

**参数与环境变量**

| 参数 / 变量 | 默认 | 说明 |
|---|---|---|
| `$1` RADIUS_SERVER | `10.255.228.55` | Windows 主机 IP（Java RADIUS 所在） |
| `$2` RADIUS_SECRET | `mytestkey` | 共享密钥，须与 `PKI/CONFIG.txt` 的 `RADIUSKEY` 一致 |
| `$3` GW_ID | `vpn.local` | 网关证书 CN/SAN（客户端"远程 ID"） |
| `POOL_ADDRS` | `10.10.0.0/24` | 客户端地址池（同时用于 NAT/FORWARD 规则） |
| `VPN_DNS` | `223.5.5.5,8.8.8.8` | 下发给客户端的 DNS（留空=不下发） |
| `GW_CRT` / `GW_KEY` / `ROOT_CRT` | `/tmp/gw.crt` 等 | 指定证书路径（不传则按默认路径 → 再回退复用 `/etc/swanctl` 里已有证书） |
| `NO_NAT=1` | 关 | 跳过 NAT/FORWARD/MSS 配置（纯内网互访时用） |
| `NO_PERSIST=1` | 关 | 不安装 iptables-persistent、不保存规则 |
| `RADIUS_TEST=1` | 关 | 强制做 RADIUS 连通性自检（需 radclient） |

**脚本做了什么（幂等，可反复执行）**

1. 装包：`strongswan`、`strongswan-pki`、`libcharon-extra-plugins`（eap-radius / eap-tls / eap-mschapv2 等插件）、`iptables`、`openssl`，并尝试安装 `strongswan-swanctl`
2. 解析 systemd 单元：优先 `strongswan.service`（Debian 13 即 swanctl 前端）；若存在并启用了 `strongswan-starter`（`/etc/ipsec.conf` 体系，与 swanctl 互斥）则自动停用
3. 部署证书并**逐项校验**：私钥与证书配对（SPKI 比对）、EKU 含 serverAuth、有效期、**SAN 是否含本机 IP**（不含则打印醒目警告并说明 Windows 症状与重签方法）、能否用根证书链验证；私钥置 `600`
4. 写 `/etc/strongswan.d/charon/eap-radius.conf`（RADIUS 地址/密钥/端口 + `nas_identifier`）
5. 写 `/etc/swanctl/swanctl.conf`（**4 条连接**：用户名密码 / 客户端证书 × 网关ID / 服务器 IP；另有地址池与 DNS）
6. 内核转发：`/etc/sysctl.d/99-modpkica-vpn.conf` 写入 `net.ipv4.ip_forward=1` 并生效
7. 防火墙（幂等追加）：`MASQUERADE`（地址池 → 默认出接口）、`FORWARD` 双向放行、**TCP MSS 钳制**（避免"能 ping 不能开网页"）；默认用 `netfilter-persistent` 持久化
8. 启动并验证：`systemctl restart` → `swanctl --load-all`（**配置语法错误会显式报错**）→ 校验 4 条连接都在清单里 → 检查 UDP 500/4500 监听 →（有 radclient 时）RADIUS 连通性自检
9. 覆盖任何文件前自动备份为 `<文件>.bak.<时间戳>`

**预期输出尾部（示例）**

```
[OK] 证书 / 私钥配对校验通过
[OK] 网关证书：CN=vpn.local,OU=IT Clubs,O=China IT Boys,L=newer york,C=CN
[OK] 网关证书 SAN 含本机 IP（Windows 用 IP 拨号可过「证书身份=连接地址」校验）
[OK] 已写入 swanctl.conf（4 条连接 / 网关ID=vpn.local / 证书=gw.crt / 池=10.10.0.0/24）
[OK] 已配置：MASQUERADE(10.10.0.0/24 → enp0s3) + FORWARD 双向 + MSS 钳制
[OK] strongswan.service 运行中
[OK] 4 条连接（用户名密码 / 客户端证书 × 网关ID / 服务器IP）均已加载
[OK] 已监听 UDP 500 / 4500（IKEv2）
[OK] RADIUS 可达、共享密钥正确（Access-Reject = 服务器活着且已校验密钥/账号）
```

> 若脚本打印出**红底/黄字**的 SAN 警告，请先按提示重签网关证书再继续（否则 Windows 用 IP 拨号必失败）。

---

## 三、方式二：手工部署

```bash
# 1) 装包
sudo apt update
sudo apt install -y strongswan strongswan-pki libcharon-extra-plugins iptables
sudo apt install -y strongswan-swanctl || true     # 有该包则装（提供 swanctl 命令）

# 2) 确认服务单元与版本
systemctl list-unit-files | grep strongswan
swanctl --version

# 3) 目录
sudo mkdir -p /etc/swanctl/{x509,private,x509ca} /etc/strongswan.d/charon

# 4) 后续各节：证书（第 6 节）→ swanctl.conf（第 7 节）→ eap-radius.conf（第 8 节）
#    → 转发与 NAT（第 9 节）→ 启动验证（第 11 节）
```

> **Debian 13 / strongSwan 6.0**：`eap-radius`、`eap-tls`、`eap-mschapv2`、`openssl`、`vici` 等插件随 `libcharon-extra-plugins` 装在 `/usr/lib/ipsec/plugins/`。
> 启动时若看到 `plugin 'aes' failed to load` / `plugin 'sha2' failed to load` 之类提示——**无害**：6.0 的加解密由 openssl 插件后端提供，旧式 aes/sha2/gmp 插件已不存在，忽略即可。
> **Ubuntu 24.04（strongSwan 5.9）**：同样可用本指南（连接写法一致），只是服务单元名为 `strongswan-swanctl`（`strongswan.service` 可能指向旧 starter，启用哪个以 `systemctl list-unit-files` 为准）。

---

## 四、用 MODPKICA 签发网关证书

### 4.1 WebAdmin 界面签发（推荐）

WebAdmin → **签发证书** 页面，签一张 **终端证书（E）**：

| 参数 | 值 | 为什么 |
|---|---|---|
| 证书类型 | 终端证书（E） | 网关证书不是 CA |
| 颁发者 | 根证书（R）或中间 CA（C） | 客户端信任链的起点 |
| 密钥算法 / 位数 | RSA 2048（推荐）或 ECC 256 | iOS 13+/Win11 拒绝 < 2048 位 RSA |
| 哈希算法 | SHA256 | SHA1 已被现代客户端拒绝 |
| 增强型密钥用法（EKU） | **服务器身份验证 `1.3.6.1.5.5.7.3.1`** | IKEv2 响应方身份；缺了 iOS/Windows 会拒绝 |
| SAN 域名 | `vpn.local`（或你的域名） | 客户端"远程 ID"填这个 |
| SAN IP | **Linux 服务器 IP，如 `10.255.228.225`** | ⚠️ 见下方警告 |
| 扩展控制 | **noAIA** | 不写 AIA/CRL 分发点，避免客户端去访问不可达的 `localhost:80` 吊销服务而超时/失败 |

> ⚠️ **SAN 必须包含服务器 IP**：Windows 10/11 原生 IKEv2 会严格校验「证书身份 = 连接地址」。若证书 SAN 里没有服务器 IP，客户端会**静默丢弃连接**（症状：提示"在连接完成前，连接被远程计算机终止"）。手机 strongSwan App / iOS 用域名（远程 ID 填 `vpn.local`）可只用域名 SAN，但**同一个网关同时给 Windows 用时必须有 IP SAN**。一键脚本会自动检查并告警。

### 4.2 命令行签发（等价）

```bash
java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.MakeCert \
  "C=CN,L=newer york,O=China IT Boys,OU=IT Clubs,CN=vpn.local" \
  2048 sha256 1 1 0 1 "vpn.local" "10.255.228.225,127.0.0.1" noAIA \
  7712d9352e6038ce78e57e3f572cec74 RSA
# 参数：  DN                                     位数 哈希 类型 KeyUsage EKU 写SAN "SAN内容"    扩展   颁发者序列号 算法
```

### 4.3 产物

| 产物 | 路径 |
|---|---|
| 网关证书 | `PKI/CERT/{序列号}.crt`（示例 `f7679b33352bd0d0e150e8594606c01f.crt`） |
| 网关私钥 | `PKI/KEY/{序列号}.key` |
| 根证书 | `PKI/ROOT/{序列号}.crt`（示例 `7712d9352e6038ce78e57e3f572cec74.crt`） |

### 4.4 EAP-TLS 服务器证书（RADIUS 侧）

EAP-TLS 握手时，**RADIUS 服务端**（本 Java 程序）也会向客户端出示一张服务器证书。它取自：

- `PKI/CERT/{序列号}.crt`，要求 **EKU 含 serverAuth**，私钥需在 `PKI/KEY/{序列号}.key`；
- 可用 `PKI/CONFIG.txt` 的 **`RADIUSCERT=序列号`** 显式指定；未指定时按文件名排序自动选择第一张"有配对私钥"的证书；
- 证书链按 issuer DN 从 `PKI/CA`、`PKI/ROOT` 目录自动组装（叶→根）。

> 实践上：**让网关证书与 EAP-TLS 服务器证书用同一张**（都用 `CN=vpn.local` 那张，SAN 含域名与服务器 IP），并在 `CONFIG.txt` 里 `RADIUSCERT=<该证书序列号>` 固定下来，这样客户端只需信任一个根、验证一个名字。

---

## 五、签发 EAP-TLS 客户端证书

客户端证书登录（EAP-TLS）需要给每台设备签一张**带私钥的终端证书**：

1. WebAdmin → **签发证书**：证书类型"终端证书"；颁发者用根（R）或中间 CA（C）；密钥 RSA 2048；哈希 SHA256；
   **增强型密钥用法勾选「客户端身份验证 `1.3.6.1.5.5.7.3.2`」**（建议连同"服务器身份验证"一起勾，最省事）；SAN 可留空（服务端按证书 DN 识别用户）。
2. 签发成功后在 **证书库 → 右键该证书 → 下载证书 → 下载证书+私钥(.pfx)**，得到带链的 `.pfx`（END + CA + ROOT）。打包时设置的密码就是导入时用的密码。
3. 分发到各设备（见第十二节 12.2 / 12.4）。

> - 客户端证书**必须带 clientAuth EKU**：只带 serverAuth 的证书（例如网关那张）会被 RADIUS 侧按 RFC 5280 拒绝，日志显示 EAP-TLS 握手失败/证书策略拒绝。
> - 证书登录**不需要**在 `PKI/USERS.txt` 建账号：认证通过后服务端以**证书 DN** 作为身份放行（日志：`用户=CN=…（客户端证书: …）`）；如需限制，可把该 DN 的 CN 加进用户库并停用（`D`）——r18 起会按证书 CN 命中用户库做账户状态校验。
> - 证书吊销后（CERTS.txt 对应行状态为 `R`）该设备立即无法登录（r18 起 EAP-TLS 会校验全链有效期 + 吊销 + 账户状态）。

---

## 六、证书部署与权限

```bash
sudo mkdir -p /etc/swanctl/x509 /etc/swanctl/private /etc/swanctl/x509ca
sudo mv /tmp/gw.crt   /etc/swanctl/x509/{网关序列号}.crt
sudo mv /tmp/gw.key   /etc/swanctl/private/{网关序列号}.key
sudo mv /tmp/root.crt /etc/swanctl/x509ca/{根序列号}.crt

sudo chown root:root /etc/swanctl/x509/* /etc/swanctl/private/* /etc/swanctl/x509ca/*
sudo chmod 600 /etc/swanctl/private/*.key
sudo chmod 644 /etc/swanctl/x509/*.crt /etc/swanctl/x509ca/*.crt
```

- 6.0 中证书文件**以真实文件名（序列号）引用**；旧写法 `gwCert.pem` 也能用，但建议统一用序列号，和 `PKI/` 目录一一对应。
- 私钥权限必须 `600`（strongSwan 会检查；root 之外的读权限会让 charon 拒绝加载）。
- 校验三件套（强烈建议）：

```bash
# ① 私钥与证书配对
diff <(openssl x509 -in /etc/swanctl/x509/{网关序列号}.crt -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum) \
     <(openssl pkey -in /etc/swanctl/private/{网关序列号}.key -pubout -outform DER | sha256sum)
# ② SAN 里有没有服务器 IP（Windows 用 IP 拨号必须）
openssl x509 -in /etc/swanctl/x509/{网关序列号}.crt -noout -ext subjectAltName
# ③ 链验证
openssl verify -CAfile /etc/swanctl/x509ca/{根序列号}.crt /etc/swanctl/x509/{网关序列号}.crt
```

---

## 七、swanctl.conf 逐字段详解

文件：`/etc/swanctl/swanctl.conf`（一键脚本会自动生成下面这份；手工部署可直接抄）

```conf
connections {

    # ---------- ① 用户名密码（EAP-MSCHAPv2 → RADIUS） ----------
    ikev2-mschapv2 {
        version   = 2                 # 只接受 IKEv2（Windows/iOS/安卓都支持；IKEv1 已无必要）
        send_cert = always            # 无条件发送网关证书：iOS/Windows 在 EAP 前要先验服务端身份，缺了会直接断开
        pools     = vpnpool           # 从地址池给客户端分配虚拟 IP
        proposals = aes256gcm16-prfsha256-ecp256,aes128gcm16-prfsha256-ecp256,
                    aes256-sha256-ecp256,aes128-sha256-ecp256,
                    aes256-sha256-modp2048,aes128-sha256-modp2048,
                    aes256-sha1-modp2048,aes128-sha1-modp2048    # IKE 提议：客户端命中其一即可
        local {
            auth  = pubkey            # 网关用证书证明自身（与 client 的"远程 ID"校验对应）
            certs = {网关序列号}.crt    # 引用 /etc/swanctl/x509/ 下的文件名
            id    = vpn.local         # 网关对外声明身份，必须与证书 CN/SAN 一致
        }
        remote {
            auth   = eap-radius       # 客户端认证整包转发到 RADIUS（eap-radius 插件）
            eap_id = %any             # 接受任意 EAP 身份；真实账号由 RADIUS 判定
        }
        children {
            ikev2-mschapv2 {
                remote_ts = 0.0.0.0/0 # 客户端侧流量选择器：全部走 VPN
            }
        }
    }

    # ---------- ② 用户名密码（客户端"远程 ID"= 服务器 IP 时命中） ----------
    ikev2-mschapv2-ip {
        version   = 2
        send_cert = always
        pools     = vpnpool
        proposals = （同上）
        local {
            auth  = pubkey
            certs = {网关序列号}.crt
            id    = 10.255.228.225    # Windows 自带 VPN「远程 ID」留空时会用服务器地址做身份
        }
        remote { auth = eap-radius   eap_id = %any }
        children { ikev2-mschapv2-ip { remote_ts = 0.0.0.0/0 } }
    }

    # ---------- ③ 客户端证书（EAP-TLS → RADIUS） ----------
    ikev2-eaptls {
        version   = 2
        send_cert = always
        pools     = vpnpool
        proposals = （同上）
        local { auth = pubkey   certs = {网关序列号}.crt   id = vpn.local }
        remote {
            auth    = eap-tls          # 要求客户端用证书做 EAP-TLS
            eap_id  = %any
            cacerts = {根序列号}.crt    # 只接受本 PKI 根签发的客户端证书（网关侧预筛）
        }
        children { ikev2-eaptls { remote_ts = 0.0.0.0/0 } }
    }

    # ---------- ④ 客户端证书（远程 ID = 服务器 IP 时命中） ----------
    ikev2-eaptls-ip {
        version   = 2
        send_cert = always
        pools     = vpnpool
        proposals = （同上）
        local { auth = pubkey   certs = {网关序列号}.crt   id = 10.255.228.225 }
        remote { auth = eap-tls   eap_id = %any   cacerts = {根序列号}.crt }
        children { ikev2-eaptls-ip { remote_ts = 0.0.0.0/0 } }
    }
}

pools {
    vpnpool {
        addrs = 10.10.0.0/24          # 客户端虚拟地址池（勿与内网/服务器网段重叠）
        dns   = 223.5.5.5,8.8.8.8     # 下发给客户端的 DNS（可删）
    }
}

secrets {                             # IKEv2 本方案不用 PSK；保留空段
}
```

**关键字段为什么这么写**

| 字段 | 说明 |
|---|---|
| `version = 2` | 只开 IKEv2。IKEv1 的 Cisco XAUTH 场景在 strongSwan 6.0 已不可用（xauth-radius 插件被移除） |
| `send_cert = always` | iOS/Windows 在 EAP 之前就要验证**服务端身份**；不无条件发证书会导致"连到一半被终止" |
| `local.certs` / `local.id` | 网关证书文件名 + 对外身份；`id` 必须与证书 CN 或 SAN 一致（本 PKI 里是 `vpn.local`） |
| `remote.auth = eap-radius` | **用户名密码走这里**：EAP 报文交由 eap-radius 插件整包转发 RADIUS |
| `remote.auth = eap-tls` | **客户端证书走这里**：EAP-TLS 报文同样转发 RADIUS，由 Java 服务端做真正的证书校验（网关侧 `cacerts` 只是预筛） |
| `eap_id = %any` | 允许任意 EAP 身份（真实账号由 RADIUS 判定）；若写死 `%any` 之外的值会限制客户端 |
| `cacerts`（EAP-TLS 连接） | 网关只接受由该 CA 签发的客户端证书；**注意服务端证书信任锚不是这里**（那是 `x509ca/`） |
| 4 条连接的意义 | 客户端「远程 ID」填 `vpn.local` 命中 ①/③；Windows 留空或填 IP 时命中 ②/④——**两种身份都可用，不用改客户端** |
| `children.remote_ts = 0.0.0.0/0` | 客户端侧全流量进隧道；服务端侧地址由 pool 动态分配（不需要写 `local_ts`） |
| `proposals` | 单条连接可写多条提议（逗号分隔）作备选；建议保留 GCM 与 CBC 各若干、DH 至少 ecp256 + modp2048，兼容老客户端 |

> **改完配置必须重新加载**（第 11 节）：`sudo swanctl --load-all`。语法错误（例如残留 5.x 的 `eap_radius { servers { … } }` 子块）会让整份配置加载失败——`--load-all` 会明确报错，连接清单则为空。

---

## 八、eap-radius.conf 逐字段详解

文件：`/etc/strongswan.d/charon/eap-radius.conf`（一键脚本自动生成）

```conf
eap-radius {
    load = yes                        # 加载插件（Debian 包默认已启用，显式写更清楚）

    nas_identifier = vpn-gw           # 写进 Access-Request 的 NAS-Identifier，便于 RADIUS 侧区分网关

    servers {
        primary {                     # 服务器名（任意），connection 里可用 servers = primary
            address   = 10.255.228.55 # ★ Windows 主机 IP（Java RADIUS 所在）
            secret    = mytestkey     # ★ 共享密钥，必须与 PKI/CONFIG.txt 的 RADIUSKEY 完全一致
            auth_port = 1812          # 认证端口
            acct_port = 1813          # 计费端口
        }
    }

    # ---- 可调项（默认即可；仅在链路丢包严重时调整） ----
    # sockets            = 1          # 每服务器 UDP socket 数
    # timeout            = 5          # 等待 RADIUS 响应（秒）
    # retransmit_tries   = 3          # 无响应时重传次数
    # retransmit_timeout = 2.0        # 首次重传间隔（秒）
    # accounting         = yes        # 是否转发计费（Acct-Request → 1813）
}
```

**要点**

- `secret` 不一致的症状：**认证请求石沉大海**（RADIUS 侧静默丢弃 Message-Authenticator 校验失败的包），客户端表现为"一直在连接"。改完 `systemctl restart strongswan`。
- `address` 必须是 Windows 主机**可达的** IP，且 Windows 防火墙放行 UDP 1812/1813（第 10 节）。
- 5.x 的旧写法（connection 内嵌 `eap_radius { servers { … } }`、`xauth_radius { … }`）在 6.0 会**解析失败并导致整份配置加载失败**，务必使用上面这种"插件级配置"。
- `nas_identifier` 会出现在 RADIUS 日志的来源信息中，多网关时便于区分（可选）。
- 关于 `retransmit_*`：strongSwan 在 UDP 上对未确认的 Access-Request 会整包重传（同一 EAP 数据、仅 RADIUS identifier 递增）。**MODPKICA v1.28-r20 起服务端已按 RFC 3748 §5.1 做"事务化重放"**，重传不会再把 TLS 状态机打乱，因此默认重传参数无需调整（第 14 节）。

---

## 九、内核转发、NAT 与 TCP MSS

```bash
# 1) 内核转发
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-modpkica-vpn.conf
sudo sysctl --system

# 2) 出接口（换成实际网卡名，ip route 看 default 行的第 5 列）
IFACE=$(ip route | awk '/^default/{print $5; exit}'); echo $IFACE

# 3) NAT + 转发 + MSS 钳制（幂等：已存在会跳过）
sudo iptables -t nat -C POSTROUTING -s 10.10.0.0/24 -o $IFACE -j MASQUERADE 2>/dev/null || \
sudo iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o $IFACE -j MASQUERADE
sudo iptables -C FORWARD -s 10.10.0.0/24 -j ACCEPT 2>/dev/null || \
sudo iptables -A FORWARD -s 10.10.0.0/24 -j ACCEPT
sudo iptables -C FORWARD -d 10.10.0.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
sudo iptables -A FORWARD -d 10.10.0.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t mangle -C FORWARD -s 10.10.0.0/24 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
sudo iptables -t mangle -A FORWARD -s 10.10.0.0/24 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# 4) 持久化
sudo apt install -y iptables-persistent && sudo netfilter-persistent save
```

- **为什么要有 MSS 钳制**：VPN 封装会增加报文长度，客户端大包（尤其 TCP SYN）可能超路径 MTU 被丢，典型症状是**能 ping 通、网页打不开/卡住**。
- Debian 13 的 `iptables` 由 nft 后端承载（`iptables-nft`），以上命令依然有效；若你只用 nftables 原生规则，请把等价的 `masquerade / accept / tcp flags syn tcp option maxseg size set rt mtu` 写进 `/etc/nftables.conf`。
- 若客户端只需要访问内网、不做上网出口 NAT，可只保留 FORWARD 两条、不要 MASQUERADE。

---

## 十、Windows 主机防火墙放行

在 Windows（管理员 PowerShell）：

```powershell
# 放行来自 Linux 网关的 RADIUS 流量（按你的网关 IP 收紧）
New-NetFirewallRule -DisplayName "MODPKICA RADIUS from VPN server" -Direction Inbound -Protocol UDP -LocalPort 1812,1813 -RemoteAddress 10.255.228.225 -Action Allow

# 确认 Java RADIUS 在监听
Get-NetUDPEndpoint -LocalPort 1812
netstat -ano | findstr :1812
```

> 若 Windows 主机同时开了第三方安全软件/主机防火墙，一并放行 UDP 1812/1813。
> 反向注意：**Java 侧不需要向网关发起连接**，所以网关侧无需为 RADIUS 开入站规则。

---

## 十一、启动与验证

```bash
# 1) 服务
sudo systemctl enable --now strongswan          # Debian 13：单元名 strongswan（不是 strongswan-swanctl）
sudo systemctl restart strongswan
systemctl status strongswan --no-pager | head -20

# 2) 加载配置并看清单（★ 语法错误会在这里报出来）
sudo swanctl --load-all
sudo swanctl --list-conns          # 应看到 ikev2-mschapv2 / -ip / ikev2-eaptls / -ip
sudo swanctl --list-pools          # 应看到 vpnpool 10.10.0.0/24
sudo swanctl --list-certs          # 应看到网关证书与根证书

# 3) 监听检查
ss -lunp | grep -E ':500|:4500'

# 4) 活动会话（连接后）
sudo swanctl --list-sas

# 5) RADIUS 连通性自检（装 freeradius-utils 提供 radclient；探针账号会得到 Access-Reject = 正常）
sudo apt install -y freeradius-utils
echo -e "User-Name=modpkica-probe\nUser-Password=probe" | \
  radclient -t 3 -r 2 10.255.228.55:1812 auth mytestkey
#   ↑ 收到 Access-Reject：服务器可达且共享密钥正确
#   ↑ 超时无响应：Windows 防火墙 / address / secret / MAIN 未运行
```

> **日志入口**：网关 `sudo journalctl -u strongswan -f`；Windows 侧 WebAdmin → **Radius服务管理 → 服务器日志**（内存环形日志，含 EAP-TLS 分片/重传/重启明细）与 `PKI/logs.log`（认证结果台账）。

---

## 十二、客户端拨号配置（iOS / 安卓 / Windows / macOS）

### 12.0 共同前提：安装根证书

| 平台 | 安装方式 | 关键点 |
|---|---|---|
| iOS | 把 `PKI/ROOT/{根序列号}.crt` 发到设备安装描述文件 | 必须再到 **设置 → 通用 → 关于本机 → 证书信任设置** 手动打勾，否则不受信任 |
| Windows | 双击 → 安装证书 → **本地计算机** → 放入"受信任的根证书颁发机构" | 用普通用户装到"当前用户"也能用，但服务/其他用户账户连接时会失败 |
| Android | 设置 → 安全 → 加密与凭据 → 安装 CA 证书 | 部分机型需锁屏密码；strongSwan App 也可在 App 内"导入 CA" |
| macOS | 钥匙串 → 系统 → 拖入 → 设为"始终信任" | — |

### 12.1 iOS（用户名密码）

1. 先按 12.0 安装并信任根证书。
2. 设置 → 通用 → VPN 与设备管理 → VPN → 添加 VPN 配置：
   - 类型：**IKEv2**
   - 服务器：`10.255.228.225`（网关 IP）
   - 远程 ID：`vpn.local`（与证书 SAN 一致）
   - 本地 ID：留空
   - 用户鉴定：**用户名** → 填 `PKI/USERS.txt` 里的账号密码

### 12.2 iOS（客户端证书，EAP-TLS）

1. 安装根证书并信任（12.0）；把第 5 节生成的 `.pfx` 也安装为描述文件（会出现在"VPN 与设备管理 → 已下载的描述文件"）。
2. 添加 VPN 配置：类型 **IKEv2**；服务器 `10.255.228.225`；远程 ID `vpn.local`；
   **用户鉴定选"证书"**，证书选刚导入的那张（若导入的是 `.pfx`，装完在"证书"里选即可）。
3. 连接：服务端以证书 DN 作为用户名，日志显示 `用户=CN=…（客户端证书: …）`。

> iOS 的"证书"鉴定方式底层就是 EAP-TLS（客户端证书在 EAP 隧道内传输）。它比安卓 strongSwan App 更严格，因此服务端证书的 EKU/SAN/有效期、以及 EAP-TLS 分片时序必须完全正确（r20 已修）。

### 12.3 安卓（strongSwan App）

- **用户名密码**：类型 `IKEv2 EAP (Username/Password)`；服务器 `10.255.228.225`；服务器标识 `vpn.local`；在 App 内导入/信任根证书；填账号密码。
- **客户端证书**：类型 `IKEv2 Certificate`（或 `IKEv2 EAP` + 客户端证书）：
  - 服务器 `10.255.228.225`；服务器标识（远程 ID）`vpn.local`
  - 本地标识：`vpn.local` 或留空（服务端以证书 DN 识别）
  - 配置页"证书"→ 从文件导入 `.pfx`（输入密码）；"CA 证书"导入 `PKI/ROOT/{根序列号}.crt`
- **安卓系统自带 VPN**（部分机型）：类型 `IKEv2/IPsec MSCHAPv2`，IPSec 标识符 `vpn.local`，账号密码同上。

### 12.4 Windows 10/11 自带 VPN

**用户名密码**：设置 → 网络和 Internet → VPN → 添加：
- VPN 提供商：Windows（内置）；VPN 类型：**IKEv2**
- 服务器名称或地址：`10.255.228.225`
- 登录信息的类型：**用户名和密码**

**客户端证书（EAP-TLS）**：
1. 根证书装到"受信任的根证书颁发机构"（12.0）。
2. `.pfx` 双击导入"当前用户/本地计算机 → 个人"，确保证书带**客户端身份验证**用途。
3. 添加 VPN 同上传入服务器地址；**登录信息的类型选"证书"**（若无该选项，先在"网络和共享中心 → 更改适配器设置 → VPN 连接属性 → 安全 → 使用可扩展的身份验证协议(EAP) → Microsoft: 智能卡或其他证书 → 属性"里勾选你的客户端证书）。
4. 若"远程 ID"留空，Windows 会用**服务器地址**作为身份 → 命中 ②/④ 连接；也可显式填 `vpn.local` → 命中 ①/③。
5. 提示"服务器证书无效/连接被远程终止"时，先查：根证书是否装到受信任根、网关证书 SAN 是否含 `10.255.228.225`（第四节），再查网关日志。

### 12.5 macOS 系统 VPN

类型 `IKEv2`；服务器 `10.255.228.225`；远程 ID `vpn.local`；用户鉴定可选"用户名"或"证书"（选已装的客户端证书）；根证书设为始终信任。

---

## 十三、故障排查

> 先看两处日志：**网关** `sudo journalctl -u strongswan -f`；**RADIUS** WebAdmin → Radius服务管理 → 服务器日志（内存环形日志，最近 500 条，含 EAP-TLS 明细分片）。`PKI/logs.log` 只有认证结果台账。

| 症状 | 可能原因与处置 |
|---|---|
| 客户端"一直在连接"，网关日志无 RADIUS 响应 / `received no response` | ① `eap-radius.conf` 的 `address` 写错（必须是 Windows 主机 IP）② `secret` 与 `PKI/CONFIG.txt` 的 `RADIUSKEY` 不一致（服务端静默丢弃）③ Windows 防火墙未放行 UDP 1812 **④ MAIN/RADIUS 服务未启动**（WebAdmin → Radius服务管理 看状态） |
| Windows 提示"**在连接完成前，连接被远程计算机终止**" | ① 网关证书 SAN 缺服务器 IP（Windows 严格校验"证书身份=连接地址"）→ 重签证书加 IP SAN（第四节，一键脚本会自动告警）② 根证书没装到"受信任的根证书颁发机构"③ 认证被 RADIUS 拒（看服务端日志：EAP-失败/证书策略拒绝/账号停用） |
| iOS 提示"无法连接 VPN 服务器 / 证书无效" | ① 根证书未在"证书信任设置"里打勾 ② 远程 ID 与证书 SAN 不一致（本方案用 `vpn.local`）③ 服务端证书 EKU 缺 serverAuth、或 RSA < 2048 |
| 网关日志同一秒大量 `parsed IKE_AUTH request … [ EAP/RES/TLS ]`、随后 `deleting half open IKE_SA after timeout`；RADIUS 日志刷屏 `[iOS兼容] EAP-TLS 检测到网关重传…` | 这是 **EAP-TLS 分片交换死循环**的历史症状：**升级 MODPKICA 到 v1.28-r20 及以上**（重传按事务重放、拉取片不跳片、客户端重启自动重建会话）。若仍复现，把该行 `body=` 与 `快照/片偏移` 记下来反馈 |
| RADIUS 日志 `EAP-TLS 认证通过` 但客户端仍失败，网关回 `N(AUTH_FAILED)` | 服务端 Access-Accept 未下发 **MS-MPPE 32+32B**：要求 MODPKICA **v1.28-r16 及以上**；服务端日志应出现 `[DBG] EAP-TLS 已下发 MS-MPPE 密钥 32+32B`（若是 `16+16B` 或 `[WARN] 未导出 MSK` 则版本不对） |
| `no acceptable proposal` / 客户端提议算法不匹配 | 连接的 `proposals` 太窄；改用第七节的完整列表（GCM + CBC、ecp256 + modp2048 起） |
| `swanctl --list-conns` 为空；服务 failed（`status=22`） | **配置语法错误**：`sudo swanctl --load-all` 会打印具体行；最常见是残留 5.x 写法（connection 内 `eap_radius { servers {…} }` / `xauth_radius`）——见第八节改成插件级配置 |
| 提示 `plugin 'aes'/'sha2'/'gmp' failed to load` | strongSwan 6.0 正常现象（改由 openssl 后端提供），忽略 |
| 证书未加载 / `no matching peer config` | 证书文件名与 `swanctl.conf` 里 `certs =` 不一致；私钥权限不是 600；证书链缺根（`x509ca/` 要放根证书） |
| 连上但打不开网页、ping 通 | ① 没有 MSS 钳制（第九节最后一条）② 客户端 DNS 是内网不可达地址（改 `pools.vpnpool.dns`）③ `ip_forward` 未生效 |
| 客户端拿不到 IP | `pools` 未配置或地址池与内网重叠；`swanctl --list-pools` 检查 |
| 认证偶发失败/时快时慢 | 网关与 Windows 间 UDP 丢包；可调 `eap-radius.conf` 的 `timeout`/`retransmit_*`（第 8 节），或把两端放同网段 |
| Windows 装了根证书仍报链错误 | 根证书装到了"当前用户"而连接使用另一个账户；改为装到"本地计算机" |

---

## 十四、兼容性与协议要点（重传 / 重启 / MSK）

### 14.1 为什么网关会"整包重传"（以及 r20 怎么处理）

strongSwan 的 `eap-radius` 通过 UDP 与 RADIUS 通信：**未收到响应时会整包重传 Access-Request**——EAP-Identifier 与 EAP 数据逐字节相同，只有 RADIUS identifier 递增。EAP-TLS 的握手数据是分片交换的，重传若处理不当会打乱 TLS 状态机：

| 版本 | 行为 | 结果 |
|---|---|---|
| r16 及以前 | 重传的分片再次喂给 BC TLS 状态机 | `TlsFatalAlert: unexpected_message(10)`（iOS 实测） |
| r17–r19 | 识别重传，**重发"最近一次响应体"** | 拉片阶段"最近一次"是**末片**：客户端重发 ClientHello 时拿到末片（M=0）→ 永远解析不出 ServerHello → **无限循环** |
| **r20（当前）** | **按事务重放**：`(入包 EAP-Id + 数据指纹) → (当时的 EAP-Id + 响应快照 + 片内偏移)`，逐字节重建该片并回绕游标 | 首片仍是首片；空拉取片重传回放上一片（不跳片）；服务端 Request Identifier 按 RFC 3748 §4.1 自增 |

### 14.2 客户端重启握手

客户端在握手途中重开 TLS（**新的** ClientHello：新 random、新指纹）时，r20 会**丢弃旧会话并重建握手**（`[iOS兼容] EAP-TLS 客户端重启握手…→ 重建会话`），而不再把它喂给旧状态机导致 `unexpected_message(10)` + 立即失败。

### 14.3 EAP-Identifier 规则（自研脚本注意）

- 服务端（MODPKICA）对每个新 EAP-Request **自增** Identifier（RFC 3748 §4.1）。
- 客户端响应应**回显**所答 Request 的 Identifier（iOS / Windows / strongSwan 原生行为本就如此）。
- 若你写脚本直连 1812 做分片拉取：**不要用固定 EAP-Id 连续发多个空拉取片**——那会被正确判定为"IKE 层重传"而回放上一片（这是修复目标，不是故障）。

### 14.4 MSK / MS-MPPE（IKEv2 能否成功的关键）

EAP-TLS 握手完成后，MODPKICA 按 RFC 5216 §2.4 导出 64B MSK：`PRF(master_secret,"client EAP encryption",client_random‖server_random)`，并按 RFC 2548 §2.4.3 以 **MS-MPPE-Recv-Key = MSK[0..32) / MS-MPPE-Send-Key = MSK[32..64)**（32+32 字节，加密种子 = 对应 Access-Request 的 Request-Authenticator）随 Access-Accept 下发；网关解密后重组 64B MSK 完成 IKEv2 AUTH（RFC 7296 §2.16）。服务端与客户端的 MSK **逐字节一致**（已实测）；若网关回 `N(AUTH_FAILED)` 而日志显示认证通过，首先怀疑 MSK 未下发（见第十三节）。

---

## 十五、版本差异（strongSwan 5.9 ↔ 6.0）

| 项目 | 5.9（如 Ubuntu 24.04） | 6.0（如 Debian 13） | 本指南做法 |
|---|---|---|---|
| RADIUS 服务器配置位置 | connection 内嵌 `eap_radius { servers {…} }`（可解析） | **移到插件级** `/etc/strongswan.d/charon/eap-radius.conf` | 统一用插件级（5.9 同样支持） |
| Cisco XAUTH（IKEv1） | `remote { xauth = radius }` + `xauth_radius` 块 | **xauth-radius 插件已移除，不可用** | 只用 IKEv2 |
| 算法后端 | 自带 gmp/aes/sha2 插件 | openssl 插件后端（旧插件提示 failed to load 属正常） | 忽略提示 |
| systemd 单元 | `strongswan-swanctl` | `strongswan.service`（`strongswan-swanctl` 是其别名，enable 别名会报 `Refusing to operate on linked unit`） | 以 `systemctl list-unit-files \| grep strongswan` 为准；脚本自动解析 |
| 证书引用 | `certs = gwCert.pem` | 任意文件名 | 统一用 `{序列号}.crt` |
| `eap_id` | 支持 `%any` | 支持 `%any` | 一致 |
| 配置加载 | `swanctl --load-all` | 同 | 同 |

---

## 十六、附录：报文时序与日志样例

### 16.1 EAP-MSCHAPv2（用户名密码）

```
客户端 ──IKE_SA_INIT──────────────────────────▶ 网关
客户端 ◀─IKE_SA_INIT────────────────────────── 网关
客户端 ──IKE_AUTH [IDi, EAP/Resp/Identity]────▶ 网关
        网关 ──Access-Request(User-Name + EAP)──▶ RADIUS
        RADIUS ──Access-Challenge(EAP-MSCHAPv2 挑战)──▶ 网关
客户端 ◀─IKE_AUTH [EAP/Req/MSCHAPv2]────────── 网关
客户端 ──IKE_AUTH [EAP/Resp/MSCHAPv2]────────▶ 网关   （…第二次交换）
        RADIUS ──Access-Accept + MS-MPPE 16+16B──▶ 网关
客户端 ◀─IKE_AUTH [EAP/Success]─────────────── 网关
客户端 ──IKE_AUTH [AUTH（用 MSK 派生密钥）]──▶ 网关   → SA 建立，分配地址池 IP
```

### 16.2 EAP-TLS（客户端证书）关键分片

```
客户端 ──EAP/Resp/Identity（DER-DN 或用户名）▶ 网关 → RADIUS
客户端 ◀─EAP/Req/TLS(Start)────────────────── 网关 ← RADIUS
客户端 ──EAP/Resp/TLS(ClientHello, 1 片)─────▶ 网关 → RADIUS
客户端 ◀─EAP/Req/TLS(ServerHello+Cert+SKE+CertReq+SHDone, 分片 1100B×3)
         （客户端逐片以"空 EAP-Resp/TLS(1B 0x00)"回显 Request 的 EAP-Id 拉取）
客户端 ──EAP/Resp/TLS(客户端证书+CertVerify+Finished)─▶ 网关 → RADIUS
客户端 ◀─EAP/Req/TLS(CCS+Finished)──────────── 网关 ← RADIUS
客户端 ◀─EAP/Success + Access-Accept(MS-MPPE 32+32B)─ 网关
```

### 16.3 服务端日志样例（WebAdmin → Radius服务管理 → 服务器日志）

```
EAP-TLS 收到 TLS 数据 1110B（radiusId=37） 来源=10.255.228.225:36965 用户=vpn.local
[DBG] 首片下发 快照=3112B 片偏移=0 flags=0xc0 剩余=2012B 来源=10.255.228.225:36965
[DBG] 下发续片 快照=3112B 片偏移=1100 flags=0x40 剩余=912B 来源=…        ← 客户端回显新 EAP-Id 拉取
[DBG] 下发续片 快照=3112B 片偏移=2200 flags=0x00 剩余=0B 来源=…
[EAP-TLS] MSK 导出成功，MPPE-Recv(前16B)=afceed3df16008ac1cb19ea584cadd8d
[DBG] EAP-TLS 已下发 MS-MPPE 密钥 32+32B（用户=CN=localhost,…）
EAP-TLS 认证通过 来源=10.255.228.225:36965 用户=CN=localhost,…（客户端证书: CN=localhost,…）

# 网关整包重传（同一 ClientHello 再来一次）→ 按事务重放该笔响应：
[iOS兼容] EAP-TLS 检测到网关重传（EAP-Id=2，156B，scope=src），按 RFC 3748 §5.1 重放该事务响应（快照 3112B，片偏移 0） 来源=… 用户=… body=c000000c28160303003b…

# 客户端握手途中重开 TLS（新的 ClientHello）→ 自动重建会话：
[iOS兼容] EAP-TLS 客户端重启握手（新 ClientHello，EAP-Id=7）→ 重建会话 来源=… 用户=…
```

---

> 相关文档：[README.md](README.md)（项目总览与全部配置文件）· [CHANGELOG.md](CHANGELOG.md)（版本历史）· `linux/install_strongswan.sh`（一键部署脚本，`--help` 查看参数）
