# MODPKICA RADIUS × strongSwan 网关接入指南

> 用途：在虚拟机（Ubuntu/Debian）上部署 strongSwan IKEv2/IPsec 网关，把手机/iOS/Android 的 VPN 认证转发到你 Windows 上的 Java RADIUS 服务（UDP 1812）。
> 适用版本：Ubuntu Server 24.04.x / Debian 13.x（默认内核自带 IPsec 支持）。

## 目录

1. [架构与前提](#一架构与前提)
2. [安装 strongSwan](#二安装-strongswan)
3. [用 MODPKICA 签发网关证书](#三用-modpkica-签发网关证书)
4. [拷贝证书到虚拟机](#四拷贝证书到虚拟机)
5. [swanctl 配置（三合一）](#五swanctl-配置三合一)
6. [Windows 防火墙放行](#六windows-防火墙放行)
7. [启动与验证](#七启动与验证)
8. [手机拨号配置](#八手机拨号配置)
9. [L2TP（可选，较繁琐）](#九l2tp可选较繁琐)
10. [故障排查](#十故障排查)

---

## 一、架构与前提

```
手机(iOS/Android)
   │  IKEv2(EAP-MSCHAPv2 / EAP-TLS) ｜ Cisco XAUTH ｜ L2TP
   ▼
虚拟机 strongSwan  (UDP 500 / 4500)
   │  RADIUS 转发 (UDP 1812)
   ▼
Windows 主机 Java RADIUS (modpkica.MAIN)
```

**前提清单**：
- 虚拟机已装好 Ubuntu/Debian，**网卡桥接模式**，已设静态 IP（与 Windows 同网段，下文示例 `192.168.1.3`）
- Windows 主机局域网 IP（下文示例 `192.168.1.100`）
- Java RADIUS 已运行（MAIN 服务），**共享密钥**从 WebAdmin → Radius服务管理 → 服务器设置 中确认（本文示例 `mytestkey`，请替换为你实际配置的值）
- 测试账号（PKI/USERS.txt，示例 `admin666 / admin666`）

## 二、安装 strongSwan

```bash
sudo apt update
sudo apt install strongswan strongswan-pki libcharon-extra-plugins
```

> `libcharon-extra-plugins` 包含 `eap-radius`、`xauth-radius` 插件（转发 RADIUS 必需），缺它配置加载会报 unknown plugin。

确认插件可用：
```bash
swanctl --load-all 2>&1 | head
```

## 三、用 MODPKICA 签发网关证书

在 WebAdmin → 签发证书 页面签一张 **终端证书（E）**：

| 参数 | 值 |
|---|---|
| 证书类型 | 终端证书 |
| 颁发者 | 你的某个 CA（类型 C） |
| 密钥算法 | RSA / ECC 均可 |
| 哈希算法 | SHA256 |
| 增强型密钥用法 | **服务器身份验证 (1.3.6.1.5.5.7.3.1)** |
| 使用者可选名称 SAN | `DNS:vpn.mydomain.com`（重要！手机要校验域名） |
| 证书策略 | 可不选 |

> iOS/Android 对 IKEv2 服务器证书要求：必须由设备信任的 CA 签发（你的 MODPKICA 根证书要装到手机），且证书名称与"远程 ID"匹配。

签发后导出以下三个文件（拷到虚拟机，路径见下一节）：
- 终端证书：`PKI/CERT/{序列号}.crt` → 作为网关证书 `gwCert.pem`
- 私钥：`PKI/KEY/{序列号}.key` → `gwKey.pem`
- 根证书：`PKI/ROOT/{序列号}.crt` → `rootCert.pem`

## 四、拷贝证书到虚拟机

在虚拟机上执行（或用 WinSCP 传输）：

```bash
sudo mkdir -p /etc/swanctl/x509 /etc/swanctl/private /etc/swanctl/x509ca
# 把三个文件放到 /tmp 后：
sudo mv /tmp/gwCert.pem  /etc/swanctl/x509/gwCert.pem
sudo mv /tmp/gwKey.pem   /etc/swanctl/private/gwKey.pem
sudo mv /tmp/rootCert.pem /etc/swanctl/x509ca/rootCert.pem
sudo chown root:root /etc/swanctl/x509/* /etc/swanctl/private/* /etc/swanctl/x509ca/*
sudo chmod 600 /etc/swanctl/private/gwKey.pem
```

## 五、swanctl 配置（三合一）

编辑 `/etc/swanctl/swanctl.conf`（替换整个文件）：

```
# ============ MODPKICA × strongSwan 网关配置 ============
# 替换以下占位符：
#   192.168.1.3   → 虚拟机静态 IP
#   192.168.1.100 → Windows 主机 IP（Java RADIUS 所在）
#   mytestkey     → WebAdmin 中实际配置的 RADIUS 共享密钥
#   vpn.mydomain.com → 网关证书中的域名（SAN）
#   group123456   → iOS Cisco IPsec 的组密钥（自定）
# =======================================================

connections {

    # ---------- ① IKEv2 · EAP-MSCHAPv2（用户名密码，iOS/Android 首选） ----------
    ikev2-mschapv2 {
        version = 2
        proposals = aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp2048
        pools = vpn_pool
        fragmentation = yes
        rekey_time = 0
        local {
            auth = pubkey
            certs = gwCert.pem
            id = vpn.mydomain.com
        }
        remote {
            auth = eap-mschapv2
            eap_id = %any
        }
        eap_radius {
            eap_start = yes
            servers {
                java-radius {
                    address = 192.168.1.100
                    secret = "mytestkey"
                    ports {
                        auth = 1812
                        acct = 1813
                    }
                }
            }
        }
        children {
            net {
                local_ts = 0.0.0.0/0
                remote_ts = 0.0.0.0/0
                esp_proposals = aes256-sha256,aes128-sha256
            }
        }
    }

    # ---------- ② IKEv2 · EAP-TLS（客户端证书认证） ----------
    ikev2-eaptls {
        version = 2
        proposals = aes256-sha256-modp2048,aes128-sha256-modp2048
        pools = vpn_pool
        fragmentation = yes
        rekey_time = 0
        local {
            auth = pubkey
            certs = gwCert.pem
            id = vpn.mydomain.com
        }
        remote {
            auth = eap-tls
            eap_id = %any
            ca_certs = rootCert.pem
        }
        children {
            net {
                local_ts = 0.0.0.0/0
                remote_ts = 0.0.0.0/0
                esp_proposals = aes256-sha256,aes128-sha256
            }
        }
    }

    # ---------- ③ Cisco IPsec（IKEv1 + XAUTH，组名/密钥 + 用户名密码） ----------
    ikev1-xauth {
        version = 1
        proposals = aes256-sha1-modp1024,aes128-sha1-modp1024
        pools = vpn_pool
        fragmentation = yes
        rekey_time = 0
        local {
            auth = psk
        }
        remote {
            auth = psk
            xauth = radius
        }
        xauth_radius {
            servers {
                java-radius {
                    address = 192.168.1.100
                    secret = "mytestkey"
                    ports {
                        auth = 1812
                        acct = 1813
                    }
                }
            }
        }
        children {
            net {
                local_ts = 0.0.0.0/0
                remote_ts = 0.0.0.0/0
                esp_proposals = aes256-sha1,aes128-sha1
            }
        }
    }
}

pools {
    vpn_pool {
        addrs = 10.10.0.0/24
        dns = 223.5.5.5,8.8.8.8
    }
}

secrets {
    # iOS Cisco IPsec 的"群组名称 + 密钥"
    ike-1 {
        id-remote = cisco-group
        secret = "group123456"
    }
}
```

## 六、Windows 防火墙放行

在 Windows（管理员 PowerShell）放行来自虚拟机的 RADIUS 流量：

```powershell
# 放行 UDP 1812/1813 来自虚拟机（按你的虚拟机 IP 或子网）
New-NetFirewallRule -DisplayName "MODPKICA RADIUS from VPN VM" `
  -Direction Inbound -Protocol UDP -LocalPort 1812,1813 `
  -RemoteAddress 192.168.1.3 -Action Allow
```

确认 Java RADIUS 监听：
```powershell
Get-NetUDPEndpoint -LocalPort 1812
```

## 七、启动与验证

```bash
sudo systemctl enable --now strongswan-swanctl
sudo swanctl --load-all
sudo swanctl --list-conns    # 应看到 3 个 connection
```

验证 RADIUS 转发（虚拟机内手动拨一次，看 Java 侧日志）：

```bash
# 在虚拟机测试 EAP-MSCHAPv2 是否能通到 Java RADIUS（用 eapol_test 或 strongswan 自带工具）
# 更直接：看 Windows 上 WebAdmin → Radius服务管理 → 服务器日志 是否出现来自 192.168.1.3 的请求
```

Java 侧确认点：WebAdmin → Radius服务管理 → 服务器日志，出现 `Access-Request 来源=192.168.1.3` 且认证通过 = 链路通。

## 八、手机拨号配置

**iOS —— IKEv2 用户名密码：**
1. 设置 → 通用 → VPN 与设备管理 → 安装你的 MODPKICA 根证书（信任它）
2. 添加 VPN 配置：类型 `IKEv2`，服务器填虚拟机 IP `192.168.1.3`，远程 ID 填 `vpn.mydomain.com`，本地 ID 留空，鉴定选"用户名"，输入 `admin666 / admin666`

**Android —— IKEv2/IPsec MSCHAPv2：**
1. 安装根证书（设置 → 安全 → 加密与凭据 → 安装证书）
2. 添加 VPN：类型 `IKEv2/IPsec MSCHAPv2`，服务器地址填虚拟机 IP，IPSec 标识符填 `vpn.mydomain.com`，用户名/密码 `admin666 / admin666`

**iOS —— Cisco IPsec：**
- 类型选 IPsec（Cisco），服务器填虚拟机 IP，帐户 `admin666`，密码 `admin666`，群组名称 `cisco-group`，密钥 `group123456`（每次询问可关）

## 九、L2TP（可选，较繁琐）

L2TP = IPsec(PSK) 隧道 + L2TP(1701) + PPP 认证。PPP 层认证转发 RADIUS 用 PAM 插件：

```bash
sudo apt install xl2tpd ppp libpam-radius-auth
```

`/etc/xl2tpd/xl2tpd.conf`：
```
[global]
listen-addr = 0.0.0.0
port = 1701
auth file = /etc/ppp/chap-secrets

[lns default]
ip range = 10.11.0.2-10.11.0.200
local ip = 10.11.0.1
require chap = yes
require pap = no
require authentication = yes
name = MODPKICA-L2TP
ppp debug = no
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
```

`/etc/ppp/options.xl2tpd`：
```
ipcp-accept-local
ipcp-accept-remote
ms-dns 223.5.5.5
noccp
auth
crtscts
idle 1800
mtu 1400
mru 1400
lock
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
plugin pam.so
```

PAM 转发 RADIUS（`/etc/pam.d/ppp`）：
```
auth required pam_radius_auth.so
account required pam_radius_auth.so
```

RADIUS 客户端配置（`/etc/radiusclient/radiusclient.conf` + `/etc/radiusclient/servers`）：
```
# servers 文件：
#   IP/name    secret   timeout
192.168.1.100    mytestkey    3
```

> L2TP 的 IPsec 部分在 swanctl.conf 加一个 IKEv1 + `local_ts/remote_ts = 0.0.0.0/0` 的连接并把 ESP 流量放行 UDP 1701 即可；较繁琐，建议先跑通 IKEv2 再折腾。

## 十、故障排查

| 症状 | 排查 |
|---|---|
| 连接建立失败 | `sudo journalctl -u strongswan-swanctl -f` 看 charon 日志；`sudo swanctl --list-sas` |
| 认证失败 | 看 Windows 上 Java 侧日志（WebAdmin → Radius 服务器日志）；确认共享密钥一致 |
| 手机提示证书无效 | 根证书未安装/未信任；远程 ID 与证书 SAN 不匹配 |
| RADIUS 无响应 | Windows 防火墙未放行 UDP 1812；虚拟机 IP 写错 |
| 路由不通 | 确认虚拟机网卡桥接、`sysctl net.ipv4.ip_forward=1`、防火墙 NAT（见下） |

若需让 VPN 客户端访问内网，虚拟机开 IP 转发 + NAT：

```bash
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
# iptables NAT（虚拟机的出接口 eth0 替换）
sudo iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o eth0 -j MASQUERADE
```
