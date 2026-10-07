# MODPKICA Java 复刻版 v1.28-r15（BC 1.85 离线）

> 使用 **Java + BouncyCastle 1.85** 离线复刻 Go 版 MODPKICA 全套 PKI 功能：X.509 证书签发、CRL 吊销列表、OCSP 在线状态、RFC3161 / Authenticode 时间戳、RFC 6962 CT 日志服务（SCT 服务管理）、WebAdmin 浏览器管理面板。
>
> - **技术栈**：纯 `javac` 编译，无 Maven / Gradle，无网络依赖，离线可开发
> - **依赖**：`BC185/` 目录下 BouncyCastle 1.85 全家桶（bcprov / bcpkix / bcutil / bcmail）+ `lib/`（pdfbox-app-3.0.4.jar）
> - **平台**：Windows（build.cmd）/ Linux（build.sh）
> - **作者**：@魔帝本尊（QQ：2829969554）

---

## 目录

- [界面截图](#界面截图)
- [功能特性](#功能特性)
- [项目结构](#项目结构)
- [环境要求](#环境要求)
- [一键编译](#一键编译)
- [运行方式](#运行方式)
- [命令行用法（7 个主程序）](#命令行用法7-个主程序)
- [RADIUS / PPPoE 接入服务](#8-radiusserver--pppoeserver--radius-与-pppoe-接入服务)
- [WebAdmin 管理面板](#webadmin-管理面板)
- [PKI 目录与文件说明](#pki-目录与文件说明)
- [证书类型与命名规则](#证书类型与命名规则)
- [配置文件 CONFIG.txt](#配置文件-configtxt)
- [登记表 CERTS.txt](#登记表-cerstxt)
- [操作日志 logs.log](#操作日志-logslog)
- [常见问题 FAQ](#常见问题-faq)
- [更新记录](#更新记录)

---

## 界面截图

### 仪表盘（证书链树 + 服务状态）

根 R → 中间 CA C → 终端 E 的证书链树，节点悬停显示证书参数；顶部一键刷新全部 CRL / 签发全部 OCSP / 签发全部时间戳；底部最近日志。

![仪表盘](a.png)

### 证书查看器（仿制 Windows 证书查看器）

**完全仿制 Windows 系统"证书"查看器对话框**——Windows 风格窗口（可拖拽移动、✕ 关闭），三页签布局与系统原版一致：

- **常规**：大证书图标 + 状态条（自动判定：不在有效期内显示琥珀色"已过期"；有效期内异步查询本库吊销状态，正常=绿色"该证书没有问题"，吊销=红色"该证书已被证书颁发机构吊销"）、"证书的目的"（EKU OID 全量中文对照，含证书策略特殊 OID「所有应用策略 / 所有颁发策略」）、颁发给 / 颁发者 / 有效期，底部「颁发者说明(S)」按钮——当证书策略含 CPS 链接或用户通告（Explicit Text）时自动出现，点击弹出说明窗（CPS 可点击外链 + 通告文本）；无证书策略则按钮自动隐藏
- **详细信息**：版本 / 序列号 / 签名算法（OID 正确命名，如 `SM2withSM3`、SHA256withRSA）/ 签名哈希算法 / 颁发者 / 有效期 / 使用者 / 公钥（**密钥类型 + 完整 HEX 字节流，16 字节一行**）；下拉过滤（全部 / 基本字段 / 扩展字段 / 关键字段）；扩展逐项展开——EKU（OID 中文对照）、AIA（OCSP + 颁发者 URL）、CRL 分发点、证书策略（CPS + User Notice）、密钥用法、SCT 列表（逐条：日志版本 / 日志名称 / 完整日志标识符 / 时间戳 / 签名类型 / 签名 / 验签状态）
- **证书路径**：树状信任路径（根→中间→终端），双击任意层级打开**独立新查看器**（路径自动截断到该层并默认选中）；底部显示当前层证书概要

入口：证书库每行「详情」→ JSON 结构弹窗 →「查看证书」按钮；证书库行**双击**直接打开。cacerts 公网证书库打开时只判有效期、不查吊销（无本库记录）。

![证书查看器](certview.png)

### 证书库（选择夹：证书库 CERTS.txt / 可信公网证书库 cacerts）

**「证书库 CERTS.txt」页**：序列号 / 类型 / 状态 / 原因 / 时间 / 颁发者 ID / 算法 / 操作，支持筛选与刷新；类型中文显示（R=根证书 / C=CA证书 / E=终端证书），状态三色（V 正常绿 / R 已吊销深红 / N 未知橙）；序列号与颁发者序列号悬停显示证书简要信息；每行含详情 / 验证 / 操作三个按钮（验证弹窗按状态显示绿/红/橙标题）；行**鼠标右键**弹出「下载证书 / 导出证书 / 删除证书」菜单——下载含单证书、证书链（crt/p7b）、私钥、pfx/jks 密钥库；导出含 PEM / HEX / Base64 剪贴板复制；**删除证书**经二次确认后**不删除文件**，只在 CERTS.txt 中为该行加 `#` 注释（忽略此行数据），生成 CRL / OCSP 证书时自动跳过。

**「可信公网证书库 cacerts」页**：读取 JAVA 环境 `cacerts`（JKS 信任库）全部证书，列表列 = 序列号 / 算法 / 生效日期 / 失效日期 / DN字段（时间格式 `yyyy/MM/dd HH:mm:ss`，序列号列收窄超长省略）；点击「详情」从 cacerts 导出 PEM 并转 JSON 结构化弹窗展示（X509JsonConverter 解析）。

![证书库](b.png)

### 签发根证书（MakeRoot + DN 辅助输入）

证书 DN（key=value 逗号分隔，key 可为标准属性或 OID）+ 密钥算法（RSA / ECC / SM2 下拉）+ 哈希算法 + 密钥位数（RSA 可编辑 1024~8192，ECC 只读 256/384/521，SM2 只读 256）；**DN 辅助输入**：通用名称 / 组织 / 组织单位 / 国家 / 省州 / 城市 / 邮箱各字段独立编辑框（placeholder 中文说明 + 例子），「是否 EV 扩展验证」勾选后显示 EV 注册字段，「+ 添加自定义字段」「从上方 DN 解析回填」双向同步；生成证书时 DN 按 X.500/RFC 规范顺序统一排序（C→ST→L→STREET→PostalCode→O→OU→SERIALNUMBER→CN，EV 字段随后）。

![签发根证书](c.png)

### 证书操作（吊销 / 续签 / 密钥更换）

证书库每行「操作」按钮弹出窗口，默认「吊销证书」分组：序列号可输入或下拉选择，显示证书简要信息（类型 / 序列号 / DN / 密钥对 / 哈希 / 长度 / OCSP 状态 / CRL 状态），选择吊销理由后确认吊销，或「恢复证书」将状态 R→V、原因置 0 并同步生成 CRL；另有「续签证书」（选择生效 / 失效时间重签）与「密钥更换」（按原算法生成新密钥对测试后重签，SKI 随新公钥更新）分组。

![证书操作](h.png)

### 证书链详情（悬停悬浮窗）

证书链树节点悬停弹出详情：证书类型（含策略识别）、序列号、DN、密钥对 / 哈希 / 密钥长度、OCSP 状态、CRL 状态。

![证书链详情](e.png)

### 调试专区（模拟 OCSP / 时间戳请求）

按标准协议构造请求并 POST 本机 MAIN，日志逐步展示：模拟 OCSP 请求（RFC 6960，CertID 基于真正颁发者证书 + Nonce，哈希算法可选 SHA1/SHA256/SHA384/SHA512/SM3，验证响应签名与 Nonce 回显）；模拟时间戳请求（RFC 3161，随机 32 字节 → 按所选摘要算法计算 messageImprint → TimeStampReq（Nonce + certReq）→ 解析 TimeStampResp 并验证 token 签名）。

![调试专区](g.png)

### 签名专区（选择夹：微软代码签名 / PDF 文档签名）

**选择夹布局**：签名专区改为上下两个独立页签（tab）——「微软代码签名」与「PDF 文档签名」各占整页，空间更大、互不干扰；全局字体 15px，控件间距与列表行高同步放大。

**微软代码签名（Authenticode）**：**同样支持批量选择与拖拽添加**——把 exe / dll / sys / cab / cat / msi 文件拖入虚线拖拽区或点击「选择文件」多选；待签名列表逐行显示文件名 / 大小 / 状态（待处理 / 签名中 / 成功 / 失败），行内可单独签名、验证、移除，成功后行内下载；顶部「批量签名」「批量验证」「清空」一次处理全部。签名支持 RSA / ECC / SM2（摘要分别 SHA256 / SHA256 / SM3），证书表按 Microsoft PE/COFF 规范嵌入。**时间戳类型**下拉可选 **RFC3161**（标准 TimeStampToken）或 **Authenticode**（老式 PKCS#7）；**时间戳请求地址**可编辑下拉留空 = 本机 MAIN，或指向 DigiCert / Symantec / Comodo / Certum 等外部 TSA。

**PDF 文档签名**：**支持批量选择（多选文件）与拖拽添加**——把 PDF 文件直接拖入虚线拖拽区，或点击「选择 PDF 文件」多选；待签名列表逐行显示文件名 / 大小 / 状态（待处理 / 签名中 / 成功 / 失败），每行可单独签名、验证、移除，成功后可下载；顶部「批量签名」「批量验证」「清空」一次处理全部。证书（带文档签名 EKU，微软 OID `1.3.6.1.4.1.311.10.3.12` 或通用 OID `1.3.6.1.5.5.7.3.36` 任一即可；**证书留空 = 纯文档时间戳，不签名**）。**签章类型**下拉四种：Adobe 标准文档签名（`adbe.pkcs7.detached`，RSA/ECC/SM2 均可，可选签章图片生成可见签章；**选中证书时时间戳按 CAdES-T / PAdES-T 标准嵌入签名内部（SignerInfo 的 unsignedAttrs 属性 id-aa-timeStampToken，messageImprint = SHA-256(签名值)），DSS/LTV 数据（证书链 + OCSP 响应 + CRL）与签名同一次保存、被签名覆盖，签名后零增量**；不选证书时生成独立 DocTimeStamp（ETSI.RFC3161）纯文档时间戳，同样带 DSS/LTV）；国密 GB/T 35275-2017（`GM.sm2cms.detached`，仅 SM2 证书 + 签章图；同样支持 CAdES-T 签名时间戳（SM3 摘要 + unsignedAttrs）与 DSS/LTV 同保存）；国密 GB/T 38540-2020（`GM.sm2seal` SES_Signature，仅 SM2 证书 + 签章图；按标准 7.1.6 支持嵌入时间戳——SES_Signature 可选第 5 字段 timeStamp（对签名值的时间戳，符合 GB/T 20520= RFC3161，DER 编码，SM3 messageImprint），并支持 DSS/LTV 同保存）；国密 GM/T 0031-2025（`GM.sm2seal`，仅 SM2 证书 + 签章图，数据结构与 38540 一致）。验证支持三种类型：CMS 验签 / 文档摘要比对 / 证书链（Adobe 与 35275），SES_Signature 专用解析（dataHash 比对 + SM2 验签，自动判别 38540 四/五字段、0031 两字段；38540 时间戳字段 timeStamp 解析：TSA/时间/算法/绑定签名值（SM3）+ TSA 证书验签）；Adobe 模式逐签名字段验证（数字签名含签名时间戳 CAdES-T unsignedAttrs 解析：TSA/时间/算法/绑定签名值，哈希算法自适应 SHA-256/SM3；DocTimeStamp 走 TimeStampToken 专用解析：messageImprint 比对 + TSA 证书验签），输出含 LTV 状态（DSS Certs/OCSPs/CRLs 数量）。

![签名专区选择夹](f.png)

### 签发证书（EV 扩展验证辅助输入）

证书 DN 辅助输入：CN / O / OU / C / S / L / E 邮箱基础字段 + 「是否 EV 扩展验证」勾选后显示 **EV 注册字段区**（注册类型 businessCategory 四选一：Private Organization / Government Entity / Business Entity / Non-Commercial Entity、注册号 serialNumber、组织标识符 organizationIdentifier、注册国家 / 注册省 / 注册市 jurisdiction*、组织标识符扩展 OID 版本新旧选择）；「密钥与算法」分组：证书类型（根证书 / CA证书 / 终端证书）、密钥算法、密钥位数、哈希算法；生成证书时 DN 按统一标准排序。

![签发证书](i.png)

### 签名专区（签章图片素材示例）

国密 PDF 电子签章（35275 / 38540 / 0031）需选择签章图片（png/jpg/bmp/gif），本图为内置示例签章 `stamp.png`（红色圆形电子签章：MODPKICA / 电子签章）。

![签章素材](stamp.png)

### SCT 服务管理（选择夹：CT日志密钥管理 / CT请求日志 / 可信公网CT公钥管理）

**CT日志密钥管理**：描述输入 + 生成 ECDSA / RSA / SM2 密钥对三按钮 + 刷新列表；密钥列表逐行显示 序号 / 描述 / 类型 / 日志公钥 ID（自适应列宽，超长省略）/ 状态（可用绿 / 不可用红）/ 创建时间 / 操作（「启用⇄暂停」单按钮点击切换 + 「删除」置末），密钥写入 `PKI/CTLOG/modpkica_ct_list.json`（v3 风格，`type` 字段区分 ECDSA/RSA/SM2，缺省 ECDSA）。

**CT请求日志**：只读展示 `PKI/CTLOG/ctlogs.txt` 全部行（自带序号）。

**可信公网CT公钥管理**：展示项目根 `log_list.json`（Google 权威 CT 日志公钥数据集 v3，`https://www.gstatic.com/ct/log_list/v3/log_list.json`）全部日志，含数据日期与「拉取最新数据」按钮（在线更新后刷新列表），布局参考密钥管理。

![SCT服务管理](j.png)

### 证书库（SCT 列表验签弹窗）

证书库「验证」按钮弹窗的 SCT列表 区块：逐条显示 日志版本 / 日志名称 / 日志标识符 / 时间戳 / 签名类型 / 签名 / 状态（签名有效 / 签名无效 / 未知日志，无法验证）——SM2 证书的 SCT 由 SM2 日志密钥签名（SM2-SM3），状态显示"签名有效"。

![SCT验签弹窗](k.png)

### 操作日志（logs.log 可视化）

时间范围筛选（最近 1/6/12/24 小时、全部）、行数设置、自动刷新（3 秒）、手动刷新；每条日志含时间、时间戳、操作、命令、结果。

![操作日志](d.png)

---

## 功能特性

### 1. MAIN —— 网络服务主程序

- **OCSP 在线证书状态协议**：`/OCSP`、`/ocsp`（POST），按请求证书序列号查 CERTS.txt 返回正常 / 已吊销 / 未知状态；支持 Nonce、按请求摘要算法自适应（SHA1/SHA256/SHA384/SHA512，SM2 固定 SM3，无摘要默认 SHA1）；未知序列号返回无签名 unauthorized 响应；用 `序列号_ocsp.crt/.key` 签署响应；SM2 分支吊销响应按 RFC 6960 标准编码（`revoked [1] IMPLICIT RevokedInfo`），openssl / BC 均可正常解析
- **CRL 吊销列表下载**：`/CRL/序列号.crl`、`/CRL/序列号.der.crl`
- **证书下载**：`/CRT/序列号.crt`
- **RFC3161 时间戳**：`/rfc3161`（文档签名专用，SHA1 / SHA256 自适应）
- **微软 Authenticode 时间戳**：`/timestamp`（SHA256）、`/timestamp/sha1`（SHA1）；请求体为 base64（容忍 CRLF / 末尾 NUL 等杂字符），响应为 PKCS#7 分离签名（eContent + signedAttrs 含 id-data 属性）
- **自适应根 TSA**：SHA1 → 随机 `rsa_sha1` / `ecc_sha1`；SHA256 → 随机 `rsa_sha256` / `ecc_sha256`；SM3/SM2 → `sm2_sm3`
- **CT 日志服务（RFC 6962）**：`/ct/add`（仅 POST），请求体为「PEM 预证书 + PEM 颁发者证书」，按 RFC 6962 §3.1 构造 precert_entry（issuer_key_hash + 去 poison TBS）→ 加载 `PKI/CTLOG/modpkica_ct_list.json` 中 usable 密钥签名 → 返回二进制 SCTList TLS 编码；**类型匹配选组**：SM2 预证书只选 usable 的 SM2 密钥，RSA/ECDSA 预证书只选 RSA+ECDSA 密钥，随机 ≤3 组（仅一组就签一组）；SCT 枚举 SM2=(7,4)（国密 CT 实现枚举，对齐零信 sm2ct.cn），ECDSA=(4,3)，RSA=(4,1)；每密钥一行追加 `PKI/CTLOG/ctlogs.txt`（`SCT待签名摘要||时间戳||终端SKI||终端AKI||日志公钥ID`）
- **静态网页**：`/` 提供 `PKI/WebPublic` 下文件
- **启动时自动刷新全部 CRL**
- **内嵌 WebAdmin 管理面板**（管理端口见下）

### 2. Admin —— 管理控制台（命令行）

`init` 初始化环境、`makeroot` 签发根证书、`list` 列出证书、`signcert` 签发证书、`revoke` 吊销证书、`signCRL` 刷新 CRL、`initOCSP` 签发全部 OCSP 证书、`initTIMESTAMP` 签发全部时间戳证书、`verifyCERT` 证书验证。

### 3. MakeRoot —— 签发根证书

生成 `ROOT/序列号.crt`、`ROOT/序列号.key`，同步 `WebPublic/CRT/序列号.crt`，登记 CERTS.txt（类型 R）。

### 4. MakeCert —— 签发下级证书

支持签发中间 CA（类型 C）、终端证书（类型 E）；颁发者证书类型自动从 ROOT / CA 目录加载密钥对；支持 RSA / ECC / SM2 / PQC（ML-DSA-44/65/87，纯签名哈希 NULL）、SHA1 / SHA256 / SHA384 / SHA512 / SM3；密钥用法、增强型密钥用法（EKU 编号或 OID）、证书策略、SAN、有效期自定义。**SCT 预证书流程**：签发服务器 / 客户端证书（EKU 含服务器/客户端认证）时，先签发含 poison 扩展（RFC 6962）的 SCT 预证书，POST 本机 `/ct/add` 获取 SCTList，嵌入 SCT 扩展（OID `1.3.6.1.4.1.11129.2.4.2`）二次签名生成最终证书（已移除自创 2.4.5 扩展）。

### 5. RootGetCrl —— 签发吊销列表

遍历 CERTS.txt 中全部 R / C 证书，为每个颁发者生成独立 CRL（`WebPublic/CRL/序列号.crl`），哈希算法沿用颁发者证书（如 RSA/sha256、RSA/sha512）。

### 6. CertVerify —— 证书验证

输入证书文件或序列号，打印证书全字段（版本、序列号、签名算法、DN、有效期、公钥、SKI/AKI、EKU、SAN、AIA、CRL 分发点、KeyUsage、基本约束、证书策略、扩展、SCT）、签名验证、证书链、CRL + OCSP 吊销状态、各类哈希。**SCT 列表逐条验签**（RFC 6962）：按 log_id 匹配日志公钥（本地 CTLOG 密钥库 + 权威 log_list.json），构造 precert_entry / x509_entry 待签名数据重算摘要，ECDSA（DER + 裸 r‖s 兼容）/ RSA / SM2（枚举 7,4 与 7,7 均支持）验签，输出 日志名称 / 日志标识符 / 时间戳 / 签名类型 / 状态（签名有效 / 签名无效 / 未知日志，无法验证）。

### 7. Auto —— 自动化命令

`init` 初始化环境、`revoke 序列号 原因` 吊销证书、`newcert 序列号 类型 状态 原因 时间 颁发者ID 算法` 手工登记。

### 8. RadiusServer / PPPoEServer —— RADIUS 与 PPPoE 接入服务

#### RADIUS 服务（`RadiusServer.java`，RFC 2865 / 2866 / 2869 / 3579）

UDP 认证端口（默认 1812）+ 计费端口（默认 1813）双线程；账号复用用户管理库（`PKI/USERS.txt`）；认证与计费请求/响应全部写入 `logs.log` 与内存环形日志（最近 500 条）。

**12 种认证方式（全部按 RFC 标准实现，服务端 + 客户端调试双端）**：

| # | 认证方式 | 标准依据 | 说明 |
|---|---|---|---|
| 1 | PAP | RFC 2865 §5.2 | 明文口令，`MD5(Secret+Authenticator)` 混淆 |
| 2 | CHAP | RFC 2865 §5.3 | 16B 挑战 + `MD5(ChapId‖密码‖挑战)` |
| 3 | MS-CHAPv1 | RFC 2433 | Vendor-Specific(微软, Type=24)，MD4 NT-Hash 2×DES 加密挑战比对 |
| 4 | MS-CHAPv2 | RFC 2759 | 8B 挑战 + 50B 响应（Ident+Pad+PeerChallenge16+Reserved8+NT-Response24），服务端单包携带挑战+响应 |
| 5 | EAP-MD5 | RFC 3748 §5.4 | 16B 挑战，`MD5(InnerId‖密码‖挑战)` |
| 6 | EAP-GTC | RFC 3748 §5.6 | 明文令牌挑战（"Enter Password:" 提示），常数时间比对 |
| 7 | EAP-TLS | RFC 5216 | BC 1.85 `bctls` TLS 1.2 完整握手；RFC 5216 §2.1 240B 分片每片一个 EAP 包；RFC 3579 §2.1 EAP-Message 属性切分拼接；TLS 1.2 RSA 签名 PKCS#1 v1.5 填充 |
| 8 | EAP-TTLS | RFC 5281 | 外层 TLS 隧道 + **内层 PAP AVP 交换**（RFC 5281 §8.5：Type(1)+Length(1)+Value，User-Name/User-Password） |
| 9 | PEAP-MD5 | RFC 5216 隧道 + 内层 EAP-MD5 | 外层 PEAP Start→TLS 隧道→内层 MD5 挑战/响应 |
| 10 | PEAP-MSCHAPv2 | RFC 5216 + RFC 2759 | 内层 MS-CHAPv2 两轮隧道交换（Challenge→NT-Response 50B） |
| 11 | PEAP-GTC | RFC 5216 隧道 + RFC 3748 §5.6 | 内层 GTC 明文令牌 |
| 12 | EAP-pwd | RFC 5931（P-256） | 四轮密钥交换：ID(Group=6)→Commit(标量32B+SEC1 压缩点33B)→双向 Confirm(HMAC-SHA256)→Success；猎取-啄食法 PWE 派生（HKDF-SHA256，p≡3 mod 4 开根） |

**EAP 会话密钥（MSK）下发**：EAP-MSCHAPv2 认证通过后，Access-Accept 自动携带 **MS-MPPE-Recv-Key(type17)/MS-MPPE-Send-Key(type16)**（RFC 2548 §2.4.3 加密 + §2.4.2 语义）——密钥按 RFC 3079 §3.1 由 `SHA1(MD4(NT-Hash)‖NT-Response‖MPPE 魔数)` 派生（magic2=客户端 send / 服务器 receive、magic3=客户端 recv / 服务器 send）；strongSwan `eap-radius` 网关解密后重组 `recv‖send‖补零 64B` 即得到与客户端完全一致的 64 字节 EAP MSK（RFC 5247），**IKEv2（手机 strongSwan）+ PEAP + TTLS 会话密钥链路实测打通**；属性布局与 strongSwan `radius_socket.decrypt_msk` 的 `mppe_key_t` 逐字节对齐（`Vendor-ID(311)‖Type‖Length‖Salt‖Cipher`，Length=4+N，加密种子=对应 Access-Request 的 Request-Authenticator）。

**属性支持**：`User-Name` / `User-Password` / `CHAP-Password`+`CHAP-Challenge` / `NAS-*`；**Vendor-Specific（微软，RFC 2548）**：MS-CHAP-Challenge / MS-CHAP-Response / MS-CHAP2-Response（按 Vendor-Type 自动分流 v1/v2）；**MS-MPPE-Send/Recv-Key（type16/17，会话密钥下发）**；**隧道属性（RFC 2867/2868）**：Tunnel-Type / Tunnel-Medium-Type / Tunnel-Client-Server-Endpoint / Tunnel-Password 自动解析成文字记录（PPTP/L2TP/IPsec/GRE 场景可见）；`Message-Authenticator`（RFC 2869 §5.3，HMAC-MD5）；`EAP-Message`（RFC 3579 §2.1，>253B 自动切分、响应端按出现顺序拼接还原）。

**Identity 用户名前缀分流**（大小写不敏感，顺序固定）：`ttls:`/`eap-ttls:`→TTLS；`pwd:`/`eap-pwd:`→EAP-pwd；`gtc:`/`eap-gtc:`→EAP-GTC；`peap-gtc:`/`eap-peap-gtc:`→PEAP-GTC；`peap-mschapv2:`/`eap-peap-mschapv2:`→PEAP-MSCHAPv2；`peap:`/`eap-peap:`→PEAP-MD5；`tls:`/`eap-tls:`→EAP-TLS；无前缀→PAP/CHAP/MS-CHAPv1/MS-CHAPv2。

**配置项（`PKI/CONFIG.txt`）**：`RADIUSPORT=1812`（认证端口）、`RADIUSACCT=1813`（计费端口）、`RADIUSKEY=mytestkey`（共享密钥）、`RADIUSAUTO=on/off`（MAIN 启动时自动开启，默认 off）。

#### PPPoE 服务（`PPPoEServer.java`，RFC 2516 + RFC 1661 + RFC 1334 + RFC 1994）

UDP 封装标准报文：Discovery `0x8863`（默认 512）+ Session `0x8864`（默认 513）。

- **Discovery 阶段（RFC 2516）**：PADI(0x09)→PADO(0x07)/PADR(0x19)→PADS(0x65)/PADT(0xa7)；标签 Service-Name(0x0101)/AC-Name(0x0102)/Host-Uniq(0x0103)
- **Session 阶段（RFC 1661 PPP LCP）**：Conf-Req/ACK/NAK/REJ/Term-Req/Ack；选项 MRU / Auth-Protocol / Magic-Number
- **PPP 认证**：PAP（RFC 1334）+ CHAP（RFC 1994，`MD5(Id‖密码‖挑战)`）
- 认证复用用户管理库；配置项 `PPPOEDISC=512`、`PPPOESESS=513`、`PPPOEAUTO=on/off`

#### 客户端-调试专区（WebAdmin）

「Radius服务管理 / PPPoE服务管理」页面均含「服务管理 / 客户端-调试专区」双分类夹：调试专区可选任意一种认证方式（12 项下拉）+ 账号/密码/共享密钥/端口，`发起调试` 后逐步打印完整握手过程（含每步 EAP 报文、TLS 分片、AVP 帧、EAP-pwd 标量/元素/Confirm 值）；PPPoE 专区提供完整拨号流程模拟（PADI→PADO→PADR→PADS→LCP→PAP/CHAP→PADT）。调试请求与结果全部写入 `logs.log`。

### WebAdmin —— 浏览器管理面板

深色主题管理后台（15 个页面，含「SCT服务管理」），详见下文。

---

## 项目结构

```
modpkica4JAVA/
├── BC185/                        # BouncyCastle 1.85 离线 jar 全家桶
├── lib/                          # pdfbox-app-3.0.4.jar（PDF 签名/验证）
│   ├── bcprov-jdk18on-1.85.jar   # 加密 Provider
│   ├── bcpkix-jdk18on-1.85.jar   # 证书 / CMS / TSP
│   ├── bcutil-jdk18on-1.85.jar   # ASN.1 工具
│   └── bcmail-jdk18on-1.85.jar   # 邮件 / SMIME
├── src/modpkica/                 # 全部源码（21 个类）
├── out/                          # 编译输出（javac -d out）
├── build.cmd                     # Windows 一键编译脚本
├── build.sh                      # Linux 一键编译脚本
├── PKI/                          # 运行时数据目录（MODPKICA_BASE 指向项目根时）
│   ├── ROOT/                     # 根证书（类型 R） 序列号.crt / 序列号.key
│   ├── CA/                       # 中间证书（类型 C） 序列号.crt / 序列号.key
│   ├── CERT/                     # 终端证书 PEM（类型 E） 序列号.crt
│   ├── KEY/                      # 终端证书私钥（类型 E） 序列号.key
│   ├── OCSP/                     # OCSP 签名证书 序列号_ocsp.crt / .key
│   ├── TIMSTAMP/                 # TSA 时间戳证书（类型_哈希算法.crt，如 rsa_sha256.crt）
│   ├── WebPublic/
│   │   ├── CRT/                  # 全部证书对外下载目录（序列号.crt）
│   │   └── CRL/                  # 全部 CRL 对外下载目录（序列号.crl）
│   ├── CERTS.txt                 # 证书登记表
│   ├── CONFIG.txt                # 系统配置
│   └── logs.log                  # 操作日志（只追加）
├── a.png ~ k.png                 # WebAdmin 界面截图（本文档配图）
├── stamp.png                     # PDF 国密签章示例图片
├── README.md                     # 本文件
└── 开发助手_源码分析.pdf          # 源码结构 / 运行流程 / 常量函数速查
```

### 源码类一览（src/modpkica/）

| 类 | 职责 |
|---|---|
| `MAIN` | 主程序 1：HTTP 服务（OCSP / CRL / 时间戳 / 静态网页）+ 内嵌 WebAdmin |
| `Admin` | 主程序 2：管理控制台（doInit / doMakeRoot / doSignCert / doRevoke / doSignCrl / doInitOcsp / doInitTimestamp / doVerifyCert / doList） |
| `MakeRoot` | 主程序 3：签发根证书 |
| `MakeCert` | 主程序 4：签发下级证书（CA / 终端） |
| `RootGetCrl` | 主程序 5：生成全部 CRL |
| `CertVerify` | 主程序 6：证书验证（详情 / 签名 / 链 / 吊销 / 哈希） |
| `Auto` | 主程序 7：自动化（init / revoke / newcert） |
| `WebAdmin` | 浏览器管理面板（8080 管理端口，15 页面，32 个 API） |
| `Bc` | BC Provider 注册 |
| `PemIO` | PEM 证书 / 私钥读写、密钥类型探测 |
| `CertUtil` | 证书构建工具（SKI、扩展组装、私钥读取等） |
| `CrlUtil` | CRL 生成 / DER→PEM |
| `OcspUtil` | OCSP 请求解析 / 响应生成（含 SM2、Nonce、无签名响应） |
| `TimestampUtil` | RFC3161 与 Authenticode 时间戳（含 SM2→SM3） |
| `Sm2Util` | 国密 SM2 签名 / 验签 / SM3 / ZA 计算 |
| `SignTool` | EXE / PDF 签名与验证（Authenticode 手工 ASN.1、RFC3161/Authenticode 时间戳、Adobe 与国密 PDF 电子签章、SES_Signature 验证） |
| `CtLog` | CT 日志密钥库 CRUD（ECDSA/RSA/SM2 多算法）、RFC 6962 预证书 SCT 签名、SCTList 编码、类型匹配选组（≤3 组）、`isSm2Precert` 判断 |
| `CertsDB` | CERTS.txt 登记表加载 / 查询 / 刷新 |
| `Config` | CONFIG.txt 配置加载 |
| `MLog` | 追加式操作日志（时间 / 时间戳 / 操作 / 命令 / 结果） |
| `AppPaths` | 工作目录定位（环境变量 MODPKICA_BASE） |
| `AppEnv` | 可执行程序清单 |
| `X509JsonConverter` | X.509 证书 → JSON 结构化（证书库详情展示用） |

---

## 环境要求

| 项目 | 要求 |
|---|---|
| JDK | 17+（已装 JDK 17/21 均可），`javac` / `java` 在 PATH 中 |
| 依赖 | 无需联网，`BC185/`（BC 1.85 全家桶）+ `lib/`（pdfbox-app-3.0.4.jar） |
| 系统 | Windows 10/11 或 Linux（脚本分别提供 .cmd / .sh） |

---

## 一键编译

### Windows

双击 `build.cmd`，或在 cmd 中执行：

```bat
build.cmd
```

脚本流程：检查 javac → 清理 `out/` → `javac -encoding UTF-8 -cp "BC185\*;lib\*" -d out src\modpkica\*.java` → 校验 8 个 class（7 个主程序 + WebAdmin）→ 编译成功才打印运行命令提示。

**编号参数（编译后自动运行）：**

```bat
build.cmd [1-9]
```

`build.cmd` 后跟 1~9 的编号，编译**成功后**自动执行对应编号的命令；编译**失败**则跳过，不运行任何命令。编号非法（非 1-9）会在编译前直接报错退出。

| 编号 | 自动运行的命令（等价于手敲 java 命令） |
|---|---|
| `1` | `java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.MAIN`（MAIN 服务 + WebAdmin 面板，默认 8080 端口） |
| `2` | `java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.WebAdmin`（只开管理面板） |
| `3` | `java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.Admin`（交互式管理控制台） |
| `4` | `java ... modpkica.MakeRoot "CN=Root,O=Org,C=CN" 2048 sha256 RSA`（签发根证书**示例参数**） |
| `5` | `java ... modpkica.MakeCert "CN=www.test.com" 2048 sha256 1 1 0 1 "www.test.com" null null root RSA`（签发证书**示例参数**） |
| `6` | `java ... modpkica.RootGetCrl`（刷新全部 CRL） |
| `7` | `java ... modpkica.CertVerify cert.crt`（验证**示例文件** cert.crt） |
| `8` | `java ... modpkica.Auto revoke 1234567890 1`（吊销**示例序列号**） |
| `9` | `ModpkicaUnitTest`（单元测试：先编译 debug_test\ModpkicaUnitTest.java，编译失败则不运行） |

> **注意**：编号 4/5/7/8 自动运行的是脚本内置的**固定示例参数**，不会透传额外参数（如 `build.cmd 8 revoke xxx 5` 中的 `revoke xxx 5` 会被忽略）。实际业务参数请改脚本 `:run_4`~`:run_8` 段落，或直接手敲完整 `java` 命令。

### Linux

```bash
chmod +x build.sh
./build.sh        # 只编译
./build.sh 1      # 编译成功后自动运行 MAIN（编号 1-9，与 build.cmd 完全一致）
```

> 编译成功后所有类在 `out/` 目录。

---

## 运行方式

所有主程序统一入口格式：

```bat
set MODPKICA_BASE=你的PKI根目录
java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.主程序名 [参数...]
```

> **重要**：Windows 下必须加 `-Dfile.encoding=UTF-8`，否则中文日志 / 中文 DN 乱码（GBK 问题）。
> `MODPKICA_BASE` 缺省时取当前工作目录。示例环境为 `C:\Users\28299\Desktop\modpkica4JAVA`（PKI 目录直接位于其下）。

**运行 MAIN（推荐，WebAdmin 面板随服务自动启动）：**

```bat
set MODPKICA_BASE=C:\Users\28299\Desktop\modpkica4JAVA
java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.MAIN
```

- WEB 服务端口：`PKI/CONFIG.txt` 的 `WEBPORT`（默认 80）
- WebAdmin 管理端口：默认 8080；可用系统属性改：`-Dmodpkica.admin.port=8082`
- 启动后浏览器访问 `http://localhost:8080`（管理面板），`http://localhost:80`（WEB 服务）

**只运行 WebAdmin（不启动 MAIN 服务）：**

```bat
java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.WebAdmin
```

---

## 命令行用法（7 个主程序）

### Admin（管理控制台）

```bat
java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.Admin
```

交互命令一览：

| 命令 | 说明 |
|---|---|
| `init` | 初始化环境（清空证书目录 + 重建 CERTS.txt） |
| `makeroot 证书DN 密钥位数 哈希算法 密钥算法` | 签发根证书，如 `makeroot "CN=Root,O=My Org,C=CN" 2048 sha256 RSA` |
| `list` | 列出全部登记证书 |
| `signcert 证书DN 密钥位数 哈希算法 证书类型 有效期年数 SAN类型 SAN内容 颁发者序列号 密钥算法` | 签发下级证书 |
| `revoke 序列号 原因编号` | 吊销证书（原因 0-9） |
| `signCRL` | 刷新全部 CRL |
| `initOCSP 密钥算法 [序列号]` | 为全部（或指定）R/C 证书签发 OCSP 签名证书 |
| `initTIMESTAMP 哈希算法` | 签发时间戳证书（rsa/ecc/sm2 × sha1/sha256/sm3） |
| `verifyCERT 证书文件或序列号` | 证书验证 |

### MakeRoot

```bat
java ... modpkica.MakeRoot "CN=Root,O=My Org,C=CN" 2048 sha256 RSA
```

### MakeCert

```bat
java ... modpkica.MakeCert "CN=www.test.com" 2048 sha256 1 1 0 1 "www.test.com" null null root RSA
```

### RootGetCrl

```bat
java ... modpkica.RootGetCrl
```

### CertVerify

```bat
java ... modpkica.CertVerify cert.crt        # 按文件
java ... modpkica.CertVerify 113521bfd       # 按序列号（自动去 WebPublic/CRT 查找）
```

### Auto

```bat
java ... modpkica.Auto init
java ... modpkica.Auto revoke 113521bfd 5
java ... modpkica.Auto newcert 序列号 E V 0 null 13fbe86586d1bca RSA
```

---

## WebAdmin 管理面板

启动 MAIN 或 WebAdmin 后，浏览器访问管理端口（默认 `http://localhost:8080`）。

### 页面（15 个）

| 页面 | 功能 |
|---|---|
| 仪表盘 | 服务状态、证书链树（R→C→E，悬停详情、R 展开 / C 收起管理下级）、一键刷新 CRL / 签发 OCSP / 签发时间戳、最近日志 |
| 证书库 | CERTS.txt 列表（类型中文：R=根证书 / C=CA证书 / E=终端证书；状态三色：V 正常绿 / R 已吊销深红 / N 未知橙；筛选、刷新）、序列号与颁发者序列号悬停悬浮窗、详情按钮（JSON 结构化证书信息）、验证按钮（弹窗三态：正常/已吊销/未知 + SCT 列表逐条验签）、操作按钮（吊销证书 / 续签证书 / 密钥更换分组） |
| 签发根证书 | 根证书参数表单 |
| 签发证书 | 完整参数表单（DN / 类型 / 密钥算法 / 密钥位数联动 / 哈希 / KeyUsage / EKU / 有效期 / SAN） |
| 吊销证书 | 按序列号 + 原因吊销 |
| CRL 刷新 | 重新生成全部 CRL |
| OCSP 签发 | 为全部 R/C 证书签发 OCSP 签名证书 |
| 时间戳签发 | 签发时间戳证书 |
| 证书验证 | 输入证书文件或序列号验证（证书策略识别含 SSL/代码签名/文档签名/TSA 等 OID；SCT 列表逐条验签，日志公钥源：本地 CTLOG 密钥库 + 权威 log_list.json） |
| 初始化环境 | 清空重建（不会执行重置类脚本，由 WEB 面板提供） |
| 系统配置 | 可视化读写 CONFIG.txt（WEBPORT / SUPORT / OCSP / CRL / CRT / CPS / CPS_Nonice 多行文本） |
| 操作日志 | logs.log 时间范围筛选 + 自动刷新 |
| 调试专区 | 模拟 OCSP 请求（RFC 6960，CertID+Nonce，哈希算法可选 SHA1/256/384/512/SM3，验证响应签名与 Nonce 回显）+ 模拟时间戳请求（RFC 3161，随机数据按所选摘要算法构造 TimeStampReq，解析并验证 token 签名） |
| SCT服务管理 | CT日志密钥管理（生成 ECDSA/RSA/SM2 密钥对、密钥列表 删除/启用/暂停，写 PKI/CTLOG/modpkica_ct_list.json）+ CT请求日志（只读 ctlogs.txt） |
| 签名专区 | EXE 代码签名（时间戳类型 RFC3161/Authenticode + 时间戳地址可编辑下拉）+ PDF 文档签名（签章类型 Adobe/国密 35275/国密 38540/国密 0031 + 时间戳地址可编辑下拉），均含签名与验证 |

### API（33 个）

`/api/status`、`/api/certs`、`/api/certs/delete`、`/api/logs`、`/api/config`、`/api/chain`、`/api/certjson`、`/api/version`、`/api/issuers`、`/api/init`、`/api/makeroot`、`/api/signcert`、`/api/revoke`、`/api/restore`、`/api/rekey`、`/api/renew`、`/api/crl`、`/api/initocsp`、`/api/inittimestamp`、`/api/verify`、`/api/signcerts?kind=exe|pdf`（GET）、`/api/sign/exe`、`/api/sign/pdf`、`/api/verify/exe`、`/api/verify/pdf`、`/api/debug/ocsp`、`/api/debug/tsa`、`/api/ctlog/list`、`/api/ctlog/logs`、`/api/ctlog/gen`、`/api/ctlog/delete`、`/api/ctlog/enable`、`/api/ctlog/pause`

---

## PKI 目录与文件说明

| 路径 | 内容 |
|---|---|
| `PKI/ROOT/` | 根证书：`序列号.crt` + `序列号.key` |
| `PKI/CA/` | 中间证书：`序列号.crt` + `序列号.key` |
| `PKI/CERT/` | 终端证书 PEM：`序列号.crt` |
| `PKI/KEY/` | 终端证书私钥：`序列号.key` |
| `PKI/OCSP/` | OCSP 签名证书：`序列号_ocsp.crt` + `序列号_ocsp.key` |
| `PKI/TIMSTAMP/` | TSA 证书：`类型_哈希算法.crt`（rsa_sha1 / rsa_sha256 / ecc_sha1 / ecc_sha256 / sm2_sm3）+ `.key` |
| `PKI/WebPublic/CRT/` | 全部证书对外下载：`序列号.crt` |
| `PKI/WebPublic/CRL/` | 全部 CRL 对外下载：`序列号.crl`、`序列号.der.crl` |
| `PKI/CERTS.txt` | 证书登记表 |
| `PKI/CONFIG.txt` | 系统配置 |
| `PKI/logs.log` | 操作日志 |
| `PKI/CTLOG/` | CT 日志密钥库 `modpkica_ct_list.json`（v3 风格，含 type 字段）+ 请求日志 `ctlogs.txt`（只追加） |

---

## 证书类型与命名规则

| 类型 | 含义 | 密钥存储 | 对外 |
|---|---|---|---|
| `R` | 根证书 | `ROOT/序列号.crt`、`ROOT/序列号.key` | `WebPublic/CRT/序列号.crt` |
| `C` | 中间证书 | `CA/序列号.crt`、`CA/序列号.key` | `WebPublic/CRT/序列号.crt` |
| `E` | 终端证书 | `CERT/序列号.crt`、`KEY/序列号.key` | `WebPublic/CRT/序列号.crt` |
| OCSP 专用 | OCSP 签名 | `OCSP/序列号_ocsp.crt`、`_ocsp.key` | `WebPublic/CRT/序列号.crt` |
| TSA 专用 | 时间戳签名 | `TIMSTAMP/类型_哈希.crt/.key` | `WebPublic/CRT/序列号.crt` |

> 所有证书签发后同时按 `序列号.crt` 同步到 `WebPublic/CRT/`，供 `/CRT/{CID}.crt` 下载。
> CERTS.txt 中行首加 `#` 的证书（Web 面板右键「删除证书」）会被**忽略**：CRL 生成、OCSP 查询、时间戳处理均自动跳过（CertsDB 统一跳过 `#` 行）。

---

## 配置文件 CONFIG.txt

位于 `PKI/CONFIG.txt`，无文件时 WebAdmin 系统配置页会自动创建默认内容：

```ini
WEBPORT=80
OCSP=http://localhost:80/OCSP
CRL=http://localhost:80/CRL/{CID}.crl
CRT=http://localhost:80/CRT/{CID}.crt
CPS=https://gitee.com/wxgshuju/modpkica
CPS_Nonice=http://example.com/nonice
```

- `WEBPORT`：WEB 服务监听端口（默认 80）
- `OCSP` / `CRL` / `CRT`：写入证书 AIA / CRL 分发点的 URL，支持 `{CID}` 占位符（替换为证书序列号）
- `CPS`：证书策略 CPS URI
- `CPS_Nonice`：证书策略用户通告（UserNotice）文本；WEB 面板多行输入，保存时换行以 `\n` 存储，签发证书时 `\n` 还原为真实换行

---

## 登记表 CERTS.txt

位于 `PKI/CERTS.txt`，每行一条，空白分隔：

```
序列号 类型 状态 原因编号 签发/吊销时间 颁发者序列号 密钥算法
```

示例：

```
13fbe86586d1bca R V 0 2026/09/08-23:18:34 13fbe86586d1bca RSA
113521bfd E R 5 2026/09/09-00:53:25 1cdd332012fa2 RSA
```

- 类型：`R` 根 / `C` 中间 / `E` 终端
- 状态：`V` 正常 / `R` 已吊销 / `N` 未知
- 原因编号：0-9（吊销原因）
- 时间格式：`yyyy/MM/dd-HH:mm:ss`

> MAIN 在 OCSP / 时间戳处理前会重新加载 CERTS.txt，外部修改即时生效（无需重启）。

---

## 操作日志 logs.log

位于 `PKI/logs.log`，**只追加**，每条记录包含：时间、时间戳、操作、命令、结果，记录间以**两个换行**分隔。所有操作（Admin 命令、WEB 请求、CRT/CRL/OCSP/时间戳请求、签名、摘要、验签过程）都会写入。

---

## 常见问题 FAQ

**Q1：编译/运行时中文乱码？**
A：必须带 `-Dfile.encoding=UTF-8` 运行；源码编译已用 `-encoding UTF-8`。脚本注释使用英文避免 cmd 代码页问题。

**Q2：`Address already in use: bind`？**
A：WEB 端口（默认 80）被占用。先 `netstat -ano | findstr :80` 找到 PID 结束旧进程，或改 `CONFIG.txt` 的 `WEBPORT`。

**Q3：OCSP 报"未知序列号"？**
A：确认 CERTS.txt 有记录、`WebPublic/CRT/序列号.crt` 存在、`OCSP/颁发者序列号_ocsp.crt` 已生成（先运行 `initOCSP`）。

**Q4：Wosign 代码签名选 RFC3161 时间戳失败？**
A：RFC3161 时间戳用于 PDF 文档签名；微软代码签名请选 **Authenticode** 类型（`/timestamp` 或 `/timestamp/sha1`）。

**Q5：签发 ECC 证书报错？**
A：确认密钥位数按 ECC 曲线选择（256/384/521），且 BC 1.85 的 `BC185/` 完整放入项目根。

**Q6：SM2 已吊销证书 OCSP 验证报 `OCSP无法检查吊销状态 | 上报失败~`？**
A：v1.1 已修复。根因是 SM2 分支手动 ASN.1 编码 `CertStatus.revoked` 误用 EXPLICIT，RFC 6960 要求 `[1] IMPLICIT RevokedInfo`，导致 openssl / BC 解析错位（`wrong tag` / `illegal object`）。RSA / ECC 已吊销证书不受影响（走 BC 高层 API）。升级后重启 MAIN 生效。

**Q7：如何离线开发？**
A：所有依赖只有 `BC185/` 全家桶 + `lib/`（pdfbox），无 Maven 仓库；源码改完直接 `build.cmd` 编译，`out/` 即产物。

**Q8：国密 PDF 签章（35275 / 38540 / 0031）报错？**
A：三者都**必须**使用 SM2 证书，且**必须**选择签章图片（png/jpg/bmp/gif）。GB/T 38540-2020 与 GM/T 0031-2025（`GM.sm2seal`）无标准时间戳扩展，即使填了时间戳地址也不嵌入；GB/T 35275-2017（`GM.sm2cms.detached`）为 CMS 结构可正常验签（SM3withSM2 含 ZA）。若用非 SM2 证书或未选图片，面板会给出明确中文错误。

**Q9：签名时时间戳地址填了外网 TSA 但失败？**
A：离线 / 无外网环境会请求失败，但签名**不中断**——时间戳失败自动降级（日志记录原因），文件照常签名成功。连接外部 TSA 需本机可访问其 80/443 端口；留空则使用本机 MAIN 时间戳服务。

---

## 更新记录
- **v1.28-r15（2026-10-07）——统一版接入服务与多客户端兼容能力整理**
  - **RADIUS 服务统一整合**：`RadiusServer` 提供 UDP/1812 认证、UDP/1813 计费服务，共享密钥可配置，账号统一使用 `PKI/USERS.txt`；WebAdmin 支持服务启动、停止、配置保存、状态统计、认证/计费日志查看与清空。
  - **认证方式扩展**：统一 RADIUS 服务支持 PAP、CHAP、MS-CHAPv1、MS-CHAPv2，以及 EAP-MD5、EAP-GTC、EAP-MSCHAPv2、EAP-TLS、EAP-TTLS、EAP-pwd、PEAP-MD5、PEAP-MSCHAPv2、PEAP-GTC 等认证流程；客户端调试区同步提供对应认证方式的模拟拨号入口。
  - **EAP-MSCHAPv2 完整链路**：实现 EAP-Identity → MSCHAPv2 Challenge/Response → 方法层 Success → 客户端确认 → Access-Accept 的完整状态机；支持 RFC 2759 的 NT-Response 校验，并结合 RFC 3079 / RFC 2548 派生及下发 MS-MPPE-Recv-Key / MS-MPPE-Send-Key。
  - **EAP 自适应认证流程**：裸用户名进入统一 EAP-MSCHAPv2 首选流程；客户端通过 EAP-NAK 明确声明可用方法后，可根据协商结果进行兼容处理；带 `mschapv2:`、`eap-mschapv2:`、`md5:`、`eap-md5:`、`tls:`、`eap-tls:`、`ttls:`、`eap-ttls:`、`peap:`、`eap-peap:`、`peap-mschapv2:`、`eap-peap-mschapv2:`、`peap-gtc:`、`eap-peap-gtc:`、`pwd:`、`eap-pwd:`、`gtc:`、`eap-gtc:` 前缀可直接选择对应认证流程。
  - **TLS 族认证基础设施**：基于 BouncyCastle 1.85 实现 EAP-TLS、EAP-TTLS、PEAP 系列认证，支持 TLS 分片、重组、会话状态维护及可选客户端证书；客户端调试区 TLS 族支持选择证书作为信任锚/客户端凭据。
  - **RADIUS 客户端调试区完善**：WebAdmin 提供 PAP / CHAP / MS-CHAPv1 / MS-CHAPv2 / EAP-MD5 / EAP-GTC / EAP-MSCHAPv2 / EAP-TLS / EAP-TTLS / PEAP-MD5 / PEAP-MSCHAPv2 / PEAP-GTC / EAP-pwd 等方法选择，并支持 TLS 族客户端证书选择。
  - **PPPoE 服务整合**：新增/整合 PPPoE 服务管理，按 RFC 2516 模拟 Discovery 与 Session 阶段，覆盖 PADI → PADO → PADR → PADS → PPP LCP → PAP/CHAP → PADT；认证账号与 RADIUS 共用 `PKI/USERS.txt`，WebAdmin 提供服务管理、状态统计、日志及客户端完整拨号模拟。
  - **配置统一管理**：`CONFIG.txt` 统一管理 RADIUS 认证端口、计费端口、共享密钥、自动启动，以及 PPPoE Discovery/Session 端口；MAIN 启动时可根据配置自动拉起 RADIUS / PPPoE 服务。
  - **证书签发模板与 CA 路径配置**：WebAdmin 证书模板管理支持根证书/CA/终端证书类型、DN、算法、密钥长度、摘要算法、KeyUsage、EKU、路径长度、策略、有效期、DNS/IP 等参数；签发页面提供 CA 路径长度选择及统一参数回填。
  - **CT 服务管理继续统一集成**：保留 RFC 6962 CT 日志服务、CT 日志密钥管理、可信公网 CT 日志公钥库、CT 请求日志及 Merkle 树数据展示，并支持证书签发时按配置提交 SCT。
  - **WebAdmin 服务化管理继续完善**：RADIUS、PPPoE、用户管理、证书模板、CT 服务、证书库及证书查看/验证等功能统一纳入 WebAdmin，服务日志采用 WinRadius 风格列表展示并支持自动刷新。
  - **构建方式保持离线化**：项目继续采用 Java `javac` + BouncyCastle 1.85 + PDFBox 离线依赖结构，Windows 使用 `build.cmd`、Linux 使用 `build.sh`，不依赖 Maven/Gradle 在线仓库。

- **v1.28-r14（2026-10-05）——打通手机 strongSwan(IKEv2 EAP-MSCHAPv2) → Debian eap-radius 网关 → MODPKICA RADIUS 全链路认证**
  - **背景**：手机日志实证 `EAP method EAP_MSCHAPV2 succeeded, MSK established` 后网关仍回 `AUTHENTICATION_FAILED`——服务端 Access-Accept 缺 **MS-MPPE-Recv/Send-Key**（RFC 2548），eap-radius 网关（`radius_client.get_msk` / `radius_socket.decrypt_msk`）拿不到 MSK，无法校验手机 IKE_AUTH [AUTH]
  - **核心修复一（EAP-MSCHAPv2 算法对齐 strongSwan 官方源码 `eap-mschapv2.c`）**：`computeNtResponse` 的 ChallengeHash 由 **MD5(16B) 改为 SHA-1(PeerChallenge‖AuthChallenge‖UserName) 取前 8 字节、三次 DES 加密同一 8 字节块**（RFC 2759 §8.2/8.5）；两处 MS-Length 字段按 RFC 2759 §3.2 修正（v1 响应 37 字节 / v2 响应 51 字节）；`verifyMsChapV2` 失败日志挑战哈希改 SHA-1-8 十六进制；新增 `sha1()` 工具
  - **核心修复二（MSK 派生 + MS-MPPE 属性下发，RFC 3079 §3.1 + RFC 2548 §2.4.3）**：新增 `deriveMschapv2Msk(ntHash, ntResponse)`——`master=SHA1(MD4(NT-Hash)‖NT-Response‖"This is the MPPE Master Key")[0..16]`，`receiveKey=SHA1(master‖0x00×40‖magic2‖0xF2×40)[0..16]`（客户端 send / 服务器 receive）、`sendKey=SHA1(master‖0x00×40‖magic3‖0xF2×40)[0..16]`（客户端 recv / 服务器 send），64 字节 MSK=receive‖send‖0x00×32；新增 `encryptMppeKey()`（RFC 2548：`b1=MD5(Secret‖Request-Authenticator‖Salt)`、`b(i)=MD5(Secret‖c(i-1))`，明文=keyLen‖key‖补齐 16 倍数，Salt 首字节 MSB=0）与 `msMppeAttr()`（strongSwan `mppe_key_t` 布局：`Vendor-ID(311)‖Type‖Length‖Salt‖Cipher`，Length=4+N）；EAP-MSCHAPv2 认证通过后 Access-Accept 附带 **MS-MPPE-Recv-Key(type17)=magic2 派生** 与 **MS-MPPE-Send-Key(type16)=magic3 派生**（种子=该次 Access-Request 的 Request-Authenticator，RFC 2548 §2.4.3）；`buildEapResponse` 新增 10 参重载（`extraAttrs`，仅 Access-Accept 并入）
  - **独立验证（`_MppeVerifyClient.java`，RFC 2759/3079/2548 全独立实现）**：走 R1 Challenge → R2 NT-Response → Access-Accept，按 strongSwan `radius_socket.decrypt_msk` 逻辑解密 type16/17 → 重组 `recv‖send‖补零 64B` → 与客户端 GenerateMSK **逐字节完全一致**（`0d50de2a...‖aa6571cf...‖00×32`），VSA Length=36、Salt/密文结构全部符合 RFC 2548
  - **实测**：手机 strongSwan 重新拨号——`EAP_MSCHAPV2 succeeded` → IKE_AUTH [AUTH] 校验通过 → **拿到 10.10.0.x 地址，全链路认证成功**；`javac -Xlint:all` **零警告**；README 升 v1.28-r14

- **v1.28-r13（2026-10-05）——补齐独立 EAP-MSCHAPv2（IKEv2 用户名密码认证的核心链路）**
  - **背景**：方案 4 确认手机 VPN 认证链路时发现——服务端已有 `case EAP_TYPE_MSCHAPV2` 响应校验（NT-Response 验证复用 `verifyMsChapV2`），但 **Identity 分流缺 `mschapv2:` 前缀启动**，客户端 `clientDial` 缺 `EAP-MSCHAPV2` 方法名，导致"独立 EAP-MSCHAPv2"无法从调试专区发起
  - **服务端**：Identity 分流新增 `mschapv2:` / `eap-mschapv2:` 前缀 → `startEapMsChapV2` 逻辑（查用户存在/启用 → 建 `EapState{method="MSCHAPV2", challenge=16B 随机}` → 回 `EAP-Request/MSCHAPV2 Challenge`：OpCode(1)=1、MS-CHAPv2-ID、MS-Length、Value-Size=16、Value(16B 认证挑战)、Name=MODPKICA-MSCHAPV2）；`case EAP_TYPE_MSCHAPV2` 响应校验补 `"MSCHAPV2".equals(st.method)` 检查（防状态串用）
  - **客户端**：`clientDial` 新增 `EAP-MSCHAPV2` / `EAP-MSCHAP-V2` / `EAPMSCHAPV2` 分支 → `eapMsChapV2ClientDial()`（Identity 带 `mschapv2:` 前缀 → 解析 Challenge（OpCode=1，Value-Size=16）→ 随机 PeerChallenge + `computeNtResponse`（50B Value：Ident+Pad+PeerChallenge16+Reserved8+NT-Response24）→ 回 `EAP-Response/MSCHAPV2`（OpCode=2）→ Access-Accept/EAP-Success）
  - **WebAdmin**：客户端-调试专区认证方式下拉扩为 **13 项**（新增 EAP-MSCHAPv2，位于 EAP-GTC 与 EAP-TLS 之间）
  - **回归（方案 4 手机 VPN 认证链路全量确认）**：PAP / CHAP / MS-CHAPv2 / **EAP-MSCHAPv2**（新）全部 Access-Accept；EAP-TLS 匿名与带证书（25cef1995955a535fa2ab03204648f81）全部 EAP-Success；叠加 r12 已回归的 EAP-TTLS/PEAP 族——**IKEv2（EAP-MSCHAPv2 用户名密码 / EAP-TLS 证书）、Cisco XAUTH 转发（PAP/MS-CHAPv2）、L2TP PPP（PAP/CHAP/MS-CHAPv2）三条手机 VPN 认证链路全部确认支持**；`javac -Xlint:all` **零警告**；README 升 v1.28-r13

- **v1.28-r12（2026-10-05）——RADIUS 客户端调试专区：TLS 族可选证书（信任锚验证 + 客户端凭据）**
  - **RadiusServer**：`clientDial` 新增 6 参重载（`+certSerial`，旧 5 参委托传 null 保持兼容）；`AnonTlsClient` 升级为 **`TrustedTlsClient`**——可选「信任锚证书链」`notifyServerCertificate` 用 `verifyServerChain()` 逐级验签、链顶须等于某信任锚或被其签发（锚为空则保持原匿名不校验行为），可选「客户端证书/私钥」`getClientCredentials()` 用 `ModpkicaTlsSigner` + `DefaultTlsCredentialedSigner` 出示凭据（RSA→sha256+rsa，ECC→sha256+ecdsa）；新常量 `EAP_TLS_CIPHERS`（原六套件提取复用）；新增 `loadClientTlsCred(certSerial)`——按序列号查 `CertsDB`，R→`PKI/ROOT`、C→`PKI/CA`、E→`PKI/CERT`（缺失回退 `WebPublic/CRT`），组装本证书+颁发者链（C/E 追到 ROOT），私钥按 ROOT/CA/KEY 顺序探测（可缺省，仅作信任锚）；`eapTlsClientDial` / `eapTtlsClientDial` / `eapPeapClientDial` 三方法加 `certSerial` 参数，内部加载凭据后建 `TrustedTlsClient`
  - **WebAdmin**：客户端-调试专区表单在认证方式后新增「客户端证书（TLS族可选）」下拉 `#radCert`（默认「（默认·匿名）」+ `/api/certs` 全部证书记录：序列号·算法·类型）；`loadRadCerts()` 首次填充（`radCertLoaded` 标志防重复重建、保留已选值）；`radClientDial()` body 增 `cert` 字段；后端 `radiusDial` 透传至 6 参 `clientDial` 并写 MLog（含证书序列号）
  - **回归**：无证书路径（匿名）EAP-TLS/EAP-TTLS/PEAP-MD5/PEAP-MSCHAPv2/PEAP-GTC 全部 EAP-Success；带证书路径（cert=`25cef1995955a535fa2ab03204648f81`，CA RSA，链 3 级含私钥）**5 种 TLS 族方法全部通过**（服务器证书链验证成功——锚不匹配将抛 IOException 握手失败）；`javac -Xlint:all` **零警告**；README 升 v1.28-r12

- **v1.28-r11（2026-10-05）——RADIUS 认证方式扩展至 12 种：EAP-GTC / PEAP-GTC / EAP-TTLS / EAP-pwd**
  - **EAP-GTC（RFC 3748 §5.6，明文令牌）**：服务端常量 `EAP_TYPE_GTC=6`；Identity 用户名带 `gtc:` / `eap-gtc:` 前缀分流（剥前缀查真实用户 → 建立 EapState(method="GTC") → 回 `EAP-Request/GTC` 提示 "Enter Password: "）；`handleEapGtc` 用 `constantTimeEquals` 验证明文令牌；客户端 `eapGtcClientDial()`（`gtc:` 前缀 Identity → 提示 → 令牌响应），`clientDial` 路由 `EAP-GTC`/`EAPGTC`
  - **PEAP-GTC（内层 GTC）**：前缀 `peap-gtc:` / `eap-peap-gtc:`（**分流检查排在 `peap-mschapv2:` 之前**，避免被 `peap:` 吞掉）；`startEapPeap(...,innerMethod)` 内层 switch 支持 MD5 / GTC / MSCHAPV2；内层 `peapInnerGtc()`（隧道内 Identity → GTC 提示 → 令牌比对）；客户端 `eapPeapClientDial()` 增加 innerGtc 分支（两轮隧道交换与 MSCHAPV2 同构）
  - **EAP-TTLS（RFC 5281，内层 PAP AVP 交换）**：常量 `EAP_TYPE_TTLS=21`；前缀 `ttls:` / `eap-ttls:`；`startEapTtls()` 复用 EAP-TLS 凭据/会话基础设施，握手线程 `ttlsInnerPap()` 隧道内 AVP 帧交换（Type(1)+Length(1)+Value；先发 User-Name 空 AVP 请求 Type=1 Len=2，循环读直到 Type=2 明文 User-Password，RFC 5281 §8.5）；`handleEapTtls` 状态机整段同构于 handleEapPeap（仅 EAP Type=21）；客户端 `eapTtlsClientDial()`（握手复制 PEAP、隧道建后读 AVP 请求 → 回 User-Name+User-Password AVP → 回传 TLS 分片 → 收尾空响应）
  - **EAP-pwd（RFC 5931，P-256）**：常量 `EAP_TYPE_PWD=52`；前缀 `pwd:` / `eap-pwd:`；新增 `EapPwdState{pwe,scalarS,elementS,scalarP,elementP,kx,confirmC,phase,expires}` + `pwdStates` 队列 + `evictPwdStates()` 超时回收；`pwdCurve()`（secp256r1）；`eapPwdDerivePwe()`（§2.8 猎取-啄食法：HKDF-SHA256 "EAP-pwd Hunting And Pecking"，p≡3 mod 4 开根，counter 循环 255 次）；元素 SEC1 压缩点 33B / 标量 32B 编解码（1<标量<N）；`eapPwdKx()`（elementP·scalarS + elementS·scalarP 取 x 坐标）；`eapPwdConfirm()`（HMAC-SHA256(kx, S‖scalarS‖elementS‖scalarP‖elementP‖tag)，tag="client"/"server"）；`handleEapPwd` 四轮状态机：phase0 ID/Response（2B Group=6 回显）→ phase1 Commit/Request（标量 32B + 元素 33B）→ phase2 Confirm/Request（32B）→ ACC/REJ；客户端 `eapPwdClientDial()` 四轮镜像（S=Request组‖Response组=0006；Confirm 双向校验）
  - **WebAdmin**：`#radMethod` 下拉扩为 12 项——PAP / CHAP / MS-CHAPv1 / MS-CHAPv2 / EAP-MD5 / EAP-GTC / EAP-TLS / EAP-TTLS / PEAP-MD5 / PEAP-MSCHAPv2 / PEAP-GTC / EAP-pwd
  - **修复**：`handleEapPeap` 成功日志硬编码 "PEAP-MD5" → 动态 `"PEAP-" + innerMethod`（PEAP-GTC 成功正确显示）；EAP-pwd ID/Response 校验按 RFC 5931 用 2B Group 回显（修复误判 4B）
  - **全量回归**：12 种认证用测试账号 `admin666` 逐一拨号 **全部认证通过**（PAP/CHAP/MS-CHAPv1/MS-CHAPv2 直接响应；EAP-MD5/GTC 明文挑战；EAP-TLS/TTLS/PEAP 族完整 TLS 隧道；EAP-pwd 四轮密钥交换+双向 Confirm）；`javac -Xlint:all` **零警告**；README 升 v1.28-r11

- **v1.28-r10（2026-10-05）——RADIUS PEAP 扩展：内层 MS-CHAPv2（RFC 5216 + RFC 2759 / EAP-MSCHAPv2）**
  - **服务端**（`RadiusServer.java`）：认证方式下拉新增 **PEAP-MSCHAPv2**（第 8 项）；Identity 用户名带 `peap-mschapv2:` / `eap-peap-mschapv2:` 前缀自动分流至 `startEapPeap(...,"MSCHAPV2")`；`EapTlsSession` 新增 `innerMethod` 字段，`startEapPeap()` 参数化内层方法（MD5 / MSCHAPV2），握手线程按内层方法分派 `peapInnerMd5` / `peapInnerMsChapV2`
  - **内层 MS-CHAPv2 实现**（`peapInnerMsChapV2()`，RFC 5216 §3.2 隧道 + RFC 2759 / EAP-MSCHAPv2 报文）：隧道内 EAP-Request/Identity → EAP-Request/MSCHAPv2 **Challenge**（OpCode=1、MS-CHAPv2-ID、MS-Length、Value-Size=16、16B 认证挑战、Name=MODPKICA-PEAP）→ 校验 EAP-Response/MSCHAPv2（OpCode=2）的 NT-Response（`verifyMsChapV2` = MD4 口令哈希 + 3×DES 挑战哈希，RFC 2759 §8.5）；内层报文偏移：Data = OpCode[5] + MS-CHAPv2-ID[6] + MS-Length[7..8] + Value-Size[9] + Value[10..]
  - **客户端调试**（`eapPeapClientDial(...,innerMethod,...)`）：PEAP-MSCHAPv2 分支完整模拟内层 **两轮隧道交换**——Identity 响应写隧道 → `tunnelExchange()` 把 TLS 密文逐片回传服务器并拉取服务器 TLS 输出（重组 → feed 客户端 TLS → 解密读 Challenge）→ 算 NT-Response（`computeNtResponse`，50B 响应 Value：Ident+Pad+PeerChallenge16+Reserved8+NT-Response24）→ 再次回传 → 外层 EAP-Success；`/api/radius/dial` 支持 `method=PEAP-MSCHAPv2`
  - **关键修复**：内层每写一个 EAP 包必须 `pollOutput()` 取 TLS 密文经外层 EAP-PEAP 分片回传（此前缺此步导致服务器 `readEapPacket` 等不到 Identity 响应、客户端等 Challenge 死锁超时）；响应 Value 为 **50B**（非 49B，修复 `arraycopy` 越界）
  - **实测**：`admin666` 拨号 PEAP-MSCHAPv2——Start 交换 → 外层 TLS 握手 → 内层 Identity/Challenge/NT-Response 两轮隧道交换 → **EAP-Success 认证通过**；**PAP/CHAP/MS-CHAPv1/MS-CHAPv2/EAP-MD5/EAP-TLS/PEAP-MD5 七种旧认证全部回归通过**（8 种全量 PASS）；`javac -Xlint:all` **零警告**

- **v1.28-r9（2026-10-05）——RADIUS PEAP 认证（RFC 5216 外层 TLS 隧道 + 内层 EAP）**
  - **PEAP-MD5 服务端实现**（`RadiusServer.java`）：认证方式下拉新增 **PEAP-MD5**（第 7 项），Identity 用户名带 `peap:` / `eap-peap:` 前缀自动分流至 `startEapPeap()`
  - **协议流程（RFC 5216）**：服务器发 `EAP-Request/PEAP/Start`（S 位=0x10）→ 客户端确认 Start → 外层 TLS 1.2 握手（BC `TlsServerProtocol`/`TlsClientProtocol`，分片/重组/拉取复用 EAP-TLS 全套基础设施，每片一个 EAP 包）→ TLS 隧道建立后进入**内层 EAP-MD5**（RFC 3748 §5.4）：隧道内发 `EAP-Request/MD5`（16B 挑战 + 名称 MODPKICA-PEAP）→ 客户端算 `MD5(内层Id || 密码 || 挑战)` 写回 → 验证通过发外层 `EAP-Success` → Access-Accept
  - **内层实现**：`peapInnerMd5()` 经 `TlsServerProtocol` 应用数据通道交换（`readEapPacket()` 读 TLS 流中的完整 EAP 包）；`EapTlsSession` 扩展 `innerEap` 标志 + `tlsProto`/`clientTlsProto` 引用，握手线程 `accept()` 返回后继续内层认证，`ok` 反映内层结果
  - **用户名前缀剥离**：`startEapPeap` 剥掉 `peap:`/`eap-peap:` 前缀用于内层密码查询（修复 `UsersDB.find("peap:admin666")` 查不到用户导致内层失败的根因）；`handleEapPeap` 日志/记账统一显示真实用户名
  - **客户端调试**：`eapPeapClientDial()` 完整模拟 Identity(peap:前缀)→Start 交换→外层 TLS 多轮分片→内层 MD5 响应（TLS 加密输出逐片回传）→EAP-Success；`/api/radius/dial` 支持 `method=PEAP-MD5`
  - **实测**：`admin666` 拨号 PEAP-MD5——Start 交换 → ClientHello → 服务器证书 6 片拉取 → Finished → 隧道内 MD5 挑战/响应 → **EAP-Success 认证通过**；PAP/CHAP/MS-CHAPv1/MS-CHAPv2/EAP-MD5/EAP-TLS 六种旧认证全部回归通过；`javac -Xlint:all` **零警告**

- **v1.28-r8（2026-10-05）——RADIUS EAP-TLS 认证（BC 1.85 TLS 协议层，RFC 5216）**
  - **EAP-TLS 服务端完整实现**（`RadiusServer.java`，基于 BouncyCastle 1.85 `bctls-jdk18on`）：认证方式下拉新增 **EAP-TLS**（第 6 项），Identity 用户名带 `tls:` / `eap-tls:` 前缀自动分流
  - **服务端证书自动加载**：从 PKI 证书库自动挑选（CA 目录优先、回退 ROOT 目录；仅 RSA/ECC，排除 SM2/PQC），证书 + 私钥 + 链一并装入 BC TLS 凭据
  - **TLS 会话状态机**：`EapTlsSession` 会话队列 + 8 秒超时 + 并发锁；`ModpkicaTlsServer` 仅协商 TLS 1.2（RFC 5216 基于 TLS≤1.2），6 个套件（ECDHE_RSA/ECDHE_ECDSA × GCM/CBC + TLS_RSA × CBC/GCM），不强制客户端证书（RFC 5216 可选）
  - **RFC 5216 §2.1 分片**：服务端输出按 240B 分片**每片一个 EAP 包**（首片带 L|总长、未发完带 M）；客户端空 `EAP-Response/TLS`（flags=0）逐片拉取；`EapTlsSession.nextOutFrag()` 游标管理发送进度；客户端 `splitTlsFragments()` 逐片发送；接收侧 `reassemble()` 按 flags/L/M 重组
  - **RFC 3579 §2.1 属性切分**：EAP 包 >253B 拆多个 `EAP-Message` 属性（服务端 `getEapMessageConcat()` 按出现顺序拼接还原，修复此前只取第一个属性导致超长 EAP 截断）
  - **TLS 1.2 RSA 签名修复（关键）**：自建 `TlsSigner` RSA 分支补全 **PKCS#1 v1.5 填充**（EM=0x00 01 FF…FF 00 || DigestInfo 模幂），此前仅裸 RSA(DigestInfo) 导致客户端 `verifyServerKeyExchangeSignature` 报 `decrypt_error(51)`；ECDSA 分支用 HMacDSAKCalculator(SHA256) 确定性签名 + DER(r||s)（RFC 3279）
  - **客户端调试**：`eapTlsClientDial()` 完整模拟 Identity→Start→多轮分片→Success（自动处理空挑战拉取、M=1 续片、分片重组），`/api/radius/dial` 支持 `method=EAP-TLS`
  - **实测**：重启服务后用测试账号 `admin666` 拨号 EAP-TLS——Identity 收 Start → ClientHello → 服务器证书输出 6 片拉取 → ClientKeyExchange+CCS+Finished → **EAP-Success 认证通过**；独立 `TlsSelfTest` TCP 直连握手（应用数据 ping/pong 回显）确认 TLS 层完好；原有 PAP/CHAP/MS-CHAPv1/MS-CHAPv2/EAP-MD5 五种认证全部回归通过；`javac -Xlint:all` **零警告**

- **v1.28-r7（2026-10-05）——左侧菜单精简 + OCSP|TSA签发合并页 + 取消 OCSP/时间戳请求体上限**
  - **取消 OCSP / 时间戳服务端请求体大小限制**：原 `readAll()` 对全部接口统一施加 8MB 上限（`MAX_BODY_BYTES`，防内存 DoS）；新增 `readAllUnlimited(InputStream)` 无上限读取，`/OCSP`、`/ocsp`、`/timestamp`、`/timestamp/sha1`、`/rfc3161` 五个接口全部改用——请求体不再有任何大小/长度限制（超大签名内容也可接收）；CT 日志接口（`/ct/add` 与 `/ct/v1/*`）保留 8MB 上限不动。实测：9MB 随机请求体发往三个接口均正常进入解析阶段（OCSP 报 DER 长度异常、RFC3161 报序列构造失败、Authenticode 报 Base64 结尾错误，均系无效数据解析失败，**不再出现 "request body too large"**）；浏览器模拟 OCSP / RFC3161 正常请求端到端通过
  - **菜单精简**：隐藏「CRL 刷新」「OCSP 签发」「时间戳签发」「调试专区」四个菜单项——CRL 刷新入口仅保留仪表盘「刷新全部 CRL」快捷按钮；原 OCSP 签发、时间戳签发、调试专区三个页面合并为一个新菜单 **「OCSP|TSA签发」**
  - **合并页分类夹**（复用 `.sig-tabs` 样式，新增 `ocspTab(t)` 切换函数，默认显示「OCSP签发」）：四个页内 Tab——**OCSP签发**（原 initOCSP 页面：算法下拉 RSA/ECC/SM2 + 一键签发）、**TSA签发**（原 initTIMSTAMP 页面：SHA1/SHA256/SM3 下拉 + 一键签发）、**OCSP模拟请求调试**（原调试专区「模拟 OCSP 请求（RFC 6960）」：CertID 哈希九种算法 + Nonce 回显验证 + DER 长度展示）、**TSA模拟请求调试**（原「模拟时间戳请求（RFC 3161）」：九种摘要算法 + 随机数据签名 + TimeStampResp 验证）
  - **实现细节**：删除 `page-crl`、`page-timestamp`、`page-debug` 三个页面 div 与对应菜单、TITLES 条目；`page-ocsp` 重构为含分类夹的合并页，原 OCSP 签发 / 时间戳签发 / 调试专区全部表单控件（`ocAlgo`/`tsHash`/`dbgOcspSerial`/`dbgOcspHash`/`dbgTsaHash` 及各输出框）原样保留，`sendDebugOcsp()`/`sendDebugTsa()` 函数不动，功能零损失；仪表盘三个快捷按钮（刷新全部 CRL / 签发全部 OCSP / 签发全部时间戳）保留
  - **菜单排序**（用户指定）：仪表盘 → 证书库 → 签发根证书 → 签发证书 → OCSP|TSA签发 → 模板管理 → 吊销证书 → 证书验证 → 签名专区 → SCT服务管理 → Radius服务管理 → PPPoE服务管理 → 初始化环境 → 用户管理 → 系统配置 → 操作日志
  - **Radius / PPPoE 服务管理页新增「清空日志」按钮**（位于「刷新日志」旁）：后端新增 `/api/radius/clearlogs`、`/api/pppoe/clearlogs` 两个接口（RadiusServer/PPPoEServer 各加 `clearLogs()` 清空内存环形日志，`ConcurrentLinkedDeque.clear()` / `ArrayDeque.clear()`）；前端 `radiusClearLogs()`/`pppoeClearLogs()` 调用后刷新表格与统计，并用 `ctxToast` 顶部悬浮提示「日志已清空」
  - **RADIUS 服务端新增 MS-CHAPv1 认证与隧道属性解析（对齐 WinRADIUS 协议集）**：新增 **MS-CHAPv1**（RFC 2433，Vendor-Specific Microsoft Vendor-Type=24：8 字节挑战 + 49 字节响应，`verifyMsChapV1()` = MD4 NT-Password-Hash 2×DES 加密挑战比对，`hasMsChapVsa()` 自动分流 v1/v2），PPTP/拨号场景直接可用；新增**隧道属性解析**（RFC 2867/2868：Tunnel-Type / Tunnel-Medium-Type / Tunnel-Client/Server-Endpoint / Tunnel-Password 自动解析成文字记录，`logTunnelAttrs()` 认证与计费均记录，PPTP/L2TP/IPsec/GRE 等 VPN 场景可见）；客户端-调试专区下拉新增 **MS-CHAPv1** 模拟（`msChapV1ClientDial()` 构造完整 v1 请求验证）；顺手修复历史遗留 `dangling-doc-comments` 警告
  - **验证**：`javac -Xlint:all` **零警告**；内置浏览器实测——「客户端-调试专区」认证方式下拉为 PAP|CHAP|MS-CHAPv1|MS-CHAPv2|EAP-MD5 五项，五种方法用测试账号 `admin666` 逐一拨号**全部认证通过**（Access-Accept、响应 Authenticator 校验通过）；铁律遵守（未运行任何 ResetData/ResetExe 类脚本、不改监听方式、明文不加密、不加 API 鉴权、全中文 UI）

- **v1.28-r6（2026-10-05）——RADIUS 客户端-调试专区 + 自动启动 on/off 统一 + 三个协议修复**
  - **自动刷新不再覆盖编辑框（修复「3 秒后端口/共享密钥/自动开启被旧数据替换」）**：原 3 秒自动刷新定时器直接调用 `loadRadius()/loadPppoe()`，会整体回填端口、共享密钥、「MAIN 启动时自动开启」等表单控件，用户编辑中未在 3 秒内保存即被旧值覆盖；拆出自动刷新专用函数 `refreshRadiusStatus()/refreshPppoeStatus()`——**只更新状态徽章 / 统计数字 / 页面下方「服务器日志」**，绝不写任何编辑框；表单控件仅页面刷新、导航进入、启停/保存等操作后由 `loadRadius()/loadPppoe()` 回填。实测：RADIUS 认证端口 1812→9999、共享密钥改值后等 4.5 秒仍保持，PPPoE 端口 512/513→9998/9999 同样保持，日志仍按 3 秒刷新
  - **RADIUS 页面新增双分类夹「服务管理 / 客户端-调试专区」**：现有状态徽章 / 启停 / 配置 / 统计 / 服务日志迁入「服务管理」；新增「客户端-调试专区」——认证方式下拉（PAP / CHAP / MS-CHAPv2 / EAP-MD5）+ 账号 / 密码 / 密钥 / 端口 + 「发起调试」按钮，`#radDialOut` 逐步日志展示完整握手过程；后端新增 `RadiusServer.clientDial(method,username,password,secret,authPort)`（返回 ok/message/logs[]）与 API `POST /api/radius/dial`，操作写入 logs.log
  - **四种认证模拟客户端全部按 RFC 标准实现并实测通过**：
    - **PAP（RFC 2865 §5.2）**：`encodeUserPassword` 每 16B 块 XOR `MD5(secret + 前块)`，首块用 Request Authenticator；实测 Access-Accept、响应 Authenticator 校验通过
    - **CHAP（RFC 1994）**：MD5(challenge + password + id) 响应；实测 Access-Accept
    - **MS-CHAPv2（RFC 2759）**：客户端自生成 Peer Challenge + `computeNtResponse`（MD4 口令哈希 + 3×DES 挑战加密）→ MS-CHAP2-Response VSA（Vendor `0x137`，Type 25）；实测 Access-Accept
    - **EAP-MD5（RFC 3748）**：两阶段——Identity → 服务器回 Access-Challenge + EAP-Request/MD5（Type=4，Value-Size + 16B 挑战 + 名称）→ 客户端 `MD5(eapId + 密码 + 挑战)` 回 EAP-Response/MD5 → Access-Accept；全程 Message-Authenticator（HMAC-MD5）随包
    - **错误密码拒绝**：PAP 错误密码实测 Access-Reject、响应 Authenticator 校验通过
  - **协议修复（三处，均以「实践出真知」实测定位）**：
    - **MS-CHAPv2 NT-Response 第 3 次 DES 错位**：`computeNtResponse` 三次 DES 中第 3 次错误复用 `challengeHash[16..24)` 导致 `input buffer too short`，按 RFC 2759 §8.5 改为第 3 次仍用 `challengeHash[0..7]`（`i==2 ? 0 : i*8`）；修复后 Access-Accept
    - **MS-CHAPv2 VSA Vendor-Length 语义**：RFC 2548 VSA 的 Length 字段含 Vendor-Type + Vendor-Length 头（=8），数据实际长度应为 `vlen - 2`；原实现按整段截取导致挑战/响应解析错位（Data 内残留 2 字节）→ 修复后挑战响应逐字节对齐
    - **EAP-MD5 挑战包双重封装**：旧 `buildEapRequestMd5` 自带完整 EAP 头（Code/Id/Length/Type），又被 `buildEapResponse` 再套一层 EAP 头 → 属性 79 内容错乱（Type 缺失、Length 差 1）；修复为 `buildEapResponse` 新增带 `eapType` 参数的重载（旧 7 参签名委托新签名 eapType=-1），Identity 分支只传裸 Data（Value-Size + 挑战 + 名称）由统一逻辑写 Type/Length；并删除无引用的 `buildEapRequestMd5`
  - **自动启动配置统一（RADIUS 与 PPPoE 同规则）**：面板勾选「MAIN 启动时自动开启」→ 保存写 CONFIG.txt `RADIUSAUTO=on` / `PPPOEAUTO=on`，取消勾选 → 写 `off`；`startRadiusIfConfigured()` / `startPppoeIfConfigured()` 缺省统一 `"off"`（仅用户勾选后才自动拉起）；实测闭环：勾选 on → 重启 MAIN 自动启动；取消 → CONFIG 写 off → 重启后服务不自动拉起（service.log 仅打印 PPPoE 自动启动、RADIUS 无）
  - **验证**：`javac -Xlint:all` **零警告**；内置浏览器实测 PAP / CHAP / MS-CHAPv2 / EAP-MD5 四方法通过 + 错误密码拒绝通过 + on/off 配置持久化与重启行为闭环 + 3 秒自动刷新不覆盖编辑框；临时编译日志已清理；铁律遵守（未运行任何 ResetData/ResetExe 类脚本、不改监听方式、明文不加密、不加 API 鉴权、全中文 UI）

- **v1.28-r5（2026-10-05）——用户管理 + RADIUS 服务管理 + PPPoE 服务管理**
  - **用户管理（PKI/USERS.txt）**：新增 `UsersDB.java`——明文行式存储 `用户名 密码 状态 组 备注`，删除 = 行首 `#` 注释不真删；`User.enabled()` / `load(baseDir)` / `find(baseDir,user)`；WebAdmin 新增「用户管理」页面（增删改查、启用/停用）
  - **RADIUS 服务管理（RFC 2865/2866 + EAP）**：新增 `RadiusServer.java`——UDP 1812 认证 / 1813 计账双线程，PAP / CHAP / MS-CHAPv2 / EAP 认证框架，环形日志（最近 500 条）、`statusJson()`（运行状态/账户数/认证请求/通过/拒绝/启动时间）；账号与用户管理同库；WebAdmin 新增「Radius服务管理」页面（启动/停止/统计清零/刷新/自动刷新/日志实时显示）；CONFIG.txt 支持 `RADIUSPORT`、`RADIUSAUTO` 键
  - **PPPoE 服务管理（RFC 2516 + PPP）**：新增 `PPPoEServer.java`——UDP 封装模拟标准报文（Discovery `0x8863`/UDP 512，Session `0x8864`/UDP 513），Discovery 阶段完整处理 PADI(0x09)→PADO(0x07)/PADR(0x19)→PADS(0x65)/PADT(0xa7)，标签 Service-Name(0x0101)/AC-Name(0x0102)/Host-Uniq(0x0103)；Session 阶段 PPP LCP（Conf-Req/ACK/NAK/REJ/Term-Req/Ack，选项 MRU/Auth-Protocol/Magic）+ **PAP（RFC 1334）** + **CHAP（RFC 1994，MD5(id+secret+challenge)）**；认证复用用户管理同库；客户端-调试专区提供完整拨号流程模拟（PADI→PADO→PADR→PADS→LCP→PAP/CHAP→PADT），自测闭环；CONFIG.txt 支持 `PPPEO_DISC_PORT`、`PPPEO_SESS_PORT`、`PPPEOAUTO` 键
  - **关键修复（PPPoE CHAP 认证失效）**：`hasAuthProto()` 遍历 LCP 选项时误用 `p += 2 + len`——RFC 1661 选项的 Length 字段已含 Type+Length 头，选项步长应为 `p += len`；修复后 CHAP Challenge/Response/Success 全流程可用，PAP/CHAP 双认证与错误密码拒绝均实测通过
  - **关键修复（「MAIN 启动时自动开启」不生效）**：`pppoeSaveConfig` 会正常写入 `PPPOEAUTO=on` 到 CONFIG.txt，但 MAIN 启动时缺少读取并拉起 PPPoE 的代码（RADIUS 有 `startRadiusIfConfigured()`，PPPoE 没有）——每次 MAIN 重启后 PPPoE 都处于未运行，看起来像"自动关闭"；新增 `WebAdmin.startPppoeIfConfigured()`（读取 PPPOEAUTO/PPPOEDISC/PPPOESESS，缺省 off 仅用户勾选后开启，与面板共用同一实例），MAIN.java 启动时调用并打印「MOD PKI CA PPPoE服务已自动启动」；实测：面板勾选→保存（CONFIG.txt 出现 `PPPOEAUTO=on`）→重启 MAIN→PPPoE 自动运行中、复选框保持勾选，全链路通过
  - **验证**：`javac -Xlint:all` **零警告**；内置浏览器实测：PPPoE 启动/停止/状态徽章、PAP 认证成功（admin666）、CHAP 认证成功（admin666）、错误密码 CHAP 拒绝（日志「账号不存在、停用或响应不匹配」）、服务器日志实时联动全部通过
  - **铁律遵守**：未运行任何 ResetData / ResetExe 类脚本；不改监听方式（默认 127.0.0.1:8080 管理界面）、不改文件存储格式（USERS.txt 明文）、不加 API 鉴权；全中文 UI

- **v1.28-r4（2026-10-03）——证书库列表验证 SCT 原始类型标注 + CertVerify KeyUsage NPE 修复**
  - **SCT 原始类型标注（RFC 6962 §3.2）**：证书库列表「验证」弹窗与 CLI `CertVerify` 中，若证书含 SCT 列表扩展（`1.3.6.1.4.1.11129.2.4.2`），验证每条 SCT 记录时标注其签名的原始数据模式——按 RFC 6962 §3.2 先构造「预证书模式（precert_entry：`entry_type=1 + issuer_key_hash(32B) + u24(len)+去 SCT 扩展的 PreCert TBS` + `u16(extensions)`）」输入验签，失败再回退「正式证书模式（x509_entry：`entry_type=0 + 剥离 SCT 扩展后的 TBSCertificate` + `u16(extensions)`）」；`sctStatus` 返回值由 `String` 改为内部类 `SctVerifyOutcome{status, mode}`，`printSctList` 在「签名类型 / 签名」之后新增 `原始类型:  预证书模式(precert_entry) / 正式证书模式(x509_entry) / 无法判定` 行，再接原「状态:」行（冒号与「签名」保持对齐）
  - **端到端实测（两条路径均真实签发验证）**：`CTLOGapi=/ct/v1/add-pre-chain` 签发终端证书 → 3 条 SCT 全部标注「预证书模式(precert_entry)」且验签「签名有效」；`CTLOGapi=/ct/v1/add-chain` 签发 → 全部标注「正式证书模式(x509_entry)」且验签「签名有效」；冒烟测试证书与 crtRAW 提交记录已清理，`PKI/CONFIG.txt` 恢复用户原配置
  - **修复 CertVerify KeyUsage NPE**（验证 `331d3b67…` 等无 KeyUsage 扩展的证书时崩溃）：根因是 `run()` 中 `"密钥用法： " + cert.getKeyUsage() != null` 的运算符优先级错误——`+` 先于 `!=`，字符串拼接结果恒非空、恒走 `bitsToString(null)` 分支导致 `bits.length` 空指针；修复为拆出局部变量判空，并在 `bitsToString` 开头增加 `bits == null` 返回「无」的兜底
  - **回归**：全量编译零错误；单元测试 **173 passed / 0 failed**（SCT 改动后重跑确认）；MAIN 已重启加载最新 class，面板「证书验证」同样输出原始类型标注

- **v1.28-r3（2026-10-03）——CT 日志服务扩展：RFC 6962 §4 标准 HTTP API 全套（/ct/v1）**
  - **背景**：用户问「/ct/add 是不是太简洁了」，要求在不改动现有 `/ct/add`（及现有任何函数/接口）的前提下，按 RFC 6962 §4 扩展完整 CT 日志 API——**全部为独立新增 function，现有 `signSctList / pickLogKeys / buildSctInput / submitPrecert` 一行未动**
  - **新增 8 个标准接口（`/ct/v1` 前缀，MAIN.java 新 handler `handleCtV1` 统一分发，未知路径 404，校验错误 400，内部异常 500）**：
    - `POST /ct/v1/add-chain`：接收 base64(DER) 证书链（叶子+颁发者+根），**拒绝含 poison 扩展的预证书**（提示「正式证书请使用 add-chain 接口」）；逐级校验 issuer/subject 匹配 + 签名，issuerKeyHash = SHA-256(颁发者公钥 SPKI)；返回 RFC 6962 §4.1 格式 SCT（sct_version/id/timestamp/extensions/signature）
    - `POST /ct/v1/add-pre-chain`：接收预证书链，**必须含 poison 扩展且 ≥2 个证书**；issuerKeyHash 取 chain[1] 公钥 SPKI；SM2 预证书自动选 SM2 日志密钥（`resolveLogKey`：`?log_id=` 精确匹配否则第一个 usable 且类型匹配）
    - `GET /ct/v1/get-sth`：返回 tree_size / timestamp（取最后条目时间）/ sha256_root_hash / tree_head_signature（version=0 + sig_type=1 + u64 ts + 32B root，用日志密钥签名）
    - `GET /ct/v1/get-roots`：返回 CERTS.txt 中全部 R 类型根的 **DER** base64 数组（§4.7 要求 DER——修复：ROOT 目录 .crt 为 PEM，首字节检测 `-----BEGIN` 后用 `X509JsonConverter.pemToDer` 转 DER）
    - `GET /ct/v1/get-entries?start=&end=`：返回 leaf_input + extra_data（x509_entry / precert_entry 双类型），越界返回 400
    - `GET /ct/v1/get-proof-by-hash?hash=&tree_size=`：返回 leaf_index + audit_path（§3.4.1/3.4.2 审计路径）
    - `GET /ct/v1/get-sth-consistency?first=&second=`：返回两棵树一致性证明（§3.4.3）——**修复 first=0 边界 bug**：`consNode` 增加 `m==0` 短路，`first=0&second=N` 返回空数组 `[]`（Google CT 行为；原实现递归进单元素子树产生错误节点）
    - `GET /ct/v1/get-entry-and-proof?leaf_index=&tree_size=`：返回 leaf_input + extra_data + audit_path
  - **Merkle 树持久化（CtLog.java 新增）**：`PKI/CTLOG/trees/{log_id hex}.json`，JSON Lines 逐行追加 `{"leaf_input":"b64","extra_data":"b64"}`——O(1) 追加、不删除、append-only（对齐 RFC 6962）；新增 `loadTreeEntries / appendTreeEntry / mthNode / mthRoot / auditPath / consistencyProof / treeHeadSignature / signOneSct` 等方法；SCT 签发与 Merkle 树追加同一事务（`signOneSct` 复用现有 `buildSctInput` / `buildSerializedSct` / `signInput`）
  - **其他修复**：业务校验错误统一返回 **400**（此前 500，RFC 6962 §4 约定 4xx 客户端错误）；MAIN 启动信息补充 `CT日志服务 /ct/add` 与 `CT标准API /ct/v1/...` 说明；新增 `verifyChainLinks / resolveLogKey / parseB64Chain / queryParam / intParam / sendJson / jsonEscape` 等辅助函数
  - **验证（全部实测）**：`javac -Xlint:all` **零警告**；两次 `add-chain` → tree_size 1→2、SCT timestamp 与 `get-sth` 完全一致；`get-roots` 首字节 `30 82`（DER ✓）；**密码学级独立核验**——用 `get-proof-by-hash` 审计路径独立重算 Merkle 根 == `get-sth` 根（ROOT MATCH: True）、用 `first=0&second=2` 一致性证明独立重算根同样匹配（CONSISTENCY MATCH: True，且修复后 first=0 返回 `[]`、first=1 返回 1 节点）；`add-pre-chain` 传正式证书 → 400 拒绝 ✓；`get-entries` 越界 → 400 ✓；单元测试 `build.cmd 9` → **162 passed / 0 failed**；冒烟产生的测试树数据与临时文件已清理
  - **铁律遵守**：未运行任何 ResetData / ResetExe 类脚本；现有 `/ct/add` 与 `MakeCert` 的 SCT 提交流程（`CtLog.submitPrecert`）零改动；不加 API 鉴权、不改监听方式、文件明文存储

- **v1.28-r2（2026-10-02）——全项目源码自检修复（18 项）+ 登记时间真实化**
  - **自检方式**：对 `src/modpkica/` 全部 23 个源码类逐文件审查（Read + Grep），输出 18 项缺陷清单（1 高 H1 / 5 中 M1–M5 / 12 低 L1–L12），并确认无问题区段（MAIN 请求体读中限流 + 路径穿越防护、CertsDB 原子写 + 文件锁、MLog 线程安全、MakeCert 策略/SCT/颁发者校验、CtLog 选组 ≤3、X509JsonConverter 往返检测 + raw 兜底、无 Runtime.exec 等）
  - **H1 WebAdmin 写接口并发锁补全**：`WRITE_PATHS` 由 15 项补全至 21 项——新增 `/api/certs/delete`、`/api/ctlog/gen|delete|enable|pause|publicFetch`，凡改动 CERTS.txt / myCERTS.txt / CONFIG.txt / modpkica_ct_list.json / log_list.json / CRL / OCSP / TIMSTAMP / 证书私钥文件的接口统一入写锁
  - **M1 CertsDB 线程安全**：内存 `entries` 改为 `CopyOnWriteArrayList`；`revokeCert` 改为锁内**克隆替换**（读方永不看到半更新字段）；`getAll()` 返回不可变快照；`rewriteAll` 先写回 `preservedLines`（空行 + `#` 注释行）再写条目——保住「右键删除证书 = 行首 `#` 注释不真删」的既有语义
  - **M2 PemIO 私钥解析与写入健壮性**：`ENCRYPTED PRIVATE KEY` 从 PKCS#8 直通拆出，明确报错「不支持加密私钥…请先解密为标准 PKCS#8 私钥再导入」；`detectKeyType` 补全标准 PKCS#8 算法 OID 映射（RSA `1.2.840.113549.1.1.1`、RSA-PSS `…1.1.10`、SM2 曲线 `1.2.156.10197.1.301` 归 SM2 否则 ECC）——修复标准 PKCS#8 RSA 私钥被误判 ECC；`writePemObject` 改为原子写（新增 `PemIO.atomicWrite`：tmp → fsync → .bak → move，POSIX 权限 600）
  - **M3 WebAdmin 输入校验与路径规范化**：新增 `normSerial()`（去 `0x` 前缀 + 小写 + `[0-9a-fA-F]+` 白名单，非法返回 null）；`qp()` 改 URLDecoder UTF-8 解码；`certDownload` / `certExport` / `loadCertBySource` / `findCertFile` / `findKeyFile` / `rekeyAction` / `renewAction` / `myDelete` / `saveRekeyFiles` 全部先 normSerial 再拼路径（共 23 处序列号拼路径落点全覆盖）
  - **M4 MakeCert 并发写安全**：`removeCertsLine` 改 synchronized + `PemIO.atomicWrite` 原子替换，保留 `#`/空行——TSA / OCSP 重跑不再可能半截写坏 CERTS.txt
  - **M5 MAIN 多线程与资源管理**：`server.setExecutor(Executors.newFixedThreadPool(8))` 替代单线程执行器（落实「服务不能改成多线程吗」的历史诉求；CertsDB 已改 CopyOnWrite + 锁内写，可安全并发 reload / 查询）；`writeFile` 加 synchronized（OCSP / 时间戳 / CT 调试文件并发写串行化）；3 处 500 分支补 `ex.close()`（OCSP / Authenticode / RFC3161）；新增安静模式 `-Dmodpkica.quiet=true`（`log()` 静默，启动信息提示）
  - **L1/L2/L3**：WebAdmin `readAll` 读中限流（默认 8MB，multipart 256MB）；MAIN 调试文件并发写串行；500 分支连接释放
  - **L4 tailFile 中文乱码修复**：重写为「仅按块定位换行索引、整段一次性 UTF-8 解码」，删除空操作 normalizeTail——多字节中文不再按块截断
  - **L5 build 脚本示例过时修复**：`build.cmd` / `build.sh` 的 MakeCert 示例与帮助文本中已废除的 `root` 颁发者别名改为 `ROOTSERIAL` 占位符（注释注明 = CERTS.txt 中 R 类型根证书序列号，多根模型已废除 root 别名）
  - **L6/L7 CertUtil 修正**：`getSignatureAlgOid` PQC 分支由硬编码 ML-DSA-65 OID 改为按规格映射（`.17`=ML-DSA-44 / `.18`=ML-DSA-65 / `.19`=ML-DSA-87，FIPS 204）；`buildCpsPolicy` 占位 OID `1.2.3.4.1` 改为项目标准 `1.3.6.1.4.1.4146.1.95`
  - **L8 登记时间真实化（用户确认）**：`MakeRoot` / `MakeCert` 登记 CERTS.txt 的时间、`Auto` 的 `newcert` 默认时间与 `revoke` 吊销时间，由 `LocalDateTime.now().minusDays(3)` 全部改为真实时间 `now()`——`revoke` 与 `restore` 行为统一（此前 revoke 比 restore 早 3 天，属旧 Go 版对齐遗留）
  - **L9–L12**：PemIO 加密私钥提示信息明确化；WebAdmin 路径拼接前规范序列号；手写 JSON 解析新增 `readJsonString` 统一支持 `\n \r \t \b \f \/ \" \\` 与 `\uXXXX` 十六进制转义；PemIO 原子写落地
  - **验证**：`javac -Xlint:all` **零警告**；单元测试 `build.cmd 9` → **151 passed / 0 failed**（KeyUsage 无损往返、PQC 44/65/87、RSA-PSS、SHA3、DSA、EdDSA、CRL 扩展、42 个真实证书样本 DER 字节级往返、SCT、JSON 自适应最小化等 17 组）；顺带修复单测 1 处 deprecation 警告（`getKeyIdentifier()` → `getKeyIdentifierOctets()`）
  - **铁律遵守**：未运行任何 ResetData / ResetExe 类脚本；SHA1 保持可用（仅注释警告、无 alert）；不改监听方式（默认 127.0.0.1）、不改文件存储格式、不加 API 鉴权；证书过期不影响信任链（2001–2099 样本离线验证实测通过）

- **v1.28（2026-09-28）——审计修复收尾 + 签发证书策略/路径长度 + 右键删除证书（注释式）**
  - **基于 20260927 逐文件逐函数源码审计报告的修复**：完成 P1-01 / P1-03 / P1-05 三项更新（证书验证与解析的时间无关性——证书过期不影响信任关系，满足"一百年后仍可用此证书验证现在验证的数据与证书链"的离线验证要求）与 P2 系列优化（签名专区单文件上传上限按需求提升至 **20MB**、总请求体上限 **256MB**、JSON 4MB；`javac -Xlint:all` 编译警告从 396 条**清零**；build.cmd / build.sh 保留并完善 1-9 编号自动运行）
  - **签发证书页增强**：证书类型「中间CA」时新增「路径长度」可编辑下拉（默认 `null`，可选 0-9）→ 后端 `MakeCert` 新增 `a[12]=pathlen`，按 `BasicConstraints(pathLen)` 写入中间 CA 证书；证书类型「终端证书」时新增「证书策略」分区，8 个多选框（SSL `DV/IV/OV/EV`、代码签名 `标准/EV`、文档签名、TSA 对应 OID）——**仅勾选的策略才写入证书策略扩展**，基础策略 `1.3.6.1.4.1.4146.1.95`（CPS + 用户通告）始终保留；`Admin.doSignCert` 新增 14 参重载，原 12 参 CLI 入口保持兼容
  - **证书链验证提示中文化**：`CertVerify.chainConstraintsOk` 对 `parent pathLenConstraint=0 forbids issuing CA certificates` 改为中文提示「因为证书路径中有一个证书颁发机构似乎没有颁发证书的权限或不允许用作终端实体证书,所以此证书无效」
  - **证书库 CERTS.txt 右键「删除证书」**：右键菜单新增红色加粗「删除证书」项（仅 CERTS.txt 库显示）→ 二次确认「是否删除选中当前行序列号为 xxxx 的证书？」→ 确定后**不删除文件**，仅在 CERTS.txt 中为该行加 `# ` 前缀注释（保留原行内容，原子写回 tmp→fsync→.bak→move）；`CertsDB.load` 已统一跳过 `#` 开头行，故 CRL 生成、OCSP 查询、时间戳处理自动忽略被注释证书，无需改动下游代码；新增 API `/api/certs/delete`（WebAdmin API 33 个）；操作写入 logs.log
  - **验证**：全量编译 `-Xlint:all` 零警告；新增冒烟测试 `debug_test/TestCertsDelete.java` 8 项全 PASS（删除返回成功 / 行已注释 / 行不再激活 / 根、CA 行保留 / 列表不含已删除序列号 / CRL 正常生成）；单元测试 `131 passed, 0 failed`（含新增 PSS/SHA3 用例）

- **v1.27（2026-09-26）——服务安静模式 + Ed25519（EDDSA）签发修复**
  - **服务安静模式（修复 MAIN 控制台刷屏/卡死）**：MAIN（`build.cmd 1`）服务运行期间，WebAdmin 面板操作（签发时间戳 / OCSP / 证书、CRL、吊销等）不再向服务控制台打印「TSA专用证书生成成功！…」等生成信息——`MakeCert` 新增 quiet 服务模式开关（`setQuiet` / `out` 方法，生成成功信息统一写入 `PKI/logs.log`），`WebAdmin.runAction` 管理动作执行期间自动置位 / 复位 quiet；CLI 直接运行 `Admin` / `MakeCert` 仍正常打印结果；面板操作日志完整留痕 logs.log
  - **Ed25519（EDDSA）签发修复**：修复签发 Ed25519 证书报「不支持的算法: EDDSA」——根因是算法参数 `toUpperCase` 归一化为 `EDDSA` 后与分发代码大小写敏感的 `"EdDSA"` 不匹配；`MakeRoot` 算法分发 `case "EdDSA"→"EDDSA"`、`parseKeyBits` 改 `equalsIgnoreCase`；`MakeCert.generateKeyPair` 方法内统一 `toUpperCase` 归一化、`case "EDDSA"`、`defaultBit` 改 `equalsIgnoreCase`；实测 CLI 全大写 `EDDSA` 签根 / 签叶（含 SCT 流程，自动选 RSA/ECDSA CT 日志密钥）成功，`CertVerify` 根 / 叶验证通过，单元测试 163 passed / 0 failed

- **v1.26（2026-09-26）——新增 PQC（ML-DSA）签发/导入 + 我的证书库 + 证书查看器 ML-DSA 显示**
  - **我的证书（MyCerts）导入**：证书库新增选择夹「我的证书」，增加「导入证书」按钮，支持 pfx / jks / p12 / cer / crt / pem 文件；选择 .pfx/.p12/.jks 时弹密码输入悬浮窗，并**立即校验文件与密码是否匹配**，匹配后导出内部全部证书/私钥存于 `PKI/MY/序列号.crt` + `序列号.key`，并按格式登记 `PKI/MY/myCERTS.txt`（# 序列号 类型 R/C/E 是否存在私钥 Y/N 算法 RSA/ECC/SM2/PQC 生效日期 失效日期，模板 `myCERTS.txt.sm`）；每行操作含 详情 / 验证 / 删除（深红字体，删除弹「是否删除 序列号为xxxx的证书？」确认窗）
  - **PQC（ML-DSA）证书导入**：支持 PQC 目录下 PEM 证书（.crt/.cer）与私钥（.key.pem）导入，算法登记为 `PQC`；PKCS12（pfx/jks）对 ML-DSA 私钥封装存在兼容性问题时提示改用同目录 PEM 文件导入；国密 jks/pfx 样本导入兼容修复
  - **PQC（ML-DSA）证书签发**：签发证书 / 签发根证书 / 初始化环境三页新增密钥算法 `PQC`，密钥位数（下拉）可选 `ML-DSA-44 / ML-DSA-65 / ML-DSA-87`，哈希算法新增 `NULL`——选 PQC 时哈希自动锁定 NULL（不可选其他，切回 RSA/ECC/SM2 自动恢复）；CERTS.txt 算法列统一写 `PQC`；后端 `MakeRoot.java` / `MakeCert.java` 新增 PQC 分支，`CertUtil.generatePqcKeyPair` 改用 BC 1.85 标准 `MLDSAParameterSpec.fromName(...)`；实测三规格根证书签名算法 OID 分别为 `2.16.840.1.101.3.4.3.17/.18/.19`、签名长度 2420/3309/4627，自签验证通过，PQC 根签 PQC 终端证书链验证通过，PQC 根 CRL 生成成功
  - **证书查看器支持 ML-DSA（PQC）**：签名算法 OID `2.16.840.1.101.3.4.3.17/18/19` 正确显示 `ML-DSA-44 / ML-DSA-65 / ML-DSA-87`（SIG_OID_NAMES 新增三条映射）；签名哈希算法按 FIPS 204 纯签名特性显示 `内置SHAKE128（纯签名）`（44）与 `内置SHAKE256（纯签名）`（65/87），不再误显示 SHA256；公钥类型（详细信息页）对三个 SPKI 算法 OID 同样显示 ML-DSA 名称
  - **签名专区联动我的证书**：微软代码签名 / PDF 文档签名两个下拉式选择框「签名证书」自动追加 `PKI/MY/myCERTS.txt` 中含私钥的记录（不判 OID，按格式直接加入）

- **v1.25（2026-09-21）——新增 Windows 风格证书查看器 + 颁发者说明弹窗**
  - **证书查看器（cert-viewer.js，仿制 Windows 证书查看器）**：
    - **三页签**：常规 / 详细信息 / 证书路径，Windows 风格可拖拽窗口；入口 = 证书库「详情」弹窗→「查看证书」按钮、证书库行双击、证书路径页双击层级（每层打开独立新查看器，路径截断到该层）
    - **签名算法 OID 正确命名**：新增 SIG_OID_NAMES 全量映射（RSA / ECDSA / DSA / SM2 / EdDSA），OID `1.2.156.10197.1.501` 正确显示 **SM2withSM3**；签名哈希算法从算法名自动提取（SM3 / SHA1~SHA512）
    - **EKU OID↔中文用途对照**：35 项 EKU OID 两张映射表（详细信息页 + 常规页"证书的目的"Windows 文本），未收录 OID 回退显示编号；新增证书策略特殊 OID——`1.3.6.1.4.1.311.10.12.1` = 所有应用策略、`2.5.29.32.0` = 所有颁发策略
    - **公钥 HEX 字节流**：详细信息公钥字段 = 密钥类型描述 + 完整公钥 HEX（16 字节一行、字节间空格）
    - **SCT 列表完整显示**：每条 SCT 显示 日志版本 / 日志名称 / 完整日志标识符（64 字符不截断）/ 时间戳（本地）/ 签名类型（ECDSA-SHA256、SM2-SM3 等）/ 签名（hex）/ 验签状态
    - **自动状态判定**：打开后先比有效期（不在区间→琥珀色"已过期"），在有效期内异步 POST `/api/verify` 吊销检查（对齐 WebAdmin parseVerifyState：仅"已吊销/已被"判吊销，"证书吊销列表/CRL 分发点"不误判）；cacerts 入口传 `{noRevokeCheck:true}` 只判有效期不查吊销
  - **颁发者说明按钮**：打开后检测证书策略（2.5.29.32），含 CPS 链接（`cpsUri`）或用户通告（`userNotice.explicitText`）则常规页底部显示「颁发者说明(S)」按钮，点击弹出 Windows 风格小窗（CPS 外链 + 通告文本，Esc/确定关闭）；无策略自动隐藏（替换原"演示环境"占位按钮）
  - **修复**：详情弹窗点「查看证书」后 JSON 原文被"正在获取证书链..."覆盖——showDetail 保存原文、打开查看器后自动恢复
  - 新增截图：`certview.png`（证书查看器常规页）

- **v1.24（2026-09-20）——cacerts 可信公网证书库 + DN 统一标准排序 + SCT 服务管理补全**
  - **「可信公网证书库 cacerts」**：
    - 证书库页新增选择夹「证书库 CERTS.txt / 可信公网证书库 cacerts」；cacerts 列表列 = 序列号 / 算法 / 生效日期 / 失效日期 / DN字段（去掉状态/原因/悬浮窗/验证/操作按钮），时间格式 `yyyy/MM/dd HH:mm:ss`，序列号列收窄 130px 超长省略；点击「详情」从 cacerts 导出 PEM 并转 JSON 结构化弹窗（X509JsonConverter 解析），修复详情按钮事件绑定
    - 证书验证页支持**本地 cer/crt/pem 文件验证**：文件选择框位于验证按钮后，选择完毕自动开始验证（`/api/verify/file`，临时文件用后即删）
    - 可信根列表除「实验信任锚 PKI/ROOT」外，新增信任 **JAVA 环境 cacerts** 中的证书（JKS→PKCS12，密码 changeit，SPKI 字节比对；`CertVerify.inJavaCacerts`）
  - **DN 统一标准排序**：`MakeCert.java` / `MakeRoot.java` 的 `buildSubject()` 重构为全字段权重排序——标准字段按 **X.500/RFC 规范顺序（C→ST→L→STREET→PostalCode→O→OU→SERIALNUMBER→CN）**，EV 注册字段（jurisdiction 注册市/省/国 `1.3.6.1.4.1.311.60.2.1.x`、organizationIdentifier `2.5.4.97`、emailAddress `1.2.840.113549.1.9.1`）随后，自定义 OID 字段排最后保持输入顺序；签发证书 / 签发根证书 / 初始化环境三个入口统一生效；两处重复逻辑收敛为 `dnOrder()` + `addDnField()`；反射冒烟验证乱序输入输出固定规范顺序
  - **DN 辅助输入三页面（签发证书 / 签发根证书 / 初始化环境）**：主框与辅助框默认值清空，每个字段编辑框 placeholder 写中文说明 + 例子（如「通用名称（CN），如 www.test.com」）
  - **MAIN 启动横幅补充**：OCSP 行标注「（RSA/ECC/SM2，摘要自适应 SHA1/SHA256/SHA384/SHA512/SM3）」、Authenticode SHA256 行标注「（SM2/SM3 自适应）」、RFC3161 行标注「（SHA1&SHA256&SM3 自适应）」、新增「MOD PKI CA CT日志服务启动: http://localhost:<port>/ct/add（RFC 6962 / Certificate Transparency，接收 PEM 预证书+颁发者证书）」
  - **SCT 服务管理补全**：新增「可信公网CT公钥管理」选择夹（数据源 `log_list.json`，显示数据日期 + 「拉取最新数据」按钮在线更新）；密钥列表「启用 / 暂停」合并为单按钮（点击切换状态），「删除」按钮置末；密钥列表增加 `type` 字段（ECDSA/RSA/SM2，缺省 ECDSA）
  - 截图更新：`a.png`（仪表盘）/ `b.png`（证书库选择夹）/ `c.png`（签发根证书 DN 辅助输入）/ `i.png`（签发证书 EV 辅助输入）/ `j.png`（SCT 服务管理三选择夹）

- **v1.23（2026-09-19）——SCT 多算法选组修复 + 国密 SCT 枚举对齐生产生态**
  - **修复 `isSm2Precert`（SM2 证书被误判为非 SM2）**：EC 公钥 SPKI 的算法 OID 固定为 `1.2.840.10045.2.1`（id-ecPublicKey），SM2 特性在 **named curve 参数 OID**（`1.2.156.10197.1.301` = sm2p256v1）——原实现只查外层算法 OID，SM2 证书永远匹配不到 → SCT 从 RSA/ECDSA 密钥池选组。修复：解析 SPKI ECParameters（SEQUENCE 首元素 / 裸 OID）取曲线 OID 判断；实测 `1135b7249`（SM2 曲线）=true、普通 ECC=false、RSA=false；新签发 SM2 证书 `1135b731c` 的 SCT 全部来自 SM2 池（SM2 TEST6/TEST2/TEST4，SM2-SM3，≤3 组）
  - **国密 SCT 枚举对齐生产生态**：验证零信（ZoTrus）SM2 SSL Pro 生产证书 `demo3.crt` 发现其 SCT 由零信国密 CT 日志系统（sm2ct.cn，参考 RFC 6962 实现）签发，实测枚举为 **hash=7(SM3) + sig=4**——原代码 sigName 无 sig=4 映射（显示 `TYPE4-SM3`），验签也只认 (7,7) 组合
    - `sigName` 补映射：**sig=4 → SM2**（国密 CT 实现枚举，生产证书实测）+ 保留 sig=7（GB/T 38636-2020 / RFC 8998 枚举）
    - `verifySctSignature`：SM2 验签支持 **(7,4)** 与 **(7,7)** 两种组合
    - `buildSerializedSct`：自家 SM2 签发枚举由 (7,7) 改为 **(7,4)**（对齐零信 sm2ct.cn 生产生态，外部验证器可识别）
  - **demo3.crt 验证结论**：3 条 SCT 的 log_id（15f210e3…、735700ef…、78a41057…）公钥不在本地密钥库、也不在 Google 权威 log_list.json（26 条）——属零信私有国密 CT 日志，显示"未知日志，无法验证"为正常；如需验签需补充零信日志公钥
  - **WebAdmin 截图更新**：新增 `j.png`（SCT服务管理 CT日志密钥管理）、`k.png`（证书库验证弹窗 SCT 列表验签）、`stamp.png`（国密签章素材示例）

- **v1.22（2026-09-18）——新增「SCT服务管理」：RFC 6962 CT 日志服务器 + 签发证书嵌入 SCT**
  - **新增 CtLog 核心类**（`src/modpkica/CtLog.java`）：CT 日志密钥库 CRUD（ECDSA-P256 密钥写入 `PKI/CTLOG/modpkica_ct_list.json`，v3 风格结构 `operators[].logs[]`，含 `private_key` 字段）、RFC 6962 §3.1 预证书签名（`issuer_key_hash = SHA-256(颁发者 SPKI DER)` + 去 poison TBS）、SCTList TLS 编码组装、`ctlogs.txt` 追加 / 读取、PEM 证书解析
  - **MAIN 新增 `/ct/add` 路由**：仅 POST；请求体为 PEM 格式「终端预证书 + 中间证书」（按序解析 ≥2 张）；对每个 usable 密钥生成一条 SCT 并追加一行日志，返回二进制 SCTList
  - **WebAdmin 新增「SCT服务管理」页面**（14 个页面）：
    - 密钥管理分组：生成 ECDSA-P256 密钥对（写 modpkica_ct_list.json）、密钥列表（描述 / log_id / 状态 / 创建时间），每行「删除 / 启用 / 暂停」操作按钮（删除 = 从文件移除；启用 = usable；暂停 = disable）
    - 请求日志分组：只读展示 `PKI/CTLOG/ctlogs.txt` 全部行（自带序号），格式 `SCT待签名数据取数据摘要||签名时的时间戳||终端证书使用者密钥标识符||终端证书授权密钥标识符||日志公钥的ID`
  - **MakeCert 改造**：移除自创扩展 OID `1.3.6.1.4.1.11129.2.4.5`；签发非 CA 证书且 EKU 含服务器/客户端认证时，改为「签发含 poison 的 SCT 预证书 → POST 自身 /ct/add → 取回 SCTList 嵌入 SCT 扩展 → 二次签名生成最终证书」，证书包含标准 SCT 列表（OID `1.3.6.1.4.1.11129.2.4.2`，双重 OCTET STRING + TLS 编码）
  - **冒烟测试（全部通过）**：MAIN 后台启动 → `/api/ctlog/gen` 生成密钥成功（log_id base64 = SHA-256(SPKI)）→ `MakeCert` 签发 `1135b42cc.crt`（颁发者 `1cdd332014ecd`）走真实 HTTP `/ct/add` → ctlogs.txt 正确追加一行 → 证书含 1 条 SCT（ECDSA-SHA256，DER 签名）→ 用本地 modpkica_ct_list.json 作为日志公钥源，CertVerify SCT 验签 **通过（precert_entry）**；demo1 / demo2 官方日志验签回归 2/2 通过不受影响
  - **修复**：`loadKeys` 段解析原从 log_id 后截取导致 `description`（在 log_id 之前）丢失，改按本条 log 对象整体截取后逐字段提取；修复 WebAdmin 文本块常量池溢出（PAGE_* 拆 4 段，每段 ≤65535 字节）与 P2/P3 文本块边界（P2 结束引号被 P3 定义吞掉）问题

- **v1.21（2026-09-18）——证书验证新增 SCT 列表签名验证（RFC 6962 / Certificate Transparency）**
  - **功能**：Web 面板「证书验证」在原有 OCSP / CRL / 证书签名 / 证书链验证基础上，新增对证书 SCT 扩展（OID `1.3.6.1.4.1.11129.2.4.2`）中**每一组 SCT 的日志签名验证**——不再只是解析展示
  - **日志公钥数据**：读取项目根目录 `log_list.json`（Google 官方 CT 日志公钥数据集 v3，权威远程地址 `https://www.gstatic.com/ct/log_list/v3/log_list.json`，已离线下载到项目根；也支持 `PKI/log_list.json`、`PKI/WebPublic/log_list.json` 备选位置）。按 `log_id` 匹配日志描述与 `key`（base64 SPKI DER），日志缺失时明确提示"log_list.json 中无此日志"
  - **验证流程**：解析 SCT 扩展（双重 OCTET STRING 解壳 → SCTList）→ 逐条 SCT 提取版本 / log_id(32B) / 时间戳 / extensions / hashAlg / sigAlg / signature → 按 RFC 6962 §3.2 构造签名输入：`version + signature_type(0) + timestamp(8B) + entry_type(2B) + signed_entry + extensions(2B+数据)`
    - **precert_entry**（Web PKI 绝大多数场景）：`issuer_key_hash(32B) = SHA-256(颁发者 SPKI DER)` + **TBS DER**——RFC 6962 §3.1 规定 `tbs_certificate` 为**最终证书 TBS 删除 SCT 扩展**（不含 poison 扩展），TBS 重建采用 BC 解析逐扩展剔除 SCT、其余原样保真重编码
    - 失败时回退 **x509_entry**：`完整证书 DER`
  - **算法支持**：ECDSA-SHA256（DER 签名 + TLS 裸 r‖s 兼容）、RSA（SHA1/256/384/512），SM2/SM3（RFC 8998 枚举）预留
  - **输出**：逐条显示 `通过/失败 | 日志=描述 | 算法=ECDSA-SHA256 | 时间戳=...（precert_entry）`，末尾汇总"通过 N 条，失败 M 条"；结果打印 stdout，经现有链路自动联动 Web 面板验证弹窗展示
  - **冒烟测试**（项目根样本）：
    - `demo1.crt`（Google Trust Services WE2 签发 `*.gstatic.com`，2 条 SCT）：Google 'Xenon2027h1' 通过、Sectigo 'Tiger2027h1' 通过（precert_entry）✓
    - `demo2.crt`（DigiCert 签发 `www.boc.cn`，3 条 SCT）：Google 'Argon2027h1'、DigiCert 'Wyvern2027h1'、DigiCert 'sphinx2027h1' 全部通过（precert_entry）✓
  - **排查要点（供维护参考）**：SCT 验签曾全部失败，最终确认两个根因——① 错误地在 TBS 重建时补回 poison 扩展（RFC 6962 §3.1 明确 `tbs_certificate` **不含 poison**）；② ECDSA 签名曾按裸 r‖s 转换，而实际日志签名为 **DER 编码**（先直接验 DER，失败再回退裸格式）。修复后 5 条 SCT 全部通过


- **v1.20（2026-09-17）——WebAdmin 改为多线程执行器 + 写操作串行锁**
  - **多线程响应**：`HttpServer` 执行器由单线程改为 8 线程固定线程池（`wa-worker` 守护线程）——读接口（status / certs / config / logs / chain / verify 等）并发响应，单个慢请求（如大日志）不再阻塞其他请求
  - **写操作串行锁**：所有修改 PKI 数据的 API（config 保存、init、makeroot、signcert、revoke、restore、rekey、renew、crl、initocsp、inittimestamp、sign/exe、sign/pdf）统一走 `WRITE_LOCK` 全局锁串行执行，避免并发写证书 / 私钥 / CRL / CONFIG 造成文件竞争
  - **日志线程安全**：`MLog.write` 加静态 `synchronized`，多线程下 logs.log 追加不会交错损坏
  - **缓存加大**：`countLogLines` 缓存 10 秒 → **30 秒**、读缓冲 64KB → **256KB**（日志行数显示秒级精度无意义，30 秒缓存几乎不读文件）
  - **实测**：8 个并发请求（status×3 + config×2 + certs×2 + logs×1）全部 200；稳定延迟 status 3–8ms、certs 4ms；浏览器页面正常、console 无错误

- **v1.19（2026-09-17）——管理界面端口写入 CONFIG.txt（SUPORT）+ 修复大日志导致服务卡死**
  - **管理界面端口配置化**：WebAdmin 管理界面端口写入 `PKI/CONFIG.txt` 的 `SUPORT` 键（默认 `8080`，键名大小写不敏感）
    - 启动时自动确保：CONFIG.txt 不存在 → 按默认模板创建（含 `SUPORT=8080`）；文件存在但无 SUPORT 项 → 自动追加 `SUPORT=8080`
    - **启动时以配置文件为准**：修改 `SUPORT` 后重启 WebAdmin 即监听新端口（端口优先级：系统属性 `modpkica.admin.port` → CONFIG.txt SUPORT → 默认 8080）
    - 系统配置页（系统设置）新增「SUPORT 管理界面端口」输入框，可读取 / 修改 / 保存，页面提示"修改保存后需重启 WebAdmin 生效"
    - 实测：保存 `SUPORT=8081` 后重启 → 监听 8081，/api/config 返回 suport=8081；改回 8080 重启恢复正常
  - **修复：日志量大时 WebAdmin 全部请求超时（服务卡死）**
    - 现象：日志积累到 2 万+ 行后，/api/status、/api/config 等所有接口超时
    - 根因：`countLogLines()` 用单字节 `InputStream.read()` 逐字节扫描整个 logs.log（200 万+ 次系统调用），而 HttpServer 是单线程执行器——仪表盘 3 秒一次的 `/api/status` 把唯一线程长期占住，后续请求全部排队超时
    - 修复：改为 64KB 缓冲批量读 + 10 秒缓存（`lastLogCountTime/cachedLogLines`），日志行数不再每次全文件扫描；`tailFile`（尾部 N 行）本就是高效随机访问实现，保持不变
    - 实测：21744 行日志下三个接口全部 200 快速响应
  - 截图与使用方式不变

- **v1.18（2026-09-16）——修复 WebAdmin 独立启动时 MAIN 状态误判**
  - **问题**：`java modpkica.WebAdmin` 独立启动时，仪表盘 MAIN 状态显示矛盾——"MAIN: 未运行" 与 "● 运行中" 并存，且 MAIN 明明在运行却显示未运行
  - **根因**：`mainPort` 静态字段初始值为字符串 `"未运行"`，`WebAdmin.start()` 原判定 `!isEmpty()` 把该占位串当作合法端口，导致 `mainRunning` 被误置为 true；且独立启动进程不持有 MAIN 的端口信息，状态永不刷新
  - **修复**：①`WebAdmin.main()` 独立启动时探测本机 MAIN——读取 `CONFIG.txt` 的 `WEBPORT`（默认 80），TCP 连接成功则 `mainPort=实际端口`、`mainRunning=true`，否则 `未运行/false`；②`start()` 判定改为仅接受**数字端口**（`matches("\\d+")`），MAIN 内嵌启动传 "80" 正常、占位串不再误判；③`statusJson()` 每次被调用时按需重探测（3 秒缓存 `probeMainIfStale`），MAIN 启停后刷新页面/点刷新即可反映最新状态
  - **实测**：MAIN 运行中（监听 80）→ 独立 WebAdmin 仪表盘显示 `MAIN: 80` + `● 运行中` ✓；console 无错误

- **v1.17（2026-09-16）——微软代码签名也改为批量 + 拖拽布局（与 PDF 一致）**
  - **微软代码签名页签改为与 PDF 相同的拖拽批量布局**：虚线拖拽区（ondragover/ondrop）+「选择文件」多选按钮（`multiple`，accept exe/dll/sys/cab/cat/msi）；待签名列表逐行显示文件名 / 大小 / 状态（待处理 / 签名中 / 成功 / 失败），行内单独签名 / 验证 / 移除，成功后行内下载链接；顶部「批量签名」「批量验证」「清空」串行处理全部并汇总（成功 N / 失败 M + 逐条错误）；按文件名 + 大小去重、非 PE 扩展名自动过滤
  - 参数区保留：签名证书（代码签名 EKU 下拉）、时间戳类型（RFC3161 / Authenticode）、时间戳请求地址（留空 = 本机 MAIN / 外部 TSA 可编辑下拉）
  - 请求参数与后端一致（`/api/sign/exe`：serial/tsType/tsUrl/file/name；`/api/verify/exe`：file），实测 `notepad.exe`（RSA SHA256）签名返回 200 且附加 RFC3161 时间戳（3229B）
  - 移除旧单文件版 `signDo/verifyDo/signExeDo/verifyExeDo`（死代码）；JS 队列复用 `fmtSize/esc` 等工具函数
  - 截图更新：`f.png` 替换为微软代码签名批量布局（拖拽区 + 2 文件待签名列表）

- **v1.16（2026-09-16）——签名专区选择夹布局 + PDF 批量拖拽签名**
  - **签名专区改造为选择夹（tab）形式**：「微软代码签名」与「PDF 文档签名」两个页签各占整页，空间更大；全局字体 14px → 15px，输出区、列表、按钮同步放大
  - **PDF 文档签名支持批量与拖拽**：虚线拖拽区（ondragover/ondrop）+ 「选择 PDF 文件」多选按钮（`multiple`）；待签名列表逐行显示文件名 / 大小 / 状态（待处理 / 签名中 / 成功 / 失败），行内可单独签名 / 验证 / 移除，成功后行内显示下载链接；顶部「批量签名」「批量验证」串行处理全部文件并汇总（成功 N 个 / 失败 M 个 + 逐条错误）；按文件名 + 大小去重，非 PDF 自动过滤
  - 修复 Java text block 内 JS 正则转义（`\.` → `\\.`）与 `\n` 字面量（`'\n'` → `'\\n'`），消除编译错误与运行时 JS SyntaxError；签名 API（`/api/sign/pdf`、`/api/verify/pdf`）参数格式不变（serial/sealType/tsUrl/image/file/name）
  - 截图更新：`f.png` 替换为选择夹 + PDF 拖拽区新布局

- **v1.15（2026-09-16）——国密 GM/T 0031-2025 修正为与 GB/T 38540-2020 一致的数据结构**
  - **问题**：v1.14 按 GM/T 0031-2014 的两层结构（`SES_Signature{toSign, signature}` + `SESeal{esealInfo, signInfo}` + `header.version=11`）实现，权威工具识别为 **"SESv11"（GM/T 0031-2014）**，不是 0031-2025
  - **依据**：国家密码管理局第 54 号公告（2026-01-05）发布 GM/T 0031-2025《安全电子签章密码技术规范》，**2026-07-01 实施并废止 2014 版**；标准牵头单位（北京数字认证）官方解读明确：**"本次标准充分考虑与 GB/T 38540-2020 标准的兼容性和延续性，在保证数据结构一致的前提下有所扩展"**——即 0031-2025 的电子印章/电子签章数据结构与 GB/T 38540-2020 一致（4 字段 SESeal、TBS_Sign 5 字段、SES_Signature 4-5 字段、header.version=4）
  - **修正**：`signPdfGm` 中 0031 分支直接复用 **GB/T 38540 数据结构**（`buildGmSealInfo38540` + `buildGm38540Signature`），SubFilter 仍为 `GM.sm2seal`、签名理由显示"GM/T 0031-2025 国密电子签章"；删除 2014 两层结构的 `buildGm0031Signature`/`buildGm0031TimeInfo`/`buildGmSealInfo0031`；**时间戳与 LTV 沿用 38540 方案**（timeStamp[0] BIT STRING 绑定签名值 + DSS 同保存）
  - **验证端兼容**：`verifyGmSeal38540` 保留对旧版 0031（2014 两层结构）的解析（字段数=2 分支），新结构（4-5 字段）走 38540 分支，两种样本都能验证
  - **实测（113548382 SM2 文档签名证书，本机 MAIN /rfc3161）**：TBS_Sign 5 字段、version=4（权威工具应识别为 SESv4/2025 版而非 SESv11）；`SM2 签名验证: 通过 ✓`；`印章签名验证: 通过 ✓`；`签名时间戳(timeStamp 字段): TSA=… 绑定签名值(SM3): 通过 ✓ TSA 证书验签: 通过 ✓`；`LTV: 已启用（DSS 3/3/2）`；最终结论：国密 PDF 电子签章有效 ✓
  - 演示产物：`MODPKICA_v115_GM0031_2025结构_时间戳_LTV.pdf`（桌面，供权威工具复核）

- **v1.14（2026-09-16）——国密 GM/T 0031（2014 两层结构版本，被 v1.15 取代）**
  - **标准依据**：GM/T 0031-2014《安全电子签章密码技术规范》（官方全文已下载核实；GM/T 0031-2025 已于 2026-07-01 实施并废止 2014 版，2025 版全文未公开，按其前身 2014 版可查证的 ASN.1 结构实现）
  - **结构核对结论（vs 2014 版标准，逐项）**：
    - `SES_Signature ::= SEQUENCE{ toSign TBS_Sign, signature BIT STRING }`（2 字段）✓
    - `TBS_Sign` 7 字段：`version/eseal/timeInfo/dataHash/propertyInfo/cert/signatureAlgorithm` ✓
    - `timeInfo ::= BIT STRING`——标准原文"可以是时间戳，也可以是 UTCTIME 时间"→ **支持嵌入时间戳** ✓（已实现）
    - `SESeal ::= SEQUENCE{ esealInfo SES_SealInfo, signInfo SES_SignInfo }` ✓
    - `SES_SealInfo.property` = 6 字段（type/name/certList/createDate/validStart/validEnd，**UTCTIME**）✓
    - `SES_SignInfo.signData` = 制章人对 **SEQUENCE{ 印章信息, 制章人证书, 签名算法标识 }** 的签名（非仅印章信息）✓
    - `extDatas` 为 **EXPLICIT [0]**（A0 包 SEQUENCE）——**本次修正**（原为无标签 SEQUENCE）
  - **本次变更**：
    1. `buildGmSealInfo0031`：extDatas 改为 `DERTaggedObject(true, 0, …)`（标准 EXPLICIT [0]）
    2. `buildGm0031TimeInfo`：timeInfo 支持时间戳——`tsUrl` 非空时 BIT STRING 内容 = **完整 TimeStampToken DER**；因 timeInfo 是被签名 TBS_Sign 的组成部分、先于签名值存在，时间戳 **messageImprint = 原文 SM3 杂凑（dataHash）**（避免循环依赖，等价证明原文在 TSA 时间已存在）；失败降级 UTCTime 不阻断
    3. **LTV**：0031 也装 DSS（DSS 是 PDF 层标准 ISO 32000，与签名格式无关），同一次保存（签名后零增量）
    4. `verifyGmSeal38540` 0031 分支：新增**印章签名自检**（按 SEQUENCE{印章信息,证书,算法标识} 验签）+ **timeInfo 时间戳解析**（TimeStampToken 优先、UTCTime 回退；绑定原文杂凑 + TSA 验签）
  - **实测（113548382 SM2 文档签名证书，本机 MAIN /rfc3161）**：TBS_Sign 7 字段；`SM2 签名验证: 通过 ✓`；`印章签名验证(制章者…): 通过 ✓`；`签章时间信息(timeInfo): TSA=… 时间=2026-09-16 23:02:09 算法=1.2.156.10197.1.401(SM3)`；`绑定原文杂凑(SM3): 通过 ✓ TSA 证书验签: 通过 ✓`；`LTV: 已启用（DSS Certs=3/OCSPs=3/CRLs=2）`；最终结论：国密 PDF 电子签章有效 ✓
  - 演示产物：`MODPKICA_v114_GM0031_时间戳_LTV.pdf`（桌面，供权威工具复核）
  - **答复用户问题**：①样本符合标准（已按 2014 版权威结构逐项核对并修正 extDatas EXPLICIT 标签）；②**支持嵌入时间戳**（timeInfo 字段，标准明文允许）；③**支持 LTV**（DSS 字典，PDF 层标准）

- **v1.13（2026-09-16）——修正 GB/T 38540 timeStamp 字段编码为标准 `[0] BIT STRING` + 印章签名自检**
  - **问题**：v1.12 把 timeStamp 编码成 universal OCTET STRING（tag 0x04），而标准 7.1.1 定义为 **`timeStamp[0] BIT STRING OPTIONAL`**（对签名值的时间戳，GB/T 20520 = RFC3161，DER 编码存放；ASN.1 无模块级 TAGS 声明时默认 EXPLICIT 标签）——权威验章工具按 `[0]` 上下文标签找时间戳，认不出 0x04 → 不显示时间戳（显示本地时间），并把异常字段计入解析导致印章验证报错
  - **修正**：`buildGm38540Signature` 时间戳改为 **EXPLICIT [0]（A0）包 BIT STRING**（`new DERTaggedObject(true, 0, new DERBitString(tok))`）；SES_Signature 第 5 字段实测 tag=`DLTaggedObject tag=0x0` ✓
  - **印章签名自检**：`verifyGmSeal38540` 新增按 GB/T 38540 6.1.5 验证 SESeal.signedValue（制章者对 eSealInfo SEQUENCE 的 SM3withSM2 签名，用 SESeal.cert 公钥）——本机实测印章签名验证**通过 ✓**，证明印章签名本身正确，权威工具之前报"印章签名错误"系 timeStamp 字段类型错误引发的连锁解析异常
  - **时间戳解析兼容**：支持 EXPLICIT [0]（A0 包 03/04）、IMPLICIT [0]（80/81）、universal BIT STRING（03）、旧 OCTET STRING（04）四种编码；绑定签名值（SM3）+ TSA 证书验签
  - **实测（113548382 SM2 文档签名证书，本机 MAIN）**：SES_Signature 5 字段；`印章签名验证(制章者 …): 通过 ✓`；`签名时间戳(timeStamp 字段): TSA=… 算法=1.2.156.10197.1.401 绑定签名值(SM3): 通过 ✓ TSA 证书验签: 通过 ✓`；`LTV: 已启用（DSS Certs=3/OCSPs=3/CRLs=2）`；最终结论：国密 PDF 电子签章有效 ✓
  - 演示产物：`MODPKICA_v113_GM38540_时间戳_标准timeStamp.pdf`（桌面，供权威工具复核）

- **v1.12（2026-09-16）——国密 GB/T 38540-2020 支持嵌入时间戳与 LTV**
  - **标准依据**：GB/T 38540-2020 **7.1.6 时间戳**明确定义——SES_Signature 可选第 5 字段 `timeStamp`（对签名值的时间戳，符合 GB/T 20520 规定 = RFC3161，时间戳格式按 DER 编码存放；验证流程 h) 要求验证时间戳有效性，比对时间戳时间与签章时间）；参考实现（PDF国密GBT 38540-2020（4））只做了 4 字段、未实现该字段，本次按标准补齐
  - **时间戳**：`buildGm38540Signature` 生成 SES_Signature 后取 SM2 签名值 → **SM3 摘要** → RFC3161（SM3）时间戳请求 → token DER 作为第 5 字段 `timeStamp`（OCTET STRING）加入；失败降级无时间戳（日志）
  - **LTV**：DSS 是 PDF 层标准（ISO 32000 DSS 字典），与签名格式无关——`signPdfGm` 的 38540 分支同样 `collectLtvData` + `installDss` 同保存（被签名覆盖，签名后零增量）；GM/T 0031 保持不装（结构无对应约定）
  - **verifyGmSeal38540**：接受 4/5 字段结构；时间戳解析（TSA/时间/算法/**绑定签名值（SM3）**/TSA 证书验签），时间戳无效则最终结论为无效
  - **实测（113548382 SM2 文档签名证书，本机 MAIN）**：SubFilter=`GM.sm2seal`，SES_Signature 5 字段；`签名时间戳(timeStamp 字段): TSA=… 时间=2026-09-16 22:24:50 算法=1.2.156.10197.1.401 绑定签名值(SM3)=通过 TSA 证书验签=通过`；`LTV: 已启用（DSS Certs=3/OCSPs=3/CRLs=2）`；dataHash 比对 + SM2 验签 + 时间戳全部通过
  - 演示产物：`MODPKICA_v112_GM38540_时间戳_LTV.pdf`（桌面）

- **v1.11（2026-09-16）——国密 GB/T 35275-2017 支持嵌入签名时间戳（SM3）与 LTV**
  - **标准依据**：GB/T 35275-2017 是基于 CMS（SM2 密码算法加密签名消息语法）的国密实现，SignerInfo 的 **unsignedAttrs 为通用结构**——CAdES-T 签名时间戳（`id-aa-timeStampToken`）可正常承载；DSS/LTV 是 PDF 层标准（ISO 32000 DSS 字典），与签名算法无关，任意 SubFilter 均可用
  - **时间戳**：`buildGm35275Signature` 生成 CMS 后取 SM2 签名值 → **SM3 摘要**（SM2/SM3 证书固定 SM3）→ RFC3161 时间戳请求（`requestTimestamp` 新增摘要算法参数，SM3 OID `1.2.156.10197.1.401`）→ token 写入 unsignedAttrs → `replaceUnsignedAttributes` + `replaceSigners` 重建；失败降级无时间戳签名（日志）
  - **LTV**：`signPdfGm` 的 35275 分支在保存前 `collectLtvData`（SM2 证书链 OCSP + CRL）+ `installDss`，与签名同一次保存（被签名覆盖，签名后零增量）；38540/0031 的 SES_Signature 无标准 LTV 扩展，不装 DSS
  - **verifyPdf**：时间戳绑定校验按 token 哈希算法**自适应**（新增 `boundToSignature`：SHA-256/SHA-224/SHA-384/SHA-512/SM3），SM3 时间戳正确显示"绑定签名值=true"
  - **实测（113548382 SM2 文档签名证书，链 SM2CA→ROOTCA，本机 MAIN）**：SubFilter=`GM.sm2cms.detached`；`签名时间戳(CAdES-T unsignedAttrs): TSA=… 时间=2026-09-16 22:11:31 算法=1.2.156.10197.1.401 绑定签名值=true`；`LTV: 已启用（DSS Certs=3/OCSPs=3/CRLs=2）`；CMS 验签 + SM3 摘要比对 + 证书链全部通过
  - 演示产物：`MODPKICA_v111_GM35275_时间戳_LTV.pdf`（桌面）

- **v1.10（2026-09-16）——PDF Adobe 签名时间戳位置修正：按权威工具样本对齐 CAdES-T（unsignedAttrs）**
  - **背景**：v1.9 把时间戳放 signedAttrs（PAdES-BES 属性方式），用户权威验证工具判"签名不包含嵌入的时间戳"
  - **样本逆向**：解析用户提供的权威工具签名样本 `签名嵌入时间戳无LTV.pdf`（Wosign 类工具，TSA 恰为本机 MODPKICA SHA256 时间戳证书）——其 SignerInfo **无 signedAttrs**，时间戳 token 位于 **unsignedAttrs** 的 `id-aa-timeStampToken`（1.2.840.113549.1.9.16.2.14），且 **messageImprint = SHA-256(签名值)**（非待签数据摘要）——这正是 **CAdES-T / PAdES-T 签名时间戳**的标准位置（ETSI TS 101 733）
  - **重构 `buildCms`**：时间戳不再进 signedAttrs——先生成 CMS（BC 默认 signedAttrs：contentType/messageDigest/signingTime），取 SignerInfo 签名值 → SHA-256 摘要 → 请求 RFC3161 → token 放入 unsignedAttrs 属性 → `SignerInformation.replaceUnsignedAttributes`（BC 静态 API）+ `CMSSignedData.replaceSigners` 重建 CMS；时间戳失败仍降级无时间戳签名（日志）
  - **verifyPdf 同步**：签名时间戳解析改查 **unsignedAttrs**，输出 TSA/时间/算法/`绑定签名值=true|false`（imprint 对签名值比对）
  - **实测（113548234 RSA 文档签名证书，链 EVCA→ROOTCA，本机 MAIN）**：`签名时间戳(CAdES-T unsignedAttrs): TSA=… 时间=2026-09-16 21:30:36 算法=SHA-256 绑定签名值=true`；独立探针确认 unsignedAttrs 含 id-aa-timeStampToken、**imprint==SHA-256(签名值)=true**（与权威工具样本同构）；DSS Certs=3/OCSPs=3/CRLs=2 保留；CMS 验签 + 摘要比对 + 证书链全部通过
  - **纯文档时间戳（无签名证书）补上 LTV**：修复 `extractTsaChain` 的 BC 泛型编译错误（`Store.getMatches` 擦除问题，此前 addDocTimeStamp 的 LTV 逻辑从未编译进 out，纯 DocTimeStamp 一直无 DSS）——现探测请求取 TSA 证书链 → `collectLtvData`（链上证书 OCSP 响应 + 根 CRL）→ `installDss` 与时间戳同一次保存（被 DocTimeStamp 覆盖，签名后零增量）；实测 `LTV: 已启用（DSS Certs=2/OCSPs=2/CRLs=1）`，messageImprint 比对通过、TSA 验签通过
  - 演示产物：`MODPKICA_v110_签名内嵌时间戳_CAdES-T.pdf` 与 `MODPKICA_v110_纯文档时间戳_LTV.pdf`（桌面，可用权威工具复核）

- **v1.9（2026-09-16）——PDF Adobe 标准签名时间戳策略重构：签名内嵌时间戳，独立 DocTimeStamp 仅用于无证书纯时间戳**
  - **时间戳与签名不分离（用户明确要求）**：选中数字证书签名时，不再叠加独立 DocTimeStamp 签名字段——时间戳按 PAdES-BES 标准**嵌入数字签名内部**（signedAttrs 的 `id-aa-timeStampToken`，1.2.840.113549.1.9.16.2.14 属性），**文档只有一个签名字段（adbe.pkcs7.detached）**
  - **纯文档时间戳（无签名证书）**：PDF 签名区证书下拉新增"（不签名，仅文档时间戳）"选项——不选证书时调用 `SignTool.signPdfTimestampOnly`，生成独立 DocTimeStamp 签名字段（Filter=Adobe.PPKLite、SubFilter=`ETSI.RFC3161`、Contents=RFC3161 TimeStampToken）；此时不可附加签章图片、不可选国密签章
  - **LTV 同保存（签名后零增量）**：DSS（Certs 证书链 / OCSPs / CRLs）与数字签名**同一次保存**，全部落在签名 ByteRange 覆盖区内——数字签名是文档最后一次修改，无"签名区外内容增加"告警；因数字签名 ByteRange 无法在保存前预知（PDFBox 增量保存会改写 trailer `/ID[1]`，MD5 含时间），**省略 VRI 索引字典**（PAdES 允许），验证器按证书/响应内容匹配 DSS 数据
  - **verifyPdf 新增"签名时间戳"解析**：主签名 CMS 的 signedAttrs 中若含 `id-aa-timeStampToken`，输出 TSA 名称 / 时间戳时间 / 摘要算法（TimeStampToken 专用解析）
  - **实测（1135228a2 RSA，链 EVCA→ROOTCA，本机 MAIN，双场景）**：
    - 选中证书：签名字段=1（adbe.pkcs7.detached）；`签名时间戳(id-aa-timeStampToken): TSA=… 时间=2026-09-16 20:54:07 算法=SHA256`；DSS Certs=3/OCSPs=3/CRLs=2/无 VRI；CMS 验签 + 证书链通过，最终"PDF 签名有效"
    - 纯时间戳：签名字段=1（ETSI.RFC3161）；messageImprint 比对通过、TSA 证书验签通过，最终"PDF 文档时间戳有效（未附加数字签名）"
  - WebAdmin PDF 签名区逻辑：`serial` 空 → 纯文档时间戳（signPdfTimestampOnly）；`serial` 非空 → signPdf（内嵌时间戳属性）；前端同步校验（纯时间戳禁签章图片/禁国密）

- **v1.8（2026-09-16）——PDF Adobe 标准签名 PAdES 重构：DocTimeStamp 文档时间戳 + LTV 同保存，签名后零增量**
  - **文档时间戳（DocTimeStamp）**：Adobe 标准签名现在**先盖文档时间戳**——独立签名字段，Filter=Adobe.PPKLite、SubFilter=`ETSI.RFC3161`、Contents=RFC 3161 TimeStampToken（覆盖整个文档）。Acrobat 据此显示"签名时间来自 TSA"而非本地时间（修复"签名时间来自本地、不含时间戳"）。时间戳地址留空（= 本机 MAIN）或指定外部 TSA 均可；请求失败自动降级（跳过时间戳继续签名，原因写 logs.log）
  - **顺序重构（修复"签名控制区未经修改但有内容增加"）**：原实现"数字签名 → 签名后增量追加 DSS"造成签名后追加未签名内容，严格工具告警。现改为 **PAdES 部分签名顺序：① DocTimeStamp（覆盖原文档）→ ② 数字签名（adbe.pkcs7.detached）与 DSS/VRI 同一次保存**——数字签名是文档**最后一次**修改，其 ByteRange 覆盖含 DocTimeStamp 与全部 LTV 数据的整个文档，签名后零增量
  - **DSS（Document Security Store）**：与数字签名同一次保存写入，全部被签名覆盖：
    - `/DSS/Certs`：签名证书链 DER（去重）
    - `/DSS/OCSPs`：链上每张证书的 OCSP 响应（RFC 6960 完整 OCSPResp；CertID=SHA-1 + Nonce；地址 = CONFIG.txt `OCSP`，缺省 `http://127.0.0.1:WEBPORT/OCSP`）
    - `/DSS/CRLs`：链上每个 CA/根的 CRL（DER；优先 CONFIG `CRL` 替换 `{CID}` 的 `.der.crl` 变体，回退原 URL 与本地 `PKI/WebPublic/CRL/序列号.der.crl`）
    - `/DSS/VRI`：key = **DocTimeStamp 的 ByteRange SHA-1 大写 hex**（PAdES 规范；时间戳失败降级时省略 VRI，DSS 数组仍全局可用）；VRI 引用 DSS 中对应 OCSP/CRL/Cert
  - `verifyPdf` 升级：**逐个验证全部签名字段**——DocTimeStamp 走专用解析（TimeStampToken：messageImprint 与 ByteRange 摘要比对 + token 内 TSA 证书验签 + 时间戳时间/序列号输出），数字签名走 CMS 验签 + 文档摘要比对 + 证书链；输出含 LTV 状态（DSS Certs/OCSPs/CRLs/VRI）
  - **实测（1135228a2 RSA，链 EVCA→ROOTCA，本机 MAIN）**：签名字段 2 个（ETSI.RFC3161 + adbe.pkcs7.detached）；DocTimeStamp messageImprint 比对通过、TSA 签名验证通过；数字签名 CMS 验签/摘要比对/证书链三级全部通过；DSS Certs=3/OCSPs=3/CRLs=2/VRI=DocTimeStamp SHA1 命中；OCSP `responseStatus=0`、CRL 可解析；数字签名后无任何增量

- **v1.7（2026-09-15）——PDF 签名专区新增第四种签章类型：国密 GM/T 0031-2025《安全电子签章密码技术规范》**
  - **标准澄清**：需求中"GB/T 0031-2025"实际为 **GM/T 0031-2025**（密码行业标准，非 GB/T 国标；国家密码管理局公告第 54 号发布，2026-07-01 实施，替代 GM/T 0031-2014）。2025 版全文未公开（行业标准不免费发布），实现依据 = **GM/T 0031-2014 官方标准原文**（gmbz.org.cn）公开的 ASN.1 + 2025 版公告确认的兼容演进，交付如需对拍正式文本以官方为准
  - **与 GB/T 38540-2020 的结构差异**（August 技术博客 + 2014 官方原文交叉确认）：
    | 层次 | GB/T 38540-2020 | GM/T 0031 |
    |---|---|---|
    | 电子印章 SESeal | { eSealInfo, **cert, signAlgID, signedValue** } 4 子节点 | { SES_SealInfo, **SES_SignInfo{cert, signatureAlgorithm, signData}** } 2 子节点 |
    | 印章属性 | { type, name, **certListType**, certList(证书 DER), ... } | { type, name, certList(SEQUENCE OF **certID=IA5String 证书序列号**), ... }，无 certListType |
    | 电子签章 SES_Signature | { TBS_Sign, cert, signatureAlgID, signature } 4 子节点 | { TBS_Sign, signature } 2 子节点 |
    | TBS_Sign | { version, eseal, timeInfo(GeneralizedTime), dataHash, propertyInfo } 5 字段 | { version, eseal, timeInfo(**BIT STRING**，时间戳或 UTCTIME), dataHash, propertyInfo, **cert, signatureAlgorithm** } 7 字段 |
    | 判别法 | 签章第 2 子节点 OCTET STRING；印章 4 子节点 | 签章第 2 子节点 BIT STRING；印章 2 子节点 |
    | 制章签名对象 | SES_SealInfo 本体 | SEQUENCE{ SES_SealInfo, cert, signatureAlgorithm } |
  - **新增构造器**：`buildGmSealInfo0031`（SES_SealInfo：header{ID="ES",version=11,Vid="MODPKICA"} / esID / property{type=1,name,certList 三项证书序列号,createDate/validStart/validEnd=UTCTIME} / picture / extDatas 政务 OID）；`buildGm0031Signature`（SES_Signature：SESeal 两层嵌套 → TBS_Sign 7 字段 → SM2 对 TBS_Sign 完整 DER 签名）；`signPdfGm` 三路分发（38540/0031/35275），0031 的制章签名单独按 SEQUENCE{SealInfo,cert,OID} 计算；`signPdf` 入口白名单加入 `GM0031`
  - **PDF 集成**：Filter=`Adobe.SM2`、**SubFilter=`GM.sm2seal`**（GM/T 0112-2021《PDF 格式文档的密码应用技术要求》规定的国密电子签章子过滤器，与 38540 共用，验证端按签章子节点类型自动判别 38540/0031）、DM/SM 属性=SM3/SM2 OID、Contents=SES_Signature DER 十六进制；时间戳按 GM/T 0112 建议附签章尾部，本实现 timeInfo 内嵌 UTCTIME（签章时间），外部时间戳扩展沿用现有"仅 ADOBE/GM35275 嵌入"规则
  - **验证侧**：`verifyGmSeal38540` 升级为判别式——SES_Signature 4 子节点走 38540 分支（证书/算法在【外层】），2 子节点走 0031 分支（证书/算法在【TBS_Sign 内部】tbs[5]/tbs[6]），两者 dataHash 均取 TBS_Sign[3] 与 SM3(ByteRange) 比对 + 证书公钥 SM3withSM2 验签 TBS_Sign 完整 DER
  - **实测（113548382 SM2 证书，链 SM2CA→ROOTCA）**：`sealType=GM0031` 签名 → 产物 SubFilter=GM.sm2seal、SES_Signature 2 子节点、TBS_Sign 7 字段、SESeal 2 子节点、certList 三项证书序列号（113548382/1cdd33203a2ce/13fbe86586d3f90）、version=4、header version=11；验证接口输出「TBS_Sign 字段数: 7」「文档摘要比对: 通过 ✓」「SM2 签名验证: 通过 ✓」「最终结论: 国密 PDF 电子签章有效 ✓」；GM38540（5 字段）与 GM35275（CMS）回归均通过
  - WebAdmin：PDF 组「签章类型」下拉新增 `国密 GM/T 0031-2025`；`sealLabel` 四路映射；hint 说明更新；签章仅限 SM2 证书且必须选择签章图片

- **v1.6（2026-09-15）——Authenticode 时间戳嵌入方式修复 + 国密 PDF 签名空间修复**
  - **国密 PDF 签名空间修复**：GB/T 35275-2017 与 GB/T 38540-2020 签名时若印章图片较大（> ~55KB），签名 Contents（印章图片字节 + 证书链 + ASN.1 结构）会超过固定预留的 65536 字节，触发 `java.io.IOException: Can't write signature, not enough space`。修复：`signPdfGm` 按实际输入**动态计算预留空间**（`pref = max(65536, 图片字节+证书链+8192) × 1.5 + 32768`）。实测 2MB 印章图两种国密标准均签名成功（输出 8.4MB 增量 PDF）；小图场景不变（最小仍 64KB）
  - **问题**：签名专区选择「Authenticode」时间戳时，签名操作本身成功（日志显示"已附加 Authenticode 时间戳"），但 Windows 原生验证失败：`signtool verify /pa /v` 报 `0x80091004`（File is not timestamped）→ 修复后进一步暴露 `0x80096003`（BAD_DIGEST），两者根因不同：
    - **0x80091004 根因**：旧实现把 RFC3161 的 `SPC_RFC3161_TS`（`1.3.6.1.4.1.311.3.3.1`）属性嵌入完整 ContentInfo，Windows 只认老式 **countersignature（`1.2.840.113549.1.9.6`）** 机制。用 signtool 自身产物 asn1parse 对照确认：老式时间戳 = unsignedAttrs 中 `countersignature` 属性，其值为 token 内**首个 SignerInfo**（不是完整 token）
    - **0x80096003 根因**：countersignature 的签名需要 **TSA 证书**参与验证，但主 CMS 证书集合只放了签名证书链，未并入 token 内的 TSA 证书（signtool 会合并）→ 修复：`extractCertificates` 从 token `SignedData` 提取证书（注意 `certificates` 为 **IMPLICIT [0]**，需 `ASN1Set.getInstance(tagged, false)`），按序列号去重后并入主 CMS 证书集合
  - **请求侧对齐**：新增 `SignTool.requestAuthenticodeTimestamp(sig, baseDir, tsUrl)`——请求体 = base64( `ContentInfo{1.3.6.1.4.1.311.3.2.1, SEQUENCE{id-data, [0] OCTET STRING(主签名值)}}` )，与 signtool `/t` 及 Go 版 MAIN `/timestamp` 提取协议（0x04 0x81/82/83 定位被签名内容）完全一致；响应兼容 DER 直返与 base64 PEM 正文两种
  - **嵌入侧**：`buildExeCms` 对 AUTHENTICODE 类型走 countersignature 分支（提取 token 首个 SignerInfo 嵌入 `1.2.840.113549.1.9.6`），RFC3161 仍走 `SPC_RFC3161_TS` 完整 token 分支，互不影响
  - **实测（Windows 原生）**：两种模式均 `signtool verify /pa /v` → 0 错误，`The signature is timestamped`，`Timestamp Verified by ROOTCA By Timstamp SHA256`；Authenticode 产物 asn1parse 与 signtool 自身产物逐字段一致（signedAttrs 含 contentType / signingTime / CMSAlgorithmProtection / messageDigest=SHA256(主签名值) / id-data=主签名值）
  - **说明**：外部 TSA（DigiCert 等）选择 Authenticode 类型时，若其响应为 `TimeStampResp`（PKIStatus 包装）或直接 `ContentInfo`，`extractFirstSignerInfo` 均兼容；请求失败自动降级不影响主签名

- **v1.5（2026-09-15）——签名专区：时间戳类型 / 签章类型 / 国密 PDF 电子签章**
  - **EXE 代码签名组新增「时间戳类型」下拉**（RFC3161 / Authenticode）：RFC3161 → 标准 TimeStampToken（POST `application/timestamp-query`，默认本机 MAIN `/rfc3161`）；Authenticode → 微软老式 PKCS#7（请求体 base64 文本，默认本机 MAIN `/timestamp`）。`SignTool.requestTimestamp` 增加类型/地址重载：Authenticode 响应兼容 DER 直接返回与 base64 PEM 正文（本机 MAIN 按 Go 版返回 PKCS#7 DER 的 base64，需解码后再嵌入 unsignedAttrs `1.3.6.1.4.1.311.3.3.1`）
  - **EXE / PDF 两组新增「时间戳请求地址」可编辑下拉**：留空 = 本机 MAIN（WEBPORT 读 CONFIG.txt）；内置 DigiCert / Symantec / Comodo / Certum 四个外部 TSA 快捷选项，可手输任意地址。实测连接 `http://timestamp.digicert.com` 成功获取真实 RFC3161 时间戳（5986B）并嵌入；请求失败自动降级（签名成功、日志记录原因）
  - **PDF 组新增「签章类型」下拉**（三种）：
    - **Adobe 标准文档签名**（默认，`adbe.pkcs7.detached`）：支持 RSA / ECC / SM2；`buildCms` 经 `DefaultSignedAttributeTableGenerator` 在 signedAttrs 附加 `id-aa-timeStampToken`（`1.2.840.113549.1.9.16.2.14`，值为 RFC3161 时间戳令牌），BC 自动补 contentType / messageDigest；实测 CMS 验签、文档摘要比对、证书链全部通过
    - **国密 GB/T 35275-2017**（`GM.sm2cms.detached`，仅 SM2 证书）：Contents 为标准 CMS SignedData（detached），SESeal 电子印章挂 signedAttrs 私有 OID `1.2.156.112600.8.1`（eSealInfo + 印章证书链块 + SM2 OID + 制章签名）；Filter=`Adobe.SM2`、DM/SM 属性=SM3/SM2 OID；证书链完整写入 CMS certificates；实测 CMS 验签（SM3withSM2 含 ZA）、文档摘要比对、证书链通过
    - **国密 GB/T 38540-2020**（`GM.sm2seal`，仅 SM2 证书，必须选签章图片）：Contents 手工 ASN.1 构造 **SES_Signature**（SEQUENCE{ toSign TBS_Sign, cert, signatureAlgID=SM2 OID, signature }）；TBS_Sign=SEQUENCE{ version=4, eseal SESeal, GeneralizedTime, dataHash=SM3(ByteRange), propertyInfo }；SESeal=eSealInfo（header/esID/property 含证书列表与有效期/picture/extDatas 政务 OID）+ 制章证书 + SM2 OID + 制章签名；`setPreferredSignatureSize(65536)` 预留大签名区；验证新增 `verifyGmSeal38540` 专用解析：dataHash 与 SM3(ByteRange) 比对 + 证书公钥 SM3withSM2 验签 TBS_Sign 完整 DER，实测两项全部通过
  - 国密 PDF 印章信息构建：`buildGmSealInfo38540`（SES_SealInfo 五段）/ `buildGmSealInfo35275`（sealId/UUID/certInfo/imgInfo/ext），制章签名与文档签名均走 `Signature.getInstance("SM3WITHSM2","BC")`（BC 内置 ZA 计算，符合 GB/T 32918）；参考实现：`java-lening\PDF或者OFD国密SM2签名验证\多个版本\PDF国密GBT 38540-2020（4）` 与 `PDF国密SM2公安政务兼容GBT 35275-2017（2）`
  - WebAdmin `signAction` 读取并传递 `tsType` / `tsUrl` / `sealType`，日志与 `lastTsInfo` 完整展示类型与地址；`signDo` JS 追加对应 FormData 字段；PDF 组国密模式（35275/38540）下选择非 SM2 证书与未选签章图片时给出明确中文报错

- **v1.4（2026-09-15）——签名专区修复与增强**
  - **微软代码签名（Authenticode）重写**：`SignTool.signExe` 改为手工 ASN.1 构造（对齐参考项目 `java-lening\微软RSA国密双签名带时间戳` 的合规点），修复旧实现（BC `CMSSignedDataGenerator` 自动构造）产物被 Windows 判 `0x80096010 / 签名无效` 的问题：
    - `SpcAttributeTypeAndOptionalValue.value` 直接 SEQUENCE（无 `[0]` 包装）；`SpcPeImageData.file` 实际标签 `[0] EXPLICIT`；`SpcString` 空串 `[0] IMPLICIT 80 00`；`DigestInfo.digestAlgorithm.parameters` 带 `NULL`；eContent 直接 SEQUENCE（无 OCTET STRING 包装）；messageDigest = SHA-256(SpcIndirectData **内容字节**，跳过 `30 xx` 头)；证书表 8 字节对齐追加 `WIN_CERTIFICATE 0x0200/0x0002`；证书顺序根在前
    - **自动时间戳**：签名后 `messageImprint = SHA-256(签名值)` → 请求本机 MAIN `/rfc3161`（`application/timestamp-query`，WEBPORT 读 `PKI/CONFIG.txt`）→ `TimeStampToken` 嵌入 unsignedAttrs（`1.3.6.1.4.1.311.3.3.1`）；失败自动降级不影响签名，状态写入日志
    - **实测（Windows 原生）**：`signtool verify /pa /v` → 0 错误、时间戳验证通过；`Get-AuthenticodeSignature` → **Valid**（证书链 ROOTCA→终端、时间戳 ROOTCA By Timstamp SHA256）
    - **已知限制**：中间 CA 若 EKU 仅含 serverAuth（不含代码签名），Windows Authenticode 链验证会拒绝该 CA 签发的证书用于代码签名（`signing certificate is not valid for the requested usage`）——根直接签发的代码签名证书不受影响；如需使用中间 CA 链，请重签 CA 时在 EKU 中加入代码签名或不设 EKU
    - SM2 主签名 EXE：签名与时间戳正常生成；Windows crypt32 白名单不含 SM2，原生验证不支持（与参考项目结论一致），可用本面板"签名验证"做链内验证
  - **PDF 可见签章**：PDF 分组新增"签章图片（可选，png/jpg/bmp/gif）"选择框；采用参考项目 `SignatureOptions.setVisualSignature` 外观文档模式（独立外观 PDF 内放置带 Rect+AP 的 widget，PDFBox 将 Rect/外观搬至主文档第 1 页右下角，最大 150×80 等比缩放），**避免 addSignature 后改动文档破坏 ByteRange**（替代早期 PDSignatureField 手动方式，后者报 `signature reserve byte range has been changed`）；不选签章则不可见签名
  - 实测：`test.pdf`（5 页）带签章签名 → `CMS 签名验证通过`、文档摘要比对通过、证书链通过，第 1 页右下角签章渲染可见；无签章 PDF 签名回归通过；SM2 证书 EXE 签名回归通过

- **v1.3（2026-09-15）**
  - WebAdmin 新增「签名专区」页面（调试专区下方）：两个分组均支持选择文件 + 下拉式证书选择（自动按 EKU 筛选、悬停显示证书简介）
    - **微软代码签名（Authenticode）**：对 exe/dll/sys 等 PE 文件按 Microsoft PE/COFF 规范嵌入证书表（WIN_CERTIFICATE 0x0200/0x0002 + CMS SignedData，contentType=spcIndirectDataContext，SpcIndirectDataContent 内含 Authenticode 文件哈希：跳过 Checksum/Security Directory/证书表区域），支持 RSA/ECC/SM2（SM2 走 GB/T 32918 含 ZA，摘要 SM3；RSA/ECC 摘要 SHA256）；验证输出 CMS 签名、文件哈希比对、证书链逐级验证（签名证书 → 颁发者 → 自签根）三要素
    - **PDF 文档签名**：标准 PKCS#7 detached（SubFilter adbe.pkcs7.detached），基于 PDFBox 3.0.4 外部签名两段式（saveIncrementalForExternalSigning）增量保存，ByteRange 由 PDFBox 维护；验证时以 ByteRange 区间数据作为 detached 内容构造 CMS 后验签（否则 BC 按空内容计算摘要导致 mismatch），同样支持 RSA/ECC/SM2
  - 新增 `SignTool.java`（签名/验证核心，约 35KB）：按 CERTS.txt 台账加载证书（R→ROOT、C→CA、E→CERT）与私钥（E→KEY），按颁发者关系加载完整证书链；EKU 筛选集合：代码签名 `1.3.6.1.5.5.7.3.3` / 内核模式 `1.3.6.1.4.1.311.61.1.1` / 驱动验证 `1.3.6.1.4.1.311.10.3.5` / 系统组件 `1.3.6.1.4.1.311.10.3.6` / OEM `1.3.6.1.4.1.311.10.3.7` / 内嵌 `1.3.6.1.4.1.311.10.3.8`，文档签名 `1.3.6.1.4.1.311.10.3.12` / 通用文档签名 `1.3.6.1.5.5.7.3.36`（代码签名证书亦可签 PDF）
  - WebAdmin 新增 API：`GET /api/signcerts?kind=exe|pdf`（可签名证书列表）、`POST /api/sign/exe`、`POST /api/sign/pdf`（multipart 上传文件 + serial，返回签名结果 + Base64 下载）、`POST /api/verify/exe`、`POST /api/verify/pdf`；所有签名/验证操作写入 logs.log
  - 依赖：`lib/pdfbox-app-3.0.4.jar`（PDFBox 3.0.4，从参考项目引入）；`build.cmd` / `build.sh` 编译与运行 classpath 均加入 `lib\*`（`-cp "BC185\*;lib\*"` / `"out;BC185\*;lib\*"`）
  - 实测（真实样本）：`CERTVERIFY.exe`（9.8MB）Authenticode 签名/验证三要素全部通过；`test.pdf`（5 页）与 SM2 证书 PDF 签名/验证全部通过（SM3 摘要、SM3withSM2 含 ZA 验签成功）

- **v1.2（2026-09-14）**
  - WebAdmin 新增「调试专区」页面：两个分组均按标准协议构造请求并 POST 本机 MAIN，日志逐步展示
    - **模拟 OCSP 请求（RFC 6960）**：按 CertID（issuerNameHash/issuerKeyHash 基于真正颁发者证书计算，哈希算法可选 SHA1/SHA256/SHA384/SHA512/SM3）+ Nonce 扩展构造请求 → 解析响应（responseStatus、responderID、证书状态/吊销原因时间、thisUpdate/nextUpdate、Nonce 回显比对）→ 用响应者证书验证签名
    - **模拟时间戳请求（RFC 3161）**：随机 32 字节数据 → 按所选摘要算法（SHA1/SHA256/SHA384/SHA512/SM3）计算 messageImprint → 构造 TimeStampReq（Nonce + certReq）→ 解析 TimeStampResp（status、TimeStampToken 序列号/genTime/policy、messageImprint 回显比对）→ 用签名者证书验证 token 签名；MAIN 返回非 200 时显示真实错误与所需 TSA 证书提示
  - OCSP 服务端行为（RFC 6960）：解析请求哈希算法 OID 与序列号 → 按 `颁发者序列号_ocsp.crt/.key` 加载响应者密钥对；RSA/ECC 按请求哈希算法（sha1/256/384/512，缺省 sha1）签名，SM2 固定 SM3 签名（`MAIN.handleOcsp` + `OcspUtil`，此前已实现，本轮以调试专区实测 Nonce 回显与签名验证通过）

- **v1.1（2026-09-13）**
  - 修复 SM2 分支 OCSP 吊销响应的 DER 编码错误：`CertStatus.revoked` 由 EXPLICIT 改为 RFC 6960 规定的 `[1] IMPLICIT RevokedInfo`（`OcspUtil.createResponseSm2`）。此前 openssl 解析报 `Field=revocationTime ... wrong tag`、BC 报 `illegal object in getInstance`，表现为 SM2 已吊销证书（含重复吊销/修改吊销原因）验证时输出 `OCSP无法检查吊销状态 | 上报失败~`；修复后 openssl / BC 均能正确解析出吊销时间与原因
  - `build.cmd` / `build.sh` 支持编号参数：`build.cmd 1` ~ `build.cmd 8`，编译成功后自动运行对应编号的启动命令（编译失败则不运行；编号 4/5/7/8 为脚本内置固定示例参数）
  - WebAdmin 证书库美化：类型中文显示（R=根证书 / C=CA证书 / E=终端证书）、状态三色（V 正常绿 / R 已吊销深红 / N 未知橙）、颁发者序列号悬停悬浮窗；每行新增「验证」按钮（弹窗三态：正常/已吊销/未知，对应绿/红/橙配色标题）与「操作」按钮（吊销证书 / 续签证书 / 密钥更换分组，吊销支持下拉选择 + 证书简要信息）
  - `CertVerify` 证书策略识别补充 TSA 证书 OID `2.23.140.1.4.2`
