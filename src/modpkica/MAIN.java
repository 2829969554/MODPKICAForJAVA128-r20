package modpkica;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Random;

/**
 * MAIN —— MODPKICA 主服务（对应 Go 版 cmd/main）。
 *
 * <p>提供以下 HTTP 端点（端口取自 PKI/CONFIG.txt 的 WEBPORT，默认 80）：
 * <ul>
 *   <li><b>/OCSP 与 /ocsp</b>：OCSP 在线证书状态协议（POST）。
 *       按请求序列号查 CERTS.txt → 用颁发者序列号加载 PKI/OCSP/序列号_ocsp.crt|.key
 *       签名响应；RSA/ECC 按请求哈希自适应（sha1/256/384/512，默认 sha1），
 *       SM2 固定 SM3；未知序列号返回 5 字节无签名响应（unauthorized）。</li>
 *   <li><b>/</b>：静态文件分发（CRL/CRT），根目录为 PKI/WebPublic。</li>
 *   <li><b>/timestamp 与 /timestamp/sha1</b>：微软 Authenticode 时间戳
 *       （SHA256 / SHA1，自适应根随机选 rsa/ecc 组）。</li>
 *   <li><b>/rfc3161</b>：RFC3161 文档时间戳（sha1 → rsa_sha1/ecc_sha1 随机，
 *       sha256 → rsa_sha256/ecc_sha256 随机，sm3 → sm2_sm3 固定）。</li>
 * </ul>
 *
 * <p>所有操作写入 PKI/logs.log（时间、操作、结果，两个换行符分隔，只追加）。
 */
public final class MAIN {

    /** 当前程序根目录（MODPKICA_BASE 或 jar 所在目录） */
    private static String baseDir;
    /** 配置文件 */
    private static Config cfg;
    /** 证书登记表 */
    private static CertsDB db;

    /** 安静模式开关：-Dmodpkica.quiet=true 时关闭请求级控制台日志（错误仍输出 stderr）。 */
    private static final boolean QUIET = Boolean.getBoolean("modpkica.quiet");

    private MAIN() {
    }

    public static void main(String[] args) throws Exception {
        baseDir = AppPaths.baseDir();
        cfg = new Config(baseDir);
        db = new CertsDB();
        db.load(baseDir);

        // 启动时刷新一次 CRL 吊销列表（对齐 Go 版：main 启动调用 rootGETcrl）
        try {
            RootGetCrl.run();
        } catch (Exception e) {
            System.err.println("启动时刷新 CRL 失败: " + e.getMessage());
        }

        String port = cfg.getWebPort();
        if (port == null || port.isEmpty()) {
            port = "80";
        }

        HttpServer server = HttpServer.create(new InetSocketAddress(Integer.parseInt(port)), 0);
        server.createContext("/OCSP", MAIN::handleOcsp);
        server.createContext("/ocsp", MAIN::handleOcsp);
        server.createContext("/timestamp/sha1", MAIN::handleTimestampSha1);
        server.createContext("/timestamp", MAIN::handleTimestampSha256);
        server.createContext("/rfc3161", MAIN::handleRfc3161);
        server.createContext("/ct/add", MAIN::handleCtAdd);
        server.createContext("/ct/v1", MAIN::handleCtV1);
        server.createContext("/", MAIN::handleFile);
        // 多线程处理请求：OCSP/时间戳/CT/静态文件互不阻塞，响应更快。
        // CertsDB 已改为 CopyOnWriteArrayList + 锁内写，可安全并发 reload/查询。
        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(8));
        server.start();

        // 启动可视化 WebAdmin 管理界面（默认 127.0.0.1:8080，
        // 可用 -Dmodpkica.admin.port / -Dmodpkica.admin.bind 调整；
        // 端口被占用时自动跳过，不影响 MAIN 主服务）
        WebAdmin.start(port);
        if (WebAdmin.port() > 0) {
            System.out.println("MOD PKI CA 可视化管理界面启动: http://localhost:"
                    + WebAdmin.port());
        }

        System.out.println("MOD PKI CA Server is running on http://localhost:" + port);
        System.out.println("MOD PKI CA 服务端启动: http://localhost:" + port);
        System.out.println("MOD PKI CA OCSP服务启动: http://localhost:" + port + "/OCSP（RSA/ECC/SM2，摘要自适应 SHA1/SHA256/SHA384/SHA512/SM3）");
        System.out.println("MOD PKI CA 微软Authenticode时间戳SHA1 服务启动: http://localhost:"
                + port + "/timestamp/sha1");
        System.out.println("MOD PKI CA 微软Authenticode时间戳SHA256 服务启动: http://localhost:"
                + port + "/timestamp（SM2/SM3 自适应）");
        System.out.println("MOD PKI CA RFC3161文档签名专用时间戳(SHA1&SHA256&SM3自适应) 服务启动: http://localhost:"
                + port + "/rfc3161");
        System.out.println("MOD PKI CA CT日志服务启动: http://localhost:" + port + "/ct/add（RFC 6962 / Certificate Transparency，接收 PEM 预证书+颁发者证书）");
        System.out.println("MOD PKI CA CT标准API启动(RFC 6962 §4): http://localhost:" + port + "/ct/v1/add-chain | add-pre-chain | get-sth | get-roots | get-entries | get-proof-by-hash | get-sth-consistency | get-entry-and-proof");
        System.out.println("MOD PKI CA 监听端口  :" + port);
        System.out.println("如需修改配置请编辑./PKI/CONFIG.txt文件");
        if (QUIET) {
            System.out.println("安静模式已开启(-Dmodpkica.quiet=true)：请求日志不输出控制台，仅写 logs.log");
        }
        System.out.println("本程序作者：@魔帝本尊  QQ：2829969554");
        System.out.println("MOD PKI CA SERVER支持x.509 证书管理、CRL吊销列表、时间戳服务器、OCSP在线状态协议、自动化签发。");
        System.out.println("本系统仅供学习 x.509 ASN.1编码使用。作者不承担任何由此产生的一切问题。");
    }

    // ============================================================
    // OCSP 在线证书状态协议
    // ============================================================

    /**
     * /OCSP 与 /ocsp 共用的处理器（Go 版两个 handler 逻辑相同）。
     */
    private static void handleOcsp(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            byte[] msg = "/OCSP:在线证书状态协议查询接口：仅支持POST方式访问"
                    .getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, msg.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(msg);
            }
            return;
        }

        byte[] req = readAll(ex.getRequestBody());
        String remote = ex.getRemoteAddress() != null
                ? ex.getRemoteAddress().getAddress().getHostAddress() : "?";
        MLog.append(baseDir, "收到OCSP请求",
                "来源=" + remote + " 路径=" + ex.getRequestURI().getPath()
                        + " 长度=" + req.length + "字节");

        try {
            // 写原始请求到 ocsp.req（供调试，对齐 Go 版）
            writeFile("PKI/OCSP/ocsp.req", req);

            // 解析 OCSP 请求
            OcspUtil.OcspRequest parsed = OcspUtil.parseRequest(req);
            String serialHex = parsed.serialNumber.toString(16);
            String hashOid = parsed.hashAlgOid;
            byte[] nonce = parsed.nonce;
            MLog.append(baseDir, "OCSP请求解析", "序列号=" + serialHex
                    + " 哈希=" + hashOid + " Nonce=" + (nonce == null ? "无" : toHex(nonce)));

            // 查 CERTS.txt：状态、颁发者ID、吊销原因、吊销时间
            // 每次请求前重新加载：签发/吊销/外部编辑 CERTS.txt 后保持内存数据最新
            db.reload();
            CertsDB.CertEntry entry = db.findBySerial(serialHex);
            if (entry == null) {
                // 未知序列号：返回无签名响应（unauthorized，无 responseBytes）
                log("OCSP:未知序列号,返回无签名响应 " + serialHex);
                byte[] unsigned = OcspUtil.unauthorizedResponse();
                sendBytes(ex, unsigned, "application/ocsp-response");
                MLog.append(baseDir, "OCSP响应", "状态=unauthorized(未知序列号) 长度="
                        + unsigned.length + "字节");
                return;
            }

            // 状态：V 正常 / R 吊销 / 其它视为未知
            int status;
            String statusName;
            if (entry.status == 'R') {
                status = OcspUtil.REVOKED;
                statusName = "已吊销";
            } else if (entry.status == 'V') {
                status = OcspUtil.GOOD;
                statusName = "正常";
            } else {
                status = OcspUtil.UNKNOWN;
                statusName = "未知";
            }
            int reason = entry.reason;
            Date revokedAt = java.sql.Timestamp.valueOf(
                    entry.time.withSecond(entry.time.getSecond())); // CERTS.txt 时间（本地时区）
            log("OCSP:" + statusName + ",序列号 " + serialHex);

            // ---- 加载 OCSP 签名证书/私钥（多根模型：统一 颁发者序列号_ocsp.crt/.key） ----
            String issuerId = entry.issuerId;
            String ocspCertPath = "PKI/OCSP/" + issuerId + "_ocsp.crt";
            if (!fileExists(ocspCertPath)) {
                throw new IllegalStateException("缺少 OCSP 签名证书: " + ocspCertPath
                        + "（请先运行 admin initOCSP）");
            }
            String ocspKeyPath = ocspCertPath.replace(".crt", ".key");
            X509Certificate responderCert = PemIO.readCert(baseDir + "/" + ocspCertPath);
            String keyType = PemIO.detectKeyType(baseDir + "/" + ocspKeyPath);
            // RSA-PSS：OCSP 证书私钥物理为 RSA，文件无法区分，须按 CERTS.txt 登记算法判断
            CertsDB.CertEntry ocspDb = db.findBySerial(responderCert.getSerialNumber().toString(16));
            if (ocspDb != null && "RSA-PSS".equalsIgnoreCase(ocspDb.algo)) {
                keyType = "RSA-PSS";
            }
            PrivateKey ocspKey = CertUtil.readJcaPrivateKey(baseDir + "/" + ocspKeyPath);

            // ---- 加载真正颁发者证书（ROOT/CA 目录，用于计算 CertID 的 issuer 哈希） ----
            String issuerCertPath = findExisting(
                    "PKI/ROOT/" + issuerId + ".crt",
                    "PKI/CA/" + issuerId + ".crt");
            X509Certificate issuerCert = PemIO.readCert(baseDir + "/" + issuerCertPath);

            // ---- P1-06：按 issuer 二次校验 ----
            // 请求 CertID 携带 issuerNameHash/issuerKeyHash 时，与真正颁发者证书重算值比对；
            // 不一致说明请求的 serial 属于其它颁发者（同序列号冲突），按未知序列号返回无签名响应。
            if (parsed.issuerNameHash != null && parsed.issuerKeyHash != null
                    && !OcspUtil.matchesIssuerHash(issuerCert, hashOid,
                            parsed.issuerNameHash, parsed.issuerKeyHash)) {
                log("OCSP:颁发者哈希不匹配,返回无签名响应 序列号=" + serialHex
                        + " 实际颁发者=" + issuerCert.getSubjectX500Principal());
                byte[] unsigned = OcspUtil.unauthorizedResponse();
                sendBytes(ex, unsigned, "application/ocsp-response");
                MLog.append(baseDir, "OCSP响应",
                        "状态=unauthorized(颁发者哈希不匹配) 长度=" + unsigned.length + "字节");
                return;
            }

            // ---- 构造响应 ----
            byte[] respBytes;
            if ("SM2".equalsIgnoreCase(keyType)) {
                // SM2：固定 SM3 签名，CertID 哈希按请求回显（对齐 Go 版 smocsp）
                ECPrivateKeyParameters sm2Priv = Sm2Util.toEcPrivateParams(ocspKey);
                respBytes = OcspUtil.createResponse("SM2", issuerCert, responderCert,
                        null, sm2Priv, parsed.serialNumber, hashOid,
                        status, reason, revokedAt, nonce);
                MLog.append(baseDir, "OCSP签名",
                        "算法=SM2WithSM3 响应者=" + responderCert.getSubjectX500Principal()
                                + " 请求序列号=" + serialHex);
            } else {
                // RSA/ECC：签名哈希按请求自适应（sha1/256/384/512，缺省 sha1）
                String hashName = ocspHashName(hashOid);
                ContentSigner signer = CertUtil.createContentSigner(ocspKey, keyType, hashName);
                // 回显的 CertID 哈希算法 OID：请求给了就用请求的，否则默认 sha1
                String echoOid = isKnownHash(hashOid) ? hashOid : SHA1_OID;
                respBytes = OcspUtil.createResponse(keyType, issuerCert, responderCert,
                        signer, null, parsed.serialNumber, echoOid,
                        status, reason, revokedAt, nonce);
                MLog.append(baseDir, "OCSP签名",
                        "算法=" + keyType + "(" + hashName + ") 响应者="
                                + responderCert.getSubjectX500Principal()
                                + " 请求序列号=" + serialHex);
            }

            // ---- 输出 ----
            writeFile("PKI/OCSP/ocsp.res", respBytes);
            sendBytes(ex, respBytes, "application/ocsp-response");
            MLog.append(baseDir, "OCSP响应", "状态=success(200) 长度=" + respBytes.length + "字节");
        } catch (Exception e) {
            MLog.append(baseDir, "OCSP处理异常", "错误=" + e);
            System.err.println("OCSP 处理异常: " + e);
            ex.sendResponseHeaders(500, -1);
            ex.close();
        }
    }

    /** CertID 哈希 OID：SHA1 */
    private static final String SHA1_OID = "1.3.14.3.2.26";

    /** 判断是否已知哈希 OID。 */
    private static boolean isKnownHash(String oid) {
        return oid != null && (oid.equals(SHA1_OID)
                || oid.equals("2.16.840.1.101.3.4.2.1")   // SHA256
                || oid.equals("2.16.840.1.101.3.4.2.2")   // SHA384
                || oid.equals("2.16.840.1.101.3.4.2.3")   // SHA512
                || oid.equals("2.16.840.1.101.3.4.2.7")   // SHA3-224
                || oid.equals("2.16.840.1.101.3.4.2.8")   // SHA3-256
                || oid.equals("2.16.840.1.101.3.4.2.9")   // SHA3-384
                || oid.equals("2.16.840.1.101.3.4.2.10")  // SHA3-512
                || oid.equals(Sm2Util.OID_SM3));
    }

    /** OCSP 请求哈希 OID → 签名哈希名（默认 sha1）。 */
    private static String ocspHashName(String oid) {
        if (oid == null) {
            return "sha1";
        }
        switch (oid) {
            case "2.16.840.1.101.3.4.2.1":
                return "sha256";
            case "2.16.840.1.101.3.4.2.2":
                return "sha384";
            case "2.16.840.1.101.3.4.2.3":
                return "sha512";
            case "2.16.840.1.101.3.4.2.7":
                return "sha3-224";
            case "2.16.840.1.101.3.4.2.8":
                return "sha3-256";
            case "2.16.840.1.101.3.4.2.9":
                return "sha3-384";
            case "2.16.840.1.101.3.4.2.10":
                return "sha3-512";
            case Sm2Util.OID_SM3:
                return "sm3";
            case "1.3.14.3.2.26":
            default:
                return "sha1";
        }
    }

    // ============================================================
    // 静态文件分发（CRL / CRT）
    // ============================================================

    /**
     * / 根路径：静态文件分发，文件根目录为 PKI/WebPublic。
     * 路径规则与 Go 版一致：URL 中的 crl→CRL、crt→CRT 大小写归一化。
     */
    private static void handleFile(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        MLog.append(baseDir, "收到文件请求",
                "来源=" + (ex.getRemoteAddress() != null
                        ? ex.getRemoteAddress().getAddress().getHostAddress() : "?")
                        + " 路径=" + path);

        if ("/".equals(path)) {
            byte[] msg = "欢迎访问 MOD PKI CA 基础服务页面。"
                    .getBytes(StandardCharsets.UTF_8);
            sendBytes(ex, msg, "text/plain; charset=utf-8");
            return;
        }

        // 大小写归一化：/CRL/xx.crl 与 /crl/xx.crl 都可访问
        String rel = path;
        rel = rel.replace("/crl", "/CRL");
        rel = rel.replace("/crt", "/CRT");
        rel = rel.replace(".CRT", ".crt");
        rel = rel.replace(".CRL", ".crl");

        // 防目录穿越：规范化后必须仍以 / 开头且在 WebPublic 内
        Path webRoot = Paths.get(baseDir, "PKI", "WebPublic").toAbsolutePath().normalize();
        Path target = webRoot.resolve(rel.substring(1)).normalize();
        if (!target.startsWith(webRoot)) {
            sendText(ex, 404, "404：访问地址不存在");
            return;
        }

        if (Files.exists(target) && Files.isRegularFile(target)) {
            byte[] fileBytes = Files.readAllBytes(target);
            String name = target.getFileName().toString();
            String suffix = name.length() >= 3 ? name.substring(name.length() - 3) : "";
            String contentType = "application/octet-stream";
            if ("crl".equalsIgnoreCase(suffix)) {
                contentType = "application/pkix-crl";
            } else if ("crt".equalsIgnoreCase(suffix)) {
                contentType = "application/pkix-cert";
            }
            ex.getResponseHeaders().set("Content-Disposition",
                    "attachment; filename=" + name);
            ex.getResponseHeaders().set("Content-Type", contentType);
            ex.sendResponseHeaders(200, fileBytes.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(fileBytes);
            }
            MLog.append(baseDir, "文件响应", "文件=" + name + " 大小="
                    + fileBytes.length + "字节 类型=" + suffix);
        } else {
            sendText(ex, 404, "404：访问地址不存在");
        }
    }

    // ============================================================
    // 微软 Authenticode 时间戳
    // ============================================================

    private static void handleTimestampSha1(HttpExchange ex) throws IOException {
        handleAuthenticode(ex, 1, "sha1");
    }

    private static void handleTimestampSha256(HttpExchange ex) throws IOException {
        handleAuthenticode(ex, 2, "sha256");
    }

    /**
     * Authenticode 时间戳处理器。
     *
     * @param digitype 1=sha1 2=sha256 3=sha384 4=sha512
     * @param tsaGroup 自适应根选择组（"sha1"/"sha256"）
     */
    private static void handleAuthenticode(HttpExchange ex, int digitype, String tsaGroup)
            throws IOException {
        MLog.append(baseDir, "收到时间戳请求",
                "来源=" + (ex.getRemoteAddress() != null
                        ? ex.getRemoteAddress().getAddress().getHostAddress() : "?")
                        + " 路径=" + ex.getRequestURI().getPath());

        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            sendText(ex, 200, "欢迎访问MODPKICA系统可信时间戳服务，此接口仅允许POST方式提交数据");
            return;
        }
        // RFC3161 请求（Content-Type: application/timestamp-query）转交给 RFC3161 处理器
        if ("application/timestamp-query".equalsIgnoreCase(
                ex.getRequestHeaders().getFirst("Content-Type"))) {
            handleRfc3161(ex);
            return;
        }

        byte[] body = readAll(ex.getRequestBody());
        try {
            // 请求体是 base64 文本（实测含 \r\n 与末尾 \0 空字节）。
            // 只保留 base64 字母表字符，其余（换行/回车/NUL/空格）全部丢弃，最健壮
            String b64 = new String(body, StandardCharsets.UTF_8)
                    .replaceAll("[^A-Za-z0-9+/=]", "");
            byte[] decoded = Base64.getDecoder().decode(b64);

            // 提取被签名内容：在 0x04 0x81/82/83 分割点之后（对齐 Go 版）
            byte[] content = extractAuthenticodeContent(decoded);

            // 自适应根：rsa/ecc 随机一组
            String[] tsaPaths = pickTSACert(tsaGroup);
            X509Certificate tsaCert = PemIO.readCert(baseDir + "/" + tsaPaths[0]);
            PrivateKey tsaKey = CertUtil.readJcaPrivateKey(baseDir + "/" + tsaPaths[1]);

            // Authenticode 签名（PKCS#7 分离签名，输出 base64 PEM 正文）
            byte[] signature = TimestampUtil.createAuthenticodeTimestamp(
                    content, tsaCert, tsaKey, digitype);

            String digestHex = sha1Hex(content);
            log("时间戳签名 Authenticode "
                    + (digitype == 1 ? "SHA1" : digitype == 3 ? "SHA384"
                    : digitype == 4 ? "SHA512" : "SHA256") + "  " + digestHex);
            MLog.append(baseDir, "时间戳签名", "算法=Authenticode-"
                    + (digitype == 1 ? "SHA1" : digitype == 3 ? "SHA384"
                    : digitype == 4 ? "SHA512" : "SHA256")
                    + " 证书=" + tsaCert.getSubjectX500Principal() + " 摘要=" + digestHex);

            // 写入请求/响应日志文件（对齐 Go 版 TIMSTAMP/log/摘要.req|.res）
            writeFile("PKI/TIMSTAMP/log/" + digestHex + ".req", body);
            writeFile("PKI/TIMSTAMP/log/" + digestHex + ".res", signature);

            sendBytes(ex, signature, "application/timestamp-reply");
            MLog.append(baseDir, "时间戳响应", "长度=" + signature.length + "字节");
        } catch (Exception e) {
            MLog.append(baseDir, "时间戳处理异常", "错误=" + e
                    + " 请求体前256字节HEX=" + toHex(head(body, 256)));
            // 失败请求落盘，供分析客户端实际发送格式
            try {
                writeFile("PKI/TIMSTAMP/log/auth_fail.req", body);
            } catch (Exception ignore) {
            }
            System.err.println("时间戳处理异常: " + e);
            ex.sendResponseHeaders(500, -1);
            ex.close();
        }
    }

    /** 取字节数组前 max 个字节。 */
    private static byte[] head(byte[] a, int max) {
        if (a == null) {
            return new byte[0];
        }
        if (a.length <= max) {
            return a;
        }
        byte[] r = new byte[max];
        System.arraycopy(a, 0, r, 0, max);
        return r;
    }

    /** RFC3161 时间戳签名哈希名 → JCA 摘要算法名。 */
    private static String jcaHashName(String hashName) {
        if ("sha1".equals(hashName)) {
            return "SHA1";
        }
        if ("sha384".equals(hashName)) {
            return "SHA384";
        }
        if ("sha512".equals(hashName)) {
            return "SHA512";
        }
        if ("sha3-224".equals(hashName)) {
            return "SHA3-224";
        }
        if ("sha3-256".equals(hashName)) {
            return "SHA3-256";
        }
        if ("sha3-384".equals(hashName)) {
            return "SHA3-384";
        }
        if ("sha3-512".equals(hashName)) {
            return "SHA3-512";
        }
        return "SHA256";
    }

    /**
     * 提取 Authenticode 被签名内容：找到 0x04 0x81/82/83 标记，
     * 取其后的数据（长度头 1/2/3 字节，对齐 Go 版 bytes.Split 逻辑）。
     */
    private static byte[] extractAuthenticodeContent(byte[] data) {
        int[] heads = {0x81, 0x82, 0x83};
        for (int h : heads) {
            int idx = lastIndexOf(data, new byte[]{0x04, (byte) h});
            if (idx >= 0) {
                int offset = idx + 2 + (h - 0x80); // 0x81→+1, 0x82→+2, 0x83→+3
                if (offset < data.length) {
                    byte[] out = new byte[data.length - offset];
                    System.arraycopy(data, offset, out, 0, out.length);
                    return out;
                }
            }
        }
        // 找不到标记时原样返回（对齐 Go 版返回空时的行为）
        return data;
    }

    // ============================================================
    // RFC3161 时间戳
    // ============================================================

    private static void handleRfc3161(HttpExchange ex) throws IOException {
        MLog.append(baseDir, "收到时间戳请求(RFC3161)",
                "来源=" + (ex.getRemoteAddress() != null
                        ? ex.getRemoteAddress().getAddress().getHostAddress() : "?")
                        + " 路径=" + ex.getRequestURI().getPath());

        byte[] body = readAll(ex.getRequestBody());
        try {
            TimestampUtil.Rfc3161Request parsed = TimestampUtil.parseRfc3161Request(body);
            MLog.append(baseDir, "时间戳请求解析(RFC3161)",
                    "摘要算法=" + parsed.hashAlgOid + " 消息摘要=" + toHex(parsed.messageImprint)
                            + " Nonce=" + parsed.nonce);

            // 自适应根：sha1→rsa_sha1/ecc_sha1 随机；sha256/sha384/sha512/SHA3→rsa_sha256/ecc_sha256 随机；sm3→sm2_sm3 固定
            String hashName;
            if (Sm2Util.OID_SM3.equals(parsed.hashAlgOid)) {
                hashName = "sm3";
            } else if (SHA1_OID.equals(parsed.hashAlgOid)) {
                hashName = "sha1";
            } else if ("2.16.840.1.101.3.4.2.2".equals(parsed.hashAlgOid)) {
                hashName = "sha384";
            } else if ("2.16.840.1.101.3.4.2.3".equals(parsed.hashAlgOid)) {
                hashName = "sha512";
            } else if ("2.16.840.1.101.3.4.2.7".equals(parsed.hashAlgOid)) {
                hashName = "sha3-224";
            } else if ("2.16.840.1.101.3.4.2.8".equals(parsed.hashAlgOid)) {
                hashName = "sha3-256";
            } else if ("2.16.840.1.101.3.4.2.9".equals(parsed.hashAlgOid)) {
                hashName = "sha3-384";
            } else if ("2.16.840.1.101.3.4.2.10".equals(parsed.hashAlgOid)) {
                hashName = "sha3-512";
            } else {
                hashName = "sha256";
            }
            String[] tsaPaths = pickTSACert(hashName);

            X509Certificate tsaCert = PemIO.readCert(baseDir + "/" + tsaPaths[0]);
            PrivateKey tsaKey = CertUtil.readJcaPrivateKey(baseDir + "/" + tsaPaths[1]);
            String keyType = PemIO.detectKeyType(baseDir + "/" + tsaPaths[1]);

            // 通过 TSA 证书序列号找颁发者，加载颁发者证书进证书链（多根模型：按序列号从 ROOT/CA 目录加载）
            // 每次请求前重新加载 CERTS.txt，保持与磁盘最新状态一致
            db.reload();
            // RSA-PSS：TSA 证书私钥物理为 RSA，文件无法区分，须按 CERTS.txt 登记算法判断
            CertsDB.CertEntry tsaDb = db.findBySerial(tsaCert.getSerialNumber().toString(16));
            if (tsaDb != null && "RSA-PSS".equalsIgnoreCase(tsaDb.algo)) {
                keyType = "RSA-PSS";
            }
            String issuerId = db.findIssuerIdBySerial(tsaCert.getSerialNumber().toString(16));
            X509Certificate issuerCert;
            if (issuerId != null && !"null".equals(issuerId) && !issuerId.isEmpty()) {
                String p = findExisting("PKI/ROOT/" + issuerId + ".crt", "PKI/CA/" + issuerId + ".crt");
                issuerCert = PemIO.readCert(baseDir + "/" + p);
            } else {
                throw new IllegalStateException("TSA 证书未在 CERTS.txt 登记颁发者: "
                        + tsaCert.getSerialNumber().toString(16));
            }

            // 构造签名器与摘要计算器
            ContentSigner signer;
            DigestCalculator digestCalc;
            String signHashName = hashName;
            if ("SM2".equalsIgnoreCase(keyType)) {
                // SM2：签名摘要与回传 hashAlgorithm 都按 SM3（GB/T 32918）
                ECPrivateKeyParameters sm2Priv = Sm2Util.toEcPrivateParams(tsaKey);
                signer = new CertUtil.SM2ContentSigner(sm2Priv);
                digestCalc = new TimestampUtil.SM3DigestCalculator();
                signHashName = "sm3";
            } else {
                String jcaHash = jcaHashName(hashName);
                String jcaSigAlg;
                if ("RSA-PSS".equalsIgnoreCase(keyType)) {
                    // RSASSA-PSS：签名算法标识带 PSS 参数，符合 RFC 3161 时间戳标准
                    jcaSigAlg = jcaHash + "withRSAandMGF1";
                } else {
                    jcaSigAlg = jcaHash + "with" + ("ECC".equalsIgnoreCase(keyType) ? "ECDSA" : "RSA");
                }
                signer = new JcaContentSignerBuilder(jcaSigAlg)
                        .setProvider("BC").build(tsaKey);
                // 摘要计算器直接用请求中的 messageImprint 算法标识（含 NULL 参数，
                // 与请求完全一致，否则 BC 会以 "request contains unknown algorithm" 拒绝）
                AlgorithmIdentifier digestAlgId =
                        new org.bouncycastle.tsp.TimeStampRequest(body).getMessageImprintAlgID();
                digestCalc = new JcaDigestCalculatorProviderBuilder()
                        .setProvider("BC").build().get(digestAlgId);
            }

            // 证书链必须包含 TSA 证书本身 + 颁发者证书
            // （BC 用 ESS signingCert 属性校验签名者证书哈希）
            List<X509Certificate> chain = new java.util.ArrayList<>();
            chain.add(tsaCert);
            if (!issuerCert.getSubjectX500Principal()
                    .equals(tsaCert.getSubjectX500Principal())) {
                chain.add(issuerCert);
            }
            byte[] response = TimestampUtil.createRfc3161Response(
                    body, tsaCert, chain, signer, digestCalc);

            String digestHex = sha1Hex(parsed.messageImprint);
            log("时间戳签名 RFC3161文档签名 " + signHashName.toUpperCase() + " "
                    + digestHex + " TSA证书 " + tsaPaths[0]);
            MLog.append(baseDir, "时间戳签名(RFC3161)", "算法=" + signHashName
                    + " TSA证书=" + tsaCert.getSubjectX500Principal() + " 摘要=" + digestHex);
            writeFile("PKI/TIMSTAMP/log/rfc3161" + digestHex + ".req", body);
            writeFile("PKI/TIMSTAMP/log/rfc3161" + digestHex + ".res", response);

            sendBytes(ex, response, "application/timestamp-reply");
            MLog.append(baseDir, "时间戳响应(RFC3161)", "长度=" + response.length + "字节");
        } catch (Exception e) {
            MLog.append(baseDir, "时间戳处理异常(RFC3161)", "错误=" + e);
            System.err.println("RFC3161 处理异常: " + e);
            ex.sendResponseHeaders(500, -1);
            ex.close();
        }
    }


    // ============================================================
    // CT 日志服务（RFC 6962 / Certificate Transparency，/ct/add）
    // ============================================================

    /**
     * /ct/add：仅接受 POST。请求体 = PEM 预证书（含 poison 扩展）+ PEM 颁发者（中间）证书。
     * 按 RFC 6962 §3.1/§3.2 构造 precert_entry 签名输入，用 PKI/CTLOG/modpkica_ct_list.json
     * 中全部 usable 日志密钥 ECDSA-P256 签名，返回 SCTList（TLS 编码，二进制），
     * 可直接作为证书 1.3.6.1.4.1.11129.2.4.2 扩展的 OCTET STRING 内容。
     * 每条密钥签发追加一行 PKI/CTLOG/ctlogs.txt 请求日志。
     */
    private static void handleCtAdd(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            sendText(ex, 200, "CT Log /ct/add: 仅支持 POST 方式（PEM 预证书 + PEM 颁发者证书）");
            return;
        }
        byte[] req = readAll(ex.getRequestBody());
        String remote = ex.getRemoteAddress() != null
                ? ex.getRemoteAddress().getAddress().getHostAddress() : "?";
        MLog.append(baseDir, "收到CTLog请求",
                "来源=" + remote + " 路径=/ct/add 长度=" + req.length + "字节");
        try {
            java.util.List<X509Certificate> chain = CtLog.parsePemCerts(req);
            if (chain.size() < 2) {
                throw new IOException("请求体需要两个 PEM 证书块：预证书 + 颁发者（中间）证书，实际解析到 "
                        + chain.size() + " 个");
            }
            X509Certificate precert = chain.get(0);
            X509Certificate issuer = chain.get(1);

            // RFC 6962 hardening (no auth by design):
            // 1) precert.issuer must equal issuer.subject
            if (!precert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                throw new IOException("precert issuer does not match submitted issuer cert: precert.issuer="
                        + precert.getIssuerX500Principal() + " issuer.subject=" + issuer.getSubjectX500Principal());
            }
            // 2) precert MUST carry the poison extension (RFC 6962 SS3.1)
            if (precert.getExtensionValue(CtLog.OID_POISON) == null) {
                throw new IOException("precert missing poison extension " + CtLog.OID_POISON);
            }
            // 3) precert signature must verify with the submitted issuer public key
            try {
                precert.verify(issuer.getPublicKey(), "BC");
            } catch (Exception ve) {
                throw new IOException("precert signature verification failed with issuer public key: " + ve);
            }

            // RFC 6962 §3.1：tbs_certificate = 预证书 TBS 删除 poison 扩展
            byte[] tbs = CtLog.tbsWithoutPoison(precert);
            // issuer_key_hash = SHA-256(颁发者公钥 SPKI DER)
            byte[] issuerKeyHash = CtLog.sha256(issuer.getPublicKey().getEncoded());

            // 按预证书类型随机选出最多 3 组 usable 日志密钥（SM2 预证书→SM2 密钥；RSA/ECDSA→RSA/ECDSA）
            boolean sm2Precert = CtLog.isSm2Precert(precert);
            java.util.List<CtLog.LogKey> pool = CtLog.pickLogKeys(baseDir, sm2Precert);
            byte[] sctList = CtLog.signSctList(baseDir, tbs, issuerKeyHash, pool);

            // 请求日志：SCT待签名数据SHA256 || 毫秒时间戳 || 使用者SKI || 颁发者AKI || 日志公钥ID(base64)
            String userSki = CtLog.extHex(precert, "2.5.29.14");
            String issuerAki = CtLog.extHex(precert, "2.5.29.35");
            StringBuilder l = new StringBuilder();
            boolean first = true;
            for (CtLog.LogKey k : pool) {
                long ts = System.currentTimeMillis();
                byte[] input = CtLog.buildSctInput(ts, tbs, issuerKeyHash);
                if (!first) {
                    l.append('\n');
                }
                l.append(CtLog.toHex(CtLog.sha256(input))).append("||").append(ts).append("||")
                        .append(userSki).append("||").append(issuerAki).append("||").append(k.logId);
                first = false;
            }
            if (l.length() > 0) {
                CtLog.appendRequestLog(baseDir, l.toString());
            }

            log("CTLog /ct/add 预证书=" + precert.getSubjectX500Principal()
                    + " 类型=" + (sm2Precert ? "SM2" : "RSA/ECDSA")
                    + " 密钥组数=" + pool.size() + " 签发SCT列表 " + sctList.length + "字节");
            MLog.append(baseDir, "CTLog签发SCT列表",
                    "预证书=" + precert.getSubjectX500Principal() + " 颁发者="
                            + issuer.getSubjectX500Principal()
                            + " 类型=" + (sm2Precert ? "SM2" : "RSA/ECDSA") + " 密钥组数=" + pool.size(),
                    "SCT列表=" + sctList.length + "字节，已写入 ctlogs.txt");
            sendBytes(ex, sctList, "application/octet-stream");
        } catch (Exception e) {
            MLog.appendErr(baseDir, "CTLog请求异常", "路径=/ct/add 长度=" + req.length,
                    String.valueOf(e));
            log("CTLog 请求处理异常: " + e);
            sendText(ex, 400, "CT Log 错误: " + e.getMessage());
        }
    }

    // ============================================================
    // RFC 6962 标准 HTTP API（/ct/v1/*，新增，不影响现有 /ct/add）
    // 接口：add-chain / add-pre-chain / get-sth / get-roots / get-entries /
    //       get-proof-by-hash / get-sth-consistency / get-entry-and-proof
    // 所有响应均为 JSON（application/json），错误返回 4xx/5xx + 人类可读消息。
    // ============================================================

    /** /ct/v1 统一分发入口。 */
    private static void handleCtV1(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        try {
            switch (path) {
                case "/ct/v1/add-chain":          handleCtAddChain(ex); break;
                case "/ct/v1/add-pre-chain":      handleCtAddPreChain(ex); break;
                case "/ct/v1/get-sth":            handleCtGetSth(ex); break;
                case "/ct/v1/get-roots":          handleCtGetRoots(ex); break;
                case "/ct/v1/get-entries":        handleCtGetEntries(ex); break;
                case "/ct/v1/get-proof-by-hash":  handleCtGetProofByHash(ex); break;
                case "/ct/v1/get-sth-consistency":handleCtGetConsistency(ex); break;
                case "/ct/v1/get-entry-and-proof":handleCtGetEntryAndProof(ex); break;
                default:
                    sendJson(ex, 404, "{\"error\":\"unknown CT v1 endpoint: " + path + "\"}");
            }
        } catch (IOException e) {
            // 请求校验/业务错误：RFC 6962 §4 约定 4xx 客户端错误
            MLog.appendErr(baseDir, "CTLog v1 API 异常", path, String.valueOf(e.getMessage()));
            log("CTLog v1 API 异常: " + e.getMessage());
            sendJson(ex, 400, "{\"error\":\"" + jsonEscape(String.valueOf(e.getMessage())) + "\"}");
        } catch (Exception e) {
            MLog.appendErr(baseDir, "CTLog v1 API 异常", path, String.valueOf(e));
            log("CTLog v1 API 异常: " + e);
            sendJson(ex, 500, "{\"error\":\"" + jsonEscape(String.valueOf(e.getMessage())) + "\"}");
        }
    }

    /** POST /ct/v1/add-chain：提交正式证书链，返回该日志的 SCT（RFC 6962 §4.1）。 */
    private static void handleCtAddChain(HttpExchange ex) throws Exception {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            sendJson(ex, 405, "{\"error\":\"add-chain requires POST\"}");
            return;
        }
        String body = new String(readAll(ex.getRequestBody()), StandardCharsets.UTF_8);
        java.util.Map<String, Object> root = CtLog.MiniJson.parse(body);
        java.util.List<byte[]> chainDer = parseB64Chain(root.get("chain"));
        List<X509Certificate> chain = derToCerts(chainDer);
        if (chain.size() < 1) {
            throw new IOException("chain 数组为空");
        }
        // RFC 6962：add-chain 不接受预证书（含 poison 扩展的必须是 add-pre-chain）
        if (chain.get(0).getExtensionValue(CtLog.OID_POISON) != null) {
            throw new IOException("该证书含 poison 扩展（预证书），请使用 add-pre-chain 接口");
        }
        verifyChainLinks(chain);
        X509Certificate leaf = chain.get(0);
        boolean sm2 = CtLog.isSm2Precert(leaf);
        String lid = queryParam(ex, "log_id");
        CtLog.LogKey k = lid.isEmpty() ? pickFreshLogKey(baseDir, sm2)
                : resolveLogKey(baseDir, lid, sm2);
        long ts = System.currentTimeMillis();
        CtLog.saveRawCert(baseDir, chainDer.get(0), ts);   // 保存提交的原始正式证书副本
        CtLog.SctOutcome out = CtLog.signOneSct(baseDir, k, 0, ts, null, null, chainDer);
        MLog.append(baseDir, "CTLog add-chain",
                "日志=" + k.description + " log_id=" + k.logId + " 叶子=" + leaf.getSubjectX500Principal(),
                "已签发 SCT timestamp=" + ts + "，并追加到 Merkle 树");
        log("CTLog v1 add-chain 叶子=" + leaf.getSubjectX500Principal()
                + " 日志=" + k.description + " SCT=" + Base64.getEncoder().encodeToString(out.signature).length() + "字节");
        sendJson(ex, 200, "{\"sct_version\":0,\"id\":\"" + k.logId
                + "\",\"timestamp\":" + ts
                + ",\"extensions\":\"\",\"signature\":\""
                + Base64.getEncoder().encodeToString(out.signature)
                + "\",\"type\":\"" + k.type + "\"}");
    }

    /** POST /ct/v1/add-pre-chain：提交预证书链，返回该日志的 SCT（RFC 6962 §4.2）。 */
    private static void handleCtAddPreChain(HttpExchange ex) throws Exception {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            sendJson(ex, 405, "{\"error\":\"add-pre-chain requires POST\"}");
            return;
        }
        String body = new String(readAll(ex.getRequestBody()), StandardCharsets.UTF_8);
        java.util.Map<String, Object> root = CtLog.MiniJson.parse(body);
        java.util.List<byte[]> chainDer = parseB64Chain(root.get("chain"));
        List<X509Certificate> chain = derToCerts(chainDer);
        if (chain.size() < 2) {
            throw new IOException("add-pre-chain 至少需要预证书 + 颁发者两个证书");
        }
        X509Certificate precert = chain.get(0);
        if (precert.getExtensionValue(CtLog.OID_POISON) == null) {
            throw new IOException("precert missing poison extension " + CtLog.OID_POISON
                    + "（正式证书请使用 add-chain 接口）");
        }
        verifyChainLinks(chain);
        // RFC 6962 §3.1：tbs_certificate = 预证书 TBS 删除 poison 扩展
        byte[] tbs = CtLog.tbsWithoutPoison(precert);
        byte[] issuerKeyHash = CtLog.sha256(chain.get(1).getPublicKey().getEncoded());
        boolean sm2 = CtLog.isSm2Precert(precert);
        String lid = queryParam(ex, "log_id");
        CtLog.LogKey k = lid.isEmpty() ? pickFreshLogKey(baseDir, sm2)
                : resolveLogKey(baseDir, lid, sm2);
        long ts = System.currentTimeMillis();
        CtLog.saveRawCert(baseDir, chainDer.get(0), ts);   // 保存提交的原始预证书副本
        CtLog.SctOutcome out = CtLog.signOneSct(baseDir, k, 1, ts, tbs, issuerKeyHash, chainDer);
        MLog.append(baseDir, "CTLog add-pre-chain",
                "日志=" + k.description + " log_id=" + k.logId + " 预证书=" + precert.getSubjectX500Principal(),
                "已签发 SCT timestamp=" + ts + "，并追加到 Merkle 树");
        log("CTLog v1 add-pre-chain 预证书=" + precert.getSubjectX500Principal()
                + " 日志=" + k.description);
        sendJson(ex, 200, "{\"sct_version\":0,\"id\":\"" + k.logId
                + "\",\"timestamp\":" + ts
                + ",\"extensions\":\"\",\"signature\":\""
                + Base64.getEncoder().encodeToString(out.signature)
                + "\",\"type\":\"" + k.type + "\"}");
    }

    /** GET /ct/v1/get-sth：最新签名树头（RFC 6962 §4.3）。可选 ?log_id= 指定日志，默认第一个 usable。 */
    private static void handleCtGetSth(HttpExchange ex) throws Exception {
        CtLog.LogKey k = resolveLogKey(baseDir, queryParam(ex, "log_id"), false);
        List<CtLog.TreeEntry> es = CtLog.loadTreeEntries(baseDir, k.logId);
        List<byte[]> hashes = new java.util.ArrayList<>();
        for (CtLog.TreeEntry e : es) {
            hashes.add(CtLog.leafHash(Base64.getDecoder().decode(e.leafInput)));
        }
        long ts = es.isEmpty() ? System.currentTimeMillis()
                : CtLog.treeEntryTimestamp(Base64.getDecoder().decode(es.get(es.size() - 1).leafInput));
        byte[] root = CtLog.mthRoot(hashes);
        byte[] sig = CtLog.treeHeadSignature(k, ts, root);
        sendJson(ex, 200, "{\"tree_size\":" + es.size()
                + ",\"timestamp\":" + ts
                + ",\"sha256_root_hash\":\"" + Base64.getEncoder().encodeToString(root)
                + "\",\"tree_head_signature\":\"" + Base64.getEncoder().encodeToString(sig)
                + "\",\"log_id\":\"" + k.logId + "\"}");
    }

    /** GET /ct/v1/get-roots：日志接受的根证书（RFC 6962 §4.7，来自 CERTS.txt type=R）。 */
    private static void handleCtGetRoots(HttpExchange ex) throws Exception {
        StringBuilder arr = new StringBuilder("{\"certificates\":[");
        boolean first = true;
        for (CertsDB.CertEntry e : db.getAll()) {
            if (e.type != 'R') {
                continue;
            }
            Path p = Paths.get(baseDir, "PKI", "ROOT", e.serial + ".crt");
            if (!Files.exists(p)) {
                continue;
            }
            byte[] der = Files.readAllBytes(p);
            // ROOT 目录 .crt 可能为 PEM（-----BEGIN CERTIFICATE-----），RFC 6962 §4.7 要求 DER
            if (der.length > 0 && der[0] == '-' && new String(der, 0,
                    Math.min(der.length, 28), StandardCharsets.US_ASCII).contains("-----BEGIN")) {
                der = X509JsonConverter.pemToDer(der);
            }
            if (!first) {
                arr.append(',');
            }
            arr.append('"').append(Base64.getEncoder().encodeToString(der)).append('"');
            first = false;
        }
        arr.append("]}");
        sendJson(ex, 200, arr.toString());
    }

    /** GET /ct/v1/get-entries：批量取日志条目（RFC 6962 §4.6）。可选 ?log_id=。 */
    private static void handleCtGetEntries(HttpExchange ex) throws Exception {
        int start = intParam(ex, "start", 0);
        int end = intParam(ex, "end", -1);
        CtLog.LogKey k = resolveLogKey(baseDir, queryParam(ex, "log_id"), false);
        List<CtLog.TreeEntry> es = CtLog.loadTreeEntries(baseDir, k.logId);
        if (end < 0) {
            end = es.size() - 1;
        }
        if (start < 0 || start >= es.size() || end < start) {
            throw new IOException("无效范围 start=" + start + " end=" + end + "（tree_size=" + es.size() + "）");
        }
        // RFC：允许 end >= tree_size 时返回部分（截断到有效区间）
        if (end >= es.size()) {
            end = es.size() - 1;
        }
        StringBuilder arr = new StringBuilder("{\"entries\":[");
        for (int i = start; i <= end; i++) {
            CtLog.TreeEntry e = es.get(i);
            if (i > start) {
                arr.append(',');
            }
            arr.append("{\"leaf_input\":\"").append(e.leafInput)
                    .append("\",\"extra_data\":\"").append(e.extraData).append("\"}");
        }
        arr.append("]}");
        sendJson(ex, 200, arr.toString());
    }

    /** GET /ct/v1/get-proof-by-hash：按叶子哈希取审计证明（RFC 6962 §4.5）。可选 ?log_id=。 */
    private static void handleCtGetProofByHash(HttpExchange ex) throws Exception {
        String hashB64 = queryParam(ex, "hash");
        if (hashB64.isEmpty()) {
            throw new IOException("缺少 hash 参数（base64 叶子哈希）");
        }
        int treeSize = intParam(ex, "tree_size", -1);
        CtLog.LogKey k = resolveLogKey(baseDir, queryParam(ex, "log_id"), false);
        List<CtLog.TreeEntry> es = CtLog.loadTreeEntries(baseDir, k.logId);
        if (treeSize < 0 || treeSize > es.size()) {
            treeSize = es.size();
        }
        List<byte[]> hashes = new java.util.ArrayList<>();
        for (CtLog.TreeEntry e : es) {
            hashes.add(CtLog.leafHash(Base64.getDecoder().decode(e.leafInput)));
        }
        byte[] target = Base64.getDecoder().decode(hashB64);
        int idx = -1;
        for (int i = 0; i < treeSize; i++) {
            if (java.util.Arrays.equals(hashes.get(i), target)) {
                idx = i;
                break;
            }
        }
        if (idx < 0) {
            throw new IOException("hash 未在日志中找到（tree_size=" + treeSize + "）");
        }
        List<byte[]> path = CtLog.auditPath(hashes.subList(0, treeSize), idx);
        StringBuilder arr = new StringBuilder("{\"leaf_index\":" + idx + ",\"audit_path\":[");
        for (int i = 0; i < path.size(); i++) {
            if (i > 0) {
                arr.append(',');
            }
            arr.append('"').append(Base64.getEncoder().encodeToString(path.get(i))).append('"');
        }
        arr.append("]}");
        sendJson(ex, 200, arr.toString());
    }

    /** GET /ct/v1/get-sth-consistency：两棵树头间一致性证明（RFC 6962 §4.4）。可选 ?log_id=。 */
    private static void handleCtGetConsistency(HttpExchange ex) throws Exception {
        int first = intParam(ex, "first", -1);
        int second = intParam(ex, "second", -1);
        CtLog.LogKey k = resolveLogKey(baseDir, queryParam(ex, "log_id"), false);
        List<CtLog.TreeEntry> es = CtLog.loadTreeEntries(baseDir, k.logId);
        if (first < 0 || second < 0 || first > second || second > es.size()) {
            throw new IOException("无效范围 first=" + first + " second=" + second + "（tree_size=" + es.size() + "）");
        }
        List<byte[]> hashes = new java.util.ArrayList<>();
        for (CtLog.TreeEntry e : es) {
            hashes.add(CtLog.leafHash(Base64.getDecoder().decode(e.leafInput)));
        }
        List<byte[]> proof = CtLog.consistencyProof(hashes, first, second);
        StringBuilder arr = new StringBuilder("{\"consistency\":[");
        for (int i = 0; i < proof.size(); i++) {
            if (i > 0) {
                arr.append(',');
            }
            arr.append('"').append(Base64.getEncoder().encodeToString(proof.get(i))).append('"');
        }
        arr.append("]}");
        sendJson(ex, 200, arr.toString());
    }

    /** GET /ct/v1/get-entry-and-proof：按索引取条目 + 审计证明（RFC 6962 §4.8）。可选 ?log_id=。 */
    private static void handleCtGetEntryAndProof(HttpExchange ex) throws Exception {
        int leafIndex = intParam(ex, "leaf_index", -1);
        int treeSize = intParam(ex, "tree_size", -1);
        CtLog.LogKey k = resolveLogKey(baseDir, queryParam(ex, "log_id"), false);
        List<CtLog.TreeEntry> es = CtLog.loadTreeEntries(baseDir, k.logId);
        if (treeSize < 0 || treeSize > es.size()) {
            treeSize = es.size();
        }
        if (leafIndex < 0 || leafIndex >= treeSize) {
            throw new IOException("无效 leaf_index=" + leafIndex + "（tree_size=" + treeSize + "）");
        }
        CtLog.TreeEntry e = es.get(leafIndex);
        List<byte[]> hashes = new java.util.ArrayList<>();
        for (CtLog.TreeEntry x : es) {
            hashes.add(CtLog.leafHash(Base64.getDecoder().decode(x.leafInput)));
        }
        List<byte[]> path = CtLog.auditPath(hashes.subList(0, treeSize), leafIndex);
        StringBuilder arr = new StringBuilder("{\"leaf_input\":\"").append(e.leafInput)
                .append("\",\"extra_data\":\"").append(e.extraData)
                .append("\",\"audit_path\":[");
        for (int i = 0; i < path.size(); i++) {
            if (i > 0) {
                arr.append(',');
            }
            arr.append('"').append(Base64.getEncoder().encodeToString(path.get(i))).append('"');
        }
        arr.append("]}");
        sendJson(ex, 200, arr.toString());
    }

    /** 解析 add-chain/add-pre-chain 的 chain 数组（base64 DER 证书）。 */
    private static java.util.List<byte[]> parseB64Chain(Object chainObj) throws IOException {
        if (!(chainObj instanceof java.util.List)) {
            throw new IOException("chain 必须是 base64 证书数组");
        }
        java.util.List<byte[]> out = new java.util.ArrayList<>();
        for (Object o : (java.util.List<?>) chainObj) {
            String b64 = CtLog.MiniJson.strVal(o);
            if (b64 == null || b64.isEmpty()) {
                throw new IOException("chain 中存在空证书项");
            }
            try {
                out.add(Base64.getDecoder().decode(b64));
            } catch (Exception e) {
                throw new IOException("chain 中 base64 解码失败: " + e);
            }
        }
        return out;
    }

    /** DER 字节列表 → X509Certificate 列表。 */
    private static List<X509Certificate> derToCerts(java.util.List<byte[]> ders) throws Exception {
        List<X509Certificate> out = new java.util.ArrayList<>();
        for (byte[] der : ders) {
            out.add(new JcaX509CertificateConverter().setProvider("BC")
                    .getCertificate(new X509CertificateHolder(der)));
        }
        return out;
    }

    /** 校验链的颁发者-使用者关系与逐级签名（RFC 6962 §4.1 链校验）。 */
    private static void verifyChainLinks(List<X509Certificate> chain) throws IOException {
        for (int i = 0; i + 1 < chain.size(); i++) {
            X509Certificate c = chain.get(i);
            X509Certificate p = chain.get(i + 1);
            if (!c.getIssuerX500Principal().equals(p.getSubjectX500Principal())) {
                throw new IOException("chain[" + i + "] 颁发者与 chain[" + (i + 1) + "] 使用者不匹配："
                        + c.getIssuerX500Principal() + " != " + p.getSubjectX500Principal());
            }
            try {
                c.verify(p.getPublicKey(), "BC");
            } catch (Exception ve) {
                throw new IOException("chain[" + i + "] 签名验证失败（用 chain[" + (i + 1) + "] 公钥）: " + ve);
            }
        }
    }

    /**
     * 解析日志密钥：优先 ?log_id= 精确匹配；否则选第一个 usable 且类型匹配
     * （sm2Only 时只选 SM2）的密钥。无可用密钥抛异常。
     */
    private static CtLog.LogKey resolveLogKey(String baseDir, String logIdParam, boolean sm2Only)
            throws IOException {
        List<CtLog.LogKey> keys = CtLog.loadKeys(baseDir);
        if (!logIdParam.isEmpty()) {
            for (CtLog.LogKey k : keys) {
                if (k.logId.equals(logIdParam)) {
                    if (!"usable".equals(k.state)) {
                        throw new IOException("指定日志密钥已暂停（disable）: " + logIdParam);
                    }
                    if (sm2Only && !"SM2".equalsIgnoreCase(k.type)) {
                        throw new IOException("预证书类型为 SM2，指定日志密钥类型不匹配: " + k.type);
                    }
                    return k;
                }
            }
            throw new IOException("log_id 未找到: " + logIdParam);
        }
        for (CtLog.LogKey k : keys) {
            if (!"usable".equals(k.state)) {
                continue;
            }
            if (sm2Only && !"SM2".equalsIgnoreCase(k.type)) {
                continue;
            }
            return k;
        }
        throw new IOException("没有 usable 的 CT 日志密钥，请先在「SCT服务管理」生成并启用密钥");
    }

    /** 最近已用于响应 SCT 的日志公钥 ID（保证连续多次 add-chain/add-pre-chain 请求用不同密钥）。 */
    private static final java.util.Set<String> recentSctLogIds =
            java.util.Collections.synchronizedSet(new java.util.LinkedHashSet<String>());

    /**
     * 随机选一组 usable 且类型匹配的日志密钥，尽量避开最近已响应的日志：
     * SM2 预证书只选 SM2 密钥，其他类型只选 RSA/ECDSA 密钥（禁用 SM2 日志密钥）。
     * 密钥池 ≥3 组时，连续 3 次调用必然返回 3 组不同密钥。
     */
    private static synchronized CtLog.LogKey pickFreshLogKey(String baseDir, boolean sm2Only)
            throws IOException {
        List<CtLog.LogKey> pool = CtLog.pickLogKeys(baseDir, sm2Only);
        if (pool.isEmpty()) {
            throw new IOException("没有 usable 且类型匹配的 CT 日志密钥，请先在「SCT服务管理」生成并启用密钥");
        }
        CtLog.LogKey chosen = pool.get(0);
        for (CtLog.LogKey k : pool) {
            if (!recentSctLogIds.contains(k.logId)) {
                chosen = k;
                break;
            }
        }
        recentSctLogIds.add(chosen.logId);
        if (recentSctLogIds.size() > 64) {
            // 保留最近 32 个，清掉最旧的 32 个
            java.util.Iterator<String> it = recentSctLogIds.iterator();
            for (int i = 0; i < 32 && it.hasNext(); i++) {
                it.next();
                it.remove();
            }
        }
        return chosen;
    }

    /** 读取 GET query 参数（无则返回空串）。 */
    private static String queryParam(HttpExchange ex, String name) {
        String q = ex.getRequestURI().getRawQuery();
        if (q == null || q.isEmpty()) {
            return "";
        }
        for (String pair : q.split("&")) {
            int eq = pair.indexOf('=');
            String k = eq >= 0 ? pair.substring(0, eq) : pair;
            String v = eq >= 0 ? pair.substring(eq + 1) : "";
            if (name.equals(k)) {
                try {
                    return java.net.URLDecoder.decode(v, StandardCharsets.UTF_8);
                } catch (Exception e) {
                    return v;
                }
            }
        }
        return "";
    }

    /** 读取 GET 整数参数，缺失/非法返回默认值。 */
    private static int intParam(HttpExchange ex, String name, int def) {
        String v = queryParam(ex, name);
        if (v.isEmpty()) {
            return def;
        }
        try {
            return Integer.parseInt(v);
        } catch (Exception e) {
            return def;
        }
    }

    /** 发送 JSON 响应。 */
    private static void sendJson(HttpExchange ex, int code, String json) throws IOException {
        byte[] msg = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(code, msg.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(msg);
        }
    }

    /** JSON 字符串字段转义（用于错误消息）。 */
    private static String jsonEscape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
    // ============================================================
    // 辅助函数
    // ============================================================

    /**
     * 自适应根选择 TSA 证书/私钥路径（对齐 Go 版 pickTSACert）。
     * sha1→rsa_sha1/ecc_sha1 随机；sha256→rsa_sha256/ecc_sha256 随机；sm3→sm2_sm3 固定。
     * 随机选中后若文件缺失则回退另一组。
     */
    private static String[] pickTSACert(String hash) {
        String dir = "PKI/TIMSTAMP/";
        if ("sm3".equals(hash)) {
            return new String[]{dir + "sm2_sm3.crt", dir + "sm2_sm3.key"};
        }
        String base = "sha1".equals(hash) ? "sha1" : "sha256";
        // 自适应根：rsa / ecc / rsa-pss 三组中随机选一组存在的
        String[][] groups = {
            {dir + "rsa_" + base + ".crt", dir + "rsa_" + base + ".key"},
            {dir + "ecc_" + base + ".crt", dir + "ecc_" + base + ".key"},
            {dir + "rsa-pss_" + base + ".crt", dir + "rsa-pss_" + base + ".key"}
        };
        java.util.List<String[]> cand = new java.util.ArrayList<>();
        for (String[] g : groups) {
            if (fileExists(g[0])) {
                cand.add(g);
            }
        }
        if (!cand.isEmpty()) {
            return cand.get(new Random().nextInt(cand.size()));
        }
        return groups[0]; // 都没有 → 回退 rsa（后续读取会给出明确报错）
    }

    private static boolean fileExists(String relPath) {
        return Files.exists(Paths.get(baseDir, relPath));
    }

    /** 按顺序找第一个存在的文件路径（相对 baseDir）。 */
    private static String findExisting(String... relPaths) {
        for (String p : relPaths) {
            if (fileExists(p)) {
                return p;
            }
        }
        return relPaths[relPaths.length - 1];
    }

    /** 最大请求体：8MB（OCSP/时间戳/CT 请求均远小于此，仅防内存 DoS）。 */
    private static final long MAX_BODY_BYTES = 8L * 1024 * 1024;

    /** 读取请求体全部字节（带上限，超限抛 IOException 拒绝）。 */
    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        long total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > MAX_BODY_BYTES) {
                throw new IOException("request body too large (limit " + MAX_BODY_BYTES + " bytes)");
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    /** 发送字节响应。 */
    private static void sendBytes(HttpExchange ex, byte[] data, String contentType)
            throws IOException {
        ex.getResponseHeaders().set("Content-Type", contentType);
        ex.getResponseHeaders().set("Content-Length", String.valueOf(data.length));
        ex.sendResponseHeaders(200, data.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(data);
        }
    }

    /** 发送文本响应。 */
    private static void sendText(HttpExchange ex, int code, String text) throws IOException {
        byte[] msg = text.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, msg.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(msg);
        }
    }

    /** 写文件（相对 baseDir，自动创建父目录）。synchronized：多线程下文件写串行化，
     *  避免 OCSP/时间戳/CT 的调试文件并发交错覆盖（Files.write 非原子）。 */
    private static synchronized void writeFile(String relPath, byte[] data) throws IOException {
        Path p = Paths.get(baseDir, relPath);
        Path parent = p.getParent();
        if (parent != null && !Files.exists(parent)) {
            Files.createDirectories(parent);
        }
        Files.write(p, data);
    }

    /** SHA-1 十六进制。 */
    private static String sha1Hex(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return toHex(md.digest(data));
    }

    /** 字节 → 小写十六进制。 */
    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    /** 在 data 中找子串最后一次出现的位置。 */
    private static int lastIndexOf(byte[] data, byte[] needle) {
        outer:
        for (int i = data.length - needle.length; i >= 0; i--) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /** 控制台请求日志（前缀时间；安静模式下静默，日志仍完整写入 PKI/logs.log）。 */
    private static void log(String msg) {
        if (QUIET) {
            return;
        }
        System.out.println(new java.text.SimpleDateFormat("yyyy/MM/dd HH:mm:ss")
                .format(new Date()) + " " + msg);
    }
}
