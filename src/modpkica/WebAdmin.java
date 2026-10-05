package modpkica;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

/**
 * WebAdmin —— 浏览器版可视化管理界面（对应 Go 版 admin 的图形化替代）。
 *
 * <p>监听 <b>127.0.0.1:8080</b>（可通过系统属性 -Dmodpkica.admin.port 修改，
 * -Dmodpkica.admin.bind 修改绑定地址），单页 GUI 展示 ADMIN 全部功能：
 * <ul>
 *   <li>仪表盘：MAIN 服务状态、运行时长、API 调用计数、日志行数</li>
 *   <li>证书库：CERTS.txt 全量展示</li>
 *   <li>签发根证书 / 签发证书 / 吊销证书 / CRL / OCSP / 时间戳 / 证书验证 / 初始化环境</li>
 *   <li>日志：PKI/logs.log 尾部实时查看</li>
 * </ul>
 *
 * <p>所有操作复用 Admin.doXxx 公共方法（与控制台行为完全一致），
 * 并写入 PKI/logs.log 操作日志。MAIN 启动时会自动拉起本服务；
 * 也可单独运行 java modpkica.WebAdmin。
 */
public final class WebAdmin {

    /** 默认端口 8080。 */
    private static final int DEFAULT_PORT = 8080;
    /** 默认绑定地址：仅本机回环（管理界面不暴露公网）。 */
    private static final String DEFAULT_BIND = "127.0.0.1";

    /** 注册 BC Provider（独立运行时也必须可用 SM2/SM3 等算法）。 */
    static {
        Bc.init();
    }

    /** MAIN 服务端口（同进程集成时由 MAIN 传入）。 */
    private static volatile String mainPort = "未运行";
    /** MAIN 是否同进程运行。 */
    private static volatile boolean mainRunning = false;
    /** 服务启动时间。 */
    private static volatile long startTime = System.currentTimeMillis();

    /** 总 API 调用次数。 */
    private static final AtomicLong TOTAL_CALLS = new AtomicLong();
    /** 各端点调用计数。 */
    private static final Map<String, Long> ENDPOINT_CALLS = new ConcurrentHashMap<>();

    private static volatile String baseDir = AppPaths.baseDir();
    private static HttpServer server;

    /** RADIUS 服务（UDP 认证 1812 / 计费 1813，面板启停，用户库 PKI/USERS.txt）。 */
    private static final RadiusServer RADIUS = new RadiusServer(AppPaths.baseDir());

    /** PPPoE 服务（RFC 2516，Discovery/UDP 512 + Session/UDP 513 模拟，认证复用 PKI/USERS.txt）。 */
    private static final PPPoEServer PPPOE = new PPPoEServer(AppPaths.baseDir());

    private WebAdmin() {
    }

    /** 独立启动入口：java modpkica.WebAdmin。 */
    public static void main(String[] args) throws Exception {
        baseDir = AppPaths.baseDir();
        ensureSuportConfig();
        probeMain();
        start(mainPort);
        System.out.println("WebAdmin 管理界面已启动: http://localhost:" + port());
        System.out.println("（Ctrl+C 停止）");
    }

    /**
     * 确保 PKI/CONFIG.txt 存在且含管理界面端口项（SUPORT）。
     * 文件不存在 → 创建默认模板（含 SUPORT=8080）；存在但无 SUPORT 项 → 追加 SUPORT=8080。
     */
    private static void ensureSuportConfig() {
        try {
            Path f = Paths.get(baseDir, "PKI", "CONFIG.txt");
            if (!Files.exists(f)) {
                Files.createDirectories(f.getParent());
                String tpl = "WEBPORT=80\r\n"
                        + "SUPORT=8080\r\n"
                        + "OCSP=http://localhost:80/OCSP\r\n"
                        + "CRL=http://localhost:80/CRL/{CID}.crl\r\n"
                        + "CRT=http://localhost:80/CRT/{CID}.crt\r\n"
                        + "CPS=https://gitee.com/wxgshuju/modpkica\r\n"
                        + "CPS_Nonice=http://example.com/nonice\r\n"
                        + "CTLOGapi=/ct/add\r\n"
                        + "RADIUSPORT=1812\r\n"
                        + "RADIUSACCT=1813\r\n"
                        + "RADIUSKEY=mytestkey\r\n"
                        + "RADIUSAUTO=off\r\n";
                Files.write(f, tpl.getBytes(StandardCharsets.UTF_8));
                return;
            }
            // 已存在：补齐缺失的 RADIUS 配置键（保留注释与未知键）
            java.util.List<String> lines = Files.readAllLines(f, StandardCharsets.UTF_8);
            java.util.Set<String> keys = new java.util.HashSet<>();
            for (String line : lines) {
                int idx = line.indexOf('=');
                if (idx > 0) {
                    keys.add(line.substring(0, idx).trim());
                }
            }
            if (!keys.contains("RADIUSPORT") || !keys.contains("RADIUSACCT")
                    || !keys.contains("RADIUSKEY") || !keys.contains("RADIUSAUTO")) {
                StringBuilder sb = new StringBuilder();
                for (String line : lines) {
                    sb.append(line).append("\r\n");
                }
                if (!keys.contains("RADIUSPORT")) {
                    sb.append("RADIUSPORT=1812\r\n");
                }
                if (!keys.contains("RADIUSACCT")) {
                    sb.append("RADIUSACCT=1813\r\n");
                }
                if (!keys.contains("RADIUSKEY")) {
                    sb.append("RADIUSKEY=mytestkey\r\n");
                }
                if (!keys.contains("RADIUSAUTO")) {
                    sb.append("RADIUSAUTO=on\r\n");
                }
                Files.write(f, sb.toString().getBytes(StandardCharsets.UTF_8));
            }
            boolean hasSuport = false;
            for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#")) {
                    continue;
                }
                int idx = t.indexOf('=');
                if (idx > 0 && t.substring(0, idx).trim().equalsIgnoreCase("SUPORT")) {
                    hasSuport = true;
                    break;
                }
            }
            if (!hasSuport) {
                String all = new String(Files.readAllBytes(f), StandardCharsets.UTF_8);
                if (!all.endsWith("\n") && !all.endsWith("\r")) {
                    all += "\r\n";
                }
                Files.write(f, (all + "SUPORT=8080\r\n").getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) {
            // 配置写入失败不影响服务启动
        }
    }

    /** 读取 CONFIG.txt 的管理界面端口（SUPORT，大小写不敏感），缺省返回 8080。 */
    private static int readConfigAdminPort() {
        try {
            Path f = Paths.get(baseDir, "PKI", "CONFIG.txt");
            if (Files.exists(f)) {
                for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                    String t = line.trim();
                    if (t.isEmpty() || t.startsWith("#")) {
                        continue;
                    }
                    int idx = t.indexOf('=');
                    if (idx <= 0) {
                        continue;
                    }
                    if (t.substring(0, idx).trim().equalsIgnoreCase("SUPORT")) {
                        String v = t.substring(idx + 1).trim();
                        if (v.matches("\\d+")) {
                            int p = Integer.parseInt(v);
                            if (p > 0 && p <= 65535) {
                                return p;
                            }
                        }
                    }
                }
            }
        } catch (Exception ignore) {
            // 读取失败返回默认
        }
        return DEFAULT_PORT;
    }

    /** 独立启动时探测本机 MAIN 服务（CONFIG.txt WEBPORT，默认 80）是否在运行。 */
    private static volatile boolean integrated = false;

    /** 独立启动时探测本机 MAIN 服务（CONFIG.txt WEBPORT，默认 80）是否在运行。 */
    private static void probeMain() {
        int p = 0;
        String cfg = readConfigWebPort();
        if (cfg != null && cfg.matches("\\d+")) {
            p = Integer.parseInt(cfg);
        }
        if (p > 0 && canConnect(p)) {
            mainPort = String.valueOf(p);
            mainRunning = true;
        } else {
            mainPort = "未运行";
            mainRunning = false;
        }
    }

    /** 距上次探测的时间间隔（毫秒），避免每次状态请求都做 TCP 探测。 */
    private static volatile long lastProbeTime = 0;

    /** 状态接口调用时按需刷新 MAIN 探测结果（3 秒缓存）。集成模式不探测（WebAdmin 存活即 MAIN 存活）。 */
    private static void probeMainIfStale() {
        if (integrated) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - lastProbeTime < 3000) {
            return;
        }
        lastProbeTime = now;
        probeMain();
    }

    /** 尝试 TCP 连接本机端口，用于探测 MAIN 服务是否在运行。 */
    private static boolean canConnect(int port) {
        try (java.net.Socket s = new java.net.Socket()) {
            s.connect(new java.net.InetSocketAddress("127.0.0.1", port), 1000);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** 当前管理端口。 */
    public static int port() {
        return server != null ? server.getAddress().getPort() : DEFAULT_PORT;
    }

    /**
     * 启动 WebAdmin 管理服务（MAIN 启动时自动调用；端口被占用时静默跳过）。
     *
     * @param mainWebPort MAIN 的 WEBPORT（用于状态展示），可传 null
     */
    public static synchronized void start(String mainWebPort) {
        if (server != null) {
            return;
        }
        ensureSuportConfig();
        if (mainWebPort != null && mainWebPort.matches("\\d+")) {
            // 集成模式：WebAdmin 由 MAIN 同进程启动，WebAdmin 存活即代表 MAIN 存活，
            // 状态直接取自 MAIN 传入的端口，不再做 TCP 探测（避免瞬时探测失败误报"未运行"）。
            integrated = true;
            mainPort = mainWebPort;
            mainRunning = true;
        }
        // 端口优先级：系统属性 modpkica.admin.port（显式调试）→ CONFIG.txt SUPORT → 默认 8080
        String prop = System.getProperty("modpkica.admin.port");
        int port = (prop != null && prop.matches("\\d+"))
                ? Integer.parseInt(prop) : readConfigAdminPort();
        String bind = System.getProperty("modpkica.admin.bind", DEFAULT_BIND);
        // P2-03：默认仅绑定 127.0.0.1；显式绑定到非回环地址时给出警告（管理接口含签发/吊销/签名等写操作）
        if (!DEFAULT_BIND.equals(bind) && !"localhost".equalsIgnoreCase(bind)) {
            System.out.println("[WebAdmin] 警告：管理界面绑定地址 " + bind
                    + " 不是回环地址；若暴露到公网，所有 /api/* 写操作将无认证可访问！");
        }
        try {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getByName(bind), port), 0);
            server.createContext("/", WebAdmin::route);
            // 多线程执行器：读接口并发响应（大日志/慢请求不再阻塞其他请求）；
            // 写 PKI 数据的 API 在 handleApi 内通过 WRITE_LOCK 串行，避免文件竞争
            server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(8, r -> {
                Thread t = new Thread(r, "wa-worker");
                t.setDaemon(true);
                return t;
            }));
            server.start();
        } catch (Exception e) {
            // 端口被占用或绑定失败：不影响 MAIN 主服务，打印提示后跳过
            System.out.println("[WebAdmin] 管理界面启动失败（端口 " + port + " 可能被占用）: " + e.getMessage());
            server = null;
        }
    }

    // ============================================================
    // HTTP 路由
    // ============================================================

    private static void route(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        String method = ex.getRequestMethod();

        // 页面与静态资源
        if ("GET".equalsIgnoreCase(method) && "/".equals(path)) {
            sendText(ex, 200, "text/html; charset=utf-8", PAGE_HTML);
            return;
        }
        if ("GET".equalsIgnoreCase(method) && "/favicon.ico".equals(path)) {
            ex.sendResponseHeaders(204, -1);
            return;
        }

        // API
        if (path.startsWith("/api/")) {
            handleApi(ex);
            return;
        }

        sendJson(ex, 404, Map.of("ok", false, "message", "404: " + path));
    }

    /** 写 PKI 数据的管理 API（并发时串行执行，避免文件竞争）。
     *  注意：凡改动 CERTS.txt / myCERTS.txt / CONFIG.txt / modpkica_ct_list.json /
     *  log_list.json / CRL / OCSP / TIMSTAMP / 证书与私钥文件 的接口都必须在此登记，
     *  否则并发时与其它写操作发生文件竞争（tmp→move 互相覆盖）。 */
    private static final java.util.Set<String> WRITE_PATHS = java.util.Set.of(
            "/api/config", "/api/init", "/api/makeroot", "/api/signcert",
            "/api/revoke", "/api/restore", "/api/rekey", "/api/renew",
            "/api/crl", "/api/initocsp", "/api/inittimestamp",
            "/api/sign/exe", "/api/sign/pdf",
            "/api/my/import", "/api/my/delete",
            // 证书库删除（改 CERTS.txt 注释行）与 CT 日志密钥管理（写 modpkica_ct_list.json / 拉取 log_list.json）
            "/api/certs/delete",
            "/api/ctlog/gen", "/api/ctlog/delete",
            "/api/ctlog/enable", "/api/ctlog/pause", "/api/ctlog/publicFetch",
            // 模板管理（写 PKI/tamplate/data.json）
            "/api/template/save", "/api/template/delete", "/api/template/sign",
            // 用户管理（写 PKI/USERS.txt）与 RADIUS 服务启停 / 配置（写 CONFIG.txt）
            "/api/users/add", "/api/users/update", "/api/users/delete", "/api/users/status",
            "/api/radius/start", "/api/radius/stop", "/api/radius/config");

    /** 写操作全局锁：保证 PKI 文件（证书/私钥/CRL/CONFIG/日志）串行修改。 */
    private static final Object WRITE_LOCK = new Object();

    /** API 分发（多线程执行；写操作经 WRITE_LOCK 串行）。 */
    private static void handleApi(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        String method = ex.getRequestMethod();
        TOTAL_CALLS.incrementAndGet();
        ENDPOINT_CALLS.merge(path, 1L, Long::sum);
        if (WRITE_PATHS.contains(path)) {
            synchronized (WRITE_LOCK) {
                dispatchApi(ex, path, method);
            }
        } else {
            dispatchApi(ex, path, method);
        }
    }

    /** 实际 API 处理（原 switch 主体）。 */
    private static void dispatchApi(HttpExchange ex, String path, String method) throws IOException {
        try {
            switch (path) {
                case "/api/status":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, statusJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/certs":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, certsJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/certs/delete":
                    runAction(ex, m -> certsDelete(str(m, "serial")));
                    return;
                case "/api/certs/cacerts":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, cacertsJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/logs":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, logsJson(ex));
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/config":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, configJson());
                    } else if ("POST".equalsIgnoreCase(method)) {
                        saveConfig(ex);
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET/POST"));
                    }
                    return;
                case "/api/chain":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, chainJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/certjson":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, certJson(ex));
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/certchainjson":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, certChainJson(ex));
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/cert/download":
                    if ("GET".equalsIgnoreCase(method)) {
                        certDownload(ex);
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/cert/export":
                    if ("GET".equalsIgnoreCase(method)) {
                        certExport(ex);
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/version":
                    sendJson(ex, 200, Map.of("ok", true, "message", Admin.VERSION));
                    return;
                case "/api/issuers":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, issuersJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/init":
                    runAction(ex, m -> Admin.doInit(baseDir,
                            str(m, "dn"), str(m, "bits"), str(m, "hash"), str(m, "algo")));
                    return;
                case "/api/makeroot":
                    runAction(ex, m -> Admin.doMakeRoot(baseDir,
                            str(m, "dn"), str(m, "bits"), str(m, "hash"), str(m, "algo"),
                            str(m, "evoid")));
                    return;
                case "/api/signcert":
                    runAction(ex, m -> Admin.doSignCert(baseDir,
                            str(m, "dn"), str(m, "bits"), str(m, "hash"),
                            str(m, "keyusage"), str(m, "exusage"), str(m, "isca"),
                            str(m, "days"), str(m, "dns"), str(m, "ips"),
                            str(m, "issuer"), str(m, "algo"),
                            str(m, "pathlen"), str(m, "policy")));
                    return;
                case "/api/template/list":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, templateListJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/template/save":
                    runAction(ex, m -> templateSave(m));
                    return;
                case "/api/template/delete":
                    runAction(ex, m -> templateDelete(m));
                    return;
                case "/api/template/sign":
                    runAction(ex, m -> templateSign(m));
                    return;
                case "/api/revoke":
                    runAction(ex, m -> Admin.doRevoke(baseDir,
                            str(m, "serial"), str(m, "reason")));
                    return;
                case "/api/restore":
                    runAction(ex, m -> Admin.doRestore(baseDir, str(m, "serial")));
                    return;
                case "/api/debug/ocsp":
                    runAction(ex, m -> debugOcsp(str(m, "serial"), str(m, "hash")));
                    return;
                case "/api/debug/tsa":
                    runAction(ex, m -> debugTsa(str(m, "hash")));
                    return;
                case "/api/rekey":
                    runAction(ex, m -> rekeyAction(str(m, "serial")));
                    return;
                case "/api/renew":
                    runAction(ex, m -> renewAction(str(m, "serial"),
                            str(m, "notBefore"), str(m, "notAfter")));
                    return;
                case "/api/crl":
                    runAction(ex, m -> Admin.doSignCrl(baseDir));
                    return;
                case "/api/initocsp":
                    runAction(ex, m -> Admin.doInitOcsp(baseDir, str(m, "algo")));
                    return;
                case "/api/inittimestamp":
                    runAction(ex, m -> Admin.doInitTimestamp(baseDir, str(m, "hash")));
                    return;
                case "/api/verify":
                    runAction(ex, m -> Admin.doVerifyCert(baseDir, verifyTarget(str(m, "target"))));
                    return;
                case "/api/my/list":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, myListJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/my/import":
                    myImportAction(ex);
                    return;
                case "/api/my/delete":
                    runAction(ex, m -> myDelete(str(m, "serial")));
                    return;
                case "/api/verify/file":
                    verifyCertFileAction(ex);
                    return;
                case "/api/signcerts":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, signCertsJson(ex));
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/sign/exe":
                    signAction(ex, false);
                    return;
                case "/api/sign/pdf":
                    signAction(ex, true);
                    return;
                case "/api/verify/exe":
                    verifyAction(ex, false);
                    return;
                case "/api/verify/pdf":
                    verifyAction(ex, true);
                    return;
                case "/api/ctlog/list":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, ctlogListJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/ctlog/logs":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, ctlogLogsJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/ctlog/gen":
                    runAction(ex, m -> ctlogGen(str(m, "desc"), str(m, "type")));
                    return;
                case "/api/ctlog/delete":
                    runAction(ex, m -> ctlogDelete(str(m, "log_id")));
                    return;
                case "/api/ctlog/enable":
                    runAction(ex, m -> ctlogSetState(str(m, "log_id"), "usable"));
                    return;
                case "/api/ctlog/pause":
                    runAction(ex, m -> ctlogSetState(str(m, "log_id"), "disable"));
                    return;
                case "/api/ctlog/public":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, ctlogPublicJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/ctlog/publicFetch":
                    runAction(ex, m -> ctlogPublicFetch());
                    return;
                case "/api/ctlog/tree":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, ctlogTreeJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/ctlog/samplechain":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, ctlogSampleChainJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/ctlog/v1proxy":
                    runAction(ex, m -> ctlogV1Proxy(m));
                    return;
                // ===== 用户管理（PKI/USERS.txt） =====
                case "/api/users/list":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, usersListJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/users/add":
                    runAction(ex, m -> usersAdd(m));
                    return;
                case "/api/users/update":
                    runAction(ex, m -> usersUpdate(m));
                    return;
                case "/api/users/delete":
                    runAction(ex, m -> usersDelete(m));
                    return;
                case "/api/users/status":
                    runAction(ex, m -> usersSetState(m));
                    return;
                // ===== Radius 服务管理 =====
                case "/api/radius/status":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, radiusStatusJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/radius/logs":
                    if ("GET".equalsIgnoreCase(method)) {
                        String q = ex.getRequestURI().getQuery();
                        sendJson(ex, 200, radiusLogsJson(qp(q, "lines")));
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/radius/start":
                    runAction(ex, m -> radiusStart(m));
                    return;
                case "/api/radius/stop":
                    runAction(ex, m -> radiusStop());
                    return;
                case "/api/radius/reset":
                    runAction(ex, m -> radiusReset());
                    return;
                case "/api/radius/clearlogs":
                    runAction(ex, m -> radiusClearLogs());
                    return;
                case "/api/radius/config":
                    runAction(ex, m -> radiusSaveConfig(m));
                    return;
                case "/api/radius/dial":
                    runAction(ex, m -> radiusDial(m));
                    return;
                // ===== PPPoE 服务管理 =====
                case "/api/pppoe/status":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, pppoeStatusJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/pppoe/logs":
                    if ("GET".equalsIgnoreCase(method)) {
                        String q = ex.getRequestURI().getQuery();
                        sendJson(ex, 200, pppoeLogsJson(qp(q, "lines")));
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/pppoe/start":
                    runAction(ex, m -> pppoeStart(m));
                    return;
                case "/api/pppoe/stop":
                    runAction(ex, m -> pppoeStop());
                    return;
                case "/api/pppoe/reset":
                    runAction(ex, m -> pppoeReset());
                    return;
                case "/api/pppoe/clearlogs":
                    runAction(ex, m -> pppoeClearLogs());
                    return;
                case "/api/pppoe/config":
                    runAction(ex, m -> pppoeSaveConfig(m));
                    return;
                case "/api/pppoe/dial":
                    runAction(ex, m -> pppoeDial(m));
                    return;
                default:
                    sendJson(ex, 404, Map.of("ok", false, "message", "未知 API: " + path));
            }
        } catch (Exception e) {
            MLog.appendErr(baseDir, "WebAdmin API 异常", method + " " + path, String.valueOf(e));
            sendJson(ex, 500, Map.of("ok", false, "message", String.valueOf(e)));
        }
    }

    /** 执行一个管理动作：解析 JSON → 调用 doXxx → 返回输出。日志记录完整提交数据。 */
    private static void runAction(HttpExchange ex, ActionInvoker invoker) {
        try {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 POST"));
                return;
            }
            // P2-03：JSON 管理请求体上限 4MB（内存 DoS 防护）
            byte[] bodyBytes = readAll(ex.getRequestBody());
            if (bodyBytes.length > 4L * 1024 * 1024) {
                throw new IllegalArgumentException("JSON 请求体过大（上限 4MB）");
            }
            String bodyStr = new String(bodyBytes, StandardCharsets.UTF_8);
            Map<String, Object> m = parseJsonObject(bodyStr);
            String path = ex.getRequestURI().getPath();
            try {
                // 服务模式安静：管理动作（签发/吊销/CRL/TSA 等）执行期间
                // 不向服务控制台打印生成信息（避免刷屏/卡死），结果由前端展示并写入日志
                MakeCert.setQuiet(true);
                try {
                    String out = invoker.run(m);
                    // 完整命令 = 方法 + 路径 + 提交数据（JSON 原文，可视化）
                    MLog.append(baseDir, "WebAdmin " + path,
                            "POST " + path + " 提交数据=" + bodyStr, out);
                    sendJson(ex, 200, Map.of("ok", true, "message", out));
                } finally {
                    MakeCert.setQuiet(false);
                }
            } catch (Exception e) {
                MLog.appendErr(baseDir, "WebAdmin " + path + " 异常",
                        "POST " + path + " 提交数据=" + bodyStr, String.valueOf(e));
                sendJson(ex, 500, Map.of("ok", false, "message", String.valueOf(e)));
            }
        } catch (Exception e) {
            try {
                sendJson(ex, 400, Map.of("ok", false, "message",
                        "请求解析失败: " + e));
            } catch (Exception ignored) { }
        }
    }

    @FunctionalInterface
    private interface ActionInvoker {
        String run(Map<String, Object> params) throws Exception;
    }

    // ============================================================
    // 调试专区：模拟 OCSP / 时间戳请求（RFC 6960 / RFC 3161 标准构造与解析）
    // ============================================================

    /** 哈希名称 → 算法 OID。 */
    private static String hashOidOf(String name) {
        if (name == null) {
            return "2.16.840.1.101.3.4.2.1";
        }
        switch (name.toLowerCase()) {
            case "sha1":
                return "1.3.14.3.2.26";
            case "sha384":
                return "2.16.840.1.101.3.4.2.2";
            case "sha512":
                return "2.16.840.1.101.3.4.2.3";
            case "sm3":
                return Sm2Util.OID_SM3;
            case "sha3-224":
                return "2.16.840.1.101.3.4.2.7";
            case "sha3-256":
                return "2.16.840.1.101.3.4.2.8";
            case "sha3-384":
                return "2.16.840.1.101.3.4.2.9";
            case "sha3-512":
                return "2.16.840.1.101.3.4.2.10";
            case "sha256":
            default:
                return "2.16.840.1.101.3.4.2.1";
        }
    }

    /** 哈希名称 → JCA 摘要算法名。 */
    private static String jcaHashOf(String name) {
        if (name == null) {
            return "SHA-256";
        }
        switch (name.toLowerCase()) {
            case "sha1":
                return "SHA-1";
            case "sha384":
                return "SHA-384";
            case "sha512":
                return "SHA-512";
            case "sm3":
                return "SM3";
            case "sha3-224":
                return "SHA3-224";
            case "sha3-256":
                return "SHA3-256";
            case "sha3-384":
                return "SHA3-384";
            case "sha3-512":
                return "SHA3-512";
            default:
                return "SHA-256";
        }
    }

    /** 哈希名称 → 展示名。 */
    private static String hashLabel(String name) {
        return (name == null ? "sha256" : name).toUpperCase();
    }

    /** hex 编码。 */
    private static String hexOf(byte[] b) {
        if (b == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }

    /** POST DER 到本机 MAIN 端点（WEBPORT），返回响应字节。 */
    private static byte[] postMain(String path, String contentType, byte[] body) throws Exception {
        String port = readConfigWebPort();
        if (port == null || port.isEmpty() || "未配置".equals(port)) {
            port = "80";
        }
        URL url = new java.net.URI("http://127.0.0.1:" + port + path).toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", contentType);
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(10000);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body);
        }
        int code = conn.getResponseCode();
        byte[] respBody;
        try (InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream()) {
            if (is == null) {
                respBody = new byte[0];
            } else {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                int n;
                while ((n = is.read(buf)) > 0) {
                    bos.write(buf, 0, n);
                }
                respBody = bos.toByteArray();
            }
        }
        if (code >= 400) {
            String errText = new String(respBody, StandardCharsets.UTF_8).trim();
            if (errText.length() > 300) {
                errText = errText.substring(0, 300);
            }
            throw new IOException("MAIN 返回 HTTP " + code + (errText.isEmpty() ? "" : ": " + errText));
        }
        return respBody;
    }

    /** 模拟 OCSP 请求（RFC 6960）：标准 CertID + Nonce → POST /OCSP → 解析响应并验签。 */
    private static String debugOcsp(String serial, String hash) throws Exception {
        StringBuilder log = new StringBuilder();
        String hashName = (hash == null || hash.isEmpty()) ? "sha256" : hash.toLowerCase();
        String hashOid = hashOidOf(hashName);
        String jcaHash = jcaHashOf(hashName);

        // 1. 目标证书（未指定序列号时自动选第一个终端证书）
        CertsDB db = new CertsDB();
        db.load(baseDir);
        CertsDB.CertEntry entry;
        if (serial != null && !serial.isEmpty()) {
            entry = db.findBySerial(serial.trim().toLowerCase());
        } else {
            entry = db.getAll().stream().filter(e -> e.type == 'E').findFirst().orElse(null);
        }
        if (entry == null) {
            return "未找到目标证书（序列号 " + serial + "），无法构造 OCSP 请求";
        }
        String issuerId = entry.issuerId;
        log.append("== 模拟 OCSP 请求（RFC 6960）==\n");
        log.append("[1] 目标证书\n");
        log.append("    序列号: ").append(entry.serial).append("  类型: ").append(entry.type)
                .append("  状态: ").append(entry.status).append("  颁发者: ").append(issuerId).append('\n');

        // 2. 加载颁发者证书（CertID 的 issuerNameHash/issuerKeyHash 基于真正颁发者）
        Path issuerPath = null;
        for (String p : new String[]{"PKI/ROOT/" + issuerId + ".crt", "PKI/CA/" + issuerId + ".crt"}) {
            if (Files.exists(Paths.get(baseDir, p))) {
                issuerPath = Paths.get(baseDir, p);
                break;
            }
        }
        if (issuerPath == null) {
            return "未找到颁发者证书: " + issuerId + "（ROOT/CA 目录均无）";
        }
        java.security.cert.X509Certificate issuerCert = PemIO.readCert(issuerPath.toString());

        // 3. 构造标准 OCSP 请求（RFC 6960 4.1.1：CertID + Nonce 扩展）
        AlgorithmIdentifier algId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(hashOid));
        DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder()
                .setProvider("BC").build();
        DigestCalculator dc = dcp.get(algId);
        CertificateID cid = new CertificateID(dc,
                new JcaX509CertificateHolder(issuerCert),
                new java.math.BigInteger(entry.serial, 16));
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(cid);
        byte[] nonce = new byte[8];
        new SecureRandom().nextBytes(nonce);
        gen.setRequestExtensions(new Extensions(new Extension(
                OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce))));
        OCSPReq ocspReq = gen.build();
        byte[] reqDer = ocspReq.getEncoded();

        log.append("[2] 构造请求\n");
        log.append("    CertID 哈希算法: ").append(hashLabel(hashName)).append(" (").append(hashOid).append(")\n");
        log.append("    issuerNameHash: ").append(hexOf(cid.getIssuerNameHash())).append('\n');
        log.append("    issuerKeyHash: ").append(hexOf(cid.getIssuerKeyHash())).append('\n');
        log.append("    Nonce: ").append(hexOf(nonce)).append('\n');
        log.append("    请求 DER 长度: ").append(reqDer.length).append(" 字节\n");

        // 4. POST 到本机 MAIN
        String port = readConfigWebPort();
        log.append("[3] POST http://127.0.0.1:").append(port).append("/OCSP\n");
        byte[] respDer;
        try {
            respDer = postMain("/OCSP", "application/ocsp-request", reqDer);
            log.append("    响应长度: ").append(respDer.length).append(" 字节\n");
        } catch (Exception e) {
            log.append("    请求失败: ").append(e).append('\n');
            log.append("    （请确认 MAIN 服务已启动且 WEBPORT 配置正确）\n");
            return log.toString();
        }

        // 5. 解析响应
        log.append("[4] 响应解析（RFC 6960 OCSPResp）\n");
        OCSPResp resp = new OCSPResp(respDer);
        int st = resp.getStatus();
        log.append("    responseStatus: ").append(ocspStatusName(st)).append('\n');
        if (st != 0) {
            log.append("    （非 successful，无 responseBytes）\n");
            return log.toString();
        }
        Object obj = resp.getResponseObject();
        if (!(obj instanceof BasicOCSPResp)) {
            log.append("    responseBytes 不是 BasicOCSPResp\n");
            return log.toString();
        }
        BasicOCSPResp basic = (BasicOCSPResp) obj;
        org.bouncycastle.asn1.ocsp.ResponderID rid =
                basic.getResponderId().toASN1Primitive();
        if (rid.getKeyHash() != null) {
            log.append("    responderID: byKey ").append(hexOf(rid.getKeyHash())).append('\n');
        } else if (rid.getName() != null) {
            log.append("    responderID: byName ").append(rid.getName()).append('\n');
        } else {
            log.append("    responderID: (空)\n");
        }
        log.append("    producedAt: ").append(basic.getProducedAt()).append('\n');
        SingleResp[] singles = basic.getResponses();
        for (int i = 0; i < singles.length; i++) {
            SingleResp sr = singles[i];
            log.append("    [单条响应 ").append(i + 1).append("]\n");
            log.append("       CertID 序列号: ")
                    .append(sr.getCertID().getSerialNumber().toString(16)).append('\n');
            Object cs = sr.getCertStatus();
            if (cs == CertificateStatus.GOOD) {
                log.append("       证书状态: good（正常）\n");
            } else if (cs instanceof RevokedStatus) {
                RevokedStatus rs = (RevokedStatus) cs;
                log.append("       证书状态: revoked（已吊销） 时间=").append(rs.getRevocationTime())
                        .append(" 原因=").append(rs.getRevocationReason()).append('\n');
            } else if (cs instanceof UnknownStatus) {
                log.append("       证书状态: unknown（未知）\n");
            }
            log.append("       thisUpdate: ").append(sr.getThisUpdate()).append('\n');
            if (sr.getNextUpdate() != null) {
                log.append("       nextUpdate: ").append(sr.getNextUpdate()).append('\n');
            }
        }
        // Nonce 回显比对
        Extension ne = basic.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (ne != null) {
            byte[] echo = org.bouncycastle.asn1.ASN1OctetString.getInstance(
                    ne.getExtnValue()).getOctets();
            log.append("    Nonce 回显: ").append(hexOf(echo))
                    .append(java.util.Arrays.equals(echo, nonce)
                            ? "  （与请求一致）" : "  （与请求不一致！）").append('\n');
        } else {
            log.append("    Nonce 回显: 无\n");
        }

        // 6. 签名验证
        log.append("[5] 签名验证\n");
        X509CertificateHolder[] certs = basic.getCerts();
        if (certs == null || certs.length == 0) {
            log.append("    响应未携带响应者证书（byName 时客户端可从受信库加载）\n");
        } else {
            java.security.cert.X509Certificate responder =
                    new JcaX509CertificateConverter().setProvider("BC")
                            .getCertificate(certs[0]);
            log.append("    响应者证书: ").append(responder.getSubjectX500Principal())
                    .append("（序列号 ").append(responder.getSerialNumber().toString(16)).append("）\n");
            ContentVerifierProvider cvp = new JcaContentVerifierProviderBuilder()
                    .setProvider("BC").build(responder);
            boolean ok = basic.isSignatureValid(cvp);
            log.append("    签名验证: ").append(ok ? "通过" : "失败").append('\n');
        }
        return log.toString();
    }

    /** 模拟时间戳请求（RFC 3161）：随机消息 → messageImprint → POST /rfc3161 → 解析响应并验签。 */
    private static String debugTsa(String hash) throws Exception {
        StringBuilder log = new StringBuilder();
        String hashName = (hash == null || hash.isEmpty()) ? "sha256" : hash.toLowerCase();
        String hashOid = hashOidOf(hashName);
        String jcaHash = jcaHashOf(hashName);

        log.append("== 模拟时间戳请求（RFC 3161）==\n");
        // 1. 随机数据 + 摘要
        byte[] msg = new byte[32];
        new SecureRandom().nextBytes(msg);
        byte[] digest = MessageDigest.getInstance(jcaHash).digest(msg);
        log.append("[1] 随机数据\n");
        log.append("    数据内容: ").append(hexOf(msg)).append('\n');
        log.append("    摘要算法: ").append(hashLabel(hashName)).append(" (").append(hashOid).append(")\n");
        log.append("    消息摘要: ").append(hexOf(digest)).append('\n');

        // 2. 构造 RFC 3161 请求（messageImprint + nonce + certReq=true）
        byte[] nonce = new byte[8];
        new SecureRandom().nextBytes(nonce);
        TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
        gen.setCertReq(true);
        TimeStampRequest tsReq = gen.generate(
                new ASN1ObjectIdentifier(hashOid), digest,
                new java.math.BigInteger(1, nonce));
        byte[] reqDer = tsReq.getEncoded();
        log.append("[2] 构造请求\n");
        log.append("    version: ").append(tsReq.getVersion()).append('\n');
        log.append("    messageImprint: {alg=")
                .append(tsReq.getMessageImprintAlgID().getAlgorithm().getId())
                .append(", digest=").append(hexOf(tsReq.getMessageImprintDigest())).append("}\n");
        log.append("    nonce: ").append(hexOf(nonce)).append('\n');
        log.append("    certReq: true\n");
        log.append("    请求 DER 长度: ").append(reqDer.length).append(" 字节\n");

        // 3. POST 到本机 MAIN
        String port = readConfigWebPort();
        log.append("[3] POST http://127.0.0.1:").append(port).append("/rfc3161\n");
        byte[] respDer;
        try {
            respDer = postMain("/rfc3161", "application/timestamp-query", reqDer);
            log.append("    响应长度: ").append(respDer.length).append(" 字节\n");
        } catch (Exception e) {
            log.append("    请求失败: ").append(e).append('\n');
            log.append("    （请确认 MAIN 服务已启动、WEBPORT 配置正确，且存在对应的 TSA 证书：")
                    .append("SHA1→rsa_sha1/ecc_sha1，SHA256→rsa_sha256/ecc_sha256，SM3→sm2_sm3）\n");
            return log.toString();
        }

        // 4. 解析响应
        log.append("[4] 响应解析（RFC 3161 TimeStampResp）\n");
        TimeStampResponse resp = new TimeStampResponse(respDer);
        int st = resp.getStatus();
        log.append("    status: ").append(tsStatusName(st)).append('\n');
        String statusStr = resp.getStatusString();
        if (statusStr != null && !statusStr.isEmpty()) {
            log.append("    statusString: ").append(statusStr).append('\n');
        }
        if (st != 0) {
            log.append("    （非 granted，无 TimeStampToken）\n");
            return log.toString();
        }
        TimeStampToken token = resp.getTimeStampToken();
        if (token == null) {
            log.append("    （未返回 TimeStampToken）\n");
            return log.toString();
        }
        TimeStampTokenInfo info = token.getTimeStampInfo();
        log.append("    [TimeStampToken]\n");
        log.append("       serialNumber: ").append(info.getSerialNumber().toString(16)).append('\n');
        log.append("       genTime: ").append(info.getGenTime()).append('\n');
        if (info.getPolicy() != null) {
            log.append("       policy: ").append(info.getPolicy().getId()).append('\n');
        }
        byte[] echoDigest = info.getMessageImprintDigest();
        log.append("       messageImprint 回显: ").append(hexOf(echoDigest))
                .append(java.util.Arrays.equals(echoDigest, digest)
                        ? "  （与请求一致）" : "  （与请求不一致！）").append('\n');

        // 5. 签名验证（RFC 3161 5.3.2）
        log.append("[5] 签名验证\n");
        java.util.Collection<X509CertificateHolder> certs =
                token.getCertificates().getMatches(null);
        if (certs == null || certs.isEmpty()) {
            log.append("    token 未携带证书链\n");
        } else {
            boolean anyOk = false;
            for (X509CertificateHolder h : certs) {
                java.security.cert.X509Certificate c =
                        new JcaX509CertificateConverter().setProvider("BC").getCertificate(h);
                try {
                    org.bouncycastle.cms.SignerInformationVerifier siv =
                            new org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder()
                                    .setProvider("BC").build(c);
                    token.validate(siv); // 校验 messageImprint 匹配 + 数字签名（失败抛异常）
                    log.append("    签名者证书: ").append(c.getSubjectX500Principal())
                            .append("（序列号 ").append(c.getSerialNumber().toString(16)).append("）\n");
                    anyOk = true;
                    break;
                } catch (Exception ignore) {
                    // 链中非签名者证书不匹配 ESSCertID，跳过继续尝试
                }
            }
            log.append("    签名验证: ").append(anyOk
                    ? "通过（messageImprint 匹配、数字签名有效）"
                    : "失败（无匹配签名者证书）").append('\n');
        }
        return log.toString();
    }

    private static String ocspStatusName(int st) {
        switch (st) {
            case 0: return "successful (0)";
            case 1: return "malformedRequest (1)";
            case 2: return "internalError (2)";
            case 3: return "tryLater (3)";
            case 5: return "sigRequired (5)";
            case 6: return "unauthorized (6)";
            default: return "未知 (" + st + ")";
        }
    }

    private static String tsStatusName(int st) {
        switch (st) {
            case 0: return "granted (0)";
            case 1: return "grantedWithMods (1)";
            case 2: return "rejection (2)";
            case 3: return "waiting (3)";
            case 4: return "revocationWarning (4)";
            case 5: return "revocationNotification (5)";
            default: return "未知 (" + st + ")";
        }
    }

    // ============================================================
    // 密钥更换（证书库「操作」按钮 → 密钥更换分组）
    // ============================================================

    /**
     * 密钥更换：按当前证书序列号识别公钥类型 → 生成同类型新密钥对 →
     * 随机数据测试（加解密 / 数字签名 / 签名验证）→ 加载颁发者 CA 证书与私钥 →
     * 对替换公钥后的 JSON 重建 TBS 并用 CA 私钥重签 → 新证书与私钥写回原位置替换。
     */
    private static String rekeyAction(String serial) throws Exception {
        serial = normSerial(serial);
        if (serial == null) {
            throw new IllegalArgumentException("缺少或非法证书序列号");
        }

        // 1) 登记表
        CertsDB db = new CertsDB();
        db.load(baseDir);
        CertsDB.CertEntry entry = db.findBySerial(serial);
        if (entry == null) {
            throw new IllegalArgumentException("CERTS.txt 中未找到序列号 " + serial);
        }

        // 2) 读原证书（WebPublic/CRT 是全部证书的统一对外目录）
        String certPath = baseDir + "/PKI/WebPublic/CRT/" + serial + ".crt";
        if (!Files.exists(Paths.get(certPath))) {
            throw new IllegalArgumentException("缺少证书文件: " + certPath);
        }
        byte[] pemBytes = Files.readAllBytes(Paths.get(certPath));
        String json = X509JsonConverter.certToJson(pemBytes);

        // 3) 识别公钥算法 → 生成同类型新密钥对
        KeyPair kp = X509JsonConverter.generateKeyPairFromJson(json);
        String keyType = X509JsonConverter.keyTypeFromJson(json);

        // 4) 随机数据密钥测试
        String tests = testKeyPair(kp, keyType);

        // 5) 加载颁发者 CA 证书与私钥（R→ROOT，C→CA）
        if (entry.issuerId == null || entry.issuerId.isEmpty()) {
            throw new IllegalArgumentException("登记表缺少颁发者序列号（" + serial + "）");
        }
        CertsDB.CertEntry issuer = db.findBySerial(entry.issuerId);
        if (issuer == null) {
            throw new IllegalArgumentException("CERTS.txt 中未找到颁发者 " + entry.issuerId);
        }
        String issuerDir = issuer.type == 'R' ? "ROOT" : (issuer.type == 'C' ? "CA" : null);
        if (issuerDir == null) {
            throw new IllegalArgumentException("颁发者类型必须为 R(根) 或 C(CA)，实际为 " + issuer.type);
        }
        String issuerKeyPath = baseDir + "/PKI/" + issuerDir + "/" + entry.issuerId + ".key";
        if (!Files.exists(Paths.get(issuerKeyPath))) {
            throw new IllegalArgumentException("缺少颁发者私钥: " + issuerKeyPath);
        }
        PrivateKey issuerKey = CertUtil.readJcaPrivateKey(issuerKeyPath);
        String issuerKeyType = PemIO.detectKeyType(issuerKeyPath);

        // 6) CA 重签：换公钥 → 重建 TBS → 颁发者私钥签名 → 新证书 PEM
        byte[] newCertPem = X509JsonConverter.rekeyJsonToPemByIssuer(
                json, kp, issuerKey, issuerKeyType);

        // 7) 写回原位置（按证书身份定位 OCSP / TSA / 登记类型目录），替换旧文件
        String saved = saveRekeyFiles(serial, entry, newCertPem, kp, keyType);

        String msg = "密钥更换完成\n"
                + "证书算法: " + keyType + "（已按原算法生成同类型新密钥对）\n"
                + "密钥测试结果:\n" + tests
                + "重签算法: " + issuerKeyType + "（颁发者 " + entry.issuerId + " 签名）\n"
                + saved;
        MLog.append(baseDir, "WebAdmin /api/rekey 详细",
                "密钥更换 序列号=" + serial + " 新密钥=" + keyType
                        + " 颁发者=" + entry.issuerId,
                msg.replace("\n", " | "));
        return msg;
    }

    /**
     * 续签证书：按当前证书序列号读取证书 → 更新 validity 的生效/失效时间 →
     * 加载颁发者 CA 证书与私钥 → 对 JSON 重建 TBS 并用 CA 私钥重签 →
     * 新证书写回原位置（公钥与扩展保持不变，仅时间更新）。
     */
    private static String renewAction(String serial, String notBeforeStr, String notAfterStr) throws Exception {
        serial = normSerial(serial);
        if (serial == null) {
            throw new IllegalArgumentException("缺少或非法证书序列号");
        }
        Date notBefore = parseLocalDateTime(notBeforeStr);
        Date notAfter = parseLocalDateTime(notAfterStr);
        if (!notAfter.after(notBefore)) {
            throw new IllegalArgumentException("失效时间必须晚于生效时间");
        }

        // 1) 登记表
        CertsDB db = new CertsDB();
        db.load(baseDir);
        CertsDB.CertEntry entry = db.findBySerial(serial);
        if (entry == null) {
            throw new IllegalArgumentException("CERTS.txt 中未找到序列号 " + serial);
        }

        // 2) 读原证书（WebPublic/CRT 是全部证书的统一对外目录）
        String certPath = baseDir + "/PKI/WebPublic/CRT/" + serial + ".crt";
        if (!Files.exists(Paths.get(certPath))) {
            throw new IllegalArgumentException("缺少证书文件: " + certPath);
        }
        byte[] pemBytes = Files.readAllBytes(Paths.get(certPath));
        String json = X509JsonConverter.certToJson(pemBytes);

        // 3) 加载颁发者 CA 证书与私钥（R→ROOT，C→CA）
        if (entry.issuerId == null || entry.issuerId.isEmpty()) {
            throw new IllegalArgumentException("登记表缺少颁发者序列号（" + serial + "）");
        }
        CertsDB.CertEntry issuer = db.findBySerial(entry.issuerId);
        if (issuer == null) {
            throw new IllegalArgumentException("CERTS.txt 中未找到颁发者 " + entry.issuerId);
        }
        String issuerDir = issuer.type == 'R' ? "ROOT" : (issuer.type == 'C' ? "CA" : null);
        if (issuerDir == null) {
            throw new IllegalArgumentException("颁发者类型必须为 R(根) 或 C(CA)，实际为 " + issuer.type);
        }
        String issuerKeyPath = baseDir + "/PKI/" + issuerDir + "/" + entry.issuerId + ".key";
        if (!Files.exists(Paths.get(issuerKeyPath))) {
            throw new IllegalArgumentException("缺少颁发者私钥: " + issuerKeyPath);
        }
        PrivateKey issuerKey = CertUtil.readJcaPrivateKey(issuerKeyPath);
        String issuerKeyType = PemIO.detectKeyType(issuerKeyPath);

        // 4) CA 重签：更新有效期 → 重建 TBS → 颁发者私钥签名 → 新证书 PEM
        byte[] newCertPem = X509JsonConverter.renewJsonToPemByIssuer(
                json, notBefore, notAfter, issuerKey, issuerKeyType);

        // 5) 写回原位置（按证书身份定位 OCSP / TSA / 登记类型目录），替换旧文件
        String saved = saveRekeyFiles(serial, entry, newCertPem, null, null);

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        String msg = "续签完成\n"
                + "新生效时间: " + sdf.format(notBefore) + " UTC\n"
                + "新失效时间: " + sdf.format(notAfter) + " UTC\n"
                + "重签算法: " + issuerKeyType + "（颁发者 " + entry.issuerId + " 签名）\n"
                + "公钥与扩展保持不变，仅更新时间\n"
                + saved;
        MLog.append(baseDir, "WebAdmin /api/renew 详细",
                "续签 序列号=" + serial + " 生效=" + notBeforeStr + " 失效=" + notAfterStr,
                msg.replace("\n", " | "));
        return msg;
    }

    /** 解析前端 datetime-local 的本地时间（yyyy-MM-ddTHH:mm[:ss]），转 UTC Date。 */
    private static Date parseLocalDateTime(String s) throws Exception {
        if (s == null || s.trim().isEmpty()) {
            throw new IllegalArgumentException("缺少时间");
        }
        String v = s.trim().replace(' ', 'T');
        if (v.endsWith("Z")) {
            v = v.substring(0, v.length() - 1); // 兼容 UTC 后缀
        }
        LocalDateTime ldt = LocalDateTime.parse(
                v.length() == 16 ? v + ":00" : v,
                DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        return Date.from(ldt.atZone(ZoneId.systemDefault()).toInstant());
    }

    /** 随机数据密钥对测试：RSA（加解密+签名验签）/ ECC（签名验签）/ SM2（SM2加解密+签名验签）。 */    private static String testKeyPair(KeyPair kp, String keyType) throws Exception {
        StringBuilder sb = new StringBuilder();
        byte[] data = new byte[64];
        new SecureRandom().nextBytes(data);
        if ("RSA".equalsIgnoreCase(keyType)) {
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            c.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            byte[] enc = c.doFinal(data);
            c.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            byte[] dec = c.doFinal(enc);
            sb.append("    RSA 加解密     : ")
                    .append(Arrays.equals(data, dec) ? "通过 ✓" : "失败 ✗")
                    .append("（64 字节随机数据）\n");
            sb.append("    RSA 签名/验签  : ")
                    .append(signAndVerify(kp, "SHA256withRSA", data) ? "通过 ✓" : "失败 ✗")
                    .append("（SHA256）\n");
        } else if ("ECC".equalsIgnoreCase(keyType)) {
            sb.append("    ECC 签名/验签  : ")
                    .append(signAndVerify(kp, "SHA256withECDSA", data) ? "通过 ✓" : "失败 ✗")
                    .append("（SHA256；ECC 为签名算法，无传统公钥加解密）\n");
        } else if ("SM2".equalsIgnoreCase(keyType)) {
            ECPublicKeyParameters pub = Sm2Util.toEcPublicParams(kp.getPublic());
            ECPrivateKeyParameters priv = Sm2Util.toEcPrivateParams(kp.getPrivate());
            SM2Engine eng = new SM2Engine(SM2Engine.Mode.C1C3C2);
            eng.init(true, new ParametersWithRandom(pub, new SecureRandom()));
            byte[] enc = eng.processBlock(data, 0, data.length);
            SM2Engine dEng = new SM2Engine(SM2Engine.Mode.C1C3C2);
            dEng.init(false, priv);
            byte[] dec = dEng.processBlock(enc, 0, enc.length);
            sb.append("    SM2 加解密     : ")
                    .append(Arrays.equals(data, dec) ? "通过 ✓" : "失败 ✗")
                    .append("（64 字节随机数据，C1C3C2）\n");
            byte[] sig = Sm2Util.sm2Sign(priv, data);
            sb.append("    SM2 签名/验签  : ")
                    .append(Sm2Util.sm2Verify(pub, data, sig) ? "通过 ✓" : "失败 ✗")
                    .append("（SM3withSM2，含 ZA）\n");
        } else {
            throw new IllegalArgumentException("不支持的密钥类型: " + keyType);
        }
        return sb.toString();
    }

    /** 用 JCA Signature 对随机数据做签名并验证。 */
    private static boolean signAndVerify(KeyPair kp, String jcaAlg, byte[] data) throws Exception {
        Signature s = Signature.getInstance(jcaAlg, "BC");
        s.initSign(kp.getPrivate());
        s.update(data);
        byte[] sig = s.sign();
        Signature v = Signature.getInstance(jcaAlg, "BC");
        v.initVerify(kp.getPublic());
        v.update(data);
        return v.verify(sig);
    }

    /**
     * 按证书身份定位保存位置并替换旧文件：
     * OCSP 证书（OCSP/{颁发者ID}_ocsp.crt 序列号匹配）→ OCSP 目录；
     * TSA 证书（TIMSTAMP 目录内证书序列号匹配）→ TIMSTAMP 目录；
     * 否则按登记类型 R→ROOT、C→CA、E→CERT/KEY。始终同步 WebPublic/CRT。
     */
    private static String saveRekeyFiles(String serial, CertsDB.CertEntry entry,
                                         byte[] certPem, KeyPair kp, String keyType) throws Exception {
        serial = normSerial(serial);
        if (serial == null) {
            throw new IllegalArgumentException("非法序列号");
        }
        String issuerId = normSerial(entry.issuerId);
        if (issuerId == null) {
            throw new IllegalArgumentException("登记表颁发者序列号非法: " + entry.issuerId);
        }
        StringBuilder sb = new StringBuilder();
        Path base = Paths.get(baseDir, "PKI");
        String syncDir = "PKI/WebPublic/CRT/" + serial + ".crt";

        // 1) 统一对外目录（所有证书类型）
        Files.write(Paths.get(baseDir, "PKI", "WebPublic", "CRT", serial + ".crt"), certPem);
        sb.append("证书已同步: ").append(syncDir).append("\n");

        // 2) 定位主位置
        Path certOut = null;
        Path keyOut = null;
        String kind = null;

        // 2a) OCSP 签名证书：OCSP/{颁发者ID}_ocsp.crt 的序列号 == 目标序列号
        Path ocspCert = Paths.get(base.toString(), "OCSP", entry.issuerId + "_ocsp.crt");
        if (Files.exists(ocspCert) && certSerialOf(ocspCert).equals(serial)) {
            certOut = ocspCert;
            keyOut = Paths.get(base.toString(), "OCSP", entry.issuerId + "_ocsp.key");
            kind = "OCSP 签名证书";
        }

        // 2b) TSA 时间戳证书：TIMSTAMP 目录内证书序列号匹配
        if (certOut == null) {
            Path tsDir = Paths.get(base.toString(), "TIMSTAMP");
            if (Files.isDirectory(tsDir)) {
                try (Stream<Path> stream = Files.list(tsDir)) {
                    List<Path> crts = stream.filter(p -> p.toString().toLowerCase().endsWith(".crt"))
                            .collect(Collectors.toList());
                    for (Path p : crts) {
                        if (certSerialOf(p).equals(serial)) {
                            certOut = p;
                            keyOut = Paths.get(p.toString().replace(".crt", ".key"));
                            kind = "TSA 时间戳证书";
                            break;
                        }
                    }
                }
            }
        }

        // 2c) 按登记类型
        if (certOut == null) {
            switch (entry.type) {
                case 'R':
                    certOut = Paths.get(base.toString(), "ROOT", serial + ".crt");
                    keyOut = Paths.get(base.toString(), "ROOT", serial + ".key");
                    kind = "根证书(R)";
                    break;
                case 'C':
                    certOut = Paths.get(base.toString(), "CA", serial + ".crt");
                    keyOut = Paths.get(base.toString(), "CA", serial + ".key");
                    kind = "CA证书(C)";
                    break;
                case 'E':
                    certOut = Paths.get(base.toString(), "CERT", serial + ".crt");
                    keyOut = Paths.get(base.toString(), "KEY", serial + ".key");
                    kind = "终端证书(E)";
                    break;
                default:
                    throw new IllegalArgumentException("不支持的证书类型: " + entry.type);
            }
        }

        // 3) 写证书 + 私钥（续签场景 kp 为 null，仅更新证书、私钥保持不变）
        Files.write(certOut, certPem);
        sb.append("证书类型: ").append(kind).append("\n");
        sb.append("证书已替换: ").append(relPath(certOut)).append("\n");
        if (kp != null && keyType != null) {
            PemIO.writePrivateKey(keyOut.toString(), kp.getPrivate(), keyType);
            sb.append("私钥已替换: ").append(relPath(keyOut)).append("\n");
        } else {
            sb.append("私钥保持不变（续签不更换密钥）\n");
        }
        return sb.toString();
    }

    /** 读取证书文件的序列号（hex 小写）。 */
    private static String certSerialOf(Path certPath) throws Exception {
        return PemIO.readCert(certPath.toString()).getSerialNumber()
                .toString(16).toLowerCase();
    }

    /** 相对 baseDir 的路径显示。 */
    private static String relPath(Path p) {
        String abs = p.toString().replace('\\', '/');
        String b = baseDir.replace('\\', '/') + "/";
        return abs.startsWith(b) ? abs.substring(b.length()) : abs;
    }

    // ============================================================
    // 数据组装
    // ============================================================

    /** MAIN 服务状态 + WebAdmin 自身统计。 */
    private static Map<String, Object> statusJson() {
        probeMainIfStale();
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("mainPort", mainPort);
        d.put("mainRunning", mainRunning);
        d.put("adminPort", port());
        d.put("uptimeSeconds", (System.currentTimeMillis() - startTime) / 1000);
        d.put("totalCalls", TOTAL_CALLS.get());
        d.put("endpointCalls", new LinkedHashMap<>(ENDPOINT_CALLS));
        d.put("version", Admin.VERSION);
        d.put("baseDir", baseDir);
        d.put("webPort", readConfigWebPort());
        long lines = countLogLines();
        d.put("logLines", lines);
        return Map.of("ok", true, "data", d);
    }

    /** 证书库列表。 */
    private static Map<String, Object> certsJson() throws Exception {
        List<Map<String, Object>> list = new ArrayList<>();
        Path f = Paths.get(baseDir, "PKI", "CERTS.txt");
        if (Files.exists(f)) {
            for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#")) {
                    continue;
                }
                String[] p = t.split("\\s+");
                if (p.length < 7) {
                    continue;
                }
                Map<String, Object> e = new LinkedHashMap<>();
                e.put("serial", p[0]);
                e.put("type", p[1]);
                e.put("status", p[2]);
                e.put("reason", p[3]);
                e.put("time", p[4]);
                e.put("issuer", p[5]);
                e.put("algo", p.length > 6 ? p[6] : "");
                list.add(e);
            }
        }
        return Map.of("ok", true, "data", list);
    }

    // ============================================================
    // 我的证书：PKI/MY 导入证书库（myCERTS.txt 台账 + {序列号}.crt/.key）
    // ============================================================

    private static Path myRecordPath() {
        return Paths.get(baseDir, "PKI", "MY", "myCERTS.txt");
    }

    /** /api/my/list：读取 PKI/MY/myCERTS.txt 台账。 */
    private static Map<String, Object> myListJson() {
        List<Map<String, Object>> list = new ArrayList<>();
        try {
            Path f = myRecordPath();
            if (Files.exists(f)) {
                for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                    String t = line.trim();
                    if (t.isEmpty() || t.startsWith("#")) {
                        continue;
                    }
                    String[] p = t.split("\\s+");
                    if (p.length < 6) {
                        continue;
                    }
                    Map<String, Object> e = new LinkedHashMap<>();
                    e.put("serial", p[0]);
                    e.put("type", p[1]);
                    e.put("hasKey", p[2]);
                    e.put("algo", p[3]);
                    e.put("notBefore", p[4]);
                    e.put("notAfter", p[5]);
                    list.add(e);
                }
            }
        } catch (Exception ignored) {
        }
        return Map.of("ok", true, "data", list);
    }

    /** myCERTS.txt 是否已登记该序列号。 */
    private static boolean myHasSerial(String serial) {
        if (serial == null || serial.isEmpty()) {
            return false;
        }
        try {
            Path f = myRecordPath();
            if (!Files.exists(f)) {
                return false;
            }
            for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#")) {
                    continue;
                }
                if (t.split("\\s+")[0].equalsIgnoreCase(serial)) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    /** 验证目标回退：MY 台账中的序列号 → PKI/MY/序列号.crt 绝对路径，其余原样（CERTS.txt 行为不变）。 */
    private static String verifyTarget(String target) {
        if (target != null && myHasSerial(target)) {
            java.io.File f = new java.io.File(baseDir, "PKI/MY/" + target.toLowerCase() + ".crt");
            if (f.exists()) {
                return f.getAbsolutePath();
            }
        }
        return target;
    }

    /** 证书序列号规范化：小写 hex，奇数补 0（与 CertVerify 显示一致）。 */
    private static String mySerialOf(java.security.cert.X509Certificate c) {
        String h = c.getSerialNumber().toString(16).toLowerCase();
        if (h.length() % 2 != 0) {
            h = "0" + h;
        }
        return h;
    }

    /** 证书算法：RSA / ECC / SM2 / PQC（ML-DSA/SLH-DSA/ML-KEM 等）。 */
    private static String myAlgoOf(java.security.cert.X509Certificate c) {
        try {
            if (c.getPublicKey() instanceof java.security.interfaces.RSAPublicKey) {
                return "RSA";
            }
            if (CtLog.isSm2Precert(c)) {
                return "SM2";
            }
            if (c.getPublicKey() instanceof java.security.interfaces.ECPublicKey) {
                return "ECC";
            }
            String alg = c.getPublicKey() == null ? "-" : c.getPublicKey().getAlgorithm();
            if (PemIO.isPqcAlgName(alg)) {
                return "PQC";
            }
            return alg;
        } catch (Exception e) {
            return "-";
        }
    }

    /** 证书类型：自签名 CA → R；CA → C；终端 → E。 */
    private static String myTypeOf(java.security.cert.X509Certificate c) {
        int bc = c.getBasicConstraints();
        if (bc >= 0) {
            boolean self = c.getSubjectX500Principal().equals(c.getIssuerX500Principal());
            return self ? "R" : "C";
        }
        return "E";
    }

    private static String fmtMyTime(java.util.Date d) {
        try {
            return new SimpleDateFormat("yyyy/MM/dd-HH:mm:ss").format(d);
        } catch (Exception e) {
            return String.valueOf(d);
        }
    }

    /** 校验证书与私钥匹配：私钥签名 → 证书公钥验签（SM2 走 Sm2Util，同一 ZA 上下文）。 */
    private static boolean myKeyMatches(java.security.cert.X509Certificate cert, PrivateKey priv) {
        try {
            if (CtLog.isSm2Precert(cert)) {
                byte[] tbs = Sm2Util.sm3("MODPKICA-IMPORT-CHECK".getBytes(StandardCharsets.UTF_8));
                org.bouncycastle.crypto.params.ECPrivateKeyParameters dp = Sm2Util.toEcPrivateParams(priv);
                byte[] sig = Sm2Util.sm2Sign(dp, tbs);
                return Sm2Util.sm2Verify(Sm2Util.toEcPublicParams(cert.getPublicKey()), tbs, sig);
            }
            // PQC（ML-DSA/SLH-DSA 等）：公钥算法名直接作 BC Signature 名；KEM 类无签名算法则视为匹配
            String pubAlg = cert.getPublicKey() == null ? "" : cert.getPublicKey().getAlgorithm();
            if (PemIO.isPqcAlgName(pubAlg)) {
                try {
                    byte[] d0 = "MODPKICA-IMPORT-CHECK".getBytes(StandardCharsets.UTF_8);
                    java.security.Signature sg0 = java.security.Signature.getInstance(pubAlg, "BC");
                    sg0.initSign(priv);
                    sg0.update(d0);
                    byte[] s0 = sg0.sign();
                    java.security.Signature vf0 = java.security.Signature.getInstance(pubAlg, "BC");
                    vf0.initVerify(cert.getPublicKey());
                    vf0.update(d0);
                    return vf0.verify(s0);
                } catch (Exception pe) {
                    // ML-KEM 等仅 KEM 的 PQC 私钥无法做数字签名：算法族一致即视为匹配
                    return true;
                }
            }
            String alg = priv instanceof java.security.interfaces.RSAPrivateKey
                    ? "SHA256withRSA" : "SHA256withECDSA";
            byte[] data = "MODPKICA-IMPORT-CHECK".getBytes(StandardCharsets.UTF_8);
            java.security.Signature sg = java.security.Signature.getInstance(alg, "BC");
            sg.initSign(priv);
            sg.update(data);
            byte[] s = sg.sign();
            java.security.Signature vf = java.security.Signature.getInstance(alg, "BC");
            vf.initVerify(cert.getPublicKey());
            vf.update(data);
            return vf.verify(s);
        } catch (Exception e) {
            return false;
        }
    }

    /** BC 私钥参数 → JCA PrivateKey（RSA / EC(SM2) / PQC 统一，供 Signature 与 KeyFactory 使用）。 */
    static PrivateKey toJcaPrivateKey(org.bouncycastle.crypto.params.AsymmetricKeyParameter akp) throws Exception {
        org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki = org.bouncycastle.crypto.util.PrivateKeyInfoFactory.createPrivateKeyInfo(akp);
        byte[] p8 = pki.getEncoded();
        String oid = pki.getPrivateKeyAlgorithm().getAlgorithm().getId();
        if (oid.startsWith("1.2.840.113549.1.1")) {
            return java.security.KeyFactory.getInstance("RSA", "BC")
                    .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(p8));
        }
        // PQC：依次尝试 BC 通用 KeyFactory（ML-DSA/SLH-DSA/ML-KEM/Falcon/XMSS）
        for (String n : new String[]{"ML-DSA", "SLH-DSA", "ML-KEM", "Falcon", "XMSS", "McEliece"}) {
            try {
                return java.security.KeyFactory.getInstance(n, "BC")
                        .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(p8));
            } catch (Exception ignored) {
            }
        }
        // SM2/ECC：BC 的 EC KeyFactory 认识 SM2 曲线 OID
        return java.security.KeyFactory.getInstance("EC", "BC")
                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(p8));
    }

    /** /api/my/import：导入 pfx/p12/jks（需密码）或 cer/crt/pem（含私钥可选）。 */
    private static void myImportAction(HttpExchange ex) {
        try {
            Map<String, byte[]> f = readMultipart(ex);
            byte[] data = f.get("file");
            if (data == null || data.length == 0) {
                throw new IllegalArgumentException("未上传证书文件");
            }
            String fn = f.get("__name_file") != null
                    ? new String(f.get("__name_file"), StandardCharsets.UTF_8) : "cert.pem";
            String password = f.get("password") != null
                    ? new String(f.get("password"), StandardCharsets.UTF_8) : "";
            Map<String, Object> r = myImportBytes(data, fn, password);
            MLog.append(baseDir, "WebAdmin /api/my/import",
                    "POST 导入证书 file=" + fn + " size=" + data.length,
                    "序列号=" + r.get("serial") + " 类型=" + r.get("type")
                            + " 算法=" + r.get("algo") + " 私钥=" + r.get("hasKey")
                            + " 证书=" + r.get("certPath") + " 私钥文件=" + r.get("keyPath"));
            sendJson(ex, 200, r);
        } catch (Exception ex2) {
            try {
                MLog.appendErr(baseDir, "WebAdmin /api/my/import 异常",
                        "POST 导入证书", String.valueOf(ex2));
                sendJson(ex, 500, Map.of("ok", false, "message", String.valueOf(ex2)));
            } catch (Exception ignored) {
            }
        }
    }

    /** 导入核心（可独立测试）：返回 ok/serial/type/algo/hasKey/certPath/keyPath/message。 */
    static Map<String, Object> myImportBytes(byte[] data, String fileName, String password) throws Exception {
        String lower = fileName == null ? "" : fileName.toLowerCase();
        if (lower.endsWith(".pfx") || lower.endsWith(".p12") || lower.endsWith(".jks")) {
            // JKS / PKCS12：导出全部私钥条目（证书链叶子 + 私钥）
            return importKeyStore(data, fileName, password);
        }
        // PEM：解析 CERTIFICATE 块 + 可选私钥块
        String text = new String(data, StandardCharsets.UTF_8);
        java.util.regex.Matcher cm = java.util.regex.Pattern.compile(
                "-----BEGIN CERTIFICATE-----\\s*([A-Za-z0-9+/=\\r\\n]+?)-----END CERTIFICATE-----",
                java.util.regex.Pattern.DOTALL).matcher(text);
        if (!cm.find()) {
            throw new IllegalArgumentException("未找到 CERTIFICATE PEM 块");
        }
        byte[] der = java.util.Base64.getDecoder().decode(cm.group(1).replaceAll("\\s", ""));
        java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate)
                java.security.cert.CertificateFactory.getInstance("X.509", "BC")
                        .generateCertificate(new java.io.ByteArrayInputStream(der));
        PrivateKey priv = null;
        java.util.regex.Matcher km = java.util.regex.Pattern.compile(
                "-----BEGIN ([A-Z0-9 ]+)-----\\s*([A-Za-z0-9+/=\\r\\n]+?)-----END",
                java.util.regex.Pattern.DOTALL).matcher(text);
        while (km.find()) {
            String type = km.group(1).trim();
            if (type.equals("ENCRYPTED PRIVATE KEY")) {
                throw new IllegalArgumentException(
                        "PEM 私钥已加密（ENCRYPTED PRIVATE KEY），请改用 pfx/p12/jks 并输入密码导入");
            }
            if (type.equals("PRIVATE KEY") || type.equals("RSA PRIVATE KEY")
                    || type.equals("EC PRIVATE KEY") || type.equals("SM2 PRIVATE KEY")) {
                java.nio.file.Path tmp = java.nio.file.Files.createTempFile("modpkica_mykey_", ".pem");
                try {
                    java.nio.file.Files.write(tmp,
                            text.substring(km.start(), km.end()).getBytes(StandardCharsets.UTF_8));
                    priv = toJcaPrivateKey(PemIO.readPrivateKey(tmp.toString()));
                } finally {
                    java.nio.file.Files.deleteIfExists(tmp);
                }
                break;
            }
        }
        if (priv != null && !myKeyMatches(cert, priv)) {
            throw new IllegalArgumentException("证书公钥与私钥不匹配，拒绝导入");
        }
        return persistMyCert(cert, priv);
    }

    /**
     * 读取 JKS / PKCS12 的全部私钥条目（私钥 + 证书链叶子）。
     * PKCS12 用 BC 直接加载；JKS 是 Sun 专有容器且私钥在 getKey() 时才解密，
     * 因此必须把「提 BC 为首位 → 加载 → 读取全部条目」放在同一作用域内完成，
     * 否则恢复位置后 Sun 的 EC KeyFactory 仍不认识 SM2 曲线（1.2.156.10197.1.301）。
     */
    private static java.util.List<Object[]> loadKeyStoreEntries(byte[] data, String ksType, String pwd) throws Exception {
        java.util.List<Object[]> out = new ArrayList<>();
        if ("PKCS12".equals(ksType)) {
            java.security.KeyStore ks;
            try {
                ks = java.security.KeyStore.getInstance(ksType, "BC");
            } catch (Exception e) {
                ks = java.security.KeyStore.getInstance(ksType);
            }
            ks.load(new java.io.ByteArrayInputStream(data), pwd.toCharArray());
            java.util.List<String> errs = new ArrayList<>();
            collectKeyStoreEntries(ks, pwd, out, errs);
            if (out.isEmpty() && !errs.isEmpty()) {
                throw new IllegalArgumentException("密钥库私钥解封装失败：" + String.join("；", errs)
                        + "。可尝试导入同目录的 PEM 证书(.crt.pem/.cer)与私钥(.key.pem)文件");
            }
            return out;
        }
        // JKS：Sun 容器；BC 提为首位解决 SM2 曲线识别
        java.security.Provider bc = java.security.Security.getProvider("BC");
        int origPos = -1;
        java.security.Provider[] ps = java.security.Security.getProviders();
        for (int i = 0; i < ps.length; i++) {
            if ("BC".equals(ps[i].getName())) {
                origPos = i;
                break;
            }
        }
        if (origPos > 0) {
            java.security.Security.removeProvider("BC");
            java.security.Security.insertProviderAt(bc, 1);
        }
        try {
            java.security.KeyStore ks = java.security.KeyStore.getInstance("JKS");
            ks.load(new java.io.ByteArrayInputStream(data), pwd.toCharArray());
            java.util.List<String> errs = new ArrayList<>();
            collectKeyStoreEntries(ks, pwd, out, errs);
            if (out.isEmpty() && !errs.isEmpty()) {
                throw new IllegalArgumentException("密钥库私钥解封装失败：" + String.join("；", errs)
                        + "。可尝试导入同目录的 PEM 证书(.crt.pem/.cer)与私钥(.key.pem)文件");
            }
            return out;
        } finally {
            if (origPos > 0) {
                java.security.Security.removeProvider("BC");
                java.security.Security.insertProviderAt(bc, origPos + 1);
            }
        }
    }

    /** 收集密钥库全部私钥条目（私钥 + 证书链叶子），单条目异常跳过并把失败原因记入 errs。 */
    private static void collectKeyStoreEntries(java.security.KeyStore ks, String pwd,
            java.util.List<Object[]> out, java.util.List<String> errs) {
        try {
            java.util.Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String a = aliases.nextElement();
                if (!ks.isKeyEntry(a)) {
                    continue;
                }
                try {
                    PrivateKey priv = (PrivateKey) ks.getKey(a, pwd.toCharArray());
                    java.security.cert.Certificate[] chain = ks.getCertificateChain(a);
                    if (priv != null && chain != null && chain.length > 0
                            && chain[0] instanceof java.security.cert.X509Certificate) {
                        out.add(new Object[]{priv, chain[0]});
                    }
                } catch (Exception e) {
                    if (errs != null) {
                        errs.add("条目[" + a + "]私钥读取失败: " + e);
                    }
                }
            }
        } catch (java.security.KeyStoreException ignored) {
        }
    }

    /** 导入 JKS/PKCS12：导出全部私钥条目（公私钥不匹配的条目跳过），返回首条 + count/all。 */
    private static Map<String, Object> importKeyStore(byte[] data, String fileName, String password) throws Exception {
        String lower = fileName.toLowerCase();
        String ksType = lower.endsWith(".jks") ? "JKS" : "PKCS12";
        String pwd = password == null ? "" : password;
        java.util.List<Object[]> entries;
        try {
            entries = loadKeyStoreEntries(data, ksType, pwd);
        } catch (Exception e) {
            throw new IllegalArgumentException("密钥库加载失败（" + ksType + "）：" + e
                    + "。若为 ML-DSA/PQC 私钥封装兼容问题，可改用同目录的 PEM 证书(.crt.pem/.cer)与私钥(.key.pem)文件导入");
        }
        if (entries.isEmpty()) {
            throw new IllegalArgumentException("密钥库中未找到私钥条目（" + ksType + "）");
        }
        java.util.List<String> importedSerials = new ArrayList<>();
        Map<String, Object> first = null;
        for (Object[] en : entries) {
            PrivateKey priv = (PrivateKey) en[0];
            java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) en[1];
            if (!myKeyMatches(cert, priv)) {
                continue;
            }
            Map<String, Object> r = persistMyCert(cert, priv);
            if (first == null) {
                first = r;
            }
            importedSerials.add((String) r.get("serial"));
        }
        if (first == null) {
            throw new IllegalArgumentException("密钥库中未找到可导入的证书（无有效私钥条目）");
        }
        Map<String, Object> out = new LinkedHashMap<>(first);
        out.put("count", importedSerials.size());
        out.put("all", importedSerials);
        out.put("message", "导入成功 " + importedSerials.size() + " 个证书：" + String.join("、", importedSerials));
        return out;
    }

    /** 落盘 PKI/MY/{serial}.crt|.key 并登记台账（重复序列号先移除旧记录）。 */
    private static Map<String, Object> persistMyCert(java.security.cert.X509Certificate cert, PrivateKey priv) throws Exception {
        String serial = mySerialOf(cert);
        String algo = myAlgoOf(cert);
        String type = myTypeOf(cert);
        String hasKey = priv != null ? "Y" : "N";
        java.io.File myDir = new java.io.File(baseDir, "PKI/MY");
        if (!myDir.exists()) {
            myDir.mkdirs();
        }
        java.io.File certF = new java.io.File(myDir, serial + ".crt");
        PemIO.writeCert(certF.getAbsolutePath(), cert);
        String keyPath = "";
        if (priv != null) {
            java.io.File keyF = new java.io.File(myDir, serial + ".key");
            PemIO.writePrivateKey(keyF.getAbsolutePath(), priv, algo);
            keyPath = "PKI/MY/" + serial + ".key";
        }
        String certPath = "PKI/MY/" + serial + ".crt";
        String rec = serial + "   " + type + "   " + hasKey + "   " + algo + "   "
                + fmtMyTime(cert.getNotBefore()) + "   " + fmtMyTime(cert.getNotAfter());
        if (myHasSerial(serial)) {
            myRemoveRecord(serial);
        }
        myAppendRecord(rec);
        return Map.of("ok", true, "serial", serial, "type", type, "algo", algo,
                "hasKey", hasKey, "certPath", certPath, "keyPath", keyPath,
                "message", "导入成功 序列号=" + serial + " 类型=" + type
                        + " 算法=" + algo + (priv != null ? "（含私钥）" : "（仅证书）"));
    }


    /** 追加台账记录：文件不存在或为空时先写模板头。 */
    private static void myAppendRecord(String rec) throws Exception {
        Path f = myRecordPath();
        boolean empty = !Files.exists(f) || Files.size(f) == 0;
        if (empty) {
            if (f.getParent() != null) {
                Files.createDirectories(f.getParent());
            }
            Files.write(f, ("# 序列号   类型       是否存在私钥          算法          生效日期    失效日期\n"
                    + "#         R/C/E        Y/N       RSA/ECC/SM2/PQC  日期格式例如 2000/06/17-12:12:12\n")
                    .getBytes(StandardCharsets.UTF_8));
        }
        Files.write(f, (rec + "\n").getBytes(StandardCharsets.UTF_8),
                java.nio.file.StandardOpenOption.APPEND);
    }

    /** /api/my/delete：删除 PKI/MY/序列号.crt/.key，并从台账移除记录。 */
    private static String myDelete(String serial) throws Exception {
        serial = normSerial(serial);
        if (serial == null) {
            throw new IllegalArgumentException("缺少或非法序列号");
        }
        String s = serial;
        Path f = myRecordPath();
        if (!Files.exists(f) || !myHasSerial(s)) {
            throw new IllegalArgumentException("未找到序列号 " + serial + "（myCERTS.txt 无此记录）");
        }
        java.io.File certF = new java.io.File(baseDir, "PKI/MY/" + s + ".crt");
        java.io.File keyF = new java.io.File(baseDir, "PKI/MY/" + s + ".key");
        boolean dc = certF.exists() && certF.delete();
        boolean dk = keyF.exists() && keyF.delete();
        myRemoveRecord(s);
        String out = "已删除序列号 " + serial + " 的证书" + (dc ? "" : "（证书文件不存在）")
                + (dk ? "" : "（私钥文件不存在）");
        MLog.append(baseDir, "WebAdmin /api/my/delete",
                "POST 删除我的证书 serial=" + serial,
                "证书删除=" + dc + " 私钥删除=" + dk);
        return out;
    }

    private static void myRemoveRecord(String serial) throws Exception {
        Path f = myRecordPath();
        if (!Files.exists(f)) {
            return;
        }
        List<String> lines = new ArrayList<>();
        for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) {
                lines.add(line);
                continue;
            }
            String[] p = t.split("\\s+");
            if (p.length >= 1 && p[0].equalsIgnoreCase(serial)) {
                continue;
            }
            lines.add(line);
        }
        Files.write(f, lines, StandardCharsets.UTF_8);
    }

    /** /api/certs/delete：将 CERTS.txt 中指定序列号行加 # 注释（忽略该行；生成 CRL/OCSP 时 CertsDB 自动跳过），不删除任何文件。 */
    private static String certsDelete(String serial) throws Exception {
        if (serial == null || serial.isEmpty()) {
            throw new IllegalArgumentException("缺少序列号");
        }
        String s = serial.toLowerCase();
        Path f = Paths.get(baseDir, "PKI", "CERTS.txt");
        if (!Files.exists(f)) {
            throw new IllegalArgumentException("CERTS.txt 不存在");
        }
        java.util.List<String> lines = Files.readAllLines(f, StandardCharsets.UTF_8);
        java.util.List<String> out = new java.util.ArrayList<>();
        boolean found = false;
        for (String line : lines) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) {
                out.add(line);
                continue;
            }
            String[] p = t.split("\\s+");
            if (p.length >= 1 && p[0].equalsIgnoreCase(s)) {
                found = true;
                out.add("# " + line);
                continue;
            }
            out.add(line);
        }
        if (!found) {
            throw new IllegalArgumentException("CERTS.txt 未找到序列号 " + serial);
        }
        // 原子写回（tmp → fsync → .bak → move，对齐 CertsDB.rewriteAll）
        Path tmp = f.resolveSibling("CERTS.txt.tmp");
        Files.writeString(tmp, String.join(System.lineSeparator(), out) + System.lineSeparator(),
                StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.TRUNCATE_EXISTING);
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(tmp.toString(), true)) {
            fos.getFD().sync();
        }
        if (Files.exists(f)) {
            Files.copy(f, f.resolveSibling("CERTS.txt.bak"), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
        Files.move(tmp, f, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        MLog.append(baseDir, "WebAdmin /api/certs/delete",
                "POST 删除证书(注释行) serial=" + serial,
                "CERTS.txt 行已加 # 注释（忽略），序列号=" + serial);
        return "已删除证书 " + serial + "（CERTS.txt 该行已加 # 注释，生成 CRL/OCSP 时跳过）";
    }

    /** /api/certs/cacerts：列出 JAVA 环境 cacerts 中的可信证书（结构同 /api/certs，只读）。 */
    private static Map<String, Object> cacertsJson() {
        List<Map<String, Object>> list = new ArrayList<>();
        for (java.security.cert.X509Certificate c : loadCacertsCerts()) {
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("serial", certSerialHex(c));
            e.put("algo", certAlgoDesc(c));
            e.put("notBefore", fmtCacertsTime(c.getNotBefore()));
            e.put("notAfter", fmtCacertsTime(c.getNotAfter()));
            e.put("subject", c.getSubjectX500Principal().getName());
            list.add(e);
        }
        return Map.of("ok", true, "data", list);
    }

    /** cacerts 列表时间格式：yyyy/MM/dd HH:mm:ss（本地时区）。 */
    private static String fmtCacertsTime(java.util.Date d) {
        try {
            return new java.text.SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(d);
        } catch (Exception e) {
            return String.valueOf(d);
        }
    }

    /** 读取 JAVA 环境 cacerts（JKS/PKCS12，默认密码 changeit）中的全部证书。 */
    private static java.util.List<java.security.cert.X509Certificate> loadCacertsCerts() {
        java.util.List<java.security.cert.X509Certificate> out = new java.util.ArrayList<>();
        try {
            java.nio.file.Path cac = java.nio.file.Paths.get(
                    System.getProperty("java.home"), "lib", "security", "cacerts");
            if (!java.nio.file.Files.exists(cac)) {
                return out;
            }
            char[] pw = "changeit".toCharArray();
            for (String ksType : new String[]{"JKS", "PKCS12"}) {
                try {
                    java.security.KeyStore ks = java.security.KeyStore.getInstance(ksType);
                    try (java.io.InputStream in = java.nio.file.Files.newInputStream(cac)) {
                        ks.load(in, pw);
                    }
                    java.util.Enumeration<String> aliases = ks.aliases();
                    while (aliases.hasMoreElements()) {
                        java.security.cert.Certificate c = ks.getCertificate(aliases.nextElement());
                        if (c instanceof java.security.cert.X509Certificate) {
                            out.add((java.security.cert.X509Certificate) c);
                        }
                    }
                    break;
                } catch (Exception ignore) {
                    // 尝试下一种 keystore 类型
                }
            }
        } catch (Exception ignore) {
        }
        return out;
    }

    /** 证书序列号 -> 小写 hex（补前导零）。 */
    private static String certSerialHex(java.security.cert.X509Certificate c) {
        StringBuilder sb = new StringBuilder();
        for (byte b : c.getSerialNumber().toByteArray()) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    /** 证书公钥算法描述：RSA 2048 / EC 256 / DSA 1024 等。 */
    private static String certAlgoDesc(java.security.cert.X509Certificate c) {
        try {
            java.security.PublicKey pk = c.getPublicKey();
            String alg = pk.getAlgorithm();
            int bits = 0;
            if (pk instanceof java.security.interfaces.RSAPublicKey) {
                bits = ((java.security.interfaces.RSAPublicKey) pk).getModulus().bitLength();
            } else if (pk instanceof java.security.interfaces.ECPublicKey) {
                bits = ((java.security.interfaces.ECPublicKey) pk).getParams()
                        .getCurve().getField().getFieldSize();
            } else if (pk instanceof java.security.interfaces.DSAPublicKey) {
                bits = ((java.security.interfaces.DSAPublicKey) pk).getParams().getP().bitLength();
            }
            return alg + (bits > 0 ? " " + bits : "");
        } catch (Exception e) {
            return c.getPublicKey().getAlgorithm();
        }
    }

    /** 按序列号在 cacerts 中查找证书，返回 PEM 字节；未找到返回 null。 */
    private static byte[] findCacertsCertBySerial(String serial) {
        String want = serial == null ? "" : serial.toLowerCase().replace("0x", "");
        for (java.security.cert.X509Certificate c : loadCacertsCerts()) {
            if (certSerialHex(c).equals(want)) {
                try {
                    return X509JsonConverter.derToPem(c.getEncoded())
                            .getBytes(StandardCharsets.UTF_8);
                } catch (Exception e) {
                    return null;
                }
            }
        }
        return null;
    }

    /** 可作颁发者的序列号（CERTS.txt 中类型 R 或 C），供签发证书下拉选择。 */
    private static Map<String, Object> issuersJson() throws Exception {
        java.util.List<String> serials = new java.util.ArrayList<>();
        Path f = Paths.get(baseDir, "PKI", "CERTS.txt");
        if (Files.exists(f)) {
            for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#")) {
                    continue;
                }
                String[] p = t.split("\\s+");
                if (p.length < 7) {
                    continue;
                }
                char type = p[1].isEmpty() ? '?' : p[1].charAt(0);
                if (type == 'R' || type == 'C') {
                    serials.add(p[0]);
                }
            }
        }
        return Map.of("ok", true, "issuers", serials);
    }

    /** 日志接口：支持 lines=N（尾部行数）与 hours=N（最近 N 小时，0=全部）。 */
    private static Map<String, Object> logsJson(HttpExchange ex) {
        String q = ex.getRequestURI().getQuery();
        int lines = 200;
        int hours = 0;
        if (q != null) {
            for (String kv : q.split("&")) {
                try {
                    if (kv.startsWith("lines=")) {
                        lines = Integer.parseInt(kv.substring(6));
                    } else if (kv.startsWith("hours=")) {
                        hours = Integer.parseInt(kv.substring(6));
                    }
                } catch (Exception ignore) {
                    // 非法参数保持默认
                }
            }
        }
        if (hours > 0) {
            return Map.of("ok", true, "data", tailFileHours("PKI/logs.log", hours));
        }
        if (lines < 1 || lines > 5000) {
            lines = 200;
        }
        return Map.of("ok", true, "data", tailFile("PKI/logs.log", lines));
    }

    /**
     * 系统配置接口（GET）：读取 PKI/CONFIG.txt 的 6 个已知参数。
     * 文件不存在时返回默认模板值（exists=false）。
     */
    private static Map<String, Object> configJson() {
        Map<String, String> d = new LinkedHashMap<>();
        Path f = Paths.get(baseDir, "PKI", "CONFIG.txt");
        boolean exists = Files.exists(f);
        String webport = "80", suport = "8080", ocsp = "", crl = "", crt = "", cps = "", cpsNonice = "", ctlogApi = "/ct/add";
        if (exists) {
            try {
                for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                    String t = line.trim();
                    if (t.isEmpty() || t.startsWith("#")) {
                        continue;
                    }
                    int idx = t.indexOf('=');
                    if (idx <= 0) {
                        continue;
                    }
                    String k = t.substring(0, idx).trim();
                    String v = t.substring(idx + 1).trim();
                    if (k.equalsIgnoreCase("SUPORT")) {
                        suport = v;
                        continue;
                    }
                    if (k.equalsIgnoreCase("CTLOGapi")) {
                        if (v.equals("/ct/add") || v.equals("/ct/v1/add-chain")
                                || v.equals("/ct/v1/add-pre-chain")) {
                            ctlogApi = v;
                        }
                        continue;
                    }
                    switch (k) {
                        case "WEBPORT":   webport = v; break;
                        case "OCSP":      ocsp = v; break;
                        case "CRL":       crl = v; break;
                        case "CRT":       crt = v; break;
                        case "CPS":       cps = v; break;
                        case "CPS_Nonice":
                            // 文件中以字面 \n 存储，读取时转回真实换行供多行显示
                            cpsNonice = v.replace("\\n", "\n");
                            break;
                        default: break;
                    }
                }
            } catch (Exception e) {
                // 读取失败：返回默认值
            }
        } else {
            // 文件不存在：返回默认模板内容
            webport = "80";
            suport = "8080";
            ocsp = "http://localhost:80/OCSP";
            crl = "http://localhost:80/CRL/{CID}.crl";
            crt = "http://localhost:80/CRT/{CID}.crt";
            cps = "https://gitee.com/wxgshuju/modpkica";
            cpsNonice = "http://example.com/nonice";
            ctlogApi = "/ct/add";
        }
        d.put("webport", webport);
        d.put("suport", suport);
        d.put("ocsp", ocsp);
        d.put("crl", crl);
        d.put("crt", crt);
        d.put("cps", cps);
        d.put("cpsNonice", cpsNonice);
        d.put("ctlogApi", ctlogApi);
        return Map.of("ok", true, "exists", exists, "data", d);
    }

    /** 系统配置接口（POST）：参数化保存 CONFIG.txt（保留注释与未知键，缺失键自动补齐）。 */
    private static void saveConfig(HttpExchange ex) throws Exception {
        String bodyStr = new String(readAll(ex.getRequestBody()), StandardCharsets.UTF_8);
        Map<String, Object> m = parseJsonObject(bodyStr);
        Map<String, String> updates = new LinkedHashMap<>();
        updates.put("WEBPORT", str(m, "webport"));
        String su = str(m, "suport");
        updates.put("SUPORT", (su == null || su.isEmpty()) ? "8080" : su);
        updates.put("OCSP", str(m, "ocsp"));
        updates.put("CRL", str(m, "crl"));
        updates.put("CRT", str(m, "crt"));
        updates.put("CPS", str(m, "cps"));
        // CPS_Nonice：多行文本保存时，真实换行统一转字面 \n（单行存储）
        String nonice = str(m, "cpsNonice");
        nonice = nonice.replace("\r\n", "\n").replace('\r', '\n').replace("\n", "\\n");
        updates.put("CPS_Nonice", nonice);
        // CTLOGapi：默认 ctlog 请求方式，白名单校验，非法回退 /ct/add
        String ctApi = str(m, "ctlogApi");
        if (ctApi == null || ctApi.isEmpty()
                || !(ctApi.equals("/ct/add") || ctApi.equals("/ct/v1/add-chain")
                     || ctApi.equals("/ct/v1/add-pre-chain"))) {
            ctApi = "/ct/add";
        }
        updates.put("CTLOGapi", ctApi);

        Path f = Paths.get(baseDir, "PKI", "CONFIG.txt");
        java.util.List<String> lines;
        if (Files.exists(f)) {
            lines = Files.readAllLines(f, StandardCharsets.UTF_8);
        } else {
            // 文件不存在：先用默认模板初始化
            lines = new java.util.ArrayList<>(java.util.Arrays.asList(
                    "WEBPORT=80",
                    "SUPORT=8080",
                    "OCSP=http://localhost:80/OCSP",
                    "CRL=http://localhost:80/CRL/{CID}.crl",
                    "CRT=http://localhost:80/CRT/{CID}.crt",
                    "CPS=https://gitee.com/wxgshuju/modpkica",
                    "CPS_Nonice=http://example.com/nonice",
                    "CTLOGapi=/ct/add"));
        }
        StringBuilder sb = new StringBuilder();
        java.util.Set<String> done = new java.util.HashSet<>();
        for (String line : lines) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) {
                sb.append(line).append("\r\n");
                continue;
            }
            int idx = t.indexOf('=');
            if (idx <= 0) {
                sb.append(line).append("\r\n");
                continue;
            }
            String k = t.substring(0, idx).trim();
            if (updates.containsKey(k)) {
                sb.append(k).append('=').append(updates.get(k)).append("\r\n");
                done.add(k);
            } else {
                sb.append(line).append("\r\n");
            }
        }
        // 补齐缺失的已知键
        for (Map.Entry<String, String> e : updates.entrySet()) {
            if (!done.contains(e.getKey())) {
                sb.append(e.getKey()).append('=').append(e.getValue()).append("\r\n");
            }
        }
        Files.createDirectories(f.getParent());
        Files.write(f, sb.toString().getBytes(StandardCharsets.UTF_8)); // UTF-8 无 BOM
        MLog.append(baseDir, "WebAdmin /api/config",
                "POST /api/config 提交数据=" + bodyStr, "CONFIG.txt 已保存");
        sendJson(ex, 200, Map.of("ok", true, "message", "CONFIG.txt 已保存"));
    }

    /** 返回最近 N 小时内的日志条目（按条目级解析，兼容新旧格式）。 */    private static String tailFileHours(String rel, int hours) {
        try {
            Path p = Paths.get(baseDir, rel);
            if (!Files.exists(p)) {
                return "(暂无日志)";
            }
            String all = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
            String[] entries = all.split("\r?\n\r?\n");
            long cutoff = System.currentTimeMillis() - (long) hours * 3600_000L;
            StringBuilder sb = new StringBuilder();
            for (String e : entries) {
                String t = e.trim();
                if (t.isEmpty()) {
                    continue;
                }
                if (entryMillis(t) >= cutoff) {
                    sb.append(t).append("\n\n");
                }
            }
            return sb.length() == 0 ? "(最近 " + hours + " 小时内无日志)" : sb.toString();
        } catch (Exception e) {
            return "读取日志失败: " + e;
        }
    }

    /** 从日志条目文本提取毫秒时间戳：优先「时间戳:」行，旧格式按首行时间解析。 */
    private static long entryMillis(String entry) {
        for (String line : entry.split("\r?\n")) {
            if (line.startsWith("时间戳: ")) {
                try {
                    return Long.parseLong(line.substring(5).trim());
                } catch (Exception ignore) { }
            }
        }
        String first = entry.split("\r?\n")[0].trim();
        try {
            java.time.LocalDateTime dt = java.time.LocalDateTime.parse(first,
                    java.time.format.DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss"));
            return dt.atZone(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli();
        } catch (Exception ignore) { }
        return Long.MAX_VALUE; // 无法解析的条目视为最新，避免被过滤掉
    }

    // ============================================================
    // 证书链树（仪表盘树形图数据源）
    // ============================================================

    /**
     * 从 CERTS.txt 构建证书链树：
     * R（自签根）为顶层 → C（中间CA）挂其下 → E（终端证书）挂最下。
     * 每个节点附带：序列号、DN、密钥对类型、哈希算法、OCSP 状态、CRL 状态。
     */
    private static Map<String, Object> chainJson() throws Exception {
        CertsDB db = new CertsDB();
        db.load(baseDir);
        List<CertsDB.CertEntry> all = db.getAll();

        // 节点容器：serial → 节点
        Map<String, Object> nodes = new LinkedHashMap<>();
        // 记录每行，便于校验
        for (CertsDB.CertEntry e : all) {
            nodes.put(e.serial, buildChainNode(e));
        }

        // 顶层：自签 R（多根模型：issuerId 为空 或 == 自身序列号，无 root 别名）
        List<Object> roots = new ArrayList<>();
        for (CertsDB.CertEntry e : all) {
            boolean selfSigned = "R".equals(String.valueOf(e.type))
                    && (e.issuerId == null || e.issuerId.isEmpty()
                        || e.issuerId.equals(e.serial));
            if (selfSigned) {
                roots.add(nodes.get(e.serial));
            }
        }

        // 挂载非顶层节点
        for (CertsDB.CertEntry e : all) {
            boolean selfSigned = "R".equals(String.valueOf(e.type))
                    && (e.issuerId == null || e.issuerId.isEmpty()
                        || e.issuerId.equals(e.serial));
            if (selfSigned) {
                continue;
            }
            String parentId = e.issuerId;
            Object parent;
            if (parentId != null && nodes.containsKey(parentId)) {
                parent = nodes.get(parentId);
            } else {
                parent = null;
            }
            @SuppressWarnings("unchecked")
            List<Object> children = parent == null ? null
                    : (List<Object>) ((Map<String, Object>) parent).get("children");
            if (children != null) {
                children.add(nodes.get(e.serial));
            } else {
                // 孤立节点（颁发者未知）作为独立顶层展示，避免丢失
                roots.add(nodes.get(e.serial));
            }
        }
        return Map.of("ok", true, "data", roots);
    }

    /** 构造单个链节点（含证书文件信息加载）。 */
    private static Map<String, Object> buildChainNode(CertsDB.CertEntry e) {
        Map<String, Object> n = new LinkedHashMap<>();
        n.put("serial", e.serial);
        n.put("type", String.valueOf(e.type));
        n.put("status", String.valueOf(e.status));
        n.put("reason", e.reason);
        n.put("algo", e.algo == null ? "" : e.algo);
        n.put("children", new ArrayList<Object>());

        // 加载证书文件读取 DN 与哈希算法（找不到文件则给占位）
        String certPath = findCertFile(e.serial);
        if (certPath != null) {
            try {
                java.security.cert.X509Certificate c = PemIO.readCert(baseDir + "/" + certPath);
                n.put("dn", c.getSubjectX500Principal().getName());
                n.put("hash", hashFromCert(c));
                n.put("bits", keyBits(c));      // 密钥长度（位）
                n.put("kind", certKind(c));     // 证书子类型（TSA/OCSP/SSL/代码签名/文档签名）
            } catch (Exception ex) {
                n.put("dn", "(证书文件读取失败: " + certPath + ")");
                n.put("hash", "");
                n.put("bits", 0);
                n.put("kind", "");
            }
        } else {
            n.put("dn", "(未找到证书文件)");
            n.put("hash", "");
            n.put("bits", 0);
            n.put("kind", "");
        }

        // OCSP / CRL 状态（基于 CERTS.txt 登记状态；两者都以此为准）
        if (e.status == 'R') {
            n.put("ocsp", "revoked");
            n.put("crl", "已吊销");
        } else if (e.status == 'V') {
            n.put("ocsp", "good");
            n.put("crl", "未吊销");
        } else {
            n.put("ocsp", "unknown");
            n.put("crl", "未知");
        }
        return n;
    }

    /** 按序列号查找证书文件（多目录回退；OCSP/TIMSTAMP 按内容扫描匹配）。 */
    static String findCertFile(String serial) {
        // 路径拼接前白名单校验：仅允许 hex 序列号，防止 ../ 穿越读取任意文件
        String s = normSerial(serial);
        if (s == null) {
            return null;
        }
        serial = s;
        String[] dirs = {
            "PKI/WebPublic/CRT/", "PKI/ROOT/", "PKI/CA/", "PKI/CERT/", "PKI/KEY/", "PKI/MY/"
        };
        for (String d : dirs) {
            String p = d + serial + ".crt";
            if (Files.exists(Paths.get(baseDir, p))) {
                return p;
            }
        }
        // OCSP：文件名为 颁发者序列号_ocsp.crt，按证书内容序列号扫描匹配
        String ocspHit = scanSerialInDir("PKI/OCSP/", serial);
        if (ocspHit != null) {
            return ocspHit;
        }
        // TIMSTAMP：文件名为 rsa_sha1.crt 等，同样扫描匹配
        String tsaHit = scanSerialInDir("PKI/TIMSTAMP/", serial);
        if (tsaHit != null) {
            return tsaHit;
        }
        return null;
    }

    /** 扫描目录下全部 .crt，返回证书序列号与目标一致的相对路径。 */
    private static String scanSerialInDir(String dir, String serial) {
        java.io.File folder = new java.io.File(baseDir, dir);
        java.io.File[] files = folder.listFiles((d, name) -> name.endsWith(".crt"));
        if (files == null) {
            return null;
        }
        for (java.io.File f : files) {
            try {
                java.security.cert.X509Certificate c = PemIO.readCert(f.getAbsolutePath());
                if (c.getSerialNumber().toString(16).equalsIgnoreCase(serial)) {
                    return dir + f.getName();
                }
            } catch (Exception ignored) { }
        }
        return null;
    }

    /** 从证书签名算法推导哈希算法名（sha1/sha256/sha384/sha512/sm3）。 */
    private static String hashFromCert(java.security.cert.X509Certificate c) {
        String alg = c.getSigAlgName();
        if (alg != null) {
            String up = alg.toUpperCase();
            if (up.contains("SM3")) {
                return "sm3";
            }
            if (up.contains("SHA3-224") || up.contains("SHA3_224")) {
                return "sha3-224";
            }
            if (up.contains("SHA3-256") || up.contains("SHA3_256")) {
                return "sha3-256";
            }
            if (up.contains("SHA3-384") || up.contains("SHA3_384")) {
                return "sha3-384";
            }
            if (up.contains("SHA3-512") || up.contains("SHA3_512")) {
                return "sha3-512";
            }
            if (up.contains("SHA512")) {
                return "sha512";
            }
            if (up.contains("SHA384")) {
                return "sha384";
            }
            if (up.contains("SHA256")) {
                return "sha256";
            }
            if (up.contains("SHA224")) {
                return "sha224";
            }
            if (up.contains("SHA1") || up.contains("SHA-1")) {
                return "sha1";
            }
            if (up.contains("MD5")) {
                return "md5";
            }
            return alg;
        }
        // fallback: derive from signature algorithm OID (match SHA3 sig OIDs first)
        String oid = c.getSigAlgOID();
        if (oid != null) {
            if (oid.equals(Sm2Util.OID_SM3_WITH_SM2)) {
                return "sm3";
            }
            if (oid.endsWith(".101.3.4.3.1") || oid.endsWith(".101.3.4.3.5")
                    || oid.endsWith(".101.3.4.3.9") || oid.endsWith(".101.3.4.3.13")) {
                return "sha3-224";
            }
            if (oid.endsWith(".101.3.4.3.2") || oid.endsWith(".101.3.4.3.6")
                    || oid.endsWith(".101.3.4.3.10") || oid.endsWith(".101.3.4.3.14")) {
                return "sha3-256";
            }
            if (oid.endsWith(".101.3.4.3.3") || oid.endsWith(".101.3.4.3.7")
                    || oid.endsWith(".101.3.4.3.11") || oid.endsWith(".101.3.4.3.15")) {
                return "sha3-384";
            }
            if (oid.endsWith(".101.3.4.3.4") || oid.endsWith(".101.3.4.3.8")
                    || oid.endsWith(".101.3.4.3.12") || oid.endsWith(".101.3.4.3.16")) {
                return "sha3-512";
            }
            if (oid.contains(".11") || oid.endsWith(".2.1")) {
                return "sha256";
            }
            if (oid.endsWith(".2.2") || oid.endsWith(".12")) {
                return "sha384";
            }
            if (oid.endsWith(".2.3") || oid.endsWith(".13")) {
                return "sha512";
            }
            if (oid.endsWith(".5") || oid.endsWith(".29") || oid.endsWith(".3.1")) {
                return "sha1";
            }
        }
        return "";
    }

    /** 从证书公钥推导密钥长度（位）：RSA=模数位长，ECC/SM2=曲线域大小。 */
    private static int keyBits(java.security.cert.X509Certificate c) {
        try {
            java.security.PublicKey pk = c.getPublicKey();
            if (pk instanceof java.security.interfaces.RSAPublicKey) {
                return ((java.security.interfaces.RSAPublicKey) pk).getModulus().bitLength();
            }
            if (pk instanceof java.security.interfaces.ECPublicKey) {
                java.security.interfaces.ECPublicKey ec =
                        (java.security.interfaces.ECPublicKey) pk;
                return ec.getParams().getCurve().getField().getFieldSize();
            }
        } catch (Exception ignored) { }
        return 0;
    }

    /** EKU OID：TSA / OCSP 专用。 */
    private static final String OID_EKU_TSA = "1.3.6.1.5.5.7.3.8";
    private static final String OID_EKU_OCSP = "1.3.6.1.5.5.7.3.9";

    /**
     * 识别证书子类型（终端证书方括号内容，只能显示一种）：
     * TSA/OCSP/文档签名靠 EKU；SSL(DV/IV/OV/EV)、代码签名(普通/EV)靠证书策略 OID；
     * TSA 证书另有策略标记 OID 2.23.140.1.4.2。
     */
    private static String certKind(java.security.cert.X509Certificate c) {
        // 1) EKU 优先：TSA / OCSP / 文档签名（标准 1.3.6.1.5.5.7.3.36，微软 1.3.6.1.4.1.311.3.10.3.12）
        try {
            java.util.List<String> eku = c.getExtendedKeyUsage();
            if (eku != null) {
                if (eku.contains(OID_EKU_TSA)) {
                    return "TSA证书";
                }
                if (eku.contains(OID_EKU_OCSP)) {
                    return "OCSP证书";
                }
                if (eku.contains("1.3.6.1.5.5.7.3.36")) {
                    return "文档签名(标准)";
                }
                if (eku.contains("1.3.6.1.4.1.311.3.10.3.12")) {
                    return "文档签名(微软)";
                }
            }
        } catch (Exception ignored) { }
        // 2) 证书策略 OID（CA/B Forum 体系；按优先级匹配，只显示一种）
        // 优先级：TSA 标记 > SSL(EV) > 代码签名(EV) > 代码签名(普通) > SSL(DV/OV/IV)
        // 普通终端证书策略同时含 2.23.140.1.1 与 2.23.140.1.3，此时按 SSL(EV) 显示（默认用途）
        Set<String> oids = policyOidSet(c);
        if (oids.contains("2.23.140.1.4.2")) return "TSA证书";        // TSA 证书策略标记
        if (oids.contains("2.23.140.1.1"))   return "SSL证书(EV)";
        if (oids.contains("2.23.140.1.3"))   return "代码签名(EV)";
        if (oids.contains("2.23.140.1.4.1")) return "代码签名(普通)";
        if (oids.contains("2.23.140.1.2.1")) return "SSL证书(DV)";
        if (oids.contains("2.23.140.1.2.2")) return "SSL证书(OV)";
        if (oids.contains("2.23.140.1.2.3")) return "SSL证书(IV)";
        return "";
    }

    /** 读取证书策略扩展（2.5.29.32）中的全部策略 OID。 */
    private static Set<String> policyOidSet(java.security.cert.X509Certificate c) {
        Set<String> oids = new LinkedHashSet<>();
        try {
            byte[] ext = c.getExtensionValue("2.5.29.32");
            if (ext == null) {
                return oids;
            }
            org.bouncycastle.asn1.ASN1OctetString oct =
                    (org.bouncycastle.asn1.ASN1OctetString)
                            org.bouncycastle.asn1.ASN1Primitive.fromByteArray(ext);
            org.bouncycastle.asn1.x509.CertificatePolicies policies =
                    org.bouncycastle.asn1.x509.CertificatePolicies.getInstance(oct.getOctets());
            for (org.bouncycastle.asn1.x509.PolicyInformation pi
                    : policies.getPolicyInformation()) {
                oids.add(pi.getPolicyIdentifier().getId());
            }
        } catch (Exception ignored) { }
        return oids;
    }

    // ============================================================
    // 证书 JSON 详情（复用 X509JsonConverter 无损转换）
    // ============================================================

    /** /api/certjson?serial=xxx：返回 X509JsonConverter 风格的证书 JSON 文本。 */
    private static Map<String, Object> certJson(HttpExchange ex) throws Exception {
        String q = ex.getRequestURI().getQuery();
        String serial = normSerial(qp(q, "serial"));
        if (serial == null) {
            return Map.of("ok", false, "message", "缺少或非法参数 serial");
        }
        String certPath = findCertFile(serial);
        if (certPath == null) {
            // 回退：在 JAVA cacerts 中按序列号查找
            byte[] pem = findCacertsCertBySerial(serial);
            if (pem != null) {
                try {
                    String json = X509JsonConverter.certToJson(pem);
                    return Map.of("ok", true, "serial", serial, "path", "JAVA cacerts", "data", json);
                } catch (Exception e) {
                    return Map.of("ok", false, "message", "cacerts 证书解析失败: " + e);
                }
            }
            return Map.of("ok", false, "message", "未找到证书文件: " + serial);
        }
        try {
            byte[] pem = Files.readAllBytes(Paths.get(baseDir, certPath));
            String json = X509JsonConverter.certToJson(pem);
            return Map.of("ok", true, "serial", serial, "path", certPath, "data", json);
        } catch (Exception e) {
            return Map.of("ok", false, "message", "证书解析失败: " + e);
        }
    }

    /** /api/certchainjson?serial=xxx：按颁发者链递归返回每层证书 JSON（[终端, ..., 根]）。 */
    private static Map<String, Object> certChainJson(HttpExchange ex) throws Exception {
        String q = ex.getRequestURI().getQuery();
        String serial = normSerial(qp(q, "serial"));
        if (serial == null) {
            return Map.of("ok", false, "message", "缺少或非法参数 serial");
        }
        CertsDB db = new CertsDB();
        db.load(baseDir);
        java.util.List<String> jsons = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        String cur = serial;
        while (cur != null && !cur.isEmpty() && !"null".equalsIgnoreCase(cur)
                && seen.add(cur.toLowerCase())) {
            String certPath = findCertFile(cur);
            if (certPath == null) {
                break;
            }
            byte[] pem = Files.readAllBytes(Paths.get(baseDir, certPath));
            jsons.add(X509JsonConverter.certToJson(pem));
            String parent = db.findIssuerIdBySerial(cur);
            if (parent == null || parent.isEmpty() || "null".equalsIgnoreCase(parent)
                    || parent.equalsIgnoreCase(cur)) {
                break;
            }
            cur = parent;
        }
        if (jsons.isEmpty()) {
            return Map.of("ok", false, "message", "未找到证书文件: " + serial);
        }
        return Map.of("ok", true, "serial", serial, "data", jsons);
    }

    // ============================================================
    // 小工具

    // ============================================================
    // 证书下载 / 导出（证书库右键菜单）
    // ============================================================

    /** /api/cert/download?serial=..&kind=..&password=..&src=certs|cacerts|my —— 下载文件（附件）。 */
    private static void certDownload(HttpExchange ex) throws Exception {
        String q = ex.getRequestURI().getQuery();
        String serial = normSerial(qp(q, "serial"));
        String kind = qp(q, "kind");
        String password = qp(q, "password");
        String src = qp(q, "src");
        if (serial == null || kind == null || kind.isEmpty()) {
            sendJson(ex, 400, Map.of("ok", false, "message", "缺少或非法参数 serial/kind"));
            return;
        }
        if (src == null || src.isEmpty()) {
            src = "certs";
        }
        byte[] data;
        String fileName;
        try {
            switch (kind) {
                case "single_crt":
                case "chain_crt":
                case "issuer_crt": {
                    java.util.List<java.security.cert.X509Certificate> chain = buildCertChain(serial, src);
                    if (chain.isEmpty()) {
                        sendJson(ex, 404, Map.of("ok", false, "message", "未找到证书: " + serial));
                        return;
                    }
                    int from = "issuer_crt".equals(kind) ? Math.min(1, chain.size()) : 0;
                    int to = "single_crt".equals(kind) ? Math.min(1, chain.size()) : chain.size();
                    StringBuilder pem = new StringBuilder();
                    for (int i = from; i < to; i++) {
                        pem.append(X509JsonConverter.derToPem(chain.get(i).getEncoded()));
                    }
                    data = pem.toString().getBytes(StandardCharsets.UTF_8);
                    fileName = serial + ".crt";
                    break;
                }
                case "p7b": {
                    java.util.List<java.security.cert.X509Certificate> chain = buildCertChain(serial, src);
                    if (chain.isEmpty()) {
                        sendJson(ex, 404, Map.of("ok", false, "message", "未找到证书: " + serial));
                        return;
                    }
                    data = p7bBytes(chain);
                    fileName = serial + ".p7b";
                    break;
                }
                case "key": {
                    String keyPath = findKeyFile(serial, src);
                    if (keyPath == null) {
                        sendJson(ex, 404, Map.of("ok", false, "message",
                                "未找到私钥文件: " + serial + "（已查找 PKI/MY、PKI/KEY、PKI/ROOT、PKI/CA、PKI/OCSP 目录）"));
                        return;
                    }
                    data = Files.readAllBytes(Paths.get(baseDir, keyPath));
                    fileName = serial + ".key";
                    break;
                }
                case "pfx":
                case "jks": {
                    java.util.List<java.security.cert.X509Certificate> chain = buildCertChain(serial, src);
                    String keyPath = findKeyFile(serial, src);
                    if (chain.isEmpty() || keyPath == null) {
                        sendJson(ex, 404, Map.of("ok", false, "message", "证书或私钥不存在: " + serial));
                        return;
                    }
                    if (password == null) {
                        password = "";
                    }
                    java.security.PrivateKey key = readJcaPrivateKey(keyPath);
                    data = keyStoreBytes(chain, key, password, "pfx".equals(kind) ? "PKCS12" : "JKS");
                    fileName = serial + ("pfx".equals(kind) ? ".pfx" : ".jks");
                    break;
                }
                default:
                    sendJson(ex, 400, Map.of("ok", false, "message", "未知 kind: " + kind));
                    return;
            }
        } catch (Exception e) {
            sendJson(ex, 500, Map.of("ok", false, "message", "下载失败: " + e));
            return;
        }
        sendBytes(ex, 200, "application/octet-stream", fileName, data);
    }

    /** /api/cert/export?serial=..&kind=..&src=.. —— 导出文本（剪贴板）。 */
    private static void certExport(HttpExchange ex) throws Exception {
        String q = ex.getRequestURI().getQuery();
        String serial = normSerial(qp(q, "serial"));
        String kind = qp(q, "kind");
        String src = qp(q, "src");
        if (serial == null || kind == null || kind.isEmpty()) {
            sendJson(ex, 400, Map.of("ok", false, "message", "缺少或非法参数 serial/kind"));
            return;
        }
        if (src == null || src.isEmpty()) {
            src = "certs";
        }
        String text;
        try {
            switch (kind) {
                case "cert_pem": {
                    java.security.cert.X509Certificate c = loadCertBySource(serial, src);
                    text = X509JsonConverter.derToPem(c.getEncoded());
                    break;
                }
                case "chain_pem":
                case "issuer_pem": {
                    java.util.List<java.security.cert.X509Certificate> chain = buildCertChain(serial, src);
                    if (chain.isEmpty()) {
                        sendJson(ex, 404, Map.of("ok", false, "message", "未找到证书: " + serial));
                        return;
                    }
                    int from = "issuer_pem".equals(kind) ? Math.min(1, chain.size()) : 0;
                    StringBuilder pem = new StringBuilder();
                    for (int i = from; i < chain.size(); i++) {
                        pem.append(X509JsonConverter.derToPem(chain.get(i).getEncoded()));
                    }
                    text = pem.toString();
                    break;
                }
                case "key_pem":
                case "key_hex":
                case "key_b64": {
                    String keyPath = findKeyFile(serial, src);
                    if (keyPath == null) {
                        sendJson(ex, 404, Map.of("ok", false, "message",
                                "未找到私钥文件: " + serial + "（已查找 PKI/MY、PKI/KEY、PKI/ROOT、PKI/CA、PKI/OCSP 目录）"));
                        return;
                    }
                    byte[] raw = Files.readAllBytes(Paths.get(baseDir, keyPath));
                    byte[] der = "key_pem".equals(kind) ? raw : pemToDer(raw);
                    if ("key_pem".equals(kind)) {
                        text = new String(Files.readAllBytes(Paths.get(baseDir, keyPath)),
                                StandardCharsets.UTF_8);
                    } else if ("key_hex".equals(kind)) {
                        text = hexOf(der);
                    } else {
                        text = Base64.getEncoder().encodeToString(der);
                    }
                    break;
                }
                default:
                    sendJson(ex, 400, Map.of("ok", false, "message", "未知 kind: " + kind));
                    return;
            }
        } catch (Exception e) {
            sendJson(ex, 500, Map.of("ok", false, "message", "导出失败: " + e));
            return;
        }
        sendJson(ex, 200, Map.of("ok", true, "text", text));
    }

    /** query 参数提取（URL 解码，非法编码返回 null）。 */
    private static String qp(String q, String name) {
        if (q == null) {
            return null;
        }
        for (String kv : q.split("&")) {
            if (kv.startsWith(name + "=")) {
                String v = kv.substring(name.length() + 1);
                try {
                    return java.net.URLDecoder.decode(v, StandardCharsets.UTF_8);
                } catch (IllegalArgumentException e) {
                    return null;
                }
            }
        }
        return null;
    }

    /** 序列号规范化：去 0x 前缀 + 小写 + [0-9a-f] 白名单校验。
     *  返回 null 表示缺失/非法（调用方应返回 400）。所有拼接文件路径的 serial 必须经过本校验，
     *  防止路径穿越读取任意 .crt/.key。 */
    private static String normSerial(String serial) {
        if (serial == null) {
            return null;
        }
        String s = serial.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {
            s = s.substring(2);
        }
        if (s.isEmpty() || !s.matches("[0-9a-fA-F]+")) {
            return null;
        }
        return s.toLowerCase();
    }

    /** 按序列号加载证书（src=certs|cacerts|my）。序列号经 normSerial 白名单校验。 */
    private static java.security.cert.X509Certificate loadCertBySource(String serial, String src)
            throws Exception {
        serial = normSerial(serial);
        if (serial == null) {
            throw new Exception("非法序列号: " + serial);
        }
        if ("cacerts".equals(src)) {
            String want = serial;
            for (java.security.cert.X509Certificate c : loadCacertsCerts()) {
                if (certSerialHex(c).equals(want)) {
                    return c;
                }
            }
            throw new Exception("cacerts 未找到序列号: " + serial);
        }
        String certPath = findCertFile(serial);
        if (certPath == null) {
            throw new Exception("未找到证书文件: " + serial);
        }
        return PemIO.readCert(baseDir + "/" + certPath);
    }

    /** 构建证书链（自身 → 颁发者 → … → 根）。 */
    private static java.util.List<java.security.cert.X509Certificate> buildCertChain(
            String serial, String src) throws Exception {
        java.util.List<java.security.cert.X509Certificate> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        out.add(loadCertBySource(serial, src));
        seen.add(serial.toLowerCase());
        CertsDB db = null;
        try {
            db = new CertsDB();
            db.load(baseDir);
        } catch (Exception ignore) {
            db = null;
        }
        java.security.cert.X509Certificate issuer = out.get(0);
        String cur = serial;
        while (true) {
            String parent = null;
            if (db != null) {
                try {
                    parent = db.findIssuerIdBySerial(cur);
                } catch (Exception ignore) {
                    parent = null;
                }
            }
            if (parent == null || parent.isEmpty() || "null".equalsIgnoreCase(parent)) {
                parent = findIssuerByDn(issuer, src);
            }
            if (parent == null || parent.equalsIgnoreCase(cur)
                    || !seen.add(parent.toLowerCase())) {
                break;
            }
            try {
                java.security.cert.X509Certificate pc = loadCertBySource(
                        parent, "cacerts".equals(src) ? "cacerts" : "certs");
                out.add(pc);
                issuer = pc;
                cur = parent;
            } catch (Exception e) {
                break;
            }
        }
        return out;
    }

    /** 按颁发者 DN 在 ROOT/CA/MY/CERT/WebPublic 目录及 cacerts 中寻找 subject 匹配的上级证书。 */
    private static String findIssuerByDn(java.security.cert.X509Certificate child, String src) {
        String issuerDn;
        try {
            issuerDn = child.getIssuerX500Principal().getName();
        } catch (Exception e) {
            return null;
        }
        String subjectDn = null;
        try {
            subjectDn = child.getSubjectX500Principal().getName();
        } catch (Exception ignore) {
            subjectDn = null;
        }
        if (issuerDn != null && issuerDn.equals(subjectDn)) {
            return null; // 自签根
        }
        String[] dirs = {"PKI/ROOT/", "PKI/CA/", "PKI/MY/", "PKI/CERT/", "PKI/WebPublic/CRT/"};
        for (String d : dirs) {
            Path dir = Paths.get(baseDir, d);
            if (!Files.isDirectory(dir)) {
                continue;
            }
            try (Stream<Path> st = Files.list(dir)) {
                List<Path> crts = st.filter(p -> p.getFileName().toString().endsWith(".crt"))
                        .collect(Collectors.toList());
                for (Path p : crts) {
                    try {
                        java.security.cert.X509Certificate c = PemIO.readCert(p.toString());
                        if (issuerDn.equals(c.getSubjectX500Principal().getName())) {
                            return c.getSerialNumber().toString(16).toLowerCase();
                        }
                    } catch (Exception ignore) {
                    }
                }
            } catch (Exception ignore) {
            }
        }
        if (!"certs".equals(src)) {
            for (java.security.cert.X509Certificate c : loadCacertsCerts()) {
                try {
                    if (issuerDn.equals(c.getSubjectX500Principal().getName())) {
                        return certSerialHex(c);
                    }
                } catch (Exception ignore) {
                }
            }
        }
        return null;
    }

    /** 查找私钥文件路径（相对 baseDir；cacerts 无私钥返回 null）。序列号经白名单校验。 */
    private static String findKeyFile(String serial, String src) {
        if ("cacerts".equals(src)) {
            return null;
        }
        String s = normSerial(serial);
        if (s == null) {
            return null;
        }
        String[] cands = {
                "PKI/MY/" + s + ".key",
                "PKI/KEY/" + s + ".key",
                "PKI/ROOT/" + s + ".key",
                "PKI/CA/" + s + ".key",
                "PKI/OCSP/" + s + "_ocsp.key"};
        for (String p : cands) {
            if (Files.exists(Paths.get(baseDir, p))) {
                return p;
            }
        }
        return null;
    }

    /** PKCS#7 certificates-only（.p7b）。 */
    private static byte[] p7bBytes(java.util.List<java.security.cert.X509Certificate> chain)
            throws Exception {
        org.bouncycastle.cms.CMSSignedDataGenerator gen =
                new org.bouncycastle.cms.CMSSignedDataGenerator();
        gen.addCertificates(new org.bouncycastle.cert.jcajce.JcaCertStore(chain));
        org.bouncycastle.cms.CMSSignedData sd =
                gen.generate(new org.bouncycastle.cms.CMSAbsentContent(), false);
        return sd.getEncoded();
    }

    /** PKCS12 / JKS 密钥库（证书链 + 私钥 + 密码）。 */
    private static byte[] keyStoreBytes(
            java.util.List<java.security.cert.X509Certificate> chain,
            java.security.PrivateKey key, String password, String type) throws Exception {
        java.security.KeyStore ks = "PKCS12".equals(type)
                ? java.security.KeyStore.getInstance("PKCS12", "BC")
                : java.security.KeyStore.getInstance("JKS"); // 默认 JDK provider
        ks.load(null, null);
        char[] pw = password.toCharArray();
        String alias = chain.get(0).getSerialNumber().toString(16).toLowerCase();
        ks.setKeyEntry(alias, key, pw, chain.toArray(new java.security.cert.Certificate[0]));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ks.store(bos, pw);
        return bos.toByteArray();
    }

    /** 读取私钥文件为 JCA PrivateKey（支持 PKCS#1 / SEC1 / PKCS#8 / OpenSSH 等 PEM 类型）。 */
    private static java.security.PrivateKey readJcaPrivateKey(String keyPath) throws Exception {
        try (java.io.Reader r = new java.io.InputStreamReader(
                Files.newInputStream(Paths.get(baseDir, keyPath)), StandardCharsets.UTF_8);
             org.bouncycastle.openssl.PEMParser pp = new org.bouncycastle.openssl.PEMParser(r)) {
            Object o = pp.readObject();
            org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter cv =
                    new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter();
            if (o instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
                return cv.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) o);
            }
            if (o instanceof org.bouncycastle.openssl.PEMKeyPair) {
                org.bouncycastle.openssl.PEMKeyPair kp =
                        (org.bouncycastle.openssl.PEMKeyPair) o;
                if (kp.getPrivateKeyInfo() != null) {
                    return cv.getPrivateKey(kp.getPrivateKeyInfo());
                }
                return cv.getKeyPair(kp).getPrivate();
            }
            if (o instanceof org.bouncycastle.asn1.pkcs.RSAPrivateKey) {
                return cv.getPrivateKey(org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(o));
            }
            if (o instanceof org.bouncycastle.asn1.sec.ECPrivateKey) {
                org.bouncycastle.asn1.sec.ECPrivateKey ec =
                        (org.bouncycastle.asn1.sec.ECPrivateKey) o;
                org.bouncycastle.asn1.x509.AlgorithmIdentifier algId =
                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                org.bouncycastle.asn1.x9.X9ObjectIdentifiers.id_ecPublicKey,
                                ec.getParametersObject());
                return cv.getPrivateKey(
                        new org.bouncycastle.asn1.pkcs.PrivateKeyInfo(algId, ec));
            }
            if (o instanceof org.bouncycastle.crypto.params.AsymmetricKeyParameter) {
                org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki =
                        org.bouncycastle.crypto.util.PrivateKeyInfoFactory
                                .createPrivateKeyInfo((org.bouncycastle.crypto.params.AsymmetricKeyParameter) o);
                return cv.getPrivateKey(pki);
            }
            throw new Exception("不支持的私钥格式: " + (o == null ? "null" : o.getClass().getSimpleName()));
        }
    }

    /** PEM 字节 → DER 字节（已是 DER 时原样返回）。字符过滤方式，兼容任何 PEM 变体。 */
    private static byte[] pemToDer(byte[] pemBytes) {
        String txt = new String(pemBytes, StandardCharsets.US_ASCII);
        int b = txt.indexOf("-----BEGIN");
        int e = txt.indexOf("-----END");
        if (b < 0 || e < 0) {
            return pemBytes;
        }
        // 从 PEM 头后的换行开始收集 base64 字符，避免把 "BEGIN CERTIFICATE" 头部的字母误当数据
        int nl = txt.indexOf('\n', b);
        int start = (nl >= 0 && nl < e) ? nl + 1 : b + 27;
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < e; i++) {
            char c = txt.charAt(i);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
                sb.append(c);
            }
        }
        return Base64.getDecoder().decode(sb.toString());
    }

    /** 发送二进制文件（附件下载）。 */
    private static void sendBytes(HttpExchange ex, int code, String contentType,
            String fileName, byte[] data) throws IOException {
        ex.getResponseHeaders().set("Content-Type", contentType);
        ex.getResponseHeaders().set("Content-Disposition",
                "attachment; filename=\"" + fileName + "\"");
        ex.getResponseHeaders().set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        ex.getResponseHeaders().set("Pragma", "no-cache");
        ex.sendResponseHeaders(code, data.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(data);
        }
    }

    // ============================================================
    // 小工具
    // ============================================================

    /** 读取 CONFIG.txt 的 WEBPORT（供状态展示）。 */
    private static String readConfigWebPort() {
        try {
            Path f = Paths.get(baseDir, "PKI", "CONFIG.txt");
            if (!Files.exists(f)) {
                return "未配置";
            }
            for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                String t = line.trim();
                if (t.toUpperCase().startsWith("WEBPORT")) {
                    int i = t.indexOf('=');
                    return i >= 0 ? t.substring(i + 1).trim() : t;
                }
            }
        } catch (Exception ignore) {
            // 读取失败返回默认
        }
        return "未配置";
    }

    /** logs.log 行数（缓冲读 + 30 秒缓存，避免每次状态请求全文件扫描）。 */
    private static volatile long lastLogCountTime = 0;
    private static volatile long cachedLogLines = 0;
    private static long countLogLines() {
        long now = System.currentTimeMillis();
        if (now - lastLogCountTime < 30_000) {
            return cachedLogLines;
        }
        lastLogCountTime = now;
        try {
            Path f = Paths.get(baseDir, "PKI", "logs.log");
            if (!Files.exists(f)) {
                cachedLogLines = 0;
                return 0;
            }
            long count = 0;
            byte[] buf = new byte[262144];
            try (BufferedInputStream in = new BufferedInputStream(Files.newInputStream(f), 262144)) {
                int n;
                while ((n = in.read(buf)) != -1) {
                    for (int i = 0; i < n; i++) {
                        if (buf[i] == '\n') {
                            count++;
                        }
                    }
                }
            }
            cachedLogLines = count;
            return count;
        } catch (Exception e) {
            return cachedLogLines;
        }
    }

    /** 读文件尾部最多 lines 行（仅定位换行起点，整段一次性 UTF-8 解码，避免分块解码截断多字节中文）。 */
    private static String tailFile(String relPath, int lines) {
        Path f = Paths.get(baseDir, relPath);
        if (!Files.exists(f)) {
            return "(日志文件不存在: " + relPath + ")";
        }
        try (RandomAccessFile raf = new RandomAccessFile(f.toFile(), "r")) {
            long length = raf.length();
            long pos = length;
            int newlines = 0;
            long block = Math.min(64 * 1024, length);
            byte[] buf = new byte[(int) block];
            // 从尾部向前按块扫描，仅定位第 (lines+1) 个换行的字节位置，不在扫描中解码
            while (pos > 0 && newlines <= lines) {
                long start = Math.max(0, pos - block);
                int readLen = (int) (pos - start);
                raf.seek(start);
                raf.readFully(buf, 0, readLen);
                int nl = 0;
                long cut = -1; // 本块内第 (lines+1) 个换行的下一字节（文件绝对偏移）
                for (int i = readLen - 1; i >= 0; i--) {
                    if (buf[i] == '\n') {
                        nl++;
                        if (newlines + nl > lines) {
                            cut = start + i + 1;
                            break;
                        }
                    }
                }
                if (cut >= 0) {
                    byte[] tail = new byte[(int) (length - cut)];
                    raf.seek(cut);
                    raf.readFully(tail);
                    return new String(tail, StandardCharsets.UTF_8);
                }
                newlines += nl;
                pos = start;
                if (start == 0) {
                    break;
                }
            }
            // 整个文件不足 lines 行：从头读到尾一次性解码
            byte[] all = new byte[(int) length];
            raf.seek(0);
            raf.readFully(all);
            return new String(all, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "(读取日志失败: " + e.getMessage() + ")";
        }
    }

    /** 读取请求体全部字节（读中限流：超过 maxBytes 立即抛 IOException，避免大 body 先占满内存）。 */
    private static byte[] readAll(InputStream in, long maxBytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        long total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > maxBytes) {
                throw new IOException("请求体过大（上限 " + (maxBytes / (1024 * 1024)) + "MB）");
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    /** 读取请求体全部字节（默认读中上限 8MB，超过即中止）。 */
    private static byte[] readAll(InputStream in) throws IOException {
        return readAll(in, 8L * 1024 * 1024);
    }

    // ============================================================
    // 签名专区：微软代码签名 / PDF 文档签名（multipart 上传 → SignTool）
    // ============================================================

    /** 解析 multipart/form-data 请求体，返回 字段名 → 字节。 */
    private static Map<String, byte[]> readMultipart(HttpExchange ex) throws Exception {
        String ct = ex.getRequestHeaders().getFirst("Content-Type");
        if (ct == null || !ct.startsWith("multipart/form-data")) {
            throw new IllegalArgumentException("需要 multipart/form-data 上传");
        }
        String boundary = null;
        for (String part : ct.split(";")) {
            String t = part.trim();
            if (t.startsWith("boundary=")) {
                boundary = t.substring("boundary=".length()).replace("\"", "").trim();
            }
        }
        if (boundary == null || boundary.isEmpty()) {
            throw new IllegalArgumentException("缺少 multipart boundary");
        }
        // P2-04: cap request body size before buffering it all (memory DoS guard).
        // 总请求体上限 256MB（兼容批量多文件），单个文件字段上限 20MB。
        String lenH = ex.getRequestHeaders().getFirst("Content-Length");
        if (lenH != null) {
            try {
                long len = Long.parseLong(lenH.trim());
                if (len > 256L * 1024 * 1024) {
                    throw new IllegalArgumentException("上传内容过大（总上限 256MB）");
                }
            } catch (NumberFormatException ignore) {
            }
        }
        byte[] body = readAll(ex.getRequestBody(), 256L * 1024 * 1024);
        if (body.length > 256L * 1024 * 1024) {
            throw new IllegalArgumentException("上传内容过大（总上限 256MB）");
        }
        byte[] delim = ("--" + boundary).getBytes(StandardCharsets.ISO_8859_1);
        Map<String, byte[]> fields = new LinkedHashMap<>();
        int pos = 0;
        while (true) {
            int start = indexOfBytes(body, delim, pos);
            if (start < 0) {
                break;
            }
            int after = start + delim.length;
            // 结束标记 "--"
            if (after + 1 < body.length && body[after] == '-' && body[after + 1] == '-') {
                break;
            }
            if (after < body.length && body[after] == '\r') {
                after++;
            }
            if (after < body.length && body[after] == '\n') {
                after++;
            }
            // part 头（到空行 \r\n\r\n 或 \n\n）
            int headerEnd = indexOfBytes(body, new byte[]{'\r', '\n', '\r', '\n'}, after);
            int lf = indexOfBytes(body, new byte[]{'\n', '\n'}, after);
            int dataStart;
            if (headerEnd >= 0 && (lf < 0 || headerEnd <= lf)) {
                dataStart = headerEnd + 4;
            } else if (lf >= 0) {
                headerEnd = lf;
                dataStart = lf + 2;
            } else {
                break;
            }
            String headers = new String(body, after, headerEnd - after,
                    StandardCharsets.ISO_8859_1);
            String name = null;
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("name=\"([^\"]*)\"").matcher(headers);
            if (m.find()) {
                name = m.group(1);
            }
            // 数据区到下一个 boundary
            int next = indexOfBytes(body, delim, dataStart);
            if (next < 0) {
                break;
            }
            int dataEnd = next;
            if (dataEnd >= 2 && body[dataEnd - 2] == '\r' && body[dataEnd - 1] == '\n') {
                dataEnd -= 2;
            } else if (dataEnd >= 1 && body[dataEnd - 1] == '\n') {
                dataEnd -= 1;
            }
            if (name != null) {
                // P2-04：单文件 20MB 上限（签名专区/证书导入等上传）
                if (dataEnd - dataStart > 20L * 1024 * 1024) {
                    throw new IllegalArgumentException("单个文件超过 20MB 上传上限");
                }
                fields.put(name, Arrays.copyOfRange(body, dataStart, dataEnd));
                String fname = null;
                java.util.regex.Matcher fm = java.util.regex.Pattern
                        .compile("filename=\"([^\"]*)\"").matcher(headers);
                if (fm.find()) {
                    fname = fm.group(1);
                }
                if (fname != null) {
                    fields.put("__name_" + name, fname.getBytes(StandardCharsets.UTF_8));
                }
            }
            pos = next;
        }
        return fields;
    }

    /** 字节数组查找。 */
    private static int indexOfBytes(byte[] hay, byte[] needle, int from) {
        outer:
        for (int i = from; i <= hay.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /** 签名动作（pdf=true 时走 PDF 签名，否则 EXE Authenticode 签名）。 */
    private static void signAction(HttpExchange ex, boolean pdf) {
        String path = ex.getRequestURI().getPath();
        try {
            Map<String, byte[]> f = readMultipart(ex);
            String serial = new String(f.getOrDefault("serial", new byte[0]),
                    StandardCharsets.UTF_8).trim();
            byte[] fileBytes = f.get("file");
            String fileName = f.containsKey("name")
                    ? new String(f.get("name"), StandardCharsets.UTF_8).trim() : "";
            if (fileBytes == null || fileBytes.length == 0) {
                throw new IllegalArgumentException("未上传文件");
            }
            // serial 为空：仅 PDF 签名允许（纯文档时间戳）；EXE 签名必须选择证书
            if (serial.isEmpty() && !pdf) {
                throw new IllegalArgumentException("未选择签名证书序列号");
            }
            String base = AppPaths.baseDir();
            CertsDB db = new CertsDB();
            db.load(base);
            CertsDB.CertEntry e = serial == null || serial.isEmpty() ? null : db.findBySerial(serial);
            String keyType = e == null ? "RSA" : e.algo;
            java.security.cert.X509Certificate cert;
            PrivateKey key;
            List<java.security.cert.X509Certificate> chain;
            if (serial != null && !serial.isEmpty() && e == null) {
                // 回退：我的证书库 PKI/MY（含私钥，无需 EKU 判断）
                String mySerial = serial.toLowerCase();
                java.io.File myCert = new java.io.File(base, "PKI/MY/" + mySerial + ".crt");
                java.io.File myKey = new java.io.File(base, "PKI/MY/" + mySerial + ".key");
                if (!myCert.exists() || !myKey.exists()) {
                    throw new IllegalArgumentException("CERTS.txt 与我的证书库均无序列号 " + serial);
                }
                try (java.io.InputStream in = Files.newInputStream(myCert.toPath())) {
                    cert = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory
                            .getInstance("X.509", "BC").generateCertificate(in);
                }
                key = toJcaPrivateKey(PemIO.readPrivateKey(myKey.getAbsolutePath()));
                keyType = myAlgoOf(cert);
                chain = new ArrayList<>();   // 我的证书仅叶子，无链（SignTool 自动兜底用叶子自身）
            } else {
                cert = e == null ? null : SignTool.loadCertBySerial(base, serial);
                key = e == null ? null : SignTool.loadKeyBySerial(base, serial);
                chain = e == null ? null : SignTool.loadChain(base, serial);
            }
            if (cert != null) {
                // PKI-019: signing cert must be within validity window and not revoked
                java.util.Date now = new java.util.Date();
                if (now.before(cert.getNotBefore()) || now.after(cert.getNotAfter())) {
                    throw new IllegalArgumentException("签名证书已过期或尚未生效: "
                            + cert.getNotBefore() + " ~ " + cert.getNotAfter());
                }
                if (e != null && e.status == 'R') {
                    throw new IllegalArgumentException("签名证书已吊销（状态=R），禁止签名");
                }
            }

            byte[] result;
            String op;
            if (pdf) {
                byte[] image = f.get("image");
                String sealType = new String(f.getOrDefault("sealType", new byte[0]),
                        StandardCharsets.UTF_8).trim();
                if (sealType.isEmpty()) {
                    sealType = "ADOBE";
                }
                String tsUrl = new String(f.getOrDefault("tsUrl", new byte[0]),
                        StandardCharsets.UTF_8).trim();
                if (cert == null) {
                    // 未选择证书：纯文档时间戳（独立 DocTimeStamp，ETSI.RFC3161）
                    if (image != null && image.length > 0) {
                        throw new IllegalArgumentException("纯文档时间戳（不选证书）不能附加签章图片");
                    }
                    result = SignTool.signPdfTimestampOnly(fileBytes, tsUrl);
                    op = "PDF 纯文档时间戳（无签名证书）\n"
                            + "  时间戳地址: " + (tsUrl.isEmpty() ? "（本机 MAIN /rfc3161 默认）" : tsUrl);
                } else {
                    result = SignTool.signPdf(fileBytes, keyType, cert, key, chain, image,
                            sealType, tsUrl);
                    String sealLabel = "ADOBE".equalsIgnoreCase(sealType) ? "Adobe 标准文档签名"
                            : "GM38540".equalsIgnoreCase(sealType) ? "国密 GB/T 38540-2020"
                            : "GM0031".equalsIgnoreCase(sealType) ? "国密 GM/T 0031-2025"
                            : "国密 GB/T 35275-2017";
                    op = "PDF 文档签名\n"
                            + "  签章类型: " + sealLabel + "\n"
                            + "  签章: " + (image != null && image.length > 0
                            ? "已附加可见签章（" + image.length + "B 图片）" : "无（不可见签名）") + "\n"
                            + "  时间戳地址: " + (tsUrl.isEmpty() ? "（本机 MAIN /rfc3161 默认）" : tsUrl);
                }
            } else {
                if (fileName.isEmpty()) {
                    fileName = "file.bin";
                }
                String tsType = new String(f.getOrDefault("tsType", new byte[0]),
                        StandardCharsets.UTF_8).trim();
                if (tsType.isEmpty()) {
                    tsType = "RFC3161";
                }
                String tsUrl = new String(f.getOrDefault("tsUrl", new byte[0]),
                        StandardCharsets.UTF_8).trim();
                SignTool.lastTsInfo = "未请求";
                result = SignTool.signExe(fileBytes, keyType, cert, key, chain, base,
                        tsType, tsUrl);
                op = "微软代码签名（Authenticode）\n"
                        + "  时间戳类型: " + tsType + "\n"
                        + "  时间戳地址: " + (tsUrl.isEmpty() ? "（本机 MAIN 默认）" : tsUrl) + "\n"
                        + "  时间戳: " + SignTool.lastTsInfo;
            }
            String out = op + "\n"
                    + "  输入: " + fileName + "（" + fileBytes.length + " 字节）\n"
                    + (cert != null
                    ? "  证书: " + cert.getSubjectX500Principal() + "\n"
                    + "  序列号: " + serial + "   算法: " + keyType
                    + "   摘要: " + SignTool.digestName(keyType) + "\n"
                    : "  证书: （未选择，纯文档时间戳）\n")
                    + "  输出: " + result.length + " 字节";
            MLog.append(base, "WebAdmin " + path,
                    "POST " + path + " serial=" + serial + " file=" + fileName
                            + " size=" + fileBytes.length,
                    out);
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("ok", true);
            r.put("message", out);
            r.put("b64", Base64.getEncoder().encodeToString(result));
            r.put("name", (pdf ? "signed_" : "signed_") + fileName);
            sendJson(ex, 200, r);
        } catch (Exception ex2) {
            try {
                MLog.appendErr(AppPaths.baseDir(), "WebAdmin " + path + " 异常",
                        "POST " + path, String.valueOf(ex2));
                sendJson(ex, 500, Map.of("ok", false, "message", String.valueOf(ex2)));
            } catch (Exception ignored) {
            }
        }
    }

    /** 验证动作（pdf=true 走 PDF 验证，否则 EXE Authenticode 验证）。 */
    private static void verifyAction(HttpExchange ex, boolean pdf) {
        String path = ex.getRequestURI().getPath();
        try {
            Map<String, byte[]> f = readMultipart(ex);
            byte[] fileBytes = f.get("file");
            if (fileBytes == null || fileBytes.length == 0) {
                throw new IllegalArgumentException("未上传文件");
            }
            String out = pdf ? SignTool.verifyPdf(fileBytes) : SignTool.verifyExe(fileBytes);
            MLog.append(AppPaths.baseDir(), "WebAdmin " + path,
                    "POST " + path + " size=" + fileBytes.length, out);
            sendJson(ex, 200, Map.of("ok", true, "message", out));
        } catch (Exception ex2) {
            try {
                MLog.appendErr(AppPaths.baseDir(), "WebAdmin " + path + " 异常",
                        "POST " + path, String.valueOf(ex2));
                sendJson(ex, 500, Map.of("ok", false, "message", String.valueOf(ex2)));
            } catch (Exception ignored) {
            }
        }
    }

    /** /api/verify/file：上传本地 cer/crt/pem 证书文件并执行完整验证（CertVerify）。 */
    private static void verifyCertFileAction(HttpExchange ex) {
        String path = ex.getRequestURI().getPath();
        java.nio.file.Path tmp = null;
        try {
            Map<String, byte[]> f = readMultipart(ex);
            byte[] data = f.get("file");
            if (data == null || data.length == 0) {
                throw new IllegalArgumentException("未上传证书文件");
            }
            tmp = java.nio.file.Files.createTempFile("modpkica_verify_", ".crt");
            java.nio.file.Files.write(tmp, data);
            String out = Admin.doVerifyCert(baseDir, tmp.toString());
            MLog.append(baseDir, "WebAdmin /api/verify/file",
                    "POST 上传证书文件 size=" + data.length, out);
            sendJson(ex, 200, Map.of("ok", true, "message", out));
        } catch (Exception ex2) {
            try {
                MLog.appendErr(baseDir, "WebAdmin /api/verify/file 异常",
                        "POST 上传证书文件", String.valueOf(ex2));
                sendJson(ex, 500, Map.of("ok", false, "message", String.valueOf(ex2)));
            } catch (Exception ignored) {
            }
        } finally {
            if (tmp != null) {
                try {
                    java.nio.file.Files.deleteIfExists(tmp);
                } catch (Exception ignored) {
                }
            }
        }
    }

    /** 可签名证书列表：kind=exe 筛代码签名 EKU；kind=pdf 筛文档签名/代码签名 EKU。 */
    private static Map<String, Object> signCertsJson(HttpExchange ex) {
        String kind = ex.getRequestURI().getQuery() == null ? "exe"
                : (ex.getRequestURI().getQuery().contains("kind=pdf") ? "pdf" : "exe");
        String base = AppPaths.baseDir();
        CertsDB db = new CertsDB();
        db.load(base);
        List<Map<String, Object>> list = new ArrayList<>();
        java.util.Set<String> seenMy = new java.util.HashSet<>();
        for (CertsDB.CertEntry e : db.getAll()) {
            if (e.type != 'E' || "PQC".equals(e.algo)) {
                // User requirement: PQC certs must not appear in the signing dropdowns
                continue;
            }
            seenMy.add(e.serial.toLowerCase());
            try {
                java.security.cert.X509Certificate c = SignTool.loadCertBySerial(base, e.serial);
                boolean usable = "pdf".equals(kind)
                        ? SignTool.isDocSignCert(c) : SignTool.isCodeSignCert(c);
                if (!usable) {
                    continue;
                }
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("serial", e.serial);
                m.put("dn", c.getSubjectX500Principal().toString());
                m.put("issuer", c.getIssuerX500Principal().toString());
                m.put("algo", e.algo);
                m.put("bits", SignTool.keyBits(c));
                m.put("validFrom", c.getNotBefore().toString());
                m.put("validTo", c.getNotAfter().toString());
                m.put("status", String.valueOf(e.status));
                m.put("ekus", new ArrayList<>(SignTool.ekusOf(c)));
                list.add(m);
            } catch (Exception ignored) {
                // 证书文件缺失或损坏则跳过
            }
        }
        // 追加「我的证书」PKI/MY 中含私钥的记录：无需 EKU 判断（签名证书可直接选自我的证书库）
        Path myRec = Paths.get(base, "PKI", "MY", "myCERTS.txt");
        if (Files.exists(myRec)) {
            try {
                for (String line : Files.readAllLines(myRec, StandardCharsets.UTF_8)) {
                    String t = line.trim();
                    if (t.isEmpty() || t.startsWith("#")) {
                        continue;
                    }
                    String[] p = t.split("\s+");
                    if (p.length < 4 || !"Y".equals(p[2]) || "PQC".equals(p[3])) {
                        // User requirement: PQC certs must not appear in the signing dropdowns
                        continue;
                    }
                    String mySerial = p[0].toLowerCase();
                    if (seenMy.contains(mySerial)) {
                        continue;
                    }
                    java.io.File cf = new java.io.File(base, "PKI/MY/" + mySerial + ".crt");
                    if (!cf.exists()) {
                        continue;
                    }
                    try (java.io.InputStream in = Files.newInputStream(cf.toPath())) {
                        java.security.cert.X509Certificate c = (java.security.cert.X509Certificate)
                                java.security.cert.CertificateFactory.getInstance("X.509", "BC")
                                        .generateCertificate(in);
                        Map<String, Object> m = new LinkedHashMap<>();
                        m.put("serial", p[0]);
                        m.put("dn", c.getSubjectX500Principal().toString());
                        m.put("issuer", c.getIssuerX500Principal().toString());
                        m.put("algo", p[3]);
                        m.put("bits", SignTool.keyBits(c));
                        m.put("validFrom", c.getNotBefore().toString());
                        m.put("validTo", c.getNotAfter().toString());
                        m.put("status", "V");
                        m.put("ekus", new ArrayList<>());
                        m.put("src", "my");
                        list.add(m);
                        seenMy.add(mySerial);
                    } catch (Exception ignored) {
                        // 证书损坏则跳过该条
                    }
                }
            } catch (Exception ignored) {
            }
        }
        return Map.of("ok", true, "data", list);
    }

    /** JSON 字符串转义。 */
    static String jsonEscape(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    /* 发送 JSON 响应。 */
    // ============================================================
    // SCT 服务管理（CT 日志密钥 + 请求日志）
    // ============================================================

    /** /api/ctlog/list：密钥库列表（不含私钥）。 */
    private static Map<String, Object> ctlogListJson() {
        List<Map<String, Object>> keys = new ArrayList<>();
        int i = 1;
        for (CtLog.LogKey k : CtLog.loadKeys(baseDir)) {
            keys.add(Map.of("index", i++, "description", k.description, "logId", k.logId,
                    "state", k.state, "type", k.type, "created", k.created));
        }
        return Map.of("ok", true, "keys", keys);
    }

    /** /api/ctlog/logs：ctlogs.txt 全部行（只读）。 */
    private static Map<String, Object> ctlogLogsJson() {
        return Map.of("ok", true, "logs", CtLog.readLogs(baseDir));
    }

    /** /api/ctlog/public：可信公网 CT 日志公钥列表（log_list.json，只读）。 */
    private static Map<String, Object> ctlogPublicJson() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("timestamp", CtLog.publicListTimestamp(baseDir));
        List<Map<String, Object>> logs = new ArrayList<>();
        int i = 1;
        for (CtLog.PubLog k : CtLog.loadPublicList(baseDir)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("index", i++);
            m.put("description", k.description);
            m.put("logId", k.logIdHex);
            m.put("state", k.state);
            m.put("url", k.url);
            logs.add(m);
        }
        out.put("logs", logs);
        return out;
    }

    /** /api/ctlog/publicFetch：从 gstatic 拉取最新 log_list.json 并保存。 */
    private static String ctlogPublicFetch() throws Exception {
        return CtLog.fetchPublicList(baseDir);
    }

    /** /api/ctlog/gen：生成日志密钥对（type=ECDSA/RSA/SM2，缺省 ECDSA）并写入密钥库。 */
    private static String ctlogGen(String desc, String type) throws Exception {
        String t = type == null || type.isEmpty() ? "ECDSA" : type;
        CtLog.LogKey k = CtLog.generateKey(baseDir, desc, t);
        return "已生成 " + k.type + " CT 日志密钥对\nlog_id=" + k.logId
                + "\n已写入 PKI/CTLOG/modpkica_ct_list.json";
    }

    /** /api/ctlog/delete：按 log_id 删除密钥对。 */
    private static String ctlogDelete(String logId) {
        if (logId == null || logId.isEmpty()) {
            throw new IllegalArgumentException("缺少 log_id 参数");
        }
        return CtLog.deleteKey(baseDir, logId) ? "已删除该密钥对" : "未找到该 log_id";
    }

    /** /api/ctlog/enable、/api/ctlog/pause：修改密钥状态。 */
    private static String ctlogSetState(String logId, String state) {
        if (logId == null || logId.isEmpty()) {
            throw new IllegalArgumentException("缺少 log_id 参数");
        }
        boolean ok = CtLog.setState(baseDir, logId, state);
        if (!ok) {
            return "未找到该 log_id";
        }
        return "usable".equals(state) ? "已启用（usable）" : "已暂停（disable）";
    }

    // ============================================================
    // 用户管理（PKI/USERS.txt）
    // ============================================================

    /** /api/users/list：用户列表（不含 # 注释行）。 */
    private static Map<String, Object> usersListJson() {
        List<Map<String, Object>> list = new ArrayList<>();
        int i = 1;
        for (UsersDB.User u : UsersDB.load(baseDir)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("index", i++);
            m.put("username", u.username);
            m.put("password", u.password);
            m.put("state", u.state);
            m.put("enabled", u.enabled());
            m.put("group", u.group);
            m.put("note", u.note);
            list.add(m);
        }
        return Map.of("ok", true, "users", list);
    }

    /** /api/users/add：新增用户。 */
    private static String usersAdd(Map<String, Object> m) {
        String name = str(m, "username");
        String pw = str(m, "password");
        String state = str(m, "state");
        String group = str(m, "group");
        String note = str(m, "note");
        UsersDB.add(baseDir, name, pw, state, group, note);
        return "已添加用户: " + name.trim();
    }

    /** /api/users/update：修改用户。 */
    private static String usersUpdate(Map<String, Object> m) {
        String oldName = str(m, "old_username");
        String name = str(m, "username");
        String pw = str(m, "password");
        String state = str(m, "state");
        String group = str(m, "group");
        String note = str(m, "note");
        UsersDB.update(baseDir, oldName, name, pw, state, group, note);
        return "已更新用户: " + oldName.trim() + " → " + name.trim();
    }

    /** /api/users/delete：删除用户（行首加 # 注释，保留原行）。 */
    private static String usersDelete(Map<String, Object> m) {
        String name = str(m, "username");
        UsersDB.remove(baseDir, name);
        return "已删除用户: " + name.trim() + "（USERS.txt 中该行已加 # 注释）";
    }

    /** /api/users/status：启用 / 停用。 */
    private static String usersSetState(Map<String, Object> m) {
        String name = str(m, "username");
        String st = str(m, "state");
        boolean enable = !"D".equalsIgnoreCase(st);
        UsersDB.setState(baseDir, name, enable);
        return "用户 " + name.trim() + " 已" + (enable ? "启用" : "停用");
    }

    // ============================================================
    // Radius 服务管理（UDP 认证 1812 / 计费 1813 + EAP）
    // ============================================================

    /** 读取 CONFIG.txt 键值（缺省回退）。 */
    private static String configGet(String key, String def) {
        try {
            Map<String, String> raw = new Config(baseDir).getRaw();
            String v = raw.get(key);
            return (v == null || v.isEmpty()) ? def : v;
        } catch (Exception e) {
            return def;
        }
    }

    /**
     * MAIN 启动时调用：若 CONFIG 中 RADIUSAUTO=on（缺省 off，仅用户勾选后开启），
     * 用共享实例自动拉起 RADIUS。与面板启停使用同一个实例，保证页面状态/统计/日志真实一致。
     *
     * @return 是否成功自动启动
     */
    public static boolean startRadiusIfConfigured() {
        try {
            if (!"on".equalsIgnoreCase(configGet("RADIUSAUTO", "off"))) {
                return false;
            }
            int ap = RadiusServer.portOf(configGet("RADIUSPORT", null), RadiusServer.DEFAULT_AUTH_PORT);
            int cpt = RadiusServer.portOf(configGet("RADIUSACCT", null), RadiusServer.DEFAULT_ACCT_PORT);
            String key = configGet("RADIUSKEY", "mytestkey");
            RADIUS.start(ap, cpt, key);
            return true;
        } catch (Exception e) {
            System.err.println("RADIUS 自动启动失败（忽略，不影响主服务）: " + e.getMessage());
            return false;
        }
    }

    /**
     * MAIN 启动时调用：若 CONFIG 中 PPPOEAUTO=on（缺省 off，仅用户勾选后开启），
     * 用共享实例自动拉起 PPPoE。与面板启停使用同一个实例，保证页面状态/统计/日志真实一致。
     *
     * @return 是否成功自动启动
     */
    public static boolean startPppoeIfConfigured() {
        try {
            if (!"on".equalsIgnoreCase(configGet("PPPOEAUTO", "off"))) {
                return false;
            }
            int disc = pppoePortOf(configGet("PPPOEDISC", null), PPPoEServer.DEFAULT_DISC_PORT);
            int sess = pppoePortOf(configGet("PPPOESESS", null), PPPoEServer.DEFAULT_SESS_PORT);
            PPPOE.start(disc, sess);
            return true;
        } catch (Exception e) {
            System.err.println("PPPoE 自动启动失败（忽略，不影响主服务）: " + e.getMessage());
            return false;
        }
    }

    private static int radiusPortOf(String s, int def) {
        if (s == null || s.trim().isEmpty()) {
            return def;
        }
        try {
            int v = Integer.parseInt(s.trim());
            return v > 0 && v < 65536 ? v : def;
        } catch (NumberFormatException e) {
            return def;
        }
    }

    /** /api/radius/status：运行状态 + CONFIG 配置 + 统计。 */
    private static Map<String, Object> radiusStatusJson() {
        Map<String, Object> m = new LinkedHashMap<>(RADIUS.statusJson());
        m.put("ok", true);
        m.put("cfgAuthPort", radiusPortOf(configGet("RADIUSPORT", null), RadiusServer.DEFAULT_AUTH_PORT));
        m.put("cfgAcctPort", radiusPortOf(configGet("RADIUSACCT", null), RadiusServer.DEFAULT_ACCT_PORT));
        m.put("cfgSecret", configGet("RADIUSKEY", "mytestkey"));
        m.put("cfgAuto", "on".equalsIgnoreCase(configGet("RADIUSAUTO", "off")));
        return m;
    }

    /** /api/radius/logs：环形日志（WinRadius 风格，最新在前）。 */
    private static Map<String, Object> radiusLogsJson(String lines) {
        int n = 100;
        if (lines != null) {
            try {
                n = Math.max(1, Math.min(Integer.parseInt(lines.trim()), RadiusServer.MAX_LOG_ENTRIES));
            } catch (NumberFormatException ignored) {
            }
        }
        List<Map<String, Object>> list = new ArrayList<>();
        for (RadiusServer.LogEntry e : RADIUS.logs(n)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", e.id);
            m.put("time", e.time);
            m.put("message", e.message);
            list.add(m);
        }
        return Map.of("ok", true, "logs", list);
    }

    /** /api/radius/start：按参数启动（未给则用 CONFIG 或默认）。 */
    private static String radiusStart(Map<String, Object> m) {
        int ap = radiusPortOf(str(m, "auth_port"), radiusPortOf(configGet("RADIUSPORT", null), RadiusServer.DEFAULT_AUTH_PORT));
        int cpt = radiusPortOf(str(m, "acct_port"), radiusPortOf(configGet("RADIUSACCT", null), RadiusServer.DEFAULT_ACCT_PORT));
        String key = str(m, "secret");
        if (key == null || key.isEmpty()) {
            key = configGet("RADIUSKEY", "mytestkey");
        }
        try {
            return RADIUS.start(ap, cpt, key);
        } catch (Exception e) {
            throw new IllegalStateException("RADIUS 启动失败（端口可能被占用）: " + e.getMessage());
        }
    }

    /** /api/radius/stop。 */
    private static String radiusStop() {
        return RADIUS.stop();
    }

    /** /api/radius/reset：统计清零。 */
    private static String radiusReset() {
        RADIUS.resetStats();
        return "统计已清零";
    }

    /** /api/radius/clearlogs：清空环形日志。 */
    private static String radiusClearLogs() {
        RADIUS.clearLogs();
        return "日志已清空";
    }

    /** /api/radius/config：参数化保存 CONFIG.txt（RADIUSPORT / RADIUSACCT / RADIUSKEY / RADIUSAUTO）。 */
    private static String radiusSaveConfig(Map<String, Object> m) throws Exception {
        Map<String, String> updates = new LinkedHashMap<>();
        int ap = radiusPortOf(str(m, "auth_port"), RadiusServer.DEFAULT_AUTH_PORT);
        int cpt = radiusPortOf(str(m, "acct_port"), RadiusServer.DEFAULT_ACCT_PORT);
        String key = str(m, "secret");
        if (key == null || key.trim().isEmpty()) {
            throw new IllegalArgumentException("共享密钥不能为空");
        }
        updates.put("RADIUSPORT", String.valueOf(ap));
        updates.put("RADIUSACCT", String.valueOf(cpt));
        updates.put("RADIUSKEY", key.trim());
        updates.put("RADIUSAUTO", "on".equalsIgnoreCase(str(m, "auto")) ? "on" : "off");

        Path f = Paths.get(baseDir, "PKI", "CONFIG.txt");
        java.util.List<String> lines;
        if (Files.exists(f)) {
            lines = Files.readAllLines(f, StandardCharsets.UTF_8);
        } else {
            lines = new java.util.ArrayList<>();
        }
        StringBuilder sb = new StringBuilder();
        java.util.Set<String> done = new java.util.HashSet<>();
        for (String line : lines) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) {
                sb.append(line).append("\r\n");
                continue;
            }
            int idx = t.indexOf('=');
            if (idx <= 0) {
                sb.append(line).append("\r\n");
                continue;
            }
            String k = t.substring(0, idx).trim();
            if (updates.containsKey(k)) {
                sb.append(k).append('=').append(updates.get(k)).append("\r\n");
                done.add(k);
            } else {
                sb.append(line).append("\r\n");
            }
        }
        for (Map.Entry<String, String> e : updates.entrySet()) {
            if (!done.contains(e.getKey())) {
                sb.append(e.getKey()).append('=').append(e.getValue()).append("\r\n");
            }
        }
        Files.createDirectories(f.getParent());
        Files.write(f, sb.toString().getBytes(StandardCharsets.UTF_8));
        return "RADIUS 配置已保存到 CONFIG.txt（认证 " + ap + " / 计费 " + cpt
                + "，自动启动=" + ("on".equalsIgnoreCase(str(m, "auto")) ? "开" : "关") + "）";
    }

    /** /api/radius/dial：客户端-调试专区，模拟 NAS 发起认证（PAP/CHAP/MS-CHAPv1/v2/EAP-MD5/EAP-TLS）。 */
    private static String radiusDial(Map<String, Object> m) throws Exception {
        String method = str(m, "method");
        String user = str(m, "user");
        String pass = str(m, "pass");
        String secret = str(m, "secret");
        if (secret == null || secret.trim().isEmpty()) {
            secret = configGet("RADIUSKEY", "mytestkey");
        }
        int port = radiusPortOf(str(m, "port"), RadiusServer.DEFAULT_AUTH_PORT);
        String certSerial = str(m, "cert");
        Map<String, Object> r = RADIUS.clientDial(method, user, pass, secret, port, certSerial);
        String msg = String.valueOf(r.get("message"));
        MLog.append(baseDir, "Radius 客户端调试",
                "认证方式=" + method + " 用户=" + user + " 目标=127.0.0.1:" + port
                        + (certSerial != null && !certSerial.isEmpty() ? " 证书=" + certSerial : ""), msg);
        @SuppressWarnings("unchecked")
        java.util.List<String> logs = (java.util.List<String>) r.get("logs");
        if (logs != null && !logs.isEmpty()) {
            return String.join("\n", logs);
        }
        return msg;
    }

    // ============================================================
    // PPPoE 服务管理（RFC 2516；服务器 + 客户端拨号模拟器）
    // ============================================================
    private static Map<String, Object> pppoeStatusJson() {
        Map<String, Object> m = new LinkedHashMap<>(PPPOE.statusJson());
        m.put("ok", true);
        m.put("cfgDiscPort", pppoePortOf(configGet("PPPOEDISC", null), PPPoEServer.DEFAULT_DISC_PORT));
        m.put("cfgSessPort", pppoePortOf(configGet("PPPOESESS", null), PPPoEServer.DEFAULT_SESS_PORT));
        m.put("cfgAuto", "on".equalsIgnoreCase(configGet("PPPOEAUTO", "off")));
        return m;
    }

    private static Map<String, Object> pppoeLogsJson(String lines) {
        int n = 100;
        if (lines != null) {
            try {
                n = Math.max(1, Math.min(Integer.parseInt(lines.trim()), PPPoEServer.MAX_LOG_ENTRIES));
            } catch (NumberFormatException ignored) {
            }
        }
        List<Map<String, Object>> list = new ArrayList<>();
        for (PPPoEServer.LogEntry e : PPPOE.logs(n)) {
            Map<String, Object> mm = new LinkedHashMap<>();
            mm.put("id", e.id);
            mm.put("time", e.time);
            mm.put("message", e.message);
            list.add(mm);
        }
        return Map.of("ok", true, "logs", list);
    }

    private static String pppoeStart(Map<String, Object> m) {
        int disc = pppoePortOf(str(m, "disc_port"),
                pppoePortOf(configGet("PPPOEDISC", null), PPPoEServer.DEFAULT_DISC_PORT));
        int sess = pppoePortOf(str(m, "sess_port"),
                pppoePortOf(configGet("PPPOESESS", null), PPPoEServer.DEFAULT_SESS_PORT));
        try {
            return PPPOE.start(disc, sess);
        } catch (Exception e) {
            throw new IllegalStateException("PPPoE 启动失败（端口可能被占用）: " + e.getMessage());
        }
    }

    private static String pppoeStop() {
        PPPOE.stop();
        return "PPPoE 服务已停止";
    }

    private static String pppoeReset() {
        PPPOE.reset();
        return "统计已清零";
    }

    /** /api/pppoe/clearlogs：清空环形日志。 */
    private static String pppoeClearLogs() {
        PPPOE.clearLogs();
        return "日志已清空";
    }

    /** /api/pppoe/dial：客户端拨号模拟，返回完整流程日志文本。 */
    private static String pppoeDial(Map<String, Object> m) {
        Map<String, Object> r = PPPOE.dial(str(m, "username"), str(m, "password"), str(m, "method"));
        StringBuilder sb = new StringBuilder();
        @SuppressWarnings("unchecked")
        List<String> log = (List<String>) r.get("log");
        if (log != null) {
            for (String line : log) {
                sb.append(line).append('\n');
            }
        }
        sb.append("结果: ").append(r.get("message"));
        return sb.toString();
    }

    /** /api/pppoe/config：参数化保存 CONFIG.txt（PPPOEDISC / PPPOESESS / PPPOEAUTO）。 */
    private static String pppoeSaveConfig(Map<String, Object> m) throws Exception {
        int disc = pppoePortOf(str(m, "disc_port"), PPPoEServer.DEFAULT_DISC_PORT);
        int sess = pppoePortOf(str(m, "sess_port"), PPPoEServer.DEFAULT_SESS_PORT);
        Map<String, String> updates = new LinkedHashMap<>();
        updates.put("PPPOEDISC", String.valueOf(disc));
        updates.put("PPPOESESS", String.valueOf(sess));
        updates.put("PPPOEAUTO", "on".equalsIgnoreCase(str(m, "auto")) ? "on" : "off");
        Path f = Paths.get(baseDir, "PKI", "CONFIG.txt");
        java.util.List<String> lines = Files.exists(f)
                ? Files.readAllLines(f, StandardCharsets.UTF_8) : new java.util.ArrayList<>();
        StringBuilder sb = new StringBuilder();
        java.util.Set<String> done = new java.util.HashSet<>();
        for (String line : lines) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) {
                sb.append(line).append("\r\n");
                continue;
            }
            int idx = t.indexOf('=');
            if (idx <= 0) {
                sb.append(line).append("\r\n");
                continue;
            }
            String k = t.substring(0, idx).trim();
            if (updates.containsKey(k)) {
                sb.append(k).append('=').append(updates.get(k)).append("\r\n");
                done.add(k);
            } else {
                sb.append(line).append("\r\n");
            }
        }
        for (Map.Entry<String, String> e : updates.entrySet()) {
            if (!done.contains(e.getKey())) {
                sb.append(e.getKey()).append('=').append(e.getValue()).append("\r\n");
            }
        }
        Files.createDirectories(f.getParent());
        Files.write(f, sb.toString().getBytes(StandardCharsets.UTF_8));
        return "PPPoE 配置已保存到 CONFIG.txt（Discovery " + disc + " / Session " + sess
                + "，自动启动=" + ("on".equalsIgnoreCase(str(m, "auto")) ? "开" : "关") + "）";
    }

    private static int pppoePortOf(String v, int def) {
        if (v == null) {
            return def;
        }
        try {
            int n = Integer.parseInt(v.trim());
            return n > 0 && n < 65536 ? n : def;
        } catch (NumberFormatException e) {
            return def;
        }
    }

    // ============================================================
    // SCT 仪表盘（Merkle 树） + /ct/v1 调试代理（v1.28-r3 新增）
    // ============================================================

    /** hex → 字节。 */
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    | Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }

    private static final class MainResp {
        int code;
        byte[] body;
        MainResp(int c, byte[] b) {
            code = c;
            body = b;
        }
    }

    /** 通用请求本机 MAIN 服务（GET/POST），返回 HTTP 状态码与响应字节。 */
    private static MainResp requestMainAny(String method, String path, String contentType, byte[] body) throws Exception {
        String port = readConfigWebPort();
        if (port == null || port.isEmpty() || "未配置".equals(port)) {
            port = "80";
        }
        URL url = new java.net.URI("http://127.0.0.1:" + port + path).toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(method);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(15000);
        if (contentType != null && !contentType.isEmpty()) {
            conn.setRequestProperty("Content-Type", contentType);
        }
        if (body != null && body.length > 0) {
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body);
            }
        }
        int code = conn.getResponseCode();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream()) {
            if (is != null) {
                byte[] buf = new byte[4096];
                int n;
                while ((n = is.read(buf)) > 0) {
                    bos.write(buf, 0, n);
                }
            }
        }
        return new MainResp(code, bos.toByteArray());
    }

    /** /api/ctlog/v1proxy：可视化调试 /ct/v1/* 8 个接口（转发到 MAIN，返回状态 + 响应原文）。 */
    private static String ctlogV1Proxy(Map<String, Object> m) throws Exception {
        String path = str(m, "path");
        String method = str(m, "method");
        String query = str(m, "query");
        String bodyB64 = str(m, "bodyB64");
        String contentType = str(m, "contentType");
        if (path == null || !path.startsWith("/ct/v1/")) {
            throw new IllegalArgumentException("path 必须以 /ct/v1/ 开头");
        }
        String mtd = (method == null || method.isEmpty()) ? "GET" : method.toUpperCase();
        if (!"GET".equals(mtd) && !"POST".equals(mtd)) {
            throw new IllegalArgumentException("method 仅支持 GET / POST");
        }
        byte[] body = (bodyB64 == null || bodyB64.isEmpty()) ? null : Base64.getDecoder().decode(bodyB64);
        String full = path + ((query == null || query.isEmpty()) ? "" : "?" + query);
        long t0 = System.currentTimeMillis();
        MainResp r = requestMainAny(mtd, full,
                (contentType == null || contentType.isEmpty()) ? "application/json" : contentType, body);
        long ms = System.currentTimeMillis() - t0;
        String text = new String(r.body, StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder();
        sb.append("MAIN ").append(mtd).append(" ").append(full)
                .append(" → HTTP ").append(r.code).append("，耗时 ").append(ms).append(" ms");
        if (r.body != null && r.body.length > 0) {
            sb.append("\n\n").append(text);
        } else {
            sb.append("\n\n（响应体为空）");
        }
        return sb.toString();
    }

    /** /api/ctlog/tree：全部日志的 Merkle 树仪表盘数据（树节点 + 叶子证书信息）。 */
    private static Map<String, Object> ctlogTreeJson() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        Map<String, CtLog.LogKey> keyMap = new LinkedHashMap<>();
        for (CtLog.LogKey k : CtLog.loadKeys(baseDir)) {
            keyMap.put(k.logId, k);
        }
        List<Map<String, Object>> trees = new ArrayList<>();
        Path dir = Paths.get(baseDir, "PKI", "CTLOG", "trees");
        List<String> files = new ArrayList<>();
        if (Files.isDirectory(dir)) {
            try (Stream<Path> s = Files.list(dir)) {
                s.filter(p -> p.getFileName().toString().endsWith(".json"))
                        .forEach(p -> files.add(p.getFileName().toString()));
            } catch (IOException ignore) {
            }
        }
        java.util.Collections.sort(files);
        int totalEntries = 0;
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        for (String fn : files) {
            String hex = fn.substring(0, fn.length() - 5);
            byte[] raw = hexToBytes(hex);
            String logIdB64 = Base64.getEncoder().encodeToString(raw);
            CtLog.LogKey k = keyMap.get(logIdB64);
            List<CtLog.TreeEntry> entries = CtLog.loadTreeEntries(baseDir, logIdB64);
            Map<String, Object> t = new LinkedHashMap<>();
            t.put("logId", logIdB64);
            t.put("logIdHex", hex);
            t.put("description", k != null ? k.description : "");
            t.put("type", k != null ? k.type : "");
            t.put("state", k != null ? k.state : "");
            t.put("entryCount", entries.size());
            totalEntries += entries.size();
            List<byte[]> leafHashes = new ArrayList<>();
            for (CtLog.TreeEntry e : entries) {
                try {
                    leafHashes.add(CtLog.leafHash(Base64.getDecoder().decode(e.leafInput)));
                } catch (Exception ignore) {
                }
            }
            List<Map<String, Object>> nodeList = new ArrayList<>();
            String rootHash = "";
            try {
                List<CtLog.MthNode> nodes = CtLog.computeMthNodes(leafHashes);
                for (CtLog.MthNode nd : nodes) {
                    Map<String, Object> nm = new LinkedHashMap<>();
                    nm.put("level", nd.level);
                    nm.put("start", nd.start);
                    nm.put("end", nd.end);
                    nm.put("hash", hexOf(nd.hash));
                    nodeList.add(nm);
                    if (nd.level == 0) {
                        rootHash = hexOf(nd.hash);
                    }
                }
                if (nodes.isEmpty() && !leafHashes.isEmpty()) {
                    rootHash = hexOf(leafHashes.get(0));
                }
            } catch (Exception ignore) {
            }
            t.put("nodes", nodeList);
            t.put("rootHash", rootHash);
            List<Map<String, Object>> entList = new ArrayList<>();
            for (int i = 0; i < entries.size(); i++) {
                CtLog.TreeEntry e = entries.get(i);
                Map<String, Object> em = new LinkedHashMap<>();
                em.put("index", i);
                try {
                    byte[] li = Base64.getDecoder().decode(e.leafInput);
                    long ts = CtLog.treeEntryTimestamp(li);
                    em.put("ts", ts);
                    em.put("tsText", sdf.format(new Date(ts)));
                    em.put("entryType", CtLog.parseLeafEntryType(li) == 1 ? "precert" : "x509");
                    em.put("leafHash", hexOf(CtLog.leafHash(li)));
                } catch (Exception ignore) {
                    em.put("ts", 0L);
                    em.put("tsText", "");
                    em.put("entryType", "");
                    em.put("leafHash", "");
                }
                String serial = "";
                String subject = "";
                String issuer = "";
                try {
                    byte[] li = Base64.getDecoder().decode(e.leafInput);
                    // x509_entry：叶子证书在 leaf_input 的 leaf_certificate 字段；
                    // precert_entry：extra_data 首个为完整预证书
                    byte[] certDer = (CtLog.parseLeafEntryType(li) == 1)
                            ? CtLog.extraDataFirstCert(Base64.getDecoder().decode(e.extraData))
                            : CtLog.leafCertFromLeafInput(li);
                    if (certDer != null) {
                        X509CertificateHolder h = new X509CertificateHolder(certDer);
                        serial = h.getSerialNumber().toString(16);
                        subject = h.getSubject().toString();
                        issuer = h.getIssuer().toString();
                    }
                } catch (Exception ignore) {
                }
                em.put("serial", serial);
                em.put("subject", subject);
                em.put("issuer", issuer);
                entList.add(em);
            }
            t.put("entries", entList);
            trees.add(t);
        }
        out.put("trees", trees);
        out.put("totalEntries", totalEntries);
        out.put("treeCount", trees.size());
        return out;
    }

    /** /api/ctlog/samplechain：从 CERTS.txt 取一个终端证书链（E→C→R），返回 base64(DER) 数组，供调试区 add-chain 使用。 */
    private static Map<String, Object> ctlogSampleChainJson() throws Exception {
        List<String[]> rows = new ArrayList<>();
        Path p = Paths.get(baseDir, "PKI", "CERTS.txt");
        if (Files.exists(p)) {
            for (String line : Files.readAllLines(p, StandardCharsets.UTF_8)) {
                String t = line.trim();
                if (!t.isEmpty() && !t.startsWith("#")) {
                    String[] q = t.split("\\s+");
                    if (q.length >= 7) {
                        rows.add(q);
                    }
                }
            }
        }
        String leafSerial = null;
        for (String[] q : rows) {
            if ("E".equals(q[1]) && !"R".equals(q[2])) {
                leafSerial = q[0];
                break;
            }
        }
        if (leafSerial == null) {
            for (String[] q : rows) {
                if ("E".equals(q[1])) {
                    leafSerial = q[0];
                    break;
                }
            }
        }
        if (leafSerial == null) {
            return Map.of("ok", false, "message", "CERTS.txt 中没有 E 类型终端证书，无法生成示例链");
        }
        List<String> chainB64 = new ArrayList<>();
        List<String> chainSerials = new ArrayList<>();
        String cur = leafSerial;
        Set<String> seen = new LinkedHashSet<>();
        while (cur != null && !cur.isEmpty() && seen.add(cur)) {
            String type = null;
            String issuerId = null;
            for (String[] q : rows) {
                if (q[0].equalsIgnoreCase(cur)) {
                    type = q[1];
                    issuerId = q[5];
                    break;
                }
            }
            String dir = "R".equals(type) ? "ROOT" : "C".equals(type) ? "CA" : "E".equals(type) ? "CERT" : null;
            if (dir != null) {
                Path cf = Paths.get(baseDir, "PKI", dir, cur + ".crt");
                if (Files.exists(cf)) {
                    byte[] der = pemToDer(Files.readAllBytes(cf));
                    if (der != null && der.length > 0) {
                        chainB64.add(Base64.getEncoder().encodeToString(der));
                        chainSerials.add(cur);
                    }
                }
            }
            cur = issuerId;
        }
        if (chainB64.isEmpty()) {
            return Map.of("ok", false, "message", "证书链文件不存在（CERT/CA/ROOT 目录）");
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("leafSerial", leafSerial);
        out.put("chainSerials", chainSerials);
        out.put("chain", chainB64);
        return out;
    }

    // ============================================================
    // 模板管理：PKI/tamplate/data.json（JSON 数组，每条 = 签发参数模板）
    // 目录名按用户指定拼写 "tamplate"；模板供"签发证书"一键回填与批量签署
    // ============================================================

    private static Path templatePath() {
        return Paths.get(baseDir, "PKI", "tamplate", "data.json");
    }

    private static String fmtTemplateNow() {
        return new java.text.SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new java.util.Date());
    }

    /** 读取全部模板（文件不存在/损坏时返回空数组）。 */
    private static List<Map<String, Object>> templateLoad() {
        try {
            Path f = templatePath();
            if (Files.exists(f)) {
                String txt = new String(Files.readAllBytes(f), StandardCharsets.UTF_8).trim();
                if (txt.startsWith("[")) {
                    return parseJsonArray(txt);
                }
            }
        } catch (Exception e) {
            MLog.appendErr(baseDir, "模板管理 读取失败", "templateLoad", String.valueOf(e));
        }
        return new ArrayList<>();
    }

    /** 原子写模板文件（先写 tmp 再 move，避免半截 JSON）。 */
    private static void templateWrite(List<Map<String, Object>> list) throws Exception {
        Path dir = Paths.get(baseDir, "PKI", "tamplate");
        Files.createDirectories(dir);
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Map<String, Object> e : list) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            appendJsonValue(sb, e);
        }
        sb.append("]\n");
        Path f = dir.resolve("data.json");
        Path tmp = dir.resolve("data.json.tmp");
        Files.write(tmp, sb.toString().getBytes(StandardCharsets.UTF_8));
        Files.move(tmp, f, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                java.nio.file.StandardCopyOption.ATOMIC_MOVE);
    }

    /** /api/template/list：模板列表。 */
    private static Map<String, Object> templateListJson() {
        return Map.of("ok", true, "data", templateLoad());
    }

    /** 解析 JSON 对象数组（对象为扁平 key/value，兼容 readJsonString 转义）。 */
    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> parseJsonArray(String json) {
        List<Map<String, Object>> out = new ArrayList<>();
        String s = json == null ? "" : json.trim();
        if (s.isEmpty() || s.charAt(0) != '[') {
            return out;
        }
        int i = 1;
        while (i < s.length()) {
            while (i < s.length() && (s.charAt(i) == ' ' || s.charAt(i) == '\t'
                    || s.charAt(i) == '\n' || s.charAt(i) == '\r' || s.charAt(i) == ',')) {
                i++;
            }
            if (i >= s.length() || s.charAt(i) == ']') {
                break;
            }
            if (s.charAt(i) != '{') {
                i++;
                continue;
            }
            int depth = 0;
            int j = i;
            while (j < s.length()) {
                char c = s.charAt(j);
                if (c == '"') {
                    Object[] r = readJsonString(s, j + 1);
                    j = (Integer) r[1];
                    continue;
                }
                if (c == '{') {
                    depth++;
                } else if (c == '}') {
                    depth--;
                    if (depth == 0) {
                        j++;
                        break;
                    }
                }
                j++;
            }
            Map<String, Object> m = parseJsonObject(s.substring(i, j));
            if (!m.isEmpty()) {
                out.add(m);
            }
            i = j;
        }
        return out;
    }

    /** /api/template/save：新增（无 id）或更新（带 id）模板。 */
    private static String templateSave(Map<String, Object> m) throws Exception {
        String id = str(m, "id");
        String name = str(m, "name");
        String ctype = str(m, "ctype");
        String dn = str(m, "dn");
        String bits = str(m, "bits");
        String hash = str(m, "hash");
        String keyusage = str(m, "keyusage");
        String exusage = str(m, "exusage");
        String pathlen = str(m, "pathlen");
        String policy = str(m, "policy");
        String days = str(m, "days");
        String dns = str(m, "dns");
        String ips = str(m, "ips");
        String algo = str(m, "algo");
        if (dn.isEmpty()) {
            throw new IllegalArgumentException("证书 DN 不能为空");
        }
        if (ctype.isEmpty()) ctype = "0";
        if (algo.isEmpty()) algo = "RSA";
        if (bits.isEmpty()) bits = "2048";
        if (hash.isEmpty()) hash = "sha256";
        // keyusage/exusage 空值 = 证书不携带对应扩展，不得回退默认值
        if (keyusage == null) keyusage = "";
        if (exusage == null) exusage = "";
        if (days.isEmpty()) days = "1";
        if (dns.isEmpty()) dns = "null";
        if (ips.isEmpty()) ips = "null";
        if (pathlen.isEmpty()) pathlen = "null";
        if (policy == null) policy = "";

        List<Map<String, Object>> list = templateLoad();
        if (id.isEmpty()) {
            int maxId = 0;
            for (Map<String, Object> e : list) {
                try {
                    maxId = Math.max(maxId, Integer.parseInt(String.valueOf(e.get("id"))));
                } catch (Exception ignore) { }
            }
            Map<String, Object> rec = new LinkedHashMap<>();
            rec.put("id", String.valueOf(maxId + 1));
            rec.put("name", name);
            rec.put("ctype", ctype);
            rec.put("dn", dn);
            rec.put("bits", bits);
            rec.put("hash", hash);
            rec.put("keyusage", keyusage);
            rec.put("exusage", exusage);
            rec.put("pathlen", pathlen);
            rec.put("policy", policy);
            rec.put("days", days);
            rec.put("dns", dns);
            rec.put("ips", ips);
            rec.put("algo", algo);
            rec.put("createTime", fmtTemplateNow());
            list.add(rec);
            templateWrite(list);
            return "已添加模板 #" + (maxId + 1) + (name.isEmpty() ? "" : "：" + name);
        }
        boolean updated = false;
        for (Map<String, Object> e : list) {
            if (String.valueOf(e.get("id")).equals(id)) {
                e.put("name", name);
                e.put("ctype", ctype);
                e.put("dn", dn);
                e.put("bits", bits);
                e.put("hash", hash);
                e.put("keyusage", keyusage);
                e.put("exusage", exusage);
                e.put("pathlen", pathlen);
                e.put("policy", policy);
                e.put("days", days);
                e.put("dns", dns);
                e.put("ips", ips);
                e.put("algo", algo);
                e.put("createTime", fmtTemplateNow());
                updated = true;
                break;
            }
        }
        if (!updated) {
            throw new IllegalArgumentException("未找到模板 #" + id);
        }
        templateWrite(list);
        return "已更新模板 #" + id + (name.isEmpty() ? "" : "：" + name);
    }

    /** /api/template/delete：按 id 删除模板。 */
    private static String templateDelete(Map<String, Object> m) throws Exception {
        String id = str(m, "id");
        if (id.isEmpty()) {
            throw new IllegalArgumentException("缺少模板 id 参数");
        }
        List<Map<String, Object>> list = templateLoad();
        boolean removed = list.removeIf(e -> String.valueOf(e.get("id")).equals(id));
        if (!removed) {
            throw new IllegalArgumentException("未找到模板 #" + id);
        }
        templateWrite(list);
        return "已删除模板 #" + id;
    }

    /** /api/template/sign：按模板参数 + 选中的 R/C 颁发者签发证书（复用 MakeCert 全流程，日志由 runAction/doSignCert 记录）。 */
    private static String templateSign(Map<String, Object> m) throws Exception {
        String id = str(m, "id");
        String issuer = str(m, "issuer");
        if (id.isEmpty()) {
            throw new IllegalArgumentException("缺少模板 id 参数");
        }
        if (issuer.isEmpty()) {
            throw new IllegalArgumentException("请选择颁发者证书（类型 R/C）");
        }
        Map<String, Object> tpl = null;
        for (Map<String, Object> e : templateLoad()) {
            if (String.valueOf(e.get("id")).equals(id)) {
                tpl = e;
                break;
            }
        }
        if (tpl == null) {
            throw new IllegalArgumentException("未找到模板 #" + id);
        }
        return Admin.doSignCert(baseDir,
                str(tpl, "dn"), str(tpl, "bits"), str(tpl, "hash"),
                str(tpl, "keyusage"), str(tpl, "exusage"), str(tpl, "ctype"),
                str(tpl, "days"), str(tpl, "dns"), str(tpl, "ips"),
                issuer, str(tpl, "algo"), str(tpl, "pathlen"), str(tpl, "policy"));
    }
    private static void sendJson(HttpExchange ex, int code, Map<String, Object> map)
            throws IOException {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : map.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(jsonEscape(e.getKey())).append("\":");
            appendJsonValue(sb, e.getValue());
        }
        sb.append('}');
        sendText(ex, code, "application/json; charset=utf-8", sb.toString());
    }

    /** JSON 值序列化（支持 String/Number/Boolean/Map/List/null）。 */
    @SuppressWarnings("unchecked")
    private static void appendJsonValue(StringBuilder sb, Object v) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String) {
            sb.append('"').append(jsonEscape((String) v)).append('"');
        } else if (v instanceof Boolean || v instanceof Number) {
            sb.append(v);
        } else if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<Object, Object> e : ((Map<Object, Object>) v).entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                sb.append('"').append(jsonEscape(String.valueOf(e.getKey()))).append("\":");
                appendJsonValue(sb, e.getValue());
            }
            sb.append('}');
        } else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object o : (List<Object>) v) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                appendJsonValue(sb, o);
            }
            sb.append(']');
        } else {
            sb.append('"').append(jsonEscape(String.valueOf(v))).append('"');
        }
    }

    /** 发送文本响应。 */
    private static void sendText(HttpExchange ex, int code, String contentType, String text)
            throws IOException {
        byte[] msg = text.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", contentType);
        ex.getResponseHeaders().set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        ex.getResponseHeaders().set("Pragma", "no-cache");
        ex.sendResponseHeaders(code, msg.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(msg);
        }
    }

    // ============================================================
    // 极简 JSON 解析（仅需扁平对象，无需通用 JSON 库，保持离线）
    // ============================================================

    /** 解析 JSON 对象为 Map（只处理扁平字符串值）。 */
    private static Map<String, Object> parseJsonObject(String json) {
        Map<String, Object> out = new LinkedHashMap<>();
        String s = json == null ? "" : json.trim();
        if (s.isEmpty() || !s.startsWith("{")) {
            return out;
        }
        s = s.substring(1);
        int i = 0;
        while (i < s.length()) {
            // 找 key
            while (i < s.length() && (s.charAt(i) == ' ' || s.charAt(i) == ',')) {
                i++;
            }
            if (i >= s.length() || s.charAt(i) == '}') {
                break;
            }
            if (s.charAt(i) == '"') {
                Object[] kr = readJsonString(s, i + 1);
                String key = (String) kr[0];
                i = (Integer) kr[1];
                while (i < s.length() && s.charAt(i) != ':') {
                    i++;
                }
                i++;
                while (i < s.length() && (s.charAt(i) == ' ' || s.charAt(i) == '\t')) {
                    i++;
                }
                // 值
                if (i < s.length() && s.charAt(i) == '"') {
                    Object[] vr = readJsonString(s, i + 1);
                    out.put(key, (String) vr[0]);
                    i = (Integer) vr[1];
                } else {
                    int vEnd = i;
                    while (vEnd < s.length() && s.charAt(vEnd) != ',' && s.charAt(vEnd) != '}') {
                        vEnd++;
                    }
                    out.put(key, s.substring(i, vEnd).trim());
                    i = vEnd;
                }
            } else {
                i++;
            }
        }
        return out;
    }

    /** 读取 JSON 字符串字面量（i 指向开引号后一字符），返回 [解码值, 闭引号后一位置]。
     *  支持 \\n \\r \\t \\b \\f \\/ \\" \\\\ 与 uXXXX 十六进制转义（未闭合时返回剩余内容）。 */
    private static Object[] readJsonString(String s, int i) {
        StringBuilder v = new StringBuilder();
        int p = i;
        while (p < s.length()) {
            char c = s.charAt(p);
            if (c == '\\' && p + 1 < s.length()) {
                char n = s.charAt(p + 1);
                switch (n) {
                    case 'n': v.append('\n'); break;
                    case 'r': v.append('\r'); break;
                    case 't': v.append('\t'); break;
                    case 'b': v.append('\b'); break;
                    case 'f': v.append('\f'); break;
                    case '/': v.append('/'); break;
                    case '"': v.append('"'); break;
                    case '\\': v.append('\\'); break;
                    case 'u': {
                        if (p + 5 < s.length()) {
                            try {
                                v.append((char) Integer.parseInt(s.substring(p + 2, p + 6), 16));
                                p += 4; // uXXXX 转义共 6 字符：p+=4 后由下方 p+=2 收尾
                            } catch (NumberFormatException e) {
                                v.append('u');
                            }
                        } else {
                            v.append('u');
                        }
                        break;
                    }
                    default: v.append(n); break;
                }
                p += 2;
                continue;
            }
            if (c == '"') {
                return new Object[]{v.toString(), p + 1};
            }
            v.append(c);
            p++;
        }
        return new Object[]{v.toString(), p}; // 未闭合引号
    }

    /** 从解析出的参数取字符串值。 */
    private static String str(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v == null ? "" : String.valueOf(v);
    }

    // ============================================================
    // 内嵌前端页面（单文件原生 HTML/CSS/JS，无任何外部依赖，离线可用）
    // ============================================================

    @SuppressWarnings("text-blocks")
    private static final String PAGE_P1 = """
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>MODPKICA 管理控制台</title>
        <style>
          :root {
            --bg: #0f1419; --panel: #171e26; --panel2: #1d2630;
            --border: #263241; --text: #d8e1ea; --dim: #8b98a5;
            --accent: #38bdf8; --accent2: #22d3ee; --ok: #34d399; --warn: #fbbf24;
            --err: #f87171; --mono: Consolas, "Courier New", monospace;
          }
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { background: var(--bg); color: var(--text); font-family: "Segoe UI", "Microsoft YaHei", sans-serif; font-size: 15px; display: flex; height: 100vh; overflow: hidden; }
          /* ===== 侧边栏 ===== */
          #sidebar { width: 200px; min-width: 200px; background: var(--panel); border-right: 1px solid var(--border); display: flex; flex-direction: column; }
          .logo { padding: 18px 16px; font-size: 18px; font-weight: 700; letter-spacing: 1px; border-bottom: 1px solid var(--border); }
          .logo span { color: var(--accent); }
          nav { flex: 1; overflow-y: auto; padding: 8px 0; }
          nav a { display: block; padding: 10px 18px; color: var(--dim); text-decoration: none; cursor: pointer; border-left: 3px solid transparent; transition: all .15s; }
          nav a:hover { color: var(--text); background: var(--panel2); }
          nav a.active { color: var(--accent); background: var(--panel2); border-left-color: var(--accent); }
          .side-foot { padding: 12px 16px; font-size: 12px; color: var(--dim); border-top: 1px solid var(--border); }
          /* ===== 主区 ===== */
          #main { flex: 1; display: flex; flex-direction: column; min-width: 0; }
          #topbar { height: 56px; display: flex; align-items: center; gap: 14px; padding: 0 20px; background: var(--panel); border-bottom: 1px solid var(--border); }
          #topbar h1 { font-size: 16px; font-weight: 600; flex: 1; }
          #content { flex: 1; overflow-y: auto; min-height: 0; padding: 20px; }
          .page { display: none; }
          .page.active { display: block; }
          /* ===== 组件 ===== */
          .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px 18px; margin-bottom: 16px; }
          .card h2 { font-size: 14px; font-weight: 600; margin-bottom: 12px; color: var(--accent); }
          .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; }
          .stat { background: var(--panel2); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }
          .stat .label { font-size: 12px; color: var(--dim); margin-bottom: 6px; }
          .stat .value { font-size: 20px; font-weight: 700; font-family: var(--mono); }
          .stat .value.ok { color: var(--ok); } .stat .value.warn { color: var(--warn); } .stat .value.err { color: var(--err); }
          .stat.stat-wide { grid-column: 1 / -1; }
          .stat.stat-wide .value { font-size: 13px; white-space: normal; word-break: break-all; line-height: 1.6; }
          .cfg-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 14px; margin-top: 14px; }
          .cfg-field { background: var(--panel2); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; }
          .cfg-field label { display: block; font-size: 13px; font-weight: 600; color: var(--fg); margin-bottom: 8px; }
          .cfg-tag { font-size: 11px; font-weight: 400; color: var(--dim); margin-left: 6px; }
          .cfg-field input { width: 100%; box-sizing: border-box; font-family: var(--mono); font-size: 13px; }
          .cfg-field textarea { width: 100%; box-sizing: border-box; font-family: var(--mono); font-size: 13px; resize: vertical; min-height: 90px; line-height: 1.6; }
          .cfg-field-wide { grid-column: 1 / -1; }
          .cfg-hint { font-size: 11px; color: var(--dim); margin: 8px 0 0; line-height: 1.5; }
          .eku-modal { width: min(700px, 94vw); }
          .eku-body { display: grid; grid-template-columns: repeat(auto-fill, minmax(310px, 1fr)); gap: 4px; max-height: 55vh; overflow: auto; padding: 10px 4px; }
          .eku-item { display: flex; align-items: center; gap: 8px; font-size: 13px; padding: 7px 9px; border-radius: 6px; cursor: pointer; }
          .eku-item:hover { background: var(--panel2); }
          .eku-item input { width: auto; flex: none; }
          .eku-item code { color: var(--dim); font-size: 11px; margin-left: auto; white-space: nowrap; }
          .modal-foot { display: flex; gap: 10px; justify-content: flex-end; padding: 12px 18px; border-top: 1px solid var(--border); }
          .val-row { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
          .val-row label { width: 64px; font-size: 13px; color: var(--fg); flex: none; }
          .val-row input { width: 100%; font-family: var(--mono); font-size: 13px; }
          .fsec { margin-top: 16px; padding-top: 12px; border-top: 1px dashed var(--border); }
          .fsec:first-of-type { margin-top: 0; padding-top: 0; border-top: none; }
          .fsec-title { font-size: 12px; font-weight: 700; color: var(--accent); margin-bottom: 10px; letter-spacing: 1px; }
          select.t-box { cursor: pointer; }
          select.t-box:hover { border-color: var(--accent); }
          .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; }
          .badge.ok { background: rgba(52,211,153,.15); color: var(--ok); }
          .badge.err { background: rgba(248,113,113,.15); color: var(--err); }
          .badge.dim { background: var(--panel2); color: var(--dim); }
          label { display: block; font-size: 12px; color: var(--dim); margin: 10px 0 4px; }
          input, select, textarea { width: 100%; background: var(--panel2); border: 1px solid var(--border); color: var(--text); border-radius: 6px; padding: 8px 10px; font-family: var(--mono); font-size: 13px; outline: none; }
          input:focus, select:focus, textarea:focus { border-color: var(--accent); }
          .row { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
          .sig-tabs { display: flex; gap: 10px; margin-bottom: 16px; border-bottom: 1px solid var(--border); padding-bottom: 12px; }
          .sig-tab { padding: 10px 28px; font-size: 15px; font-weight: 700; background: var(--panel2); color: var(--dim); border: 1px solid var(--border); border-radius: 8px; cursor: pointer; transition: all .15s; }
          .sig-tab:hover { color: var(--text); border-color: var(--accent); }
          .sig-tab.active { background: var(--accent); color: #0b1220; border-color: var(--accent); }
          .sig-pane { font-size: 14px; }
          .sig-pane .row { grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); }
          .dropzone { border: 2px dashed var(--border); border-radius: 10px; padding: 28px 20px; text-align: center; margin: 14px 0; cursor: pointer; transition: all .15s; }
          .dropzone.over { border-color: var(--accent); background: rgba(96,165,250,.08); }
          .fake-btn { display: inline-block; padding: 9px 22px; font-size: 14px; font-weight: 700; color: #0b1220; background: var(--accent); border-radius: 7px; cursor: pointer; }
          .pdf-list-head { display: flex; gap: 10px; align-items: center; margin-top: 14px; font-size: 14px; }
          .pdf-list-head button { padding: 7px 16px; }
          .pdf-list { max-height: 240px; overflow: auto; border: 1px solid var(--border); border-radius: 8px; margin: 10px 0; }
          .pdf-row { display: flex; align-items: center; gap: 10px; padding: 8px 12px; border-bottom: 1px solid var(--border); font-size: 13px; }
          .pdf-row:last-child { border-bottom: none; }
          .pdf-row .nm { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; }
          .pdf-row .st { font-size: 12px; min-width: 150px; }
          .pdf-row .st.ok { color: var(--ok); } .pdf-row .st.err { color: var(--err); } .pdf-row .st.wait { color: var(--dim); }
          .pdf-row button { padding: 3px 10px; font-size: 12px; }
          .pdf-row a.dl { color: var(--accent); font-weight: 700; font-size: 12px; text-decoration: none; }
          button { background: var(--accent); color: #06202e; border: none; border-radius: 6px; padding: 9px 20px; font-size: 13px; font-weight: 700; cursor: pointer; transition: filter .15s; }
          button:hover { filter: brightness(1.15); }
          button.ghost { background: var(--panel2); color: var(--text); border: 1px solid var(--border); }
          button.danger { background: #7f1d1d; color: #fecaca; }
          button.success { background: #14532d; color: #bbf7d0; }
          button:disabled { opacity: .5; cursor: not-allowed; }
          table { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 12.5px; }
          th, td { padding: 8px 10px; border-bottom: 1px solid var(--border); text-align: left; white-space: nowrap; }
          th { color: var(--dim); font-weight: 600; position: sticky; top: 0; background: var(--panel); }
          tr:hover td { background: var(--panel2); }
          pre.out { background: #0a0e13; border: 1px solid var(--border); border-radius: 8px; padding: 14px; font-family: var(--mono); font-size: 13px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; max-height: 420px; overflow-y: auto; margin-top: 14px; }
          pre.out.ok { border-color: rgba(52,211,153,.4); } pre.out.err { border-color: rgba(248,113,113,.4); }
          .toolbar { display: flex; gap: 10px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
          .toolbar input { width: auto; } .toolbar select { width: auto; }
          .hint { font-size: 12px; color: var(--warn); background: rgba(251,191,36,.08); border: 1px solid rgba(251,191,36,.3); border-radius: 6px; padding: 8px 12px; margin-bottom: 10px; }
          .loading { opacity: .6; pointer-events: none; }
          ::-webkit-scrollbar { width: 8px; height: 8px; }
          ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
          /* ===== 证书链树 ===== */
          .t-row { display: flex; gap: 28px; align-items: flex-start; flex-wrap: wrap; }
          .t-node { position: relative; margin: 4px 0; }
          .t-head { display: flex; align-items: center; gap: 4px; }
          .t-toggle { flex: none; width: 16px; height: 16px; line-height: 14px; text-align: center; font-size: 9px; cursor: pointer; user-select: none; color: var(--accent); background: var(--panel2); border: 1px solid var(--border); border-radius: 4px; }
          .t-toggle:hover { background: var(--border); }
          .t-node-root > .t-head > .t-box { border-color: #b45309; }
          .t-node-c > .t-head > .t-box { border-color: #2563eb; }
          .t-node-e > .t-head > .t-box { border-color: #059669; }
          .t-box { display: inline-block; padding: 7px 12px; border: 1px solid var(--border); border-left-width: 4px; border-radius: 8px; background: var(--panel2); cursor: default; font-family: var(--mono); font-size: 12px; white-space: nowrap; }
          .t-box .t-badge { display: inline-block; width: 18px; height: 18px; line-height: 18px; text-align: center; border-radius: 4px; font-size: 11px; font-weight: 700; margin-right: 6px; }
          .t-badge.R { background: rgba(180,83,9,.25); color: #fbbf24; }
          .t-badge.C { background: rgba(37,99,235,.25); color: #60a5fa; }
          .t-badge.E { background: rgba(5,150,105,.25); color: #34d399; }
          .t-kind { color: var(--dim); font-size: 11px; margin-right: 8px; }
          .t-box .t-st { margin-left: 8px; font-size: 11px; }
          .t-box .t-st.V { color: var(--ok); } .t-box .t-st.R { color: var(--err); } .t-box .t-st.N { color: var(--warn); }
          .t-children { margin-left: 22px; padding-left: 14px; border-left: 2px solid var(--border); }
          .t-children.collapsed { display: none; }
          .t-tip, #tipFloat b { color: var(--accent); }
          .t-tip, #tipFloat .kv { font-family: var(--mono); }
          /* 悬浮详情：fixed 挂 body，避免被 #content 滚动容器裁剪或被顶栏遮挡 */
          #tipFloat { position: fixed; z-index: 9999; left: 0; top: 0; min-width: 260px; max-width: 420px; background: #0a0e13; border: 1px solid var(--accent); border-radius: 8px; padding: 10px 12px; font-size: 12px; line-height: 1.7; display: none; pointer-events: none; box-shadow: 0 8px 24px rgba(0,0,0,.5); }
          /* ===== 详情弹窗 ===== */
          .modal-mask { position: fixed; inset: 0; background: rgba(0,0,0,.65); z-index: 100; display: none; align-items: center; justify-content: center; }
          .modal-mask.show { display: flex; }
          .modal { width: min(900px, 92vw); max-height: 86vh; background: var(--panel); border: 1px solid var(--border); border-radius: 12px; display: flex; flex-direction: column; overflow: hidden; }
          .modal-head { display: flex; align-items: center; padding: 12px 18px; border-bottom: 1px solid var(--border); }
          .modal-head h3 { flex: 1; font-size: 14px; color: var(--accent); }
          .modal-body { overflow: auto; padding: 14px 18px; }
          .modal-body pre { font-family: var(--mono); font-size: 12px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; }
          /* ===== 证书操作弹窗（吊销/续签/密钥更换） ===== */
          .op-tabs { display: flex; gap: 4px; margin-bottom: 14px; border-bottom: 1px solid var(--border); }
          .op-tab { padding: 8px 18px; cursor: pointer; color: var(--dim); border-bottom: 2px solid transparent; font-size: 13px; user-select: none; }
          .op-tab:hover { color: var(--text); }
          .op-tab.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: 700; }
          .op-pane label { display: block; color: var(--dim); font-size: 12px; margin: 10px 0 6px; }
          .op-pane input[list] { width: 100%; }
          .op-serial-info { margin-top: 12px; padding: 10px 14px; background: var(--panel2); border: 1px solid var(--border); border-radius: 8px; font-size: 12px; line-height: 1.8; }
          .op-serial-info .kv { font-family: var(--mono); }
          .op-serial-info .kv b { color: var(--accent); }
          #opSerialList { display: none; }
          /* ===== 证书验证弹窗：状态徽标 + 标题三态配色 ===== */
          .v-badge { padding: 3px 14px; border-radius: 6px; font-weight: 700; font-size: 12px; margin-right: 10px; white-space: nowrap; }
          .v-text { font-size: 13px; color: var(--text); margin-right: 12px; white-space: nowrap; }
        </style>
        </head>
        <body>
        <!-- ===== 侧边栏 ===== -->
        <aside id="sidebar">
          <div class="logo">MOD<span>PKICA</span></div>
          <nav id="nav">
            <a data-page="dashboard" class="active">仪表盘</a>
            <a data-page="certs">证书库</a>
            <a data-page="makeroot">签发根证书</a>
            <a data-page="signcert">签发证书</a>
            <a data-page="ocsp">OCSP|TSA签发</a>
            <a data-page="template">模板管理</a>
            <a data-page="revoke">吊销证书</a>
            <a data-page="verify">证书验证</a>
            <a data-page="sign">签名专区</a>
            <a data-page="ctlog">SCT服务管理</a>
            <a data-page="radius">Radius服务管理</a>
            <a data-page="pppoe">PPPoE服务管理</a>
            <a data-page="init">初始化环境</a>
            <a data-page="users">用户管理</a>
            <a data-page="config">系统配置</a>
            <a data-page="logs">操作日志</a>
          </nav>
          <div class="side-foot" id="sideVersion">加载中...</div>
        </aside>

        <!-- ===== 主区 ===== -->
        <div id="main">
          <header id="topbar">
            <h1 id="pageTitle">仪表盘</h1>
            <span class="badge dim" id="mainPort">MAIN: --</span>
            <span class="badge ok" id="mainState">--</span>
            <button class="ghost" onclick="loadStatus()">刷新</button>
          </header>

          <section id="content">

            <!-- 仪表盘 -->
            <div class="page active" id="page-dashboard">
              <div class="grid">
                <div class="stat"><div class="label">MAIN 服务端口</div><div class="value ok" id="stPort">--</div></div>
                <div class="stat"><div class="label">服务运行时长</div><div class="value" id="stUptime">--</div></div>
                <div class="stat"><div class="label">管理界面端口</div><div class="value" id="stAdmin">--</div></div>
                <div class="stat"><div class="label">API 调用次数</div><div class="value" id="stCalls">--</div></div>
                <div class="stat"><div class="label">日志行数</div><div class="value" id="stLogs">--</div></div>
                <div class="stat stat-wide"><div class="label">工作目录</div><div class="value" id="stBase">--</div></div>
              </div>
              <div class="card" style="margin-top:16px">
                <h2>快捷操作</h2>
                <div class="toolbar">
                  <button onclick="quickAction('/api/crl')">刷新全部 CRL</button>
                  <button onclick="quickAction('/api/initocsp')">签发全部 OCSP</button>
                  <button onclick="quickAction('/api/inittimestamp')">签发全部时间戳</button>
                </div>
                <pre class="out" id="dashOut" hidden></pre>
              </div>
              <div class="card">
                <h2>证书链树</h2>
                <div class="toolbar">
                  <span style="color:var(--dim);font-size:12px">根 R → 中间 CA C → 终端 E；鼠标悬停节点查看证书参数</span>
                  <button class="ghost" onclick="loadChain()">刷新</button>
                </div>
                <div id="chainBox" style="overflow:auto;max-height:52vh;padding:10px">加载中...</div>
              </div>
              <div class="card">
                <h2>最近日志</h2>
                <pre class="out" id="dashLogs" style="max-height:260px"></pre>
              </div>
            </div>

            <!-- 证书库 -->
            <div class="page" id="page-certs">
              <div class="card">
                <div class="ct-tabs">
                  <button class="ct-tab active" id="csTabBtnLocal" onclick="csSwitchTab('local')">证书库 CERTS.txt</button>
                  <button class="ct-tab" id="csTabBtnCa" onclick="csSwitchTab('cacerts')">可信公网证书库 cacerts</button>
                  <button class="ct-tab" id="csTabBtnMy" onclick="csSwitchTab('my')">我的证书</button>
                </div>
                <div id="csPaneLocal">
                  <div class="toolbar">
                    <input id="certsFilter" placeholder="筛选：序列号 / 类型 / 状态 / 算法" style="flex:1;max-width:360px" oninput="renderCerts()">
                    <button class="ghost" onclick="loadCerts()">刷新列表</button>
                  </div>
                  <div style="overflow:auto;max-height:60vh">
                    <table id="certsTable">
                      <thead><tr><th>序列号</th><th>类型</th><th>状态</th><th>原因</th><th>时间</th><th>颁发者ID</th><th>算法</th><th>操作</th></tr></thead>
                      <tbody></tbody>
                    </table>
                  </div>
                </div>
                <div id="csPaneCa" style="display:none">
                  <div class="hint">JAVA 环境 lib/security/cacerts 中的可信证书（只读参考）。点击"详情"可查看 PEM 证书结构（JSON）。本地证书文件验证请到"证书验证"页面上传。</div>
                  <div class="toolbar">
                    <input id="caFilter" placeholder="筛选：序列号 / 颁发者 / 算法" style="flex:1;max-width:360px" oninput="renderCacerts()">
                    <button class="ghost" onclick="loadCacerts()">刷新列表</button>
                  </div>
                  <div style="overflow:auto;max-height:60vh">
                    <table id="caTable">
                      <thead><tr><th>序列号</th><th>算法</th><th>生效日期</th><th>失效日期</th><th>DN字段</th><th>操作</th></tr></thead>
                      <tbody></tbody>
                    </table>
                  </div>
                </div>
                <div id="csPaneMy" style="display:none">
                  <div class="toolbar">
                    <input id="myFilter" placeholder="筛选：序列号 / 类型 / 算法" style="flex:1;max-width:360px" oninput="renderMy()">
                    <button class="primary" onclick="$('myFile').click()">导入证书</button>
                    <button class="ghost" onclick="loadMy()">刷新列表</button>
                  </div>
                  <input type="file" id="myFile" accept=".pfx,.p12,.jks,.cer,.crt,.pem" style="display:none" onchange="myFileChosen()">
                  <div id="myMsg" class="hint" style="margin:6px 0;color:var(--dim)">从本机导入证书（pfx / p12 / jks 需输入密码；cer / crt / pem 直接导入，可含私钥）。</div>
                  <div style="overflow:auto;max-height:60vh">
                    <table id="myTable">
                      <thead><tr><th>序列号</th><th>类型</th><th>算法</th><th>是否含有私钥</th><th>生效日期</th><th>失效日期</th><th>操作</th></tr></thead>
                      <tbody></tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>

            <!-- 签发根证书 -->
            <div class="page" id="page-makeroot">
              <div class="card">
                <h2>签发根证书（MakeRoot）</h2>
                <div class="row">
                  <div style="grid-column:1/-1"><label>证书 DN（逗号分隔 key=value）</label><input id="mkDn" placeholder="根证书 DN（key=value 逗号分隔，key 可为标准属性或 OID），如 CN=My Root CA,O=My Org,C=CN"></div>
                  <div><label>密钥算法</label><select id="mkAlgo" onchange="extAlgoChanged('mk')"><option>RSA</option><option>RSA-PSS</option><option>ECC</option><option>SM2</option><option>DSA</option><option>EdDSA</option><option>PQC</option></select></div>
                  <div><label>哈希算法</label><select id="mkHash"><option>sha256</option><option>sha1</option><option>sha384</option><option>sha512</option><option>SHA3-224</option><option>SHA3-256</option><option>SHA3-384</option><option>SHA3-512</option><option>SM3</option><option>NULL</option></select></div>
                  <div><label>密钥位数</label><select id="mkBits"></select></div>
                </div>
                <div class="fsec" style="margin-top:14px">
                  <div class="fsec-title">DN 辅助编辑 — 基础字段 / EV 注册字段 / 自定义 OID</div>
                  <div class="row">
                    <div><label>CN 通用名称</label><input id="mkDnCn" placeholder="通用名称（CN），如 My Root CA" oninput="syncMkDn()"></div>
                    <div><label>O 组织</label><input id="mkDnO" placeholder="组织（O），如 My Org" oninput="syncMkDn()"></div>
                    <div><label>OU 组织单位</label><input id="mkDnOu" placeholder="组织单位（OU），如 IT Dept（可选）" oninput="syncMkDn()"></div>
                    <div><label>C 国家</label><input id="mkDnC" placeholder="国家代码（C），如 CN（两位）" maxlength="2" oninput="syncMkDn()"></div>
                    <div><label>S 省/州</label><input id="mkDnS" placeholder="省/州（S），如 Guangdong（可选）" oninput="syncMkDn()"></div>
                    <div><label>L 城市</label><input id="mkDnL" placeholder="城市（L），如 Shenzhen（可选）" oninput="syncMkDn()"></div>
                    <div><label>E 邮箱（OID 字段）</label><input id="mkDnE" placeholder="邮箱（E，OID 1.2.840.113549.1.9.1），如 admin@example.com" oninput="syncMkDn()"></div>
                    <div><label>是否 EV 扩展验证</label>
                      <label style="display:flex;justify-content:flex-start;align-items:center;width:100%;height:32px;cursor:pointer;margin:0"><input type="checkbox" id="mkDnEvToggle" onchange="toggleMkDnEv()" style="margin:0;flex:none"></label>
                    </div>
                  </div>
                  <div id="mkDnEvFields" style="margin-top:14px;display:none">
                    <div class="fsec-title" style="font-size:12px;margin-bottom:8px">EV 注册字段（EV Guidelines 专属 OID；注册类型四选一，注册号填营业执照/统一社会信用代码）</div>
                    <div class="row">
                      <div><label>注册类型（businessCategory 2.5.4.15）</label>
                        <select id="mkDnBc" onchange="syncMkDn()">
                          <option value="">（不填）</option>
                          <option>Private Organization</option>
                          <option>Government Entity</option>
                          <option>Business Entity</option>
                          <option>Non-Commercial Entity</option>
                        </select>
                      </div>
                      <div><label>注册号（serialNumber 2.5.4.5）</label><input id="mkDnReg" placeholder="注册号（serialNumber 2.5.4.5），如 91310000MA5XXXXXXXX" oninput="syncMkDn()"></div>
                      <div><label>注册国家（jurisdictionCountry）</label><input id="mkDnJc" placeholder="注册国家（jurisdictionCountry），如 CN（两位）" maxlength="2" oninput="syncMkDn()"></div>
                      <div><label>注册省（jurisdictionStateOrProvince）</label><input id="mkDnJs" placeholder="注册省（jurisdictionStateOrProvince），如 Guangdong（可选）" oninput="syncMkDn()"></div>
                      <div><label>注册市（jurisdictionLocality）</label><input id="mkDnJl" placeholder="注册市（jurisdictionLocality），如 Shenzhen（可选）" oninput="syncMkDn()"></div>
                      <div><label>注册地址（streetAddress 2.5.4.9）</label><input id="mkDnAddr" placeholder="注册地址（streetAddress 2.5.4.9），如 No.1 Beijing Road（可选）" oninput="syncMkDn()"></div>
                      <div><label>组织标识符（2.5.4.97）</label><input id="mkDnOi" placeholder="组织标识符（2.5.4.97），如 NTRCN-91310000MA5XXXXXXXX" oninput="syncMkDn()"></div>
                      <div><label>组织标识符扩展 OID 版本</label>
                        <label style="display:flex;justify-content:flex-start;align-items:center;width:100%;height:32px;cursor:pointer;margin:0" title="未勾选=旧版 1.3.6.1.4.1.57264.1.8（SC27-2019）；勾选=新版 2.23.140.3.1（EVG 2.0.1）"><input type="checkbox" id="mkDnOidNew" style="margin:0;flex:none"></label>
                      </div>
                    </div>
                  </div>
                  <div style="margin-top:12px">
                    <div class="fsec-title" style="font-size:12px;margin-bottom:8px">自定义字段（key 可写字段名或对象标识符 OID，如 2.5.4.42=张三、2.23.140.1.1=EV）</div>
                    <div id="mkDnOidRows"></div>
                    <button type="button" class="ghost" onclick="addMkDnRow('','')">+ 添加自定义字段</button>
                  </div>
                  <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                    <button type="button" class="ghost" onclick="parseMkDn()">从上方 DN 解析回填</button>
                    <span style="color:var(--dim);font-size:12px">辅助编辑实时同步到上方 DN 输入框；也可直接编辑 DN 后点“解析回填”拆分到各字段。</span>
                  </div>
                </div>
                <div style="margin-top:16px"><button onclick="postForm('/api/makeroot', {dn:v('mkDn'),bits:extBitsVal('mk'),hash:v('mkHash'),algo:v('mkAlgo'),evoid: $('mkDnOidNew') && $('mkDnOidNew').checked ? 'new' : 'old'}, 'mkOut')">签发根证书</button></div>
                <pre class="out" id="mkOut"></pre>
              </div>
            </div>

            <!-- 签发证书 -->
            <div class="page" id="page-signcert">
              <div class="card">
                <h2>签发证书（MakeCert 普通模式，12 参数）</h2>

                <div class="fsec"><div class="fsec-title">主体信息</div>
                  <div class="row">
                    <div style="grid-column:1/-1"><label>证书 DN（key=value 逗号分隔，key 可为标准属性或 OID）</label><input id="scDn" placeholder="证书 DN（key=value 逗号分隔，key 可为标准属性或 OID），如 CN=www.test.com,O=My Org,C=CN"></div>
                  </div>
                </div>

                <div class="fsec" style="margin-top:14px">
                  <div class="fsec-title">DN 辅助编辑 — 基础字段 / EV 注册字段 / 自定义 OID</div>
                  <div class="row">
                    <div><label>CN 通用名称</label><input id="scDnCn" placeholder="通用名称（CN），如 www.test.com" oninput="syncDn('sc')"></div>
                    <div><label>O 组织</label><input id="scDnO" placeholder="组织（O），如 My Org" oninput="syncDn('sc')"></div>
                    <div><label>OU 组织单位</label><input id="scDnOu" placeholder="组织单位（OU），如 IT Dept（可选）" oninput="syncDn('sc')"></div>
                    <div><label>C 国家</label><input id="scDnC" placeholder="国家代码（C），如 CN（两位）" maxlength="2" oninput="syncDn('sc')"></div>
                    <div><label>S 省/州</label><input id="scDnS" placeholder="省/州（S），如 Guangdong（可选）" oninput="syncDn('sc')"></div>
                    <div><label>L 城市</label><input id="scDnL" placeholder="城市（L），如 Shenzhen（可选）" oninput="syncDn('sc')"></div>
                    <div><label>E 邮箱（OID 字段）</label><input id="scDnE" placeholder="邮箱（E，OID 1.2.840.113549.1.9.1），如 admin@example.com" oninput="syncDn('sc')"></div>
                    <div><label>是否 EV 扩展验证</label>
                      <label style="display:flex;justify-content:flex-start;align-items:center;width:100%;height:32px;cursor:pointer;margin:0"><input type="checkbox" id="scDnEvToggle" onchange="toggleDnEv('sc')" style="margin:0;flex:none"></label>
                    </div>
                  </div>
                  <div id="scDnEvFields" style="margin-top:14px;display:none">
                    <div class="fsec-title" style="font-size:12px;margin-bottom:8px">EV 注册字段（EV Guidelines 专属 OID；注册类型四选一，注册号填营业执照/统一社会信用代码）</div>
                    <div class="row">
                      <div><label>注册类型（businessCategory 2.5.4.15）</label>
                        <select id="scDnBc" onchange="syncDn('sc')">
                          <option value="">（不填）</option>
                          <option>Private Organization</option>
                          <option>Government Entity</option>
                          <option>Business Entity</option>
                          <option>Non-Commercial Entity</option>
                        </select>
                      </div>
                      <div><label>注册号（serialNumber 2.5.4.5）</label><input id="scDnReg" placeholder="注册号（serialNumber 2.5.4.5），如 91310000MA5XXXXXXXX" oninput="syncDn('sc')"></div>
                      <div><label>注册国家（jurisdictionCountry）</label><input id="scDnJc" placeholder="注册国家（jurisdictionCountry），如 CN（两位）" maxlength="2" oninput="syncDn('sc')"></div>
                      <div><label>注册省（jurisdictionStateOrProvince）</label><input id="scDnJs" placeholder="注册省（jurisdictionStateOrProvince），如 Guangdong（可选）" oninput="syncDn('sc')"></div>
                      <div><label>注册市（jurisdictionLocality）</label><input id="scDnJl" placeholder="注册市（jurisdictionLocality），如 Shenzhen（可选）" oninput="syncDn('sc')"></div>
                      <div><label>注册地址（streetAddress 2.5.4.9）</label><input id="scDnAddr" placeholder="注册地址（streetAddress 2.5.4.9），如 No.1 Beijing Road（可选）" oninput="syncDn('sc')"></div>
                      <div><label>组织标识符（2.5.4.97）</label><input id="scDnOi" placeholder="组织标识符（2.5.4.97），如 NTRCN-91310000MA5XXXXXXXX" oninput="syncDn('sc')"></div>
                      <div><label>组织标识符扩展 OID 版本</label>
                        <label style="display:flex;justify-content:flex-start;align-items:center;width:100%;height:32px;cursor:pointer;margin:0" title="未勾选=旧版 1.3.6.1.4.1.57264.1.8（SC27-2019）；勾选=新版 2.23.140.3.1（EVG 2.0.1）"><input type="checkbox" id="scDnOidNew" style="margin:0;flex:none"></label>
                      </div>
                    </div>
                  </div>
                  <div style="margin-top:12px">
                    <div class="fsec-title" style="font-size:12px;margin-bottom:8px">自定义字段（key 可写字段名或对象标识符 OID，如 2.5.4.42=张三、2.23.140.1.1=EV）</div>
                    <div id="scDnOidRows"></div>
                    <button type="button" class="ghost" onclick="addDnRow('sc','','')">+ 添加自定义字段</button>
                  </div>
                  <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                    <button type="button" class="ghost" onclick="parseDn('sc')">从上方 DN 解析回填</button>
                  </div>
                </div>
                <div class="fsec"><div class="fsec-title">密钥与算法</div>
                  <div class="row">
                    <div><label>证书类型</label><select id="scCa" onchange="scCaChanged()"><option value="0">终端证书</option><option value="1">中间 CA</option></select></div>
                    <div id="scPathLenWrap" style="display:none"><label>路径长度</label><select id="scPathLen" title="中间CA 的 BasicConstraints pathLenConstraint；null 表示不限制"><option value="">null</option><option>0</option><option>1</option><option>2</option><option>3</option><option>4</option><option>5</option><option>6</option><option>7</option><option>8</option><option>9</option></select></div>
                    <div><label>密钥算法</label><select id="scAlgo" onchange="algoChanged()"><option>RSA</option><option>RSA-PSS</option><option>ECC</option><option>SM2</option><option>DSA</option><option>EdDSA</option><option>PQC</option></select></div>
                    <div><label>密钥位数</label><select id="scBits"></select></div>
                    <div><label>哈希算法</label><select id="scHash"><option>sha256</option><option>sha1</option><option>sha384</option><option>sha512</option><option>SHA3-224</option><option>SHA3-256</option><option>SHA3-384</option><option>SHA3-512</option><option>SM3</option><option>NULL</option></select></div>
                  </div>
                </div>

                <div class="fsec"><div class="fsec-title">密钥用途</div>
                  <div class="row">
                    <div><label>KeyUsage 编号</label>
                      <select id="scKu" onchange="kuSelChanged()">
                        <option value="">（无 KeyUsage 扩展）</option>
                        <option value="1">1 - 数字签名+不可否认+密钥加密+数据加密+密钥协商（通用）</option>
                        <option value="2">2 - 数字签名+不可否认+证书签名+CRL签名（CA用途）</option>
                        <option value="3">3 - 仅加密 Encipher Only</option>
                        <option value="4">4 - 仅解密 Decipher Only</option>
                        <option value="5">5 - 数字签名+不可否认（签名用途）</option>
                        <option value="6">6 - 数据加密 Data Encipherment</option>
                        <option value="7">7 - 密钥加密 Key Encipherment</option>
                        <option value="8">8 - 密钥协商 Key Agreement</option>
                        <option value="custom">自定义组合…（密钥用法选择器）</option>
                      </select>
                      <div style="display:flex;gap:6px;align-items:center;margin-top:6px">
                        <input id="scKuCustom" placeholder="自定义数值：各位值相加，如 5=数字签名1+密钥加密4" style="display:none">
                        <button type="button" class="ghost" onclick="openKuModal()" style="white-space:nowrap;flex:none">密钥用法…</button>
                      </div>
                    </div>
                    <div><label>EKU 编号/OID（逗号分隔）</label>
                      <div style="display:flex;gap:6px;align-items:center">
                        <input id="scEu" value="1" onclick="openEkuModal()" title="点击输入框或右侧按钮弹出 EKU 选择器">
                        <button type="button" class="ghost" onclick="openEkuModal()" style="white-space:nowrap;flex:none">选择…</button>
                      </div>
                    </div>
                  </div>
                </div>

                <div class="fsec" id="scPolWrap" style="display:none"><div class="fsec-title">证书策略（仅终端证书，勾选的策略才写入证书策略扩展）</div>
                  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(235px,1fr));gap:8px 16px;padding-top:6px">
                    <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="scPolDv"><span>SSL DV（2.23.140.1.2.1）</span></label>
                    <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="scPolIv"><span>SSL IV（2.23.140.1.2.3）</span></label>
                    <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="scPolOv"><span>SSL OV（2.23.140.1.2.2）</span></label>
                    <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="scPolEv"><span>SSL EV（2.23.140.1.1）</span></label>
                    <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="scPolCsStd"><span>代码签名-标准（2.23.140.1.4.1）</span></label>
                    <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="scPolCsEv"><span>代码签名-EV（2.23.140.1.3）</span></label>
                    <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="scPolDoc"><span>文档签名（1.3.6.1.5.5.7.3.36）</span></label>
                    <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="scPolTsa"><span>TSA 策略（2.23.140.1.4.2）</span></label>
                  </div>
                  <div style="display:flex;gap:6px;align-items:center;padding-top:8px">
                    <input id="scPolCustomOid" placeholder="自定义策略 OID，如 1.2.3.4.5" style="flex:1;min-width:220px" onkeydown="if(event.key==='Enter')addScPolCustom()">
                    <button type="button" onclick="addScPolCustom()">添加自定义策略</button>
                  </div>
                  <div id="scPolCustomBox"></div>
                </div>

                <div class="fsec"><div class="fsec-title">有效期</div>
                  <div class="row">
                    <div><label>有效期（年数或 起始T截至）</label>
                      <div style="display:flex;gap:6px;align-items:center">
                        <input id="scDays" value="1" title="数字=年数；或格式 起始T截至，如 2026/09/12-10:30:00T2027/09/12-10:30:00">
                        <button type="button" class="ghost" onclick="openValModal()" style="white-space:nowrap;flex:none">选择日期…</button>
                      </div>
                    </div>
                  </div>
                </div>

                <div class="fsec"><div class="fsec-title">SAN 扩展</div>
                  <div class="row">
                    <div><label>SAN 域名（逗号分隔，无则 null）</label><input id="scDns" value="null"></div>
                    <div><label>SAN IP（逗号分隔，无则 null）</label><input id="scIps" value="null"></div>
                  </div>
                </div>

                <div class="fsec"><div class="fsec-title">颁发者</div>
                  <div class="row">
                    <div style="grid-column:1/-1"><label>颁发者证书（CERTS.txt 中 R/C 类型序列号，鼠标悬停显示详情）</label>
                      <select id="scIssuer" class="t-box" onchange="refreshIssuerTip()"></select>
                    </div>
                  </div>
                </div>

                <div style="margin-top:16px"><button onclick="postForm('/api/signcert', {dn:v('scDn'),bits:bitsVal(),hash:v('scHash'),keyusage:kuVal(),exusage:v('scEu'),isca:v('scCa'),days:v('scDays'),dns:v('scDns'),ips:v('scIps'),issuer:v('scIssuer'),algo:v('scAlgo'),pathlen:pathLenVal(),policy:policyVal()}, 'scOut')">签发证书</button></div>
                <pre class="out" id="scOut"></pre>
              </div>
            </div>

            <!-- 吊销证书 -->
            <div class="page" id="page-revoke">
              <div class="card">
                <h2>吊销证书（RevokeCERT）</h2>
                <div class="hint">吊销后自动刷新 CRL 吊销列表。请先在「证书库」中确认序列号。</div>
                <div class="row">
                  <div><label>证书序列号</label><input id="rvSerial" placeholder="如 13fbe86586bb0a4"></div>
                  <div><label>吊销原因编号（0~9）</label><select id="rvReason">
                    <option value="0">0 - 未指定</option><option value="1">1 - 密钥泄露</option><option value="2">2 - CA泄露</option>
                    <option value="3">3 - 信息变更</option><option value="4">4 - 被替换</option><option value="5">5 - 操作终止</option>
                    <option value="6">6 - 证书暂停</option><option value="9">9 - 其它</option>
                  </select></div>
                </div>

                <div style="margin-top:16px"><button class="danger" onclick="postForm('/api/revoke', {serial:v('rvSerial'),reason:v('rvReason')}, 'rvOut')">吊销该证书</button></div>
                <pre class="out" id="rvOut"></pre>
              </div>
            </div>

            <!-- OCSP|TSA签发（签发证书 + 模拟请求调试 合并页） -->
            <div class="page" id="page-ocsp">
              <div class="card">
                <div class="sig-tabs" id="ocspTabs">
                  <button class="sig-tab active" data-tab="issue" onclick="ocspTab('issue')">OCSP签发</button>
                  <button class="sig-tab" data-tab="tsaissue" onclick="ocspTab('tsaissue')">TSA签发</button>
                  <button class="sig-tab" data-tab="debugocsp" onclick="ocspTab('debugocsp')">OCSP模拟请求调试</button>
                  <button class="sig-tab" data-tab="debugtsa" onclick="ocspTab('debugtsa')">TSA模拟请求调试</button>
                </div>
                <div id="ocspIssue">
                  <h2>签发 OCSP 签名证书（initOCSP）</h2>
                  <p style="color:var(--dim);margin-bottom:14px">为证书库中全部 R（根）/ C（中间CA）证书逐个生成 OCSP 签名证书，输出到 PKI/OCSP/序列号_ocsp.crt|.key。</p>
                  <div class="toolbar">
                    <select id="ocAlgo"><option value="">全部证书（按各自算法）</option><option>RSA</option><option>ECC</option><option>SM2</option></select>
                    <button onclick="postForm('/api/initocsp', {algo:v('ocAlgo')}, 'ocOut')">签发 OCSP 证书</button>
                  </div>
                  <pre class="out" id="ocOut"></pre>
                </div>
                <div id="tsaIssue" style="display:none">
                  <h2>签发时间戳证书（initTIMSTAMP）</h2>
                  <p style="color:var(--dim);margin-bottom:14px">为全部根证书生成时间戳证书：RSA/ECC → rsa/ecc_sha1 + rsa/ecc_sha256，SM2 → sm2_sm3，输出到 PKI/TIMSTAMP/。</p>
                  <div class="toolbar">
                    <select id="tsHash"><option value="">全部根证书（按各自算法）</option><option>SHA1</option><option>SHA256</option><option>SM3</option></select>
                    <button onclick="postForm('/api/inittimestamp', {hash:v('tsHash')}, 'tsOut')">签发时间戳证书</button>
                  </div>
                  <pre class="out" id="tsOut"></pre>
                </div>
                <div id="dbgOcsp" style="display:none">
                  <h2>模拟 OCSP 请求（RFC 6960）</h2>
                  <div class="hint">按标准构造 CertID（issuerNameHash/issuerKeyHash 基于真正颁发者证书）+ Nonce 扩展，POST 本机 MAIN 的 /OCSP，解析响应并验证签名与 Nonce 回显。</div>
                  <div class="row">
                    <div><label>目标证书序列号（留空自动选第一个终端证书）</label><input id="dbgOcspSerial" placeholder="例如 1135228a2"></div>
                    <div><label>CertID 哈希算法</label><select id="dbgOcspHash">
                      <option value="sha256" selected>SHA256</option>
                      <option value="sha1">SHA1</option>
                      <option value="sha384">SHA384</option>
                      <option value="sha512">SHA512</option>
                      <option value="sha3-224">SHA3-224</option>
                      <option value="sha3-256">SHA3-256</option>
                      <option value="sha3-384">SHA3-384</option>
                      <option value="sha3-512">SHA3-512</option>
                      <option value="sm3">SM3</option>
                    </select></div>
                    <div style="align-self:end"><button onclick="sendDebugOcsp()">发送模拟请求</button></div>
                  </div>
                  <pre class="out" id="dbgOcspOut" style="max-height:56vh;overflow:auto;white-space:pre;font-family:var(--mono);font-size:12px;line-height:1.55"></pre>
                </div>
                <div id="dbgTsa" style="display:none">
                  <h2>模拟时间戳请求（RFC 3161）</h2>
                  <div class="hint">随机生成 32 字节数据 → 按所选摘要算法计算 messageImprint → 构造 TimeStampReq（含 Nonce、certReq=true）→ POST 本机 MAIN 的 /rfc3161 → 解析 TimeStampResp 并验证签名。</div>
                  <div class="row">
                    <div><label>摘要算法</label><select id="dbgTsaHash">
                      <option value="sha256" selected>SHA256</option>
                      <option value="sha1">SHA1</option>
                      <option value="sha384">SHA384</option>
                      <option value="sha512">SHA512</option>
                      <option value="sha3-224">SHA3-224</option>
                      <option value="sha3-256">SHA3-256</option>
                      <option value="sha3-384">SHA3-384</option>
                      <option value="sha3-512">SHA3-512</option>
                      <option value="sm3">SM3</option>
                    </select></div>
                    <div style="align-self:end"><button onclick="sendDebugTsa()">对随机数据签名</button></div>
                  </div>
                  <pre class="out" id="dbgTsaOut" style="max-height:56vh;overflow:auto;white-space:pre;font-family:var(--mono);font-size:12px;line-height:1.55"></pre>
                </div>
              </div>
            </div>

            <!-- 证书验证 -->
            <div class="page" id="page-verify">
              <div class="card">
                <h2>证书验证（CertVerify）</h2>
                <div class="toolbar">
                  <input id="vfTarget" placeholder="证书文件路径，或序列号（自动查 PKI/WebPublic/CRT/序列号.crt）" style="flex:1;max-width:420px">
                  <button onclick="postForm('/api/verify', {target:v('vfTarget')}, 'vfOut')">验证</button>
                  <input type="file" id="vfFile" accept=".cer,.crt,.pem" onchange="verifyFile()" style="flex:1;max-width:320px">
                </div>
                <pre class="out" id="vfOut"></pre>
              </div>
            </div>

            <!-- 模板管理 -->
            <div class="page" id="page-template">
              <div class="card">
                <div class="toolbar">
                  <h2 style="margin:0">模板管理</h2>
                  <span style="color:var(--dim);font-size:12px">文件：PKI/tamplate/data.json</span>
                  <button onclick="openTpModal()">+ 添加模板</button>
                  <button class="ghost" onclick="loadTemplates()">刷新</button>
                </div>
                <div class="hint">模板保存签发证书的全部参数（DN / 算法 / 密钥用途 / EKU / 策略 / 有效期 / SAN），签署时选择 R 或 C 类型颁发者一键签发，操作全程写入 logs.log。</div>
                <table class="tbl" id="tplTable">
                  <thead><tr><th style="width:60px">序号</th><th style="width:110px">证书类型</th><th>DN</th><th style="width:150px">时间</th><th style="width:200px">操作</th></tr></thead>
                  <tbody></tbody>
                </table>
                <pre class="out" id="tplMsg"></pre>
              </div>
            </div>

            <!-- 签名专区 -->
            <div class="page" id="page-sign">
              <div class="card">
                <h2>签名专区</h2>
                <div class="sig-tabs">
                  <button class="sig-tab active" id="sigTabBtn-exe" onclick="sigTab('exe',this)">微软代码签名</button>
                  <button class="sig-tab" id="sigTabBtn-pdf" onclick="sigTab('pdf',this)">PDF 文档签名</button>
                </div>

                <!-- 微软代码签名（批量 + 拖拽） -->
                <div class="sig-pane" id="sigPane-exe">
                  <div class="hint">拖拽或批量选择 PE 可执行文件（exe / dll / sys / cab / cat / msi）加入待签名列表，再选证书与时间戳参数执行签名 / 验证。支持 RSA / ECC / SM2（摘要分别用 SHA256 / SHA256 / SM3），证书表按 Microsoft PE/COFF 规范嵌入。时间戳类型可选 RFC3161（标准 TimeStampToken）或 Authenticode（微软老式 PKCS#7）；地址可指向本机 MAIN（留空）或任意外部 TSA。</div>
                  <div class="row">
                    <div><label>签名证书（代码签名 EKU）</label><select id="sgExeCert" title="鼠标悬停查看证书简介"><option value="">（加载中...）</option></select></div>
                    <div><label>时间戳类型</label><select id="sgExeTsType">
                      <option value="RFC3161" selected>RFC3161（标准）</option>
                      <option value="AUTHENTICODE">Authenticode（老式 PKCS#7）</option>
                    </select></div>
                    <div style="grid-column:1/2"><label>时间戳请求地址（留空 = 本机 MAIN）</label>
                      <input id="sgExeTsUrl" list="tsUrlList" placeholder="http://timestamp.digicert.com" spellcheck="false">
                      <datalist id="tsUrlList">
                        <option value="http://timestamp.digicert.com">
                        <option value="http://sha256timestamp.ws.symantec.com/sha256/">
                        <option value="http://timestamp.comodoca.com">
                        <option value="http://time.certum.pl">
                      </datalist>
                    </div>
                  </div>
                  <div class="dropzone" id="exeDrop">
                    <div style="font-size:16px;font-weight:700;color:var(--text)">拖拽可执行文件到此处</div>
                    <div style="margin-top:6px;color:var(--dim)">支持 exe / dll / sys / cab / cat / msi（可多选）</div>
                    <label class="fake-btn" style="margin-top:12px">选择文件<input type="file" id="sgExeFile" multiple accept=".exe,.dll,.sys,.cab,.cat,.msi,application/octet-stream" hidden></label>
                  </div>
                  <div class="pdf-list-head">
                    <span style="font-weight:700">待签名列表（<b id="exeCount" style="color:var(--accent)">0</b> 个）</span>
                    <button onclick="exeSignAll()">批量签名</button>
                    <button class="ghost" onclick="exeVerifyAll()">批量验证</button>
                    <button class="ghost" onclick="exeClear()">清空</button>
                  </div>
                  <div id="exeList" class="pdf-list"></div>
                  <pre class="out" id="sgExeOut" style="max-height:30vh;overflow:auto;white-space:pre;font-family:var(--mono);font-size:12px;line-height:1.55"></pre>
                </div>

                <!-- PDF 文档签名（批量 + 拖拽） -->
                <div class="sig-pane" id="sigPane-pdf" style="display:none">
                  <div class="hint">批量选择或拖拽 PDF 文件加入待签名列表，再选证书与签章参数执行签名 / 验证。证书筛选：微软文档签名 OID（1.3.6.1.4.1.311.10.3.12）或通用文档签名 OID（1.3.6.1.5.5.7.3.36）任一即可。<br>签章类型：Adobe 标准文档签名（adbe.pkcs7.detached，RSA/ECC/SM2 均可）；国密 GB/T 35275-2017（GM.sm2cms.detached，仅 SM2）；国密 GB/T 38540-2020（GM.sm2seal，仅 SM2，需签章图片）；国密 GM/T 0031-2025（GM.sm2seal，仅 SM2，需签章图片）。</div>
                  <div class="row">
                    <div><label>签章图片（png/jpg/bmp/gif）</label><input type="file" id="sgPdfImage" accept="image/png,image/jpeg,image/bmp,image/gif"></div>
                    <div><label>签名证书（留空 = 仅文档时间戳）</label><select id="sgPdfCert" title="鼠标悬停查看证书简介（留空=纯文档时间戳，不签名）"><option value="">（不签名，仅文档时间戳）</option></select></div>
                    <div><label>签章类型</label><select id="sgPdfSeal">
                      <option value="ADOBE" selected>Adobe 标准文档签名</option>
                      <option value="GM35275">国密 GB/T 35275-2017</option>
                      <option value="GM38540">国密 GB/T 38540-2020</option>
                      <option value="GM0031">国密 GM/T 0031-2025</option>
                    </select></div>
                    <div style="grid-column:1/3"><label>时间戳请求地址（留空 = 本机 MAIN）</label>
                      <input id="sgPdfTsUrl" list="tsUrlListPdf" placeholder="http://timestamp.digicert.com" spellcheck="false">
                      <datalist id="tsUrlListPdf">
                        <option value="http://timestamp.digicert.com">
                        <option value="http://sha256timestamp.ws.symantec.com/sha256/">
                        <option value="http://timestamp.comodoca.com">
                        <option value="http://time.certum.pl">
                      </datalist>
                    </div>
                  </div>
                  <div class="dropzone" id="pdfDrop">
                    <div style="font-size:16px;font-weight:700;color:var(--text)">拖拽 PDF 文件到此处</div>
                    <div style="margin-top:6px;color:var(--dim)">或点击下方按钮选择文件（可多选）</div>
                    <label class="fake-btn" style="margin-top:12px">选择 PDF 文件<input type="file" id="sgPdfFile" multiple accept=".pdf,application/pdf" hidden></label>
                  </div>
                  <div class="pdf-list-head">
                    <span style="font-weight:700">待签名列表（<b id="pdfCount" style="color:var(--accent)">0</b> 个）</span>
                    <button onclick="pdfSignAll()">批量签名</button>
                    <button class="ghost" onclick="pdfVerifyAll()">批量验证</button>
                    <button class="ghost" onclick="pdfClear()">清空</button>
                  </div>
                  <div id="pdfList" class="pdf-list"></div>
                  <pre class="out" id="sgPdfOut" style="max-height:30vh;overflow:auto;white-space:pre;font-family:var(--mono);font-size:12px;line-height:1.55"></pre>
                </div>
              </div>
            </div>


<style>
.ctx-menu{position:fixed;z-index:99999;background:var(--panel2);border:1px solid var(--border);border-radius:8px;box-shadow:0 8px 28px rgba(0,0,0,.45);padding:6px;min-width:224px;user-select:none;font-size:13px}
.ctx-item{padding:8px 12px;border-radius:6px;cursor:pointer;white-space:nowrap;position:relative;color:var(--text)}
.ctx-item:hover{background:var(--accent);color:#0b1120}
.ctx-item.disabled{color:var(--dim);cursor:not-allowed;pointer-events:none;background:transparent}
.ctx-item.has-sub .ctx-sub{display:none;position:absolute;left:100%;top:0;background:var(--panel2);border:1px solid var(--border);border-radius:8px;box-shadow:0 8px 28px rgba(0,0,0,.45);padding:6px 6px 6px 8px;min-width:290px;z-index:99998}
.ctx-item.has-sub .ctx-sub.ctx-sub-up{top:auto;bottom:0}
.ctx-sub .ctx-item{font-size:12px}
</style>
<!-- 证书库右键菜单：下载证书 / 导出证书 -->
<div id="ctxMenu" class="ctx-menu" style="display:none">
  <div class="ctx-item has-sub"><span>下载证书</span>
    <div class="ctx-sub">
      <div class="ctx-item" onclick="ctxDownload('single_crt')">下载单证书(END.crt)</div>
      <div class="ctx-item" onclick="ctxDownload('chain_crt')">下载组合证书链(END+CA+ROOT.crt)</div>
      <div class="ctx-item" onclick="ctxDownload('p7b')">下载组合证书链(END+CA+ROOT.p7b)</div>
      <div class="ctx-item" onclick="ctxDownload('issuer_crt')">下载颁发者证书链(CA+ROOT.crt)</div>
      <div class="ctx-item" data-needkey onclick="ctxDownload('key')">下载私钥(END.key)</div>
      <div class="ctx-item" data-needkey onclick="ctxDownload('pfx',1)">下载证书+私钥(.pfx)</div>
      <div class="ctx-item" data-needkey onclick="ctxDownload('jks',1)">下载证书+私钥(.jks)</div>
    </div>
  </div>
  <div class="ctx-item has-sub"><span>导出证书</span>
    <div class="ctx-sub">
      <div class="ctx-item" onclick="ctxExport('cert_pem')">导出单证书到剪辑板(PEM)</div>
      <div class="ctx-item" onclick="ctxExport('chain_pem')">导出证书链到剪辑板(PEM：END+CA+ROOT)</div>
      <div class="ctx-item" onclick="ctxExport('issuer_pem')">PEM颁发者证书链到剪辑板(PEM：CA+ROOT)</div>
      <div class="ctx-item" data-needkey onclick="ctxExport('key_pem')">导出私钥到剪辑板(PEM)</div>
      <div class="ctx-item" data-needkey onclick="ctxExport('key_hex')">导出私钥到剪辑板(HEX)</div>
      <div class="ctx-item" data-needkey onclick="ctxExport('key_b64')">导出私钥到剪辑板(Base64)</div>
    </div>
  </div>
  <div class="ctx-item" data-ctxsrc="certs" onclick="ctxDeleteCert()" style="color:#dc2626;font-weight:700">删除证书</div>
</div>
<!-- 证书库右键下载 pfx/jks：密码输入 -->
<div class="modal-mask" id="ctxPwdModal" style="display:none" onclick="if(event.target===this)closeCtxPwd()">
  <div class="modal" style="width:min(460px,92vw)">
    <div class="modal-head">
      <h3>输入密钥库密码</h3>
      <button class="ghost" onclick="closeCtxPwd()">取消</button>
    </div>
    <div class="modal-body">
      <p class="cfg-hint" id="ctxPwdFile" style="margin-bottom:10px"></p>
      <label>密码</label>
      <input type="password" id="ctxPwd" placeholder="请输入导出密钥库的密码（pfx / jks）" onkeydown="if(event.key==='Enter')ctxPwdOk()">
    </div>
    <div class="modal-foot">
      <button onclick="ctxPwdOk()">确定</button>
      <button class="ghost" onclick="closeCtxPwd()">取消</button>
    </div>
  </div>
</div>
<!-- 证书库导出：浏览器剪贴板授权失败时的手动复制面板 -->
<div class="modal-mask" id="ctxCopyModal" style="display:none" onclick="if(event.target===this)closeCtxCopy()">
  <div class="modal" style="width:min(620px,94vw)">
    <div class="modal-head">
      <h3>复制到剪贴板</h3>
      <button class="ghost" onclick="closeCtxCopy()">取消</button>
    </div>
    <div class="modal-body">
      <p class="cfg-hint" style="margin-bottom:8px">浏览器未自动授权剪贴板写入，内容已预选，请点击下方"复制"按钮（或直接按 Ctrl+C）。</p>
      <textarea id="ctxCopyText" readonly spellcheck="false" style="width:100%;height:150px;box-sizing:border-box;font-family:var(--mono);font-size:11px;background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:8px;white-space:pre"></textarea>
    </div>
    <div class="modal-foot">
      <button onclick="ctxCopyTextarea()">复制</button>
      <button class="ghost" onclick="closeCtxCopy()">关闭</button>
    </div>
  </div>
</div>
<!-- 证书库 CERTS.txt：右键删除证书（注释行忽略）确认 -->
<div class="modal-mask" id="ctxDelModal" style="display:none" onclick="if(event.target===this)ctxDelCancel()">
  <div class="modal" style="width:min(460px,92vw)">
    <div class="modal-head"><h3>删除证书</h3><button class="ghost" onclick="ctxDelCancel()">取消</button></div>
    <div class="modal-body">
      <p class="cfg-hint" style="margin-bottom:6px">是否删除选中当前行序列号为 <b id="ctxDelSerial" style="color:#dc2626"></b> 的证书？</p>
      <p class="cfg-hint">确定后将在 CERTS.txt 中为该行添加 # 注释（代表忽略此行数据），生成 CRL / OCSP 证书时将自动跳过。</p>
    </div>
    <div class="modal-foot">
      <button onclick="ctxDelOk()">确定</button>
      <button class="ghost" onclick="ctxDelCancel()">取消</button>
    </div>
  </div>
</div>
    """;
    private static final String PAGE_P1B = """
            <!-- 初始化环境 -->
            <div class="page" id="page-init">
              <div class="card">
                <h2>初始化环境（Admin init）</h2>
                <div class="hint">注意：会备份现有 CERTS.txt 为 .old.时间戳，然后写入模板、签发根证书、全量 OCSP 与时间戳证书。仅在全新环境或确认无业务数据时执行。</div>
                <div class="row">
                  <div style="grid-column:1/-1"><label>根证书 DN</label><input id="inDn" placeholder="根证书 DN（key=value 逗号分隔，key 可为标准属性或 OID），如 CN=My Root CA,O=My Org,C=CN"></div>
                  <div><label>密钥算法</label><select id="inAlgo" onchange="extAlgoChanged('in')"><option>RSA</option><option>RSA-PSS</option><option>ECC</option><option>SM2</option><option>DSA</option><option>EdDSA</option><option>PQC</option></select></div>
                  <div><label>哈希算法</label><select id="inHash"><option>sha256</option><option>sha1</option><option>sha384</option><option>sha512</option><option>SHA3-224</option><option>SHA3-256</option><option>SHA3-384</option><option>SHA3-512</option><option>SM3</option><option>NULL</option></select></div>
                  <div><label>密钥位数</label><select id="inBits"></select></div>
                </div>
                <div class="fsec" style="margin-top:14px">
                  <div class="fsec-title">DN 辅助编辑 — 基础字段 / EV 注册字段 / 自定义 OID</div>
                  <div class="row">
                    <div><label>CN 通用名称</label><input id="inDnCn" placeholder="通用名称（CN），如 My Root CA" oninput="syncDn('in')"></div>
                    <div><label>O 组织</label><input id="inDnO" placeholder="组织（O），如 My Org" oninput="syncDn('in')"></div>
                    <div><label>OU 组织单位</label><input id="inDnOu" placeholder="组织单位（OU），如 IT Dept（可选）" oninput="syncDn('in')"></div>
                    <div><label>C 国家</label><input id="inDnC" placeholder="国家代码（C），如 CN（两位）" maxlength="2" oninput="syncDn('in')"></div>
                    <div><label>S 省/州</label><input id="inDnS" placeholder="省/州（S），如 Guangdong（可选）" oninput="syncDn('in')"></div>
                    <div><label>L 城市</label><input id="inDnL" placeholder="城市（L），如 Shenzhen（可选）" oninput="syncDn('in')"></div>
                    <div><label>E 邮箱（OID 字段）</label><input id="inDnE" placeholder="邮箱（E，OID 1.2.840.113549.1.9.1），如 admin@example.com" oninput="syncDn('in')"></div>
                    <div><label>是否 EV 扩展验证</label>
                      <label style="display:flex;justify-content:flex-start;align-items:center;width:100%;height:32px;cursor:pointer;margin:0"><input type="checkbox" id="inDnEvToggle" onchange="toggleDnEv('in')" style="margin:0;flex:none"></label>
                    </div>
                  </div>
                  <div id="inDnEvFields" style="margin-top:14px;display:none">
                    <div class="fsec-title" style="font-size:12px;margin-bottom:8px">EV 注册字段（EV Guidelines 专属 OID；注册类型四选一，注册号填营业执照/统一社会信用代码）</div>
                    <div class="row">
                      <div><label>注册类型（businessCategory 2.5.4.15）</label>
                        <select id="inDnBc" onchange="syncDn('in')">
                          <option value="">（不填）</option>
                          <option>Private Organization</option>
                          <option>Government Entity</option>
                          <option>Business Entity</option>
                          <option>Non-Commercial Entity</option>
                        </select>
                      </div>
                      <div><label>注册号（serialNumber 2.5.4.5）</label><input id="inDnReg" placeholder="注册号（serialNumber 2.5.4.5），如 91310000MA5XXXXXXXX" oninput="syncDn('in')"></div>
                      <div><label>注册国家（jurisdictionCountry）</label><input id="inDnJc" placeholder="注册国家（jurisdictionCountry），如 CN（两位）" maxlength="2" oninput="syncDn('in')"></div>
                      <div><label>注册省（jurisdictionStateOrProvince）</label><input id="inDnJs" placeholder="注册省（jurisdictionStateOrProvince），如 Guangdong（可选）" oninput="syncDn('in')"></div>
                      <div><label>注册市（jurisdictionLocality）</label><input id="inDnJl" placeholder="注册市（jurisdictionLocality），如 Shenzhen（可选）" oninput="syncDn('in')"></div>
                      <div><label>注册地址（streetAddress 2.5.4.9）</label><input id="inDnAddr" placeholder="注册地址（streetAddress 2.5.4.9），如 No.1 Beijing Road（可选）" oninput="syncDn('in')"></div>
                      <div><label>组织标识符（2.5.4.97）</label><input id="inDnOi" placeholder="组织标识符（2.5.4.97），如 NTRCN-91310000MA5XXXXXXXX" oninput="syncDn('in')"></div>
                      <div><label>组织标识符扩展 OID 版本</label>
                        <label style="display:flex;justify-content:flex-start;align-items:center;width:100%;height:32px;cursor:pointer;margin:0" title="未勾选=旧版 1.3.6.1.4.1.57264.1.8（SC27-2019）；勾选=新版 2.23.140.3.1（EVG 2.0.1）"><input type="checkbox" id="inDnOidNew" style="margin:0;flex:none"></label>
                      </div>
                    </div>
                  </div>
                  <div style="margin-top:12px">
                    <div class="fsec-title" style="font-size:12px;margin-bottom:8px">自定义字段（key 可写字段名或对象标识符 OID，如 2.5.4.42=张三、2.23.140.1.1=EV）</div>
                    <div id="inDnOidRows"></div>
                    <button type="button" class="ghost" onclick="addDnRow('in','','')">+ 添加自定义字段</button>
                  </div>
                  <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                    <button type="button" class="ghost" onclick="parseDn('in')">从上方 DN 解析回填</button>
                  </div>
                </div>
                <div style="margin-top:16px"><button class="danger" onclick="postForm('/api/init', {dn:v('inDn'),bits:extBitsVal('in'),hash:v('inHash'),algo:v('inAlgo')}, 'inOut')">执行初始化</button></div>
                <pre class="out" id="inOut"></pre>
              </div>
            </div>

            <!-- 用户管理（RADIUS 账号库） -->
            <div class="page" id="page-users">
              <div class="card">
                <div class="toolbar">
                  <h2 style="margin:0">用户管理</h2>
                  <span style="color:var(--dim);font-size:12px">文件：PKI/USERS.txt（RADIUS 账号库）</span>
                  <button onclick="openUserModal()">+ 添加用户</button>
                  <button class="ghost" onclick="loadUsers()">刷新</button>
                </div>
                <div class="hint">RADIUS 认证账号（PAP / CHAP / MS-CHAPv2 / EAP 共用）。明文存储遵循项目约定；状态 E=启用、D=停用；删除 = 行首加 # 注释（保留原行，与 CERTS.txt 惯例一致）。</div>
                <table class="tbl" id="userTable">
                  <thead><tr><th style="width:50px">序号</th><th style="width:150px">用户名</th><th style="width:130px">密码</th><th style="width:70px">状态</th><th style="width:110px">组</th><th>备注</th><th style="width:220px">操作</th></tr></thead>
                  <tbody></tbody>
                </table>
                <pre class="out" id="userOut"></pre>
              </div>
            </div>

            <!-- 用户添加 / 编辑弹窗 -->
            <div class="modal-mask" id="userModal" style="display:none" onclick="if(event.target===this)closeUserModal()">
              <div class="modal" style="width:min(620px,92vw)">
                <div class="modal-head"><h3 id="userModalTitle">添加用户</h3><button class="ghost" onclick="closeUserModal()">✕</button></div>
                <div class="modal-body">
                  <div class="row">
                    <div><label>用户名</label><input id="uName" placeholder="例如 alice" spellcheck="false"></div>
                    <div><label>密码</label><input id="uPass" placeholder="RADIUS 明文密码" spellcheck="false"></div>
                    <div><label>状态</label><select id="uState"><option value="E">启用</option><option value="D">停用</option></select></div>
                  </div>
                  <div class="row">
                    <div><label>组</label><input id="uGroup" placeholder="users / admin" spellcheck="false"></div>
                    <div style="flex:2"><label>备注</label><input id="uNote" placeholder="例如 测试账号" spellcheck="false"></div>
                  </div>
                  <pre class="out" id="uOut" hidden></pre>
                </div>
                <div class="modal-foot">
                  <button class="ghost" onclick="closeUserModal()">取消</button>
                  <button onclick="saveUser()">确定</button>
                </div>
              </div>
            </div>

            <!-- 用户删除确认弹窗 -->
            <div class="modal-mask" id="delUserModal" style="display:none" onclick="if(event.target===this)closeDelUserModal()">
              <div class="modal" style="width:min(440px,92vw)">
                <div class="modal-head"><h3>确认删除用户</h3><button class="ghost" onclick="closeDelUserModal()">✕</button></div>
                <div class="modal-body" id="delUserMsg" style="color:var(--text)"></div>
                <div class="modal-foot">
                  <button class="ghost" onclick="closeDelUserModal()">取消</button>
                  <button class="danger" onclick="doDelUser()">确定删除</button>
                </div>
              </div>
            </div>

            <!-- Radius 服务管理 -->
            <div class="page" id="page-radius">
              <div class="card">
                <div class="toolbar">
                  <h2 style="margin:0">Radius 服务管理</h2>
                  <span id="radState" class="badge err">● 未运行</span>
                  <button onclick="radiusStart()">启动服务</button>
                  <button class="ghost" onclick="radiusStop()">停止服务</button>
                  <button class="ghost" onclick="radiusReset()">统计清零</button>
                  <button class="ghost" onclick="loadRadius()">刷新</button>
                </div>
                <div class="hint">RADIUS 认证 / 计费服务（RFC 2138/2139/2284/2865/2866/2867/2868/2869）。认证端口 UDP/1812、计费端口 UDP/1813，共享密钥用于包 Authenticator 校验与属性加解密。认证方法：PAP / CHAP / MS-CHAPv2 与 EAP（Identity / MD5 / MSCHAPv2，TLS 预留）；适用于 PPP / PPPoE / PPTP / VPN / VoIP / ADSL / Cable Modem / CDMA / GSM / GPRS / WEB / WAP / WLAN 等 NAS 接入。账号管理在 <b>用户管理</b> 页面（PKI/USERS.txt）。</div>
                <div class="sig-tabs" id="radTabs">
                  <button class="sig-tab active" data-tab="server" onclick="radTab('server')">服务管理</button>
                  <button class="sig-tab" data-tab="client" onclick="radTab('client')">客户端-调试专区</button>
                </div>
                <!-- 服务管理 -->
                <div id="radServer">
                  <div class="row" style="margin-top:4px">
                    <div><label>认证端口（UDP）</label><input id="radAuthPort" placeholder="1812" spellcheck="false"></div>
                    <div><label>计费端口（UDP）</label><input id="radAcctPort" placeholder="1813" spellcheck="false"></div>
                    <div><label>共享密钥</label><input id="radSecret" placeholder="mytestkey" spellcheck="false"></div>
                    <div style="align-self:end"><label style="display:flex;align-items:center;gap:6px;white-space:nowrap"><input type="checkbox" id="radAuto" style="width:auto"> MAIN 启动时自动开启</label></div>
                    <div style="align-self:end"><button class="ghost" onclick="radiusSaveCfg()">保存配置</button></div>
                  </div>
                  <div class="row" style="margin-top:10px;flex-wrap:wrap;gap:8px 18px">
                    <span style="color:var(--dim);white-space:nowrap">账号数: <b id="radAccounts" style="color:var(--text)">0</b></span>
                    <span style="color:var(--dim);white-space:nowrap">认证请求: <b id="radReq" style="color:var(--text)">0</b></span>
                    <span style="color:var(--dim);white-space:nowrap">认证通过: <b id="radOk" style="color:var(--ok)">0</b></span>
                    <span style="color:var(--dim);white-space:nowrap">认证拒绝: <b id="radFail" style="color:var(--err)">0</b></span>
                    <span style="color:var(--dim);white-space:nowrap">计费请求: <b id="radAcct" style="color:var(--text)">0</b></span>
                    <span style="color:var(--dim);white-space:nowrap">启动时间: <b id="radStart" style="color:var(--text)">-</b></span>
                  </div>
                  <pre class="out" id="radOut" style="margin-top:10px"></pre>
                  <div class="card" style="margin-top:16px">
                    <div class="toolbar">
                      <h2 style="margin:0">服务日志</h2>
                      <span style="color:var(--dim);font-size:12px">WinRadius 风格，最近 500 条</span>
                      <button class="ghost" onclick="loadRadiusLogs()">刷新日志</button>
                      <button class="ghost danger" onclick="radiusClearLogs()">清空日志</button>
                      <label style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--dim)"><input type="checkbox" id="radAutoRefresh" checked style="width:auto" onchange="radAutoRefreshToggle()"> 自动刷新</label>
                    </div>
                    <table class="tbl" id="radLogTable">
                      <thead><tr><th style="width:60px">ID</th><th style="width:180px">时间</th><th>消息</th></tr></thead>
                      <tbody></tbody>
                    </table>
                  </div>
                </div>
                <!-- 客户端-调试专区 -->
                <div id="radClient" style="display:none">
                  <div class="hint" style="margin-top:12px">RADIUS 客户端认证模拟：按 RFC 2865/2759/3748 构造 Access-Request 并解析响应（响应 Authenticator 独立核验）。账号必须已存在于用户管理（PKI/USERS.txt），例如 admin666 / admin666；共享密钥必须与服务端一致。</div>
                  <div class="row" style="margin-top:10px">
                    <div><label>认证方式</label><select id="radMethod"><option>PAP</option><option>CHAP</option><option>MS-CHAPv1</option><option>MS-CHAPv2</option><option>EAP-MD5</option><option>EAP-GTC</option><option>EAP-MSCHAPv2</option><option>EAP-TLS</option><option>EAP-TTLS</option><option>PEAP-MD5</option><option>PEAP-MSCHAPv2</option><option>PEAP-GTC</option><option>EAP-pwd</option></select></div>
                    <div><label>客户端证书（TLS族可选）</label><select id="radCert"><option value="">（默认·匿名）</option></select></div>
                    <div><label>用户名</label><input id="radUser" placeholder="admin666" spellcheck="false"></div>
                    <div><label>密码</label><input id="radPass" type="password" placeholder="admin666" spellcheck="false"></div>
                    <div><label>共享密钥</label><input id="radDialSecret" placeholder="mytestkey" spellcheck="false"></div>
                    <div><label>认证端口（UDP）</label><input id="radDialPort" placeholder="1812" spellcheck="false"></div>
                    <div style="align-self:end"><button onclick="radClientDial()">发起调试</button></div>
                  </div>
                  <pre class="out" id="radDialOut" style="margin-top:10px"></pre>
                </div>
              </div>
            </div>

            <!-- PPPoE 服务管理 -->
            <div class="page" id="page-pppoe">
              <div class="card">
                <div class="toolbar">
                  <h2 style="margin:0">PPPoE 服务管理</h2>
                  <span id="pppoeState" class="badge err">● 未运行</span>
                  <button onclick="pppoeStart()">启动服务</button>
                  <button class="ghost" onclick="pppoeStop()">停止服务</button>
                  <button class="ghost" onclick="pppoeReset()">统计清零</button>
                  <button class="ghost" onclick="loadPppoe()">刷新</button>
                </div>
                <div class="hint">PPPoE（RFC 2516）以太网承载点对点协议。本实现为 UDP 封装模拟标准报文结构（Discovery/UDP 512，Session/UDP 513），覆盖 Discovery 阶段 PADI→PADO→PADR→PADS→PADT 与 Session 阶段 PPP LCP 协商及 PAP / CHAP 认证。认证账号复用 <b>用户管理</b>（PKI/USERS.txt），与 RADIUS 同库。客户端-调试专区提供完整拨号流程模拟，可自测闭环。</div>
                <div class="sig-tabs" id="pppoeTabs">
                  <button class="sig-tab active" data-tab="server" onclick="pppoeTab('server')">服务器管理</button>
                  <button class="sig-tab" data-tab="client" onclick="pppoeTab('client')">客户端-调试专区</button>
                </div>
                <div id="pppoeServer" class="tab-body">
                  <div class="row">
                    <div><label>Discovery 端口（UDP）</label><input id="pppoeDiscPort" placeholder="512" spellcheck="false"></div>
                    <div><label>Session 端口（UDP）</label><input id="pppoeSessPort" placeholder="513" spellcheck="false"></div>
                    <div style="align-self:end;display:flex;align-items:center;gap:6px;white-space:nowrap"><label style="display:flex;align-items:center;gap:6px"><input type="checkbox" id="pppoeAuto" style="width:auto"> MAIN 启动时自动开启</label></div>
                    <div style="align-self:end"><button class="ghost" onclick="pppoeSaveCfg()">保存配置</button></div>
                  </div>
                  <div class="row" style="margin-top:10px;flex-wrap:wrap;gap:8px 18px">
                    <span style="color:var(--dim);white-space:nowrap">账号数: <b id="pppoeAccounts" style="color:var(--text)">0</b></span>
                    <span style="color:var(--dim);white-space:nowrap">认证请求: <b id="pppoeReq" style="color:var(--text)">0</b></span>
                    <span style="color:var(--dim);white-space:nowrap">认证通过: <b id="pppoeOk" style="color:var(--ok)">0</b></span>
                    <span style="color:var(--dim);white-space:nowrap">认证拒绝: <b id="pppoeFail" style="color:var(--err)">0</b></span>
                    <span style="color:var(--dim);white-space:nowrap">活动会话: <b id="pppoeSess" style="color:var(--text)">0</b></span>
                    <span style="color:var(--dim);white-space:nowrap">AC 名称: <b id="pppoeAcName" style="color:var(--text)">-</b></span>
                    <span style="color:var(--dim);white-space:nowrap">启动时间: <b id="pppoeStart" style="color:var(--text)">-</b></span>
                  </div>
                  <pre class="out" id="pppoeOut" style="margin-top:10px"></pre>
                </div>
                <div id="pppoeClient" class="tab-body" style="display:none">
                  <div class="row">
                    <div><label>用户名</label><input id="pppoeUser" placeholder="admin666" spellcheck="false"></div>
                    <div><label>密码</label><input id="pppoePass" type="password" placeholder="输入密码" spellcheck="false"></div>
                    <div><label>认证方式</label><select id="pppoeMethod"><option value="PAP">PAP</option><option value="CHAP">CHAP</option></select></div>
                    <div style="align-self:end"><button onclick="pppoeDial()">发起拨号</button></div>
                  </div>
                  <div class="hint">模拟 PPPoE 客户端完整拨号流程：PADI → PADO → PADR → PADS → PPP LCP 协商 → PAP/CHAP 认证 → PADT 断开。认证账号必须已存在于用户管理（PKI/USERS.txt），例如 admin666 / admin666。</div>
                  <pre class="out" id="pppoeDialOut" style="margin-top:10px;height:340px"></pre>
                </div>
              </div>
              <div class="card" style="margin-top:16px">
                <div class="toolbar">
                  <h2 style="margin:0">服务器日志</h2>
                  <span style="color:var(--dim);font-size:12px">WinRadius 风格，最近 500 条</span>
                  <button class="ghost" onclick="loadPppoeLogs()">刷新日志</button>
                  <button class="ghost danger" onclick="pppoeClearLogs()">清空日志</button>
                  <label style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--dim)"><input type="checkbox" id="pppoeAutoRefresh" checked style="width:auto" onchange="pppoeAutoRefreshToggle()"> 自动刷新</label>
                </div>
                <table class="tbl" id="pppoeLogTable">
                  <thead><tr><th style="width:60px">ID</th><th style="width:180px">时间</th><th>消息</th></tr></thead>
                  <tbody></tbody>
                </table>
              </div>
            </div>

            <!-- 系统配置 -->
            <div class="page" id="page-config">
              <div class="card">
                <h2>系统配置（PKI/CONFIG.txt）</h2>
                <div class="toolbar">
                  <span style="color:var(--dim);font-size:12px" id="cfgState">读取中...</span>
                  <button class="ghost" onclick="loadConfig()">重新读取</button>
                </div>
                <div class="cfg-grid">
                  <div class="cfg-field">
                    <label>WEBPORT <span class="cfg-tag">Web 服务端口</span></label>
                    <input id="cfgWebport" placeholder="80" spellcheck="false">
                    <p class="cfg-hint">MAIN 服务监听端口，修改后需重启 MAIN 生效。</p>
                  </div>
                  <div class="cfg-field">
                    <label>SUPORT <span class="cfg-tag">管理界面端口</span></label>
                    <input id="cfgSuport" placeholder="8080" spellcheck="false">
                    <p class="cfg-hint">WebAdmin 管理界面监听端口（默认 8080），修改保存后需重启 WebAdmin 生效。</p>
                  </div>
                  <div class="cfg-field">
                    <label>OCSP <span class="cfg-tag">OCSP 响应器 URL</span></label>
                    <input id="cfgOcsp" placeholder="http://localhost:80/OCSP" spellcheck="false">
                    <p class="cfg-hint">写入证书 AuthorityInfoAccess 扩展的 OCSP 地址。</p>
                  </div>
                  <div class="cfg-field">
                    <label>CRL <span class="cfg-tag">CRL 分发点 URL</span></label>
                    <input id="cfgCrl" placeholder="http://localhost:80/CRL/{CID}.crl" spellcheck="false">
                    <p class="cfg-hint">支持 {CID} 变量（证书序列号），写入 CRL 分发点扩展。</p>
                  </div>
                  <div class="cfg-field">
                    <label>CRT <span class="cfg-tag">证书下载 URL</span></label>
                    <input id="cfgCrt" placeholder="http://localhost:80/CRT/{CID}.crt" spellcheck="false">
                    <p class="cfg-hint">caIssuers 地址，支持 {CID} 变量。</p>
                  </div>
                  <div class="cfg-field">
                    <label>CPS <span class="cfg-tag">证书策略 CPS URI</span></label>
                    <input id="cfgCps" placeholder="https://gitee.com/wxgshuju/modpkica" spellcheck="false">
                    <p class="cfg-hint">证书策略限定符指向的 CPS 链接。</p>
                  </div>
                  <div class="cfg-field">
                    <label>CTLOGapi <span class="cfg-tag">默认 ctlog 请求方式</span></label>
                    <select id="cfgCtlogApi" onchange="saveCtlogApi()">
                      <option value="/ct/add">/ct/add（PEM 预证书 + 颁发者）</option>
                      <option value="/ct/v1/add-chain">/ct/v1/add-chain（RFC 6962 正式证书链）</option>
                      <option value="/ct/v1/add-pre-chain">/ct/v1/add-pre-chain（RFC 6962 预证书链）</option>
                    </select>
                    <p class="cfg-hint">签发证书嵌入 SCT 时使用的 CT 日志提交接口；变更后实时写入 CONFIG.txt。</p>
                  </div>
                  <div class="cfg-field cfg-field-wide">
                    <label>CPS_Nonice <span class="cfg-tag">用户通告文本（支持多行）</span></label>
                    <textarea id="cfgCpsNonice" rows="5" spellcheck="false" placeholder="http://example.com/nonice"></textarea>
                    <p class="cfg-hint">多行输入；保存到 CONFIG.txt 时换行自动以 \\n 代替（单行存储）。</p>
                  </div>
                </div>
                <div style="margin-top:18px;display:flex;gap:10px;align-items:center">
                  <button onclick="saveConfigBtn(this)">保存配置</button>
                  <button class="ghost" onclick="loadConfig()">放弃修改</button>
                </div>
                <pre class="out" id="cfgOut" hidden></pre>
              </div>
            </div>

            <!-- 日志 -->
            <div class="page" id="page-logs">
              <div class="card">
                <h2>操作日志（PKI/logs.log）</h2>
                <div class="toolbar">
                  <span style="margin:0;color:var(--dim)">时间范围</span>
                  <button class="ghost" onclick="loadLogsHours(1)">最近1小时</button>
                  <button class="ghost" onclick="loadLogsHours(6)">最近6小时</button>
                  <button class="ghost" onclick="loadLogsHours(12)">最近12小时</button>
                  <button class="ghost" onclick="loadLogsHours(24)">最近24小时</button>
                  <button class="ghost" onclick="loadLogsHours(0)">全部</button>
                  <span style="margin:0 4px 0 12px;color:var(--dim)">行数</span>
                  <select id="logLines" onchange="loadLogs()"><option>100</option><option selected>200</option><option>500</option><option>1000</option></select>
                  <label style="margin:0"><input type="checkbox" id="logAuto" checked style="width:auto"> 自动刷新(3s)</label>
                  <button class="ghost" onclick="loadLogs()">手动刷新</button>
                </div>
                <pre class="out" id="logsOut" style="max-height:calc(100vh - 260px)"></pre>
              </div>
            </div>

          </section>
        </div>

        <!-- 证书 JSON 详情弹窗 -->
        <div class="modal-mask" id="modal" onclick="if(event.target===this)closeModal()">
          <div class="modal">
            <div class="modal-head">
              <h3 id="modalTitle">证书详情</h3>
              <div style="display:flex;gap:8px">
                <button class="ghost" onclick="viewChainCert()">查看证书</button>
                <button class="ghost" onclick="closeModal()">关闭</button>
              </div>
            </div>
            <div class="modal-body">
              <div id="modalMeta" style="color:var(--dim);font-size:12px;margin-bottom:10px"></div>
              <pre id="modalJson">加载中...</pre>
            </div>
          </div>
        </div>

        <!-- 证书操作弹窗：吊销证书 / 续签证书 / 密钥更换 -->
        <div class="modal-mask" id="opModal" style="display:none" onclick="if(event.target===this)closeOp()">
          <div class="modal" style="width:min(580px,92vw)">
            <div class="modal-head">
              <h3>证书操作</h3>
              <button class="ghost" onclick="closeOp()">关闭</button>
            </div>
            <div class="modal-body">
              <div class="op-tabs">
                <span class="op-tab active" id="opTabRevoke" onclick="switchOp('revoke')">吊销证书</span>
                <span class="op-tab" id="opTabRenew" onclick="switchOp('renew')">续签证书</span>
                <span class="op-tab" id="opTabKey" onclick="switchOp('key')">密钥更换</span>
              </div>
              <!-- 吊销证书 -->
              <div class="op-pane" id="opPaneRevoke">
                <label>证书序列号（可输入，也可从下拉中选择）</label>
                <input id="opSerial" list="opSerialList" placeholder="输入或选择证书序列号" oninput="opInfo()">
                <datalist id="opSerialList"></datalist>
                <div class="op-serial-info" id="opSerialInfo">未选择证书</div>
                <label>吊销理由</label>
                <select id="opReason"></select>
                <pre class="out" id="opOut" style="margin-top:14px"></pre>
              </div>
              <!-- 续签证书：保持公钥与扩展，仅更新生效/失效时间并 CA 重签 -->
              <div class="op-pane" id="opPaneRenew" style="display:none">
                <label>证书序列号（可输入，也可从下拉中选择）</label>
                <input id="renewSerial" list="opSerialList" placeholder="输入或选择证书序列号" oninput="renewInfo()">
                <div class="op-serial-info" id="renewInfoBox">未选择证书</div>
                <div style="display:flex;gap:12px;margin-top:12px">
                  <div style="flex:1">
                    <label>生效时间（本地时间）</label>
                    <input type="datetime-local" id="renewNotBefore" step="1">
                  </div>
                  <div style="flex:1">
                    <label>失效时间（本地时间）</label>
                    <input type="datetime-local" id="renewNotAfter" step="1">
                  </div>
                </div>
                <div id="renewTests" style="margin-top:10px;font-size:13px;line-height:1.9"></div>
                <pre class="out" id="renewOut" style="margin-top:14px"></pre>
              </div>
              <!-- 密钥更换：生成同类型新密钥对 → 测试 → CA 重签 → 替换旧文件 -->
              <div class="op-pane" id="opPaneKey" style="display:none">
                <label>证书序列号（可输入，也可从下拉中选择）</label>
                <input id="keySerial" list="opSerialList" placeholder="输入或选择证书序列号" oninput="keyInfo()">
                <div class="op-serial-info" id="keyInfoBox">未选择证书</div>
                <div id="keyTests" style="margin-top:10px;font-size:13px;line-height:1.9"></div>
                <pre class="out" id="keyOut" style="margin-top:14px"></pre>
              </div>
            </div>
            <div class="modal-foot" id="opFoot">
              <button class="danger" id="opFootRevoke" onclick="doOpRevoke()">确认吊销</button>
              <button class="success" id="opFootRestore" onclick="doOpRestore()" style="display:none">恢复证书</button>
              <button class="primary" id="opFootRenew" onclick="doOpRenew()" style="display:none">确认续签</button>
              <button class="primary" id="opFootKey" onclick="doOpKey()" style="display:none">确认密钥更换</button>
              <button class="ghost" onclick="closeOp()">取消</button>
            </div>
          </div>
        </div>

        <!-- 证书验证弹窗：按序列号调用 /api/verify -->
        <div class="modal-mask" id="verifyModal" style="display:none" onclick="if(event.target===this)closeVerifyModal()">
          <div class="modal">
            <div class="modal-head" id="verifyHead">
              <h3 id="verifyModalTitle">证书验证</h3>
              <span class="v-badge" id="verifyBadge" style="display:none">状态</span>
              <span class="v-text" id="verifyText"></span>
              <button class="ghost" onclick="closeVerifyModal()">关闭</button>
            </div>
            <div class="modal-body">
              <pre class="out" id="verifyModalOut">验证中...</pre>
            </div>
          </div>
        </div>

        <!-- 我的证书：导入密码输入弹窗 -->
        <div class="modal-mask" id="myPwdModal" style="display:none" onclick="if(event.target===this)closeMyPwd()">
          <div class="modal" style="width:min(460px,92vw)">
            <div class="modal-head">
              <h3 id="myPwdTitle">输入密钥库密码</h3>
              <button class="ghost" onclick="closeMyPwd()">取消</button>
            </div>
            <div class="modal-body">
              <p class="cfg-hint" id="myPwdFile" style="margin-bottom:10px"></p>
              <label>密码</label>
              <input type="password" id="myPwd" placeholder="请输入密钥库密码（pfx / p12 / jks）" onkeydown="if(event.key==='Enter')myPwdOk()">
            </div>
            <div class="modal-foot">
              <button onclick="myPwdOk()">确定</button>
              <button class="ghost" onclick="closeMyPwd()">取消</button>
            </div>
          </div>
        </div>

        <!-- 我的证书：删除确认弹窗 -->
        <div class="modal-mask" id="myDelModal" style="display:none" onclick="if(event.target===this)closeMyDel()">
          <div class="modal" style="width:min(440px,92vw)">
            <div class="modal-head">
              <h3>删除证书</h3>
              <button class="ghost" onclick="closeMyDel()">取消</button>
            </div>
            <div class="modal-body">
              <p id="myDelText" style="line-height:1.8"></p>
            </div>
            <div class="modal-foot">
              <button class="danger" onclick="myDoDelete()">确定</button>
              <button class="ghost" onclick="closeMyDel()">取消</button>
            </div>
          </div>
        </div>

        <!-- 有效期选择悬浮窗 -->
        <div class="modal-mask" id="valModal" style="display:none" onclick="if(event.target===this)closeValModal()">
          <div class="modal" style="width:min(460px,92vw)">
            <div class="modal-head">
              <h3>选择有效期（精确到秒）</h3>
              <button class="ghost" onclick="closeValModal()">取消</button>
            </div>
            <div class="modal-body">
              <div class="val-row"><label>起始时间</label><input type="datetime-local" id="valStart" step="1"></div>
              <div class="val-row"><label>截至时间</label><input type="datetime-local" id="valEnd" step="1"></div>
              <p class="cfg-hint">时间精确到秒；确定后以 起始T截至 格式写入有效期输入框（如 2026/09/12-10:30:00T2027/09/12-10:30:00），也可直接手输数字年数。</p>
            </div>
            <div class="modal-foot">
              <button onclick="valOk()">确定</button>
              <button class="ghost" onclick="closeValModal()">取消</button>
            </div>
          </div>
        </div>

        <!-- KeyUsage 密钥用法选择悬浮窗 -->
        <div class="modal-mask" id="kuModal" style="display:none;z-index:200" onclick="if(event.target===this)closeKuModal()">
          <div class="modal eku-modal">
            <div class="modal-head">
              <h3>选择密钥用法（KeyUsage</h3>
              <button class="ghost" onclick="closeKuModal()">取消</button>
            </div>
            <div class="eku-body" id="kuBody"></div>
            <div class="modal-foot">
              <button onclick="kuOk()">确定</button>
              <button class="ghost" onclick="closeKuModal()">取消</button>
            </div>
          </div>
        </div>

        <!-- EKU 增强型密钥用法选择悬浮窗 -->
        <div class="modal-mask" id="ekuModal" style="display:none;z-index:200" onclick="if(event.target===this)closeEkuModal()">
          <div class="modal eku-modal">
            <div class="modal-head">
              <h3>增强型密钥用法（EKU）选择</h3>
              <button class="ghost" onclick="closeEkuModal()">取消</button>
            </div>
            <div class="eku-body" id="ekuBody"></div>
            <div class="modal-foot">
              <button onclick="ekuOk()">确定</button>
              <button class="ghost" onclick="closeEkuModal()">取消</button>
            </div>
          </div>
        </div>

        <!-- 模板管理：添加/编辑模板 -->
        <div class="modal-mask" id="tpModal" style="display:none" onclick="if(event.target===this)closeTpModal()">
          <div class="modal" style="width:min(960px,94vw);max-height:88vh">
            <div class="modal-head">
              <h3 id="tpModalTitle">添加模板</h3>
              <button class="ghost" onclick="closeTpModal()">取消</button>
            </div>
            <div class="modal-body" style="overflow:auto">

              <div class="fsec"><div class="fsec-title">模板信息</div>
                <div class="row">
                  <div><label>模板名称（可选，便于识别）</label><input id="tpName" placeholder="例如：Web 服务器证书 / 代码签名证书"></div>
                </div>
              </div>

              <div class="fsec"><div class="fsec-title">主体信息</div>
                <div class="row">
                  <div style="grid-column:1/-1"><label>证书 DN（key=value 逗号分隔，key 可为标准属性或 OID）</label><input id="tpDn" placeholder="如 CN=www.test.com,O=My Org,C=CN"></div>
                </div>
              </div>

              <div class="fsec" style="margin-top:14px">
                <div class="fsec-title">DN 辅助编辑 — 基础字段 / EV 注册字段 / 自定义 OID</div>
                <div class="row">
                  <div><label>CN 通用名称</label><input id="tpDnCn" placeholder="通用名称（CN），如 www.test.com" oninput="syncDn('tp')"></div>
                  <div><label>O 组织</label><input id="tpDnO" placeholder="组织（O），如 My Org" oninput="syncDn('tp')"></div>
                  <div><label>OU 组织单位</label><input id="tpDnOu" placeholder="组织单位（OU），如 IT Dept（可选）" oninput="syncDn('tp')"></div>
                  <div><label>C 国家</label><input id="tpDnC" placeholder="国家代码（C），如 CN（两位）" maxlength="2" oninput="syncDn('tp')"></div>
                  <div><label>S 省/州</label><input id="tpDnS" placeholder="省/州（S），如 Guangdong（可选）" oninput="syncDn('tp')"></div>
                  <div><label>L 城市</label><input id="tpDnL" placeholder="城市（L），如 Shenzhen（可选）" oninput="syncDn('tp')"></div>
                  <div><label>E 邮箱（OID 字段）</label><input id="tpDnE" placeholder="邮箱（E，OID 1.2.840.113549.1.9.1）" oninput="syncDn('tp')"></div>
                  <div><label>是否 EV 扩展验证</label>
                    <label style="display:flex;justify-content:flex-start;align-items:center;width:100%;height:32px;cursor:pointer;margin:0"><input type="checkbox" id="tpDnEvToggle" onchange="toggleDnEv('tp')" style="margin:0;flex:none"></label>
                  </div>
                </div>
                <div id="tpDnEvFields" style="margin-top:14px;display:none">
                  <div class="fsec-title" style="font-size:12px;margin-bottom:8px">EV 注册字段（EV Guidelines 专属 OID；注册类型四选一，注册号填营业执照/统一社会信用代码）</div>
                  <div class="row">
                    <div><label>注册类型（businessCategory 2.5.4.15）</label>
                      <select id="tpDnBc" onchange="syncDn('tp')">
                        <option value="">（不填）</option>
                        <option>Private Organization</option>
                        <option>Government Entity</option>
                        <option>Business Entity</option>
                        <option>Non-Commercial Entity</option>
                      </select>
                    </div>
                    <div><label>注册号（serialNumber 2.5.4.5）</label><input id="tpDnReg" placeholder="注册号（serialNumber 2.5.4.5）" oninput="syncDn('tp')"></div>
                    <div><label>注册国家（jurisdictionCountry）</label><input id="tpDnJc" placeholder="注册国家（jurisdictionCountry），如 CN（两位）" maxlength="2" oninput="syncDn('tp')"></div>
                    <div><label>注册省（jurisdictionStateOrProvince）</label><input id="tpDnJs" placeholder="注册省（jurisdictionStateOrProvince）" oninput="syncDn('tp')"></div>
                    <div><label>注册市（jurisdictionLocality）</label><input id="tpDnJl" placeholder="注册市（jurisdictionLocality）" oninput="syncDn('tp')"></div>
                    <div><label>注册地址（streetAddress 2.5.4.9）</label><input id="tpDnAddr" placeholder="注册地址（streetAddress 2.5.4.9）" oninput="syncDn('tp')"></div>
                    <div><label>组织标识符（2.5.4.97）</label><input id="tpDnOi" placeholder="组织标识符（2.5.4.97）" oninput="syncDn('tp')"></div>
                    <div><label>组织标识符扩展 OID 版本</label>
                      <label style="display:flex;justify-content:flex-start;align-items:center;width:100%;height:32px;cursor:pointer;margin:0" title="未勾选=旧版 1.3.6.1.4.1.57264.1.8（SC27-2019）；勾选=新版 2.23.140.3.1（EVG 2.0.1）"><input type="checkbox" id="tpDnOidNew" style="margin:0;flex:none"></label>
                    </div>
                  </div>
                </div>
                <div style="margin-top:12px">
                  <div class="fsec-title" style="font-size:12px;margin-bottom:8px">自定义字段（key 可写字段名或对象标识符 OID）</div>
                  <div id="tpDnOidRows"></div>
                  <button type="button" class="ghost" onclick="addDnRow('tp','','')">+ 添加自定义字段</button>
                </div>
                <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                  <button type="button" class="ghost" onclick="parseDn('tp')">从上方 DN 解析回填</button>
                </div>
              </div>

              <div class="fsec"><div class="fsec-title">密钥与算法</div>
                <div class="row">
                  <div><label>证书类型</label><select id="tpCa" onchange="tpCaChanged()"><option value="0">终端证书</option><option value="1">中间 CA</option></select></div>
                  <div id="tpPathLenWrap" style="display:none"><label>路径长度</label><select id="tpPathLen" title="中间CA 的 BasicConstraints pathLenConstraint；null 表示不限制"><option value="">null</option><option>0</option><option>1</option><option>2</option><option>3</option><option>4</option><option>5</option><option>6</option><option>7</option><option>8</option><option>9</option></select></div>
                  <div><label>密钥算法</label><select id="tpAlgo" onchange="tpAlgoChanged()"><option>RSA</option><option>RSA-PSS</option><option>ECC</option><option>SM2</option><option>DSA</option><option>EdDSA</option><option>PQC</option></select></div>
                  <div><label>密钥位数</label><select id="tpBits"></select></div>
                  <div><label>哈希算法</label><select id="tpHash"><option>sha256</option><option>sha1</option><option>sha384</option><option>sha512</option><option>SHA3-224</option><option>SHA3-256</option><option>SHA3-384</option><option>SHA3-512</option><option>SM3</option><option>NULL</option></select></div>
                </div>
              </div>

              <div class="fsec"><div class="fsec-title">密钥用途</div>
                <div class="row">
                  <div><label>KeyUsage 编号</label>
                    <select id="tpKu" onchange="kuSelChanged('tp')">
                      <option value="">（无 KeyUsage 扩展）</option>
                      <option value="1">1 - 数字签名+不可否认+密钥加密+数据加密+密钥协商（通用）</option>
                      <option value="2">2 - 数字签名+不可否认+证书签名+CRL签名（CA用途）</option>
                      <option value="3">3 - 仅加密 Encipher Only</option>
                      <option value="4">4 - 仅解密 Decipher Only</option>
                      <option value="5">5 - 数字签名+不可否认（签名用途）</option>
                      <option value="6">6 - 数据加密 Data Encipherment</option>
                      <option value="7">7 - 密钥加密 Key Encipherment</option>
                      <option value="8">8 - 密钥协商 Key Agreement</option>
                      <option value="custom">自定义组合…（密钥用法选择器）</option>
                    </select>
                    <div style="display:flex;gap:6px;align-items:center;margin-top:6px">
                      <input id="tpKuCustom" placeholder="自定义数值：各位值相加，如 5=数字签名1+密钥加密4" style="display:none">
                      <button type="button" class="ghost" onclick="openKuModal('tp')" style="white-space:nowrap;flex:none">密钥用法…</button>
                    </div>
                  </div>
                  <div><label>EKU 编号/OID（逗号分隔）</label>
                    <div style="display:flex;gap:6px;align-items:center">
                      <input id="tpEu" value="1" onclick="openEkuModal('tp')" title="点击输入框或右侧按钮弹出 EKU 选择器">
                      <button type="button" class="ghost" onclick="openEkuModal('tp')" style="white-space:nowrap;flex:none">选择…</button>
                    </div>
                  </div>
                </div>
              </div>

              <div class="fsec" id="tpPolWrap" style="display:none"><div class="fsec-title">证书策略（仅终端证书，勾选的策略才写入证书策略扩展）</div>
                <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(235px,1fr));gap:8px 16px;padding-top:6px">
                  <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="tpPolDv"><span>SSL DV（2.23.140.1.2.1）</span></label>
                  <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="tpPolIv"><span>SSL IV（2.23.140.1.2.3）</span></label>
                  <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="tpPolOv"><span>SSL OV（2.23.140.1.2.2）</span></label>
                  <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="tpPolEv"><span>SSL EV（2.23.140.1.1）</span></label>
                  <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="tpPolCsStd"><span>代码签名-标准（2.23.140.1.4.1）</span></label>
                  <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="tpPolCsEv"><span>代码签名-EV（2.23.140.1.3）</span></label>
                  <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="tpPolDoc"><span>文档签名（1.3.6.1.5.5.7.3.36）</span></label>
                  <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="tpPolTsa"><span>TSA 策略（2.23.140.1.4.2）</span></label>
                </div>
                <div style="display:flex;gap:6px;align-items:center;padding-top:8px">
                  <input id="tpPolCustomOid" placeholder="自定义策略 OID，如 1.2.3.4.5" style="flex:1;min-width:220px" onkeydown="if(event.key==='Enter')addTpPolCustom()">
                  <button type="button" onclick="addTpPolCustom()">添加自定义策略</button>
                </div>
                <div id="tpPolCustomBox"></div>
              </div>

              <div class="fsec"><div class="fsec-title">有效期</div>
                <div class="row">
                  <div><label>有效期（年数或 起始T截至）</label><input id="tpDays" value="1" title="数字=年数；或格式 起始T截至，如 2026/09/12-10:30:00T2027/09/12-10:30:00"></div>
                </div>
              </div>

              <div class="fsec"><div class="fsec-title">SAN 扩展</div>
                <div class="row">
                  <div><label>SAN 域名（逗号分隔，无则 null）</label><input id="tpDns" value="null"></div>
                  <div><label>SAN IP（逗号分隔，无则 null）</label><input id="tpIps" value="null"></div>
                </div>
              </div>

              <pre class="out" id="tpSaveOut" style="margin-top:12px"></pre>

            </div>
            <div class="modal-foot">
              <button onclick="saveTemplate()">保存模板</button>
              <button class="ghost" onclick="closeTpModal()">取消</button>
            </div>
          </div>
        </div>

        <!-- 模板管理：签署模板（选择 R/C 颁发者） -->
        <div class="modal-mask" id="tpSignModal" style="display:none" onclick="if(event.target===this)closeSignModal()">
          <div class="modal" style="width:min(640px,94vw)">
            <div class="modal-head">
              <h3 id="tpSignTitle">签署模板</h3>
              <button class="ghost" onclick="closeSignModal()">取消</button>
            </div>
            <div class="modal-body">
              <div class="kv" id="tpSignInfo"></div>
              <div style="margin-top:10px"><label>颁发者证书（CERTS.txt 中 R/C 类型序列号）</label>
                <select id="tpSignIssuer" onchange="tpSignIssuerChanged()"></select>
              </div>
              <div id="tpSignTip" style="margin-top:10px;padding:10px;background:rgba(128,128,128,.07);border-radius:8px;font-size:12px;line-height:1.9"></div>
              <pre class="out" id="tpSignOut" style="margin-top:10px"></pre>
            </div>
            <div class="modal-foot">
              <button onclick="signDo()">确定签署</button>
              <button class="ghost" onclick="closeSignModal()">取消</button>
            </div>
          </div>
        </div>



            <!-- SCT 服务管理 -->
            <div class="page" id="page-ctlog">
              <style>
                #ctKeysTable, #ctLogsTable, #ctPubTable { table-layout: fixed; width: 100%; }
                #ctKeysTable th:nth-child(1) { width: 5%; }
                #ctKeysTable th:nth-child(2) { width: 18%; }
                #ctKeysTable th:nth-child(3) { width: 8%; }
                #ctKeysTable th:nth-child(4) { width: 32%; }
                #ctKeysTable th:nth-child(5) { width: 9%; }
                #ctKeysTable th:nth-child(6) { width: 15%; }
                #ctKeysTable th:nth-child(7) { width: 13%; }
                #ctLogsTable th:nth-child(1) { width: 6%; }
                #ctLogsTable th:nth-child(2) { width: 94%; }
                /* 鍗曞厓鏍奸暱鍐呭鐢?td > div 妯悜婊氬姩澶勭悊锛屼笉鎹㈣ */
                #ctKeysTable td > div, #ctLogsTable td > div, #ctPubTable td > div { overflow-x: auto; min-height: 1.4em; white-space: nowrap; }
                #ctPubTable th:nth-child(1) { width: 5%; }
                #ctPubTable th:nth-child(2) { width: 22%; }
                #ctPubTable th:nth-child(3) { width: 32%; }
                #ctPubTable th:nth-child(4) { width: 8%; }
                #ctPubTable th:nth-child(5) { width: 33%; }
                #ctKeysTable td:last-child > div { overflow: visible; white-space: nowrap; }
                .ct-tabs { display: flex; gap: 6px; margin-bottom: 12px; border-bottom: 2px solid var(--border); }
                .ct-tab { padding: 8px 18px; border: 1px solid var(--border); border-bottom: none; border-radius: 8px 8px 0 0; background: var(--panel); color: var(--text); cursor: pointer; font-size: 14px; font-weight: 600; }
                .ct-tab.active { background: #2563eb; color: #fff; }
                /* Merkle 树仪表盘（crt.sh 风格：等宽、信息优先、hover 高亮） */
                .ct-tree-stats { display: flex; gap: 14px; flex-wrap: wrap; margin: 10px 0; }
                .ct-tree-stat { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 8px 14px; min-width: 150px; }
                .ct-tree-stat b { display: block; font-size: 12px; color: var(--dim); font-weight: 600; margin-bottom: 3px; }
                .ct-tree-stat span { font-family: var(--mono); font-size: 13px; word-break: break-all; }
                #ctTreeView { font-family: var(--mono); font-size: 13px; line-height: 1.7; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 12px; overflow: auto; max-height: 46vh; }
                .ct-tree-line { white-space: nowrap; cursor: default; border-radius: 4px; padding: 1px 6px; }
                .ct-tree-line:hover { background: rgba(37,99,235,.10); }
                .ct-tree-node { color: #7c3aed; }
                .ct-tree-leaf { color: #0f766e; }
                .ct-tree-leaf .sn { color: #1d4ed8; font-weight: 700; }
                .ct-tree-leaf .dm { color: var(--dim); }
                #ctTreeDetail { font-family: var(--mono); font-size: 12px; color: var(--text); background: var(--panel2); border: 1px solid var(--border); border-left: 3px solid var(--accent); border-radius: 8px; padding: 10px 14px; margin-top: 8px; display: none; white-space: pre-wrap; word-break: break-all; }
                #v1Params label { display: inline-block; min-width: 110px; color: var(--dim); font-size: 13px; }
                #v1Params .v1-row { margin-bottom: 8px; }
                #v1Params input, #v1Params select { font-family: var(--mono); }
                #v1Params textarea { width: 100%; height: 120px; box-sizing: border-box; font-family: var(--mono); font-size: 12px; }
                #v1LogTable td { font-family: var(--mono); font-size: 12px; white-space: pre-wrap; word-break: break-all; }
              </style>
              <div class="card">
                <div class="ct-tabs">
                  <button class="ct-tab active" id="ctTabBtnKeys" onclick="ctSwitchTab('keys')">CT 日志密钥管理</button>
                  <button class="ct-tab" id="ctTabBtnLogs" onclick="ctSwitchTab('logs')">CT 请求日志</button>
                  <button class="ct-tab" id="ctTabBtnPub" onclick="ctSwitchTab('pub')">可信公网CT公钥管理</button>
                  <button class="ct-tab" id="ctTabBtnTree" onclick="ctSwitchTab('tree')">仪表盘</button>
                  <button class="ct-tab" id="ctTabBtnV1" onclick="ctSwitchTab('v1debug')">调试区</button>
                </div>
                <div id="ctPaneKeys">
                  <div class="hint">MAIN 服务 /ct/add 按 RFC 6962 标准对预证书签发 SCT。密钥库：PKI/CTLOG/modpkica_ct_list.json（支持 ECDSA-P256 / RSA-2048 / SM2-P256，结构参考 Google log_list v3；状态 usable=启用 / disable=暂停）。</div>
                  <div class="toolbar">
                    <input id="ctDesc" placeholder="密钥描述（可选），例如 MODPKICA CT Log 1" style="flex:1;max-width:340px">
                    <button onclick="genCtKey('ECDSA')">生成 ECDSA 密钥对</button>
                    <button onclick="genCtKey('RSA')">生成 RSA 密钥对</button>
                    <button onclick="genCtKey('SM2')">生成 SM2 密钥对</button>
                    <span id="ctMsg" style="margin-left:12px;font-size:12px"></span>
                    <button class="ghost" onclick="loadCtKeys()">刷新列表</button>
                  </div>
                  <div style="overflow:auto;max-height:52vh">
                    <table id="ctKeysTable">
                      <thead><tr><th>#</th><th>描述</th><th>类型</th><th>日志公钥 ID（log_id）</th><th>状态</th><th>创建时间</th><th>操作</th></tr></thead>
                      <tbody></tbody>
                    </table>
                  </div>
                </div>
                <div id="ctPaneLogs" style="display:none">
                  <div class="hint">每行格式：SCT待签名数据SHA256 || 签名毫秒时间戳 || 使用者SKI || 颁发者AKI || 日志公钥ID(base64)，只追加不删除。</div>
                  <div class="toolbar"><button class="ghost" onclick="loadCtLogs()">刷新日志</button></div>
                  <div style="overflow:auto;max-height:52vh">
                    <table id="ctLogsTable">
                      <thead><tr><th>序号</th><th>内容</th></tr></thead>
                      <tbody></tbody>
                    </table>
                  </div>
                </div>
                <div id="ctPanePub" style="display:none">
                  <div class="hint">可信公网 CT 日志公钥库：PKI/CTLOG/log_list.json（Google CT log list v3，来源 https://www.gstatic.com/ct/log_list/v3/log_list.json）。公网日志为只读参考数据，不支持启用/暂停/删除。</div>
                  <div class="toolbar">
                    <span style="font-size:13px;color:var(--dim)">数据日期：<span id="ctPubDate" style="font-family:var(--mono)">-</span></span>
                    <button onclick="fetchCtPub()">拉取最新数据</button>
                    <button class="ghost" onclick="loadCtPub()">刷新列表</button>
                    <span id="ctPubMsg" style="margin-left:12px;font-size:12px"></span>
                  </div>
                  <div style="overflow:auto;max-height:52vh">
                    <table id="ctPubTable">
                      <thead><tr><th>#</th><th>日志名称</th><th>日志公钥 ID（log_id）</th><th>状态</th><th>日志地址（url）</th></tr></thead>
                      <tbody></tbody>
                    </table>
                  </div>
                </div>
                <div id="ctPaneTree" style="display:none">
                  <div class="hint">Merkle 树仪表盘（参考 crt.sh 风格）：展示每个 CT 日志的树型图与全部节点信息。数据源 PKI/CTLOG/trees/{log_id hex}.json（JSON Lines 逐行追加，append-only）。节点含内部节点（MTH 子树哈希）与叶子（证书条目：索引/时间戳/类型/序列号/DN）。</div>
                  <div class="toolbar">
                    <select id="ctTreeSel" onchange="ctRenderTree()" style="max-width:430px"></select>
                    <button onclick="loadCtTree()">刷新</button>
                    <span id="ctTreeMsg" style="margin-left:12px;font-size:12px"></span>
                  </div>
                  <div id="ctTreeStats" class="ct-tree-stats"></div>
                  <div id="ctTreeView"></div>
                  <div id="ctTreeDetail"></div>
                </div>
                <div id="ctPaneV1Debug" style="display:none">
                  <div class="hint">调试区：可视化参数调试 RFC 6962 §4 的 /ct/v1/* 全部 8 个接口（add-chain / add-pre-chain / get-sth / get-roots / get-entries / get-proof-by-hash / get-sth-consistency / get-entry-and-proof）。请求实际转发到本机 MAIN 服务（CONFIG.txt WEBPORT），返回真实 HTTP 状态与响应体。</div>
                  <div class="toolbar">
                    <select id="v1ApiSel" onchange="v1ShowForm()" style="max-width:300px">
                      <option value="/ct/v1/add-chain">POST /ct/v1/add-chain</option>
                      <option value="/ct/v1/add-pre-chain">POST /ct/v1/add-pre-chain</option>
                      <option value="/ct/v1/get-sth">GET /ct/v1/get-sth</option>
                      <option value="/ct/v1/get-roots">GET /ct/v1/get-roots</option>
                      <option value="/ct/v1/get-entries">GET /ct/v1/get-entries</option>
                      <option value="/ct/v1/get-proof-by-hash">GET /ct/v1/get-proof-by-hash</option>
                      <option value="/ct/v1/get-sth-consistency">GET /ct/v1/get-sth-consistency</option>
                      <option value="/ct/v1/get-entry-and-proof">GET /ct/v1/get-entry-and-proof</option>
                    </select>
                    <button onclick="v1Send()">发送请求</button>
                    <button class="ghost" onclick="v1ClearLog()">清空日志</button>
                    <span id="v1Msg" style="margin-left:12px;font-size:12px"></span>
                  </div>
                  <div id="v1Params" style="margin:10px 0 4px 0"></div>
                  <div id="v1Resp" class="out" style="display:none;max-height:30vh;overflow:auto;white-space:pre-wrap;word-break:break-all;font-family:var(--mono);font-size:12px"></div>
                  <div style="margin-top:12px;font-size:13px;color:var(--dim);font-weight:600">请求日志（最近 20 条）</div>
                  <div style="overflow:auto;max-height:24vh">
                    <table id="v1LogTable">
                      <thead><tr><th style="width:6%">#</th><th style="width:94%">请求 / 响应</th></tr></thead>
                      <tbody></tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>
""";
    @SuppressWarnings("text-blocks")
    private static final String PAGE_P2 = """
        <script>
        // ===== 工具 =====
                window.addEventListener('error', function(e){ var d=document.getElementById('jsErr'); if(!d){ d=document.createElement('div'); d.id='jsErr'; d.style.cssText='position:fixed;bottom:10px;right:10px;background:#7f1d1d;color:#fecaca;padding:8px 12px;border-radius:8px;font-size:12px;z-index:99999;max-width:60vw;white-space:pre-wrap'; document.body.appendChild(d); } d.textContent='JS Error: '+(e.message||e); setTimeout(function(){d.remove()},8000); });
const $ = id => document.getElementById(id);
        const v = id => $(id).value.trim();
        const TITLES = { dashboard:'仪表盘', certs:'证书库', makeroot:'签发根证书', signcert:'签发证书', revoke:'吊销证书', ocsp:'OCSP|TSA签发', verify:'证书验证', template:'模板管理', ctlog:'SCT服务管理', sign:'签名专区', init:'初始化环境', users:'用户管理', radius:'Radius服务管理', config:'系统配置', logs:'操作日志' };

        async function api(path, body) {
          const opt = { method: body ? 'POST' : 'GET', headers: {} };
          if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
          const r = await fetch(path, opt);
          return r.json();
        }

        function showOut(id, text, ok) {
          const el = $(id);
          el.hidden = false;
          el.textContent = text || '(无输出)';
          el.className = 'out ' + (ok ? 'ok' : 'err');
        }

        // 证书验证：上传本地 cer/crt/pem 文件验证
        async function verifyFile() {
          const inp = $('vfFile');
          if (!inp.files || !inp.files.length) { showOut('vfOut', '请先选择证书文件（cer / crt / pem）', false); return; }
          const fd = new FormData();
          fd.append('file', inp.files[0]);
          showOut('vfOut', '验证中...', true);
          try {
            const resp = await fetch('/api/verify/file', { method: 'POST', body: fd });
            const j = await resp.json();
            if (j.ok) showOut('vfOut', j.message || '(无输出)', true);
            else showOut('vfOut', '验证失败: ' + (j.message || ''), false);
          } catch (e) { showOut('vfOut', '请求异常: ' + e, false); }
        }

        async function postForm(path, params, outId, btn) {
          const el = $(outId);
          el.hidden = false; el.className = 'out'; el.textContent = '执行中...';
          if (btn) btn.disabled = true;
          try {
            const r = await api(path, params);
            showOut(outId, r.message || 'OK', !!r.ok);
          } catch (e) {
            showOut(outId, '请求失败: ' + e, false);
          } finally {
            if (btn) btn.disabled = false;
          }
        }

        // ===== 签发根证书：DN 辅助编辑 =====
        // 基础字段映射 [输入框id, DN key]；输出顺序按 CA/B Forum 常见 subject DN 顺序（C,S,L,O,OU,CN,E）。
        // E 邮箱后端按 OID 1.2.840.113549.1.9.1 处理。
        // ===== 通用 DN 辅助编辑（mk 签发根证书 / sc 签发证书 / in 初始化环境 共用）=====
        // 基础字段 [后缀, DN key]，输出顺序 C,S,L,O,OU,CN,E；E 邮箱后端按 OID 1.2.840.113549.1.9.1 处理
        const DN_STD_PAT = [['C','C'],['S','S'],['L','L'],['O','O'],['Ou','OU'],['Cn','CN'],['E','1.2.840.113549.1.9.1']];
        const DN_EV_PAT = [['Reg','2.5.4.5'],['Bc','2.5.4.15'],
          ['Jc','1.3.6.1.4.1.311.60.2.1.3'],['Js','1.3.6.1.4.1.311.60.2.1.2'],['Jl','1.3.6.1.4.1.311.60.2.1.1'],
          ['Addr','2.5.4.9'],['Oi','2.5.4.97']];
        function dnF(p,n){ return p + 'Dn' + n; }
        function dnStd(p){ return DN_STD_PAT.map(function(x){ return [dnF(p,x[0]), x[1]]; }); }
        function dnEvFields(p){ return DN_EV_PAT.map(function(x){ return [dnF(p,x[0]), x[1]]; }); }
        function dnEvOn(p){ const el = $(dnF(p,'EvToggle')); return el && el.checked; }
        function syncDn(p) {
          const parts = [];
          const all = dnStd(p).concat(dnEvOn(p) ? dnEvFields(p) : []);
          all.forEach(function(pa){
            const el = $(pa[0]); if (!el) return;
            const val = el.value.trim();
            if (val) parts.push(pa[1] + '=' + val);
          });
          document.querySelectorAll('#' + p + 'DnOidRows .dn-oid-row').forEach(function(row){
            const k = row.querySelector('.dn-key').value.trim();
            const val = row.querySelector('.dn-val').value.trim();
            if (k && val) parts.push(k + '=' + val);
          });
          $(p + 'Dn').value = parts.join(',');
        }
        function toggleDnEv(p) {
          const on = dnEvOn(p);
          $(p + 'DnEvFields').style.display = on ? '' : 'none';
          syncDn(p);
        }
        function addDnRow(p, key, val) {
          const div = document.createElement('div');
          div.className = 'dn-oid-row';
          div.style.cssText = 'display:flex;gap:6px;margin-bottom:6px;align-items:center';
          const esc = s => String(s || '').replace(/"/g, '&quot;');
          div.innerHTML = '<input class="dn-key" placeholder="字段名或 OID（如 2.5.4.42）" style="flex:1.2;max-width:320px" value="' + esc(key) + '" oninput="syncDn(\\'' + p + '\\')">'
            + '<input class="dn-val" placeholder="值" style="flex:1.5" value="' + esc(val) + '" oninput="syncDn(\\'' + p + '\\')">'
            + '<button type="button" class="ghost" style="flex:none" onclick="this.parentNode.remove();syncDn(\\'' + p + '\\')">✕</button>';
          $(p + 'DnOidRows').appendChild(div);
        }
        function parseDn(p) {
          const dn = $(p + 'Dn').value.trim();
          if (!dn) return;
          $(p + 'DnOidRows').innerHTML = '';
          const all = dnStd(p).concat(dnEvFields(p));
          all.forEach(function(pa){ $(pa[0]).value = ''; });
          let evHit = false;
          dn.split(',').forEach(function(seg){
            seg = seg.trim(); if (!seg) return;
            const i = seg.indexOf('='); if (i < 0) return;
            const k = seg.slice(0, i).trim(), val = seg.slice(i + 1).trim();
            const hit = all.find(function(pa){ return pa[1].toUpperCase() === k.toUpperCase(); });
            if (hit) {
              $(hit[0]).value = val;
              if (dnEvFields(p).indexOf(hit) >= 0) evHit = true;
            } else addDnRow(p, k, val);
          });
          if (evHit) { $(dnF(p,'EvToggle')).checked = true; $(p + 'DnEvFields').style.display = ''; }
        }
        // mk 兼容包装（签发根证书原有函数名不变）
        function mkDnEvOn(){ return dnEvOn('mk'); }
        function syncMkDn(){ return syncDn('mk'); }
        function toggleMkDnEv(){ return toggleDnEv('mk'); }
        function addMkDnRow(k,v){ return addDnRow('mk',k,v); }
        function parseMkDn(){ return parseDn('mk'); }
        // 页面就绪：把各页默认 DN 拆分到辅助字段
        parseMkDn(); parseDn('sc'); parseDn('in');


        async function quickAction(path) {
          postForm(path, {}, 'dashOut');
        }

        // ===== 签名专区：微软代码签名 / PDF 文档签名 =====
        async function loadSignCerts() {
          try {
            const re = await api('/api/signcerts?kind=exe');
            const rp = await api('/api/signcerts?kind=pdf');
            fillSignSel($('sgExeCert'), (re.data || []).length ? re.data : null, 'exe');
            fillSignSel($('sgPdfCert'), (rp.data || []).length ? rp.data : null, 'pdf');
          } catch (e) {
            $('sgExeCert').innerHTML = '<option value="">（加载失败: ' + e + '）</option>';
            $('sgPdfCert').innerHTML = '<option value="">（加载失败: ' + e + '）</option>';
          }
        }
        function fillSignSel(sel, list, kind) {
          if (!list) {
            sel.innerHTML = kind === 'pdf'
              ? '<option value="">（不签名，仅文档时间戳）</option>'
              : '<option value="">（无可用证书）</option>';
            return;
          }
          const hint = kind === 'exe' ? '代码签名 EKU' : '文档签名 EKU';
          sel.innerHTML = kind === 'pdf'
            ? '<option value="">（不签名，仅文档时间戳）</option>'
            : '<option value="">（请选择 ' + hint + ' 证书）</option>';
          list.forEach(c => {
            const o = document.createElement('option');
            o.value = c.serial;
            o.textContent = (c.src === 'my' ? '〔我的〕 ' : '') + c.serial + ' ｜ ' + (c.algo || '') + (c.bits ? ' ' + c.bits : '') + ' ｜ ' + c.dn;
            o.title = '序列号: ' + c.serial + '\\n算法: ' + (c.algo || '') + (c.bits ? ' ' + c.bits + ' 位' : '') +
              '\\n颁发者: ' + (c.issuer || '') + '\\n有效期: ' + (c.validFrom || '') + ' ~ ' + (c.validTo || '') +
              '\\n状态: ' + (c.status === 'V' ? '正常' : c.status === 'R' ? '已吊销' : '未知') +
              '\\nEKU: ' + ((c.ekus || []).join(', ') || '（无）') +
              '\\nDN: ' + c.dn;
            sel.appendChild(o);
          });
        }
        // ===== 微软代码签名批量待签名队列（多选 + 拖拽） =====
        const exeJobs = [];
        function addExeFiles(files) {
          let added = 0;
          [...files].forEach(f => {
            if (!/\\.(exe|dll|sys|cab|cat|msi)$/i.test(f.name)) return;
            if (exeJobs.some(j => j.file.name === f.name && j.file.size === f.file.size)) return;
            exeJobs.push({ file: f, state: 'wait', msg: '待处理', b64: null, name: null });
            added++;
          });
          renderExeList();
          return added;
        }
        function renderExeList() {
          const box = $('exeList');
          box.innerHTML = '';
          exeJobs.forEach((j, i) => {
            const row = document.createElement('div');
            row.className = 'pdf-row';
            row.innerHTML = '<span class="nm" title="' + esc(j.file.name) + '">' + esc(j.file.name) + '（' + fmtSize(j.file.size) + '）</span>'
              + '<span class="st ' + (j.state === 'ok' ? 'ok' : j.state === 'err' ? 'err' : '') + '">' + esc(j.msg) + '</span>'
              + (j.state === 'ok' && j.b64 ? '<a class="dl" href="data:application/octet-stream;base64,' + j.b64 + '" download="' + esc(j.name) + '">⬇ 下载</a>' : '')
              + '<button onclick="exeSignOne(' + i + ')">签名</button>'
              + '<button class="ghost" onclick="exeVerifyOne(' + i + ')">验证</button>'
              + '<button class="ghost" onclick="exeRemove(' + i + ')">移除</button>';
            box.appendChild(row);
          });
          $('exeCount').textContent = exeJobs.length;
        }
        function exeRemove(i) { exeJobs.splice(i, 1); renderExeList(); }
        function exeClear() { exeJobs.length = 0; renderExeList(); $('sgExeOut').hidden = true; }
        function exeParams() {
          const fd = new FormData();
          fd.append('serial', $('sgExeCert').value);
          fd.append('tsType', $('sgExeTsType').value);
          fd.append('tsUrl', $('sgExeTsUrl').value);
          return fd;
        }
        function exePreCheck() {
          if (!$('sgExeCert').value) return '请先选择签名证书';
          return null;
        }
        async function exeSignOne(i) {
          const j = exeJobs[i];
          if (!j) return;
          const err = exePreCheck();
          if (err) { j.state = 'err'; j.msg = err; renderExeList(); return; }
          j.state = 'signing'; j.msg = '签名中...'; renderExeList();
          const fd = exeParams();
          fd.append('name', j.file.name);
          fd.append('file', j.file);
          try {
            const resp = await fetch('/api/sign/exe', { method: 'POST', body: fd });
            const r = await resp.json();
            j.state = r.ok ? 'ok' : 'err';
            j.msg = (r.ok ? '✓ 签名成功' : '✗ ' + (r.message || '失败')).substring(0, 120);
            j.b64 = r.ok ? (r.b64 || null) : null;
            j.name = r.ok ? (r.name || 'signed_' + j.file.name) : null;
            j.lastDetail = r.message || '';
          } catch (e) {
            j.state = 'err'; j.msg = '请求失败: ' + e; j.lastDetail = '';
          }
          renderExeList();
          $('sgExeOut').hidden = false;
          $('sgExeOut').className = 'out ' + (j.state === 'ok' ? 'ok' : 'err');
          $('sgExeOut').textContent = '[' + j.file.name + '] ' + (j.lastDetail || j.msg);
        }
        async function exeVerifyOne(i) {
          const j = exeJobs[i];
          if (!j) return;
          j.state = 'signing'; j.msg = '验证中...'; renderExeList();
          const fd = new FormData();
          fd.append('file', j.file);
          try {
            const resp = await fetch('/api/verify/exe', { method: 'POST', body: fd });
            const r = await resp.json();
            j.state = r.ok ? 'ok' : 'err';
            j.msg = (r.ok ? '✓ 验证完成' : '✗ 验证失败').substring(0, 120);
            j.lastDetail = r.message || '';
          } catch (e) {
            j.state = 'err'; j.msg = '请求失败: ' + e; j.lastDetail = '';
          }
          renderExeList();
          $('sgExeOut').hidden = false;
          $('sgExeOut').className = 'out ' + (j.state === 'ok' ? 'ok' : 'err');
          $('sgExeOut').textContent = '[' + j.file.name + '] ' + (j.lastDetail || j.msg);
        }
        async function exeSignAll() {
          const out = $('sgExeOut');
          if (!exeJobs.length) { out.hidden = false; out.className = 'out err'; out.textContent = '待签名列表为空，请先添加文件'; return; }
          let okN = 0, errN = 0; const lines = [];
          for (let i = 0; i < exeJobs.length; i++) {
            const j = exeJobs[i];
            const err = exePreCheck();
            if (err) { j.state = 'err'; j.msg = err; errN++; lines.push('✗ ' + j.file.name + ' → ' + err); renderExeList(); continue; }
            j.state = 'signing'; j.msg = '签名中...'; renderExeList();
            const fd = exeParams();
            fd.append('name', j.file.name);
            fd.append('file', j.file);
            try {
              const resp = await fetch('/api/sign/exe', { method: 'POST', body: fd });
              const r = await resp.json();
              j.state = r.ok ? 'ok' : 'err';
              j.msg = r.ok ? '✓ 签名成功' : ('✗ ' + (r.message || '失败')).substring(0, 100);
              j.b64 = r.ok ? (r.b64 || null) : null;
              j.name = r.ok ? (r.name || 'signed_' + j.file.name) : null;
              if (r.ok) okN++; else { errN++; lines.push('✗ ' + j.file.name + ' → ' + (r.message || '失败')); }
            } catch (e) {
              j.state = 'err'; j.msg = '请求失败: ' + e; errN++; lines.push('✗ ' + j.file.name + ' → ' + e);
            }
            renderExeList();
          }
          out.hidden = false;
          out.className = 'out ' + (errN ? 'err' : 'ok');
          out.textContent = '批量签名完成：成功 ' + okN + ' 个，失败 ' + errN + ' 个' + (lines.length ? '\\n' + lines.join('\\n') : '');
        }
        async function exeVerifyAll() {
          const out = $('sgExeOut');
          if (!exeJobs.length) { out.hidden = false; out.className = 'out err'; out.textContent = '待签名列表为空，请先添加文件'; return; }
          let okN = 0, errN = 0; const lines = [];
          for (let i = 0; i < exeJobs.length; i++) {
            const j = exeJobs[i];
            j.state = 'signing'; j.msg = '验证中...'; renderExeList();
            const fd = new FormData();
            fd.append('file', j.file);
            try {
              const resp = await fetch('/api/verify/exe', { method: 'POST', body: fd });
              const r = await resp.json();
              j.state = r.ok ? 'ok' : 'err';
              j.msg = r.ok ? '✓ 验证完成' : '✗ 验证失败';
              if (r.ok) okN++; else { errN++; lines.push('✗ ' + j.file.name + ' → ' + (r.message || '失败')); }
            } catch (e) {
              j.state = 'err'; j.msg = '请求失败: ' + e; errN++; lines.push('✗ ' + j.file.name + ' → ' + e);
            }
            renderExeList();
          }
          out.hidden = false;
          out.className = 'out ' + (errN ? 'err' : 'ok');
          out.textContent = '批量验证完成：成功 ' + okN + ' 个，失败 ' + errN + ' 个' + (lines.length ? '\\n' + lines.join('\\n') : '');
        }
        // 拖拽与多选初始化
        (function initExeDrop() {
          const dz = $('exeDrop');
          if (!dz) return;
          dz.ondragover = e => { e.preventDefault(); dz.classList.add('over'); };
          dz.ondragleave = () => dz.classList.remove('over');
          dz.ondrop = e => { e.preventDefault(); dz.classList.remove('over'); addExeFiles(e.dataTransfer.files); };
          const fi = $('sgExeFile');
          if (fi) fi.onchange = e => { addExeFiles(e.target.files); e.target.value = ''; };
        })();

        // ===== 签名专区：选择夹切换 =====
        function sigTab(name, btn) {
          ['exe', 'pdf'].forEach(n => {
            $('sigPane-' + n).style.display = n === name ? '' : 'none';
            $('sigTabBtn-' + n).classList.toggle('active', n === name);
          });
        }

        // ===== OCSP|TSA签发：分类夹切换（OCSP签发 / TSA签发 / 模拟请求调试） =====
        function ocspTab(t) {
          document.querySelectorAll('#ocspTabs .sig-tab').forEach(b => b.classList.toggle('active', b.getAttribute('data-tab') === t));
          $('ocspIssue').style.display = t === 'issue' ? '' : 'none';
          $('tsaIssue').style.display = t === 'tsaissue' ? '' : 'none';
          $('dbgOcsp').style.display = t === 'debugocsp' ? '' : 'none';
          $('dbgTsa').style.display = t === 'debugtsa' ? '' : 'none';
        }

        // ===== PDF 批量待签名队列（多选 + 拖拽） =====
        const pdfJobs = [];
        function addPdfFiles(files) {
          let added = 0;
          [...files].forEach(f => {
            if (!/\\.pdf$/i.test(f.name)) return;
            if (pdfJobs.some(j => j.file.name === f.name && j.file.size === f.file.size)) return;
            pdfJobs.push({ file: f, state: 'wait', msg: '待处理', b64: null, name: null });
            added++;
          });
          renderPdfList();
          return added;
        }
        function fmtSize(n) {
          return n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB';
        }
        function renderPdfList() {
          const box = $('pdfList');
          box.innerHTML = '';
          pdfJobs.forEach((j, i) => {
            const row = document.createElement('div');
            row.className = 'pdf-row';
            row.innerHTML = '<span class="nm" title="' + esc(j.file.name) + '">' + esc(j.file.name) + '（' + fmtSize(j.file.size) + '）</span>'
              + '<span class="st ' + (j.state === 'ok' ? 'ok' : j.state === 'err' ? 'err' : '') + '">' + esc(j.msg) + '</span>'
              + (j.state === 'ok' && j.b64 ? '<a class="dl" href="data:application/pdf;base64,' + j.b64 + '" download="' + esc(j.name) + '">⬇ 下载</a>' : '')
              + '<button onclick="pdfSignOne(' + i + ')">签名</button>'
              + '<button class="ghost" onclick="pdfVerifyOne(' + i + ')">验证</button>'
              + '<button class="ghost" onclick="pdfRemove(' + i + ')">移除</button>';
            box.appendChild(row);
          });
          $('pdfCount').textContent = pdfJobs.length;
        }
        function pdfRemove(i) { pdfJobs.splice(i, 1); renderPdfList(); }
        function pdfClear() { pdfJobs.length = 0; renderPdfList(); $('sgPdfOut').hidden = true; }
        function pdfParams() {
          const fd = new FormData();
          fd.append('serial', $('sgPdfCert').value);
          fd.append('sealType', $('sgPdfSeal').value);
          fd.append('tsUrl', $('sgPdfTsUrl').value);
          const img = $('sgPdfImage').files && $('sgPdfImage').files[0];
          if (img) fd.append('image', img);
          return fd;
        }
        function pdfPreCheck() {
          const serial = $('sgPdfCert').value;
          const seal = $('sgPdfSeal').value;
          if (!serial) {
            if (seal !== 'ADOBE') return '纯文档时间戳（不选证书）仅支持 Adobe 标准';
            if ($('sgPdfImage').files && $('sgPdfImage').files[0]) return '纯文档时间戳（不选证书）不能附加签章图片';
          }
          return null;
        }
        async function pdfSignOne(i) {
          const j = pdfJobs[i];
          if (!j) return;
          const err = pdfPreCheck();
          if (err) { j.state = 'err'; j.msg = err; renderPdfList(); return; }
          j.state = 'signing'; j.msg = '签名中...'; renderPdfList();
          const fd = pdfParams();
          fd.append('name', j.file.name);
          fd.append('file', j.file);
          try {
            const resp = await fetch('/api/sign/pdf', { method: 'POST', body: fd });
            const r = await resp.json();
            j.state = r.ok ? 'ok' : 'err';
            j.msg = (r.ok ? '✓ 签名成功' : '✗ ' + (r.message || '失败')).substring(0, 120);
            j.b64 = r.ok ? (r.b64 || null) : null;
            j.name = r.ok ? (r.name || 'signed_' + j.file.name) : null;
            j.lastDetail = r.message || '';
          } catch (e) {
            j.state = 'err'; j.msg = '请求失败: ' + e; j.lastDetail = '';
          }
          renderPdfList();
          $('sgPdfOut').hidden = false;
          $('sgPdfOut').className = 'out ' + (j.state === 'ok' ? 'ok' : 'err');
          $('sgPdfOut').textContent = '[' + j.file.name + '] ' + (j.lastDetail || j.msg);
        }
        async function pdfVerifyOne(i) {
          const j = pdfJobs[i];
          if (!j) return;
          j.state = 'signing'; j.msg = '验证中...'; renderPdfList();
          const fd = new FormData();
          fd.append('file', j.file);
          try {
            const resp = await fetch('/api/verify/pdf', { method: 'POST', body: fd });
            const r = await resp.json();
            j.state = r.ok ? 'ok' : 'err';
            j.msg = (r.ok ? '✓ 验证完成' : '✗ 验证失败').substring(0, 120);
            j.lastDetail = r.message || '';
          } catch (e) {
            j.state = 'err'; j.msg = '请求失败: ' + e; j.lastDetail = '';
          }
          renderPdfList();
          $('sgPdfOut').hidden = false;
          $('sgPdfOut').className = 'out ' + (j.state === 'ok' ? 'ok' : 'err');
          $('sgPdfOut').textContent = '[' + j.file.name + '] ' + (j.lastDetail || j.msg);
        }
        async function pdfSignAll() {
          const out = $('sgPdfOut');
          if (!pdfJobs.length) { out.hidden = false; out.className = 'out err'; out.textContent = '待签名列表为空，请先添加 PDF 文件'; return; }
          let okN = 0, errN = 0; const lines = [];
          for (let i = 0; i < pdfJobs.length; i++) {
            const j = pdfJobs[i];
            const err = pdfPreCheck();
            if (err) { j.state = 'err'; j.msg = err; errN++; lines.push('✗ ' + j.file.name + ' → ' + err); renderPdfList(); continue; }
            j.state = 'signing'; j.msg = '签名中...'; renderPdfList();
            const fd = pdfParams();
            fd.append('name', j.file.name);
            fd.append('file', j.file);
            try {
              const resp = await fetch('/api/sign/pdf', { method: 'POST', body: fd });
              const r = await resp.json();
              j.state = r.ok ? 'ok' : 'err';
              j.msg = r.ok ? '✓ 签名成功' : ('✗ ' + (r.message || '失败')).substring(0, 100);
              j.b64 = r.ok ? (r.b64 || null) : null;
              j.name = r.ok ? (r.name || 'signed_' + j.file.name) : null;
              if (r.ok) okN++; else { errN++; lines.push('✗ ' + j.file.name + ' → ' + (r.message || '失败')); }
            } catch (e) {
              j.state = 'err'; j.msg = '请求失败: ' + e; errN++; lines.push('✗ ' + j.file.name + ' → ' + e);
            }
            renderPdfList();
          }
          out.hidden = false;
          out.className = 'out ' + (errN ? 'err' : 'ok');
          out.textContent = '批量签名完成：成功 ' + okN + ' 个，失败 ' + errN + ' 个' + (lines.length ? '\\n' + lines.join('\\n') : '');
        }
        async function pdfVerifyAll() {
          const out = $('sgPdfOut');
          if (!pdfJobs.length) { out.hidden = false; out.className = 'out err'; out.textContent = '待签名列表为空，请先添加 PDF 文件'; return; }
          let okN = 0, errN = 0; const lines = [];
          for (let i = 0; i < pdfJobs.length; i++) {
            const j = pdfJobs[i];
            j.state = 'signing'; j.msg = '验证中...'; renderPdfList();
            const fd = new FormData();
            fd.append('file', j.file);
            try {
              const resp = await fetch('/api/verify/pdf', { method: 'POST', body: fd });
              const r = await resp.json();
              j.state = r.ok ? 'ok' : 'err';
              j.msg = r.ok ? '✓ 验证完成' : '✗ 验证失败';
              if (r.ok) okN++; else { errN++; lines.push('✗ ' + j.file.name + ' → ' + (r.message || '失败')); }
            } catch (e) {
              j.state = 'err'; j.msg = '请求失败: ' + e; errN++; lines.push('✗ ' + j.file.name + ' → ' + e);
            }
            renderPdfList();
          }
          out.hidden = false;
          out.className = 'out ' + (errN ? 'err' : 'ok');
          out.textContent = '批量验证完成：成功 ' + okN + ' 个，失败 ' + errN + ' 个' + (lines.length ? '\\n' + lines.join('\\n') : '');
        }
        // 拖拽与多选初始化
        (function initPdfDrop() {
          const dz = $('pdfDrop');
          if (!dz) return;
          dz.ondragover = e => { e.preventDefault(); dz.classList.add('over'); };
          dz.ondragleave = () => dz.classList.remove('over');
          dz.ondrop = e => { e.preventDefault(); dz.classList.remove('over'); addPdfFiles(e.dataTransfer.files); };
          const fi = $('sgPdfFile');
          if (fi) fi.onchange = e => { addPdfFiles(e.target.files); e.target.value = ''; };
        })();

        // ===== 页面切换 =====
        document.querySelectorAll('#nav a').forEach(a => {
          a.onclick = () => {
            document.querySelectorAll('#nav a').forEach(x => x.classList.remove('active'));
            document.querySelectorAll('.page').forEach(x => x.classList.remove('active'));
            a.classList.add('active');
            const p = a.dataset.page;
            $('page-' + p).classList.add('active');
            $('pageTitle').textContent = TITLES[p] || p;
            if (p === 'dashboard') loadStatus();
            if (p === 'certs') { loadCerts(); loadIssuers(); }
            if (p === 'config') loadConfig();
            if (p === 'logs') loadLogs();
            if (p === 'sign') loadSignCerts();
            if (p === 'template') { loadTemplates(); loadCerts(); loadIssuers(); }
            if (p === 'ctlog') loadCtLog();
            if (p === 'users') loadUsers();
            if (p === 'radius') { loadRadius(); }
            if (p === 'pppoe') { loadPppoe(); loadPppoeLogs(); }
          };
        });

        // ===== 仪表盘 =====
        function fmtUptime(s) {
          if (s < 60) return s + ' 秒';
          if (s < 3600) return Math.floor(s/60) + ' 分 ' + (s%60) + ' 秒';
          if (s < 86400) return Math.floor(s/3600) + ' 时 ' + Math.floor(s%3600/60) + ' 分';
          return Math.floor(s/86400) + ' 天 ' + Math.floor(s%86400/3600) + ' 时';
        }
        async function loadStatus() {
          try {
            const r = await api('/api/status');
            if (!r.ok) return;
            const d = r.data;
            if ($('stPort')) $('stPort').textContent = d.mainPort;
            if ($('stUptime')) $('stUptime').textContent = fmtUptime(d.uptimeSeconds);
            if ($('stAdmin')) $('stAdmin').textContent = d.adminPort;
            if ($('stCalls')) $('stCalls').textContent = d.totalCalls;
            if ($('stLogs')) $('stLogs').textContent = d.logLines;
            if ($('stBase')) $('stBase').textContent = d.baseDir;
            if ($('mainPort')) $('mainPort').textContent = 'MAIN: ' + d.mainPort;
            const st = $('mainState');
            if (st) {
              st.textContent = d.mainRunning ? '● 运行中' : '○ 未运行';
              st.className = 'badge ' + (d.mainRunning ? 'ok' : 'err');
            }
            if ($('sideVersion')) $('sideVersion').textContent = d.version;
            // 最近日志（仅仪表盘页拉取，避免其它页面白耗流量）
            if ($('page-dashboard') && $('page-dashboard').classList.contains('active')) {
              const lr = await api('/api/logs?lines=30');
              if (lr.ok && $('dashLogs')) $('dashLogs').textContent = lr.data;
            }
          } catch (e) {
            const st = $('mainState');
            if (st) { st.textContent = '连接失败'; st.className = 'badge err'; }
          }
        }

        // ===== 证书库 =====
        let certData = [];
        async function loadCerts() {
          try {
            const r = await api('/api/certs');
            if (r.ok) { certData = r.data; renderCerts(); }
          } catch (e) { /* ignore */ }
        }
        function renderCerts() {
          const f = v('certsFilter').toLowerCase();
          const rows = certData.filter(e => !f || JSON.stringify(e).toLowerCase().includes(f));
          const tb = $('certsTable').querySelector('tbody');
          tb.innerHTML = '';
          rows.forEach(e => {
            const tr = document.createElement('tr');
            tr.dataset.serial = e.serial;
            // 状态文本：V.正常 / R.已吊销 / N.未知；配色：正常绿、已吊销深红、未知橙
            const stTxt = {V:'V.正常', R:'R.已吊销', N:'N.未知'}[e.status] || e.status;
            const stCls = e.status === 'R' ? 'color:#dc2626' : e.status === 'V' ? 'color:var(--ok)' : e.status === 'N' ? 'color:#f59e0b' : '';
            // 序列号列：鼠标悬浮显示证书详情（与仪表盘证书链同款悬浮窗）
            const tip = certTip(e.serial);
            tr.innerHTML = '<td class="t-box" data-tip="' + esc(tip) + '">' + esc(e.serial) + '</td>' +
              '<td>' + esc(typeName(e.type)) + '</td><td style="' + stCls + ';font-weight:700">' + esc(stTxt) + '</td>' +
              '<td>' + esc(e.reason) + '</td><td>' + esc(e.time) + '</td>' +
              '<td class="t-box" data-tip="' + esc(certTip(e.issuer)) + '">' + esc(e.issuer) + '</td><td>' + esc(e.algo) + '</td>' +
              '<td><button class="ghost" data-serial="' + e.serial + '" style="padding:4px 12px;font-size:12px">详情</button> ' +
              '<button class="ghost" data-verify="' + e.serial + '" style="padding:4px 12px;font-size:12px">验证</button> ' +
              '<button class="ghost" data-op="' + e.serial + '" style="padding:4px 12px;font-size:12px">操作</button></td>';
            tb.appendChild(tr);
          });
          if (!rows.length) tb.innerHTML = '<tr><td colspan="8" style="color:var(--dim)">（无匹配记录）</td></tr>';
        }
        // 证书悬浮窗：优先用证书链树的详情（DN/密钥/哈希/长度/OCSP/CRL），未登记链数据时回退登记表信息
        function certTip(serial) {
          const n = issuerMap[serial];
          if (n) return issuerTip(serial);
          const e = certData.find(x => x.serial.toLowerCase() === String(serial).toLowerCase());
          if (!e) return '<div class="kv"><b>证书信息：</b>未找到（该序列号未登记详情）</div>';
          const stTxt = {V:'正常', R:'已吊销', N:'未知'}[e.status] || e.status;
          return '<div class="kv"><b>序列号：</b>' + esc(e.serial) + '</div>' +
            '<div class="kv"><b>证书类型：</b>' + esc(typeName(e.type)) + '</div>' +
            '<div class="kv"><b>状态：</b>' + esc(stTxt) + ' / 算法：' + esc(e.algo || '-') + '</div>' +
            '<div class="kv"><b>颁发者：</b>' + esc(e.issuer) + '</div>' +
            '<div class="kv"><b>时间：</b>' + esc(e.time) + '</div>';
        }

        // ===== 证书库：可信公网 cacerts 选择夹（结构同 CERTS.txt 列表） =====
        let caData = [];
        function csSwitchTab(t) {
          document.getElementById('csTabBtnLocal').className = 'ct-tab' + (t==='local' ? ' active' : '');
          document.getElementById('csTabBtnCa').className = 'ct-tab' + (t==='cacerts' ? ' active' : '');
          document.getElementById('csTabBtnMy').className = 'ct-tab' + (t==='my' ? ' active' : '');
          document.getElementById('csPaneLocal').style.display = t==='local' ? '' : 'none';
          document.getElementById('csPaneCa').style.display = t==='cacerts' ? '' : 'none';
          document.getElementById('csPaneMy').style.display = t==='my' ? '' : 'none';
          if (t==='cacerts') loadCacerts();
          if (t==='my') loadMy();
        }
        async function loadCacerts() {
          try {
            const r = await api('/api/certs/cacerts');
            if (r.ok) { caData = r.data; renderCacerts(); }
          } catch (e) { /* ignore */ }
        }
        function renderCacerts() {
          const f = v('caFilter').toLowerCase();
          const rows = caData.filter(e => !f || JSON.stringify(e).toLowerCase().includes(f));
          const tb = $('caTable').querySelector('tbody');
          tb.innerHTML = '';
          rows.forEach(e => {
            const tr = document.createElement('tr');
            tr.dataset.serial = e.serial;
            tr.innerHTML = '<td style="font-family:var(--mono);font-size:12px;max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(e.serial) + '">' + esc(e.serial) + '</td>' +
              '<td>' + esc(e.algo) + '</td>' +
              '<td>' + esc(e.notBefore) + '</td><td>' + esc(e.notAfter) + '</td>' +
              '<td style="max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(e.subject) + '">' + esc(e.subject) + '</td>' +
              '<td><button class="ghost" data-serial="' + esc(e.serial) + '" style="padding:4px 12px;font-size:12px">详情</button></td>';
            tb.appendChild(tr);
          });
          if (!rows.length) tb.innerHTML = '<tr><td colspan="6" style="color:var(--dim)">（无匹配记录）</td></tr>';
        }

        // ===== 证书库：我的证书（PKI/MY 导入库） =====
        let myData = [];
        let myPendingFile = null;
        let myPendingName = '';
        let myDeleteSerial = '';
        async function loadMy() {
          try {
            const r = await api('/api/my/list');
            if (r.ok) { myData = r.data || []; renderMy(); }
          } catch (e) { /* ignore */ }
        }
        function myTypeTxt(t) { return {R:'根证书', C:'CA证书', E:'终端证书'}[t] || t; }
        function renderMy() {
          const f = v('myFilter').toLowerCase();
          const rows = myData.filter(e => !f || JSON.stringify(e).toLowerCase().includes(f));
          const tb = $('myTable').querySelector('tbody');
          tb.innerHTML = '';
          rows.forEach(e => {
            const tr = document.createElement('tr');
            tr.dataset.serial = e.serial;
            tr.innerHTML =
              '<td class="t-box" data-tip="' + esc(myTip(e)) + '">' + esc(e.serial) + '</td>' +
              '<td>' + esc(myTypeTxt(e.type)) + '</td>' +
              '<td>' + esc(e.algo) + '</td>' +
              '<td>' + (e.hasKey === 'Y' ? '是' : '否') + '</td>' +
              '<td>' + esc(e.notBefore) + '</td><td>' + esc(e.notAfter) + '</td>' +
              '<td><button class="ghost" data-mserial="' + esc(e.serial) + '" data-act="detail" style="padding:4px 12px;font-size:12px">详情</button> ' +
              '<button class="ghost" data-mserial="' + esc(e.serial) + '" data-act="verify" style="padding:4px 12px;font-size:12px">验证</button> ' +
              '<button class="ghost" data-mserial="' + esc(e.serial) + '" data-act="del" style="padding:4px 12px;font-size:12px;color:#dc2626;font-weight:700">删除</button></td>';
            tb.appendChild(tr);
          });
          if (!rows.length) tb.innerHTML = '<tr><td colspan="7" style="color:var(--dim)">（无记录，点击"导入证书"添加）</td></tr>';
        }
        function myTip(e) {
          return '<div class="kv"><b>序列号：</b>' + esc(e.serial) + '</div>' +
            '<div class="kv"><b>证书类型：</b>' + esc(myTypeTxt(e.type)) + '</div>' +
            '<div class="kv"><b>算法：</b>' + esc(e.algo) + ' / 私钥：' + (e.hasKey === 'Y' ? '有' : '无') + '</div>' +
            '<div class="kv"><b>有效期：</b>' + esc(e.notBefore) + ' ~ ' + esc(e.notAfter) + '</div>';
        }
        function myFileChosen() {
          const inp = $('myFile');
          if (!inp.files || !inp.files.length) return;
          const file = inp.files[0];
          const name = (file.name || '').toLowerCase();
          myPendingFile = file; myPendingName = file.name || 'cert';
          if (name.endsWith('.pfx') || name.endsWith('.p12') || name.endsWith('.jks')) {
            $('myPwdFile').textContent = '文件：' + file.name;
            $('myPwd').value = '';
            $('myPwdModal').style.display = 'flex';
            setTimeout(function(){ $('myPwd').focus(); }, 60);
          } else {
            myDoImport('');
          }
          inp.value = '';
        }
        function closeMyPwd() { $('myPwdModal').style.display = 'none'; }
        function myPwdOk() { myDoImport($('myPwd').value); closeMyPwd(); }
        async function myDoImport(password) {
          if (!myPendingFile) return;
          const msg = $('myMsg');
          msg.className = 'hint'; msg.style.color = 'var(--dim)';
          msg.textContent = '正在导入 ' + myPendingName + ' ...';
          const fd = new FormData();
          fd.append('file', myPendingFile);
          if (password !== '') fd.append('password', password);
          try {
            const resp = await fetch('/api/my/import', { method: 'POST', body: fd });
            const j = await resp.json();
            if (j.ok) {
              msg.style.color = 'var(--ok)';
              msg.textContent = (j.message || '导入成功') + '，证书：' + (j.certPath || '') + (j.keyPath ? '，私钥：' + j.keyPath : '');
              loadMy();
            } else {
              msg.style.color = 'var(--err)';
              msg.textContent = '导入失败：' + (j.message || '未知错误');
            }
          } catch (e) {
            msg.style.color = 'var(--err)';
            msg.textContent = '导入请求异常：' + e;
          }
        }
        function myAskDelete(serial) {
          myDeleteSerial = serial;
          $('myDelText').textContent = '是否删除 序列号为 ' + serial + ' 的证书？';
          $('myDelModal').style.display = 'flex';
        }
        function closeMyDel() { $('myDelModal').style.display = 'none'; }
        async function myDoDelete() {
          const s = myDeleteSerial;
          closeMyDel();
          if (!s) return;
          try {
            const r = await api('/api/my/delete', { serial: s });
            const msg = $('myMsg');
            msg.className = 'hint';
            msg.style.color = r.ok ? 'var(--ok)' : 'var(--err)';
            msg.textContent = r.message || (r.ok ? '删除成功' : '删除失败');
            loadMy();
          } catch (e) {
            const msg = $('myMsg');
            msg.className = 'hint'; msg.style.color = 'var(--err)';
            msg.textContent = '删除请求异常：' + e;
          }
        }

        // 签发证书的颁发者下拉：CERTS.txt 中 R/C 类型序列号（悬停显示证书详情）
        let issuerMap = {};
        async function loadIssuers() {
          try {
            const [ri, rc] = await Promise.all([api('/api/issuers'), api('/api/chain')]);
            if (!ri.ok) return;
            issuerMap = {};
            if (rc.ok) {
              // /api/chain 返回嵌套树，展平为 serial → 节点
    """;
    private static final String PAGE_P2B = """
              const walk = nodes => (nodes || []).forEach(n => {
                issuerMap[n.serial] = n;
                if (n.children && n.children.length) walk(n.children);
              });
              walk(rc.data);
            }
            const sel = $('scIssuer');
            if (!sel) return;
            const keep = sel.value;
            sel.innerHTML = '';
            ri.issuers.forEach(s => {
              const opt = document.createElement('option');
              opt.value = s;
              opt.textContent = s;
              sel.appendChild(opt);
            });
            if (keep && [...sel.options].some(o => o.value === keep)) sel.value = keep;
            refreshIssuerTip();
          } catch (e) { /* ignore */ }
        }
        // 颁发者悬浮窗：与仪表盘证书链相同样式
        function issuerTip(serial) {
          const n = issuerMap[serial];
          if (!n) return '<div class="kv"><b>证书信息：</b>未找到（该序列号未登记详情）</div>';
          const stTxt = {V:'正常', R:'已吊销', N:'未知'}[n.status] || n.status;
          const kind = n.type === 'E' && n.kind ? '[' + n.kind + ']' : '';
          return '<div class="kv"><b>证书类型：</b>' + esc(typeName(n.type) + kind) + '</div>' +
            '<div class="kv"><b>序列号：</b>' + esc(n.serial) + '</div>' +
            '<div class="kv"><b>DN：</b>' + esc(n.dn) + '</div>' +
            '<div class="kv"><b>密钥对：</b>' + esc(n.algo || '-') + ' / 哈希：' + esc(n.hash || '-') + ' / 长度：' + (n.bits ? n.bits + '位' : '-') + '</div>' +
            '<div class="kv"><b>OCSP 状态：</b>' + esc(n.ocsp) + '</div>' +
            '<div class="kv"><b>CRL 状态：</b>' + esc(n.crl) + '（登记状态 ' + stTxt + '）</div>';
        }
        function refreshIssuerTip() {
          const sel = $('scIssuer');
          if (!sel) return;
          sel.dataset.tip = issuerTip(sel.value);
        }

        // ===== 证书 JSON 详情 =====
        let currentDetailSerial = '';
        let currentDetailJson = '';
        let currentDetailSource = 'certs';
        async function showDetail(serial, sourceType) {
          currentDetailSerial = serial;
          currentDetailJson = '';
          currentDetailSource = sourceType || 'certs';
          $('modal').classList.add('show');
          $('modalTitle').textContent = '证书详情 · ' + serial;
          $('modalJson').textContent = '加载中...';
          $('modalMeta').textContent = '';
          try {
            const r = await api('/api/certjson?serial=' + encodeURIComponent(serial));
            if (r.ok) {
              $('modalMeta').textContent = '路径: ' + r.path;
              $('modalJson').textContent = r.data;
              currentDetailJson = r.data;
            } else {
              $('modalJson').textContent = r.message || '解析失败';
            }
          } catch (e) {
            $('modalJson').textContent = '请求失败: ' + e;
          }
        }
        function closeModal() { $('modal').classList.remove('show'); }
        async function viewChainCert(serialOverride) {
          const s = ((serialOverride || currentDetailSerial) || '').trim();
          if (!s) { $('modalJson').textContent = '未选择证书'; return; }
          if (currentDetailSource === 'cacerts' && currentDetailJson) {
            MODPKICACERTVIERW(currentDetailJson, { noRevokeCheck: true });
            return;
          }
          if (currentDetailSource === 'my' && currentDetailJson) {
            MODPKICACERTVIERW(currentDetailJson);
            return;
          }
          $('modalJson').textContent = '正在获取证书链...';
          try {
            const r = await api('/api/certchainjson?serial=' + encodeURIComponent(s));
            if (r.ok && Array.isArray(r.data) && r.data.length) {
              MODPKICACERTVIERW.apply(null, r.data);
              $('modalJson').textContent = currentDetailJson || '（证书链已在查看器中打开）';
            } else {
              $('modalJson').textContent = (r && r.message) || '证书链解析失败';
            }
          } catch (e) {
            $('modalJson').textContent = '证书链请求失败: ' + e;
          }
        }

        // ===== 证书操作弹窗（吊销证书 / 续签证书 / 密钥更换） =====
        const OP_REASONS = [['0','未指定'],['1','密钥泄露'],['2','CA泄露'],['3','从属关系变更'],['4','证书超期'],['5','停止运营'],['6','证书吊销'],['8','从CRL移除'],['9','其他']];
        function openOp(serial) {
          $('opSerial').value = serial || '';
          $('keySerial').value = serial || '';
          $('renewSerial').value = serial || '';
          // 续签默认：生效=当前时间，失效=一年后（可自行修改）
          const now = new Date();
          const pad = n => String(n).padStart(2, '0');
          const fmt = d => d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
          const oneYear = new Date(now.getTime());
          oneYear.setFullYear(oneYear.getFullYear() + 1);
          $('renewNotBefore').value = fmt(now);
          $('renewNotAfter').value = fmt(oneYear);
          $('opSerialList').innerHTML = certData.map(e => '<option value="' + esc(e.serial) + '"></option>').join('');
          const sel = $('opReason');
          sel.innerHTML = OP_REASONS.map(r => '<option value="' + r[0] + '">' + r[0] + ' - ' + r[1] + '</option>').join('');
          sel.value = '0';
          $('opOut').textContent = '';
          $('opOut').hidden = true;
          $('keyOut').textContent = '';
          $('keyOut').hidden = true;
          $('keyTests').innerHTML = '';
          $('renewOut').textContent = '';
          $('renewOut').hidden = true;
          $('renewTests').innerHTML = '';
          switchOp('revoke');
          $('opModal').style.display = 'flex';
          opInfo();
          keyInfo();
          renewInfo();
        }
        function closeOp() { $('opModal').style.display = 'none'; }
        // 分组切换：吊销（含恢复）/ 续签 / 密钥更换均有实际功能
        function switchOp(tab) {
          ['revoke', 'renew', 'key'].forEach(t => {
            const cap = t[0].toUpperCase() + t.slice(1);
            $('opTab' + cap).classList.toggle('active', t === tab);
            $('opPane' + cap).style.display = t === tab ? '' : 'none';
          });
          $('opFootRevoke').style.display = tab === 'revoke' ? '' : 'none';
          $('opFootRestore').style.display = tab === 'revoke' ? '' : 'none';
          $('opFootRenew').style.display = tab === 'renew' ? '' : 'none';
          $('opFootKey').style.display = tab === 'key' ? '' : 'none';
          if (tab === 'key') keyInfo();
          if (tab === 'renew') renewInfo();
        }
        // 序列号输入/选择后：显示证书简要信息（同仪表盘证书链悬浮窗数据）
        function opInfo() {
          renderCertInfo($('opSerialInfo'), $('opSerial').value.trim().toLowerCase());
        }
        // 密钥更换分组的序列号简要信息
        function keyInfo() {
          renderCertInfo($('keyInfoBox'), $('keySerial').value.trim().toLowerCase());
        }
        // 续签分组的序列号简要信息
        function renewInfo() {
          renderCertInfo($('renewInfoBox'), $('renewSerial').value.trim().toLowerCase());
        }
        function renderCertInfo(box, s) {
          if (!s) { box.innerHTML = '<span style="color:var(--dim)">未选择证书</span>'; return; }
          const n = issuerMap[s];
          if (n) {
            box.innerHTML = '<div class="kv"><b>证书类型：</b>' + esc(typeName(n.type) + (n.type === 'E' && n.kind ? '[' + n.kind + ']' : '')) + '</div>' +
              '<div class="kv"><b>序列号：</b>' + esc(n.serial) + '</div>' +
              '<div class="kv"><b>DN：</b>' + esc(n.dn) + '</div>' +
              '<div class="kv"><b>密钥对：</b>' + esc(n.algo || '-') + ' / 哈希：' + esc(n.hash || '-') + ' / 长度：' + (n.bits ? n.bits + '位' : '-') + '</div>' +
              '<div class="kv"><b>OCSP 状态：</b>' + esc(n.ocsp) + '</div>' +
              '<div class="kv"><b>CRL 状态：</b>' + esc(n.crl) + '（登记状态 ' + esc({V:'正常', R:'已吊销', N:'未知'}[n.status] || n.status) + '）</div>';
          } else {
            const e = certData.find(x => x.serial.toLowerCase() === s);
            if (e) {
              box.innerHTML = '<div class="kv"><b>序列号：</b>' + esc(e.serial) + '</div>' +
                '<div class="kv"><b>证书类型：</b>' + esc(typeName(e.type)) + ' / 状态：' + esc({V:'正常', R:'已吊销', N:'未知'}[e.status] || e.status) + '</div>' +
                '<div class="kv"><b>算法：</b>' + esc(e.algo || '-') + ' / 颁发者：' + esc(e.issuer) + '</div>' +
                '<div class="kv"><b>时间：</b>' + esc(e.time) + '</div>';
            } else {
              box.innerHTML = '<div class="kv" style="color:var(--err)"><b>提示：</b>未找到该序列号（请检查 CERTS.txt 登记表）</div>';
            }
          }
        }
        // 确认吊销：调用 /api/revoke，成功后刷新证书库列表
        async function doOpRevoke() {
          const s = $('opSerial').value.trim();
          if (!s) { $('opOut').hidden = false; showOut('opOut', '请先输入证书序列号', false); return; }
          await postForm('/api/revoke', { serial: s, reason: $('opReason').value }, 'opOut');
          loadCerts();
          loadIssuers();
        }
        // 恢复证书：调用 /api/restore（R→V、原因 0，同步刷新 CRL）
        async function doOpRestore() {
          const s = $('opSerial').value.trim();
          if (!s) { $('opOut').hidden = false; showOut('opOut', '请先输入证书序列号', false); return; }
          $('opOut').hidden = false;
          $('opOut').textContent = '正在恢复证书并刷新 CRL...';
          await postForm('/api/restore', { serial: s }, 'opOut');
          loadCerts();
          loadIssuers();
        }
        // 确认密钥更换：调用 /api/rekey（生成新密钥对 → 测试 → CA 重签 → 替换文件）
        async function doOpKey() {
          const s = $('keySerial').value.trim();
          if (!s) { $('keyOut').hidden = false; showOut('keyOut', '请先输入证书序列号', false); return; }
          $('keyTests').innerHTML = '<div class="kv" style="color:var(--dim)">正在生成新密钥对并执行加解密 / 签名验签测试...</div>';
          await postForm('/api/rekey', { serial: s }, 'keyOut');
          loadCerts();
          loadIssuers();
        }
        // 确认续签：调用 /api/renew（更新生效/失效时间 → CA 重签 → 替换文件）
        async function doOpRenew() {
          const s = $('renewSerial').value.trim();
          if (!s) { $('renewOut').hidden = false; showOut('renewOut', '请先输入证书序列号', false); return; }
          const nb = $('renewNotBefore').value;
          const na = $('renewNotAfter').value;
          if (!nb || !na) { $('renewOut').hidden = false; showOut('renewOut', '请选择生效时间和失效时间', false); return; }
          if (nb >= na) { $('renewOut').hidden = false; showOut('renewOut', '失效时间必须晚于生效时间', false); return; }
          $('renewTests').innerHTML = '<div class="kv" style="color:var(--dim)">正在按新时间重建 TBS 并由颁发者 CA 重签...</div>';
          await postForm('/api/renew', { serial: s, notBefore: nb, notAfter: na }, 'renewOut');
          loadCerts();
          loadIssuers();
        }

        // ===== 证书验证弹窗：按当前行序列号调用 /api/verify =====
        const V_REASONS = {0:'未指定', 1:'密钥泄露', 2:'CA泄露', 3:'从属关系变更', 4:'证书超期', 5:'停止运营', 6:'证书吊销', 8:'从CRL移除', 9:'其他'};
        // 从验证输出文本解析证书状态：正常 / 已吊销（含原因）/ 未知（实时数据获取失败）
        function parseVerifyState(text) {
          const t = text || '';
          if (/无法|未知|None|解析失败|失败(?!\s*[0-9]+\s*个)/.test(t)) {
            return { k: 'unknown', badge: '未知', txt: '证书有效，因实时数据获取失败无法进行权威校验' };
          }
          if (t.includes('已吊销') || t.includes('已被')) {
            const m = t.match(/原因[:：]?\\s*(\\d+)/);
            const reason = m ? (V_REASONS[parseInt(m[1], 10)] || ('原因码 ' + m[1])) : '';
            return { k: 'revoked', badge: '已吊销', txt: reason ? '因' + reason + '，证书已被吊销' : '证书已被吊销' };
          }
          if (t.includes('证书正常') || t.includes('正常')) {
            return { k: 'ok', badge: '正常', txt: '证书有效，状态正常' };
          }
          return { k: 'unknown', badge: '未知', txt: '证书有效，因实时数据获取失败无法进行权威校验' };
        }
        const V_HEAD_BG = { ok: 'rgba(16,185,129,0.16)', revoked: 'rgba(239,68,68,0.16)', unknown: 'rgba(245,158,11,0.16)' };
        const V_BADGE_BG = { ok: '#dcfce7', revoked: '#fee2e2', unknown: '#ffedd5' };
        const V_BADGE_FG = { ok: '#065f46', revoked: '#991b1b', unknown: '#b45309' };
        const V_TEXT_FG = { ok: '#6ee7b7', revoked: '#fca5a5', unknown: '#fcd34d' };
        async function openVerify(serial) {
          $('verifyModal').style.display = 'flex';
          $('verifyModalTitle').textContent = '证书验证 · ' + serial;
          const out = $('verifyModalOut');
          out.className = 'out';
          out.textContent = '验证中...';
          try {
            const r = await api('/api/verify', { target: serial });
            out.textContent = r.message || (r.ok ? 'OK' : '失败');
            out.className = 'out ' + (r.ok ? 'ok' : 'err');
            const st = parseVerifyState(out.textContent);
            $('verifyHead').style.background = V_HEAD_BG[st.k];
            $('verifyHead').style.borderBottomColor = V_HEAD_BG[st.k];
            const b = $('verifyBadge');
            b.style.display = 'inline-block';
            b.style.background = V_BADGE_BG[st.k];
            b.style.color = V_BADGE_FG[st.k];
            b.textContent = st.badge;
            $('verifyText').textContent = st.txt;
            $('verifyText').style.color = V_TEXT_FG[st.k];
          } catch (e) {
            out.textContent = '请求失败: ' + e;
            out.className = 'out err';
          }
        }
        function closeVerifyModal() { $('verifyModal').style.display = 'none'; }

        // ===== 证书链树 =====
        function esc(s) { return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
        function typeName(t) { return {R:'根证书', C:'CA证书', E:'终端证书'}[t] || t; }
        function tipHtml(n) {
          const stTxt = {V:'正常', R:'已吊销', N:'未知'}[n.status] || n.status;
          const kind = n.type === 'E' && n.kind ? '[' + n.kind + ']' : '';
          return '<div class="kv"><b>证书类型：</b>' + esc(typeName(n.type) + kind) + '</div>' +
            '<div class="kv"><b>序列号：</b>' + esc(n.serial) + '</div>' +
            '<div class="kv"><b>DN：</b>' + esc(n.dn) + '</div>' +
            '<div class="kv"><b>密钥对：</b>' + esc(n.algo || '-') + ' / 哈希：' + esc(n.hash || '-') + ' / 长度：' + (n.bits ? n.bits + '位' : '-') + '</div>' +
            '<div class="kv"><b>OCSP 状态：</b>' + esc(n.ocsp) + '</div>' +
            '<div class="kv"><b>CRL 状态：</b>' + esc(n.crl) + '（登记状态 ' + stTxt + '）</div>';
        }
        function renderNode(n, isRoot, collapsed) {
          const kids = n.children || [];
          const hasKids = kids.length > 0;
          const kind = n.type === 'E' && n.kind ? '[' + n.kind + ']' : '';
          let h = '<div class="t-node t-node-' + n.type.toLowerCase() + (isRoot ? ' t-node-root' : '') + '">';
          h += '<div class="t-head">';
          if (hasKids) {
            h += '<span class="t-toggle" data-col="' + (collapsed ? '1' : '0') + '">' + (collapsed ? '▶' : '▼') + '</span>';
          }
          h += '<span class="t-box" data-tip="' + esc(tipHtml(n)) + '"><span class="t-badge ' + n.type + '">' + n.type + '</span>' +
            '<span class="t-kind">' + typeName(n.type) + kind + '</span>' + esc(n.dn || n.serial) +
            ' <span class="t-st ' + n.status + '">' + (n.status === 'V' ? '● 正常' : n.status === 'R' ? '● 已吊销' : '● 未知') + '</span></span>';
          h += '</div>';
          h += '</div>';
          if (hasKids) {
            h += '<div class="t-children' + (collapsed ? ' collapsed' : '') + '">';
            kids.forEach(k => { h += renderNode(k, false, k.type === 'C'); });
            h += '</div>';
          }
          return h;
        }
        async function loadChain() {
          const box = $('chainBox');
          box.textContent = '加载中...';
          try {
            const r = await api('/api/chain');
            if (!r.ok) { box.textContent = r.message || '加载失败'; return; }
            const roots = r.data;
            if (!roots.length) { box.innerHTML = '<span style="color:var(--dim)">（证书库为空，先签发根证书）</span>'; return; }
            let h = '<div class="t-row">';
            roots.forEach(root => { h += '<div>' + renderNode(root, true, false) + '</div>'; });
            h += '</div>';
            box.innerHTML = h;
          } catch (e) {
            box.textContent = '请求失败: ' + e;
          }
        }

        // 收起 / 展开（R 默认展开，C 默认收起，点箭头切换）
        document.addEventListener('click', function (e) {
          const tg = e.target.closest ? e.target.closest('.t-toggle') : null;
          if (!tg) return;
          const node = tg.closest('.t-node');
          if (!node) return;
          const kids = node.nextElementSibling;
          if (!kids || !kids.classList.contains('t-children')) return;
          const collapsed = tg.dataset.col === '1';
          if (collapsed) {
            kids.classList.remove('collapsed');
            tg.dataset.col = '0';
            tg.textContent = '▼';
          } else {
            kids.classList.add('collapsed');
            tg.dataset.col = '1';
            tg.textContent = '▶';
          }
        });

        // ===== 链树悬浮详情：fixed 浮层挂 body（不被滚动容器裁剪、不被顶栏遮挡、始终置顶） =====
        (function () {
          const tip = document.createElement('div');
          tip.id = 'tipFloat';
          document.body.appendChild(tip);
          document.addEventListener('mouseover', function (e) {
            const box = e.target.closest ? e.target.closest('.t-box') : null;
            if (box) {
              tip.innerHTML = box.dataset.tip || '';
              tip.style.display = 'block';
              return;
            }
            if (tip.style.display === 'block') {
              const rel = e.relatedTarget;
              if (!rel || !rel.closest || !rel.closest('.t-box')) tip.style.display = 'none';
            }
          });
          document.addEventListener('mousemove', function (e) {
            if (tip.style.display !== 'block') return;
            const pad = 14, gap = 8;
            const w = tip.offsetWidth, h = tip.offsetHeight;
            let x = e.clientX + gap;
            let y = e.clientY + gap;
            if (x + w > innerWidth - pad) x = e.clientX - w - gap;
            if (y + h > innerHeight - pad) y = e.clientY - h - gap;
            tip.style.left = Math.max(pad, x) + 'px';
            tip.style.top = Math.max(pad, y) + 'px';
          });
        })();

        // ===== 日志 =====
        async function loadLogs() {
          try {
            const n = v('logLines') || '200';
            const r = await api('/api/logs?lines=' + n);
            if (r.ok) $('logsOut').textContent = r.data;
          } catch (e) { /* ignore */ }
        }
        // 按最近 N 小时加载日志（0=全部）
        async function loadLogsHours(h) {
          try {
            const r = await api('/api/logs?hours=' + h);
            if (r.ok) $('logsOut').textContent = r.data;
          } catch (e) { /* ignore */ }
        }

        // ===== 密钥位数联动（RSA 可编辑下拉 / ECC·SM2 只读固定） =====
        const BITS_OPT = { RSA: [1024, 2048, 3072, 4096, 5120, 6144, 7168, 8192], 'RSA-PSS': [1024, 2048, 3072, 4096, 5120, 6144, 7168, 8192], ECC: [256, 384, 521], SM2: [256], DSA: [1024, 2048, 3072], EdDSA: [256], PQC: ['ML-DSA-44','ML-DSA-65','ML-DSA-87'] };
        function syncHashForAlgo(algo, hashSel) {
          if (!hashSel) return;
          if (algo === 'PQC' || algo === 'EdDSA') {
            // PQC internally embeds its hash; Ed25519 is a pure signature algorithm (RFC 8032)
            hashSel.value = 'NULL';
            hashSel.disabled = true;
          } else {
            hashSel.disabled = false;
            if (hashSel.value === 'NULL') hashSel.value = 'sha256';
          }
        }
        function scCaChanged() {
          const isCa = $('scCa').value === '1';
          $('scPathLenWrap').style.display = isCa ? '' : 'none';
          $('scPolWrap').style.display = isCa ? 'none' : '';
        }
        function pathLenVal() {
          return $('scPathLen').value || 'null';
        }
        // 自定义证书策略（签发证书页）：{oid, on}，勾选的才写入证书策略扩展
        let scPolCustom = [];
        function addScPolCustom() {
          const oid = v('scPolCustomOid').trim();
          if (!oid) { showOut('scOut', '请输入自定义策略 OID', false); return; }
          if (!/^(\\d+)(\\.\\d+)+$/.test(oid)) { showOut('scOut', 'OID 格式不正确（如 1.2.3.4.5）', false); return; }
          if (scPolCustom.some(x => x.oid === oid)) { showOut('scOut', '该策略 OID 已添加', false); return; }
          scPolCustom.push({oid: oid, on: true});
          $('scPolCustomOid').value = '';
          renderScPolCustom();
        }
        function delScPolCustom(i) { scPolCustom.splice(i, 1); renderScPolCustom(); }
        function renderScPolCustom() {
          const box = $('scPolCustomBox');
          box.innerHTML = scPolCustom.map((x, i) =>
            '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding-top:6px">' +
            '<input type="checkbox" ' + (x.on ? 'checked' : '') + ' onchange="scPolCustom[' + i + '].on=this.checked">' +
            '<span style="font-family:Consolas,monospace">' + esc(x.oid) + '</span>' +
            '<a style="color:#c0392b;cursor:pointer" onclick="delScPolCustom(' + i + ')">删除</a></label>').join('');
        }
        function policyVal() {
          const ids = ['scPolDv','scPolIv','scPolOv','scPolEv','scPolCsStd','scPolCsEv','scPolDoc','scPolTsa'];
          const OIDS = {scPolDv:'2.23.140.1.2.1',scPolIv:'2.23.140.1.2.3',scPolOv:'2.23.140.1.2.2',scPolEv:'2.23.140.1.1',scPolCsStd:'2.23.140.1.4.1',scPolCsEv:'2.23.140.1.3',scPolDoc:'1.3.6.1.5.5.7.3.36',scPolTsa:'2.23.140.1.4.2'};
          const arr = ids.filter(id => $(id) && $(id).checked).map(id => OIDS[id]);
          (scPolCustom || []).forEach(x => { if (x.on && !arr.includes(x.oid)) arr.push(x.oid); });
          return arr.join(',');
        }
        function algoChanged() {
          const algo = $('scAlgo').value;
          const opts = BITS_OPT[algo] || [];
          const cur = parseInt($('scBits').value, 10);
          $('scBits').innerHTML = opts.map(v => '<option>' + v + '</option>').join('');
          $('scBits').value = opts.includes(cur) ? String(cur) : String(opts[0]);
          syncHashForAlgo(algo, $('scHash'));
        }
        // 取当前密钥位数实际值
        function bitsVal() {
          return $('scBits').value;
        }

        // ===== 密钥位数联动（扩展列表：签发根证书/初始化环境共用） =====
        // RSA 可编辑下拉 1024..8192（含 5120/6144/7168）；ECC 固定 256/384/521；SM2 固定 256
        const BITS_OPT_EXT = { RSA: [1024, 2048, 3072, 4096, 5120, 6144, 7168, 8192], 'RSA-PSS': [1024, 2048, 3072, 4096, 5120, 6144, 7168, 8192], ECC: [256, 384, 521], SM2: [256], DSA: [1024, 2048, 3072], EdDSA: [256], PQC: ['ML-DSA-44','ML-DSA-65','ML-DSA-87'] };
        function extAlgoChanged(p) {
          const algo = $(p + 'Algo').value;
          const opts = BITS_OPT_EXT[algo] || [];
          const cur = parseInt($(p + 'Bits').value, 10);
          $(p + 'Bits').innerHTML = opts.map(v => '<option>' + v + '</option>').join('');
          $(p + 'Bits').value = opts.includes(cur) ? String(cur) : String(opts[0]);
          syncHashForAlgo(algo, $(p + 'Hash'));
        }
        function extBitsVal(p) {
          return $(p + 'Bits').value;
        }
        // 初始填充（脚本位于 DOM 之后，直接填充三个页面）
        algoChanged();
        extAlgoChanged('mk');
        extAlgoChanged('in');
        scCaChanged();

        // ===== 有效期选择器 =====
        // 前端 datetime-local: '2026-09-12T10:30:00' ↔ 后端格式 '2026/09/12-10:30:00'
        function toBackendFmt(v) {
          const i = v.indexOf('T');
          return (i > 0 ? v.substring(0, i) : v).replace(/-/g, '/') + (i > 0 ? '-' + v.substring(i + 1) : '');
        }
        function fromBackendFmt(v) {
          const i = v.indexOf('-', 10); // 日期部分 '2026/09/12' 占 10 位
          if (i < 0) return '';
          return v.substring(0, i).replace(/\\//g, '-') + 'T' + v.substring(i + 1);
        }
        function openValModal() {
          let s = '', e = '';
          const cur = ($('scDays').value || '').trim();
          if (cur && cur.length >= 5 && isNaN(parseInt(cur, 10))) {
            const parts = cur.split('T');
            if (parts.length === 2) { s = fromBackendFmt(parts[0]); e = fromBackendFmt(parts[1]); }
          }
          $('valStart').value = s;
          $('valEnd').value = e;
          $('valModal').style.display = 'flex';
        }
        function valOk() {
          const s = $('valStart').value, e = $('valEnd').value;
          if (s && e) { $('scDays').value = toBackendFmt(s) + 'T' + toBackendFmt(e); }
          else if (s) { $('scDays').value = toBackendFmt(s); }
          closeValModal();
        }
        function closeValModal() { $('valModal').style.display = 'none'; }

        // ===== KeyUsage 密钥用法选择器 =====
        // 位值对齐 Go 版 x509.KeyUsage：1=数字签名 2=不可否认 4=密钥加密 8=数据加密
        // 16=密钥协商 32=证书签名 64=CRL签名 128=仅加密 256=仅解密
        const KU_OPTS = [
          ['数字签名 Digital Signature', 1],
          ['不可否认 Non Repudiation', 2],
          ['密钥加密 Key Encipherment', 4],
          ['数据加密 Data Encipherment', 8],
          ['密钥协商 Key Agreement', 16],
          ['证书签名 Certificate Sign', 32],
          ['CRL签名 CRL Sign', 64],
          ['仅加密 Encipher Only', 128],
          ['仅解密 Decipher Only', 256]
        ];
        const KU_PRESETS = { '1': 1 | 2 | 4 | 8 | 16, '2': 1 | 2 | 32 | 64, '3': 128, '4': 256, '5': 1 | 2, '6': 8, '7': 4, '8': 16 };
        function renderKuOpts() {
          const b = $('kuBody');
          if (!b || b.childElementCount) return;
          b.innerHTML = KU_OPTS.map(o =>
            '<label class="eku-item"><input type="checkbox" value="' + o[1] + '"><span>' + o[0] + '</span><code>' + o[1] + '</code></label>'
          ).join('');
        }
        function kuSelChanged(p) {
          p = p || 'sc';
          $(p + 'KuCustom').style.display = $(p + 'Ku').value === 'custom' ? 'block' : 'none';
          if ($(p + 'Ku').value === 'custom' && !$(p + 'KuCustom').value) {
            $(p + 'KuCustom').value = '1';
          }
        }
        // 取当前 KeyUsage 实际数值（预设编号或自定义组合值；自定义加 C 前缀避免与编号冲突）
        function kuVal(p) {
          p = p || 'sc';
          const s = $(p + 'Ku').value;
          return s === 'custom' ? 'C' + ($(p + 'KuCustom').value || '1') : s;
        }
        function openKuModal(p) {
          p = p || 'sc';
          window._kuTarget = p;
          renderKuOpts();
          // 回显：预设编号取位掩码，自定义(C前缀)取数值，其余按数字解析
          const raw = kuVal(p);
          let cur = 0;
          if (/^C\\d+$/.test(raw)) cur = parseInt(raw.substring(1), 10) || 0;
          else if (KU_PRESETS[raw]) cur = KU_PRESETS[raw];
          else cur = parseInt(raw, 10) || 0;
          document.querySelectorAll('#kuBody input[type=checkbox]').forEach(c => { c.checked = (cur & parseInt(c.value, 10)) !== 0; });
          $('kuModal').style.display = 'flex';
        }
        function kuOk() {
          let p = window._kuTarget || 'sc';
          let sum = 0;
          document.querySelectorAll('#kuBody input[type=checkbox]:checked').forEach(c => { sum += parseInt(c.value, 10); });
          // 未勾选任何项 = 证书不携带 KeyUsage 扩展，置空
          if (sum === 0) {
            $(p + 'Ku').value = '';
            $(p + 'KuCustom').value = '';
            $(p + 'KuCustom').style.display = 'none';
            closeKuModal(); return;
          }
          // 命中预设编号则选中下拉，否则用自定义数值
          let preset = null;
          for (const k in KU_PRESETS) { if (KU_PRESETS[k] === sum) { preset = k; break; } }
          if (preset) {
            $(p + 'Ku').value = preset;
            $(p + 'KuCustom').style.display = 'none';
          } else {
            $(p + 'Ku').value = 'custom';
            $(p + 'KuCustom').value = String(sum);
            $(p + 'KuCustom').style.display = 'block';
          }
          closeKuModal();
        }
        function closeKuModal() { $('kuModal').style.display = 'none'; }

        // ===== EKU 增强型密钥用法选择器 =====
        const EKU_OPTS = [
          ['服务器身份验证', '1.3.6.1.5.5.7.3.1'],
          ['客户端身份验证', '1.3.6.1.5.5.7.3.2'],
          ['代码签名', '1.3.6.1.5.5.7.3.3'],
          ['安全电子邮件', '1.3.6.1.5.5.7.3.4'],
          ['IP 安全终端系统', '1.3.6.1.5.5.7.3.5'],
          ['IP 安全隧道终止', '1.3.6.1.5.5.7.3.6'],
          ['IP 安全用户', '1.3.6.1.5.5.7.3.7'],
          ['时间戳', '1.3.6.1.5.5.7.3.8'],
          ['OCSP 签名', '1.3.6.1.5.5.7.3.9'],
          ['内核模式代码签名', '1.3.6.1.4.1.311.61.1.1'],
          ['Windows 硬件驱动程序验证', '1.3.6.1.4.1.311.10.3.5'],
          ['Windows 系统组件验证', '1.3.6.1.4.1.311.10.3.6'],
          ['OEM Windows 系统组件验证', '1.3.6.1.4.1.311.10.3.7'],
          ['内嵌 Windows 系统组件验证', '1.3.6.1.4.1.311.10.3.8'],
          ['域名系统(DNS)服务器信任', '1.3.6.1.4.1.311.64.1.1'],
          ['通用文档签名', '1.3.6.1.5.5.7.3.36'],
          ['已吊销列表签名者', '1.3.6.1.4.1.311.10.3.19'],
          ['KDC 身份验证', '1.3.6.1.5.2.3.5'],
          ['生存时间签名', '1.3.6.1.4.1.311.10.3.13'],
          ['私钥存档', '1.3.6.1.4.1.311.21.5'],
          ['合格的部属', '1.3.6.1.4.1.311.10.3.10'],
          ['密钥恢复', '1.3.6.1.4.1.311.10.3.11'],
          ['文档签名', '1.3.6.1.4.1.311.10.3.12'],
          ['Microsoft 时间戳', '1.3.6.1.4.1.311.10.3.2'],
          ['加密文件系统', '1.3.6.1.4.1.311.10.3.4'],
          ['密钥恢复代理', '1.3.6.1.4.1.311.21.6'],
          ['目录服务电子邮件复制', '1.3.6.1.4.1.311.21.19'],
          ['IP 安全 IKE 中级', '1.3.6.1.5.5.8.2.2'],
          ['文件恢复', '1.3.6.1.4.1.311.10.3.4.1'],
          ['根列表签名者', '1.3.6.1.4.1.311.10.3.9'],
          ['数字权利', '1.3.6.1.4.1.311.10.5.1'],
          ['CTL 用法', '1.3.6.1.4.1.311.20.1'],
          ['密钥数据包许可证', '1.3.6.1.4.1.311.10.6.1'],
          ['许可证服务器验证', '1.3.6.1.4.1.311.10.6.2'],
          ['智能卡登录', '1.3.6.1.4.1.311.20.2.2']
        ];
        function renderEkuOpts() {
          const b = $('ekuBody');
          if (!b || b.childElementCount) return;
          b.innerHTML = EKU_OPTS.map(o =>
            '<label class="eku-item"><input type="checkbox" value="' + o[1] + '"><span>' + o[0] + '</span><code>' + o[1] + '</code></label>'
          ).join('');
        }
        function openEkuModal(p) {
          p = p || 'sc';
          window._ekuTarget = p;
          renderEkuOpts();
          // 回显：输入框中的编号(1~46)映射为对应 OID，OID/自定义值原样匹配
          const cur = $(p + 'Eu').value.split(',').map(s => s.trim()).filter(Boolean)
            .map(s => NUM_EKU[s] || s);
          document.querySelectorAll('#ekuBody input[type=checkbox]').forEach(c => { c.checked = cur.includes(c.value); });
          $('ekuModal').style.display = 'flex';
        }
        function ekuOk() {
          const p = window._ekuTarget || 'sc';
          const checked = [...document.querySelectorAll('#ekuBody input[type=checkbox]:checked')].map(c => c.value);
          // 未勾选任何项 = 证书不携带 EKU 扩展，置空
          if (!checked.length) { $(p + 'Eu').value = ''; closeEkuModal(); return; }
          // 弹窗选项内的旧值（编号或 OID）一律以勾选状态为准：未勾选即删除；
          // 仅保留不在弹窗选项中的自定义 OID（用户手输的非预设值）
          const optOids = EKU_OPTS.map(o => o[1]);
          const old = $(p + 'Eu').value.split(',').map(s => s.trim()).filter(s => {
            if (!s) return false;
            if (checked.includes(s)) return false;
            const oid = NUM_EKU[s] || s;
            return !optOids.includes(oid);
          });
          $(p + 'Eu').value = checked.concat(old).join(',');
          closeEkuModal();
        }
        // 编号 → OID（对齐 MakeCert builtinEku 0~11 与 EXT_OIDS 12~46）
        const NUM_EKU = {
          '0': '2.5.29.37.0', '1': '1.3.6.1.5.5.7.3.1', '2': '1.3.6.1.5.5.7.3.2',
          '3': '1.3.6.1.5.5.7.3.3', '4': '1.3.6.1.5.5.7.3.4', '5': '1.3.6.1.5.5.7.3.5',
          '6': '1.3.6.1.5.5.7.3.6', '7': '1.3.6.1.5.5.7.3.7', '8': '1.3.6.1.5.5.7.3.8',
          '9': '1.3.6.1.5.5.7.3.9', '10': '1.3.6.1.4.1.311.10.3.3', '11': '2.16.840.1.113730.4.1',
          '12': '1.3.6.1.4.1.311.2.1.22', '13': '1.3.6.1.4.1.311.61.1.1', '14': '1.3.6.1.4.1.311.10.3.5',
          '15': '1.3.6.1.4.1.311.10.3.6', '16': '1.3.6.1.4.1.311.10.3.7', '17': '1.3.6.1.4.1.311.10.3.8',
          '18': '1.3.6.1.4.1.311.64.1.1', '19': '1.3.6.1.4.1.311.47.1.1', '20': '1.3.6.1.4.1.311.10.3.19',
          '21': '1.3.6.1.5.2.3.5', '22': '1.3.6.1.4.1.311.10.3.13', '23': '1.3.6.1.4.1.311.21.5',
          '24': '1.3.6.1.4.1.311.10.3.10', '25': '1.3.6.1.4.1.311.10.3.11', '26': '1.3.6.1.4.1.311.10.3.12',
          '27': '1.3.6.1.4.1.311.10.3.2', '28': '1.3.6.1.4.1.311.10.3.4', '29': '1.3.6.1.4.1.311.21.6',
          '30': '1.3.6.1.4.1.311.21.19', '31': '1.3.6.1.5.5.8.2.2', '32': '1.3.6.1.4.1.311.10.3.4.1',
          '33': '1.3.6.1.4.1.311.10.3.9', '34': '1.3.6.1.4.1.311.10.5.1', '35': '1.3.6.1.4.1.311.20.1',
          '36': '1.3.6.1.4.1.311.10.6.1', '37': '1.3.6.1.4.1.311.10.6.2', '38': '1.3.6.1.4.1.311.20.2.1',
          '39': '1.3.6.1.4.1.311.20.2.2', '40': '1.3.6.1.4.1.311.21.30', '41': '1.3.6.1.4.1.311.21.31',
          '42': '1.3.6.1.4.1.311.21.32', '43': '1.2.840.113635.100.4.1', '44': '1.2.840.113635.100.4.1.1',
          '45': '1.2.840.113635.100.4.1.4', '46': '1.2.840.113635.100.4.2'
        };
        function closeEkuModal() { $('ekuModal').style.display = 'none'; }

        // ===== 模板管理（PKI/tamplate/data.json） =====
        let tplData = [];
        async function loadTemplates() {
          try {
            const r = await api('/api/template/list');
            if (r.ok) { tplData = r.data || []; renderTemplates(); }
          } catch (e) { /* ignore */ }
        }
        function tplTip(e) {
          return '<div class="kv"><b>模板：</b>#' + esc(e.id) + (e.name ? ' ' + esc(e.name) : '') + '</div>' +
            '<div class="kv"><b>证书类型：</b>' + (e.ctype === '1' ? '中间 CA' : '终端证书') + '</div>' +
            '<div class="kv"><b>算法：</b>' + esc(e.algo) + ' / 位数：' + esc(e.bits) + ' / 哈希：' + esc(e.hash) + '</div>' +
            '<div class="kv"><b>KeyUsage：</b>' + esc(e.keyusage) + ' / EKU：' + esc(e.exusage) + '</div>' +
            '<div class="kv"><b>有效期：</b>' + esc(e.days) + '</div>' +
            '<div class="kv"><b>创建时间：</b>' + esc(e.createTime || '') + '</div>';
        }
        function renderTemplates() {
          const tb = $('tplTable').querySelector('tbody');
          tb.innerHTML = '';
          tplData.forEach(e => {
            const tr = document.createElement('tr');
            tr.dataset.id = e.id;
            tr.innerHTML = '<td>' + esc(e.id) + '</td>' +
              '<td>' + (e.ctype === '1' ? '中间 CA' : '终端证书') + '</td>' +
              '<td class="t-box" data-tip="' + esc(tplTip(e)) + '">' + esc(e.dn) + '</td>' +
              '<td>' + esc(e.createTime || '') + '</td>' +
              '<td><button class="ghost" data-tp-del="' + esc(e.id) + '" style="padding:4px 12px;font-size:12px">删除</button> ' +
              '<button class="ghost" data-tp-edit="' + esc(e.id) + '" style="padding:4px 12px;font-size:12px">编辑</button> ' +
              '<button data-tp-sign="' + esc(e.id) + '" style="padding:4px 12px;font-size:12px">签署</button></td>';
            tb.appendChild(tr);
          });
          if (!tplData.length) tb.innerHTML = '<tr><td colspan="5" style="color:var(--dim)">（暂无模板，点击"添加模板"创建）</td></tr>';
        }
        // 行内按钮委托（删除二次确认：第一次点击变为"确认删除？"，3 秒内再点执行）
        (function initTplTable() {
          const tb = $('tplTable').querySelector('tbody');
          tb.onclick = e => {
            const del = e.target.closest('[data-tp-del]');
            const ed = e.target.closest('[data-tp-edit]');
            const sg = e.target.closest('[data-tp-sign]');
            if (del) delTemplate(del.dataset.tpDel, del);
            else if (ed) openTpModal(ed.dataset.tpEdit);
            else if (sg) openSignModal(sg.dataset.tpSign);
          };
        })();
        async function delTemplate(id, btn) {
          if (!btn || btn.dataset.arm !== '1') {
            if (btn) {
              btn.dataset.arm = '1';
              btn.textContent = '确认删除？';
              btn.style.color = '#dc2626';
            }
            setTimeout(() => {
              if (btn && btn.dataset.arm === '1') {
                btn.dataset.arm = '';
                btn.textContent = '删除';
                btn.style.color = '';
              }
            }, 3000);
            return;
          }
          try {
            const r = await api('/api/template/delete', {id: id});
            if (r.ok) loadTemplates();
            else showOut('tplMsg', r.message || '删除失败', false);
          } catch (e) { showOut('tplMsg', '请求异常: ' + e, false); }
        }

        // ===== 添加/编辑模板弹窗 =====
        let tplEditId = null;
        function openTpModal(id) {
          tplEditId = id || null;
          tplPolCustom = [];
          renderTpPolCustom();
          $('tpModalTitle').textContent = id ? '编辑模板 #' + id : '添加模板';
          const tpl = id ? (tplData.find(x => String(x.id) === String(id)) || {}) : {};
          $('tpName').value = tpl.name || '';
          $('tpDn').value = tpl.dn || '';
          $('tpCa').value = tpl.ctype || '0';
          tpCaChanged();
          $('tpAlgo').value = tpl.algo || 'RSA';
          tpAlgoChanged();
          $('tpBits').value = tpl.bits || '2048';
          $('tpHash').value = tpl.hash || 'sha256';
          const ku = tpl.keyusage || '';
          $('tpKu').value = String(ku).startsWith('C') ? 'custom' : String(ku);
          $('tpKuCustom').value = String(ku).startsWith('C') ? String(ku).substring(1) : '';
          kuSelChanged('tp');
          $('tpEu').value = tpl.exusage || '';
          $('tpPathLen').value = (!tpl.pathlen || tpl.pathlen === 'null') ? '' : String(tpl.pathlen);
          $('tpDays').value = tpl.days || '1';
          $('tpDns').value = tpl.dns || 'null';
          $('tpIps').value = tpl.ips || 'null';
          const POL_OIDS = {tpPolDv:'2.23.140.1.2.1',tpPolIv:'2.23.140.1.2.3',tpPolOv:'2.23.140.1.2.2',tpPolEv:'2.23.140.1.1',tpPolCsStd:'2.23.140.1.4.1',tpPolCsEv:'2.23.140.1.3',tpPolDoc:'1.3.6.1.5.5.7.3.36',tpPolTsa:'2.23.140.1.4.2'};
          const polSel = (tpl.policy || '').split(',').map(s => s.trim()).filter(Boolean);
          for (const k in POL_OIDS) { const c = $(k); if (c) c.checked = polSel.includes(POL_OIDS[k]); }
          // 模板中非预设的策略 OID 作为自定义策略回显（勾选状态）
          tplPolCustom = polSel.filter(o => !Object.values(POL_OIDS).includes(o)).map(o => ({oid: o, on: true}));
          renderTpPolCustom();
          parseDn('tp');
          $('tpSaveOut').hidden = true;
          $('tpModal').style.display = 'flex';
        }
        function closeTpModal() { $('tpModal').style.display = 'none'; }
        function tpCaChanged() {
          const isCa = $('tpCa').value === '1';
          $('tpPathLenWrap').style.display = isCa ? '' : 'none';
          $('tpPolWrap').style.display = isCa ? 'none' : '';
        }
        function tpAlgoChanged() {
          const algo = $('tpAlgo').value;
          const opts = BITS_OPT[algo] || [];
          const cur = $('tpBits').value;
          $('tpBits').innerHTML = opts.map(x => '<option>' + x + '</option>').join('');
          $('tpBits').value = opts.includes(cur) ? String(cur) : String(opts[0]);
          syncHashForAlgo(algo, $('tpHash'));
        }
        function tpPathLenVal() { return $('tpPathLen').value || 'null'; }
        // 自定义证书策略（模板弹窗）：{oid, on}，勾选的才写入证书策略扩展
        let tplPolCustom = [];
        function addTpPolCustom() {
          const oid = v('tpPolCustomOid').trim();
          if (!oid) { showOut('tpSaveOut', '请输入自定义策略 OID', false); return; }
          if (!/^(\\d+)(\\.\\d+)+$/.test(oid)) { showOut('tpSaveOut', 'OID 格式不正确（如 1.2.3.4.5）', false); return; }
          if (tplPolCustom.some(x => x.oid === oid)) { showOut('tpSaveOut', '该策略 OID 已添加', false); return; }
          tplPolCustom.push({oid: oid, on: true});
          $('tpPolCustomOid').value = '';
          renderTpPolCustom();
        }
        function delTpPolCustom(i) { tplPolCustom.splice(i, 1); renderTpPolCustom(); }
        function renderTpPolCustom() {
          const box = $('tpPolCustomBox');
          if (!box) return;
          box.innerHTML = tplPolCustom.map((x, i) =>
            '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding-top:6px">' +
            '<input type="checkbox" ' + (x.on ? 'checked' : '') + ' onchange="tplPolCustom[' + i + '].on=this.checked">' +
            '<span style="font-family:Consolas,monospace">' + esc(x.oid) + '</span>' +
            '<a style="color:#c0392b;cursor:pointer" onclick="delTpPolCustom(' + i + ')">删除</a></label>').join('');
        }
        function tpPolicyVal() {
          const ids = ['tpPolDv','tpPolIv','tpPolOv','tpPolEv','tpPolCsStd','tpPolCsEv','tpPolDoc','tpPolTsa'];
          const OIDS = {tpPolDv:'2.23.140.1.2.1',tpPolIv:'2.23.140.1.2.3',tpPolOv:'2.23.140.1.2.2',tpPolEv:'2.23.140.1.1',tpPolCsStd:'2.23.140.1.4.1',tpPolCsEv:'2.23.140.1.3',tpPolDoc:'1.3.6.1.5.5.7.3.36',tpPolTsa:'2.23.140.1.4.2'};
          const arr = ids.filter(id => $(id) && $(id).checked).map(id => OIDS[id]);
          (tplPolCustom || []).forEach(x => { if (x.on && !arr.includes(x.oid)) arr.push(x.oid); });
          return arr.join(',');
        }
        async function saveTemplate() {
          const p = {id: tplEditId || '', name: v('tpName'), ctype: v('tpCa'), dn: v('tpDn'),
            bits: v('tpBits'), hash: v('tpHash'), keyusage: kuVal('tp'), exusage: v('tpEu'),
            pathlen: tpPathLenVal(), policy: tpPolicyVal(), days: v('tpDays'),
            dns: v('tpDns'), ips: v('tpIps'), algo: v('tpAlgo')};
          try {
            const r = await api('/api/template/save', p);
            showOut('tpSaveOut', r.message || 'OK', !!r.ok);
            if (r.ok) { closeTpModal(); loadTemplates(); }
          } catch (e) { showOut('tpSaveOut', '请求异常: ' + e, false); }
        }

        // ===== 签署模板弹窗（选择 R/C 颁发者） =====
        let tplSignId = null;
        function openSignModal(id) {
          tplSignId = id;
          const tpl = tplData.find(x => String(x.id) === String(id)) || {};
          $('tpSignTitle').textContent = '签署模板 #' + id + (tpl.name ? '：' + tpl.name : '');
          $('tpSignInfo').innerHTML =
            '<b>模板：</b>#' + esc(id) + ' ' + esc(tpl.name || '') + '<br>' +
            '<b>证书类型：</b>' + (tpl.ctype === '1' ? '中间 CA' : '终端证书') + '<br>' +
            '<b>DN：</b>' + esc(tpl.dn || '') + '<br>' +
            '<b>算法：</b>' + esc(tpl.algo) + ' / ' + esc(tpl.bits) + ' / 哈希 ' + esc(tpl.hash);
          const sel = $('tpSignIssuer');
          sel.innerHTML = '<option value="">（请选择颁发者）</option>' +
            (certData || []).filter(e => e.type === 'R' || e.type === 'C').map(e =>
              '<option value="' + esc(e.serial) + '">' + esc(e.serial) + '（' + esc(typeName(e.type)) + '）</option>').join('');
          $('tpSignTip').innerHTML = '';
          const out = $('tpSignOut'); out.hidden = true; out.textContent = '';
          $('tpSignModal').style.display = 'flex';
        }
        function closeSignModal() { $('tpSignModal').style.display = 'none'; }
        function tpSignIssuerChanged() {
          const s = $('tpSignIssuer').value;
          $('tpSignTip').innerHTML = s ? certTip(s) : '';
        }
        async function signDo() {
          const issuer = v('tpSignIssuer');
          if (!issuer) { showOut('tpSignOut', '请先选择颁发者证书（类型 R/C）', false); return; }
          await postForm('/api/template/sign', {id: tplSignId, issuer: issuer}, 'tpSignOut');
        }

        // ===== 系统配置 =====
        async function loadConfig() {
          try {
            const r = await api('/api/config');
            if (!r.ok) { $('cfgState').textContent = '读取失败: ' + (r.message || ''); return; }
            const d = r.data;
            $('cfgWebport').value = d.webport;
            $('cfgSuport').value = d.suport;
            $('cfgOcsp').value = d.ocsp;
            $('cfgCrl').value = d.crl;
            $('cfgCrt').value = d.crt;
            $('cfgCps').value = d.cps;
            $('cfgCpsNonice').value = d.cpsNonice;
            $('cfgCtlogApi').value = d.ctlogApi || '/ct/add';
            $('cfgState').textContent = r.exists
              ? '已加载 PKI/CONFIG.txt'
              : 'PKI/CONFIG.txt 不存在，保存时将按默认模板创建';
            $('cfgOut').hidden = true;
          } catch (e) {
            $('cfgState').textContent = '读取失败: ' + e;
          }
        }
        async function saveConfigBtn(btn) {
          const el = $('cfgOut');
          el.hidden = false; el.className = 'out'; el.textContent = '保存中...';
          btn.disabled = true;
          try {
            const r = await api('/api/config', {
              webport: $('cfgWebport').value.trim(),
              suport: $('cfgSuport').value.trim(),
              ocsp: $('cfgOcsp').value.trim(),
              crl: $('cfgCrl').value.trim(),
              crt: $('cfgCrt').value.trim(),
              cps: $('cfgCps').value.trim(),
              cpsNonice: $('cfgCpsNonice').value.trim(),
              ctlogApi: $('cfgCtlogApi').value
            });
            showOut('cfgOut', r.message || 'OK', !!r.ok);
            if (r.ok) $('cfgState').textContent = '已保存 PKI/CONFIG.txt';
          } catch (e) {
            showOut('cfgOut', '请求失败: ' + e, false);
          } finally {
            btn.disabled = false;
          }
        }
        // CTLOGapi 下拉变更：实时保存（同时携带其它字段当前值，避免覆盖）
        async function saveCtlogApi() {
          const el = $('cfgOut');
          el.hidden = false; el.className = 'out'; el.textContent = '保存中...';
          try {
            const r = await api('/api/config', {
              webport: $('cfgWebport').value.trim(),
              suport: $('cfgSuport').value.trim(),
              ocsp: $('cfgOcsp').value.trim(),
              crl: $('cfgCrl').value.trim(),
              crt: $('cfgCrt').value.trim(),
              cps: $('cfgCps').value.trim(),
              cpsNonice: $('cfgCpsNonice').value.trim(),
              ctlogApi: $('cfgCtlogApi').value
            });
            showOut('cfgOut', r.message || 'OK', !!r.ok);
            if (r.ok) $('cfgState').textContent = '已保存 PKI/CONFIG.txt（CTLOGapi=' + $('cfgCtlogApi').value + '）';
          } catch (e) {
            showOut('cfgOut', '请求失败: ' + e, false);
          }
        }
        setInterval(() => {
          if ($('logAuto') && $('logAuto').checked && $('page-logs').classList.contains('active')) loadLogs();
          loadStatus();   // 任意页面都刷新状态徽章（内部已按页面判空）
        }, 3000);

        // ===== 启动 =====
        loadStatus();
        loadChain();
        loadIssuers();
        loadCerts();

        // 证书库「详情 / 验证 / 操作」按钮：事件委托，避免内联 onclick 引号转义问题
        $('certsTable').querySelector('tbody').addEventListener('click', function (ev) {
          const btn = ev.target.closest ? ev.target.closest('button[data-serial]') : null;
          if (btn) showDetail(btn.getAttribute('data-serial'));
          const vbtn = ev.target.closest ? ev.target.closest('button[data-verify]') : null;
          if (vbtn) openVerify(vbtn.getAttribute('data-verify'));
          const obtn = ev.target.closest ? ev.target.closest('button[data-op]') : null;
          if (obtn) openOp(obtn.getAttribute('data-op'));
        });
        // 双击证书库任意行：直接弹出该证书的层次查看器
        $('certsTable').querySelector('tbody').addEventListener('dblclick', function (ev) {
          const tr = ev.target.closest ? ev.target.closest('tr') : null;
          if (!tr) return;
          const btn = tr.querySelector('button[data-serial]');
          if (btn) viewChainCert(btn.getAttribute('data-serial'));
        });

        // 可信公网证书库 cacerts 表格：详情按钮事件委托
        $('caTable').querySelector('tbody').addEventListener('click', function (ev) {
          const btn = ev.target.closest ? ev.target.closest('button[data-serial]') : null;
          if (btn) showDetail(btn.getAttribute('data-serial'), 'cacerts');
        });
        $('caTable').querySelector('tbody').addEventListener('dblclick', async function (ev) {
          if (ev.target.closest && ev.target.closest('button')) return;
          const tr = ev.target.closest ? ev.target.closest('tr') : null;
          if (!tr) return;
          const btn = tr.querySelector('button[data-serial]');
          if (!btn) return;
          try {
            const r = await api('/api/certjson?serial=' + encodeURIComponent(btn.getAttribute('data-serial')));
            if (r.ok) MODPKICACERTVIERW(r.data, { noRevokeCheck: true });
          } catch (e) { /* ignore */ }
        });

        // 我的证书表格：详情 / 验证 / 删除 事件委托
        $('myTable').querySelector('tbody').addEventListener('click', function (ev) {
          const btn = ev.target.closest ? ev.target.closest('button[data-mserial]') : null;
          if (!btn) return;
          const serial = btn.getAttribute('data-mserial');
          const act = btn.getAttribute('data-act') || '';
          if (act === 'detail') showDetail(serial, 'my');
          else if (act === 'verify') openVerify(serial);
          else if (act === 'del') myAskDelete(serial);
        });
        $('myTable').querySelector('tbody').addEventListener('dblclick', function (ev) {
          if (ev.target.closest && ev.target.closest('button')) return;
          const tr = ev.target.closest ? ev.target.closest('tr') : null;
          if (!tr) return;
          const btn = tr.querySelector('button[data-mserial]');
          if (btn) viewChainCert(btn.getAttribute('data-mserial'));
        });

        // ===== 证书库右键菜单：下载证书 / 导出证书 =====
        let ctxSerial = '', ctxSrc = 'certs', ctxKind = '';
        function ctxMenuShow(ev, serial, src) {
          ev.preventDefault();
          ctxSerial = serial; ctxSrc = src;
          const m = $('ctxMenu');
          m.style.display = 'block';
          m.style.visibility = 'hidden';
          const mw = m.offsetWidth || 260;
          const mh = m.offsetHeight || 120;
          m.style.visibility = '';
          const gap = 4, subW = 300, subH = 280;
          let x = ev.clientX + gap, y = ev.clientY + gap;
          if (x + mw + subW > window.innerWidth - gap) x = Math.max(gap, ev.clientX - mw - gap);
          if (y + mh > window.innerHeight - gap) y = Math.max(gap, window.innerHeight - mh - gap);
          m.style.left = x + 'px';
          m.style.top = y + 'px';
          const subUp = (y + mh + subH > window.innerHeight - gap);
          m.querySelectorAll('.ctx-sub').forEach(function (el) {
            el.classList.toggle('ctx-sub-up', subUp);
            el.style.display = 'none';
          });
          const noKey = src === 'cacerts';
          document.querySelectorAll('#ctxMenu [data-needkey]').forEach(function (el) {
            el.classList.toggle('disabled', noKey);
          });
          document.querySelectorAll('#ctxMenu [data-ctxsrc]').forEach(function (el) {
            el.style.display = el.getAttribute('data-ctxsrc') === src ? '' : 'none';
          });
        }
        function ctxMenuHide() { const m = $('ctxMenu'); if (m) m.style.display = 'none'; }
        function ctxDownload(kind, needPwd) {
          if (needPwd) { openCtxPwd(kind); return; }
          doCtxDownload(kind, '');
        }
        function doCtxDownload(kind, pwd) {
          const u = '/api/cert/download?serial=' + encodeURIComponent(ctxSerial) + '&kind=' + kind +
            '&src=' + encodeURIComponent(ctxSrc) + (pwd ? '&password=' + encodeURIComponent(pwd) : '');
          fetch(u).then(function (r) {
            if (!r.ok) return r.json().then(function (j) { throw new Error(j.message || '下载失败'); });
            return r.blob();
          }).then(function (b) {
            const ext = { single_crt: '.crt', chain_crt: '.crt', issuer_crt: '.crt', p7b: '.p7b', key: '.key', pfx: '.pfx', jks: '.jks' }[kind] || '';
            const a = document.createElement('a');
            a.href = URL.createObjectURL(b);
            a.download = ctxSerial + ext;
            document.body.appendChild(a); a.click(); a.remove();
            setTimeout(function () { URL.revokeObjectURL(a.href); }, 5000);
            ctxMenuHide();
          }).catch(function (err) { ctxToast(String(err && err.message ? err.message : err), false); });
        }
        function ctxExport(kind) {
          const u = '/api/cert/export?serial=' + encodeURIComponent(ctxSerial) + '&kind=' + kind +
            '&src=' + encodeURIComponent(ctxSrc);
          fetch(u).then(function (r) { return r.json(); }).then(function (j) {
            if (!j.ok) throw new Error(j.message || '导出失败');
            const legacyCopy = function (text) {
              const ta = document.createElement('textarea');
              ta.value = text;
              ta.style.cssText = 'position:fixed;left:-9999px;top:0;opacity:0;width:1px;height:1px';
              document.body.appendChild(ta);
              ta.focus(); ta.select();
              let ok = false;
              try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
              ta.remove();
              if (ok) { ctxToast('已复制到剪贴板'); ctxMenuHide(); }
              else { showCtxCopyPanel(text); }
            };
            if (navigator.clipboard && navigator.clipboard.writeText) {
              navigator.clipboard.writeText(j.text)
                .then(function () { ctxToast('已复制到剪贴板'); ctxMenuHide(); })
                .catch(function () { legacyCopy(j.text); });
            } else {
              legacyCopy(j.text);
            }
          }).catch(function (err) { ctxToast(String(err && err.message ? err.message : err), false); });
        }
        // 全局悬浮提示（不依赖任何页面元素）
        function ctxToast(msg, ok) {
          let t = document.getElementById('ctxToast');
          if (!t) {
            t = document.createElement('div');
            t.id = 'ctxToast';
            t.style.cssText = 'position:fixed;left:50%;top:64px;transform:translateX(-50%);z-index:999999;padding:12px 24px;border-radius:8px;font-size:14px;font-weight:600;box-shadow:0 8px 28px rgba(0,0,0,.5);background:var(--panel2);border:1px solid var(--border);color:var(--ok);pointer-events:none;opacity:0;transition:opacity .2s;max-width:70vw;word-break:break-all';
            document.body.appendChild(t);
          }
          t.textContent = msg;
          t.style.color = ok === false ? 'var(--err)' : 'var(--ok)';
          t.style.borderColor = ok === false ? 'var(--err)' : 'var(--ok)';
          t.style.opacity = '1';
          clearTimeout(t._t);
          t._t = setTimeout(function () { t.style.opacity = '0'; }, 2600);
        }
        // 剪贴板自动授权失败时的手动复制面板
        function showCtxCopyPanel(text) {
          const ta = $('ctxCopyText');
          if (!ta) { ctxToast('复制失败，请手动复制', false); return; }
          ta.value = text;
          $('ctxCopyModal').style.display = 'flex';
          setTimeout(function () { ta.focus(); ta.select(); }, 60);
        }
        function closeCtxCopy() { $('ctxCopyModal').style.display = 'none'; }
        function ctxCopyTextarea() {
          const ta = $('ctxCopyText');
          ta.focus(); ta.select();
          let ok = false;
          try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
          if (ok) { ctxToast('已复制到剪贴板'); closeCtxCopy(); ctxMenuHide(); }
          else { ctxToast('复制失败，请手动 Ctrl+C', false); }
        }
        // 右键下载 pfx / jks 密码输入
        function openCtxPwd(kind) {
          ctxKind = kind;
          $('ctxPwdFile').textContent = '序列号：' + ctxSerial + '，将导出 ' +
            (kind === 'pfx' ? '.pfx (PKCS12)' : '.jks (Java KeyStore)') + '，含证书链与私钥';
          $('ctxPwd').value = '';
          $('ctxPwdModal').style.display = 'flex';
          setTimeout(function () { $('ctxPwd').focus(); }, 60);
        }
        function closeCtxPwd() { $('ctxPwdModal').style.display = 'none'; }
        function ctxPwdOk() {
          const p = $('ctxPwd').value;
          closeCtxPwd();
          doCtxDownload(ctxKind, p);
        }
        // 右键删除证书（仅 CERTS.txt）：确定后在台账中注释该行，不删除任何文件
        function ctxDeleteCert() {
          if (ctxSrc !== 'certs' || !ctxSerial) return;
          $('ctxDelSerial').textContent = ctxSerial;
          $('ctxDelModal').style.display = 'flex';
        }
        function ctxDelCancel() { $('ctxDelModal').style.display = 'none'; }
        async function ctxDelOk() {
          const s = ($('ctxDelSerial').textContent || '').trim();
          ctxDelCancel();
          if (!s) return;
          try {
            const r = await api('/api/certs/delete', { serial: s });
            if (r.ok) {
              ctxToast('已删除证书 ' + s + '（CERTS.txt 行已注释，生成 CRL/OCSP 时跳过）');
              loadCerts();
            } else {
              ctxToast(r.message || '删除失败', false);
            }
          } catch (e) { ctxToast('删除请求异常：' + e, false); }
        }
        // 三个证书库列表：右键菜单绑定
        [['certsTable', 'certs'], ['caTable', 'cacerts'], ['myTable', 'my']].forEach(function (p) {
          const tb = document.getElementById(p[0]).querySelector('tbody');
          tb.addEventListener('contextmenu', function (ev) {
            const tr = ev.target.closest ? ev.target.closest('tr') : null;
            if (!tr || !tr.dataset.serial) return;
            ctxMenuShow(ev, tr.dataset.serial, p[1]);
          });
        });
        // 子菜单显隐：mouseenter 显示；mouseleave 延迟隐藏，鼠标移入子菜单途中不消失
        document.querySelectorAll('#ctxMenu .ctx-item.has-sub').forEach(function (li) {
          const sub = li.querySelector('.ctx-sub');
          if (!sub) return;
          const show = function () { clearTimeout(sub._t); sub.style.display = 'block'; };
          const hide = function () { clearTimeout(sub._t); sub.style.display = 'none'; };
          li.addEventListener('mouseenter', show);
          li.addEventListener('mouseleave', function () {
            clearTimeout(sub._t); sub._t = setTimeout(hide, 240);
          });
          sub.addEventListener('mouseenter', function () { clearTimeout(sub._t); });
          sub.addEventListener('mouseleave', function () {
            clearTimeout(sub._t); sub._t = setTimeout(hide, 160);
          });
        });
        document.addEventListener('click', function (ev) {
          const m = $('ctxMenu');
          if (m && !m.contains(ev.target)) ctxMenuHide();
        });
        document.addEventListener('scroll', ctxMenuHide, true);
        window.addEventListener('resize', ctxMenuHide);
        </script>
        </body>





    """;
    private static final String PAGE_P3 = """
        <script>
        // ===== 调试专区：模拟 OCSP / 时间戳请求 =====
        async function sendDebugOcsp() {
          const out = $('dbgOcspOut');
          out.hidden = false; out.className = 'out'; out.textContent = '正在构造标准 OCSP 请求并发送...';
          try {
            const r = await api('/api/debug/ocsp', {
              serial: $('dbgOcspSerial').value.trim(),
              hash: $('dbgOcspHash').value
            });
            out.className = 'out ' + (r.ok ? 'ok' : 'err');
            out.textContent = r.message || '(无输出)';
          } catch (e) {
            out.className = 'out err';
            out.textContent = '请求失败: ' + e;
          }
        }
        async function sendDebugTsa() {
          const out = $('dbgTsaOut');
          out.hidden = false; out.className = 'out'; out.textContent = '正在构造标准 RFC3161 请求并发送...';
          try {
            const r = await api('/api/debug/tsa', { hash: $('dbgTsaHash').value });
            out.className = 'out ' + (r.ok ? 'ok' : 'err');
            out.textContent = r.message || '(无输出)';
          } catch (e) {
            out.className = 'out err';
            out.textContent = '请求失败: ' + e;
          }
        }

        // ===== SCT 服务管理 =====
        // ===== 用户管理（PKI/USERS.txt） =====
        let userData = [];
        async function loadUsers() {
          try {
            const r = await api('/api/users/list');
            const tb = $('userTable').querySelector('tbody');
            if (!r.ok) { tb.innerHTML = '<tr><td colspan="7">加载失败</td></tr>'; return; }
            userData = r.users || [];
            tb.innerHTML = userData.map(u => `
              <tr>
                <td>${u.index}</td>
                <td style="color:var(--accent)">${esc(u.username)}</td>
                <td style="font-family:var(--mono)">${esc(u.password)}</td>
                <td><span class="badge ${u.enabled ? 'ok' : 'err'}">${u.enabled ? 'E.启用' : 'D.停用'}</span></td>
                <td>${esc(u.group)}</td>
                <td>${esc(u.note)}</td>
                <td>
                  <button class="ghost" onclick="editUser('${esc(u.username)}')">编辑</button>
                  <button class="ghost" onclick="toggleUserState('${esc(u.username)}',${u.enabled})">${u.enabled ? '停用' : '启用'}</button>
                  <button class="danger" onclick="delUser('${esc(u.username)}')">删除</button>
                </td>
              </tr>`).join('') || '<tr><td colspan="7" style="color:var(--dim)">暂无用户，点击“+ 添加用户”创建</td></tr>';
          } catch (e) { showOut('userOut', '加载用户失败: ' + e, false); }
        }
        let userEditName = null;
        function openUserModal() {
          userEditName = null;
          $('userModalTitle').textContent = '添加用户';
          $('uName').value = ''; $('uPass').value = ''; $('uState').value = 'E';
          $('uGroup').value = ''; $('uNote').value = '';
          $('uOut').hidden = true;
          $('userModal').style.display = 'flex';
        }
        function editUser(name) {
          const u = userData.find(x => x.username === name);
          if (!u) return;
          userEditName = name;
          $('userModalTitle').textContent = '编辑用户';
          $('uName').value = u.username; $('uPass').value = u.password;
          $('uState').value = u.state || 'E'; $('uGroup').value = u.group || ''; $('uNote').value = u.note || '';
          $('uOut').hidden = true;
          $('userModal').style.display = 'flex';
        }
        function closeUserModal() { $('userModal').style.display = 'none'; }
        async function saveUser() {
          const name = $('uName').value.trim();
          if (!name) { showOut('uOut', '用户名不能为空', false); return; }
          const body = { username: name, password: $('uPass').value, state: $('uState').value, group: $('uGroup').value.trim(), note: $('uNote').value.trim() };
          try {
            const r = await api(userEditName ? '/api/users/update' : '/api/users/add', userEditName ? Object.assign({ old_username: userEditName }, body) : body);
            showOut('uOut', r.message || '操作完成', r.ok);
            if (r.ok) { closeUserModal(); loadUsers(); }
          } catch (e) { showOut('uOut', '操作失败: ' + e, false); }
        }
        async function toggleUserState(name, enabled) {
          try {
            const r = await api('/api/users/status', { username: name, state: enabled ? 'D' : 'E' });
            showOut('userOut', r.message || '操作完成', r.ok);
            loadUsers();
          } catch (e) { showOut('userOut', '操作失败: ' + e, false); }
        }
        let delUserName = null;
        function delUser(name) {
          delUserName = name;
          $('delUserMsg').textContent = '是否删除 用户 ' + name + ' ？（USERS.txt 中该行将加 # 注释，保留原行）';
          $('delUserModal').style.display = 'flex';
        }
        function closeDelUserModal() { $('delUserModal').style.display = 'none'; }
        async function doDelUser() {
          try {
            const r = await api('/api/users/delete', { username: delUserName });
            showOut('userOut', r.message || '操作完成', r.ok);
            if (r.ok) { closeDelUserModal(); loadUsers(); }
          } catch (e) { showOut('userOut', '删除失败: ' + e, false); }
        }

        // ===== Radius 服务管理 =====
        let radTimer = null;
        async function loadRadius() {
          try {
            loadRadCerts();
            const r = await api('/api/radius/status');
            if (!r.ok) return;
            const st = $('radState');
            st.textContent = r.running ? '● 运行中' : '○ 未运行';
            st.className = 'badge ' + (r.running ? 'ok' : 'err');
            $('radAuthPort').value = r.cfgAuthPort || 1812;
            $('radAcctPort').value = r.cfgAcctPort || 1813;
            $('radSecret').value = r.cfgSecret || '';
            $('radAuto').checked = !!r.cfgAuto;
            $('radAccounts').textContent = r.accounts;
            $('radReq').textContent = r.totalAuthRequests;
            $('radOk').textContent = r.authOk;
            $('radFail').textContent = r.authFail;
            $('radAcct').textContent = r.totalAcct;
            $('radStart').textContent = r.startTimeText || '-';
            if (r.running) { loadRadiusLogs(); startRadAutoRefresh(); }
          } catch (e) { showOut('radOut', '加载状态失败: ' + e, false); }
        }
        let radCertLoaded = false;
        async function loadRadCerts() {
          if (radCertLoaded) return;
          try {
            const r = await api('/api/certs');
            const sel = $('radCert');
            if (!sel || !r.ok || !r.data) { return; }
            const cur = sel.value;
            sel.innerHTML = '<option value="">（默认·匿名）</option>';
            (r.data || []).forEach(function (c) {
              if (!c.serial) return;
              const o = document.createElement('option');
              o.value = c.serial;
              o.textContent = c.serial + ' · ' + (c.algo || '') + ' · ' + (c.type || '');
              sel.appendChild(o);
            });
            radCertLoaded = true;
            if (cur) sel.value = cur;
          } catch (e) { /* 证书列表加载失败不影响调试 */ }
        }
        async function radiusStart() {
          try {
            const body = { auth_port: $('radAuthPort').value.trim(), acct_port: $('radAcctPort').value.trim(), secret: $('radSecret').value.trim() };
            const r = await api('/api/radius/start', body);
            showOut('radOut', r.message || '启动完成', r.ok);
            loadRadius();
          } catch (e) { showOut('radOut', '启动失败: ' + e, false); }
        }
        async function radiusStop() {
          try {
            const r = await api('/api/radius/stop', {});
            showOut('radOut', r.message || '停止完成', r.ok);
            loadRadius();
          } catch (e) { showOut('radOut', '停止失败: ' + e, false); }
        }
        async function radiusReset() {
          try {
            const r = await api('/api/radius/reset', {});
            showOut('radOut', r.message || '清零完成', r.ok);
            loadRadius();
          } catch (e) { showOut('radOut', '清零失败: ' + e, false); }
        }
        async function radiusSaveCfg() {
          try {
            const body = { auth_port: $('radAuthPort').value.trim(), acct_port: $('radAcctPort').value.trim(), secret: $('radSecret').value.trim(), auto: $('radAuto').checked ? 'on' : 'off' };
            const r = await api('/api/radius/config', body);
            showOut('radOut', r.message || '保存完成', r.ok);
            loadRadius();
          } catch (e) { showOut('radOut', '保存失败: ' + e, false); }
        }
        // 自动刷新专用：只更新状态徽章 / 统计数字 / 服务日志，
        // 绝不回填端口、共享密钥、自动启动等表单控件（用户编辑中不被 3 秒定时覆盖）
        async function refreshRadiusStatus() {
          try {
            const r = await api('/api/radius/status');
            if (!r.ok) return;
            const st = $('radState');
            st.textContent = r.running ? '● 运行中' : '○ 未运行';
            st.className = 'badge ' + (r.running ? 'ok' : 'err');
            $('radAccounts').textContent = r.accounts;
            $('radReq').textContent = r.totalAuthRequests;
            $('radOk').textContent = r.authOk;
            $('radFail').textContent = r.authFail;
            $('radAcct').textContent = r.totalAcct;
            $('radStart').textContent = r.startTimeText || '-';
            if (r.running) loadRadiusLogs();
          } catch (e) { }
        }
        async function loadRadiusLogs() {
          try {
            const r = await api('/api/radius/logs?lines=200');
            const tb = $('radLogTable').querySelector('tbody');
            if (!r.ok) { tb.innerHTML = '<tr><td colspan="3">加载失败</td></tr>'; return; }
            tb.innerHTML = (r.logs || []).map(l => '<tr><td>' + l.id + '</td><td style="color:var(--dim)">' + esc(l.time) + '</td><td>' + esc(l.message) + '</td></tr>').join('')
              || '<tr><td colspan="3" style="color:var(--dim)">暂无日志</td></tr>';
          } catch (e) { }
        }
        async function radiusClearLogs() {
          try {
            const r = await api('/api/radius/clearlogs', {});
            ctxToast(r.ok !== false ? (r.message || '日志已清空') : '清空失败', r.ok === false);
            loadRadiusLogs();
            loadRadius();
          } catch (e) { ctxToast('清空失败: ' + e, false); }
        }
        function startRadAutoRefresh() {
          stopRadAutoRefresh();
          radTimer = setInterval(() => {
            if ($('radAutoRefresh') && $('radAutoRefresh').checked && document.getElementById('page-radius').classList.contains('active')) refreshRadiusStatus();
          }, 3000);
        }
        function stopRadAutoRefresh() { if (radTimer) { clearInterval(radTimer); radTimer = null; } }
        function radAutoRefreshToggle() { if ($('radAutoRefresh').checked) startRadAutoRefresh(); else stopRadAutoRefresh(); }
        function radTab(t) {
          document.querySelectorAll('#radTabs .sig-tab').forEach(function(b){ b.classList.toggle('active', b.getAttribute('data-tab')===t); });
          $('radServer').style.display = t === 'server' ? 'block' : 'none';
          $('radClient').style.display = t === 'client' ? 'block' : 'none';
          if (t === 'client') {
            if (!$('radDialSecret').value) $('radDialSecret').value = $('radSecret').value || 'mytestkey';
            if (!$('radDialPort').value) $('radDialPort').value = $('radAuthPort').value || '1812';
          }
        }
        async function radClientDial() {
          try {
            const body = { method: $('radMethod').value, user: $('radUser').value.trim(), pass: $('radPass').value, secret: $('radDialSecret').value.trim(), port: $('radDialPort').value.trim(), cert: $('radCert').value };
            if (!body.user || !body.pass) { showOut('radDialOut', '请填写用户名与密码', false); return; }
            const r = await api('/api/radius/dial', body);
            showOut('radDialOut', r.message || '无输出', r.ok);
            loadRadius();
          } catch (e) { showOut('radDialOut', '调试失败: ' + e, false); }
        }

        // ===== PPPoE 服务管理（RFC 2516） =====
        let pppoeTimer = null;
        function pppoeTab(t) {
          document.querySelectorAll('#pppoeTabs .sig-tab').forEach(function(b){ b.classList.toggle('active', b.getAttribute('data-tab')===t); });
          $('pppoeServer').style.display = t === 'server' ? 'block' : 'none';
          $('pppoeClient').style.display = t === 'client' ? 'block' : 'none';
        }
        async function loadPppoe() {
          try {
            const r = await api('/api/pppoe/status');
            if (!r.ok) return;
            const st = $('pppoeState');
            st.textContent = r.running ? '● 运行中' : '○ 未运行';
            st.className = 'badge ' + (r.running ? 'ok' : 'err');
            $('pppoeDiscPort').value = r.discPort || 512;
            $('pppoeSessPort').value = r.sessPort || 513;
            $('pppoeAuto').checked = !!r.cfgAuto;
            $('pppoeAccounts').textContent = r.accounts;
            $('pppoeReq').textContent = r.totalAuth;
            $('pppoeOk').textContent = r.authOk;
            $('pppoeFail').textContent = r.authFail;
            $('pppoeSess').textContent = r.activeSessions;
            $('pppoeAcName').textContent = r.acName || '-';
            $('pppoeStart').textContent = r.startTimeText || '-';
            if (r.running) { loadPppoeLogs(); startPppoeAutoRefresh(); }
          } catch (e) { showOut('pppoeOut', '加载状态失败: ' + e, false); }
        }
        async function pppoeStart() {
          try {
            const body = { disc_port: $('pppoeDiscPort').value.trim(), sess_port: $('pppoeSessPort').value.trim() };
            const r = await api('/api/pppoe/start', body);
            showOut('pppoeOut', r.message || '启动完成', r.ok);
            loadPppoe();
          } catch (e) { showOut('pppoeOut', '启动失败: ' + e, false); }
        }
        async function pppoeStop() {
          try {
            const r = await api('/api/pppoe/stop', {});
            showOut('pppoeOut', r.message || '停止完成', r.ok);
            loadPppoe();
          } catch (e) { showOut('pppoeOut', '停止失败: ' + e, false); }
        }
        async function pppoeReset() {
          try {
            const r = await api('/api/pppoe/reset', {});
            showOut('pppoeOut', r.message || '清零完成', r.ok);
            loadPppoe();
          } catch (e) { showOut('pppoeOut', '清零失败: ' + e, false); }
        }
        async function pppoeSaveCfg() {
          try {
            const body = { disc_port: $('pppoeDiscPort').value.trim(), sess_port: $('pppoeSessPort').value.trim(), auto: $('pppoeAuto').checked ? 'on' : 'off' };
            const r = await api('/api/pppoe/config', body);
            showOut('pppoeOut', r.message || '保存完成', r.ok);
            loadPppoe();
          } catch (e) { showOut('pppoeOut', '保存失败: ' + e, false); }
        }
        // 自动刷新专用：只更新状态徽章 / 统计数字 / 服务日志，不回填表单控件
        async function refreshPppoeStatus() {
          try {
            const r = await api('/api/pppoe/status');
            if (!r.ok) return;
            const st = $('pppoeState');
            st.textContent = r.running ? '● 运行中' : '○ 未运行';
            st.className = 'badge ' + (r.running ? 'ok' : 'err');
            $('pppoeAccounts').textContent = r.accounts;
            $('pppoeReq').textContent = r.totalAuth;
            $('pppoeOk').textContent = r.authOk;
            $('pppoeFail').textContent = r.authFail;
            $('pppoeSess').textContent = r.activeSessions;
            $('pppoeAcName').textContent = r.acName || '-';
            $('pppoeStart').textContent = r.startTimeText || '-';
            if (r.running) loadPppoeLogs();
          } catch (e) { }
        }
        async function loadPppoeLogs() {
          try {
            const r = await api('/api/pppoe/logs?lines=200');
            const tb = $('pppoeLogTable').querySelector('tbody');
            if (!r.ok) { tb.innerHTML = '<tr><td colspan="3">加载失败</td></tr>'; return; }
            tb.innerHTML = (r.logs || []).map(l => '<tr><td>' + l.id + '</td><td style="color:var(--dim)">' + esc(l.time) + '</td><td>' + esc(l.message) + '</td></tr>').join('')
              || '<tr><td colspan="3" style="color:var(--dim)">暂无日志</td></tr>';
          } catch (e) { }
        }
        async function pppoeClearLogs() {
          try {
            const r = await api('/api/pppoe/clearlogs', {});
            ctxToast(r.ok !== false ? (r.message || '日志已清空') : '清空失败', r.ok === false);
            loadPppoeLogs();
            loadPppoe();
          } catch (e) { ctxToast('清空失败: ' + e, false); }
        }
        function startPppoeAutoRefresh() {
          stopPppoeAutoRefresh();
          pppoeTimer = setInterval(() => {
            if ($('pppoeAutoRefresh') && $('pppoeAutoRefresh').checked && document.getElementById('page-pppoe').classList.contains('active')) refreshPppoeStatus();
          }, 3000);
        }
        function stopPppoeAutoRefresh() { if (pppoeTimer) { clearInterval(pppoeTimer); pppoeTimer = null; } }
        function pppoeAutoRefreshToggle() { if ($('pppoeAutoRefresh').checked) startPppoeAutoRefresh(); else stopPppoeAutoRefresh(); }
        async function pppoeDial() {
          const u = $('pppoeUser').value.trim();
          const p = $('pppoePass').value;
          const m = $('pppoeMethod').value;
          if (!u || !p) { showOut('pppoeDialOut', '用户名和密码不能为空', false); return; }
          showOut('pppoeDialOut', '正在拨号...\\n', true);
          try {
            const r = await api('/api/pppoe/dial', { username: u, password: p, method: m });
            showOut('pppoeDialOut', r.message || '拨号完成', r.ok);
            if (r.ok) { loadPppoe(); loadPppoeLogs(); }
          } catch (e) { showOut('pppoeDialOut', '拨号异常: ' + e, false); }
        }

        async function loadCtLog() { loadCtKeys(); loadCtLogs(); loadCtPub(); }
        function ctSwitchTab(t) {
          document.getElementById('ctTabBtnKeys').className = 'ct-tab' + (t==='keys' ? ' active' : '');
          document.getElementById('ctTabBtnLogs').className = 'ct-tab' + (t==='logs' ? ' active' : '');
          document.getElementById('ctTabBtnPub').className = 'ct-tab' + (t==='pub' ? ' active' : '');
          document.getElementById('ctTabBtnTree').className = 'ct-tab' + (t==='tree' ? ' active' : '');
          document.getElementById('ctTabBtnV1').className = 'ct-tab' + (t==='v1debug' ? ' active' : '');
          document.getElementById('ctPaneKeys').style.display = t==='keys' ? '' : 'none';
          document.getElementById('ctPaneLogs').style.display = t==='logs' ? '' : 'none';
          document.getElementById('ctPanePub').style.display = t==='pub' ? '' : 'none';
          document.getElementById('ctPaneTree').style.display = t==='tree' ? '' : 'none';
          document.getElementById('ctPaneV1Debug').style.display = t==='v1debug' ? '' : 'none';
          if (t==='keys') loadCtKeys();
          else if (t==='logs') loadCtLogs();
          else if (t==='pub') loadCtPub();
          else if (t==='tree') loadCtTree();
          else if (t==='v1debug') v1ShowForm();
        }
        async function loadCtKeys() {
          try {
            const r = await api('/api/ctlog/list');
            if (!r.ok) return;
            const tb = $('ctKeysTable').querySelector('tbody');
            tb.innerHTML = '';
            (r.keys || []).forEach(k => {
              const tr = document.createElement('tr');
              const stTxt = k.state === 'usable' ? '可用（usable）' : '不可用（disable）';
              const stCls = k.state === 'usable' ? 'color:var(--ok);font-weight:700' : 'color:#dc2626;font-weight:700';
              tr.innerHTML = '<td><div>' + k.index + '</div></td>' +
                '<td><div>' + esc(k.description) + '</div></td>' +
                '<td><div>' + esc(k.type || 'ECDSA') + '</div></td>' +
                '<td><div style="font-family:var(--mono);font-size:12px">' + esc(k.logId) + '</div></td>' +
                '<td><div style="' + stCls + '">' + esc(stTxt) + '</div></td>' +
                '<td><div>' + esc(k.created) + '</div></td>' +
                '<td><div><button class="ghost" data-logid="' + esc(k.logId) + '" onclick="setCtState(this)">' + (k.state === 'usable' ? '暂停' : '启用') + '</button> ' +
                '<button class="ghost" data-logid="' + esc(k.logId) + '" onclick="delCtKey(this)">删除</button></div></td>';
              tb.appendChild(tr);
            });
          } catch (e) { const tb = $('ctKeysTable'); if (tb) tb.innerHTML = '<tr><td colspan="7" style="color:#dc2626;padding:8px">加载失败: ' + (e && e.message ? e.message : e) + '</td></tr>'; }
        }
        async function loadCtLogs() {
          try {
            const r = await api('/api/ctlog/logs');
            if (!r.ok) return;
            const tb = $('ctLogsTable').querySelector('tbody');
            tb.innerHTML = '';
            (r.logs || []).forEach((line, i) => {
              const tr = document.createElement('tr');
              tr.innerHTML = '<td><div style="color:var(--dim)">' + (i + 1) + '</div></td>' +
                '<td><div style="font-family:var(--mono);font-size:12px">' + esc(line) + '</div></td>';
              tb.appendChild(tr);
            });
          } catch (e) { const tb = $('ctLogsTable'); if (tb) tb.innerHTML = '<tr><td colspan="2" style="color:#dc2626;padding:8px">加载失败: ' + (e && e.message ? e.message : e) + '</td></tr>'; }
        }
        const CT_PUB_STATES = { usable: '可用（usable）', readonly: '只读（readonly）', retired: '退役（retired）', pending: '待定（pending）', rejected: '拒绝（rejected）' };
        async function loadCtPub() {
          try {
            const r = await api('/api/ctlog/public');
            if (!r.ok) return;
            $('ctPubDate').textContent = r.timestamp || '-';
            const tb = $('ctPubTable').querySelector('tbody');
            tb.innerHTML = '';
            (r.logs || []).forEach(k => {
              const tr = document.createElement('tr');
              const stTxt = CT_PUB_STATES[k.state] || k.state || '未知';
              const stCls = k.state === 'usable' ? 'color:var(--ok);font-weight:700' : 'color:#d97706;font-weight:700';
              tr.innerHTML = '<td><div>' + k.index + '</div></td>' +
                '<td><div>' + esc(k.description) + '</div></td>' +
                '<td><div style="font-family:var(--mono);font-size:12px">' + esc(k.logId) + '</div></td>' +
                '<td><div style="' + stCls + '">' + esc(stTxt) + '</div></td>' +
                '<td><div style="font-family:var(--mono);font-size:12px">' + esc(k.url) + '</div></td>';
              tb.appendChild(tr);
            });
          } catch (e) { const tb = $('ctPubTable'); if (tb) tb.innerHTML = '<tr><td colspan="5" style="color:#dc2626;padding:8px">加载失败: ' + (e && e.message ? e.message : e) + '</td></tr>'; }
        }
        async function fetchCtPub() {
          const msg = $('ctPubMsg');
          if (msg) msg.textContent = '正在拉取…';
          try {
            const r = await api('/api/ctlog/publicFetch', {});
            if (r.ok) { if (msg) msg.textContent = r.message || '已更新'; loadCtPub(); }
            else { if (msg) msg.textContent = '拉取失败: ' + (r.message || ''); }
          } catch (e) { if (msg) msg.textContent = '拉取异常: ' + e; }
        }
        async function genCtKey(type) {
          const desc = $('ctDesc').value.trim();
          $('ctDesc').value = '';
          const r = await api('/api/ctlog/gen', { desc: desc, type: type || 'ECDSA' });
          if (r.ok) { loadCtKeys(); ctTip('密钥对生成成功'); } else { ctTip('生成失败: ' + (r.message || ''), false); }
        }
        async function delCtKey(btn) {
          const id = btn.getAttribute('data-logid') || '';
          const r = await api('/api/ctlog/delete', { log_id: id });
          if (r.ok) { loadCtKeys(); ctTip('密钥对已删除'); } else { ctTip('删除失败: ' + (r.message || ''), false); }
        }
        async function setCtState(btn) {
          const id = btn.getAttribute('data-logid') || '';
          const pause = btn.textContent.trim() === '暂停';
          const r = await api(pause ? '/api/ctlog/pause' : '/api/ctlog/enable', { log_id: id });
          if (r.ok) { loadCtKeys(); ctTip(pause ? '密钥已暂停' : '密钥已启用'); } else { ctTip('操作失败: ' + (r.message || ''), false); }
        }
        function ctTip(msg, ok) {
          const el = $('ctMsg');
          if (!el) return;
          el.textContent = msg;
          el.style.color = ok === false ? '#dc2626' : 'var(--ok)';
          clearTimeout(ctTip._t);
          ctTip._t = setTimeout(() => { el.textContent = ''; }, 3500);
        }

        // ===== SCT 仪表盘（Merkle 树，crt.sh 风格） =====
        let CT_TREE_DATA = null;
        async function loadCtTree() {
          const msg = $('ctTreeMsg');
          if (msg) msg.textContent = '正在加载…';
          try {
            const r = await api('/api/ctlog/tree');
            CT_TREE_DATA = r;
            if (msg) msg.textContent = r.ok ? '' : ('加载失败: ' + (r.message || ''));
            const sel = $('ctTreeSel');
            const prev = sel.value;
            sel.innerHTML = '';
            (r.trees || []).forEach(t => {
              const o = document.createElement('option');
              o.value = t.logId;
              o.textContent = (t.description || t.logIdHex) + ' [' + (t.type || '') + '] 条目=' + t.entryCount + ' 状态=' + (t.state || '');
              sel.appendChild(o);
            });
            if (prev && Array.from(sel.options).some(o => o.value === prev)) sel.value = prev;
            ctRenderTree();
          } catch (e) {
            if (msg) msg.textContent = '加载异常: ' + e;
          }
        }
        function shortHash(h) {
          if (!h) return '-';
          return h.length > 24 ? h.slice(0, 12) + '…' + h.slice(-12) : h;
        }
        function ctRenderTree() {
          const sel = $('ctTreeSel');
          const tree = ((CT_TREE_DATA && CT_TREE_DATA.trees) || []).find(t => t.logId === sel.value) || null;
          const stats = $('ctTreeStats');
          const view = $('ctTreeView');
          const det = $('ctTreeDetail');
          det.style.display = 'none';
          if (!tree) {
            stats.innerHTML = '<div class="ct-tree-stat"><b>日志总数</b><span>' + (CT_TREE_DATA ? CT_TREE_DATA.treeCount : 0) + '</span></div>' +
              '<div class="ct-tree-stat"><b>总条目</b><span>' + (CT_TREE_DATA ? CT_TREE_DATA.totalEntries : 0) + '</span></div>';
            view.innerHTML = '<div style="color:var(--dim);padding:12px">暂无 Merkle 树数据 —— 使用 /ct/v1/add-chain 或 /ct/v1/add-pre-chain 提交证书后生成。</div>';
            return;
          }
          stats.innerHTML =
            '<div class="ct-tree-stat"><b>日志总数</b><span>' + (CT_TREE_DATA ? CT_TREE_DATA.treeCount : 0) + '</span></div>' +
            '<div class="ct-tree-stat"><b>总条目</b><span>' + (CT_TREE_DATA ? CT_TREE_DATA.totalEntries : 0) + '</span></div>' +
            '<div class="ct-tree-stat"><b>当前日志</b><span>' + esc(tree.description || tree.logIdHex) + '</span></div>' +
            '<div class="ct-tree-stat"><b>类型 / 状态</b><span>' + esc((tree.type || '-') + ' / ' + (tree.state || '-')) + '</span></div>' +
            '<div class="ct-tree-stat"><b>条目数</b><span>' + tree.entryCount + '</span></div>' +
            '<div class="ct-tree-stat"><b>Merkle 根</b><span title="' + esc(tree.rootHash) + '">' + esc(shortHash(tree.rootHash)) + '</span></div>';
          const nodes = tree.nodes || [];
          const entries = tree.entries || [];
          const rootNode = nodes.find(n => n.level === 0) || null;
          let html = '';
          if (rootNode) {
            html += ctTreeLine('root', 0, 'Root MTH [' + rootNode.start + ',' + rootNode.end + ')  ' + shortHash(rootNode.hash), rootNode.hash, null);
            html += ctRenderMth(nodes, entries, rootNode, 1);
          } else if (entries.length === 1) {
            html += ctTreeLine('root', 0, 'Root MTH（单叶子）  ' + shortHash(entries[0].leafHash), entries[0].leafHash, null);
            html += ctTreeLeaf(entries[0], 1);
          } else if (entries.length > 1) {
            html += '<div style="color:#dc2626;padding:8px">树内部节点缺失（computeMthNodes 失败）</div>';
            entries.forEach(e => { html += ctTreeLeaf(e, 1); });
          } else {
            html = '<div style="color:var(--dim);padding:12px">该日志树为空（0 个条目）。</div>';
          }
          view.innerHTML = html;
        }
        function ctRenderMth(nodes, entries, node, level) {
          let html = '';
          const children = nodes.filter(n => n.level === node.level + 1 && n.start >= node.start && n.end <= node.end);
          if (!children.length) {
            for (let i = node.start; i < node.end && i < entries.length; i++) {
              html += ctTreeLeaf(entries[i], level);
            }
            return html;
          }
          children.sort((a, b) => a.start - b.start);
          children.forEach(c => {
            html += ctTreeLine('node', level, '[' + c.start + ',' + c.end + ')  ' + shortHash(c.hash), c.hash, null);
            html += ctRenderMth(nodes, entries, c, level + 1);
          });
          return html;
        }
        function ctTreeLine(cls, level, text, hash, idx) {
          const pad = new Array(level * 4 + 1).join(' ');
          return '<div class="ct-tree-line ' + cls + '" data-hash="' + esc(hash || '') + '" onclick="ctTreeDetail(this)" title="' + esc(hash || '') + '">' + pad + '└─ ' + esc(text) + '</div>';
        }
        function ctTreeLeaf(e, level) {
          const pad = new Array(level * 4 + 1).join(' ');
          return '<div class="ct-tree-line ct-tree-leaf" data-index="' + e.index + '" onclick="ctTreeDetail(this)" title="leafHash: ' + esc(e.leafHash || '') + '">' + pad +
            '└─ [' + e.index + '] ' + esc(e.tsText) + ' ' + (e.entryType === 'precert' ? '预证书' : 'x509') +
            ' SN=<span class="sn">' + esc(e.serial || '-') + '</span> <span class="dm">' + esc(e.subject || '') + '</span></div>';
        }
        function ctTreeDetail(el) {
          const det = $('ctTreeDetail');
          const tree = ((CT_TREE_DATA && CT_TREE_DATA.trees) || []).find(t => t.logId === $('ctTreeSel').value) || null;
          if (!tree) return;
          const idx = el.getAttribute('data-index');
          if (idx !== null && idx !== undefined && idx !== '') {
            const e = tree.entries[parseInt(idx, 10)];
            if (!e) return;
            det.style.display = 'block';
            det.textContent = '叶节点 #' + e.index + '\\n' +
              '时间戳: ' + e.tsText + ' (' + e.ts + ' ms)\\n' +
              '条目类型: ' + (e.entryType === 'precert' ? 'precert_entry（预证书，含 poison 扩展）' : 'x509_entry（正式证书）') + '\\n' +
              '证书序列号: ' + e.serial + '\\n' +
              '使用者 DN: ' + e.subject + '\\n' +
              '颁发者 DN: ' + e.issuer + '\\n' +
              '叶哈希 (SHA-256(0x00 || leaf_input)): ' + e.leafHash;
          } else {
            const h = el.getAttribute('data-hash');
            if (h) {
              det.style.display = 'block';
              det.textContent = 'MTH 节点哈希: ' + h;
            }
          }
        }

        // ===== /ct/v1 调试区（RFC 6962 §4 全部 8 接口） =====
        const V1_API = {
          '/ct/v1/add-chain': { method: 'POST', params: [['chain', 'textarea', '证书链 base64(DER) JSON 数组，如 ["b64叶子","b64颁发者","b64根"]']] },
          '/ct/v1/add-pre-chain': { method: 'POST', params: [['chain', 'textarea', '预证书链 base64(DER) JSON 数组（[0]=含 poison 扩展的预证书）']] },
          '/ct/v1/get-sth': { method: 'GET', params: [['log_id', 'text', '日志 ID（base64，可选，默认第一个可用）']] },
          '/ct/v1/get-roots': { method: 'GET', params: [] },
          '/ct/v1/get-entries': { method: 'GET', params: [['start', 'text', '起始索引（必填）'], ['end', 'text', '结束索引（必填）'], ['log_id', 'text', '日志 ID（可选）']] },
          '/ct/v1/get-proof-by-hash': { method: 'GET', params: [['hash', 'text', '叶子哈希 hex（必填）'], ['tree_size', 'text', '树大小（必填）'], ['log_id', 'text', '日志 ID（可选）']] },
          '/ct/v1/get-sth-consistency': { method: 'GET', params: [['first', 'text', '旧树大小（必填）'], ['second', 'text', '新树大小（必填）'], ['log_id', 'text', '日志 ID（可选）']] },
          '/ct/v1/get-entry-and-proof': { method: 'GET', params: [['leaf_index', 'text', '叶子索引（必填）'], ['tree_size', 'text', '树大小（必填）'], ['log_id', 'text', '日志 ID（可选）']] }
        };
        function v1ShowForm() {
          const apiName = $('v1ApiSel').value;
          const def = V1_API[apiName] || { method: 'GET', params: [] };
          const box = $('v1Params');
          box.innerHTML = '<div style="font-size:12px;color:var(--dim);margin-bottom:6px">方法 ' + def.method + ' ' + apiName + ' —— 参数：</div>';
          if (!def.params.length) {
            box.innerHTML += '<div style="font-size:13px;color:var(--dim)">（无参数）</div>';
          }
          def.params.forEach(p => {
            const name = p[0], kind = p[1], hint = p[2];
            if (kind === 'textarea') {
              box.innerHTML += '<div class="v1-row"><label>' + esc(name) + '</label><br><textarea id="v1p_' + name + '" placeholder="' + esc(hint) + '"></textarea></div>';
            } else {
              box.innerHTML += '<div class="v1-row"><label>' + esc(name) + '</label><input id="v1p_' + name + '" placeholder="' + esc(hint) + '" style="width:360px"></div>';
            }
          });
          if (def.method === 'POST') {
            box.innerHTML += '<div class="v1-row"><label></label><button class="ghost" onclick="v1LoadSample()">载入示例链（从证书库取终端证书链）</button> <span style="font-size:12px;color:var(--dim)" id="v1SampleMsg"></span></div>';
          }
          $('v1Resp').style.display = 'none';
        }
        async function v1LoadSample() {
          const msg = $('v1SampleMsg');
          if (msg) msg.textContent = '载入中…';
          try {
            const r = await api('/api/ctlog/samplechain');
            if (r.ok) {
              const ta = $('v1p_chain');
              if (ta) ta.value = JSON.stringify(r.chain, null, 1);
              if (msg) msg.textContent = '已载入链: ' + (r.chainSerials || []).join(' → ');
            } else {
              if (msg) msg.textContent = r.message || '载入失败';
            }
          } catch (e) { if (msg) msg.textContent = '载入异常: ' + e; }
        }
        async function v1Send() {
          const apiName = $('v1ApiSel').value;
          const def = V1_API[apiName] || { method: 'GET', params: [] };
          const qs = [];
          const body = {};
          let bodyB64 = '';
          def.params.forEach(p => {
            const el = $('v1p_' + p[0]);
            const val = el ? el.value.trim() : '';
            if (def.method === 'GET') {
              if (val) qs.push(encodeURIComponent(p[0]) + '=' + encodeURIComponent(val));
            } else {
              if (val) {
                if (p[0] === 'chain') {
                  try { body[p[0]] = JSON.parse(val); } catch (e) { body[p[0]] = val; }
                } else {
                  body[p[0]] = val;
                }
              }
            }
          });
          if (def.method === 'POST') {
            bodyB64 = btoa(unescape(encodeURIComponent(JSON.stringify(body))));
          }
          const out = $('v1Resp');
          out.style.display = 'block';
          out.className = 'out';
          out.textContent = '正在转发到 MAIN ' + def.method + ' ' + apiName + ' …';
          try {
            const r = await api('/api/ctlog/v1proxy', {
              path: apiName,
              method: def.method,
              query: qs.join('&'),
              bodyB64: bodyB64,
              contentType: def.method === 'POST' ? 'application/json' : ''
            });
            out.className = 'out ' + (r.ok ? 'ok' : 'err');
            out.textContent = r.message || '(无输出)';
            v1Log(apiName, def.method, qs.join('&'), def.method === 'POST' ? body : null, r.ok, r.message || '');
          } catch (e) {
            out.className = 'out err';
            out.textContent = '请求失败: ' + e;
            v1Log(apiName, def.method, qs.join('&'), def.method === 'POST' ? body : null, false, '请求失败: ' + e);
          }
        }
        function v1Log(apiName, method, query, body, ok, resp) {
          const tb = $('v1LogTable').querySelector('tbody');
          const now = new Date();
          const ts = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0') + ' ' +
            String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0') + ':' + String(now.getSeconds()).padStart(2, '0');
          const reqDesc = method + ' ' + apiName + (query ? '?' + query : '') + (body ? '\\nbody: ' + JSON.stringify(body) : '');
          const tr = document.createElement('tr');
          tr.innerHTML = '<td><div style="color:var(--dim)">' + ts + '</div></td>' +
            '<td><div>' + esc(reqDesc) + '\\n→ ' + (ok ? '[成功] ' : '[失败] ') + esc(resp || '') + '</div></td>';
          tb.insertBefore(tr, tb.firstChild);
          while (tb.rows.length > 20) tb.deleteRow(tb.rows.length - 1);
        }
        function v1ClearLog() {
          $('v1LogTable').querySelector('tbody').innerHTML = '';
        }
        </script>
        </html>
    """;
    private static final String PAGE_VIEWER = """
<script>
/* ============================================================
 * 证书查看器核心逻辑（cert-viewer.js）
 * - 纯通用：不硬编码任何固定 JSON 文件名，也没有文件选择框
 * - 所有证书数据一律通过统一入口 MODPKICACERTVIERW(...) 置入，
 *   参数为 JSON 结构文本变量（字符串），按证书链顺序传入
 * - 所有窗口 DOM、CSS、渲染、交互均由本文件动态创建，整体移植即可运行
 * - 所有 id / class / 自定义 data 属性名均以 MODPKICA 开头，
 *   后缀为唯一随机值，一一对应，避免与其他文件命名混淆
 * 用法（唯一入口）：
 *   <script src="cert-viewer.js"><\\/script>
 *   <script>
 *     MODPKICACERTVIERW(终端证书JSON结构文本变量,
 *                       中间CA证书JSON结构文本变量,
 *                       根证书JSON结构文本变量);
 *   <\\/script>
 *   每个参数为 JSON 结构文本（字符串），第一个为终端证书，最后为根证书，
 *   支持任意层数；也兼容直接传 JSON 对象。
 * ============================================================ */
(function (global) {
  "use strict";

  /* ---------- 命名空间：所有 class / id 的唯一随机后缀 ---------- */
  var NS = {
    overlay: "MODPKICAlV5lHv",
    win: "MODPKICAA5w0ao",
    titlebar: "MODPKICAlOPxjj",
    dragging: "MODPKICAtQSHOu",
    tIcon: "MODPKICAT0mkwZ",
    tTitle: "MODPKICAOOsYgo",
    seg: "MODPKICA9Zia3O",
    on: "MODPKICAmOBnW5",
    close: "MODPKICAGJ9PzR",
    tabs: "MODPKICAr8KOKa",
    tab: "MODPKICA4gma2F",
    content: "MODPKICASxUjMn",
    pane: "MODPKICAH7aU0S",
    certHead: "MODPKICAU9cj5u",
    certTitle: "MODPKICAUNawFK",
    statusLine: "MODPKICA5roPb3",
    stOk: "MODPKICAODw0D7",
    stErr: "MODPKICAunzrkA",
    stWarn: "MODPKICACeNGtk",
    purpose: "MODPKICAGKu7Qz",
    pLabel: "MODPKICA1x8Vif",
    pNote: "MODPKICAGauIVo",
    kv: "MODPKICA7fUqVz",
    kvRow: "MODPKICAdhKyz8",
    k: "MODPKICA4ZVOqA",
    v: "MODPKICAsXdlIL",
    filter: "MODPKICAuq4wcj",
    filterId: "MODPKICAyJeOqF",
    grid: "MODPKICAg2YmjP",
    gridHead: "MODPKICAb7CcRf",
    row: "MODPKICAumLUz9",
    sel: "MODPKICARyTpUM",
    val: "MODPKICALF7zSx",
    gridBody: "MODPKICAxE7LK7",
    detail: "MODPKICA72wKYB",
    btnRow: "MODPKICA0FdwiB",
    btn: "MODPKICAvbUotE",
    pathHead: "MODPKICA0lXlbb",
    pathLabel: "MODPKICAmlWmIf",
    zoom: "MODPKICAsYtJoh",
    zbtn: "MODPKICAv66WsY",
    zval: "MODPKICAS1kQm7",
    pathTree: "MODPKICAdVaCTR",
    pnode: "MODPKICAfXu5Fk",
    lvl: "MODPKICAGmhmfq",
    pathView: "MODPKICA0vBX2C",
    viewbtn: "MODPKICAVo1kiT",
    pathStatus: "MODPKICAeo6Siy",
    psLabel: "MODPKICApOip2e",
    psText: "MODPKICATcAYaV",
    toast: "MODPKICA7dvLcV",
    show: "MODPKICAGKlE9m",
    infoBox: "MODPKICAi9Xq2p",
    ibTitle: "MODPKICAq2m8sX",
    ibBody: "MODPICAbN4cV1",
    ibLabel: "MODPKICAvW7kR3",
    ibLine: "MODPKICAwE9tY5",
    ibText: "MODPKICAzU2iO8",
    ibFoot: "MODPKICAbR4pL7"
  };
  /* 自定义 data 属性名（均以 MODPKICA 开头） */
  var DA = {
    tab: "data-MODPKICA-tab",
    s: "data-MODPKICA-s",
    z: "data-MODPKICA-z",
    idx: "data-MODPKICA-idx",
    key: "data-MODPKICA-key",
    close: "data-MODPKICA-close",
    toast: "data-MODPKICA-toast",
    ibshow: "data-MODPKICA-ibshow",
    ibclose: "data-MODPKICA-ibclose"
  };

  /* ---------- 配置 ----------
   * 不硬编码任何固定 JSON 文件名，也没有文件选择框；
   * 所有证书数据通过 MODPKICACERTVIERW(...) 以 JSON 结构文本变量置入。
   */
  var WIN_W = 420, WIN_H = 500;

  /* ---------- 基础工具 ---------- */
  function el(tag, cls, html) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html !== undefined) e.innerHTML = html;
    return e;
  }
  function esc(t) {
    var d = document.createElement("div");
    d.textContent = t == null ? "" : String(t);
    return d.innerHTML;
  }
  function pad(n) { return String(n).padStart(2, "0"); }

  /* 本地时间格式化：2026/9/12 或 2026年9月12日 1:01:33 */
  function fmtDate(iso, withTime) {
    var d = new Date(iso);
    if (isNaN(d)) return String(iso);
    var y = d.getFullYear(), mo = d.getMonth() + 1, da = d.getDate();
    if (!withTime) return y + "/" + mo + "/" + da;
    return y + "年" + mo + "月" + da + "日 " + d.getHours() + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }

  /* 公钥位数：从 SPKI hex 解析 RSA modulus 长度 */
  function rsaBits(hex) {
    if (!hex) return 0;
    var m = hex.match(/0282([0-9a-f]{4})/i) || hex.match(/0281([0-9a-f]{2})/i);
    if (!m) return 0;
    return (parseInt(m[1], 16) - 1) * 8;
  }

  /* hex 字符串 -> Windows 公钥风格显示：每 16 字节一行，字节间空格 */
  function hexBlock(hex) {
    if (!hex) return "";
    var b = String(hex).replace(/[^0-9a-fA-F]/g, "");
    if (!b) return "";
    var lines = [];
    for (var i = 0; i < b.length; i += 32) {
      var chunk = b.slice(i, i + 32);
      var bytes = [];
      for (var j = 0; j < chunk.length; j += 2) bytes.push(chunk.substr(j, 2));
      lines.push(bytes.join(" "));
    }
    return lines.join("\\n");
  }

  /* 通用公钥描述：RSA / ECC(P-256/384/521) / SM2 / Ed25519 等 */
  function pubKeyDesc(spki) {
    if (!spki) return "(未提供)";
    var alg = spki.algorithm || {};
    var oid = (alg.algorithm || "").toString();
    var name = (alg.name || "").toString();
    var hex = (spki.publicKey || "").toString();
    if (oid === "1.2.840.113549.1.1.1" || /rsa/i.test(name)) {
      var b = rsaBits(hex);
      return b ? "RSA (" + b + " Bits)" : "RSA";
    }
    if (oid === "1.2.840.10045.2.1" || /ecPublicKey/i.test(name)) {
      var ph = (alg.parameters || "").toString().toLowerCase();
      if (ph.indexOf("811ccf5501822d") >= 0) return "SM2 (256 Bits)";
      if (ph.indexOf("8648ce3d030107") >= 0) return "ECC P-256 (256 Bits)";
      if (ph.indexOf("81040022") >= 0) return "ECC P-384 (384 Bits)";
      if (ph.indexOf("81040023") >= 0) return "ECC P-521 (521 Bits)";
      // 回退：未压缩点 04||X||Y
      var n = Math.floor(hex.length / 2);
      var bits = n >= 120 ? 521 : (n >= 50 ? 384 : 256);
      return "ECC (" + bits + " Bits)";
    }
    if (oid === "2.16.840.1.101.3.4.3.17") return "ML-DSA-44";
    if (oid === "2.16.840.1.101.3.4.3.18") return "ML-DSA-65";
    if (oid === "2.16.840.1.101.3.4.3.19") return "ML-DSA-87";
    if (oid === "1.3.101.112") return "Ed25519";
    if (oid === "1.3.101.113") return "Ed448";
    if (oid === "1.2.840.10040.4.1") return "DSA";
    return name || oid || "(未提供)";
  }

  /* 名称数组（issuer/subject）→ "www.test.com, My Org, CN" */
  function fmtName(rdns) {
    if (!rdns || !rdns.length) return "(未提供)";
    return rdns.map(function (r) { return r[0].value; }).slice().reverse().join(", ");
  }
  function findCN(rdns) {
    if (!rdns) return "(未知)";
    var hit = rdns.filter(function (r) { return r[0].name === "CN"; });
    return hit.length ? hit[hit.length - 1][0].value : "(未知)";
  }

  /* ---------- 扩展字段格式化 ---------- */
  var KU_MAP = {
    digitalSignature: "Digital Signature", nonRepudiation: "Non-Repudiation",
    keyEncipherment: "Key Encipherment", dataEncipherment: "Data Encipherment",
    keyAgreement: "Key Agreement", keyCertSign: "Key Cert Sign",
    cRLSign: "CRL Sign", encipherOnly: "Encipher Only", decipherOnly: "Decipher Only"
  };

  function fmtBasic(ext) {
    var s = "Subject Type=" + (ext.cA ? "CA" : "End Entity");
    s += "\\nPath Length Constraint=" + (ext.pathLenConstraint == null ? "None" : ext.pathLenConstraint);
    return s;
  }
  function fmtKeyUsage(ext) {
    return (ext.keyUsage || []).map(function (k) { return KU_MAP[k] || k; }).join(", ");
  }
  /* EKU OID -> 中文名（详细信息页） */
  var EKU_NAME = {
    "1.3.6.1.5.5.7.3.1":  "服务器身份验证",
    "1.3.6.1.5.5.7.3.2":  "客户端身份验证",
    "1.3.6.1.5.5.7.3.3":  "代码签名",
    "1.3.6.1.5.5.7.3.4":  "安全电子邮件",
    "1.3.6.1.5.5.7.3.5":  "IP 安全终端系统",
    "1.3.6.1.5.5.7.3.6":  "IP 安全隧道终止",
    "1.3.6.1.5.5.7.3.7":  "IP 安全用户",
    "1.3.6.1.5.5.7.3.8":  "时间戳",
    "1.3.6.1.5.5.7.3.9":  "OCSP 签名",
    "1.3.6.1.4.1.311.61.1.1":    "内核模式代码签名",
    "1.3.6.1.4.1.311.10.3.5":    "Windows 硬件驱动程序验证",
    "1.3.6.1.4.1.311.10.3.6":    "Windows 系统组件验证",
    "1.3.6.1.4.1.311.10.3.7":    "OEM Windows 系统组件验证",
    "1.3.6.1.4.1.311.10.3.8":    "内嵌 Windows 系统组件验证",
    "1.3.6.1.4.1.311.64.1.1":    "域名系统(DNS)服务器信任",
    "1.3.6.1.5.5.7.3.36":        "通用文档签名",
    "1.3.6.1.4.1.311.10.3.19":   "已吊销列表签名者",
    "1.3.6.1.5.2.3.5":           "KDC 身份验证",
    "1.3.6.1.4.1.311.10.3.13":   "生存时间签名",
    "1.3.6.1.4.1.311.21.5":      "私钥存档",
    "1.3.6.1.4.1.311.10.3.10":   "合格的部属",
    "1.3.6.1.4.1.311.10.3.11":   "密钥恢复",
    "1.3.6.1.4.1.311.10.3.12":   "文档签名",
    "1.3.6.1.4.1.311.10.3.2":    "Microsoft 时间戳",
    "1.3.6.1.4.1.311.10.3.4":    "加密文件系统",
    "1.3.6.1.4.1.311.21.6":      "密钥恢复代理",
    "1.3.6.1.4.1.311.21.19":    "目录服务电子邮件复制",
    "1.3.6.1.5.5.8.2.2":         "IP 安全 IKE 中级",
    "1.3.6.1.4.1.311.10.3.4.1":  "文件恢复",
    "1.3.6.1.4.1.311.10.3.9":    "根列表签名者",
    "1.3.6.1.4.1.311.10.5.1":    "数字权利",
    "1.3.6.1.4.1.311.20.1":      "CTL 用法",
    "1.3.6.1.4.1.311.10.6.1":    "密钥数据包许可证",
    "1.3.6.1.4.1.311.10.6.2":    "许可证服务器验证",
    "1.3.6.1.4.1.311.20.2.2":    "智能卡登录"
  };

  /* 证书策略特殊 OID -> 中文目的（常规页"证书的目的"） */
  var POLICY_PURPOSE = {
    "1.3.6.1.4.1.311.10.12.1": "所有应用策略",
    "2.5.29.32.0":             "所有颁发策略"
  };
  /* EKU OID -> 常规页“证书的目的” Windows 文本（与 EKU_NAME 顺序一致） */
  var EKU_PURPOSE = {
    "1.3.6.1.5.5.7.3.1":  "保证远程计算机的身份",
    "1.3.6.1.5.5.7.3.2":  "向远程计算机证明你的身份",
    "1.3.6.1.5.5.7.3.3":  "确保软件来自软件发布者",
    "1.3.6.1.5.5.7.3.4":  "保护软件在发行后不被更改",
    "1.3.6.1.5.5.7.3.5":  "保护电子邮件消息",
    "1.3.6.1.5.5.7.3.6":  "允许 Internet 上的安全通信",
    "1.3.6.1.5.5.7.3.7":  "允许用当前时间签名数据",
    "1.3.6.1.5.5.7.3.8":  "允许加密磁盘上的数据",
    "1.3.6.1.5.5.7.3.9":  "1.3.6.1.4.1.4146.1.95",
    "1.3.6.1.4.1.311.61.1.1":    "2.23.140.1.1",
    "1.3.6.1.4.1.311.10.3.5":    "2.23.140.1.3",
    "1.3.6.1.4.1.311.10.3.6":    "OCSP 签名",
    "1.3.6.1.4.1.311.10.3.7":    "内核模式代码签名",
    "1.3.6.1.4.1.311.10.3.8":    "Windows 硬件驱动程序验证",
    "1.3.6.1.4.1.311.64.1.1":    "Windows 系统组件验证",
    "1.3.6.1.5.5.7.3.36":        "OEM Windows 系统组件验证",
    "1.3.6.1.4.1.311.10.3.19":   "内嵌 Windows 系统组件验证",
    "1.3.6.1.5.2.3.5":           "域名系统(DNS)服务器信任",
    "1.3.6.1.4.1.311.10.3.13":   "1.3.6.1.5.5.7.3.36",
    "1.3.6.1.4.1.311.21.5":      "已吊销列表签名者",
    "1.3.6.1.4.1.311.10.3.10":   "KDC 身份验证",
    "1.3.6.1.4.1.311.10.3.11":   "生存时间签名",
    "1.3.6.1.4.1.311.10.3.12":   "私钥存档",
    "1.3.6.1.4.1.311.10.3.2":    "合格的部属",
    "1.3.6.1.4.1.311.10.3.4":    "密钥恢复",
    "1.3.6.1.4.1.311.21.6":      "文档签名",
    "1.3.6.1.4.1.311.21.19":    "密钥恢复代理",
    "1.3.6.1.5.5.8.2.2":         "目录服务电子邮件复制",
    "1.3.6.1.4.1.311.10.3.4.1":  "文件恢复",
    "1.3.6.1.4.1.311.10.3.9":    "根列表签名者",
    "1.3.6.1.4.1.311.10.5.1":    "数字权利",
    "1.3.6.1.4.1.311.20.1":      "CTL 用法",
    "1.3.6.1.4.1.311.10.6.1":    "密钥数据包许可证",
    "1.3.6.1.4.1.311.10.6.2":    "许可证服务器验证",
    "1.3.6.1.4.1.311.20.2.2":    "智能卡登录"
  };

  function fmtEku(ext) {
    return (ext.extendedKeyUsage || []).map(function (e) {
      var nm = EKU_NAME[e.oid] || (e.name && e.name.indexOf(".") < 0 ? e.name : null) || e.oid;
      return nm + " (" + e.oid + ")";
    }).join("\\n");
  }
  function fmtAia(ext) {
    return (ext.authorityInfoAccess || []).map(function (a, i) {
      return "[" + (i + 1) + "]Authority Info Access\\n   Access Method: " +
        (a.accessMethodName || a.accessMethod) + " (" + a.accessMethod + ")\\n   Access Location: URI: " +
        (a.accessLocation ? a.accessLocation.value : "");
    }).join("\\n");
  }
  function fmtCrl(ext) {
    return (ext.crlDistributionPoints || []).map(function (c, i) {
      var uris = (c.distributionPoint && c.distributionPoint.fullName || [])
        .map(function (f) { return f.value || ""; }).join("\\n         URI: ");
      return "[" + (i + 1) + "]CRL Distribution Point\\n   Distribution Point Name:\\n      Full Name:\\n         URI: " + uris;
    }).join("\\n");
  }
  function fmtPolicies(ext) {
    return (ext.certificatePolicies || []).map(function (p, i) {
      var s = "[" + (i + 1) + "]Certificate Policy\\n   Policy Identifier=" + p.policyIdentifier;
      (p.policyQualifiers || []).forEach(function (q) {
        if (q.cpsUri) s += "\\n   CPS: " + q.cpsUri;
        if (q.userNotice && q.userNotice.explicitText)
          s += "\\n   User Notice:\\n      Explicit Text: " + String(q.userNotice.explicitText).split("\\n").join("\\n      ");
      });
      return s;
    }).join("\\n");
  }
  function fmtSct(ext) {
    return (ext.sctList || []).map(function (s, i) {
      return "第 " + (i + 1) + " 条 SCT:\\n" +
        "  日志版本: V" + (s.version || 1) + "\\n" +
        "  日志标识符: " + (s.logId || "(未提供)") + "\\n" +
        "  时间戳: " + fmtDate(Number(s.timestamp || 0), true) + "\\n" +
        "  签名类型: " + (s.signatureAlgorithm || "?") + "-" + (s.hashAlgorithm || "?") + "\\n" +
        "  签名: " + (s.signature || "(未提供)");
    }).join("\\n\\n");
  }

  /* 扩展 OID → 中文名（决定字段显示顺序与名称） */
  var EXT_ORDER = [
    ["2.5.29.35", "授权密钥标识符", function (e) { return "KeyID=" + e.keyIdentifier; }],
    ["2.5.29.14", "使用者密钥标识符", function (e) { return e.keyIdentifier; }],
    ["1.3.6.1.5.5.7.1.1", "授权信息访问", fmtAia],
    ["2.5.29.31", "CRL分发点", fmtCrl],
    ["2.5.29.37", "增强型密钥用法", fmtEku],
    ["2.5.29.32", "证书策略", fmtPolicies],
    ["2.5.29.19", "基本约束", fmtBasic],
    ["2.5.29.15", "密钥用法", fmtKeyUsage],
    ["1.3.6.1.4.1.11129.2.4.2", "证书透明度 SCT", fmtSct]
  ];

  /* 常见签名算法 OID → 标准名（优先于 JSON 里的 name） */
  var SIG_OID_NAMES = {
    "1.2.840.113549.1.1.2":  "MD2withRSA",
    "1.2.840.113549.1.1.4":  "MD5withRSA",
    "1.2.840.113549.1.1.5":  "SHA1withRSA",
    "1.2.840.113549.1.1.14": "SHA224withRSA",
    "1.2.840.113549.1.1.11": "SHA256withRSA",
    "1.2.840.113549.1.1.12": "SHA384withRSA",
    "1.2.840.113549.1.1.13": "SHA512withRSA",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.4.1":     "SHA1withECDSA",
    "1.2.840.10045.4.3.1":   "SHA224withECDSA",
    "1.2.840.10045.4.3.2":   "SHA256withECDSA",
    "1.2.840.10045.4.3.3":   "SHA384withECDSA",
    "1.2.840.10045.4.3.4":   "SHA512withECDSA",
    "1.2.840.10040.4.3":     "SHA1withDSA",
    "2.16.840.1.101.3.4.3.2":"SHA224withDSA",
    "2.16.840.1.101.3.4.3.3":"SHA256withDSA",
    "1.2.156.10197.1.501":   "SM2withSM3",
    "1.2.840.10040.4.3":"SHA1withDSA",
    "2.16.840.1.101.3.4.3.1":"SHA3-224withRSA",
    "2.16.840.1.101.3.4.3.2":"SHA3-256withRSA",
    "2.16.840.1.101.3.4.3.3":"SHA3-384withRSA",
    "2.16.840.1.101.3.4.3.4":"SHA3-512withRSA",
    "2.16.840.1.101.3.4.3.9":"SHA3-224withECDSA",
    "2.16.840.1.101.3.4.3.10":"SHA3-256withECDSA",
    "2.16.840.1.101.3.4.3.11":"SHA3-384withECDSA",
    "2.16.840.1.101.3.4.3.12":"SHA3-512withECDSA",
    "1.3.101.112":"Ed25519",
    "1.3.101.113":"Ed448",
    "2.16.840.1.101.3.4.3.17":"ML-DSA-44",
    "2.16.840.1.101.3.4.3.18":"ML-DSA-65",
    "2.16.840.1.101.3.4.3.19":"ML-DSA-87",
    "1.3.101.112":           "Ed25519",
    "1.3.101.113":           "Ed448"
  };

  /* ---------- 数据解析：JSON → 展示模型 ---------- */
  /* chainJsons: 完整证书链 JSON 数组（顺序：终端证书、中间CA证书、根证书），可选 */
  function parseCert(json, chainJsons) {
    var sigAlgOid = (json.signature && json.signature.algorithm) || (json.signatureAlgorithm && json.signatureAlgorithm.algorithm) || "";
    var sigName = (json.signature && json.signature.name) || (json.signatureAlgorithm && json.signatureAlgorithm.name) || "";
    var sigAlg = SIG_OID_NAMES[sigAlgOid] || sigName || sigAlgOid || "(未知)";
    var hash;
    if (sigAlgOid === "1.2.156.10197.1.501" || sigAlg === "SM2withSM3") {
      hash = "SM3";
    } else if (sigAlgOid === "2.16.840.1.101.3.4.3.17" || sigAlg === "ML-DSA-44") {
      hash = "内置SHAKE128（纯签名）";
    } else if (sigAlgOid === "2.16.840.1.101.3.4.3.18" || sigAlg === "ML-DSA-65"
        || sigAlgOid === "2.16.840.1.101.3.4.3.19" || sigAlg === "ML-DSA-87") {
      hash = "内置SHAKE256（纯签名）";
    } else {
      var mh = sigAlg.match(/SHA(\\d+)/i);
      hash = mh ? "SHA" + mh[1] : (/SHA1/i.test(sigAlg) ? "SHA1" : (/MD5/i.test(sigAlg) ? "MD5" : "SHA256"));
    }
    var pubBits = rsaBits(json.subjectPublicKeyInfo && json.subjectPublicKeyInfo.publicKey);
    var pkHex = hexBlock(json.subjectPublicKeyInfo && json.subjectPublicKeyInfo.publicKey);

    var fields = [
      { label: "版本", group: "v1", value: String(json.version || "v3").toUpperCase() },
      { label: "序列号", group: "v1", value: json.serialNumber || "(未提供)" },
      { label: "签名算法", group: "v1", value: sigAlg },
      { label: "签名哈希算法", group: "v1", value: hash },
      { label: "颁发者", group: "v1", value: fmtName(json.issuer) },
      { label: "有效期从", group: "v1", value: fmtDate(json.validity && json.validity.notBefore && json.validity.notBefore.value, true) },
      { label: "有效期到", group: "v1", value: fmtDate(json.validity && json.validity.notAfter && json.validity.notAfter.value, true) },
      { label: "使用者", group: "v1", value: fmtName(json.subject) },
      { label: "公钥", group: "v1", value: pubKeyDesc(json.subjectPublicKeyInfo) + (pkHex ? "\\n" + pkHex : "") }
    ];

    var exts = json.extensions || {};
    EXT_ORDER.forEach(function (item) {
      var ext = exts[item[0]];
      if (!ext) return;
      fields.push({
        label: item[1],
        group: ext.critical ? "crit" : "ext",
        value: item[2](ext)
      });
    });

    /* 用途列表（常规页）：EKU 文本用途 + 证书策略 OID，每项带 OID 供悬停显示 */
    var purposes = [];
    var eku = exts["2.5.29.37"];
    if (eku && eku.extendedKeyUsage) {
      eku.extendedKeyUsage.forEach(function (e) {
        purposes.push({ text: EKU_PURPOSE[e.oid] || EKU_NAME[e.oid] || e.oid, oid: e.oid });
      });
    }
    var pol = exts["2.5.29.32"];
    var policyInfo = { cps: [], notices: [] };
    if (pol && pol.certificatePolicies) {
      pol.certificatePolicies.forEach(function (p) {
        var dup = purposes.some(function (x) { return x.oid === p.policyIdentifier; });
        if (!dup) purposes.push({ text: POLICY_PURPOSE[p.policyIdentifier] || p.policyIdentifier, oid: p.policyIdentifier });
        (p.policyQualifiers || []).forEach(function (q) {
          if (q.cpsUri) policyInfo.cps.push(q.cpsUri);
          if (q.userNotice && q.userNotice.explicitText) policyInfo.notices.push(String(q.userNotice.explicitText));
        });
      });
    }
    if (!purposes.length) purposes.push({ text: "无", oid: "" });

    /* 证书链：优先使用外部传入的完整链（根→中间→终端），否则由 issuer/subject 推导 */
    var chain;
    if (chainJsons && chainJsons.length) {
      chain = chainJsons.slice().reverse().map(function (j, i) {
        return { name: findCN(j.subject), lvl: i, json: j };
      });
    } else {
      chain = [
        { name: "My Root CA", lvl: 0 },
        { name: findCN(json.issuer), lvl: 1 },
        { name: findCN(json.subject), lvl: 2, json: json }
      ];
    }

    return {
      fields: fields,
      purposes: purposes,
      chain: chain,
      chainJsons: chainJsons || null,
      thumb: null,           // 保留字段（当前不计算指纹，避免依赖 .crt 文件）
      serial: json.serialNumber || "",
      source: json._source || "",
      leafCn: findCN(json.subject),
      issuerCn: findCN(json.issuer),
      policyInfo: policyInfo,
      nbRaw: json.validity && json.validity.notBefore && json.validity.notBefore.value,
      naRaw: json.validity && json.validity.notAfter && json.validity.notAfter.value
    };
  }

  /* ---------- SVG 图标 ---------- */
  function iconOk() {
    return '<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" fill="#e6f4e6" stroke="#107c10" stroke-width="1.6"/><path d="M7.5 12.2l3 3 6-6.5" stroke="#107c10" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  }
  function iconErr() {
    return '<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" fill="#fde7e9" stroke="#c50f1f" stroke-width="1.6"/><path d="M8 8l8 8M16 8l-8 8" stroke="#c50f1f" stroke-width="2.2" stroke-linecap="round"/></svg>';
  }
  function iconWarn() {
    return '<svg viewBox="0 0 24 24" fill="none"><path d="M12 3.5L22 20H2z" fill="#fdf3d7" stroke="#c87600" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 10v4.5" stroke="#c87600" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="17.2" r="1.1" fill="#c87600"/></svg>';
  }
  function iconCert() {
    return '<svg viewBox="0 0 24 24"><rect x="4" y="6" width="16" height="14" rx="1.5" fill="#f4c542" stroke="#b8860b" stroke-width="1.1"/><path d="M8.5 6V5a3.5 3.5 0 0 1 7 0v1" fill="none" stroke="#777" stroke-width="1.3"/><circle cx="12" cy="13" r="2" fill="#0078d4"/></svg>';
  }
  function iconBigCert() {
    return '<svg viewBox="0 0 48 48"><circle cx="24" cy="24" r="23" fill="#e6eef7" stroke="#a8c8e8" stroke-width="1.4"/><circle cx="24" cy="24" r="19.5" fill="#f4f8fc" stroke="#c8dcee"/><rect x="13" y="16" width="22" height="17" rx="2.5" fill="#f7c948" stroke="#c99a2e" stroke-width="1.3"/><path d="M19.5 16v-1.5a4.5 4.5 0 0 1 9 0V16" fill="none" stroke="#8a6d1f" stroke-width="1.7"/><circle cx="24" cy="24" r="3" fill="#0078d4"/><path d="M18.5 30.5h11" stroke="#c99a2e" stroke-width="1.3"/></svg>';
  }

  /* ---------- 状态：ok / revoked / expired ---------- */
  function statusInfo(s) {
    if (s === "revoked") return { cls: NS.stErr, icon: iconErr(), text: "该证书已被证书颁发机构吊销。" };
    if (s === "expired") return { cls: NS.stWarn, icon: iconWarn(), text: "该证书已过期，或者尚未生效。" };
    return { cls: NS.stOk, icon: iconOk(), text: "该证书没有问题。" };
  }

  /* ---------- 窗口构建 ---------- */
  function buildWindow(model, opts) {
    if (!opts) opts = {};
    var urlTab = (location.search.match(/[?&]tab=(\\w+)/) || [])[1];
    var initTab = (urlTab === "detail" || urlTab === "path") ? urlTab : "general";
    var state = { tab: initTab, filter: "all", selKey: "version", status: "ok", pathSel: Math.max(0, model.chain.length - 1), pathZoom: 100 };

    /* 样式注入（仅一次） */
    injectStyle();

    /* 遮罩 + 窗口 */
    var overlay = el("div", NS.overlay);
    var win = el("div", NS.win);
    win.style.width = Math.min(WIN_W, window.innerWidth - 24) + "px";
    win.style.height = Math.min(WIN_H, window.innerHeight - 80) + "px";

    /* 标题栏 */
    var titlebar = el("div", NS.titlebar);
    titlebar.innerHTML =
      '<svg class="' + NS.tIcon + '" viewBox="0 0 24 24"><rect x="4" y="7" width="16" height="13" rx="1.5" fill="#f4c542" stroke="#b8860b"/><path d="M8 7V6a4 4 0 0 1 8 0v1" fill="none" stroke="#555" stroke-width="1.6"/><circle cx="12" cy="13" r="2.4" fill="#0078d4"/></svg>' +
      '<span class="' + NS.tTitle + '">证书' + (model.source ? ' - ' + esc(model.source) : "") + '</span>' +
      '<div class="' + NS.seg + '" style="display:none">' +
      '<button ' + DA.s + '="ok" class="' + NS.on + '">正常</button><button ' + DA.s + '="revoked">已吊销</button><button ' + DA.s + '="expired">已过期</button>' +
      '</div>' +
      '<button class="' + NS.close + '" title="关闭">✕</button>';

    /* 标签页 */
    var tabs = el("div", NS.tabs);
    tabs.innerHTML =
      '<button class="' + NS.tab + (initTab === "general" ? " " + NS.on : "") + '" ' + DA.tab + '="general">常规</button>' +
      '<button class="' + NS.tab + (initTab === "detail" ? " " + NS.on : "") + '" ' + DA.tab + '="detail">详细信息</button>' +
      '<button class="' + NS.tab + (initTab === "path" ? " " + NS.on : "") + '" ' + DA.tab + '="path">证书路径</button>';

    /* 内容区 */
    var content = el("div", NS.content);
    var paneGeneral = el("section", NS.pane + (initTab === "general" ? " " + NS.on : ""));
    var paneDetail = el("section", NS.pane + (initTab === "detail" ? " " + NS.on : ""));
    var panePath = el("section", NS.pane + (initTab === "path" ? " " + NS.on : ""));
    content.appendChild(paneGeneral);
    content.appendChild(paneDetail);
    content.appendChild(panePath);

    win.appendChild(titlebar);
    win.appendChild(tabs);
    win.appendChild(content);
    overlay.appendChild(win);
    document.body.appendChild(overlay);

    /* toast */
    var toast = el("div", NS.toast);
    document.body.appendChild(toast);
    var toastTimer = null;
    /* ---------- 颁发者说明弹窗 ---------- */
    function showIssuerNotice() {
      var info = model.policyInfo;
      if (!info || (!info.cps.length && !info.notices.length)) return;
      var box = el("div", NS.infoBox);
      var h = '<div class="' + NS.ibTitle + '">颁发者说明</div><div class="' + NS.ibBody + '">';
      if (info.cps.length) {
        h += '<div class="' + NS.ibLabel + '">CPS（证书颁发实践声明）：</div>';
        info.cps.forEach(function (u) {
          h += '<div class="' + NS.ibLine + '"><a href="' + esc(u) + '" target="_blank" rel="noopener">' + esc(u) + '</a></div>';
        });
      }
      if (info.notices.length) {
        h += '<div class="' + NS.ibLabel + '">用户通告：</div>';
        info.notices.forEach(function (t) {
          h += '<div class="' + NS.ibText + '">' + esc(t) + '</div>';
        });
      }
      h += '</div><div class="' + NS.ibFoot + '"><button class="' + NS.btn + '" ' + DA.ibclose + '="1">确定</button></div>';
      box.innerHTML = h;
      document.body.appendChild(box);
      var onKey = function (e) { if (e.key === "Escape") { box.remove(); document.removeEventListener("keydown", onKey); } };
      box.addEventListener("click", function (e) {
        if (e.target.closest("[" + DA.ibclose + "]")) { box.remove(); }
      });
      document.addEventListener("keydown", onKey);
    }

    function showToast(msg) {
      toast.textContent = msg;
      toast.classList.add(NS.show);
      clearTimeout(toastTimer);
      toastTimer = setTimeout(function () { toast.classList.remove(NS.show); }, 2200);
    }

    /* ---------- 渲染：常规 ---------- */
    function renderGeneral() {
      var s = state.status;
      var info = statusInfo(s);
      paneGeneral.innerHTML =
        '<div class="' + NS.certHead + '">' + iconBigCert() +
        '<div><div class="' + NS.certTitle + '">证书信息</div>' +
        '<div class="' + NS.statusLine + " " + info.cls + '">' + info.icon + '<span>' + info.text + '</span></div></div></div>' +
        (s === "ok"
          ? '<div class="' + NS.purpose + '"><div class="' + NS.pLabel + '">这个证书的目的如下:</div><ul>' +
            model.purposes.map(function (p) {
              return '<li title="OID: ' + esc(p.oid) + '">' + esc(p.text) + "</li>";
            }).join("") +
            '</ul><div class="' + NS.pNote + '">* 有关详细信息，请参考证书颁发机构的说明。</div></div>'
          : "") +
        '<div class="' + NS.kv + '">' +
        '<div class="' + NS.kvRow + '"><div class="' + NS.k + '">颁发给:</div><div class="' + NS.v + '">' + esc(model.leafCn || "(未知)") + '</div></div>' +
        '<div class="' + NS.kvRow + '"><div class="' + NS.k + '">颁发者:</div><div class="' + NS.v + '">' + esc(model.issuerCn || "(未知)") + '</div></div>' +
        '<div class="' + NS.kvRow + '"><div class="' + NS.k + '">有效期从</div><div class="' + NS.v + '">' + esc(fmtDate(model.nbRaw, false)) + '</div></div>' +
        '<div class="' + NS.kvRow + '"><div class="' + NS.k + '">到</div><div class="' + NS.v + '">' + esc(fmtDate(model.naRaw, false)) + '</div></div>' +
        '</div>' +
        '<div class="' + NS.btnRow + '">' +
        ((model.policyInfo && (model.policyInfo.cps.length || model.policyInfo.notices.length))
          ? '<button class="' + NS.btn + '" ' + DA.ibshow + '="1">颁发者说明(S)</button>'
          : '') +
        '<button class="' + NS.btn + '" ' + DA.close + '="1">确定</button></div>';
    }
    /* ---------- 渲染：详细信息 ---------- */
    function renderDetail() {
      var s = state.status, f = state.filter;
      var rows = model.fields.filter(function (x) {
        if (f === "v1") return x.group === "v1";
        if (f === "ext") return x.group === "ext" || x.group === "crit";
        if (f === "crit") return x.group === "crit";
        if (f === "attr") return x.group === "attr";
        return true;
      });
      if ((s === "revoked" || s === "expired") && (f === "all" || f === "v1")) {
        rows.push({
          label: "已展开错误信息", group: "v1",
          value: s === "revoked" ? "吊销状态: 证书已被吊销。" : "证书状态: 证书已过期，或尚未生效。"
        });
      }
      if (!rows.some(function (r) { return r.label === state.selKey; })) state.selKey = rows.length ? rows[0].label : "";
      paneDetail.innerHTML =
        '<div class="' + NS.filter + '"><label for="' + NS.filterId + '">显示(S):</label>' +
        '<select id="' + NS.filterId + '">' +
        '<option value="all"' + (f === "all" ? " selected" : "") + '>&lt;所有&gt;</option>' +
        '<option value="v1"' + (f === "v1" ? " selected" : "") + '>只有版本 1字段</option>' +
        '<option value="ext"' + (f === "ext" ? " selected" : "") + '>只有扩展</option>' +
        '<option value="crit"' + (f === "crit" ? " selected" : "") + '>只有关键扩展</option>' +
        '<option value="attr"' + (f === "attr" ? " selected" : "") + '>只有属性</option>' +
        '</select></div>' +
        '<div class="' + NS.grid + '"><div class="' + NS.gridHead + '"><div>字段</div><div>值</div></div>' +
        '<div class="' + NS.gridBody + '">' +
        rows.map(function (r) {
          return '<div class="' + NS.row + (r.label === state.selKey ? " " + NS.sel : "") + '" ' + DA.key + '="' + esc(r.label) + '">' +
            '<div>' + esc(r.label) + '</div><div class="' + NS.val + '">' + esc(r.value) + '</div></div>';
        }).join("") +
        '</div></div>' +
        '<div class="' + NS.detail + '"></div>' +
        '<div class="' + NS.btnRow + '">' +
        '<button class="' + NS.btn + '" ' + DA.toast + '="演示环境：已将证书信息复制到剪贴板（模拟）。">复制到文件(C)...</button>' +
        '<button class="' + NS.btn + '" ' + DA.close + '="1">确定</button></div>';
      var sel = rows.filter(function (r) { return r.label === state.selKey; })[0];
      paneDetail.querySelector("." + NS.detail).textContent = sel ? sel.value : "";
      var filter = paneDetail.querySelector("#" + NS.filterId);
      filter.addEventListener("change", function () { state.filter = filter.value; renderDetail(); });
      paneDetail.querySelector("." + NS.gridBody).addEventListener("click", function (e) {
        var row = e.target.closest("." + NS.row);
        if (!row) return;
        state.selKey = row.getAttribute(DA.key);
        /* 仅切换选中高亮与详情内容，不重建列表 DOM（保持滚动条位置） */
        Array.prototype.forEach.call(paneDetail.querySelectorAll("." + NS.row), function (r) {
          r.classList.toggle(NS.sel, r === row);
        });
        var sel2 = rows.filter(function (r) { return r.label === state.selKey; })[0];
        paneDetail.querySelector("." + NS.detail).textContent = sel2 ? sel2.value : "";
      });
    }

    /* ---------- 渲染：证书路径 ---------- */
    function renderPath() {
      var s = state.status, info = statusInfo(s);
      var icon = function (i) { return i === state.pathSel ? info.icon : iconCert(); };
      panePath.innerHTML =
        '<div class="' + NS.pathHead + '"><div class="' + NS.pathLabel + '">证书路径(P)</div>' +
        '<div class="' + NS.zoom + '"><button class="' + NS.zbtn + '" ' + DA.z + '="-" title="缩小">−</button>' +
        '<span class="' + NS.zval + '">' + state.pathZoom + '%</span>' +
        '<button class="' + NS.zbtn + '" ' + DA.z + '="+" title="放大">＋</button></div></div>' +
        '<div class="' + NS.pathTree + '">' +
        model.chain.map(function (n, i) {
          return '<div class="' + NS.pnode + " " + NS.lvl + n.lvl + (i === state.pathSel ? " " + NS.sel : "") + '" ' + DA.idx + '="' + i + '" role="button" tabindex="0">' +
            icon(i) + '<span>' + esc(n.name) + '</span></div>';
        }).join("") +
        '</div>' +
        '<div class="' + NS.pathView + '"><button class="' + NS.btn + " " + NS.viewbtn + '">查看证书(V)</button></div>' +
        '<div class="' + NS.pathStatus + '"><div class="' + NS.psLabel + '">证书状态(S):</div>' +
        '<div class="' + NS.psText + " " + info.cls + '">' + info.icon + '<span>' + info.text + '</span></div></div>' +
        '<div class="' + NS.btnRow + '"><button class="' + NS.btn + '" ' + DA.close + '="1">确定</button></div>';
      var tree = panePath.querySelector("." + NS.pathTree);
      tree.style.fontSize = state.pathZoom + "%";
      /* 缩放控制 */
      panePath.querySelector("." + NS.zoom).addEventListener("click", function (e) {
        var b = e.target.closest("." + NS.zbtn);
        if (!b) return;
        var z = state.pathZoom + (b.getAttribute(DA.z) === "+" ? 10 : -10);
        state.pathZoom = Math.max(50, Math.min(200, z));
        renderPath();
      });
      /* 点击行：仅切换高亮与图标，不重建 DOM（保持滚动位置） */
      var setSel = function (row) {
        Array.prototype.forEach.call(tree.querySelectorAll("." + NS.pnode), function (n, idx) {
          n.classList.toggle(NS.sel, n === row);
          var svg = n.querySelector("svg");
          if (svg) svg.outerHTML = (n === row ? info.icon : iconCert());
        });
      };
      /* 打开选中层证书的新窗口（双击行 / 查看证书按钮共用） */
      var openNodeCert = function (idx) {
        var node = model.chain[idx];
        if (!node || !node.json) {
          showToast("该层证书 JSON 数据不可用。");
          return;
        }
        var all = model.chainJsons || [];
        var sub;
        if (all.length) {
          // chainJsons = [terminal..root]; chain = [root..terminal]
          sub = all.slice(all.length - 1 - idx, all.length);
        } else {
          sub = [node.json];
        }
        showFromJson(node.json, sub);
      };
      /* 查看证书按钮：打开当前选中层 */
      panePath.querySelector("." + NS.viewbtn).addEventListener("click", function () {
        openNodeCert(state.pathSel);
      });
      /* 双击行：打开该层证书 */
      tree.addEventListener("dblclick", function (e) {
        var row = e.target.closest("." + NS.pnode);
        if (!row) return;
        state.pathSel = Number(row.getAttribute(DA.idx));
        setSel(row);
        openNodeCert(state.pathSel);
      });
      tree.addEventListener("click", function (e) {
        var row = e.target.closest("." + NS.pnode);
        if (!row) return;
        state.pathSel = Number(row.getAttribute(DA.idx));
        setSel(row);
      });
      tree.addEventListener("keydown", function (e) {
        if (e.key !== "Enter" && e.key !== " ") return;
        var row = e.target.closest("." + NS.pnode);
        if (!row) return;
        e.preventDefault();
        state.pathSel = Number(row.getAttribute(DA.idx));
        setSel(row);
      });
    }

    /* ---------- 事件：标签切换 ---------- */
    tabs.addEventListener("click", function (e) {
      var t = e.target.closest("." + NS.tab);
      if (!t) return;
      state.tab = t.getAttribute(DA.tab);
      Array.prototype.forEach.call(tabs.children, function (x) { x.classList.toggle(NS.on, x === t); });
      [paneGeneral, paneDetail, panePath].forEach(function (p, i) {
        p.classList.toggle(NS.on, i === (state.tab === "general" ? 0 : state.tab === "detail" ? 1 : 2));
      });
    });

    /* ---------- 事件：状态切换 ---------- */
    titlebar.querySelector("." + NS.seg).addEventListener("click", function (e) {
      var b = e.target.closest("button");
      if (!b) return;
      state.status = b.getAttribute(DA.s);
      Array.prototype.forEach.call(titlebar.querySelectorAll("." + NS.seg + " button"), function (x) {
        x.classList.toggle(NS.on, x === b);
      });
      renderGeneral(); renderDetail(); renderPath();
    });

    /* ---------- 事件：按钮反馈 / 关闭 ---------- */
    content.addEventListener("click", function (e) {
      var b = e.target.closest("." + NS.btn);
      if (!b) return;
      if (b.hasAttribute(DA.close)) { close(); return; }
      if (b.getAttribute(DA.toast)) showToast(b.getAttribute(DA.toast));
      if (b.hasAttribute(DA.ibshow)) showIssuerNotice();
    });

    function close() {
      overlay.remove();
      toast.remove();
      window.removeEventListener("resize", onResize);
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    }
    titlebar.querySelector("." + NS.close).addEventListener("click", close);

    /* ---------- 拖拽移动 ---------- */
    var dragging = false, offX = 0, offY = 0;
    function onMove(e) {
      if (!dragging) return;
      var x = e.clientX - offX, y = e.clientY - offY;
      x = Math.max(-win.offsetWidth + 80, Math.min(x, window.innerWidth - 80));
      y = Math.max(0, Math.min(y, window.innerHeight - 44));
      win.style.left = x + "px";
      win.style.top = y + "px";
    }
    function onUp() { dragging = false; titlebar.classList.remove(NS.dragging); }
    titlebar.addEventListener("mousedown", function (e) {
      if (e.target.closest("." + NS.close) || e.target.closest("." + NS.seg)) return;
      dragging = true;
      offX = e.clientX - win.offsetLeft;
      offY = e.clientY - win.offsetTop;
      titlebar.classList.add(NS.dragging);
      e.preventDefault();
    });
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
    function onResize() {
      var vw = window.innerWidth, vh = window.innerHeight;
      win.style.left = Math.max(6, Math.round((vw - win.offsetWidth) / 2)) + "px";
      win.style.top = Math.max(6, Math.round((vh - win.offsetHeight) / 2)) + "px";
    }
    onResize();
    window.addEventListener("resize", onResize);

    /* 初始渲染 */
    renderGeneral();
    renderDetail();
    renderPath();

    /* ---------- 自动状态判定：有效期 -> 异步吊销检查 ---------- */
    function applyStatus(ns) {
      if (state.status === ns) return;
      state.status = ns;
      renderGeneral(); renderDetail(); renderPath();
    }
    (function autoDetect() {
      var now = Date.now();
      var nb = model.nbRaw ? new Date(model.nbRaw).getTime() : NaN;
      var na = model.naRaw ? new Date(model.naRaw).getTime() : NaN;
      var expired = (!isNaN(nb) && now < nb) || (!isNaN(na) && now > na);
      if (expired) { applyStatus("expired"); return; }
      if (opts.noRevokeCheck) { applyStatus("ok"); return; }
      if (!model.serial) return;
      fetch("/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: model.serial })
      }).then(function (r) { return r.json(); })
        .then(function (j) {
          var t = (j && j.message) || "";
          if (/无法|未知|None|解析失败/.test(t)) { applyStatus("ok"); return; }
          applyStatus((t.indexOf("已吊销") >= 0 || t.indexOf("已被") >= 0) ? "revoked" : "ok");
        })
        .catch(function () { /* 获取失败（非本库证书 / 网络错误）保持 ok */ });
    })();
  }

  /* ---------- 样式注入（一次性，全部由 NS 生成，保证一一对应） ---------- */
  var styleInjected = false;
  function injectStyle() {
    if (styleInjected) return;
    styleInjected = true;
    var css = [
      "." + NS.overlay + "{position:fixed;inset:0;background:rgba(10,20,35,.45);z-index:10000}",
      "." + NS.win + "{background:#f0f0f0;border:1px solid rgba(255,255,255,.35);border-radius:8px;box-shadow:0 18px 55px rgba(0,0,0,.55),0 2px 8px rgba(0,0,0,.35);overflow:hidden;display:flex;flex-direction:column;font-size:13px;font-family:'Segoe UI','Microsoft YaHei',system-ui,-apple-system,sans-serif;color:#222;position:fixed;z-index:10001;max-width:calc(100vw - 24px);max-height:calc(100vh - 40px)}",
      "." + NS.titlebar + "{background:linear-gradient(180deg,#ffffff,#e8e8e8);border-bottom:1px solid #d0d0d0;padding:7px 10px;display:flex;align-items:center;gap:8px;user-select:none;cursor:move;touch-action:none;flex:none}",
      "." + NS.titlebar + "." + NS.dragging + "{background:linear-gradient(180deg,#e8f2fb,#dce9f5)}",
      "." + NS.tIcon + "{width:16px;height:16px;flex:none}",
      "." + NS.tTitle + "{font-size:13px;color:#1a1a1a;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}",
      "." + NS.seg + "{display:flex;background:#e4e4e4;border-radius:5px;overflow:hidden;border:1px solid #c8c8c8;flex:none}",
      "." + NS.seg + " button{border:none;background:transparent;font-family:inherit;font-size:11.5px;padding:4px 9px;cursor:pointer;color:#444}",
      "." + NS.seg + " button." + NS.on + "{background:#0078d4;color:#fff;font-weight:600}",
      "." + NS.close + "{width:30px;height:22px;border:none;background:transparent;border-radius:3px;cursor:pointer;font-size:12px;color:#333;line-height:1;flex:none}",
      "." + NS.close + ":hover{background:#e81123;color:#fff}",
      "." + NS.tabs + "{display:flex;padding:0 12px;background:#f0f0f0;border-bottom:1px solid #d0d0d0;flex:none}",
      "." + NS.tab + "{position:relative;top:1px;padding:8px 14px;font-size:13px;color:#333;cursor:pointer;border:1px solid transparent;border-bottom:none;border-radius:4px 4px 0 0;background:transparent;font-family:inherit;margin-right:2px}",
      "." + NS.tab + ":hover{background:#e5f1fb}." + NS.tab + "." + NS.on + "{background:#fff;border-color:#d0d0d0;border-bottom-color:#fff;color:#1a1a1a;font-weight:600}",
      "." + NS.content + "{background:#fff;flex:1;min-height:0;display:flex;flex-direction:column;padding:16px 18px 12px;overflow:auto}",
      "." + NS.pane + "{display:none;flex-direction:column;flex:1;min-height:0}",
      "." + NS.pane + "." + NS.on + "{display:flex}",
      "." + NS.certHead + "{display:flex;align-items:flex-start;gap:12px;margin-bottom:10px}",
      "." + NS.certHead + " svg{width:44px;height:44px;flex:none}",
      "." + NS.certTitle + "{font-size:15px;font-weight:600;color:#1a1a1a;margin-bottom:4px}",
      "." + NS.statusLine + "{display:flex;align-items:center;gap:7px;font-size:13.5px;font-weight:500}",
      "." + NS.statusLine + " svg{width:18px;height:18px;flex:none}",
      "." + NS.stOk + "{color:#107c10}." + NS.stErr + "{color:#c50f1f}." + NS.stWarn + "{color:#c87600}",
      "." + NS.purpose + "{margin:2px 0 12px 4px}",
      "." + NS.pLabel + "{color:#444;margin-bottom:5px}",
      "." + NS.purpose + " ul{list-style:none;margin-left:16px;max-height:88px;overflow-y:auto;padding-right:4px}",
      "." + NS.purpose + " li{position:relative;padding:2px 0 2px 14px;color:#222}",
      "." + NS.purpose + " li::before{content:'';position:absolute;left:0;top:9px;width:6px;height:6px;border-radius:50%;background:#0067c0}",
      "." + NS.pNote + "{color:#666;margin-top:7px;font-size:12px}",
      "." + NS.kv + "{margin:4px 0 6px;border-top:1px solid #e0e0e0;padding-top:9px}",
      "." + NS.kvRow + "{display:flex;margin-bottom:5px;line-height:1.5}",
      "." + NS.k + "{width:78px;flex:none;color:#333}." + NS.v + "{color:#1a1a1a;word-break:break-all}",
      "." + NS.filter + "{display:flex;align-items:center;gap:8px;margin-bottom:8px;flex:none}",
      "." + NS.filter + " select{font-family:inherit;font-size:13px;padding:3px 6px;border:1px solid #b5b5b5;border-radius:3px;background:#fff;color:#1a1a1a;min-width:150px}",
      "." + NS.grid + "{border:1px solid #c8c8c8;background:#fff;flex:1;display:flex;flex-direction:column;overflow:hidden;min-height:0}",
      "." + NS.gridHead + ",." + NS.row + "{display:grid;grid-template-columns:140px 1fr}",
      "." + NS.gridHead + "{background:#f0f0f0;border-bottom:1px solid #c8c8c8;font-weight:600;color:#1a1a1a;flex:none}",
      "." + NS.gridHead + " div,." + NS.row + " div{padding:4px 8px;border-right:1px solid #e4e4e4;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}",
      "." + NS.gridHead + " div:last-child,." + NS.row + " div:last-child{border-right:none}",
      "." + NS.gridBody + "{overflow-y:auto;flex:1;min-height:0}",
      "." + NS.row + "{cursor:pointer}." + NS.row + ":hover{background:#f3f7fb}." + NS.row + "." + NS.sel + "{background:#cce8ff}",
      "." + NS.row + " ." + NS.val + "{color:#555}." + NS.row + "." + NS.sel + " ." + NS.val + "{color:#1a1a1a}",
      "." + NS.detail + "{margin-top:8px;border:1px solid #c8c8c8;background:#fff;min-height:46px;padding:6px 8px;font-size:12px;color:#1a1a1a;line-height:1.5;white-space:pre-wrap;word-break:break-all;overflow:auto;max-height:260px;flex:none}",
      "." + NS.btnRow + "{display:flex;justify-content:flex-end;gap:8px;margin-top:12px;flex-wrap:wrap;flex:none}",
      "." + NS.btn + "{font-family:inherit;font-size:13px;padding:5px 16px;background:linear-gradient(180deg,#fcfcfc,#f0f0f0);border:1px solid #adadad;border-radius:3px;color:#1a1a1a;cursor:pointer}",
      "." + NS.btn + ":hover{border-color:#0067c0;background:linear-gradient(180deg,#fdfdff,#eaf3fb)}",
      "." + NS.btn + ":active{background:#e3e3e3}",
      "." + NS.pathHead + "{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;flex:none}",
      "." + NS.pathLabel + "{color:#333}",
      "." + NS.zoom + "{display:flex;align-items:center;gap:4px}",
      "." + NS.zbtn + "{width:22px;height:20px;border:1px solid #adadad;background:linear-gradient(180deg,#fcfcfc,#f0f0f0);border-radius:3px;cursor:pointer;font-size:12px;color:#333;line-height:1;font-family:inherit;padding:0}",
      "." + NS.zbtn + ":hover{border-color:#0067c0;background:linear-gradient(180deg,#fdfdff,#eaf3fb)}",
      "." + NS.zval + "{font-size:11.5px;color:#555;min-width:42px;text-align:center}",
      "." + NS.pathTree + "{border:1px solid #c8c8c8;background:#fff;padding:12px 8px 12px 16px;display:flex;flex-direction:column;gap:2px;flex:1;min-height:0;overflow:auto}",
      "." + NS.pnode + "{display:flex;align-items:center;gap:7px;padding:4px 6px;border-radius:3px;font-size:inherit;position:relative;cursor:pointer}",
      "." + NS.pnode + ":hover{background:#eef5fb}." + NS.pnode + ":focus-visible{outline:2px solid #0067c0;outline-offset:-2px}",
      "." + NS.pnode + " svg{width:1.15em;height:1.15em;flex:none}",
      "." + NS.pnode + "." + NS.lvl + "1{margin-left:2.4em}." + NS.pnode + "." + NS.lvl + "2{margin-left:4.8em}",
      "." + NS.pnode + "." + NS.lvl + "1::before,." + NS.pnode + "." + NS.lvl + "2::before{content:'';position:absolute;left:-2em;width:2em;border-left:1.5px solid #9aa4ae;border-bottom:1.5px solid #9aa4ae;border-radius:0 0 0 4px}",
      "." + NS.pnode + "." + NS.lvl + "1::before{top:-2.1em;height:2.1em}." + NS.pnode + "." + NS.lvl + "2::before{top:-2.1em;height:2.1em}",
      "." + NS.pnode + "." + NS.sel + "{background:#cce8ff;font-weight:600}",
      "." + NS.pathView + "{margin:8px 0 2px;text-align:right;flex:none}",
      "." + NS.pathStatus + "{margin-top:12px;border-top:1px solid #e0e0e0;padding-top:9px;flex:none}",
      "." + NS.psLabel + "{color:#333;margin-bottom:5px}",
      "." + NS.psText + "{display:flex;align-items:center;gap:7px;font-size:13.5px;font-weight:500}",
      "." + NS.psText + " svg{width:18px;height:18px;flex:none}",
      "." + NS.toast + "{position:fixed;left:50%;bottom:30px;transform:translateX(-50%) translateY(16px);background:rgba(30,30,30,.94);color:#fff;padding:9px 18px;border-radius:6px;font-size:13px;opacity:0;pointer-events:none;transition:all .22s;z-index:10010;max-width:86vw;text-align:center}",
      "." + NS.toast + "." + NS.show + "{opacity:1;transform:translateX(-50%) translateY(0)}",
      "." + NS.infoBox + "{position:fixed;left:50%;top:38%;transform:translate(-50%,-50%);background:#f0f0f0;border:1px solid #c8c8c8;border-radius:6px;box-shadow:0 12px 44px rgba(0,0,0,.45);z-index:10011;width:min(520px,90vw);font-family:'Segoe UI','Microsoft YaHei',system-ui,sans-serif;font-size:13px;color:#222}",
      "." + NS.ibTitle + "{background:linear-gradient(180deg,#ffffff,#e8e8e8);border-bottom:1px solid #d0d0d0;padding:7px 12px;font-weight:600;border-radius:6px 6px 0 0}",
      "." + NS.ibBody + "{padding:10px 14px;max-height:260px;overflow:auto;white-space:pre-wrap;word-break:break-all}",
      "." + NS.ibLabel + "{font-weight:600;margin:8px 0 3px;color:#333}",
      "." + NS.ibLine + " a{color:#0066cc;text-decoration:none}",
      "." + NS.ibLine + " a:hover{text-decoration:underline}",
      "." + NS.ibText + "{background:#fff;border:1px solid #e0e0e0;border-radius:4px;padding:6px 8px;margin:3px 0;line-height:1.5}",
      "." + NS.ibFoot + "{padding:8px 14px;border-top:1px solid #e0e0e0;text-align:right}",
      "@media (max-width:560px){." + NS.content + "{padding:12px 12px 8px}." + NS.gridHead + ",." + NS.row + "{grid-template-columns:104px 1fr}." + NS.seg + " button{padding:4px 7px}}"
    ].join("\\n");
    var st = el("style");
    st.textContent = css;
    document.head.appendChild(st);
  }

  /* ---------- 统一入口 ----------
   * 数据一律通过本函数置入，参数为 JSON 结构文本变量（字符串），
   * 不涉及任何文件读取 / 文件选择框 / 固定文件名。
   * MODPKICACERTVIERW(终端证书JSON文本, 中间CA证书JSON文本, 根证书JSON文本, ...)
   * 按证书链顺序传入（第一个为终端证书，最后为根证书），支持任意层数；
   * 也兼容直接传 JSON 对象。
   */
  function showFromJson(json, chainJsons, opts) {
    if (json && !json._source) {
      json._source = (findCN(json.subject) || "证书") + ".json";
    }
    var model = parseCert(json, chainJsons);
    buildWindow(model, opts);
  }

  function parseJsonArgs(args) {
    var list = [];
    for (var i = 0; i < args.length; i++) {
      var v = args[i];
      if (typeof v === "string") {
        var t = v.trim();
        if (!t) continue;
        try { list.push(JSON.parse(t)); }
        catch (e) { console.warn("MODPKICACERTVIERW: 第 " + (i + 1) + " 个参数 JSON 解析失败"); }
      } else if (v && typeof v === "object") {
        list.push(v);
      }
    }
    return list;
  }

  global.MODPKICACERTVIERW = function () {
    var args = Array.prototype.slice.call(arguments);
    var opts = {};
    var last = args[args.length - 1];
    if (typeof last === "boolean" && last === true) {
      args.pop(); opts = { noRevokeCheck: true };
    } else if (last && typeof last === "object" && !last.subject && "noRevokeCheck" in last) {
      args.pop(); opts = last;
    }
    var jsons = parseJsonArgs(args);
    if (!jsons.length) { console.warn("MODPKICACERTVIERW: 未收到有效证书 JSON"); return; }
    var main = jsons[0];
    /* 链顺序：传入的第一个是终端证书，最后一个是根证书；
       路径页显示顺序（根→中间→终端）由 parseCert 内部反转处理 */
    showFromJson(main, jsons, opts);
  };

})(window);

</script>
""";
    private static final String PAGE_HTML = PAGE_P1.concat(PAGE_P1B).concat(PAGE_P2).concat(PAGE_P2B).concat(PAGE_P3).concat(PAGE_VIEWER);
}
