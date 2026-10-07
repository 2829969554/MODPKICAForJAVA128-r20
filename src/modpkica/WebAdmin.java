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
 * <p>监听 <b>0.0.0.0:8080</b>（所有本地接口，局域网内其他 IP 可访问；可通过系统属性
 * -Dmodpkica.admin.port 修改端口，-Dmodpkica.admin.bind 修改绑定地址），单页 GUI 展示 ADMIN 全部功能：
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
    /** 默认绑定地址：所有本地接口（局域网内其他 IP 均可访问管理面板；可用 -Dmodpkica.admin.bind 覆盖）。 */
    private static final String DEFAULT_BIND = "0.0.0.0";

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

    /** 将多个独立的 Base64 分片在运行时解码并按原顺序拼接。
     *  每个分片单独解码，避免生成超过 Java 常量池限制的超大字符串常量。
     */
    private static String decodeBase64Parts(String[] parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Base64.Decoder decoder = Base64.getDecoder();
        for (String part : parts) {
            byte[] bytes = decoder.decode(part);
            out.write(bytes, 0, bytes.length);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    // ============================================================
    // 内嵌前端页面（单文件原生 HTML/CSS/JS，无任何外部依赖，离线可用）
    // ============================================================

    @SuppressWarnings("text-blocks")
    private static final String PAGE_P1 = decodeBase64Parts(new String[]{
            "ICAgICAgICA8IURPQ1RZUEUgaHRtbD4KICAgICAgICA8aHRtbCBsYW5nPSJ6aC1DTiI+CiAgICAgICAgPGhlYWQ+CiAgICAgICAgPG1ldGEgY2hhcnNldD0i",
            "VVRGLTgiPgogICAgICAgIDxtZXRhIG5hbWU9InZpZXdwb3J0IiBjb250ZW50PSJ3aWR0aD1kZXZpY2Utd2lkdGgsIGluaXRpYWwtc2NhbGU9MS4wIj4KICAg",
            "ICAgICA8dGl0bGU+TU9EUEtJQ0Eg566h55CG5o6n5Yi25Y+wPC90aXRsZT4KICAgICAgICA8c3R5bGU+CiAgICAgICAgICA6cm9vdCB7CiAgICAgICAgICAg",
            "IC0tYmc6ICMwZjE0MTk7IC0tcGFuZWw6ICMxNzFlMjY7IC0tcGFuZWwyOiAjMWQyNjMwOwogICAgICAgICAgICAtLWJvcmRlcjogIzI2MzI0MTsgLS10ZXh0",
            "OiAjZDhlMWVhOyAtLWRpbTogIzhiOThhNTsKICAgICAgICAgICAgLS1hY2NlbnQ6ICMzOGJkZjg7IC0tYWNjZW50MjogIzIyZDNlZTsgLS1vazogIzM0ZDM5",
            "OTsgLS13YXJuOiAjZmJiZjI0OwogICAgICAgICAgICAtLWVycjogI2Y4NzE3MTsgLS1tb25vOiBDb25zb2xhcywgIkNvdXJpZXIgTmV3IiwgbW9ub3NwYWNl",
            "OwogICAgICAgICAgfQogICAgICAgICAgKiB7IG1hcmdpbjogMDsgcGFkZGluZzogMDsgYm94LXNpemluZzogYm9yZGVyLWJveDsgfQogICAgICAgICAgYm9k",
            "eSB7IGJhY2tncm91bmQ6IHZhcigtLWJnKTsgY29sb3I6IHZhcigtLXRleHQpOyBmb250LWZhbWlseTogIlNlZ29lIFVJIiwgIk1pY3Jvc29mdCBZYUhlaSIs",
            "IHNhbnMtc2VyaWY7IGZvbnQtc2l6ZTogMTVweDsgZGlzcGxheTogZmxleDsgaGVpZ2h0OiAxMDB2aDsgb3ZlcmZsb3c6IGhpZGRlbjsgfQogICAgICAgICAg",
            "LyogPT09PT0g5L6n6L655qCPID09PT09ICovCiAgICAgICAgICAjc2lkZWJhciB7IHdpZHRoOiAyMDBweDsgbWluLXdpZHRoOiAyMDBweDsgYmFja2dyb3Vu",
            "ZDogdmFyKC0tcGFuZWwpOyBib3JkZXItcmlnaHQ6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyBkaXNwbGF5OiBmbGV4OyBmbGV4LWRpcmVjdGlvbjogY29s",
            "dW1uOyB9CiAgICAgICAgICAubG9nbyB7IHBhZGRpbmc6IDE4cHggMTZweDsgZm9udC1zaXplOiAxOHB4OyBmb250LXdlaWdodDogNzAwOyBsZXR0ZXItc3Bh",
            "Y2luZzogMXB4OyBib3JkZXItYm90dG9tOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQogICAgICAgICAgLmxvZ28gc3BhbiB7IGNvbG9yOiB2YXIoLS1h",
            "Y2NlbnQpOyB9CiAgICAgICAgICBuYXYgeyBmbGV4OiAxOyBvdmVyZmxvdy15OiBhdXRvOyBwYWRkaW5nOiA4cHggMDsgfQogICAgICAgICAgbmF2IGEgeyBk",
            "aXNwbGF5OiBibG9jazsgcGFkZGluZzogMTBweCAxOHB4OyBjb2xvcjogdmFyKC0tZGltKTsgdGV4dC1kZWNvcmF0aW9uOiBub25lOyBjdXJzb3I6IHBvaW50",
            "ZXI7IGJvcmRlci1sZWZ0OiAzcHggc29saWQgdHJhbnNwYXJlbnQ7IHRyYW5zaXRpb246IGFsbCAuMTVzOyB9CiAgICAgICAgICBuYXYgYTpob3ZlciB7IGNv",
            "bG9yOiB2YXIoLS10ZXh0KTsgYmFja2dyb3VuZDogdmFyKC0tcGFuZWwyKTsgfQogICAgICAgICAgbmF2IGEuYWN0aXZlIHsgY29sb3I6IHZhcigtLWFjY2Vu",
            "dCk7IGJhY2tncm91bmQ6IHZhcigtLXBhbmVsMik7IGJvcmRlci1sZWZ0LWNvbG9yOiB2YXIoLS1hY2NlbnQpOyB9CiAgICAgICAgICAuc2lkZS1mb290IHsg",
            "cGFkZGluZzogMTJweCAxNnB4OyBmb250LXNpemU6IDEycHg7IGNvbG9yOiB2YXIoLS1kaW0pOyBib3JkZXItdG9wOiAxcHggc29saWQgdmFyKC0tYm9yZGVy",
            "KTsgfQogICAgICAgICAgLyogPT09PT0g5Li75Yy6ID09PT09ICovCiAgICAgICAgICAjbWFpbiB7IGZsZXg6IDE7IGRpc3BsYXk6IGZsZXg7IGZsZXgtZGly",
            "ZWN0aW9uOiBjb2x1bW47IG1pbi13aWR0aDogMDsgfQogICAgICAgICAgI3RvcGJhciB7IGhlaWdodDogNTZweDsgZGlzcGxheTogZmxleDsgYWxpZ24taXRl",
            "bXM6IGNlbnRlcjsgZ2FwOiAxNHB4OyBwYWRkaW5nOiAwIDIwcHg7IGJhY2tncm91bmQ6IHZhcigtLXBhbmVsKTsgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlk",
            "IHZhcigtLWJvcmRlcik7IH0KICAgICAgICAgICN0b3BiYXIgaDEgeyBmb250LXNpemU6IDE2cHg7IGZvbnQtd2VpZ2h0OiA2MDA7IGZsZXg6IDE7IH0KICAg",
            "ICAgICAgICNjb250ZW50IHsgZmxleDogMTsgb3ZlcmZsb3cteTogYXV0bzsgbWluLWhlaWdodDogMDsgcGFkZGluZzogMjBweDsgfQogICAgICAgICAgLnBh",
            "Z2UgeyBkaXNwbGF5OiBub25lOyB9CiAgICAgICAgICAucGFnZS5hY3RpdmUgeyBkaXNwbGF5OiBibG9jazsgfQogICAgICAgICAgLyogPT09PT0g57uE5Lu2",
            "ID09PT09ICovCiAgICAgICAgICAuY2FyZCB7IGJhY2tncm91bmQ6IHZhcigtLXBhbmVsKTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgYm9y",
            "ZGVyLXJhZGl1czogMTBweDsgcGFkZGluZzogMTZweCAxOHB4OyBtYXJnaW4tYm90dG9tOiAxNnB4OyB9CiAgICAgICAgICAuY2FyZCBoMiB7IGZvbnQtc2l6",
            "ZTogMTRweDsgZm9udC13ZWlnaHQ6IDYwMDsgbWFyZ2luLWJvdHRvbTogMTJweDsgY29sb3I6IHZhcigtLWFjY2VudCk7IH0KICAgICAgICAgIC5ncmlkIHsg",
            "ZGlzcGxheTogZ3JpZDsgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOiByZXBlYXQoYXV0by1maWxsLCBtaW5tYXgoMjAwcHgsIDFmcikpOyBnYXA6IDEycHg7IH0K",
            "ICAgICAgICAgIC5zdGF0IHsgYmFja2dyb3VuZDogdmFyKC0tcGFuZWwyKTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgYm9yZGVyLXJhZGl1",
            "czogOHB4OyBwYWRkaW5nOiAxNHB4OyB9CiAgICAgICAgICAuc3RhdCAubGFiZWwgeyBmb250LXNpemU6IDEycHg7IGNvbG9yOiB2YXIoLS1kaW0pOyBtYXJn",
            "aW4tYm90dG9tOiA2cHg7IH0KICAgICAgICAgIC5zdGF0IC52YWx1ZSB7IGZvbnQtc2l6ZTogMjBweDsgZm9udC13ZWlnaHQ6IDcwMDsgZm9udC1mYW1pbHk6",
            "IHZhcigtLW1vbm8pOyB9CiAgICAgICAgICAuc3RhdCAudmFsdWUub2sgeyBjb2xvcjogdmFyKC0tb2spOyB9IC5zdGF0IC52YWx1ZS53YXJuIHsgY29sb3I6",
            "IHZhcigtLXdhcm4pOyB9IC5zdGF0IC52YWx1ZS5lcnIgeyBjb2xvcjogdmFyKC0tZXJyKTsgfQogICAgICAgICAgLnN0YXQuc3RhdC13aWRlIHsgZ3JpZC1j",
            "b2x1bW46IDEgLyAtMTsgfQogICAgICAgICAgLnN0YXQuc3RhdC13aWRlIC52YWx1ZSB7IGZvbnQtc2l6ZTogMTNweDsgd2hpdGUtc3BhY2U6IG5vcm1hbDsg",
            "d29yZC1icmVhazogYnJlYWstYWxsOyBsaW5lLWhlaWdodDogMS42OyB9CiAgICAgICAgICAuY2ZnLWdyaWQgeyBkaXNwbGF5OiBncmlkOyBncmlkLXRlbXBs",
            "YXRlLWNvbHVtbnM6IHJlcGVhdChhdXRvLWZpbGwsIG1pbm1heCgzMjBweCwgMWZyKSk7IGdhcDogMTRweDsgbWFyZ2luLXRvcDogMTRweDsgfQogICAgICAg",
            "ICAgLmNmZy1maWVsZCB7IGJhY2tncm91bmQ6IHZhcigtLXBhbmVsMik7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IGJvcmRlci1yYWRpdXM6",
            "IDhweDsgcGFkZGluZzogMTJweCAxNHB4OyB9CiAgICAgICAgICAuY2ZnLWZpZWxkIGxhYmVsIHsgZGlzcGxheTogYmxvY2s7IGZvbnQtc2l6ZTogMTNweDsg",
            "Zm9udC13ZWlnaHQ6IDYwMDsgY29sb3I6IHZhcigtLWZnKTsgbWFyZ2luLWJvdHRvbTogOHB4OyB9CiAgICAgICAgICAuY2ZnLXRhZyB7IGZvbnQtc2l6ZTog",
            "MTFweDsgZm9udC13ZWlnaHQ6IDQwMDsgY29sb3I6IHZhcigtLWRpbSk7IG1hcmdpbi1sZWZ0OiA2cHg7IH0KICAgICAgICAgIC5jZmctZmllbGQgaW5wdXQg",
            "eyB3aWR0aDogMTAwJTsgYm94LXNpemluZzogYm9yZGVyLWJveDsgZm9udC1mYW1pbHk6IHZhcigtLW1vbm8pOyBmb250LXNpemU6IDEzcHg7IH0KICAgICAg",
            "ICAgIC5jZmctZmllbGQgdGV4dGFyZWEgeyB3aWR0aDogMTAwJTsgYm94LXNpemluZzogYm9yZGVyLWJveDsgZm9udC1mYW1pbHk6IHZhcigtLW1vbm8pOyBm",
            "b250LXNpemU6IDEzcHg7IHJlc2l6ZTogdmVydGljYWw7IG1pbi1oZWlnaHQ6IDkwcHg7IGxpbmUtaGVpZ2h0OiAxLjY7IH0KICAgICAgICAgIC5jZmctZmll",
            "bGQtd2lkZSB7IGdyaWQtY29sdW1uOiAxIC8gLTE7IH0KICAgICAgICAgIC5jZmctaGludCB7IGZvbnQtc2l6ZTogMTFweDsgY29sb3I6IHZhcigtLWRpbSk7",
            "IG1hcmdpbjogOHB4IDAgMDsgbGluZS1oZWlnaHQ6IDEuNTsgfQogICAgICAgICAgLmVrdS1tb2RhbCB7IHdpZHRoOiBtaW4oNzAwcHgsIDk0dncpOyB9CiAg",
            "ICAgICAgICAuZWt1LWJvZHkgeyBkaXNwbGF5OiBncmlkOyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IHJlcGVhdChhdXRvLWZpbGwsIG1pbm1heCgzMTBweCwg",
            "MWZyKSk7IGdhcDogNHB4OyBtYXgtaGVpZ2h0OiA1NXZoOyBvdmVyZmxvdzogYXV0bzsgcGFkZGluZzogMTBweCA0cHg7IH0KICAgICAgICAgIC5la3UtaXRl",
            "bSB7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogOHB4OyBmb250LXNpemU6IDEzcHg7IHBhZGRpbmc6IDdweCA5cHg7IGJvcmRl",
            "ci1yYWRpdXM6IDZweDsgY3Vyc29yOiBwb2ludGVyOyB9CiAgICAgICAgICAuZWt1LWl0ZW06aG92ZXIgeyBiYWNrZ3JvdW5kOiB2YXIoLS1wYW5lbDIpOyB9",
            "CiAgICAgICAgICAuZWt1LWl0ZW0gaW5wdXQgeyB3aWR0aDogYXV0bzsgZmxleDogbm9uZTsgfQogICAgICAgICAgLmVrdS1pdGVtIGNvZGUgeyBjb2xvcjog",
            "dmFyKC0tZGltKTsgZm9udC1zaXplOiAxMXB4OyBtYXJnaW4tbGVmdDogYXV0bzsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogICAgICAgICAgLm1vZGFsLWZv",
            "b3QgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDEwcHg7IGp1c3RpZnktY29udGVudDogZmxleC1lbmQ7IHBhZGRpbmc6IDEycHggMThweDsgYm9yZGVyLXRvcDog",
            "MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAgICAgICAgIC52YWwtcm93IHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAx",
            "MHB4OyBtYXJnaW4tYm90dG9tOiAxMnB4OyB9CiAgICAgICAgICAudmFsLXJvdyBsYWJlbCB7IHdpZHRoOiA2NHB4OyBmb250LXNpemU6IDEzcHg7IGNvbG9y",
            "OiB2YXIoLS1mZyk7IGZsZXg6IG5vbmU7IH0KICAgICAgICAgIC52YWwtcm93IGlucHV0IHsgd2lkdGg6IDEwMCU7IGZvbnQtZmFtaWx5OiB2YXIoLS1tb25v",
            "KTsgZm9udC1zaXplOiAxM3B4OyB9CiAgICAgICAgICAuZnNlYyB7IG1hcmdpbi10b3A6IDE2cHg7IHBhZGRpbmctdG9wOiAxMnB4OyBib3JkZXItdG9wOiAx",
            "cHggZGFzaGVkIHZhcigtLWJvcmRlcik7IH0KICAgICAgICAgIC5mc2VjOmZpcnN0LW9mLXR5cGUgeyBtYXJnaW4tdG9wOiAwOyBwYWRkaW5nLXRvcDogMDsg",
            "Ym9yZGVyLXRvcDogbm9uZTsgfQogICAgICAgICAgLmZzZWMtdGl0bGUgeyBmb250LXNpemU6IDEycHg7IGZvbnQtd2VpZ2h0OiA3MDA7IGNvbG9yOiB2YXIo",
            "LS1hY2NlbnQpOyBtYXJnaW4tYm90dG9tOiAxMHB4OyBsZXR0ZXItc3BhY2luZzogMXB4OyB9CiAgICAgICAgICBzZWxlY3QudC1ib3ggeyBjdXJzb3I6IHBv",
            "aW50ZXI7IH0KICAgICAgICAgIHNlbGVjdC50LWJveDpob3ZlciB7IGJvcmRlci1jb2xvcjogdmFyKC0tYWNjZW50KTsgfQogICAgICAgICAgLmJhZGdlIHsg",
            "ZGlzcGxheTogaW5saW5lLWJsb2NrOyBwYWRkaW5nOiAzcHggMTBweDsgYm9yZGVyLXJhZGl1czogMjBweDsgZm9udC1zaXplOiAxMnB4OyBmb250LXdlaWdo",
            "dDogNjAwOyB9CiAgICAgICAgICAuYmFkZ2Uub2sgeyBiYWNrZ3JvdW5kOiByZ2JhKDUyLDIxMSwxNTMsLjE1KTsgY29sb3I6IHZhcigtLW9rKTsgfQogICAg",
            "ICAgICAgLmJhZGdlLmVyciB7IGJhY2tncm91bmQ6IHJnYmEoMjQ4LDExMywxMTMsLjE1KTsgY29sb3I6IHZhcigtLWVycik7IH0KICAgICAgICAgIC5iYWRn",
            "ZS5kaW0geyBiYWNrZ3JvdW5kOiB2YXIoLS1wYW5lbDIpOyBjb2xvcjogdmFyKC0tZGltKTsgfQogICAgICAgICAgbGFiZWwgeyBkaXNwbGF5OiBibG9jazsg",
            "Zm9udC1zaXplOiAxMnB4OyBjb2xvcjogdmFyKC0tZGltKTsgbWFyZ2luOiAxMHB4IDAgNHB4OyB9CiAgICAgICAgICBpbnB1dCwgc2VsZWN0LCB0ZXh0YXJl",
            "YSB7IHdpZHRoOiAxMDAlOyBiYWNrZ3JvdW5kOiB2YXIoLS1wYW5lbDIpOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyBjb2xvcjogdmFyKC0t",
            "dGV4dCk7IGJvcmRlci1yYWRpdXM6IDZweDsgcGFkZGluZzogOHB4IDEwcHg7IGZvbnQtZmFtaWx5OiB2YXIoLS1tb25vKTsgZm9udC1zaXplOiAxM3B4OyBv",
            "dXRsaW5lOiBub25lOyB9CiAgICAgICAgICBpbnB1dDpmb2N1cywgc2VsZWN0OmZvY3VzLCB0ZXh0YXJlYTpmb2N1cyB7IGJvcmRlci1jb2xvcjogdmFyKC0t",
            "YWNjZW50KTsgfQogICAgICAgICAgLnJvdyB7IGRpc3BsYXk6IGdyaWQ7IGdyaWQtdGVtcGxhdGUtY29sdW1uczogcmVwZWF0KGF1dG8tZml0LCBtaW5tYXgo",
            "MTgwcHgsIDFmcikpOyBnYXA6IDEycHg7IH0KICAgICAgICAgIC5zaWctdGFicyB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMTBweDsgbWFyZ2luLWJvdHRvbTog",
            "MTZweDsgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IHBhZGRpbmctYm90dG9tOiAxMnB4OyB9CiAgICAgICAgICAuc2lnLXRhYiB7",
            "IHBhZGRpbmc6IDEwcHggMjhweDsgZm9udC1zaXplOiAxNXB4OyBmb250LXdlaWdodDogNzAwOyBiYWNrZ3JvdW5kOiB2YXIoLS1wYW5lbDIpOyBjb2xvcjog",
            "dmFyKC0tZGltKTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgYm9yZGVyLXJhZGl1czogOHB4OyBjdXJzb3I6IHBvaW50ZXI7IHRyYW5zaXRp",
            "b246IGFsbCAuMTVzOyB9CiAgICAgICAgICAuc2lnLXRhYjpob3ZlciB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQp",
            "OyB9CiAgICAgICAgICAuc2lnLXRhYi5hY3RpdmUgeyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogIzBiMTIyMDsgYm9yZGVyLWNvbG9yOiB2",
            "YXIoLS1hY2NlbnQpOyB9CiAgICAgICAgICAuc2lnLXBhbmUgeyBmb250LXNpemU6IDE0cHg7IH0KICAgICAgICAgIC5zaWctcGFuZSAucm93IHsgZ3JpZC10",
            "ZW1wbGF0ZS1jb2x1bW5zOiByZXBlYXQoYXV0by1maXQsIG1pbm1heCgyMzBweCwgMWZyKSk7IH0KICAgICAgICAgIC5kcm9wem9uZSB7IGJvcmRlcjogMnB4",
            "IGRhc2hlZCB2YXIoLS1ib3JkZXIpOyBib3JkZXItcmFkaXVzOiAxMHB4OyBwYWRkaW5nOiAyOHB4IDIwcHg7IHRleHQtYWxpZ246IGNlbnRlcjsgbWFyZ2lu",
            "OiAxNHB4IDA7IGN1cnNvcjogcG9pbnRlcjsgdHJhbnNpdGlvbjogYWxsIC4xNXM7IH0KICAgICAgICAgIC5kcm9wem9uZS5vdmVyIHsgYm9yZGVyLWNvbG9y",
            "OiB2YXIoLS1hY2NlbnQpOyBiYWNrZ3JvdW5kOiByZ2JhKDk2LDE2NSwyNTAsLjA4KTsgfQogICAgICAgICAgLmZha2UtYnRuIHsgZGlzcGxheTogaW5saW5l",
            "LWJsb2NrOyBwYWRkaW5nOiA5cHggMjJweDsgZm9udC1zaXplOiAxNHB4OyBmb250LXdlaWdodDogNzAwOyBjb2xvcjogIzBiMTIyMDsgYmFja2dyb3VuZDog",
            "dmFyKC0tYWNjZW50KTsgYm9yZGVyLXJhZGl1czogN3B4OyBjdXJzb3I6IHBvaW50ZXI7IH0KICAgICAgICAgIC5wZGYtbGlzdC1oZWFkIHsgZGlzcGxheTog",
            "ZmxleDsgZ2FwOiAxMHB4OyBhbGlnbi1pdGVtczogY2VudGVyOyBtYXJnaW4tdG9wOiAxNHB4OyBmb250LXNpemU6IDE0cHg7IH0KICAgICAgICAgIC5wZGYt",
            "bGlzdC1oZWFkIGJ1dHRvbiB7IHBhZGRpbmc6IDdweCAxNnB4OyB9CiAgICAgICAgICAucGRmLWxpc3QgeyBtYXgtaGVpZ2h0OiAyNDBweDsgb3ZlcmZsb3c6",
            "IGF1dG87IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IGJvcmRlci1yYWRpdXM6IDhweDsgbWFyZ2luOiAxMHB4IDA7IH0KICAgICAgICAgIC5w",
            "ZGYtcm93IHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAxMHB4OyBwYWRkaW5nOiA4cHggMTJweDsgYm9yZGVyLWJvdHRvbTog",
            "MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IGZvbnQtc2l6ZTogMTNweDsgfQogICAgICAgICAgLnBkZi1yb3c6bGFzdC1jaGlsZCB7IGJvcmRlci1ib3R0b206",
            "IG5vbmU7IH0KICAgICAgICAgIC5wZGYtcm93IC5ubSB7IGZsZXg6IDE7IG1pbi13aWR0aDogMDsgb3ZlcmZsb3c6IGhpZGRlbjsgdGV4dC1vdmVyZmxvdzog",
            "ZWxsaXBzaXM7IHdoaXRlLXNwYWNlOiBub3dyYXA7IGZvbnQtc2l6ZTogMTNweDsgfQogICAgICAgICAgLnBkZi1yb3cgLnN0IHsgZm9udC1zaXplOiAxMnB4",
            "OyBtaW4td2lkdGg6IDE1MHB4OyB9CiAgICAgICAgICAucGRmLXJvdyAuc3Qub2sgeyBjb2xvcjogdmFyKC0tb2spOyB9IC5wZGYtcm93IC5zdC5lcnIgeyBj",
            "b2xvcjogdmFyKC0tZXJyKTsgfSAucGRmLXJvdyAuc3Qud2FpdCB7IGNvbG9yOiB2YXIoLS1kaW0pOyB9CiAgICAgICAgICAucGRmLXJvdyBidXR0b24geyBw",
            "YWRkaW5nOiAzcHggMTBweDsgZm9udC1zaXplOiAxMnB4OyB9CiAgICAgICAgICAucGRmLXJvdyBhLmRsIHsgY29sb3I6IHZhcigtLWFjY2VudCk7IGZvbnQt",
            "d2VpZ2h0OiA3MDA7IGZvbnQtc2l6ZTogMTJweDsgdGV4dC1kZWNvcmF0aW9uOiBub25lOyB9CiAgICAgICAgICBidXR0b24geyBiYWNrZ3JvdW5kOiB2YXIo",
            "LS1hY2NlbnQpOyBjb2xvcjogIzA2MjAyZTsgYm9yZGVyOiBub25lOyBib3JkZXItcmFkaXVzOiA2cHg7IHBhZGRpbmc6IDlweCAyMHB4OyBmb250LXNpemU6",
            "IDEzcHg7IGZvbnQtd2VpZ2h0OiA3MDA7IGN1cnNvcjogcG9pbnRlcjsgdHJhbnNpdGlvbjogZmlsdGVyIC4xNXM7IH0KICAgICAgICAgIGJ1dHRvbjpob3Zl",
            "ciB7IGZpbHRlcjogYnJpZ2h0bmVzcygxLjE1KTsgfQogICAgICAgICAgYnV0dG9uLmdob3N0IHsgYmFja2dyb3VuZDogdmFyKC0tcGFuZWwyKTsgY29sb3I6",
            "IHZhcigtLXRleHQpOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CiAgICAgICAgICBidXR0b24uZGFuZ2VyIHsgYmFja2dyb3VuZDogIzdm",
            "MWQxZDsgY29sb3I6ICNmZWNhY2E7IH0KICAgICAgICAgIGJ1dHRvbi5zdWNjZXNzIHsgYmFja2dyb3VuZDogIzE0NTMyZDsgY29sb3I6ICNiYmY3ZDA7IH0K",
            "ICAgICAgICAgIGJ1dHRvbjpkaXNhYmxlZCB7IG9wYWNpdHk6IC41OyBjdXJzb3I6IG5vdC1hbGxvd2VkOyB9CiAgICAgICAgICB0YWJsZSB7IHdpZHRoOiAx",
            "MDAlOyBib3JkZXItY29sbGFwc2U6IGNvbGxhcHNlOyBmb250LWZhbWlseTogdmFyKC0tbW9ubyk7IGZvbnQtc2l6ZTogMTIuNXB4OyB9CiAgICAgICAgICB0",
            "aCwgdGQgeyBwYWRkaW5nOiA4cHggMTBweDsgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IHRleHQtYWxpZ246IGxlZnQ7IHdoaXRl",
            "LXNwYWNlOiBub3dyYXA7IH0KICAgICAgICAgIHRoIHsgY29sb3I6IHZhcigtLWRpbSk7IGZvbnQtd2VpZ2h0OiA2MDA7IHBvc2l0aW9uOiBzdGlja3k7IHRv",
            "cDogMDsgYmFja2dyb3VuZDogdmFyKC0tcGFuZWwpOyB9CiAgICAgICAgICB0cjpob3ZlciB0ZCB7IGJhY2tncm91bmQ6IHZhcigtLXBhbmVsMik7IH0KICAg",
            "ICAgICAgIHByZS5vdXQgeyBiYWNrZ3JvdW5kOiAjMGEwZTEzOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyBib3JkZXItcmFkaXVzOiA4cHg7",
            "IHBhZGRpbmc6IDE0cHg7IGZvbnQtZmFtaWx5OiB2YXIoLS1tb25vKTsgZm9udC1zaXplOiAxM3B4OyBsaW5lLWhlaWdodDogMS42OyB3aGl0ZS1zcGFjZTog",
            "cHJlLXdyYXA7IHdvcmQtYnJlYWs6IGJyZWFrLWFsbDsgbWF4LWhlaWdodDogNDIwcHg7IG92ZXJmbG93LXk6IGF1dG87IG1hcmdpbi10b3A6IDE0cHg7IH0K",
            "ICAgICAgICAgIHByZS5vdXQub2sgeyBib3JkZXItY29sb3I6IHJnYmEoNTIsMjExLDE1MywuNCk7IH0gcHJlLm91dC5lcnIgeyBib3JkZXItY29sb3I6IHJn",
            "YmEoMjQ4LDExMywxMTMsLjQpOyB9CiAgICAgICAgICAudG9vbGJhciB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMTBweDsgYWxpZ24taXRlbXM6IGNlbnRlcjsg",
            "bWFyZ2luLWJvdHRvbTogMTJweDsgZmxleC13cmFwOiB3cmFwOyB9CiAgICAgICAgICAudG9vbGJhciBpbnB1dCB7IHdpZHRoOiBhdXRvOyB9IC50b29sYmFy",
            "IHNlbGVjdCB7IHdpZHRoOiBhdXRvOyB9CiAgICAgICAgICAuaGludCB7IGZvbnQtc2l6ZTogMTJweDsgY29sb3I6IHZhcigtLXdhcm4pOyBiYWNrZ3JvdW5k",
            "OiByZ2JhKDI1MSwxOTEsMzYsLjA4KTsgYm9yZGVyOiAxcHggc29saWQgcmdiYSgyNTEsMTkxLDM2LC4zKTsgYm9yZGVyLXJhZGl1czogNnB4OyBwYWRkaW5n",
            "OiA4cHggMTJweDsgbWFyZ2luLWJvdHRvbTogMTBweDsgfQogICAgICAgICAgLmxvYWRpbmcgeyBvcGFjaXR5OiAuNjsgcG9pbnRlci1ldmVudHM6IG5vbmU7",
            "IH0KICAgICAgICAgIDo6LXdlYmtpdC1zY3JvbGxiYXIgeyB3aWR0aDogOHB4OyBoZWlnaHQ6IDhweDsgfQogICAgICAgICAgOjotd2Via2l0LXNjcm9sbGJh",
            "ci10aHVtYiB7IGJhY2tncm91bmQ6IHZhcigtLWJvcmRlcik7IGJvcmRlci1yYWRpdXM6IDRweDsgfQogICAgICAgICAgLyogPT09PT0g6K+B5Lmm6ZO+5qCR",
            "ID09PT09ICovCiAgICAgICAgICAudC1yb3cgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDI4cHg7IGFsaWduLWl0ZW1zOiBmbGV4LXN0YXJ0OyBmbGV4LXdyYXA6",
            "IHdyYXA7IH0KICAgICAgICAgIC50LW5vZGUgeyBwb3NpdGlvbjogcmVsYXRpdmU7IG1hcmdpbjogNHB4IDA7IH0KICAgICAgICAgIC50LWhlYWQgeyBkaXNw",
            "bGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDRweDsgfQogICAgICAgICAgLnQtdG9nZ2xlIHsgZmxleDogbm9uZTsgd2lkdGg6IDE2cHg7",
            "IGhlaWdodDogMTZweDsgbGluZS1oZWlnaHQ6IDE0cHg7IHRleHQtYWxpZ246IGNlbnRlcjsgZm9udC1zaXplOiA5cHg7IGN1cnNvcjogcG9pbnRlcjsgdXNl",
            "ci1zZWxlY3Q6IG5vbmU7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyBiYWNrZ3JvdW5kOiB2YXIoLS1wYW5lbDIpOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1i",
            "b3JkZXIpOyBib3JkZXItcmFkaXVzOiA0cHg7IH0KICAgICAgICAgIC50LXRvZ2dsZTpob3ZlciB7IGJhY2tncm91bmQ6IHZhcigtLWJvcmRlcik7IH0KICAg",
            "ICAgICAgIC50LW5vZGUtcm9vdCA+IC50LWhlYWQgPiAudC1ib3ggeyBib3JkZXItY29sb3I6ICNiNDUzMDk7IH0KICAgICAgICAgIC50LW5vZGUtYyA+IC50",
            "LWhlYWQgPiAudC1ib3ggeyBib3JkZXItY29sb3I6ICMyNTYzZWI7IH0KICAgICAgICAgIC50LW5vZGUtZSA+IC50LWhlYWQgPiAudC1ib3ggeyBib3JkZXIt",
            "Y29sb3I6ICMwNTk2Njk7IH0KICAgICAgICAgIC50LWJveCB7IGRpc3BsYXk6IGlubGluZS1ibG9jazsgcGFkZGluZzogN3B4IDEycHg7IGJvcmRlcjogMXB4",
            "IHNvbGlkIHZhcigtLWJvcmRlcik7IGJvcmRlci1sZWZ0LXdpZHRoOiA0cHg7IGJvcmRlci1yYWRpdXM6IDhweDsgYmFja2dyb3VuZDogdmFyKC0tcGFuZWwy",
            "KTsgY3Vyc29yOiBkZWZhdWx0OyBmb250LWZhbWlseTogdmFyKC0tbW9ubyk7IGZvbnQtc2l6ZTogMTJweDsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogICAg",
            "ICAgICAgLnQtYm94IC50LWJhZGdlIHsgZGlzcGxheTogaW5saW5lLWJsb2NrOyB3aWR0aDogMThweDsgaGVpZ2h0OiAxOHB4OyBsaW5lLWhlaWdodDogMThw",
            "eDsgdGV4dC1hbGlnbjogY2VudGVyOyBib3JkZXItcmFkaXVzOiA0cHg7IGZvbnQtc2l6ZTogMTFweDsgZm9udC13ZWlnaHQ6IDcwMDsgbWFyZ2luLXJpZ2h0",
            "OiA2cHg7IH0KICAgICAgICAgIC50LWJhZGdlLlIgeyBiYWNrZ3JvdW5kOiByZ2JhKDE4MCw4Myw5LC4yNSk7IGNvbG9yOiAjZmJiZjI0OyB9CiAgICAgICAg",
            "ICAudC1iYWRnZS5DIHsgYmFja2dyb3VuZDogcmdiYSgzNyw5OSwyMzUsLjI1KTsgY29sb3I6ICM2MGE1ZmE7IH0KICAgICAgICAgIC50LWJhZGdlLkUgeyBi",
            "YWNrZ3JvdW5kOiByZ2JhKDUsMTUwLDEwNSwuMjUpOyBjb2xvcjogIzM0ZDM5OTsgfQogICAgICAgICAgLnQta2luZCB7IGNvbG9yOiB2YXIoLS1kaW0pOyBm",
            "b250LXNpemU6IDExcHg7IG1hcmdpbi1yaWdodDogOHB4OyB9CiAgICAgICAgICAudC1ib3ggLnQtc3QgeyBtYXJnaW4tbGVmdDogOHB4OyBmb250LXNpemU6",
            "IDExcHg7IH0KICAgICAgICAgIC50LWJveCAudC1zdC5WIHsgY29sb3I6IHZhcigtLW9rKTsgfSAudC1ib3ggLnQtc3QuUiB7IGNvbG9yOiB2YXIoLS1lcnIp",
            "OyB9IC50LWJveCAudC1zdC5OIHsgY29sb3I6IHZhcigtLXdhcm4pOyB9CiAgICAgICAgICAudC1jaGlsZHJlbiB7IG1hcmdpbi1sZWZ0OiAyMnB4OyBwYWRk",
            "aW5nLWxlZnQ6IDE0cHg7IGJvcmRlci1sZWZ0OiAycHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQogICAgICAgICAgLnQtY2hpbGRyZW4uY29sbGFwc2VkIHsg",
            "ZGlzcGxheTogbm9uZTsgfQogICAgICAgICAgLnQtdGlwLCAjdGlwRmxvYXQgYiB7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyB9CiAgICAgICAgICAudC10aXAs",
            "ICN0aXBGbG9hdCAua3YgeyBmb250LWZhbWlseTogdmFyKC0tbW9ubyk7IH0KICAgICAgICAgIC8qIOaCrOa1ruivpuaDhe+8mmZpeGVkIOaMgiBib2R577yM",
            "6YG/5YWN6KKrICNjb250ZW50IOa7muWKqOWuueWZqOijgeWJquaIluiiq+mhtuagj+mBruaMoSAqLwogICAgICAgICAgI3RpcEZsb2F0IHsgcG9zaXRpb246",
            "IGZpeGVkOyB6LWluZGV4OiA5OTk5OyBsZWZ0OiAwOyB0b3A6IDA7IG1pbi13aWR0aDogMjYwcHg7IG1heC13aWR0aDogNDIwcHg7IGJhY2tncm91bmQ6ICMw",
            "YTBlMTM7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWFjY2VudCk7IGJvcmRlci1yYWRpdXM6IDhweDsgcGFkZGluZzogMTBweCAxMnB4OyBmb250LXNpemU6",
            "IDEycHg7IGxpbmUtaGVpZ2h0OiAxLjc7IGRpc3BsYXk6IG5vbmU7IHBvaW50ZXItZXZlbnRzOiBub25lOyBib3gtc2hhZG93OiAwIDhweCAyNHB4IHJnYmEo",
            "MCwwLDAsLjUpOyB9CiAgICAgICAgICAvKiA9PT09PSDor6bmg4XlvLnnqpcgPT09PT0gKi8KICAgICAgICAgIC5tb2RhbC1tYXNrIHsgcG9zaXRpb246IGZp",
            "eGVkOyBpbnNldDogMDsgYmFja2dyb3VuZDogcmdiYSgwLDAsMCwuNjUpOyB6LWluZGV4OiAxMDA7IGRpc3BsYXk6IG5vbmU7IGFsaWduLWl0ZW1zOiBjZW50",
            "ZXI7IGp1c3RpZnktY29udGVudDogY2VudGVyOyB9CiAgICAgICAgICAubW9kYWwtbWFzay5zaG93IHsgZGlzcGxheTogZmxleDsgfQogICAgICAgICAgLm1v",
            "ZGFsIHsgd2lkdGg6IG1pbig5MDBweCwgOTJ2dyk7IG1heC1oZWlnaHQ6IDg2dmg7IGJhY2tncm91bmQ6IHZhcigtLXBhbmVsKTsgYm9yZGVyOiAxcHggc29s",
            "aWQgdmFyKC0tYm9yZGVyKTsgYm9yZGVyLXJhZGl1czogMTJweDsgZGlzcGxheTogZmxleDsgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsgb3ZlcmZsb3c6IGhp",
            "ZGRlbjsgfQogICAgICAgICAgLm1vZGFsLWhlYWQgeyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBwYWRkaW5nOiAxMnB4IDE4cHg7IGJv",
            "cmRlci1ib3R0b206IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CiAgICAgICAgICAubW9kYWwtaGVhZCBoMyB7IGZsZXg6IDE7IGZvbnQtc2l6ZTogMTRw",
            "eDsgY29sb3I6IHZhcigtLWFjY2VudCk7IH0KICAgICAgICAgIC5tb2RhbC1ib2R5IHsgb3ZlcmZsb3c6IGF1dG87IHBhZGRpbmc6IDE0cHggMThweDsgfQog",
            "ICAgICAgICAgLm1vZGFsLWJvZHkgcHJlIHsgZm9udC1mYW1pbHk6IHZhcigtLW1vbm8pOyBmb250LXNpemU6IDEycHg7IGxpbmUtaGVpZ2h0OiAxLjU7IHdo",
            "aXRlLXNwYWNlOiBwcmUtd3JhcDsgd29yZC1icmVhazogYnJlYWstYWxsOyB9CiAgICAgICAgICAvKiA9PT09PSDor4Hkuabmk43kvZzlvLnnqpfvvIjlkIrp",
            "lIAv57ut562+L+WvhumSpeabtOaNou+8iSA9PT09PSAqLwogICAgICAgICAgLm9wLXRhYnMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDRweDsgbWFyZ2luLWJv",
            "dHRvbTogMTRweDsgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAgICAgICAgIC5vcC10YWIgeyBwYWRkaW5nOiA4cHggMThw",
            "eDsgY3Vyc29yOiBwb2ludGVyOyBjb2xvcjogdmFyKC0tZGltKTsgYm9yZGVyLWJvdHRvbTogMnB4IHNvbGlkIHRyYW5zcGFyZW50OyBmb250LXNpemU6IDEz",
            "cHg7IHVzZXItc2VsZWN0OiBub25lOyB9CiAgICAgICAgICAub3AtdGFiOmhvdmVyIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CiAgICAgICAgICAub3AtdGFi",
            "LmFjdGl2ZSB7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyBib3JkZXItYm90dG9tLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyBmb250LXdlaWdodDogNzAwOyB9CiAg",
            "ICAgICAgICAub3AtcGFuZSBsYWJlbCB7IGRpc3BsYXk6IGJsb2NrOyBjb2xvcjogdmFyKC0tZGltKTsgZm9udC1zaXplOiAxMnB4OyBtYXJnaW46IDEwcHgg",
            "MCA2cHg7IH0KICAgICAgICAgIC5vcC1wYW5lIGlucHV0W2xpc3RdIHsgd2lkdGg6IDEwMCU7IH0KICAgICAgICAgIC5vcC1zZXJpYWwtaW5mbyB7IG1hcmdp",
            "bi10b3A6IDEycHg7IHBhZGRpbmc6IDEwcHggMTRweDsgYmFja2dyb3VuZDogdmFyKC0tcGFuZWwyKTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVy",
            "KTsgYm9yZGVyLXJhZGl1czogOHB4OyBmb250LXNpemU6IDEycHg7IGxpbmUtaGVpZ2h0OiAxLjg7IH0KICAgICAgICAgIC5vcC1zZXJpYWwtaW5mbyAua3Yg",
            "eyBmb250LWZhbWlseTogdmFyKC0tbW9ubyk7IH0KICAgICAgICAgIC5vcC1zZXJpYWwtaW5mbyAua3YgYiB7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyB9CiAg",
            "ICAgICAgICAjb3BTZXJpYWxMaXN0IHsgZGlzcGxheTogbm9uZTsgfQogICAgICAgICAgLyogPT09PT0g6K+B5Lmm6aqM6K+B5by556qX77ya54q25oCB5b69",
            "5qCHICsg5qCH6aKY5LiJ5oCB6YWN6ImyID09PT09ICovCiAgICAgICAgICAudi1iYWRnZSB7IHBhZGRpbmc6IDNweCAxNHB4OyBib3JkZXItcmFkaXVzOiA2",
            "cHg7IGZvbnQtd2VpZ2h0OiA3MDA7IGZvbnQtc2l6ZTogMTJweDsgbWFyZ2luLXJpZ2h0OiAxMHB4OyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgICAgICAg",
            "ICAudi10ZXh0IHsgZm9udC1zaXplOiAxM3B4OyBjb2xvcjogdmFyKC0tdGV4dCk7IG1hcmdpbi1yaWdodDogMTJweDsgd2hpdGUtc3BhY2U6IG5vd3JhcDsg",
            "fQogICAgICAgIDwvc3R5bGU+CiAgICAgICAgPC9oZWFkPgogICAgICAgIDxib2R5PgogICAgICAgIDwhLS0gPT09PT0g5L6n6L655qCPID09PT09IC0tPgog",
            "ICAgICAgIDxhc2lkZSBpZD0ic2lkZWJhciI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJsb2dvIj5NT0Q8c3Bhbj5QS0lDQTwvc3Bhbj48L2Rpdj4KICAgICAg",
            "ICAgIDxuYXYgaWQ9Im5hdiI+CiAgICAgICAgICAgIDxhIGRhdGEtcGFnZT0iZGFzaGJvYXJkIiBjbGFzcz0iYWN0aXZlIj7ku6rooajnm5g8L2E+CiAgICAg",
            "ICAgICAgIDxhIGRhdGEtcGFnZT0iY2VydHMiPuivgeS5puW6kzwvYT4KICAgICAgICAgICAgPGEgZGF0YS1wYWdlPSJtYWtlcm9vdCI+562+5Y+R5qC56K+B",
            "5LmmPC9hPgogICAgICAgICAgICA8YSBkYXRhLXBhZ2U9InNpZ25jZXJ0Ij7nrb7lj5Hor4HkuaY8L2E+CiAgICAgICAgICAgIDxhIGRhdGEtcGFnZT0ib2Nz",
            "cCI+T0NTUHxUU0Hnrb7lj5E8L2E+CiAgICAgICAgICAgIDxhIGRhdGEtcGFnZT0idGVtcGxhdGUiPuaooeadv+euoeeQhjwvYT4KICAgICAgICAgICAgPGEg",
            "ZGF0YS1wYWdlPSJyZXZva2UiPuWQiumUgOivgeS5pjwvYT4KICAgICAgICAgICAgPGEgZGF0YS1wYWdlPSJ2ZXJpZnkiPuivgeS5pumqjOivgTwvYT4KICAg",
            "ICAgICAgICAgPGEgZGF0YS1wYWdlPSJzaWduIj7nrb7lkI3kuJPljLo8L2E+CiAgICAgICAgICAgIDxhIGRhdGEtcGFnZT0iY3Rsb2ciPlNDVOacjeWKoeeu",
            "oeeQhjwvYT4KICAgICAgICAgICAgPGEgZGF0YS1wYWdlPSJyYWRpdXMiPlJhZGl1c+acjeWKoeeuoeeQhjwvYT4KICAgICAgICAgICAgPGEgZGF0YS1wYWdl",
            "PSJwcHBvZSI+UFBQb0XmnI3liqHnrqHnkIY8L2E+CiAgICAgICAgICAgIDxhIGRhdGEtcGFnZT0iaW5pdCI+5Yid5aeL5YyW546v5aKDPC9hPgogICAgICAg",
            "ICAgICA8YSBkYXRhLXBhZ2U9InVzZXJzIj7nlKjmiLfnrqHnkIY8L2E+CiAgICAgICAgICAgIDxhIGRhdGEtcGFnZT0iY29uZmlnIj7ns7vnu5/phY3nva48",
            "L2E+CiAgICAgICAgICAgIDxhIGRhdGEtcGFnZT0ibG9ncyI+5pON5L2c5pel5b+XPC9hPgogICAgICAgICAgPC9uYXY+CiAgICAgICAgICA8ZGl2IGNsYXNz",
            "PSJzaWRlLWZvb3QiIGlkPSJzaWRlVmVyc2lvbiI+5Yqg6L295LitLi4uPC9kaXY+CiAgICAgICAgPC9hc2lkZT4KCiAgICAgICAgPCEtLSA9PT09PSDkuLvl",
            "jLogPT09PT0gLS0+CiAgICAgICAgPGRpdiBpZD0ibWFpbiI+CiAgICAgICAgICA8aGVhZGVyIGlkPSJ0b3BiYXIiPgogICAgICAgICAgICA8aDEgaWQ9InBh",
            "Z2VUaXRsZSI+5Luq6KGo55uYPC9oMT4KICAgICAgICAgICAgPHNwYW4gY2xhc3M9ImJhZGdlIGRpbSIgaWQ9Im1haW5Qb3J0Ij5NQUlOOiAtLTwvc3Bhbj4K",
            "ICAgICAgICAgICAgPHNwYW4gY2xhc3M9ImJhZGdlIG9rIiBpZD0ibWFpblN0YXRlIj4tLTwvc3Bhbj4KICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iZ2hv",
            "c3QiIG9uY2xpY2s9ImxvYWRTdGF0dXMoKSI+5Yi35pawPC9idXR0b24+CiAgICAgICAgICA8L2hlYWRlcj4KCiAgICAgICAgICA8c2VjdGlvbiBpZD0iY29u",
            "dGVudCI+CgogICAgICAgICAgICA8IS0tIOS7quihqOebmCAtLT4KICAgICAgICAgICAgPGRpdiBjbGFzcz0icGFnZSBhY3RpdmUiIGlkPSJwYWdlLWRhc2hi",
            "b2FyZCI+CiAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZ3JpZCI+CiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJzdGF0Ij48ZGl2IGNsYXNzPSJsYWJl",
            "bCI+TUFJTiDmnI3liqHnq6/lj6M8L2Rpdj48ZGl2IGNsYXNzPSJ2YWx1ZSBvayIgaWQ9InN0UG9ydCI+LS08L2Rpdj48L2Rpdj4KICAgICAgICAgICAgICAg",
            "IDxkaXYgY2xhc3M9InN0YXQiPjxkaXYgY2xhc3M9ImxhYmVsIj7mnI3liqHov5DooYzml7bplb88L2Rpdj48ZGl2IGNsYXNzPSJ2YWx1ZSIgaWQ9InN0VXB0",
            "aW1lIj4tLTwvZGl2PjwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0ic3RhdCI+PGRpdiBjbGFzcz0ibGFiZWwiPueuoeeQhueVjOmdouerr+WP",
            "ozwvZGl2PjxkaXYgY2xhc3M9InZhbHVlIiBpZD0ic3RBZG1pbiI+LS08L2Rpdj48L2Rpdj4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InN0YXQiPjxk",
            "aXYgY2xhc3M9ImxhYmVsIj5BUEkg6LCD55So5qyh5pWwPC9kaXY+PGRpdiBjbGFzcz0idmFsdWUiIGlkPSJzdENhbGxzIj4tLTwvZGl2PjwvZGl2PgogICAg",
            "ICAgICAgICAgICAgPGRpdiBjbGFzcz0ic3RhdCI+PGRpdiBjbGFzcz0ibGFiZWwiPuaXpeW/l+ihjOaVsDwvZGl2PjxkaXYgY2xhc3M9InZhbHVlIiBpZD0i",
            "c3RMb2dzIj4tLTwvZGl2PjwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0ic3RhdCBzdGF0LXdpZGUiPjxkaXYgY2xhc3M9ImxhYmVsIj7lt6Xk",
            "vZznm67lvZU8L2Rpdj48ZGl2IGNsYXNzPSJ2YWx1ZSIgaWQ9InN0QmFzZSI+LS08L2Rpdj48L2Rpdj4KICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAg",
            "ICAgICA8ZGl2IGNsYXNzPSJjYXJkIiBzdHlsZT0ibWFyZ2luLXRvcDoxNnB4Ij4KICAgICAgICAgICAgICAgIDxoMj7lv6vmjbfmk43kvZw8L2gyPgogICAg",
            "ICAgICAgICAgICAgPGRpdiBjbGFzcz0idG9vbGJhciI+CiAgICAgICAgICAgICAgICAgIDxidXR0b24gb25jbGljaz0icXVpY2tBY3Rpb24oJy9hcGkvY3Js",
            "JykiPuWIt+aWsOWFqOmDqCBDUkw8L2J1dHRvbj4KICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJxdWlja0FjdGlvbignL2FwaS9pbml0b2Nz",
            "cCcpIj7nrb7lj5Hlhajpg6ggT0NTUDwvYnV0dG9uPgogICAgICAgICAgICAgICAgICA8YnV0dG9uIG9uY2xpY2s9InF1aWNrQWN0aW9uKCcvYXBpL2luaXR0",
            "aW1lc3RhbXAnKSI+562+5Y+R5YWo6YOo5pe26Ze05oizPC9idXR0b24+CiAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgIDxwcmUgY2xh",
            "c3M9Im91dCIgaWQ9ImRhc2hPdXQiIGhpZGRlbj48L3ByZT4KICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4K",
            "ICAgICAgICAgICAgICAgIDxoMj7or4Hkuabpk77moJE8L2gyPgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idG9vbGJhciI+CiAgICAgICAgICAgICAg",
            "ICAgIDxzcGFuIHN0eWxlPSJjb2xvcjp2YXIoLS1kaW0pO2ZvbnQtc2l6ZToxMnB4Ij7moLkgUiDihpIg5Lit6Ze0IENBIEMg4oaSIOe7iOerryBF77yb6byg",
            "5qCH5oKs5YGc6IqC54K55p+l55yL6K+B5Lmm5Y+C5pWwPC9zcGFuPgogICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJnaG9zdCIgb25jbGljaz0i",
            "bG9hZENoYWluKCkiPuWIt+aWsDwvYnV0dG9uPgogICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJjaGFpbkJveCIgc3R5",
            "bGU9Im92ZXJmbG93OmF1dG87bWF4LWhlaWdodDo1MnZoO3BhZGRpbmc6MTBweCI+5Yqg6L295LitLi4uPC9kaXY+CiAgICAgICAgICAgICAgPC9kaXY+CiAg",
            "ICAgICAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgICAgICAgICAgICA8aDI+5pyA6L+R5pel5b+XPC9oMj4KICAgICAgICAgICAgICAgIDxwcmUg",
            "Y2xhc3M9Im91dCIgaWQ9ImRhc2hMb2dzIiBzdHlsZT0ibWF4LWhlaWdodDoyNjBweCI+PC9wcmU+CiAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAg",
            "IDwvZGl2PgoKICAgICAgICAgICAgPCEtLSDor4HkuablupMgLS0+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9InBhZ2UiIGlkPSJwYWdlLWNlcnRzIj4KICAg",
            "ICAgICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImN0LXRhYnMiPgogICAgICAgICAgICAgICAgICA8YnV0",
            "dG9uIGNsYXNzPSJjdC10YWIgYWN0aXZlIiBpZD0iY3NUYWJCdG5Mb2NhbCIgb25jbGljaz0iY3NTd2l0Y2hUYWIoJ2xvY2FsJykiPuivgeS5puW6kyBDRVJU",
            "Uy50eHQ8L2J1dHRvbj4KICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iY3QtdGFiIiBpZD0iY3NUYWJCdG5DYSIgb25jbGljaz0iY3NTd2l0Y2hU",
            "YWIoJ2NhY2VydHMnKSI+5Y+v5L+h5YWs572R6K+B5Lmm5bqTIGNhY2VydHM8L2J1dHRvbj4KICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iY3Qt",
            "dGFiIiBpZD0iY3NUYWJCdG5NeSIgb25jbGljaz0iY3NTd2l0Y2hUYWIoJ215JykiPuaIkeeahOivgeS5pjwvYnV0dG9uPgogICAgICAgICAgICAgICAgPC9k",
            "aXY+CiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJjc1BhbmVMb2NhbCI+CiAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRvb2xiYXIiPgogICAgICAg",
            "ICAgICAgICAgICAgIDxpbnB1dCBpZD0iY2VydHNGaWx0ZXIiIHBsYWNlaG9sZGVyPSLnrZvpgInvvJrluo/liJflj7cgLyDnsbvlnosgLyDnirbmgIEgLyDn",
            "rpfms5UiIHN0eWxlPSJmbGV4OjE7bWF4LXdpZHRoOjM2MHB4IiBvbmlucHV0PSJyZW5kZXJDZXJ0cygpIj4KICAgICAgICAgICAgICAgICAgICA8YnV0dG9u",
            "IGNsYXNzPSJnaG9zdCIgb25jbGljaz0ibG9hZENlcnRzKCkiPuWIt+aWsOWIl+ihqDwvYnV0dG9uPgogICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAg",
            "ICAgICAgICAgICAgPGRpdiBzdHlsZT0ib3ZlcmZsb3c6YXV0bzttYXgtaGVpZ2h0OjYwdmgiPgogICAgICAgICAgICAgICAgICAgIDx0YWJsZSBpZD0iY2Vy",
            "dHNUYWJsZSI+CiAgICAgICAgICAgICAgICAgICAgICA8dGhlYWQ+PHRyPjx0aD7luo/liJflj7c8L3RoPjx0aD7nsbvlnos8L3RoPjx0aD7nirbmgIE8L3Ro",
            "Pjx0aD7ljp/lm6A8L3RoPjx0aD7ml7bpl7Q8L3RoPjx0aD7pooHlj5HogIVJRDwvdGg+PHRoPueul+azlTwvdGg+PHRoPuaTjeS9nDwvdGg+PC90cj48L3Ro",
            "ZWFkPgogICAgICAgICAgICAgICAgICAgICAgPHRib2R5PjwvdGJvZHk+CiAgICAgICAgICAgICAgICAgICAgPC90YWJsZT4KICAgICAgICAgICAgICAgICAg",
            "PC9kaXY+CiAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgIDxkaXYgaWQ9ImNzUGFuZUNhIiBzdHlsZT0iZGlzcGxheTpub25lIj4KICAg",
            "ICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iaGludCI+SkFWQSDnjq/looMgbGliL3NlY3VyaXR5L2NhY2VydHMg5Lit55qE5Y+v5L+h6K+B5Lmm77yI5Y+q",
            "6K+75Y+C6ICD77yJ44CC54K55Ye7IuivpuaDhSLlj6/mn6XnnIsgUEVNIOivgeS5pue7k+aehO+8iEpTT07vvInjgILmnKzlnLDor4Hkuabmlofku7bpqozo",
            "r4Hor7fliLAi6K+B5Lmm6aqM6K+BIumhtemdouS4iuS8oOOAgjwvZGl2PgogICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0b29sYmFyIj4KICAgICAg",
            "ICAgICAgICAgICAgICA8aW5wdXQgaWQ9ImNhRmlsdGVyIiBwbGFjZWhvbGRlcj0i562b6YCJ77ya5bqP5YiX5Y+3IC8g6aKB5Y+R6ICFIC8g566X5rOVIiBz",
            "dHlsZT0iZmxleDoxO21heC13aWR0aDozNjBweCIgb25pbnB1dD0icmVuZGVyQ2FjZXJ0cygpIj4KICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNz",
            "PSJnaG9zdCIgb25jbGljaz0ibG9hZENhY2VydHMoKSI+5Yi35paw5YiX6KGoPC9idXR0b24+CiAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAg",
            "ICAgICAgICA8ZGl2IHN0eWxlPSJvdmVyZmxvdzphdXRvO21heC1oZWlnaHQ6NjB2aCI+CiAgICAgICAgICAgICAgICAgICAgPHRhYmxlIGlkPSJjYVRhYmxl",
            "Ij4KICAgICAgICAgICAgICAgICAgICAgIDx0aGVhZD48dHI+PHRoPuW6j+WIl+WPtzwvdGg+PHRoPueul+azlTwvdGg+PHRoPueUn+aViOaXpeacnzwvdGg+",
            "PHRoPuWkseaViOaXpeacnzwvdGg+PHRoPkRO5a2X5q61PC90aD48dGg+5pON5L2cPC90aD48L3RyPjwvdGhlYWQ+CiAgICAgICAgICAgICAgICAgICAgICA8",
            "dGJvZHk+PC90Ym9keT4KICAgICAgICAgICAgICAgICAgICA8L3RhYmxlPgogICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgIDwvZGl2",
            "PgogICAgICAgICAgICAgICAgPGRpdiBpZD0iY3NQYW5lTXkiIHN0eWxlPSJkaXNwbGF5Om5vbmUiPgogICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0",
            "b29sYmFyIj4KICAgICAgICAgICAgICAgICAgICA8aW5wdXQgaWQ9Im15RmlsdGVyIiBwbGFjZWhvbGRlcj0i562b6YCJ77ya5bqP5YiX5Y+3IC8g57G75Z6L",
            "IC8g566X5rOVIiBzdHlsZT0iZmxleDoxO21heC13aWR0aDozNjBweCIgb25pbnB1dD0icmVuZGVyTXkoKSI+CiAgICAgICAgICAgICAgICAgICAgPGJ1dHRv",
            "biBjbGFzcz0icHJpbWFyeSIgb25jbGljaz0iJCgnbXlGaWxlJykuY2xpY2soKSI+5a+85YWl6K+B5LmmPC9idXR0b24+CiAgICAgICAgICAgICAgICAgICAg",
            "PGJ1dHRvbiBjbGFzcz0iZ2hvc3QiIG9uY2xpY2s9ImxvYWRNeSgpIj7liLfmlrDliJfooag8L2J1dHRvbj4KICAgICAgICAgICAgICAgICAgPC9kaXY+CiAg",
            "ICAgICAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJmaWxlIiBpZD0ibXlGaWxlIiBhY2NlcHQ9Ii5wZngsLnAxMiwuamtzLC5jZXIsLmNydCwucGVtIiBzdHls",
            "ZT0iZGlzcGxheTpub25lIiBvbmNoYW5nZT0ibXlGaWxlQ2hvc2VuKCkiPgogICAgICAgICAgICAgICAgICA8ZGl2IGlkPSJteU1zZyIgY2xhc3M9ImhpbnQi",
            "IHN0eWxlPSJtYXJnaW46NnB4IDA7Y29sb3I6dmFyKC0tZGltKSI+5LuO5pys5py65a+85YWl6K+B5Lmm77yIcGZ4IC8gcDEyIC8gamtzIOmcgOi+k+WFpeWv",
            "huegge+8m2NlciAvIGNydCAvIHBlbSDnm7TmjqXlr7zlhaXvvIzlj6/lkKvnp4HpkqXvvInjgII8L2Rpdj4KICAgICAgICAgICAgICAgICAgPGRpdiBzdHls",
            "ZT0ib3ZlcmZsb3c6YXV0bzttYXgtaGVpZ2h0OjYwdmgiPgogICAgICAgICAgICAgICAgICAgIDx0YWJsZSBpZD0ibXlUYWJsZSI+CiAgICAgICAgICAgICAg",
            "ICAgICAgICA8dGhlYWQ+PHRyPjx0aD7luo/liJflj7c8L3RoPjx0aD7nsbvlnos8L3RoPjx0aD7nrpfms5U8L3RoPjx0aD7mmK/lkKblkKvmnInnp4HpkqU8",
            "L3RoPjx0aD7nlJ/mlYjml6XmnJ88L3RoPjx0aD7lpLHmlYjml6XmnJ88L3RoPjx0aD7mk43kvZw8L3RoPjwvdHI+PC90aGVhZD4KICAgICAgICAgICAgICAg",
            "ICAgICAgIDx0Ym9keT48L3Rib2R5PgogICAgICAgICAgICAgICAgICAgIDwvdGFibGU+CiAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAg",
            "ICAgPC9kaXY+CiAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgPCEtLSDnrb7lj5HmoLnor4HkuaYgLS0+CiAg",
            "ICAgICAgICAgIDxkaXYgY2xhc3M9InBhZ2UiIGlkPSJwYWdlLW1ha2Vyb290Ij4KICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgICAg",
            "ICAgICAgIDxoMj7nrb7lj5HmoLnor4HkuabvvIhNYWtlUm9vdO+8iTwvaDI+CiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJyb3ciPgogICAgICAgICAg",
            "ICAgICAgICA8ZGl2IHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj48bGFiZWw+6K+B5LmmIERO77yI6YCX5Y+35YiG6ZqUIGtleT12YWx1Ze+8iTwvbGFiZWw+",
            "PGlucHV0IGlkPSJta0RuIiBwbGFjZWhvbGRlcj0i5qC56K+B5LmmIERO77yIa2V5PXZhbHVlIOmAl+WPt+WIhumalO+8jGtleSDlj6/kuLrmoIflh4blsZ7m",
            "gKfmiJYgT0lE77yJ77yM5aaCIENOPU15IFJvb3QgQ0EsTz1NeSBPcmcsQz1DTiI+PC9kaXY+CiAgICAgICAgICAgICAgICAgIDxkaXY+PGxhYmVsPuWvhumS",
            "peeul+azlTwvbGFiZWw+PHNlbGVjdCBpZD0ibWtBbGdvIiBvbmNoYW5nZT0iZXh0QWxnb0NoYW5nZWQoJ21rJykiPjxvcHRpb24+UlNBPC9vcHRpb24+PG9w",
            "dGlvbj5SU0EtUFNTPC9vcHRpb24+PG9wdGlvbj5FQ0M8L29wdGlvbj48b3B0aW9uPlNNMjwvb3B0aW9uPjxvcHRpb24+RFNBPC9vcHRpb24+PG9wdGlvbj5F",
            "ZERTQTwvb3B0aW9uPjxvcHRpb24+UFFDPC9vcHRpb24+PC9zZWxlY3Q+PC9kaXY+CiAgICAgICAgICAgICAgICAgIDxkaXY+PGxhYmVsPuWTiOW4jOeul+az",
            "lTwvbGFiZWw+PHNlbGVjdCBpZD0ibWtIYXNoIj48b3B0aW9uPnNoYTI1Njwvb3B0aW9uPjxvcHRpb24+c2hhMTwvb3B0aW9uPjxvcHRpb24+c2hhMzg0PC9v",
            "cHRpb24+PG9wdGlvbj5zaGE1MTI8L29wdGlvbj48b3B0aW9uPlNIQTMtMjI0PC9vcHRpb24+PG9wdGlvbj5TSEEzLTI1Njwvb3B0aW9uPjxvcHRpb24+U0hB",
            "My0zODQ8L29wdGlvbj48b3B0aW9uPlNIQTMtNTEyPC9vcHRpb24+PG9wdGlvbj5TTTM8L29wdGlvbj48b3B0aW9uPk5VTEw8L29wdGlvbj48L3NlbGVjdD48",
            "L2Rpdj4KICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+5a+G6ZKl5L2N5pWwPC9sYWJlbD48c2VsZWN0IGlkPSJta0JpdHMiPjwvc2VsZWN0PjwvZGl2",
            "PgogICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJmc2VjIiBzdHlsZT0ibWFyZ2luLXRvcDoxNHB4Ij4KICAgICAg",
            "ICAgICAgICAgICAgPGRpdiBjbGFzcz0iZnNlYy10aXRsZSI+RE4g6L6F5Yqp57yW6L6RIOKAlCDln7rnoYDlrZfmrrUgLyBFViDms6jlhozlrZfmrrUgLyDo",
            "h6rlrprkuYkgT0lEPC9kaXY+CiAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InJvdyI+CiAgICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+Q04g",
            "6YCa55So5ZCN56ewPC9sYWJlbD48aW5wdXQgaWQ9Im1rRG5DbiIgcGxhY2Vob2xkZXI9IumAmueUqOWQjeensO+8iENO77yJ77yM5aaCIE15IFJvb3QgQ0Ei",
            "IG9uaW5wdXQ9InN5bmNNa0RuKCkiPjwvZGl2PgogICAgICAgICAgICAgICAgICAgIDxkaXY+PGxhYmVsPk8g57uE57uHPC9sYWJlbD48aW5wdXQgaWQ9Im1r",
            "RG5PIiBwbGFjZWhvbGRlcj0i57uE57uH77yIT++8ie+8jOWmgiBNeSBPcmciIG9uaW5wdXQ9InN5bmNNa0RuKCkiPjwvZGl2PgogICAgICAgICAgICAgICAg",
            "ICAgIDxkaXY+PGxhYmVsPk9VIOe7hOe7h+WNleS9jTwvbGFiZWw+PGlucHV0IGlkPSJta0RuT3UiIHBsYWNlaG9sZGVyPSLnu4Tnu4fljZXkvY3vvIhPVe+8",
            "ie+8jOWmgiBJVCBEZXB077yI5Y+v6YCJ77yJIiBvbmlucHV0PSJzeW5jTWtEbigpIj48L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2PjxsYWJlbD5D",
            "IOWbveWutjwvbGFiZWw+PGlucHV0IGlkPSJta0RuQyIgcGxhY2Vob2xkZXI9IuWbveWutuS7o+egge+8iEPvvInvvIzlpoIgQ07vvIjkuKTkvY3vvIkiIG1h",
            "eGxlbmd0aD0iMiIgb25pbnB1dD0ic3luY01rRG4oKSI+PC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+UyDnnIEv5beePC9sYWJlbD48",
            "aW5wdXQgaWQ9Im1rRG5TIiBwbGFjZWhvbGRlcj0i55yBL+W3nu+8iFPvvInvvIzlpoIgR3Vhbmdkb25n77yI5Y+v6YCJ77yJIiBvbmlucHV0PSJzeW5jTWtE",
            "bigpIj48L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2PjxsYWJlbD5MIOWfjuW4gjwvbGFiZWw+PGlucHV0IGlkPSJta0RuTCIgcGxhY2Vob2xkZXI9",
            "IuWfjuW4gu+8iEzvvInvvIzlpoIgU2hlbnpoZW7vvIjlj6/pgInvvIkiIG9uaW5wdXQ9InN5bmNNa0RuKCkiPjwvZGl2PgogICAgICAgICAgICAgICAgICAg",
            "IDxkaXY+PGxhYmVsPkUg6YKu566x77yIT0lEIOWtl+aute+8iTwvbGFiZWw+PGlucHV0IGlkPSJta0RuRSIgcGxhY2Vob2xkZXI9IumCrueuse+8iEXvvIxP",
            "SUQgMS4yLjg0MC4xMTM1NDkuMS45LjHvvInvvIzlpoIgYWRtaW5AZXhhbXBsZS5jb20iIG9uaW5wdXQ9InN5bmNNa0RuKCkiPjwvZGl2PgogICAgICAgICAg",
            "ICAgICAgICAgIDxkaXY+PGxhYmVsPuaYr+WQpiBFViDmianlsZXpqozor4E8L2xhYmVsPgogICAgICAgICAgICAgICAgICAgICAgPGxhYmVsIHN0eWxlPSJk",
            "aXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OmZsZXgtc3RhcnQ7YWxpZ24taXRlbXM6Y2VudGVyO3dpZHRoOjEwMCU7aGVpZ2h0OjMycHg7Y3Vyc29yOnBv",
            "aW50ZXI7bWFyZ2luOjAiPjxpbnB1dCB0eXBlPSJjaGVja2JveCIgaWQ9Im1rRG5FdlRvZ2dsZSIgb25jaGFuZ2U9InRvZ2dsZU1rRG5FdigpIiBzdHlsZT0i",
            "bWFyZ2luOjA7ZmxleDpub25lIj48L2xhYmVsPgogICAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAg",
            "ICAgICAgICAgPGRpdiBpZD0ibWtEbkV2RmllbGRzIiBzdHlsZT0ibWFyZ2luLXRvcDoxNHB4O2Rpc3BsYXk6bm9uZSI+CiAgICAgICAgICAgICAgICAgICAg",
            "PGRpdiBjbGFzcz0iZnNlYy10aXRsZSIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O21hcmdpbi1ib3R0b206OHB4Ij5FViDms6jlhozlrZfmrrXvvIhFViBHdWlk",
            "ZWxpbmVzIOS4k+WxniBPSUTvvJvms6jlhoznsbvlnovlm5vpgInkuIDvvIzms6jlhozlj7floavokKXkuJrmiafnhacv57uf5LiA56S+5Lya5L+h55So5Luj",
            "56CB77yJPC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0icm93Ij4KICAgICAgICAgICAgICAgICAgICAgIDxkaXY+PGxhYmVsPuazqOWG",
            "jOexu+Wei++8iGJ1c2luZXNzQ2F0ZWdvcnkgMi41LjQuMTXvvIk8L2xhYmVsPgogICAgICAgICAgICAgICAgICAgICAgICA8c2VsZWN0IGlkPSJta0RuQmMi",
            "IG9uY2hhbmdlPSJzeW5jTWtEbigpIj4KICAgICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSIiPu+8iOS4jeWhq++8iTwvb3B0aW9uPgog",
            "ICAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24+UHJpdmF0ZSBPcmdhbml6YXRpb248L29wdGlvbj4KICAgICAgICAgICAgICAgICAgICAgICAgICA8",
            "b3B0aW9uPkdvdmVybm1lbnQgRW50aXR5PC9vcHRpb24+CiAgICAgICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbj5CdXNpbmVzcyBFbnRpdHk8L29wdGlv",
            "bj4KICAgICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uPk5vbi1Db21tZXJjaWFsIEVudGl0eTwvb3B0aW9uPgogICAgICAgICAgICAgICAgICAgICAg",
            "ICA8L3NlbGVjdD4KICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+5rOo5YaM5Y+377yIc2Vy",
            "aWFsTnVtYmVyIDIuNS40LjXvvIk8L2xhYmVsPjxpbnB1dCBpZD0ibWtEblJlZyIgcGxhY2Vob2xkZXI9IuazqOWGjOWPt++8iHNlcmlhbE51bWJlciAyLjUu",
            "NC4177yJ77yM5aaCIDkxMzEwMDAwTUE1WFhYWFhYWFgiIG9uaW5wdXQ9InN5bmNNa0RuKCkiPjwvZGl2PgogICAgICAgICAgICAgICAgICAgICAgPGRpdj48",
            "bGFiZWw+5rOo5YaM5Zu95a6277yIanVyaXNkaWN0aW9uQ291bnRyee+8iTwvbGFiZWw+PGlucHV0IGlkPSJta0RuSmMiIHBsYWNlaG9sZGVyPSLms6jlhozl",
            "m73lrrbvvIhqdXJpc2RpY3Rpb25Db3VudHJ577yJ77yM5aaCIENO77yI5Lik5L2N77yJIiBtYXhsZW5ndGg9IjIiIG9uaW5wdXQ9InN5bmNNa0RuKCkiPjwv",
            "ZGl2PgogICAgICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+5rOo5YaM55yB77yIanVyaXNkaWN0aW9uU3RhdGVPclByb3ZpbmNl77yJPC9sYWJlbD48",
            "aW5wdXQgaWQ9Im1rRG5KcyIgcGxhY2Vob2xkZXI9IuazqOWGjOecge+8iGp1cmlzZGljdGlvblN0YXRlT3JQcm92aW5jZe+8ie+8jOWmgiBHdWFuZ2Rvbmfv",
            "vIjlj6/pgInvvIkiIG9uaW5wdXQ9InN5bmNNa0RuKCkiPjwvZGl2PgogICAgICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+5rOo5YaM5biC77yIanVy",
            "aXNkaWN0aW9uTG9jYWxpdHnvvIk8L2xhYmVsPjxpbnB1dCBpZD0ibWtEbkpsIiBwbGFjZWhvbGRlcj0i5rOo5YaM5biC77yIanVyaXNkaWN0aW9uTG9jYWxp",
            "dHnvvInvvIzlpoIgU2hlbnpoZW7vvIjlj6/pgInvvIkiIG9uaW5wdXQ9InN5bmNNa0RuKCkiPjwvZGl2PgogICAgICAgICAgICAgICAgICAgICAgPGRpdj48",
            "bGFiZWw+5rOo5YaM5Zyw5Z2A77yIc3RyZWV0QWRkcmVzcyAyLjUuNC4577yJPC9sYWJlbD48aW5wdXQgaWQ9Im1rRG5BZGRyIiBwbGFjZWhvbGRlcj0i5rOo",
            "5YaM5Zyw5Z2A77yIc3RyZWV0QWRkcmVzcyAyLjUuNC4577yJ77yM5aaCIE5vLjEgQmVpamluZyBSb2Fk77yI5Y+v6YCJ77yJIiBvbmlucHV0PSJzeW5jTWtE",
            "bigpIj48L2Rpdj4KICAgICAgICAgICAgICAgICAgICAgIDxkaXY+PGxhYmVsPue7hOe7h+agh+ivhuespu+8iDIuNS40Ljk377yJPC9sYWJlbD48aW5wdXQg",
            "aWQ9Im1rRG5PaSIgcGxhY2Vob2xkZXI9Iue7hOe7h+agh+ivhuespu+8iDIuNS40Ljk377yJ77yM5aaCIE5UUkNOLTkxMzEwMDAwTUE1WFhYWFhYWFgiIG9u",
            "aW5wdXQ9InN5bmNNa0RuKCkiPjwvZGl2PgogICAgICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+57uE57uH5qCH6K+G56ym5omp5bGVIE9JRCDniYjm",
            "nKw8L2xhYmVsPgogICAgICAgICAgICAgICAgICAgICAgICA8bGFiZWwgc3R5bGU9ImRpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6ZmxleC1zdGFydDth",
            "bGlnbi1pdGVtczpjZW50ZXI7d2lkdGg6MTAwJTtoZWlnaHQ6MzJweDtjdXJzb3I6cG9pbnRlcjttYXJnaW46MCIgdGl0bGU9IuacquWLvumAiT3ml6fniYgg",
            "MS4zLjYuMS40LjEuNTcyNjQuMS4477yIU0MyNy0yMDE577yJ77yb5Yu+6YCJPeaWsOeJiCAyLjIzLjE0MC4zLjHvvIhFVkcgMi4wLjHvvIkiPjxpbnB1dCB0",
            "eXBlPSJjaGVja2JveCIgaWQ9Im1rRG5PaWROZXciIHN0eWxlPSJtYXJnaW46MDtmbGV4Om5vbmUiPjwvbGFiZWw+CiAgICAgICAgICAgICAgICAgICAgICA8",
            "L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9Im1h",
            "cmdpbi10b3A6MTJweCI+CiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZnNlYy10aXRsZSIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O21hcmdpbi1i",
            "b3R0b206OHB4Ij7oh6rlrprkuYnlrZfmrrXvvIhrZXkg5Y+v5YaZ5a2X5q615ZCN5oiW5a+56LGh5qCH6K+G56ymIE9JRO+8jOWmgiAyLjUuNC40Mj3lvKDk",
            "uInjgIEyLjIzLjE0MC4xLjE9RVbvvIk8L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IGlkPSJta0RuT2lkUm93cyI+PC9kaXY+CiAgICAgICAgICAg",
            "ICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJnaG9zdCIgb25jbGljaz0iYWRkTWtEblJvdygnJywnJykiPisg5re75Yqg6Ieq5a6a5LmJ",
            "5a2X5q61PC9idXR0b24+CiAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJtYXJnaW4tdG9wOjEycHg7ZGlz",
            "cGxheTpmbGV4O2dhcDoxMHB4O2FsaWduLWl0ZW1zOmNlbnRlcjtmbGV4LXdyYXA6d3JhcCI+CiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiB0eXBlPSJi",
            "dXR0b24iIGNsYXNzPSJnaG9zdCIgb25jbGljaz0icGFyc2VNa0RuKCkiPuS7juS4iuaWuSBETiDop6PmnpDlm57loas8L2J1dHRvbj4KICAgICAgICAgICAg",
            "ICAgICAgICA8c3BhbiBzdHlsZT0iY29sb3I6dmFyKC0tZGltKTtmb250LXNpemU6MTJweCI+6L6F5Yqp57yW6L6R5a6e5pe25ZCM5q2l5Yiw5LiK5pa5IERO",
            "IOi+k+WFpeahhu+8m+S5n+WPr+ebtOaOpee8lui+kSBETiDlkI7ngrnigJzop6PmnpDlm57loavigJ3mi4bliIbliLDlkITlrZfmrrXjgII8L3NwYW4+CiAg",
            "ICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJtYXJnaW4tdG9wOjE2cHgi",
            "PjxidXR0b24gb25jbGljaz0icG9zdEZvcm0oJy9hcGkvbWFrZXJvb3QnLCB7ZG46dignbWtEbicpLGJpdHM6ZXh0Qml0c1ZhbCgnbWsnKSxoYXNoOnYoJ21r",
            "SGFzaCcpLGFsZ286dignbWtBbGdvJyksZXZvaWQ6ICQoJ21rRG5PaWROZXcnKSAmJiAkKCdta0RuT2lkTmV3JykuY2hlY2tlZCA/ICduZXcnIDogJ29sZCd9",
            "LCAnbWtPdXQnKSI+562+5Y+R5qC56K+B5LmmPC9idXR0b24+PC9kaXY+CiAgICAgICAgICAgICAgICA8cHJlIGNsYXNzPSJvdXQiIGlkPSJta091dCI+PC9w",
            "cmU+CiAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgPCEtLSDnrb7lj5Hor4HkuaYgLS0+CiAgICAgICAgICAg",
            "IDxkaXYgY2xhc3M9InBhZ2UiIGlkPSJwYWdlLXNpZ25jZXJ0Ij4KICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgICAgICAgICAgIDxo",
            "Mj7nrb7lj5Hor4HkuabvvIhNYWtlQ2VydCDmma7pgJrmqKHlvI/vvIwxMiDlj4LmlbDvvIk8L2gyPgoKICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZz",
            "ZWMiPjxkaXYgY2xhc3M9ImZzZWMtdGl0bGUiPuS4u+S9k+S/oeaBrzwvZGl2PgogICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJyb3ciPgogICAgICAg",
            "ICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPjxsYWJlbD7or4HkuaYgRE7vvIhrZXk9dmFsdWUg6YCX5Y+35YiG6ZqU77yMa2V5",
            "IOWPr+S4uuagh+WHhuWxnuaAp+aIliBPSUTvvIk8L2xhYmVsPjxpbnB1dCBpZD0ic2NEbiIgcGxhY2Vob2xkZXI9IuivgeS5piBETu+8iGtleT12YWx1ZSDp",
            "gJflj7fliIbpmpTvvIxrZXkg5Y+v5Li65qCH5YeG5bGe5oCn5oiWIE9JRO+8ie+8jOWmgiBDTj13d3cudGVzdC5jb20sTz1NeSBPcmcsQz1DTiI+PC9kaXY+",
            "CiAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZnNlYyIgc3R5bGU9",
            "Im1hcmdpbi10b3A6MTRweCI+CiAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZzZWMtdGl0bGUiPkROIOi+heWKqee8lui+kSDigJQg5Z+656GA5a2X",
            "5q61IC8gRVYg5rOo5YaM5a2X5q61IC8g6Ieq5a6a5LmJIE9JRDwvZGl2PgogICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJyb3ciPgogICAgICAgICAg",
            "ICAgICAgICAgIDxkaXY+PGxhYmVsPkNOIOmAmueUqOWQjeensDwvbGFiZWw+PGlucHV0IGlkPSJzY0RuQ24iIHBsYWNlaG9sZGVyPSLpgJrnlKjlkI3np7Dv",
            "vIhDTu+8ie+8jOWmgiB3d3cudGVzdC5jb20iIG9uaW5wdXQ9InN5bmNEbignc2MnKSI+PC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+",
            "TyDnu4Tnu4c8L2xhYmVsPjxpbnB1dCBpZD0ic2NEbk8iIHBsYWNlaG9sZGVyPSLnu4Tnu4fvvIhP77yJ77yM5aaCIE15IE9yZyIgb25pbnB1dD0ic3luY0Ru",
            "KCdzYycpIj48L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2PjxsYWJlbD5PVSDnu4Tnu4fljZXkvY08L2xhYmVsPjxpbnB1dCBpZD0ic2NEbk91IiBw",
            "bGFjZWhvbGRlcj0i57uE57uH5Y2V5L2N77yIT1XvvInvvIzlpoIgSVQgRGVwdO+8iOWPr+mAie+8iSIgb25pbnB1dD0ic3luY0RuKCdzYycpIj48L2Rpdj4K",
            "ICAgICAgICAgICAgICAgICAgICA8ZGl2PjxsYWJlbD5DIOWbveWutjwvbGFiZWw+PGlucHV0IGlkPSJzY0RuQyIgcGxhY2Vob2xkZXI9IuWbveWutuS7o+eg",
            "ge+8iEPvvInvvIzlpoIgQ07vvIjkuKTkvY3vvIkiIG1heGxlbmd0aD0iMiIgb25pbnB1dD0ic3luY0RuKCdzYycpIj48L2Rpdj4KICAgICAgICAgICAgICAg",
            "ICAgICA8ZGl2PjxsYWJlbD5TIOecgS/lt548L2xhYmVsPjxpbnB1dCBpZD0ic2NEblMiIHBsYWNlaG9sZGVyPSLnnIEv5bee77yIU++8ie+8jOWmgiBHdWFu",
            "Z2RvbmfvvIjlj6/pgInvvIkiIG9uaW5wdXQ9InN5bmNEbignc2MnKSI+PC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+TCDln47luII8",
            "L2xhYmVsPjxpbnB1dCBpZD0ic2NEbkwiIHBsYWNlaG9sZGVyPSLln47luILvvIhM77yJ77yM5aaCIFNoZW56aGVu77yI5Y+v6YCJ77yJIiBvbmlucHV0PSJz",
            "eW5jRG4oJ3NjJykiPjwvZGl2PgogICAgICAgICAgICAgICAgICAgIDxkaXY+PGxhYmVsPkUg6YKu566x77yIT0lEIOWtl+aute+8iTwvbGFiZWw+PGlucHV0",
            "IGlkPSJzY0RuRSIgcGxhY2Vob2xkZXI9IumCrueuse+8iEXvvIxPSUQgMS4yLjg0MC4xMTM1NDkuMS45LjHvvInvvIzlpoIgYWRtaW5AZXhhbXBsZS5jb20i",
            "IG9uaW5wdXQ9InN5bmNEbignc2MnKSI+PC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+5piv5ZCmIEVWIOaJqeWxlemqjOivgTwvbGFi",
            "ZWw+CiAgICAgICAgICAgICAgICAgICAgICA8bGFiZWwgc3R5bGU9ImRpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6ZmxleC1zdGFydDthbGlnbi1pdGVt",
            "czpjZW50ZXI7d2lkdGg6MTAwJTtoZWlnaHQ6MzJweDtjdXJzb3I6cG9pbnRlcjttYXJnaW46MCI+PGlucHV0IHR5cGU9ImNoZWNrYm94IiBpZD0ic2NEbkV2",
            "VG9nZ2xlIiBvbmNoYW5nZT0idG9nZ2xlRG5Fdignc2MnKSIgc3R5bGU9Im1hcmdpbjowO2ZsZXg6bm9uZSI+PC9sYWJlbD4KICAgICAgICAgICAgICAgICAg",
            "ICA8L2Rpdj4KICAgICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICAgIDxkaXYgaWQ9InNjRG5FdkZpZWxkcyIgc3R5bGU9Im1hcmdpbi10",
            "b3A6MTRweDtkaXNwbGF5Om5vbmUiPgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZzZWMtdGl0bGUiIHN0eWxlPSJmb250LXNpemU6MTJweDtt",
            "YXJnaW4tYm90dG9tOjhweCI+RVYg5rOo5YaM5a2X5q6177yIRVYgR3VpZGVsaW5lcyDkuJPlsZ4gT0lE77yb5rOo5YaM57G75Z6L5Zub6YCJ5LiA77yM5rOo",
            "5YaM5Y+35aGr6JCl5Lia5omn54WnL+e7n+S4gOekvuS8muS/oeeUqOS7o+egge+8iTwvZGl2PgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InJv",
            "dyI+CiAgICAgICAgICAgICAgICAgICAgICA8ZGl2PjxsYWJlbD7ms6jlhoznsbvlnovvvIhidXNpbmVzc0NhdGVnb3J5IDIuNS40LjE177yJPC9sYWJlbD4K",
            "ICAgICAgICAgICAgICAgICAgICAgICAgPHNlbGVjdCBpZD0ic2NEbkJjIiBvbmNoYW5nZT0ic3luY0RuKCdzYycpIj4KICAgICAgICAgICAgICAgICAgICAg",
            "ICAgICA8b3B0aW9uIHZhbHVlPSIiPu+8iOS4jeWhq++8iTwvb3B0aW9uPgogICAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24+UHJpdmF0ZSBPcmdh",
            "bml6YXRpb248L29wdGlvbj4KICAgICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uPkdvdmVybm1lbnQgRW50aXR5PC9vcHRpb24+CiAgICAgICAgICAg",
            "ICAgICAgICAgICAgICAgPG9wdGlvbj5CdXNpbmVzcyBFbnRpdHk8L29wdGlvbj4KICAgICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uPk5vbi1Db21t",
            "ZXJjaWFsIEVudGl0eTwvb3B0aW9uPgogICAgICAgICAgICAgICAgICAgICAgICA8L3NlbGVjdD4KICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAg",
            "ICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+5rOo5YaM5Y+377yIc2VyaWFsTnVtYmVyIDIuNS40LjXvvIk8L2xhYmVsPjxpbnB1dCBpZD0ic2NEblJl",
            "ZyIgcGxhY2Vob2xkZXI9IuazqOWGjOWPt++8iHNlcmlhbE51bWJlciAyLjUuNC4177yJ77yM5aaCIDkxMzEwMDAwTUE1WFhYWFhYWFgiIG9uaW5wdXQ9InN5",
            "bmNEbignc2MnKSI+PC9kaXY+CiAgICAgICAgICAgICAgICAgICAgICA8ZGl2PjxsYWJlbD7ms6jlhozlm73lrrbvvIhqdXJpc2RpY3Rpb25Db3VudHJ577yJ",
            "PC9sYWJlbD48aW5wdXQgaWQ9InNjRG5KYyIgcGxhY2Vob2xkZXI9IuazqOWGjOWbveWutu+8iGp1cmlzZGljdGlvbkNvdW50cnnvvInvvIzlpoIgQ07vvIjk",
            "uKTkvY3vvIkiIG1heGxlbmd0aD0iMiIgb25pbnB1dD0ic3luY0RuKCdzYycpIj48L2Rpdj4KICAgICAgICAgICAgICAgICAgICAgIDxkaXY+PGxhYmVsPuaz",
            "qOWGjOecge+8iGp1cmlzZGljdGlvblN0YXRlT3JQcm92aW5jZe+8iTwvbGFiZWw+PGlucHV0IGlkPSJzY0RuSnMiIHBsYWNlaG9sZGVyPSLms6jlhoznnIHv",
            "vIhqdXJpc2RpY3Rpb25TdGF0ZU9yUHJvdmluY2XvvInvvIzlpoIgR3Vhbmdkb25n77yI5Y+v6YCJ77yJIiBvbmlucHV0PSJzeW5jRG4oJ3NjJykiPjwvZGl2",
            "PgogICAgICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+5rOo5YaM5biC77yIanVyaXNkaWN0aW9uTG9jYWxpdHnvvIk8L2xhYmVsPjxpbnB1dCBpZD0i",
            "c2NEbkpsIiBwbGFjZWhvbGRlcj0i5rOo5YaM5biC77yIanVyaXNkaWN0aW9uTG9jYWxpdHnvvInvvIzlpoIgU2hlbnpoZW7vvIjlj6/pgInvvIkiIG9uaW5w",
            "dXQ9InN5bmNEbignc2MnKSI+PC9kaXY+CiAgICAgICAgICAgICAgICAgICAgICA8ZGl2PjxsYWJlbD7ms6jlhozlnLDlnYDvvIhzdHJlZXRBZGRyZXNzIDIu",
            "NS40LjnvvIk8L2xhYmVsPjxpbnB1dCBpZD0ic2NEbkFkZHIiIHBsYWNlaG9sZGVyPSLms6jlhozlnLDlnYDvvIhzdHJlZXRBZGRyZXNzIDIuNS40LjnvvInv",
            "vIzlpoIgTm8uMSBCZWlqaW5nIFJvYWTvvIjlj6/pgInvvIkiIG9uaW5wdXQ9InN5bmNEbignc2MnKSI+PC9kaXY+CiAgICAgICAgICAgICAgICAgICAgICA8",
            "ZGl2PjxsYWJlbD7nu4Tnu4fmoIfor4bnrKbvvIgyLjUuNC45N++8iTwvbGFiZWw+PGlucHV0IGlkPSJzY0RuT2kiIHBsYWNlaG9sZGVyPSLnu4Tnu4fmoIfo",
            "r4bnrKbvvIgyLjUuNC45N++8ie+8jOWmgiBOVFJDTi05MTMxMDAwME1BNVhYWFhYWFhYIiBvbmlucHV0PSJzeW5jRG4oJ3NjJykiPjwvZGl2PgogICAgICAg",
            "ICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+57uE57uH5qCH6K+G56ym5omp5bGVIE9JRCDniYjmnKw8L2xhYmVsPgogICAgICAgICAgICAgICAgICAgICAg",
            "ICA8bGFiZWwgc3R5bGU9ImRpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6ZmxleC1zdGFydDthbGlnbi1pdGVtczpjZW50ZXI7d2lkdGg6MTAwJTtoZWln",
            "aHQ6MzJweDtjdXJzb3I6cG9pbnRlcjttYXJnaW46MCIgdGl0bGU9IuacquWLvumAiT3ml6fniYggMS4zLjYuMS40LjEuNTcyNjQuMS4477yIU0MyNy0yMDE5",
            "77yJ77yb5Yu+6YCJPeaWsOeJiCAyLjIzLjE0MC4zLjHvvIhFVkcgMi4wLjHvvIkiPjxpbnB1dCB0eXBlPSJjaGVja2JveCIgaWQ9InNjRG5PaWROZXciIHN0",
            "eWxlPSJtYXJnaW46MDtmbGV4Om5vbmUiPjwvbGFiZWw+CiAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8L2Rpdj4K",
            "ICAgICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9Im1hcmdpbi10b3A6MTJweCI+CiAgICAgICAgICAgICAgICAg",
            "ICAgPGRpdiBjbGFzcz0iZnNlYy10aXRsZSIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O21hcmdpbi1ib3R0b206OHB4Ij7oh6rlrprkuYnlrZfmrrXvvIhrZXkg",
            "5Y+v5YaZ5a2X5q615ZCN5oiW5a+56LGh5qCH6K+G56ymIE9JRO+8jOWmgiAyLjUuNC40Mj3lvKDkuInjgIEyLjIzLjE0MC4xLjE9RVbvvIk8L2Rpdj4KICAg",
            "ICAgICAgICAgICAgICAgICA8ZGl2IGlkPSJzY0RuT2lkUm93cyI+PC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNs",
            "YXNzPSJnaG9zdCIgb25jbGljaz0iYWRkRG5Sb3coJ3NjJywnJywnJykiPisg5re75Yqg6Ieq5a6a5LmJ5a2X5q61PC9idXR0b24+CiAgICAgICAgICAgICAg",
            "ICAgIDwvZGl2PgogICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJtYXJnaW4tdG9wOjEycHg7ZGlzcGxheTpmbGV4O2dhcDoxMHB4O2FsaWduLWl0ZW1z",
            "OmNlbnRlcjtmbGV4LXdyYXA6d3JhcCI+CiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJnaG9zdCIgb25jbGljaz0i",
            "cGFyc2VEbignc2MnKSI+5LuO5LiK5pa5IEROIOino+aekOWbnuWhqzwvYnV0dG9uPgogICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAg",
            "IDwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZnNlYyI+PGRpdiBjbGFzcz0iZnNlYy10aXRsZSI+5a+G6ZKl5LiO566X5rOVPC9kaXY+CiAg",
            "ICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InJvdyI+CiAgICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+6K+B5Lmm57G75Z6LPC9sYWJlbD48c2Vs",
            "ZWN0IGlkPSJzY0NhIiBvbmNoYW5nZT0ic2NDYUNoYW5nZWQoKSI+PG9wdGlvbiB2YWx1ZT0iMCI+57uI56uv6K+B5LmmPC9vcHRpb24+PG9wdGlvbiB2YWx1",
            "ZT0iMSI+5Lit6Ze0IENBPC9vcHRpb24+PC9zZWxlY3Q+PC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPGRpdiBpZD0ic2NQYXRoTGVuV3JhcCIgc3R5bGU9",
            "ImRpc3BsYXk6bm9uZSI+PGxhYmVsPui3r+W+hOmVv+W6pjwvbGFiZWw+PHNlbGVjdCBpZD0ic2NQYXRoTGVuIiB0aXRsZT0i5Lit6Ze0Q0Eg55qEIEJhc2lj",
            "Q29uc3RyYWludHMgcGF0aExlbkNvbnN0cmFpbnTvvJtudWxsIOihqOekuuS4jemZkOWItiI+PG9wdGlvbiB2YWx1ZT0iIj5udWxsPC9vcHRpb24+PG9wdGlv",
            "bj4wPC9vcHRpb24+PG9wdGlvbj4xPC9vcHRpb24+PG9wdGlvbj4yPC9vcHRpb24+PG9wdGlvbj4zPC9vcHRpb24+PG9wdGlvbj40PC9vcHRpb24+PG9wdGlv",
            "bj41PC9vcHRpb24+PG9wdGlvbj42PC9vcHRpb24+PG9wdGlvbj43PC9vcHRpb24+PG9wdGlvbj44PC9vcHRpb24+PG9wdGlvbj45PC9vcHRpb24+PC9zZWxl",
            "Y3Q+PC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+5a+G6ZKl566X5rOVPC9sYWJlbD48c2VsZWN0IGlkPSJzY0FsZ28iIG9uY2hhbmdl",
            "PSJhbGdvQ2hhbmdlZCgpIj48b3B0aW9uPlJTQTwvb3B0aW9uPjxvcHRpb24+UlNBLVBTUzwvb3B0aW9uPjxvcHRpb24+RUNDPC9vcHRpb24+PG9wdGlvbj5T",
            "TTI8L29wdGlvbj48b3B0aW9uPkRTQTwvb3B0aW9uPjxvcHRpb24+RWREU0E8L29wdGlvbj48b3B0aW9uPlBRQzwvb3B0aW9uPjwvc2VsZWN0PjwvZGl2Pgog",
            "ICAgICAgICAgICAgICAgICAgIDxkaXY+PGxhYmVsPuWvhumSpeS9jeaVsDwvbGFiZWw+PHNlbGVjdCBpZD0ic2NCaXRzIj48L3NlbGVjdD48L2Rpdj4KICAg",
            "ICAgICAgICAgICAgICAgICA8ZGl2PjxsYWJlbD7lk4jluIznrpfms5U8L2xhYmVsPjxzZWxlY3QgaWQ9InNjSGFzaCI+PG9wdGlvbj5zaGEyNTY8L29wdGlv",
            "bj48b3B0aW9uPnNoYTE8L29wdGlvbj48b3B0aW9uPnNoYTM4NDwvb3B0aW9uPjxvcHRpb24+c2hhNTEyPC9vcHRpb24+PG9wdGlvbj5TSEEzLTIyNDwvb3B0",
            "aW9uPjxvcHRpb24+U0hBMy0yNTY8L29wdGlvbj48b3B0aW9uPlNIQTMtMzg0PC9vcHRpb24+PG9wdGlvbj5TSEEzLTUxMjwvb3B0aW9uPjxvcHRpb24+U00z",
            "PC9vcHRpb24+PG9wdGlvbj5OVUxMPC9vcHRpb24+PC9zZWxlY3Q+PC9kaXY+CiAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgPC9k",
            "aXY+CgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZnNlYyI+PGRpdiBjbGFzcz0iZnNlYy10aXRsZSI+5a+G6ZKl55So6YCUPC9kaXY+CiAgICAgICAg",
            "ICAgICAgICAgIDxkaXYgY2xhc3M9InJvdyI+CiAgICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+S2V5VXNhZ2Ug57yW5Y+3PC9sYWJlbD4KICAgICAg",
            "ICAgICAgICAgICAgICAgIDxzZWxlY3QgaWQ9InNjS3UiIG9uY2hhbmdlPSJrdVNlbENoYW5nZWQoKSI+CiAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRp",
            "b24gdmFsdWU9IiI+77yI5pegIEtleVVzYWdlIOaJqeWxle+8iTwvb3B0aW9uPgogICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSIxIj4x",
            "IC0g5pWw5a2X562+5ZCNK+S4jeWPr+WQpuiupCvlr4bpkqXliqDlr4Yr5pWw5o2u5Yqg5a+GK+WvhumSpeWNj+WVhu+8iOmAmueUqO+8iTwvb3B0aW9uPgog",
            "ICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSIyIj4yIC0g5pWw5a2X562+5ZCNK+S4jeWPr+WQpuiupCvor4Hkuabnrb7lkI0rQ1JM562+",
            "5ZCN77yIQ0HnlKjpgJTvvIk8L29wdGlvbj4KICAgICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iMyI+MyAtIOS7heWKoOWvhiBFbmNpcGhl",
            "ciBPbmx5PC9vcHRpb24+CiAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9IjQiPjQgLSDku4Xop6Plr4YgRGVjaXBoZXIgT25seTwvb3B0",
            "aW9uPgogICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSI1Ij41IC0g5pWw5a2X562+5ZCNK+S4jeWPr+WQpuiupO+8iOetvuWQjeeUqOmA",
            "lO+8iTwvb3B0aW9uPgogICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSI2Ij42IC0g5pWw5o2u5Yqg5a+GIERhdGEgRW5jaXBoZXJtZW50",
            "PC9vcHRpb24+CiAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9IjciPjcgLSDlr4bpkqXliqDlr4YgS2V5IEVuY2lwaGVybWVudDwvb3B0",
            "aW9uPgogICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSI4Ij44IC0g5a+G6ZKl5Y2P5ZWGIEtleSBBZ3JlZW1lbnQ8L29wdGlvbj4KICAg",
            "ICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iY3VzdG9tIj7oh6rlrprkuYnnu4TlkIjigKbvvIjlr4bpkqXnlKjms5XpgInmi6nlmajvvIk8",
            "L29wdGlvbj4KICAgICAgICAgICAgICAgICAgICAgIDwvc2VsZWN0PgogICAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2dh",
            "cDo2cHg7YWxpZ24taXRlbXM6Y2VudGVyO21hcmdpbi10b3A6NnB4Ij4KICAgICAgICAgICAgICAgICAgICAgICAgPGlucHV0IGlkPSJzY0t1Q3VzdG9tIiBw",
            "bGFjZWhvbGRlcj0i6Ieq5a6a5LmJ5pWw5YC877ya5ZCE5L2N5YC855u45Yqg77yM5aaCIDU95pWw5a2X562+5ZCNMSvlr4bpkqXliqDlr4Y0IiBzdHlsZT0i",
            "ZGlzcGxheTpub25lIj4KICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJnaG9zdCIgb25jbGljaz0ib3Blbkt1",
            "TW9kYWwoKSIgc3R5bGU9IndoaXRlLXNwYWNlOm5vd3JhcDtmbGV4Om5vbmUiPuWvhumSpeeUqOazleKApjwvYnV0dG9uPgogICAgICAgICAgICAgICAgICAg",
            "ICAgPC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+RUtVIOe8luWPty9PSUTvvIjpgJfl",
            "j7fliIbpmpTvvIk8L2xhYmVsPgogICAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2dhcDo2cHg7YWxpZ24taXRlbXM6Y2Vu",
            "dGVyIj4KICAgICAgICAgICAgICAgICAgICAgICAgPGlucHV0IGlkPSJzY0V1IiB2YWx1ZT0iMSIgb25jbGljaz0ib3BlbkVrdU1vZGFsKCkiIHRpdGxlPSLn",
            "grnlh7vovpPlhaXmoYbmiJblj7PkvqfmjInpkq7lvLnlh7ogRUtVIOmAieaLqeWZqCI+CiAgICAgICAgICAgICAgICAgICAgICAgIDxidXR0b24gdHlwZT0i",
            "YnV0dG9uIiBjbGFzcz0iZ2hvc3QiIG9uY2xpY2s9Im9wZW5Fa3VNb2RhbCgpIiBzdHlsZT0id2hpdGUtc3BhY2U6bm93cmFwO2ZsZXg6bm9uZSI+6YCJ5oup",
            "4oCmPC9idXR0b24+CiAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgICAgPC9k",
            "aXY+CiAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJmc2VjIiBpZD0ic2NQb2xXcmFwIiBzdHlsZT0iZGlzcGxh",
            "eTpub25lIj48ZGl2IGNsYXNzPSJmc2VjLXRpdGxlIj7or4HkuabnrZbnlaXvvIjku4Xnu4jnq6/or4HkuabvvIzli77pgInnmoTnrZbnlaXmiY3lhpnlhaXo",
            "r4HkuabnrZbnlaXmianlsZXvvIk8L2Rpdj4KICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1u",
            "czpyZXBlYXQoYXV0by1maWxsLG1pbm1heCgyMzVweCwxZnIpKTtnYXA6OHB4IDE2cHg7cGFkZGluZy10b3A6NnB4Ij4KICAgICAgICAgICAgICAgICAgICA8",
            "bGFiZWwgc3R5bGU9ImRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjhweDtjdXJzb3I6cG9pbnRlciI+PGlucHV0IHR5cGU9ImNoZWNrYm94",
            "IiBpZD0ic2NQb2xEdiI+PHNwYW4+U1NMIERW77yIMi4yMy4xNDAuMS4yLjHvvIk8L3NwYW4+PC9sYWJlbD4KICAgICAgICAgICAgICAgICAgICA8bGFiZWwg",
            "c3R5bGU9ImRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjhweDtjdXJzb3I6cG9pbnRlciI+PGlucHV0IHR5cGU9ImNoZWNrYm94IiBpZD0i",
            "c2NQb2xJdiI+PHNwYW4+U1NMIElW77yIMi4yMy4xNDAuMS4yLjPvvIk8L3NwYW4+PC9sYWJlbD4KICAgICAgICAgICAgICAgICAgICA8bGFiZWwgc3R5bGU9",
            "ImRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjhweDtjdXJzb3I6cG9pbnRlciI+PGlucHV0IHR5cGU9ImNoZWNrYm94IiBpZD0ic2NQb2xP",
            "diI+PHNwYW4+U1NMIE9W77yIMi4yMy4xNDAuMS4yLjLvvIk8L3NwYW4+PC9sYWJlbD4KICAgICAgICAgICAgICAgICAgICA8bGFiZWwgc3R5bGU9ImRpc3Bs",
            "YXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjhweDtjdXJzb3I6cG9pbnRlciI+PGlucHV0IHR5cGU9ImNoZWNrYm94IiBpZD0ic2NQb2xFdiI+PHNw",
            "YW4+U1NMIEVW77yIMi4yMy4xNDAuMS4x77yJPC9zcGFuPjwvbGFiZWw+CiAgICAgICAgICAgICAgICAgICAgPGxhYmVsIHN0eWxlPSJkaXNwbGF5OmZsZXg7",
            "YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo4cHg7Y3Vyc29yOnBvaW50ZXIiPjxpbnB1dCB0eXBlPSJjaGVja2JveCIgaWQ9InNjUG9sQ3NTdGQiPjxzcGFuPuS7",
            "o+eggeetvuWQjS3moIflh4bvvIgyLjIzLjE0MC4xLjQuMe+8iTwvc3Bhbj48L2xhYmVsPgogICAgICAgICAgICAgICAgICAgIDxsYWJlbCBzdHlsZT0iZGlz",
            "cGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6OHB4O2N1cnNvcjpwb2ludGVyIj48aW5wdXQgdHlwZT0iY2hlY2tib3giIGlkPSJzY1BvbENzRXYi",
            "PjxzcGFuPuS7o+eggeetvuWQjS1FVu+8iDIuMjMuMTQwLjEuM++8iTwvc3Bhbj48L2xhYmVsPgogICAgICAgICAgICAgICAgICAgIDxsYWJlbCBzdHlsZT0i",
            "ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6OHB4O2N1cnNvcjpwb2ludGVyIj48aW5wdXQgdHlwZT0iY2hlY2tib3giIGlkPSJzY1BvbERv",
            "YyI+PHNwYW4+5paH5qGj562+5ZCN77yIMS4zLjYuMS41LjUuNy4zLjM277yJPC9zcGFuPjwvbGFiZWw+CiAgICAgICAgICAgICAgICAgICAgPGxhYmVsIHN0",
            "eWxlPSJkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo4cHg7Y3Vyc29yOnBvaW50ZXIiPjxpbnB1dCB0eXBlPSJjaGVja2JveCIgaWQ9InNj",
            "UG9sVHNhIj48c3Bhbj5UU0Eg562W55Wl77yIMi4yMy4xNDAuMS40LjLvvIk8L3NwYW4+PC9sYWJlbD4KICAgICAgICAgICAgICAgICAgPC9kaXY+CiAgICAg",
            "ICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6NnB4O2FsaWduLWl0ZW1zOmNlbnRlcjtwYWRkaW5nLXRvcDo4cHgiPgogICAgICAg",
            "ICAgICAgICAgICAgIDxpbnB1dCBpZD0ic2NQb2xDdXN0b21PaWQiIHBsYWNlaG9sZGVyPSLoh6rlrprkuYnnrZbnlaUgT0lE77yM5aaCIDEuMi4zLjQuNSIg",
            "c3R5bGU9ImZsZXg6MTttaW4td2lkdGg6MjIwcHgiIG9ua2V5ZG93bj0iaWYoZXZlbnQua2V5PT09J0VudGVyJylhZGRTY1BvbEN1c3RvbSgpIj4KICAgICAg",
            "ICAgICAgICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgb25jbGljaz0iYWRkU2NQb2xDdXN0b20oKSI+5re75Yqg6Ieq5a6a5LmJ562W55WlPC9idXR0",
            "b24+CiAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgICA8ZGl2IGlkPSJzY1BvbEN1c3RvbUJveCI+PC9kaXY+CiAgICAgICAgICAg",
            "ICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJmc2VjIj48ZGl2IGNsYXNzPSJmc2VjLXRpdGxlIj7mnInmlYjmnJ88L2Rpdj4KICAg",
            "ICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0icm93Ij4KICAgICAgICAgICAgICAgICAgICA8ZGl2PjxsYWJlbD7mnInmlYjmnJ/vvIjlubTmlbDmiJYg6LW3",
            "5aeLVOaIquiHs++8iTwvbGFiZWw+CiAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjZweDthbGlnbi1pdGVtczpj",
            "ZW50ZXIiPgogICAgICAgICAgICAgICAgICAgICAgICA8aW5wdXQgaWQ9InNjRGF5cyIgdmFsdWU9IjEiIHRpdGxlPSLmlbDlrZc95bm05pWw77yb5oiW5qC8",
            "5byPIOi1t+Wni1TmiKroh7PvvIzlpoIgMjAyNi8wOS8xMi0xMDozMDowMFQyMDI3LzA5LzEyLTEwOjMwOjAwIj4KICAgICAgICAgICAgICAgICAgICAgICAg",
            "PGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJnaG9zdCIgb25jbGljaz0ib3BlblZhbE1vZGFsKCkiIHN0eWxlPSJ3aGl0ZS1zcGFjZTpub3dyYXA7Zmxl",
            "eDpub25lIj7pgInmi6nml6XmnJ/igKY8L2J1dHRvbj4KICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgICAgIDwvZGl2Pgog",
            "ICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZzZWMiPjxkaXYgY2xh",
            "c3M9ImZzZWMtdGl0bGUiPlNBTiDmianlsZU8L2Rpdj4KICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0icm93Ij4KICAgICAgICAgICAgICAgICAgICA8",
            "ZGl2PjxsYWJlbD5TQU4g5Z+f5ZCN77yI6YCX5Y+35YiG6ZqU77yM5peg5YiZIG51bGzvvIk8L2xhYmVsPjxpbnB1dCBpZD0ic2NEbnMiIHZhbHVlPSJudWxs",
            "Ij48L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2PjxsYWJlbD5TQU4gSVDvvIjpgJflj7fliIbpmpTvvIzml6DliJkgbnVsbO+8iTwvbGFiZWw+PGlu",
            "cHV0IGlkPSJzY0lwcyIgdmFsdWU9Im51bGwiPjwvZGl2PgogICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAg",
            "ICAgICAgICAgIDxkaXYgY2xhc3M9ImZzZWMiPjxkaXYgY2xhc3M9ImZzZWMtdGl0bGUiPumigeWPkeiAhTwvZGl2PgogICAgICAgICAgICAgICAgICA8ZGl2",
            "IGNsYXNzPSJyb3ciPgogICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPjxsYWJlbD7pooHlj5HogIXor4HkuabvvIhD",
            "RVJUUy50eHQg5LitIFIvQyDnsbvlnovluo/liJflj7fvvIzpvKDmoIfmgqzlgZzmmL7npLror6bmg4XvvIk8L2xhYmVsPgogICAgICAgICAgICAgICAgICAg",
            "ICAgPHNlbGVjdCBpZD0ic2NJc3N1ZXIiIGNsYXNzPSJ0LWJveCIgb25jaGFuZ2U9InJlZnJlc2hJc3N1ZXJUaXAoKSI+PC9zZWxlY3Q+CiAgICAgICAgICAg",
            "ICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgPGRpdiBzdHls",
            "ZT0ibWFyZ2luLXRvcDoxNnB4Ij48YnV0dG9uIG9uY2xpY2s9InBvc3RGb3JtKCcvYXBpL3NpZ25jZXJ0Jywge2RuOnYoJ3NjRG4nKSxiaXRzOmJpdHNWYWwo",
            "KSxoYXNoOnYoJ3NjSGFzaCcpLGtleXVzYWdlOmt1VmFsKCksZXh1c2FnZTp2KCdzY0V1JyksaXNjYTp2KCdzY0NhJyksZGF5czp2KCdzY0RheXMnKSxkbnM6",
            "dignc2NEbnMnKSxpcHM6dignc2NJcHMnKSxpc3N1ZXI6dignc2NJc3N1ZXInKSxhbGdvOnYoJ3NjQWxnbycpLHBhdGhsZW46cGF0aExlblZhbCgpLHBvbGlj",
            "eTpwb2xpY3lWYWwoKX0sICdzY091dCcpIj7nrb7lj5Hor4HkuaY8L2J1dHRvbj48L2Rpdj4KICAgICAgICAgICAgICAgIDxwcmUgY2xhc3M9Im91dCIgaWQ9",
            "InNjT3V0Ij48L3ByZT4KICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICA8IS0tIOWQiumUgOivgeS5piAtLT4K",
            "ICAgICAgICAgICAgPGRpdiBjbGFzcz0icGFnZSIgaWQ9InBhZ2UtcmV2b2tlIj4KICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgICAg",
            "ICAgICAgIDxoMj7lkIrplIDor4HkuabvvIhSZXZva2VDRVJU77yJPC9oMj4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImhpbnQiPuWQiumUgOWQjuiH",
            "quWKqOWIt+aWsCBDUkwg5ZCK6ZSA5YiX6KGo44CC6K+35YWI5Zyo44CM6K+B5Lmm5bqT44CN5Lit56Gu6K6k5bqP5YiX5Y+344CCPC9kaXY+CiAgICAgICAg",
            "ICAgICAgICA8ZGl2IGNsYXNzPSJyb3ciPgogICAgICAgICAgICAgICAgICA8ZGl2PjxsYWJlbD7or4Hkuabluo/liJflj7c8L2xhYmVsPjxpbnB1dCBpZD0i",
            "cnZTZXJpYWwiIHBsYWNlaG9sZGVyPSLlpoIgMTNmYmU4NjU4NmJiMGE0Ij48L2Rpdj4KICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+5ZCK6ZSA5Y6f",
            "5Zug57yW5Y+377yIMH4577yJPC9sYWJlbD48c2VsZWN0IGlkPSJydlJlYXNvbiI+CiAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iMCI+MCAt",
            "IOacquaMh+Wumjwvb3B0aW9uPjxvcHRpb24gdmFsdWU9IjEiPjEgLSDlr4bpkqXms4TpnLI8L29wdGlvbj48b3B0aW9uIHZhbHVlPSIyIj4yIC0gQ0Hms4Tp",
            "nLI8L29wdGlvbj4KICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSIzIj4zIC0g5L+h5oGv5Y+Y5pu0PC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0i",
            "NCI+NCAtIOiiq+abv+aNojwvb3B0aW9uPjxvcHRpb24gdmFsdWU9IjUiPjUgLSDmk43kvZznu4jmraI8L29wdGlvbj4KICAgICAgICAgICAgICAgICAgICA8",
            "b3B0aW9uIHZhbHVlPSI2Ij42IC0g6K+B5Lmm5pqC5YGcPC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0iOSI+OSAtIOWFtuWugzwvb3B0aW9uPgogICAgICAgICAg",
            "ICAgICAgICA8L3NlbGVjdD48L2Rpdj4KICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9Im1hcmdpbi10b3A6MTZw",
            "eCI+PGJ1dHRvbiBjbGFzcz0iZGFuZ2VyIiBvbmNsaWNrPSJwb3N0Rm9ybSgnL2FwaS9yZXZva2UnLCB7c2VyaWFsOnYoJ3J2U2VyaWFsJykscmVhc29uOnYo",
            "J3J2UmVhc29uJyl9LCAncnZPdXQnKSI+5ZCK6ZSA6K+l6K+B5LmmPC9idXR0b24+PC9kaXY+CiAgICAgICAgICAgICAgICA8cHJlIGNsYXNzPSJvdXQiIGlk",
            "PSJydk91dCI+PC9wcmU+CiAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgPCEtLSBPQ1NQfFRTQeetvuWPke+8",
            "iOetvuWPkeivgeS5piArIOaooeaLn+ivt+axguiwg+ivlSDlkIjlubbpobXvvIkgLS0+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9InBhZ2UiIGlkPSJwYWdl",
            "LW9jc3AiPgogICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0ic2lnLXRhYnMiIGlkPSJvY3NwVGFi",
            "cyI+CiAgICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InNpZy10YWIgYWN0aXZlIiBkYXRhLXRhYj0iaXNzdWUiIG9uY2xpY2s9Im9jc3BUYWIoJ2lz",
            "c3VlJykiPk9DU1Dnrb7lj5E8L2J1dHRvbj4KICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0ic2lnLXRhYiIgZGF0YS10YWI9InRzYWlzc3VlIiBv",
            "bmNsaWNrPSJvY3NwVGFiKCd0c2Fpc3N1ZScpIj5UU0Hnrb7lj5E8L2J1dHRvbj4KICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0ic2lnLXRhYiIg",
            "ZGF0YS10YWI9ImRlYnVnb2NzcCIgb25jbGljaz0ib2NzcFRhYignZGVidWdvY3NwJykiPk9DU1DmqKHmi5/or7fmsYLosIPor5U8L2J1dHRvbj4KICAgICAg",
            "ICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0ic2lnLXRhYiIgZGF0YS10YWI9ImRlYnVndHNhIiBvbmNsaWNrPSJvY3NwVGFiKCdkZWJ1Z3RzYScpIj5UU0Hm",
            "qKHmi5/or7fmsYLosIPor5U8L2J1dHRvbj4KICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBpZD0ib2NzcElzc3VlIj4KICAg",
            "ICAgICAgICAgICAgICAgPGgyPuetvuWPkSBPQ1NQIOetvuWQjeivgeS5pu+8iGluaXRPQ1NQ77yJPC9oMj4KICAgICAgICAgICAgICAgICAgPHAgc3R5bGU9",
            "ImNvbG9yOnZhcigtLWRpbSk7bWFyZ2luLWJvdHRvbToxNHB4Ij7kuLror4HkuablupPkuK3lhajpg6ggUu+8iOague+8iS8gQ++8iOS4remXtENB77yJ6K+B",
            "5Lmm6YCQ5Liq55Sf5oiQIE9DU1Ag562+5ZCN6K+B5Lmm77yM6L6T5Ye65YiwIFBLSS9PQ1NQL+W6j+WIl+WPt19vY3NwLmNydHwua2V544CCPC9wPgogICAg",
            "ICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0b29sYmFyIj4KICAgICAgICAgICAgICAgICAgICA8c2VsZWN0IGlkPSJvY0FsZ28iPjxvcHRpb24gdmFsdWU9",
            "IiI+5YWo6YOo6K+B5Lmm77yI5oyJ5ZCE6Ieq566X5rOV77yJPC9vcHRpb24+PG9wdGlvbj5SU0E8L29wdGlvbj48b3B0aW9uPkVDQzwvb3B0aW9uPjxvcHRp",
            "b24+U00yPC9vcHRpb24+PC9zZWxlY3Q+CiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJwb3N0Rm9ybSgnL2FwaS9pbml0b2NzcCcsIHth",
            "bGdvOnYoJ29jQWxnbycpfSwgJ29jT3V0JykiPuetvuWPkSBPQ1NQIOivgeS5pjwvYnV0dG9uPgogICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAg",
            "ICAgICAgICAgPHByZSBjbGFzcz0ib3V0IiBpZD0ib2NPdXQiPjwvcHJlPgogICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICA8ZGl2IGlk",
            "PSJ0c2FJc3N1ZSIgc3R5bGU9ImRpc3BsYXk6bm9uZSI+CiAgICAgICAgICAgICAgICAgIDxoMj7nrb7lj5Hml7bpl7TmiLPor4HkuabvvIhpbml0VElNU1RB",
            "TVDvvIk8L2gyPgogICAgICAgICAgICAgICAgICA8cCBzdHlsZT0iY29sb3I6dmFyKC0tZGltKTttYXJnaW4tYm90dG9tOjE0cHgiPuS4uuWFqOmDqOagueiv",
            "geS5pueUn+aIkOaXtumXtOaIs+ivgeS5pu+8mlJTQS9FQ0Mg4oaSIHJzYS9lY2Nfc2hhMSArIHJzYS9lY2Nfc2hhMjU277yMU00yIOKGkiBzbTJfc20z77yM",
            "6L6T5Ye65YiwIFBLSS9USU1TVEFNUC/jgII8L3A+CiAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRvb2xiYXIiPgogICAgICAgICAgICAgICAgICAg",
            "IDxzZWxlY3QgaWQ9InRzSGFzaCI+PG9wdGlvbiB2YWx1ZT0iIj7lhajpg6jmoLnor4HkuabvvIjmjInlkIToh6rnrpfms5XvvIk8L29wdGlvbj48b3B0aW9u",
            "PlNIQTE8L29wdGlvbj48b3B0aW9uPlNIQTI1Njwvb3B0aW9uPjxvcHRpb24+U00zPC9vcHRpb24+PC9zZWxlY3Q+CiAgICAgICAgICAgICAgICAgICAgPGJ1",
            "dHRvbiBvbmNsaWNrPSJwb3N0Rm9ybSgnL2FwaS9pbml0dGltZXN0YW1wJywge2hhc2g6digndHNIYXNoJyl9LCAndHNPdXQnKSI+562+5Y+R5pe26Ze05oiz",
            "6K+B5LmmPC9idXR0b24+CiAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgICA8cHJlIGNsYXNzPSJvdXQiIGlkPSJ0c091dCI+PC9w",
            "cmU+CiAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgIDxkaXYgaWQ9ImRiZ09jc3AiIHN0eWxlPSJkaXNwbGF5Om5vbmUiPgogICAgICAg",
            "ICAgICAgICAgICA8aDI+5qih5oufIE9DU1Ag6K+35rGC77yIUkZDIDY5NjDvvIk8L2gyPgogICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJoaW50Ij7m",
            "jInmoIflh4bmnoTpgKAgQ2VydElE77yIaXNzdWVyTmFtZUhhc2gvaXNzdWVyS2V5SGFzaCDln7rkuo7nnJ/mraPpooHlj5HogIXor4HkuabvvIkrIE5vbmNl",
            "IOaJqeWxle+8jFBPU1Qg5pys5py6IE1BSU4g55qEIC9PQ1NQ77yM6Kej5p6Q5ZON5bqU5bm26aqM6K+B562+5ZCN5LiOIE5vbmNlIOWbnuaYvuOAgjwvZGl2",
            "PgogICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJyb3ciPgogICAgICAgICAgICAgICAgICAgIDxkaXY+PGxhYmVsPuebruagh+ivgeS5puW6j+WIl+WP",
            "t++8iOeVmeepuuiHquWKqOmAieesrOS4gOS4que7iOerr+ivgeS5pu+8iTwvbGFiZWw+PGlucHV0IGlkPSJkYmdPY3NwU2VyaWFsIiBwbGFjZWhvbGRlcj0i",
            "5L6L5aaCIDExMzUyMjhhMiI+PC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPGRpdj48bGFiZWw+Q2VydElEIOWTiOW4jOeul+azlTwvbGFiZWw+PHNlbGVj",
            "dCBpZD0iZGJnT2NzcEhhc2giPgogICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0ic2hhMjU2IiBzZWxlY3RlZD5TSEEyNTY8L29wdGlvbj4K",
            "ICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9InNoYTEiPlNIQTE8L29wdGlvbj4KICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFs",
            "dWU9InNoYTM4NCI+U0hBMzg0PC9vcHRpb24+CiAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJzaGE1MTIiPlNIQTUxMjwvb3B0aW9uPgog",
            "ICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0ic2hhMy0yMjQiPlNIQTMtMjI0PC9vcHRpb24+CiAgICAgICAgICAgICAgICAgICAgICA8b3B0",
            "aW9uIHZhbHVlPSJzaGEzLTI1NiI+U0hBMy0yNTY8L29wdGlvbj4KICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9InNoYTMtMzg0Ij5TSEEz",
            "LTM4NDwvb3B0aW9uPgogICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0ic2hhMy01MTIiPlNIQTMtNTEyPC9vcHRpb24+CiAgICAgICAgICAg",
            "ICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJzbTMiPlNNMzwvb3B0aW9uPgogICAgICAgICAgICAgICAgICAgIDwvc2VsZWN0PjwvZGl2PgogICAgICAgICAg",
            "ICAgICAgICAgIDxkaXYgc3R5bGU9ImFsaWduLXNlbGY6ZW5kIj48YnV0dG9uIG9uY2xpY2s9InNlbmREZWJ1Z09jc3AoKSI+5Y+R6YCB5qih5ouf6K+35rGC",
            "PC9idXR0b24+PC9kaXY+CiAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgICA8cHJlIGNsYXNzPSJvdXQiIGlkPSJkYmdPY3NwT3V0",
            "IiBzdHlsZT0ibWF4LWhlaWdodDo1NnZoO292ZXJmbG93OmF1dG87d2hpdGUtc3BhY2U6cHJlO2ZvbnQtZmFtaWx5OnZhcigtLW1vbm8pO2ZvbnQtc2l6ZTox",
            "MnB4O2xpbmUtaGVpZ2h0OjEuNTUiPjwvcHJlPgogICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJkYmdUc2EiIHN0eWxl",
            "PSJkaXNwbGF5Om5vbmUiPgogICAgICAgICAgICAgICAgICA8aDI+5qih5ouf5pe26Ze05oiz6K+35rGC77yIUkZDIDMxNjHvvIk8L2gyPgogICAgICAgICAg",
            "ICAgICAgICA8ZGl2IGNsYXNzPSJoaW50Ij7pmo/mnLrnlJ/miJAgMzIg5a2X6IqC5pWw5o2uIOKGkiDmjInmiYDpgInmkZjopoHnrpfms5XorqHnrpcgbWVz",
            "c2FnZUltcHJpbnQg4oaSIOaehOmAoCBUaW1lU3RhbXBSZXHvvIjlkKsgTm9uY2XjgIFjZXJ0UmVxPXRydWXvvInihpIgUE9TVCDmnKzmnLogTUFJTiDnmoQg",
            "L3JmYzMxNjEg4oaSIOino+aekCBUaW1lU3RhbXBSZXNwIOW5tumqjOivgeetvuWQjeOAgjwvZGl2PgogICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJy",
            "b3ciPgogICAgICAgICAgICAgICAgICAgIDxkaXY+PGxhYmVsPuaRmOimgeeul+azlTwvbGFiZWw+PHNlbGVjdCBpZD0iZGJnVHNhSGFzaCI+CiAgICAgICAg",
            "ICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJzaGEyNTYiIHNlbGVjdGVkPlNIQTI1Njwvb3B0aW9uPgogICAgICAgICAgICAgICAgICAgICAgPG9wdGlv",
            "biB2YWx1ZT0ic2hhMSI+U0hBMTwvb3B0aW9uPgogICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0ic2hhMzg0Ij5TSEEzODQ8L29wdGlvbj4K",
            "ICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9InNoYTUxMiI+U0hBNTEyPC9vcHRpb24+CiAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9u",
            "IHZhbHVlPSJzaGEzLTIyNCI+U0hBMy0yMjQ8L29wdGlvbj4KICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9InNoYTMtMjU2Ij5TSEEzLTI1",
            "Njwvb3B0aW9uPgogICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0ic2hhMy0zODQiPlNIQTMtMzg0PC9vcHRpb24+CiAgICAgICAgICAgICAg",
            "ICAgICAgICA8b3B0aW9uIHZhbHVlPSJzaGEzLTUxMiI+U0hBMy01MTI8L29wdGlvbj4KICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9InNt",
            "MyI+U00zPC9vcHRpb24+CiAgICAgICAgICAgICAgICAgICAgPC9zZWxlY3Q+PC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iYWxpZ24t",
            "c2VsZjplbmQiPjxidXR0b24gb25jbGljaz0ic2VuZERlYnVnVHNhKCkiPuWvuemaj+acuuaVsOaNruetvuWQjTwvYnV0dG9uPjwvZGl2PgogICAgICAgICAg",
            "ICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgICAgPHByZSBjbGFzcz0ib3V0IiBpZD0iZGJnVHNhT3V0IiBzdHlsZT0ibWF4LWhlaWdodDo1NnZoO292",
            "ZXJmbG93OmF1dG87d2hpdGUtc3BhY2U6cHJlO2ZvbnQtZmFtaWx5OnZhcigtLW1vbm8pO2ZvbnQtc2l6ZToxMnB4O2xpbmUtaGVpZ2h0OjEuNTUiPjwvcHJl",
            "PgogICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgPCEtLSDor4Hkuabp",
            "qozor4EgLS0+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9InBhZ2UiIGlkPSJwYWdlLXZlcmlmeSI+CiAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+",
            "CiAgICAgICAgICAgICAgICA8aDI+6K+B5Lmm6aqM6K+B77yIQ2VydFZlcmlmee+8iTwvaDI+CiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0b29sYmFy",
            "Ij4KICAgICAgICAgICAgICAgICAgPGlucHV0IGlkPSJ2ZlRhcmdldCIgcGxhY2Vob2xkZXI9IuivgeS5puaWh+S7tui3r+W+hO+8jOaIluW6j+WIl+WPt++8",
            "iOiHquWKqOafpSBQS0kvV2ViUHVibGljL0NSVC/luo/liJflj7cuY3J077yJIiBzdHlsZT0iZmxleDoxO21heC13aWR0aDo0MjBweCI+CiAgICAgICAgICAg",
            "ICAgICAgIDxidXR0b24gb25jbGljaz0icG9zdEZvcm0oJy9hcGkvdmVyaWZ5Jywge3RhcmdldDp2KCd2ZlRhcmdldCcpfSwgJ3ZmT3V0JykiPumqjOivgTwv",
            "YnV0dG9uPgogICAgICAgICAgICAgICAgICA8aW5wdXQgdHlwZT0iZmlsZSIgaWQ9InZmRmlsZSIgYWNjZXB0PSIuY2VyLC5jcnQsLnBlbSIgb25jaGFuZ2U9",
            "InZlcmlmeUZpbGUoKSIgc3R5bGU9ImZsZXg6MTttYXgtd2lkdGg6MzIwcHgiPgogICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICA8cHJl",
            "IGNsYXNzPSJvdXQiIGlkPSJ2Zk91dCI+PC9wcmU+CiAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgPCEtLSDm",
            "qKHmnb/nrqHnkIYgLS0+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9InBhZ2UiIGlkPSJwYWdlLXRlbXBsYXRlIj4KICAgICAgICAgICAgICA8ZGl2IGNsYXNz",
            "PSJjYXJkIj4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRvb2xiYXIiPgogICAgICAgICAgICAgICAgICA8aDIgc3R5bGU9Im1hcmdpbjowIj7mqKHm",
            "nb/nrqHnkIY8L2gyPgogICAgICAgICAgICAgICAgICA8c3BhbiBzdHlsZT0iY29sb3I6dmFyKC0tZGltKTtmb250LXNpemU6MTJweCI+5paH5Lu277yaUEtJ",
            "L3RhbXBsYXRlL2RhdGEuanNvbjwvc3Bhbj4KICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJvcGVuVHBNb2RhbCgpIj4rIOa3u+WKoOaooead",
            "vzwvYnV0dG9uPgogICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJnaG9zdCIgb25jbGljaz0ibG9hZFRlbXBsYXRlcygpIj7liLfmlrA8L2J1dHRv",
            "bj4KICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iaGludCI+5qih5p2/5L+d5a2Y562+5Y+R6K+B5Lmm55qE5YWo",
            "6YOo5Y+C5pWw77yIRE4gLyDnrpfms5UgLyDlr4bpkqXnlKjpgJQgLyBFS1UgLyDnrZbnlaUgLyDmnInmlYjmnJ8gLyBTQU7vvInvvIznrb7nvbLml7bpgInm",
            "i6kgUiDmiJYgQyDnsbvlnovpooHlj5HogIXkuIDplK7nrb7lj5HvvIzmk43kvZzlhajnqIvlhpnlhaUgbG9ncy5sb2fjgII8L2Rpdj4KICAgICAgICAgICAg",
            "ICAgIDx0YWJsZSBjbGFzcz0idGJsIiBpZD0idHBsVGFibGUiPgogICAgICAgICAgICAgICAgICA8dGhlYWQ+PHRyPjx0aCBzdHlsZT0id2lkdGg6NjBweCI+",
            "5bqP5Y+3PC90aD48dGggc3R5bGU9IndpZHRoOjExMHB4Ij7or4Hkuabnsbvlnos8L3RoPjx0aD5ETjwvdGg+PHRoIHN0eWxlPSJ3aWR0aDoxNTBweCI+5pe2",
            "6Ze0PC90aD48dGggc3R5bGU9IndpZHRoOjIwMHB4Ij7mk43kvZw8L3RoPjwvdHI+PC90aGVhZD4KICAgICAgICAgICAgICAgICAgPHRib2R5PjwvdGJvZHk+",
            "CiAgICAgICAgICAgICAgICA8L3RhYmxlPgogICAgICAgICAgICAgICAgPHByZSBjbGFzcz0ib3V0IiBpZD0idHBsTXNnIj48L3ByZT4KICAgICAgICAgICAg",
            "ICA8L2Rpdj4KICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICA8IS0tIOetvuWQjeS4k+WMuiAtLT4KICAgICAgICAgICAgPGRpdiBjbGFzcz0icGFn",
            "ZSIgaWQ9InBhZ2Utc2lnbiI+CiAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgICAgICAgICAgICA8aDI+562+5ZCN5LiT5Yy6PC9oMj4K",
            "ICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InNpZy10YWJzIj4KICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0ic2lnLXRhYiBhY3RpdmUiIGlk",
            "PSJzaWdUYWJCdG4tZXhlIiBvbmNsaWNrPSJzaWdUYWIoJ2V4ZScsdGhpcykiPuW+rui9r+S7o+eggeetvuWQjTwvYnV0dG9uPgogICAgICAgICAgICAgICAg",
            "ICA8YnV0dG9uIGNsYXNzPSJzaWctdGFiIiBpZD0ic2lnVGFiQnRuLXBkZiIgb25jbGljaz0ic2lnVGFiKCdwZGYnLHRoaXMpIj5QREYg5paH5qGj562+5ZCN",
            "PC9idXR0b24+CiAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICA8IS0tIOW+rui9r+S7o+eggeetvuWQje+8iOaJuemHjyArIOaLluaL",
            "ve+8iSAtLT4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InNpZy1wYW5lIiBpZD0ic2lnUGFuZS1leGUiPgogICAgICAgICAgICAgICAgICA8ZGl2IGNs",
            "YXNzPSJoaW50Ij7mi5bmi73miJbmibnph4/pgInmi6kgUEUg5Y+v5omn6KGM5paH5Lu277yIZXhlIC8gZGxsIC8gc3lzIC8gY2FiIC8gY2F0IC8gbXNp77yJ",
            "5Yqg5YWl5b6F562+5ZCN5YiX6KGo77yM5YaN6YCJ6K+B5Lmm5LiO5pe26Ze05oiz5Y+C5pWw5omn6KGM562+5ZCNIC8g6aqM6K+B44CC5pSv5oyBIFJTQSAv",
            "IEVDQyAvIFNNMu+8iOaRmOimgeWIhuWIq+eUqCBTSEEyNTYgLyBTSEEyNTYgLyBTTTPvvInvvIzor4HkuabooajmjIkgTWljcm9zb2Z0IFBFL0NPRkYg6KeE",
            "6IyD5bWM5YWl44CC5pe26Ze05oiz57G75Z6L5Y+v6YCJIFJGQzMxNjHvvIjmoIflh4YgVGltZVN0YW1wVG9rZW7vvInmiJYgQXV0aGVudGljb2Rl77yI5b6u",
            "6L2v6ICB5byPIFBLQ1MjN++8ie+8m+WcsOWdgOWPr+aMh+WQkeacrOacuiBNQUlO77yI55WZ56m677yJ5oiW5Lu75oSP5aSW6YOoIFRTQeOAgjwvZGl2Pgog",
            "ICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJyb3ciPgogICAgICAgICAgICAgICAgICAgIDxkaXY+PGxhYmVsPuetvuWQjeivgeS5pu+8iOS7o+eggeet",
            "vuWQjSBFS1XvvIk8L2xhYmVsPjxzZWxlY3QgaWQ9InNnRXhlQ2VydCIgdGl0bGU9Ium8oOagh+aCrOWBnOafpeeci+ivgeS5pueugOS7iyI+PG9wdGlvbiB2",
            "YWx1ZT0iIj7vvIjliqDovb3kuK0uLi7vvIk8L29wdGlvbj48L3NlbGVjdD48L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2PjxsYWJlbD7ml7bpl7Tm",
            "iLPnsbvlnos8L2xhYmVsPjxzZWxlY3QgaWQ9InNnRXhlVHNUeXBlIj4KICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9IlJGQzMxNjEiIHNl",
            "bGVjdGVkPlJGQzMxNjHvvIjmoIflh4bvvIk8L29wdGlvbj4KICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9IkFVVEhFTlRJQ09ERSI+QXV0",
            "aGVudGljb2Rl77yI6ICB5byPIFBLQ1MjN++8iTwvb3B0aW9uPgogICAgICAgICAgICAgICAgICAgIDwvc2VsZWN0PjwvZGl2PgogICAgICAgICAgICAgICAg",
            "ICAgIDxkaXYgc3R5bGU9ImdyaWQtY29sdW1uOjEvMiI+PGxhYmVsPuaXtumXtOaIs+ivt+axguWcsOWdgO+8iOeVmeepuiA9IOacrOacuiBNQUlO77yJPC9s",
            "YWJlbD4KICAgICAgICAgICAgICAgICAgICAgIDxpbnB1dCBpZD0ic2dFeGVUc1VybCIgbGlzdD0idHNVcmxMaXN0IiBwbGFjZWhvbGRlcj0iaHR0cDovL3Rp",
            "bWVzdGFtcC5kaWdpY2VydC5jb20iIHNwZWxsY2hlY2s9ImZhbHNlIj4KICAgICAgICAgICAgICAgICAgICAgIDxkYXRhbGlzdCBpZD0idHNVcmxMaXN0Ij4K",
            "ICAgICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iaHR0cDovL3RpbWVzdGFtcC5kaWdpY2VydC5jb20iPgogICAgICAgICAgICAgICAgICAg",
            "ICAgICA8b3B0aW9uIHZhbHVlPSJodHRwOi8vc2hhMjU2dGltZXN0YW1wLndzLnN5bWFudGVjLmNvbS9zaGEyNTYvIj4KICAgICAgICAgICAgICAgICAgICAg",
            "ICAgPG9wdGlvbiB2YWx1ZT0iaHR0cDovL3RpbWVzdGFtcC5jb21vZG9jYS5jb20iPgogICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJo",
            "dHRwOi8vdGltZS5jZXJ0dW0ucGwiPgogICAgICAgICAgICAgICAgICAgICAgPC9kYXRhbGlzdD4KICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAg",
            "ICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImRyb3B6b25lIiBpZD0iZXhlRHJvcCI+CiAgICAgICAgICAgICAgICAg",
            "ICAgPGRpdiBzdHlsZT0iZm9udC1zaXplOjE2cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXRleHQpIj7mi5bmi73lj6/miafooYzmlofku7bliLDm",
            "raTlpIQ8L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJtYXJnaW4tdG9wOjZweDtjb2xvcjp2YXIoLS1kaW0pIj7mlK/mjIEgZXhlIC8g",
            "ZGxsIC8gc3lzIC8gY2FiIC8gY2F0IC8gbXNp77yI5Y+v5aSa6YCJ77yJPC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPGxhYmVsIGNsYXNzPSJmYWtlLWJ0",
            "biIgc3R5bGU9Im1hcmdpbi10b3A6MTJweCI+6YCJ5oup5paH5Lu2PGlucHV0IHR5cGU9ImZpbGUiIGlkPSJzZ0V4ZUZpbGUiIG11bHRpcGxlIGFjY2VwdD0i",
            "LmV4ZSwuZGxsLC5zeXMsLmNhYiwuY2F0LC5tc2ksYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtIiBoaWRkZW4+PC9sYWJlbD4KICAgICAgICAgICAgICAgICAg",
            "PC9kaXY+CiAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InBkZi1saXN0LWhlYWQiPgogICAgICAgICAgICAgICAgICAgIDxzcGFuIHN0eWxlPSJmb250",
            "LXdlaWdodDo3MDAiPuW+heetvuWQjeWIl+ihqO+8iDxiIGlkPSJleGVDb3VudCIgc3R5bGU9ImNvbG9yOnZhcigtLWFjY2VudCkiPjA8L2I+IOS4qu+8iTwv",
            "c3Bhbj4KICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIG9uY2xpY2s9ImV4ZVNpZ25BbGwoKSI+5om56YeP562+5ZCNPC9idXR0b24+CiAgICAgICAgICAg",
            "ICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iZ2hvc3QiIG9uY2xpY2s9ImV4ZVZlcmlmeUFsbCgpIj7mibnph4/pqozor4E8L2J1dHRvbj4KICAgICAgICAgICAg",
            "ICAgICAgICA8YnV0dG9uIGNsYXNzPSJnaG9zdCIgb25jbGljaz0iZXhlQ2xlYXIoKSI+5riF56m6PC9idXR0b24+CiAgICAgICAgICAgICAgICAgIDwvZGl2",
            "PgogICAgICAgICAgICAgICAgICA8ZGl2IGlkPSJleGVMaXN0IiBjbGFzcz0icGRmLWxpc3QiPjwvZGl2PgogICAgICAgICAgICAgICAgICA8cHJlIGNsYXNz",
            "PSJvdXQiIGlkPSJzZ0V4ZU91dCIgc3R5bGU9Im1heC1oZWlnaHQ6MzB2aDtvdmVyZmxvdzphdXRvO3doaXRlLXNwYWNlOnByZTtmb250LWZhbWlseTp2YXIo",
            "LS1tb25vKTtmb250LXNpemU6MTJweDtsaW5lLWhlaWdodDoxLjU1Ij48L3ByZT4KICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgIDwh",
            "LS0gUERGIOaWh+aho+etvuWQje+8iOaJuemHjyArIOaLluaLve+8iSAtLT4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InNpZy1wYW5lIiBpZD0ic2ln",
            "UGFuZS1wZGYiIHN0eWxlPSJkaXNwbGF5Om5vbmUiPgogICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJoaW50Ij7mibnph4/pgInmi6nmiJbmi5bmi70g",
            "UERGIOaWh+S7tuWKoOWFpeW+heetvuWQjeWIl+ihqO+8jOWGjemAieivgeS5puS4juetvueroOWPguaVsOaJp+ihjOetvuWQjSAvIOmqjOivgeOAguivgeS5",
            "puetm+mAie+8muW+rui9r+aWh+aho+etvuWQjSBPSUTvvIgxLjMuNi4xLjQuMS4zMTEuMTAuMy4xMu+8ieaIlumAmueUqOaWh+aho+etvuWQjSBPSUTvvIgx",
            "LjMuNi4xLjUuNS43LjMuMzbvvInku7vkuIDljbPlj6/jgII8YnI+562+56ug57G75Z6L77yaQWRvYmUg5qCH5YeG5paH5qGj562+5ZCN77yIYWRiZS5wa2Nz",
            "Ny5kZXRhY2hlZO+8jFJTQS9FQ0MvU00yIOWdh+WPr++8ie+8m+WbveWvhiBHQi9UIDM1Mjc1LTIwMTfvvIhHTS5zbTJjbXMuZGV0YWNoZWTvvIzku4UgU00y",
            "77yJ77yb5Zu95a+GIEdCL1QgMzg1NDAtMjAyMO+8iEdNLnNtMnNlYWzvvIzku4UgU00y77yM6ZyA562+56ug5Zu+54mH77yJ77yb5Zu95a+GIEdNL1QgMDAz",
            "MS0yMDI177yIR00uc20yc2VhbO+8jOS7hSBTTTLvvIzpnIDnrb7nq6Dlm77niYfvvInjgII8L2Rpdj4KICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0i",
            "cm93Ij4KICAgICAgICAgICAgICAgICAgICA8ZGl2PjxsYWJlbD7nrb7nq6Dlm77niYfvvIhwbmcvanBnL2JtcC9naWbvvIk8L2xhYmVsPjxpbnB1dCB0eXBl",
            "PSJmaWxlIiBpZD0ic2dQZGZJbWFnZSIgYWNjZXB0PSJpbWFnZS9wbmcsaW1hZ2UvanBlZyxpbWFnZS9ibXAsaW1hZ2UvZ2lmIj48L2Rpdj4KICAgICAgICAg",
            "ICAgICAgICAgICA8ZGl2PjxsYWJlbD7nrb7lkI3or4HkuabvvIjnlZnnqbogPSDku4XmlofmoaPml7bpl7TmiLPvvIk8L2xhYmVsPjxzZWxlY3QgaWQ9InNn",
            "UGRmQ2VydCIgdGl0bGU9Ium8oOagh+aCrOWBnOafpeeci+ivgeS5pueugOS7i++8iOeVmeepuj3nuq/mlofmoaPml7bpl7TmiLPvvIzkuI3nrb7lkI3vvIki",
            "PjxvcHRpb24gdmFsdWU9IiI+77yI5LiN562+5ZCN77yM5LuF5paH5qGj5pe26Ze05oiz77yJPC9vcHRpb24+PC9zZWxlY3Q+PC9kaXY+CiAgICAgICAgICAg",
            "ICAgICAgICAgPGRpdj48bGFiZWw+562+56ug57G75Z6LPC9sYWJlbD48c2VsZWN0IGlkPSJzZ1BkZlNlYWwiPgogICAgICAgICAgICAgICAgICAgICAgPG9w",
            "dGlvbiB2YWx1ZT0iQURPQkUiIHNlbGVjdGVkPkFkb2JlIOagh+WHhuaWh+aho+etvuWQjTwvb3B0aW9uPgogICAgICAgICAgICAgICAgICAgICAgPG9wdGlv",
            "biB2YWx1ZT0iR00zNTI3NSI+5Zu95a+GIEdCL1QgMzUyNzUtMjAxNzwvb3B0aW9uPgogICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iR00z",
            "ODU0MCI+5Zu95a+GIEdCL1QgMzg1NDAtMjAyMDwvb3B0aW9uPgogICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iR00wMDMxIj7lm73lr4Yg",
            "R00vVCAwMDMxLTIwMjU8L29wdGlvbj4KICAgICAgICAgICAgICAgICAgICA8L3NlbGVjdD48L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxl",
            "PSJncmlkLWNvbHVtbjoxLzMiPjxsYWJlbD7ml7bpl7TmiLPor7fmsYLlnLDlnYDvvIjnlZnnqbogPSDmnKzmnLogTUFJTu+8iTwvbGFiZWw+CiAgICAgICAg",
            "ICAgICAgICAgICAgICA8aW5wdXQgaWQ9InNnUGRmVHNVcmwiIGxpc3Q9InRzVXJsTGlzdFBkZiIgcGxhY2Vob2xkZXI9Imh0dHA6Ly90aW1lc3RhbXAuZGln",
            "aWNlcnQuY29tIiBzcGVsbGNoZWNrPSJmYWxzZSI+CiAgICAgICAgICAgICAgICAgICAgICA8ZGF0YWxpc3QgaWQ9InRzVXJsTGlzdFBkZiI+CiAgICAgICAg",
            "ICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9Imh0dHA6Ly90aW1lc3RhbXAuZGlnaWNlcnQuY29tIj4KICAgICAgICAgICAgICAgICAgICAgICAgPG9w",
            "dGlvbiB2YWx1ZT0iaHR0cDovL3NoYTI1NnRpbWVzdGFtcC53cy5zeW1hbnRlYy5jb20vc2hhMjU2LyI+CiAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRp",
            "b24gdmFsdWU9Imh0dHA6Ly90aW1lc3RhbXAuY29tb2RvY2EuY29tIj4KICAgICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iaHR0cDovL3Rp",
            "bWUuY2VydHVtLnBsIj4KICAgICAgICAgICAgICAgICAgICAgIDwvZGF0YWxpc3Q+CiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAg",
            "ICAgIDwvZGl2PgogICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJkcm9wem9uZSIgaWQ9InBkZkRyb3AiPgogICAgICAgICAgICAgICAgICAgIDxkaXYg",
            "c3R5bGU9ImZvbnQtc2l6ZToxNnB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjp2YXIoLS10ZXh0KSI+5ouW5ou9IFBERiDmlofku7bliLDmraTlpIQ8L2Rpdj4K",
            "ICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJtYXJnaW4tdG9wOjZweDtjb2xvcjp2YXIoLS1kaW0pIj7miJbngrnlh7vkuIvmlrnmjInpkq7pgInm",
            "i6nmlofku7bvvIjlj6/lpJrpgInvvIk8L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8bGFiZWwgY2xhc3M9ImZha2UtYnRuIiBzdHlsZT0ibWFyZ2luLXRv",
            "cDoxMnB4Ij7pgInmi6kgUERGIOaWh+S7tjxpbnB1dCB0eXBlPSJmaWxlIiBpZD0ic2dQZGZGaWxlIiBtdWx0aXBsZSBhY2NlcHQ9Ii5wZGYsYXBwbGljYXRp",
            "b24vcGRmIiBoaWRkZW4+PC9sYWJlbD4KICAgICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InBkZi1saXN0LWhl",
            "YWQiPgogICAgICAgICAgICAgICAgICAgIDxzcGFuIHN0eWxlPSJmb250LXdlaWdodDo3MDAiPuW+heetvuWQjeWIl+ihqO+8iDxiIGlkPSJwZGZDb3VudCIg",
            "c3R5bGU9ImNvbG9yOnZhcigtLWFjY2VudCkiPjA8L2I+IOS4qu+8iTwvc3Bhbj4KICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIG9uY2xpY2s9InBkZlNp",
            "Z25BbGwoKSI+5om56YeP562+5ZCNPC9idXR0b24+CiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iZ2hvc3QiIG9uY2xpY2s9InBkZlZlcmlm",
            "eUFsbCgpIj7mibnph4/pqozor4E8L2J1dHRvbj4KICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJnaG9zdCIgb25jbGljaz0icGRmQ2xlYXIo",
            "KSI+5riF56m6PC9idXR0b24+CiAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgICA8ZGl2IGlkPSJwZGZMaXN0IiBjbGFzcz0icGRm",
            "LWxpc3QiPjwvZGl2PgogICAgICAgICAgICAgICAgICA8cHJlIGNsYXNzPSJvdXQiIGlkPSJzZ1BkZk91dCIgc3R5bGU9Im1heC1oZWlnaHQ6MzB2aDtvdmVy",
            "ZmxvdzphdXRvO3doaXRlLXNwYWNlOnByZTtmb250LWZhbWlseTp2YXIoLS1tb25vKTtmb250LXNpemU6MTJweDtsaW5lLWhlaWdodDoxLjU1Ij48L3ByZT4K",
            "ICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICA8L2Rpdj4KCgo8c3R5bGU+Ci5jdHgtbWVudXtwb3NpdGlv",
            "bjpmaXhlZDt6LWluZGV4Ojk5OTk5O2JhY2tncm91bmQ6dmFyKC0tcGFuZWwyKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Ym9yZGVyLXJhZGl1",
            "czo4cHg7Ym94LXNoYWRvdzowIDhweCAyOHB4IHJnYmEoMCwwLDAsLjQ1KTtwYWRkaW5nOjZweDttaW4td2lkdGg6MjI0cHg7dXNlci1zZWxlY3Q6bm9uZTtm",
            "b250LXNpemU6MTNweH0KLmN0eC1pdGVte3BhZGRpbmc6OHB4IDEycHg7Ym9yZGVyLXJhZGl1czo2cHg7Y3Vyc29yOnBvaW50ZXI7d2hpdGUtc3BhY2U6bm93",
            "cmFwO3Bvc2l0aW9uOnJlbGF0aXZlO2NvbG9yOnZhcigtLXRleHQpfQouY3R4LWl0ZW06aG92ZXJ7YmFja2dyb3VuZDp2YXIoLS1hY2NlbnQpO2NvbG9yOiMw",
            "YjExMjB9Ci5jdHgtaXRlbS5kaXNhYmxlZHtjb2xvcjp2YXIoLS1kaW0pO2N1cnNvcjpub3QtYWxsb3dlZDtwb2ludGVyLWV2ZW50czpub25lO2JhY2tncm91",
            "bmQ6dHJhbnNwYXJlbnR9Ci5jdHgtaXRlbS5oYXMtc3ViIC5jdHgtc3Vie2Rpc3BsYXk6bm9uZTtwb3NpdGlvbjphYnNvbHV0ZTtsZWZ0OjEwMCU7dG9wOjA7",
            "YmFja2dyb3VuZDp2YXIoLS1wYW5lbDIpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTtib3JkZXItcmFkaXVzOjhweDtib3gtc2hhZG93OjAgOHB4",
            "IDI4cHggcmdiYSgwLDAsMCwuNDUpO3BhZGRpbmc6NnB4IDZweCA2cHggOHB4O21pbi13aWR0aDoyOTBweDt6LWluZGV4Ojk5OTk4fQouY3R4LWl0ZW0uaGFz",
            "LXN1YiAuY3R4LXN1Yi5jdHgtc3ViLXVwe3RvcDphdXRvO2JvdHRvbTowfQouY3R4LXN1YiAuY3R4LWl0ZW17Zm9udC1zaXplOjEycHh9Cjwvc3R5bGU+Cjwh",
            "LS0g6K+B5Lmm5bqT5Y+z6ZSu6I+c5Y2V77ya5LiL6L296K+B5LmmIC8g5a+85Ye66K+B5LmmIC0tPgo8ZGl2IGlkPSJjdHhNZW51IiBjbGFzcz0iY3R4LW1l",
            "bnUiIHN0eWxlPSJkaXNwbGF5Om5vbmUiPgogIDxkaXYgY2xhc3M9ImN0eC1pdGVtIGhhcy1zdWIiPjxzcGFuPuS4i+i9veivgeS5pjwvc3Bhbj4KICAgIDxk",
            "aXYgY2xhc3M9ImN0eC1zdWIiPgogICAgICA8ZGl2IGNsYXNzPSJjdHgtaXRlbSIgb25jbGljaz0iY3R4RG93bmxvYWQoJ3NpbmdsZV9jcnQnKSI+5LiL6L29",
            "5Y2V6K+B5LmmKEVORC5jcnQpPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImN0eC1pdGVtIiBvbmNsaWNrPSJjdHhEb3dubG9hZCgnY2hhaW5fY3J0JykiPuS4",
            "i+i9vee7hOWQiOivgeS5pumTvihFTkQrQ0ErUk9PVC5jcnQpPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImN0eC1pdGVtIiBvbmNsaWNrPSJjdHhEb3dubG9h",
            "ZCgncDdiJykiPuS4i+i9vee7hOWQiOivgeS5pumTvihFTkQrQ0ErUk9PVC5wN2IpPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImN0eC1pdGVtIiBvbmNsaWNr",
            "PSJjdHhEb3dubG9hZCgnaXNzdWVyX2NydCcpIj7kuIvovb3pooHlj5HogIXor4Hkuabpk74oQ0ErUk9PVC5jcnQpPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9",
            "ImN0eC1pdGVtIiBkYXRhLW5lZWRrZXkgb25jbGljaz0iY3R4RG93bmxvYWQoJ2tleScpIj7kuIvovb3np4HpkqUoRU5ELmtleSk8L2Rpdj4KICAgICAgPGRp",
            "diBjbGFzcz0iY3R4LWl0ZW0iIGRhdGEtbmVlZGtleSBvbmNsaWNrPSJjdHhEb3dubG9hZCgncGZ4JywxKSI+5LiL6L296K+B5LmmK+engemSpSgucGZ4KTwv",
            "ZGl2PgogICAgICA8ZGl2IGNsYXNzPSJjdHgtaXRlbSIgZGF0YS1uZWVka2V5IG9uY2xpY2s9ImN0eERvd25sb2FkKCdqa3MnLDEpIj7kuIvovb3or4HkuaYr",
            "56eB6ZKlKC5qa3MpPC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KICA8ZGl2IGNsYXNzPSJjdHgtaXRlbSBoYXMtc3ViIj48c3Bhbj7lr7zlh7ror4HkuaY8",
            "L3NwYW4+CiAgICA8ZGl2IGNsYXNzPSJjdHgtc3ViIj4KICAgICAgPGRpdiBjbGFzcz0iY3R4LWl0ZW0iIG9uY2xpY2s9ImN0eEV4cG9ydCgnY2VydF9wZW0n",
            "KSI+5a+85Ye65Y2V6K+B5Lmm5Yiw5Ymq6L6R5p2/KFBFTSk8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iY3R4LWl0ZW0iIG9uY2xpY2s9ImN0eEV4cG9ydCgn",
            "Y2hhaW5fcGVtJykiPuWvvOWHuuivgeS5pumTvuWIsOWJqui+keadvyhQRU3vvJpFTkQrQ0ErUk9PVCk8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iY3R4LWl0",
            "ZW0iIG9uY2xpY2s9ImN0eEV4cG9ydCgnaXNzdWVyX3BlbScpIj5QRU3pooHlj5HogIXor4Hkuabpk77liLDliarovpHmnb8oUEVN77yaQ0ErUk9PVCk8L2Rp",
            "dj4KICAgICAgPGRpdiBjbGFzcz0iY3R4LWl0ZW0iIGRhdGEtbmVlZGtleSBvbmNsaWNrPSJjdHhFeHBvcnQoJ2tleV9wZW0nKSI+5a+85Ye656eB6ZKl5Yiw",
            "5Ymq6L6R5p2/KFBFTSk8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iY3R4LWl0ZW0iIGRhdGEtbmVlZGtleSBvbmNsaWNrPSJjdHhFeHBvcnQoJ2tleV9oZXgn",
            "KSI+5a+85Ye656eB6ZKl5Yiw5Ymq6L6R5p2/KEhFWCk8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iY3R4LWl0ZW0iIGRhdGEtbmVlZGtleSBvbmNsaWNrPSJj",
            "dHhFeHBvcnQoJ2tleV9iNjQnKSI+5a+85Ye656eB6ZKl5Yiw5Ymq6L6R5p2/KEJhc2U2NCk8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgogIDxkaXYgY2xh",
            "c3M9ImN0eC1pdGVtIiBkYXRhLWN0eHNyYz0iY2VydHMiIG9uY2xpY2s9ImN0eERlbGV0ZUNlcnQoKSIgc3R5bGU9ImNvbG9yOiNkYzI2MjY7Zm9udC13ZWln",
            "aHQ6NzAwIj7liKDpmaTor4HkuaY8L2Rpdj4KPC9kaXY+CjwhLS0g6K+B5Lmm5bqT5Y+z6ZSu5LiL6L29IHBmeC9qa3PvvJrlr4bnoIHovpPlhaUgLS0+Cjxk",
            "aXYgY2xhc3M9Im1vZGFsLW1hc2siIGlkPSJjdHhQd2RNb2RhbCIgc3R5bGU9ImRpc3BsYXk6bm9uZSIgb25jbGljaz0iaWYoZXZlbnQudGFyZ2V0PT09dGhp",
            "cyljbG9zZUN0eFB3ZCgpIj4KICA8ZGl2IGNsYXNzPSJtb2RhbCIgc3R5bGU9IndpZHRoOm1pbig0NjBweCw5MnZ3KSI+CiAgICA8ZGl2IGNsYXNzPSJtb2Rh",
            "bC1oZWFkIj4KICAgICAgPGgzPui+k+WFpeWvhumSpeW6k+WvhueggTwvaDM+CiAgICAgIDxidXR0b24gY2xhc3M9Imdob3N0IiBvbmNsaWNrPSJjbG9zZUN0",
            "eFB3ZCgpIj7lj5bmtog8L2J1dHRvbj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ibW9kYWwtYm9keSI+CiAgICAgIDxwIGNsYXNzPSJjZmctaGludCIg",
            "aWQ9ImN0eFB3ZEZpbGUiIHN0eWxlPSJtYXJnaW4tYm90dG9tOjEwcHgiPjwvcD4KICAgICAgPGxhYmVsPuWvhueggTwvbGFiZWw+CiAgICAgIDxpbnB1dCB0",
            "eXBlPSJwYXNzd29yZCIgaWQ9ImN0eFB3ZCIgcGxhY2Vob2xkZXI9Iuivt+i+k+WFpeWvvOWHuuWvhumSpeW6k+eahOWvhuegge+8iHBmeCAvIGprc++8iSIg",
            "b25rZXlkb3duPSJpZihldmVudC5rZXk9PT0nRW50ZXInKWN0eFB3ZE9rKCkiPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbC1mb290Ij4KICAg",
            "ICAgPGJ1dHRvbiBvbmNsaWNrPSJjdHhQd2RPaygpIj7noa7lrpo8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iZ2hvc3QiIG9uY2xpY2s9ImNsb3Nl",
            "Q3R4UHdkKCkiPuWPlua2iDwvYnV0dG9uPgogICAgPC9kaXY+CiAgPC9kaXY+CjwvZGl2Pgo8IS0tIOivgeS5puW6k+WvvOWHuu+8mua1j+iniOWZqOWJqui0",
            "tOadv+aOiOadg+Wksei0peaXtueahOaJi+WKqOWkjeWItumdouadvyAtLT4KPGRpdiBjbGFzcz0ibW9kYWwtbWFzayIgaWQ9ImN0eENvcHlNb2RhbCIgc3R5",
            "bGU9ImRpc3BsYXk6bm9uZSIgb25jbGljaz0iaWYoZXZlbnQudGFyZ2V0PT09dGhpcyljbG9zZUN0eENvcHkoKSI+CiAgPGRpdiBjbGFzcz0ibW9kYWwiIHN0",
            "eWxlPSJ3aWR0aDptaW4oNjIwcHgsOTR2dykiPgogICAgPGRpdiBjbGFzcz0ibW9kYWwtaGVhZCI+CiAgICAgIDxoMz7lpI3liLbliLDliarotLTmnb88L2gz",
            "PgogICAgICA8YnV0dG9uIGNsYXNzPSJnaG9zdCIgb25jbGljaz0iY2xvc2VDdHhDb3B5KCkiPuWPlua2iDwvYnV0dG9uPgogICAgPC9kaXY+CiAgICA8ZGl2",
            "IGNsYXNzPSJtb2RhbC1ib2R5Ij4KICAgICAgPHAgY2xhc3M9ImNmZy1oaW50IiBzdHlsZT0ibWFyZ2luLWJvdHRvbTo4cHgiPua1j+iniOWZqOacquiHquWK",
            "qOaOiOadg+WJqui0tOadv+WGmeWFpe+8jOWGheWuueW3sumihOmAie+8jOivt+eCueWHu+S4i+aWuSLlpI3liLYi5oyJ6ZKu77yI5oiW55u05o6l5oyJIEN0",
            "cmwrQ++8ieOAgjwvcD4KICAgICAgPHRleHRhcmVhIGlkPSJjdHhDb3B5VGV4dCIgcmVhZG9ubHkgc3BlbGxjaGVjaz0iZmFsc2UiIHN0eWxlPSJ3aWR0aDox",
            "MDAlO2hlaWdodDoxNTBweDtib3gtc2l6aW5nOmJvcmRlci1ib3g7Zm9udC1mYW1pbHk6dmFyKC0tbW9ubyk7Zm9udC1zaXplOjExcHg7YmFja2dyb3VuZDp2",
            "YXIoLS1wYW5lbCk7Y29sb3I6dmFyKC0tdGV4dCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2JvcmRlci1yYWRpdXM6NnB4O3BhZGRpbmc6OHB4",
            "O3doaXRlLXNwYWNlOnByZSI+PC90ZXh0YXJlYT4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ibW9kYWwtZm9vdCI+CiAgICAgIDxidXR0b24gb25jbGlj",
            "az0iY3R4Q29weVRleHRhcmVhKCkiPuWkjeWItjwvYnV0dG9uPgogICAgICA8YnV0dG9uIGNsYXNzPSJnaG9zdCIgb25jbGljaz0iY2xvc2VDdHhDb3B5KCki",
            "PuWFs+mXrTwvYnV0dG9uPgogICAgPC9kaXY+CiAgPC9kaXY+CjwvZGl2Pgo8IS0tIOivgeS5puW6kyBDRVJUUy50eHTvvJrlj7PplK7liKDpmaTor4Hkuabv",
            "vIjms6jph4rooYzlv73nlaXvvInnoa7orqQgLS0+CjxkaXYgY2xhc3M9Im1vZGFsLW1hc2siIGlkPSJjdHhEZWxNb2RhbCIgc3R5bGU9ImRpc3BsYXk6bm9u",
            "ZSIgb25jbGljaz0iaWYoZXZlbnQudGFyZ2V0PT09dGhpcyljdHhEZWxDYW5jZWwoKSI+CiAgPGRpdiBjbGFzcz0ibW9kYWwiIHN0eWxlPSJ3aWR0aDptaW4o",
            "NDYwcHgsOTJ2dykiPgogICAgPGRpdiBjbGFzcz0ibW9kYWwtaGVhZCI+PGgzPuWIoOmZpOivgeS5pjwvaDM+PGJ1dHRvbiBjbGFzcz0iZ2hvc3QiIG9uY2xp",
            "Y2s9ImN0eERlbENhbmNlbCgpIj7lj5bmtog8L2J1dHRvbj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9Im1vZGFsLWJvZHkiPgogICAgICA8cCBjbGFzcz0iY2Zn",
            "LWhpbnQiIHN0eWxlPSJtYXJnaW4tYm90dG9tOjZweCI+5piv5ZCm5Yig6Zmk6YCJ5Lit5b2T5YmN6KGM5bqP5YiX5Y+35Li6IDxiIGlkPSJjdHhEZWxTZXJp",
            "YWwiIHN0eWxlPSJjb2xvcjojZGMyNjI2Ij48L2I+IOeahOivgeS5pu+8nzwvcD4KICAgICAgPHAgY2xhc3M9ImNmZy1oaW50Ij7noa7lrprlkI7lsIblnKgg",
            "Q0VSVFMudHh0IOS4reS4uuivpeihjOa3u+WKoCAjIOazqOmHiu+8iOS7o+ihqOW/veeVpeatpOihjOaVsOaNru+8ie+8jOeUn+aIkCBDUkwgLyBPQ1NQIOiv",
            "geS5puaXtuWwhuiHquWKqOi3s+i/h+OAgjwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ibW9kYWwtZm9vdCI+CiAgICAgIDxidXR0b24gb25jbGlj",
            "az0iY3R4RGVsT2soKSI+56Gu5a6aPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9Imdob3N0IiBvbmNsaWNrPSJjdHhEZWxDYW5jZWwoKSI+5Y+W5raI",
            "PC9idXR0b24+CiAgICA8L2Rpdj4KICA8L2Rpdj4KPC9kaXY+Cg=="
    });

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
    private static final String PAGE_P2 = decodeBase64Parts(new String[]{
            "ICAgICAgICA8c2NyaXB0PgogICAgICAgIC8vID09PT09IOW3peWFtyA9PT09PQogICAgICAgICAgICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ2Vy",
            "cm9yJywgZnVuY3Rpb24oZSl7IHZhciBkPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdqc0VycicpOyBpZighZCl7IGQ9ZG9jdW1lbnQuY3JlYXRlRWxlbWVu",
            "dCgnZGl2Jyk7IGQuaWQ9J2pzRXJyJzsgZC5zdHlsZS5jc3NUZXh0PSdwb3NpdGlvbjpmaXhlZDtib3R0b206MTBweDtyaWdodDoxMHB4O2JhY2tncm91bmQ6",
            "IzdmMWQxZDtjb2xvcjojZmVjYWNhO3BhZGRpbmc6OHB4IDEycHg7Ym9yZGVyLXJhZGl1czo4cHg7Zm9udC1zaXplOjEycHg7ei1pbmRleDo5OTk5OTttYXgt",
            "d2lkdGg6NjB2dzt3aGl0ZS1zcGFjZTpwcmUtd3JhcCc7IGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoZCk7IH0gZC50ZXh0Q29udGVudD0nSlMgRXJyb3I6",
            "ICcrKGUubWVzc2FnZXx8ZSk7IHNldFRpbWVvdXQoZnVuY3Rpb24oKXtkLnJlbW92ZSgpfSw4MDAwKTsgfSk7CmNvbnN0ICQgPSBpZCA9PiBkb2N1bWVudC5n",
            "ZXRFbGVtZW50QnlJZChpZCk7CiAgICAgICAgY29uc3QgdiA9IGlkID0+ICQoaWQpLnZhbHVlLnRyaW0oKTsKICAgICAgICBjb25zdCBUSVRMRVMgPSB7IGRh",
            "c2hib2FyZDon5Luq6KGo55uYJywgY2VydHM6J+ivgeS5puW6kycsIG1ha2Vyb290Oifnrb7lj5HmoLnor4HkuaYnLCBzaWduY2VydDon562+5Y+R6K+B5Lmm",
            "JywgcmV2b2tlOiflkIrplIDor4HkuaYnLCBvY3NwOidPQ1NQfFRTQeetvuWPkScsIHZlcmlmeTon6K+B5Lmm6aqM6K+BJywgdGVtcGxhdGU6J+aooeadv+eu",
            "oeeQhicsIGN0bG9nOidTQ1TmnI3liqHnrqHnkIYnLCBzaWduOifnrb7lkI3kuJPljLonLCBpbml0OifliJ3lp4vljJbnjq/looMnLCB1c2Vyczon55So5oi3",
            "566h55CGJywgcmFkaXVzOidSYWRpdXPmnI3liqHnrqHnkIYnLCBjb25maWc6J+ezu+e7n+mFjee9ricsIGxvZ3M6J+aTjeS9nOaXpeW/lycgfTsKCiAgICAg",
            "ICAgYXN5bmMgZnVuY3Rpb24gYXBpKHBhdGgsIGJvZHkpIHsKICAgICAgICAgIGNvbnN0IG9wdCA9IHsgbWV0aG9kOiBib2R5ID8gJ1BPU1QnIDogJ0dFVCcs",
            "IGhlYWRlcnM6IHt9IH07CiAgICAgICAgICBpZiAoYm9keSAhPT0gdW5kZWZpbmVkKSB7IG9wdC5oZWFkZXJzWydDb250ZW50LVR5cGUnXSA9ICdhcHBsaWNh",
            "dGlvbi9qc29uJzsgb3B0LmJvZHkgPSBKU09OLnN0cmluZ2lmeShib2R5KTsgfQogICAgICAgICAgY29uc3QgciA9IGF3YWl0IGZldGNoKHBhdGgsIG9wdCk7",
            "CiAgICAgICAgICByZXR1cm4gci5qc29uKCk7CiAgICAgICAgfQoKICAgICAgICBmdW5jdGlvbiBzaG93T3V0KGlkLCB0ZXh0LCBvaykgewogICAgICAgICAg",
            "Y29uc3QgZWwgPSAkKGlkKTsKICAgICAgICAgIGVsLmhpZGRlbiA9IGZhbHNlOwogICAgICAgICAgZWwudGV4dENvbnRlbnQgPSB0ZXh0IHx8ICco5peg6L6T",
            "5Ye6KSc7CiAgICAgICAgICBlbC5jbGFzc05hbWUgPSAnb3V0ICcgKyAob2sgPyAnb2snIDogJ2VycicpOwogICAgICAgIH0KCiAgICAgICAgLy8g6K+B5Lmm",
            "6aqM6K+B77ya5LiK5Lyg5pys5ZywIGNlci9jcnQvcGVtIOaWh+S7tumqjOivgQogICAgICAgIGFzeW5jIGZ1bmN0aW9uIHZlcmlmeUZpbGUoKSB7CiAgICAg",
            "ICAgICBjb25zdCBpbnAgPSAkKCd2ZkZpbGUnKTsKICAgICAgICAgIGlmICghaW5wLmZpbGVzIHx8ICFpbnAuZmlsZXMubGVuZ3RoKSB7IHNob3dPdXQoJ3Zm",
            "T3V0JywgJ+ivt+WFiOmAieaLqeivgeS5puaWh+S7tu+8iGNlciAvIGNydCAvIHBlbe+8iScsIGZhbHNlKTsgcmV0dXJuOyB9CiAgICAgICAgICBjb25zdCBm",
            "ZCA9IG5ldyBGb3JtRGF0YSgpOwogICAgICAgICAgZmQuYXBwZW5kKCdmaWxlJywgaW5wLmZpbGVzWzBdKTsKICAgICAgICAgIHNob3dPdXQoJ3ZmT3V0Jywg",
            "J+mqjOivgeS4rS4uLicsIHRydWUpOwogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgY29uc3QgcmVzcCA9IGF3YWl0IGZldGNoKCcvYXBpL3ZlcmlmeS9m",
            "aWxlJywgeyBtZXRob2Q6ICdQT1NUJywgYm9keTogZmQgfSk7CiAgICAgICAgICAgIGNvbnN0IGogPSBhd2FpdCByZXNwLmpzb24oKTsKICAgICAgICAgICAg",
            "aWYgKGoub2spIHNob3dPdXQoJ3ZmT3V0Jywgai5tZXNzYWdlIHx8ICco5peg6L6T5Ye6KScsIHRydWUpOwogICAgICAgICAgICBlbHNlIHNob3dPdXQoJ3Zm",
            "T3V0JywgJ+mqjOivgeWksei0pTogJyArIChqLm1lc3NhZ2UgfHwgJycpLCBmYWxzZSk7CiAgICAgICAgICB9IGNhdGNoIChlKSB7IHNob3dPdXQoJ3ZmT3V0",
            "JywgJ+ivt+axguW8guW4uDogJyArIGUsIGZhbHNlKTsgfQogICAgICAgIH0KCiAgICAgICAgYXN5bmMgZnVuY3Rpb24gcG9zdEZvcm0ocGF0aCwgcGFyYW1z",
            "LCBvdXRJZCwgYnRuKSB7CiAgICAgICAgICBjb25zdCBlbCA9ICQob3V0SWQpOwogICAgICAgICAgZWwuaGlkZGVuID0gZmFsc2U7IGVsLmNsYXNzTmFtZSA9",
            "ICdvdXQnOyBlbC50ZXh0Q29udGVudCA9ICfmiafooYzkuK0uLi4nOwogICAgICAgICAgaWYgKGJ0bikgYnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgICAg",
            "IHRyeSB7CiAgICAgICAgICAgIGNvbnN0IHIgPSBhd2FpdCBhcGkocGF0aCwgcGFyYW1zKTsKICAgICAgICAgICAgc2hvd091dChvdXRJZCwgci5tZXNzYWdl",
            "IHx8ICdPSycsICEhci5vayk7CiAgICAgICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgICAgIHNob3dPdXQob3V0SWQsICfor7fmsYLlpLHotKU6ICcgKyBl",
            "LCBmYWxzZSk7CiAgICAgICAgICB9IGZpbmFsbHkgewogICAgICAgICAgICBpZiAoYnRuKSBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICAgIH0KICAg",
            "ICAgICB9CgogICAgICAgIC8vID09PT09IOetvuWPkeagueivgeS5pu+8mkROIOi+heWKqee8lui+kSA9PT09PQogICAgICAgIC8vIOWfuuehgOWtl+auteaY",
            "oOWwhCBb6L6T5YWl5qGGaWQsIEROIGtleV3vvJvovpPlh7rpobrluo/mjIkgQ0EvQiBGb3J1bSDluLjop4Egc3ViamVjdCBETiDpobrluo/vvIhDLFMsTCxP",
            "LE9VLENOLEXvvInjgIIKICAgICAgICAvLyBFIOmCrueuseWQjuerr+aMiSBPSUQgMS4yLjg0MC4xMTM1NDkuMS45LjEg5aSE55CG44CCCiAgICAgICAgLy8g",
            "PT09PT0g6YCa55SoIEROIOi+heWKqee8lui+ke+8iG1rIOetvuWPkeagueivgeS5piAvIHNjIOetvuWPkeivgeS5piAvIGluIOWIneWni+WMlueOr+WigyDl",
            "hbHnlKjvvIk9PT09PQogICAgICAgIC8vIOWfuuehgOWtl+autSBb5ZCO57yALCBETiBrZXld77yM6L6T5Ye66aG65bqPIEMsUyxMLE8sT1UsQ04sRe+8m0Ug",
            "6YKu566x5ZCO56uv5oyJIE9JRCAxLjIuODQwLjExMzU0OS4xLjkuMSDlpITnkIYKICAgICAgICBjb25zdCBETl9TVERfUEFUID0gW1snQycsJ0MnXSxbJ1Mn",
            "LCdTJ10sWydMJywnTCddLFsnTycsJ08nXSxbJ091JywnT1UnXSxbJ0NuJywnQ04nXSxbJ0UnLCcxLjIuODQwLjExMzU0OS4xLjkuMSddXTsKICAgICAgICBj",
            "b25zdCBETl9FVl9QQVQgPSBbWydSZWcnLCcyLjUuNC41J10sWydCYycsJzIuNS40LjE1J10sCiAgICAgICAgICBbJ0pjJywnMS4zLjYuMS40LjEuMzExLjYw",
            "LjIuMS4zJ10sWydKcycsJzEuMy42LjEuNC4xLjMxMS42MC4yLjEuMiddLFsnSmwnLCcxLjMuNi4xLjQuMS4zMTEuNjAuMi4xLjEnXSwKICAgICAgICAgIFsn",
            "QWRkcicsJzIuNS40LjknXSxbJ09pJywnMi41LjQuOTcnXV07CiAgICAgICAgZnVuY3Rpb24gZG5GKHAsbil7IHJldHVybiBwICsgJ0RuJyArIG47IH0KICAg",
            "ICAgICBmdW5jdGlvbiBkblN0ZChwKXsgcmV0dXJuIEROX1NURF9QQVQubWFwKGZ1bmN0aW9uKHgpeyByZXR1cm4gW2RuRihwLHhbMF0pLCB4WzFdXTsgfSk7",
            "IH0KICAgICAgICBmdW5jdGlvbiBkbkV2RmllbGRzKHApeyByZXR1cm4gRE5fRVZfUEFULm1hcChmdW5jdGlvbih4KXsgcmV0dXJuIFtkbkYocCx4WzBdKSwg",
            "eFsxXV07IH0pOyB9CiAgICAgICAgZnVuY3Rpb24gZG5Fdk9uKHApeyBjb25zdCBlbCA9ICQoZG5GKHAsJ0V2VG9nZ2xlJykpOyByZXR1cm4gZWwgJiYgZWwu",
            "Y2hlY2tlZDsgfQogICAgICAgIGZ1bmN0aW9uIHN5bmNEbihwKSB7CiAgICAgICAgICBjb25zdCBwYXJ0cyA9IFtdOwogICAgICAgICAgY29uc3QgYWxsID0g",
            "ZG5TdGQocCkuY29uY2F0KGRuRXZPbihwKSA/IGRuRXZGaWVsZHMocCkgOiBbXSk7CiAgICAgICAgICBhbGwuZm9yRWFjaChmdW5jdGlvbihwYSl7CiAgICAg",
            "ICAgICAgIGNvbnN0IGVsID0gJChwYVswXSk7IGlmICghZWwpIHJldHVybjsKICAgICAgICAgICAgY29uc3QgdmFsID0gZWwudmFsdWUudHJpbSgpOwogICAg",
            "ICAgICAgICBpZiAodmFsKSBwYXJ0cy5wdXNoKHBhWzFdICsgJz0nICsgdmFsKTsKICAgICAgICAgIH0pOwogICAgICAgICAgZG9jdW1lbnQucXVlcnlTZWxl",
            "Y3RvckFsbCgnIycgKyBwICsgJ0RuT2lkUm93cyAuZG4tb2lkLXJvdycpLmZvckVhY2goZnVuY3Rpb24ocm93KXsKICAgICAgICAgICAgY29uc3QgayA9IHJv",
            "dy5xdWVyeVNlbGVjdG9yKCcuZG4ta2V5JykudmFsdWUudHJpbSgpOwogICAgICAgICAgICBjb25zdCB2YWwgPSByb3cucXVlcnlTZWxlY3RvcignLmRuLXZh",
            "bCcpLnZhbHVlLnRyaW0oKTsKICAgICAgICAgICAgaWYgKGsgJiYgdmFsKSBwYXJ0cy5wdXNoKGsgKyAnPScgKyB2YWwpOwogICAgICAgICAgfSk7CiAgICAg",
            "ICAgICAkKHAgKyAnRG4nKS52YWx1ZSA9IHBhcnRzLmpvaW4oJywnKTsKICAgICAgICB9CiAgICAgICAgZnVuY3Rpb24gdG9nZ2xlRG5FdihwKSB7CiAgICAg",
            "ICAgICBjb25zdCBvbiA9IGRuRXZPbihwKTsKICAgICAgICAgICQocCArICdEbkV2RmllbGRzJykuc3R5bGUuZGlzcGxheSA9IG9uID8gJycgOiAnbm9uZSc7",
            "CiAgICAgICAgICBzeW5jRG4ocCk7CiAgICAgICAgfQogICAgICAgIGZ1bmN0aW9uIGFkZERuUm93KHAsIGtleSwgdmFsKSB7CiAgICAgICAgICBjb25zdCBk",
            "aXYgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgICAgIGRpdi5jbGFzc05hbWUgPSAnZG4tb2lkLXJvdyc7CiAgICAgICAgICBkaXYu",
            "c3R5bGUuY3NzVGV4dCA9ICdkaXNwbGF5OmZsZXg7Z2FwOjZweDttYXJnaW4tYm90dG9tOjZweDthbGlnbi1pdGVtczpjZW50ZXInOwogICAgICAgICAgY29u",
            "c3QgZXNjID0gcyA9PiBTdHJpbmcocyB8fCAnJykucmVwbGFjZSgvIi9nLCAnJnF1b3Q7Jyk7CiAgICAgICAgICBkaXYuaW5uZXJIVE1MID0gJzxpbnB1dCBj",
            "bGFzcz0iZG4ta2V5IiBwbGFjZWhvbGRlcj0i5a2X5q615ZCN5oiWIE9JRO+8iOWmgiAyLjUuNC40Mu+8iSIgc3R5bGU9ImZsZXg6MS4yO21heC13aWR0aDoz",
            "MjBweCIgdmFsdWU9IicgKyBlc2Moa2V5KSArICciIG9uaW5wdXQ9InN5bmNEbihcJycgKyBwICsgJ1wnKSI+JwogICAgICAgICAgICArICc8aW5wdXQgY2xh",
            "c3M9ImRuLXZhbCIgcGxhY2Vob2xkZXI9IuWAvCIgc3R5bGU9ImZsZXg6MS41IiB2YWx1ZT0iJyArIGVzYyh2YWwpICsgJyIgb25pbnB1dD0ic3luY0RuKFwn",
            "JyArIHAgKyAnXCcpIj4nCiAgICAgICAgICAgICsgJzxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0iZ2hvc3QiIHN0eWxlPSJmbGV4Om5vbmUiIG9uY2xp",
            "Y2s9InRoaXMucGFyZW50Tm9kZS5yZW1vdmUoKTtzeW5jRG4oXCcnICsgcCArICdcJykiPuKclTwvYnV0dG9uPic7CiAgICAgICAgICAkKHAgKyAnRG5PaWRS",
            "b3dzJykuYXBwZW5kQ2hpbGQoZGl2KTsKICAgICAgICB9CiAgICAgICAgZnVuY3Rpb24gcGFyc2VEbihwKSB7CiAgICAgICAgICBjb25zdCBkbiA9ICQocCAr",
            "ICdEbicpLnZhbHVlLnRyaW0oKTsKICAgICAgICAgIGlmICghZG4pIHJldHVybjsKICAgICAgICAgICQocCArICdEbk9pZFJvd3MnKS5pbm5lckhUTUwgPSAn",
            "JzsKICAgICAgICAgIGNvbnN0IGFsbCA9IGRuU3RkKHApLmNvbmNhdChkbkV2RmllbGRzKHApKTsKICAgICAgICAgIGFsbC5mb3JFYWNoKGZ1bmN0aW9uKHBh",
            "KXsgJChwYVswXSkudmFsdWUgPSAnJzsgfSk7CiAgICAgICAgICBsZXQgZXZIaXQgPSBmYWxzZTsKICAgICAgICAgIGRuLnNwbGl0KCcsJykuZm9yRWFjaChm",
            "dW5jdGlvbihzZWcpewogICAgICAgICAgICBzZWcgPSBzZWcudHJpbSgpOyBpZiAoIXNlZykgcmV0dXJuOwogICAgICAgICAgICBjb25zdCBpID0gc2VnLmlu",
            "ZGV4T2YoJz0nKTsgaWYgKGkgPCAwKSByZXR1cm47CiAgICAgICAgICAgIGNvbnN0IGsgPSBzZWcuc2xpY2UoMCwgaSkudHJpbSgpLCB2YWwgPSBzZWcuc2xp",
            "Y2UoaSArIDEpLnRyaW0oKTsKICAgICAgICAgICAgY29uc3QgaGl0ID0gYWxsLmZpbmQoZnVuY3Rpb24ocGEpeyByZXR1cm4gcGFbMV0udG9VcHBlckNhc2Uo",
            "KSA9PT0gay50b1VwcGVyQ2FzZSgpOyB9KTsKICAgICAgICAgICAgaWYgKGhpdCkgewogICAgICAgICAgICAgICQoaGl0WzBdKS52YWx1ZSA9IHZhbDsKICAg",
            "ICAgICAgICAgICBpZiAoZG5FdkZpZWxkcyhwKS5pbmRleE9mKGhpdCkgPj0gMCkgZXZIaXQgPSB0cnVlOwogICAgICAgICAgICB9IGVsc2UgYWRkRG5Sb3co",
            "cCwgaywgdmFsKTsKICAgICAgICAgIH0pOwogICAgICAgICAgaWYgKGV2SGl0KSB7ICQoZG5GKHAsJ0V2VG9nZ2xlJykpLmNoZWNrZWQgPSB0cnVlOyAkKHAg",
            "KyAnRG5FdkZpZWxkcycpLnN0eWxlLmRpc3BsYXkgPSAnJzsgfQogICAgICAgIH0KICAgICAgICAvLyBtayDlhbzlrrnljIXoo4XvvIjnrb7lj5HmoLnor4Hk",
            "uabljp/mnInlh73mlbDlkI3kuI3lj5jvvIkKICAgICAgICBmdW5jdGlvbiBta0RuRXZPbigpeyByZXR1cm4gZG5Fdk9uKCdtaycpOyB9CiAgICAgICAgZnVu",
            "Y3Rpb24gc3luY01rRG4oKXsgcmV0dXJuIHN5bmNEbignbWsnKTsgfQogICAgICAgIGZ1bmN0aW9uIHRvZ2dsZU1rRG5FdigpeyByZXR1cm4gdG9nZ2xlRG5F",
            "dignbWsnKTsgfQogICAgICAgIGZ1bmN0aW9uIGFkZE1rRG5Sb3coayx2KXsgcmV0dXJuIGFkZERuUm93KCdtaycsayx2KTsgfQogICAgICAgIGZ1bmN0aW9u",
            "IHBhcnNlTWtEbigpeyByZXR1cm4gcGFyc2VEbignbWsnKTsgfQogICAgICAgIC8vIOmhtemdouWwsee7qu+8muaKiuWQhOmhtem7mOiupCBETiDmi4bliIbl",
            "iLDovoXliqnlrZfmrrUKICAgICAgICBwYXJzZU1rRG4oKTsgcGFyc2VEbignc2MnKTsgcGFyc2VEbignaW4nKTsKCgogICAgICAgIGFzeW5jIGZ1bmN0aW9u",
            "IHF1aWNrQWN0aW9uKHBhdGgpIHsKICAgICAgICAgIHBvc3RGb3JtKHBhdGgsIHt9LCAnZGFzaE91dCcpOwogICAgICAgIH0KCiAgICAgICAgLy8gPT09PT0g",
            "562+5ZCN5LiT5Yy677ya5b6u6L2v5Luj56CB562+5ZCNIC8gUERGIOaWh+aho+etvuWQjSA9PT09PQogICAgICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRTaWdu",
            "Q2VydHMoKSB7CiAgICAgICAgICB0cnkgewogICAgICAgICAgICBjb25zdCByZSA9IGF3YWl0IGFwaSgnL2FwaS9zaWduY2VydHM/a2luZD1leGUnKTsKICAg",
            "ICAgICAgICAgY29uc3QgcnAgPSBhd2FpdCBhcGkoJy9hcGkvc2lnbmNlcnRzP2tpbmQ9cGRmJyk7CiAgICAgICAgICAgIGZpbGxTaWduU2VsKCQoJ3NnRXhl",
            "Q2VydCcpLCAocmUuZGF0YSB8fCBbXSkubGVuZ3RoID8gcmUuZGF0YSA6IG51bGwsICdleGUnKTsKICAgICAgICAgICAgZmlsbFNpZ25TZWwoJCgnc2dQZGZD",
            "ZXJ0JyksIChycC5kYXRhIHx8IFtdKS5sZW5ndGggPyBycC5kYXRhIDogbnVsbCwgJ3BkZicpOwogICAgICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgICAg",
            "ICAkKCdzZ0V4ZUNlcnQnKS5pbm5lckhUTUwgPSAnPG9wdGlvbiB2YWx1ZT0iIj7vvIjliqDovb3lpLHotKU6ICcgKyBlICsgJ++8iTwvb3B0aW9uPic7CiAg",
            "ICAgICAgICAgICQoJ3NnUGRmQ2VydCcpLmlubmVySFRNTCA9ICc8b3B0aW9uIHZhbHVlPSIiPu+8iOWKoOi9veWksei0pTogJyArIGUgKyAn77yJPC9vcHRp",
            "b24+JzsKICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgZnVuY3Rpb24gZmlsbFNpZ25TZWwoc2VsLCBsaXN0LCBraW5kKSB7CiAgICAgICAgICBpZiAo",
            "IWxpc3QpIHsKICAgICAgICAgICAgc2VsLmlubmVySFRNTCA9IGtpbmQgPT09ICdwZGYnCiAgICAgICAgICAgICAgPyAnPG9wdGlvbiB2YWx1ZT0iIj7vvIjk",
            "uI3nrb7lkI3vvIzku4XmlofmoaPml7bpl7TmiLPvvIk8L29wdGlvbj4nCiAgICAgICAgICAgICAgOiAnPG9wdGlvbiB2YWx1ZT0iIj7vvIjml6Dlj6/nlKjo",
            "r4HkuabvvIk8L29wdGlvbj4nOwogICAgICAgICAgICByZXR1cm47CiAgICAgICAgICB9CiAgICAgICAgICBjb25zdCBoaW50ID0ga2luZCA9PT0gJ2V4ZScg",
            "PyAn5Luj56CB562+5ZCNIEVLVScgOiAn5paH5qGj562+5ZCNIEVLVSc7CiAgICAgICAgICBzZWwuaW5uZXJIVE1MID0ga2luZCA9PT0gJ3BkZicKICAgICAg",
            "ICAgICAgPyAnPG9wdGlvbiB2YWx1ZT0iIj7vvIjkuI3nrb7lkI3vvIzku4XmlofmoaPml7bpl7TmiLPvvIk8L29wdGlvbj4nCiAgICAgICAgICAgIDogJzxv",
            "cHRpb24gdmFsdWU9IiI+77yI6K+36YCJ5oupICcgKyBoaW50ICsgJyDor4HkuabvvIk8L29wdGlvbj4nOwogICAgICAgICAgbGlzdC5mb3JFYWNoKGMgPT4g",
            "ewogICAgICAgICAgICBjb25zdCBvID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnb3B0aW9uJyk7CiAgICAgICAgICAgIG8udmFsdWUgPSBjLnNlcmlhbDsK",
            "ICAgICAgICAgICAgby50ZXh0Q29udGVudCA9IChjLnNyYyA9PT0gJ215JyA/ICfjgJTmiJHnmoTjgJUgJyA6ICcnKSArIGMuc2VyaWFsICsgJyDvvZwgJyAr",
            "IChjLmFsZ28gfHwgJycpICsgKGMuYml0cyA/ICcgJyArIGMuYml0cyA6ICcnKSArICcg772cICcgKyBjLmRuOwogICAgICAgICAgICBvLnRpdGxlID0gJ+W6",
            "j+WIl+WPtzogJyArIGMuc2VyaWFsICsgJ1xu566X5rOVOiAnICsgKGMuYWxnbyB8fCAnJykgKyAoYy5iaXRzID8gJyAnICsgYy5iaXRzICsgJyDkvY0nIDog",
            "JycpICsKICAgICAgICAgICAgICAnXG7pooHlj5HogIU6ICcgKyAoYy5pc3N1ZXIgfHwgJycpICsgJ1xu5pyJ5pWI5pyfOiAnICsgKGMudmFsaWRGcm9tIHx8",
            "ICcnKSArICcgfiAnICsgKGMudmFsaWRUbyB8fCAnJykgKwogICAgICAgICAgICAgICdcbueKtuaAgTogJyArIChjLnN0YXR1cyA9PT0gJ1YnID8gJ+ato+W4",
            "uCcgOiBjLnN0YXR1cyA9PT0gJ1InID8gJ+W3suWQiumUgCcgOiAn5pyq55+lJykgKwogICAgICAgICAgICAgICdcbkVLVTogJyArICgoYy5la3VzIHx8IFtd",
            "KS5qb2luKCcsICcpIHx8ICfvvIjml6DvvIknKSArCiAgICAgICAgICAgICAgJ1xuRE46ICcgKyBjLmRuOwogICAgICAgICAgICBzZWwuYXBwZW5kQ2hpbGQo",
            "byk7CiAgICAgICAgICB9KTsKICAgICAgICB9CiAgICAgICAgLy8gPT09PT0g5b6u6L2v5Luj56CB562+5ZCN5om56YeP5b6F562+5ZCN6Zif5YiX77yI5aSa",
            "6YCJICsg5ouW5ou977yJID09PT09CiAgICAgICAgY29uc3QgZXhlSm9icyA9IFtdOwogICAgICAgIGZ1bmN0aW9uIGFkZEV4ZUZpbGVzKGZpbGVzKSB7CiAg",
            "ICAgICAgICBsZXQgYWRkZWQgPSAwOwogICAgICAgICAgWy4uLmZpbGVzXS5mb3JFYWNoKGYgPT4gewogICAgICAgICAgICBpZiAoIS9cLihleGV8ZGxsfHN5",
            "c3xjYWJ8Y2F0fG1zaSkkL2kudGVzdChmLm5hbWUpKSByZXR1cm47CiAgICAgICAgICAgIGlmIChleGVKb2JzLnNvbWUoaiA9PiBqLmZpbGUubmFtZSA9PT0g",
            "Zi5uYW1lICYmIGouZmlsZS5zaXplID09PSBmLmZpbGUuc2l6ZSkpIHJldHVybjsKICAgICAgICAgICAgZXhlSm9icy5wdXNoKHsgZmlsZTogZiwgc3RhdGU6",
            "ICd3YWl0JywgbXNnOiAn5b6F5aSE55CGJywgYjY0OiBudWxsLCBuYW1lOiBudWxsIH0pOwogICAgICAgICAgICBhZGRlZCsrOwogICAgICAgICAgfSk7CiAg",
            "ICAgICAgICByZW5kZXJFeGVMaXN0KCk7CiAgICAgICAgICByZXR1cm4gYWRkZWQ7CiAgICAgICAgfQogICAgICAgIGZ1bmN0aW9uIHJlbmRlckV4ZUxpc3Qo",
            "KSB7CiAgICAgICAgICBjb25zdCBib3ggPSAkKCdleGVMaXN0Jyk7CiAgICAgICAgICBib3guaW5uZXJIVE1MID0gJyc7CiAgICAgICAgICBleGVKb2JzLmZv",
            "ckVhY2goKGosIGkpID0+IHsKICAgICAgICAgICAgY29uc3Qgcm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgICAgIHJvdy5j",
            "bGFzc05hbWUgPSAncGRmLXJvdyc7CiAgICAgICAgICAgIHJvdy5pbm5lckhUTUwgPSAnPHNwYW4gY2xhc3M9Im5tIiB0aXRsZT0iJyArIGVzYyhqLmZpbGUu",
            "bmFtZSkgKyAnIj4nICsgZXNjKGouZmlsZS5uYW1lKSArICfvvIgnICsgZm10U2l6ZShqLmZpbGUuc2l6ZSkgKyAn77yJPC9zcGFuPicKICAgICAgICAgICAg",
            "ICArICc8c3BhbiBjbGFzcz0ic3QgJyArIChqLnN0YXRlID09PSAnb2snID8gJ29rJyA6IGouc3RhdGUgPT09ICdlcnInID8gJ2VycicgOiAnJykgKyAnIj4n",
            "ICsgZXNjKGoubXNnKSArICc8L3NwYW4+JwogICAgICAgICAgICAgICsgKGouc3RhdGUgPT09ICdvaycgJiYgai5iNjQgPyAnPGEgY2xhc3M9ImRsIiBocmVm",
            "PSJkYXRhOmFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbTtiYXNlNjQsJyArIGouYjY0ICsgJyIgZG93bmxvYWQ9IicgKyBlc2Moai5uYW1lKSArICciPuKshyDk",
            "uIvovb08L2E+JyA6ICcnKQogICAgICAgICAgICAgICsgJzxidXR0b24gb25jbGljaz0iZXhlU2lnbk9uZSgnICsgaSArICcpIj7nrb7lkI08L2J1dHRvbj4n",
            "CiAgICAgICAgICAgICAgKyAnPGJ1dHRvbiBjbGFzcz0iZ2hvc3QiIG9uY2xpY2s9ImV4ZVZlcmlmeU9uZSgnICsgaSArICcpIj7pqozor4E8L2J1dHRvbj4n",
            "CiAgICAgICAgICAgICAgKyAnPGJ1dHRvbiBjbGFzcz0iZ2hvc3QiIG9uY2xpY2s9ImV4ZVJlbW92ZSgnICsgaSArICcpIj7np7vpmaQ8L2J1dHRvbj4nOwog",
            "ICAgICAgICAgICBib3guYXBwZW5kQ2hpbGQocm93KTsKICAgICAgICAgIH0pOwogICAgICAgICAgJCgnZXhlQ291bnQnKS50ZXh0Q29udGVudCA9IGV4ZUpv",
            "YnMubGVuZ3RoOwogICAgICAgIH0KICAgICAgICBmdW5jdGlvbiBleGVSZW1vdmUoaSkgeyBleGVKb2JzLnNwbGljZShpLCAxKTsgcmVuZGVyRXhlTGlzdCgp",
            "OyB9CiAgICAgICAgZnVuY3Rpb24gZXhlQ2xlYXIoKSB7IGV4ZUpvYnMubGVuZ3RoID0gMDsgcmVuZGVyRXhlTGlzdCgpOyAkKCdzZ0V4ZU91dCcpLmhpZGRl",
            "biA9IHRydWU7IH0KICAgICAgICBmdW5jdGlvbiBleGVQYXJhbXMoKSB7CiAgICAgICAgICBjb25zdCBmZCA9IG5ldyBGb3JtRGF0YSgpOwogICAgICAgICAg",
            "ZmQuYXBwZW5kKCdzZXJpYWwnLCAkKCdzZ0V4ZUNlcnQnKS52YWx1ZSk7CiAgICAgICAgICBmZC5hcHBlbmQoJ3RzVHlwZScsICQoJ3NnRXhlVHNUeXBlJyku",
            "dmFsdWUpOwogICAgICAgICAgZmQuYXBwZW5kKCd0c1VybCcsICQoJ3NnRXhlVHNVcmwnKS52YWx1ZSk7CiAgICAgICAgICByZXR1cm4gZmQ7CiAgICAgICAg",
            "fQogICAgICAgIGZ1bmN0aW9uIGV4ZVByZUNoZWNrKCkgewogICAgICAgICAgaWYgKCEkKCdzZ0V4ZUNlcnQnKS52YWx1ZSkgcmV0dXJuICfor7flhYjpgInm",
            "i6nnrb7lkI3or4HkuaYnOwogICAgICAgICAgcmV0dXJuIG51bGw7CiAgICAgICAgfQogICAgICAgIGFzeW5jIGZ1bmN0aW9uIGV4ZVNpZ25PbmUoaSkgewog",
            "ICAgICAgICAgY29uc3QgaiA9IGV4ZUpvYnNbaV07CiAgICAgICAgICBpZiAoIWopIHJldHVybjsKICAgICAgICAgIGNvbnN0IGVyciA9IGV4ZVByZUNoZWNr",
            "KCk7CiAgICAgICAgICBpZiAoZXJyKSB7IGouc3RhdGUgPSAnZXJyJzsgai5tc2cgPSBlcnI7IHJlbmRlckV4ZUxpc3QoKTsgcmV0dXJuOyB9CiAgICAgICAg",
            "ICBqLnN0YXRlID0gJ3NpZ25pbmcnOyBqLm1zZyA9ICfnrb7lkI3kuK0uLi4nOyByZW5kZXJFeGVMaXN0KCk7CiAgICAgICAgICBjb25zdCBmZCA9IGV4ZVBh",
            "cmFtcygpOwogICAgICAgICAgZmQuYXBwZW5kKCduYW1lJywgai5maWxlLm5hbWUpOwogICAgICAgICAgZmQuYXBwZW5kKCdmaWxlJywgai5maWxlKTsKICAg",
            "ICAgICAgIHRyeSB7CiAgICAgICAgICAgIGNvbnN0IHJlc3AgPSBhd2FpdCBmZXRjaCgnL2FwaS9zaWduL2V4ZScsIHsgbWV0aG9kOiAnUE9TVCcsIGJvZHk6",
            "IGZkIH0pOwogICAgICAgICAgICBjb25zdCByID0gYXdhaXQgcmVzcC5qc29uKCk7CiAgICAgICAgICAgIGouc3RhdGUgPSByLm9rID8gJ29rJyA6ICdlcnIn",
            "OwogICAgICAgICAgICBqLm1zZyA9IChyLm9rID8gJ+KckyDnrb7lkI3miJDlip8nIDogJ+KclyAnICsgKHIubWVzc2FnZSB8fCAn5aSx6LSlJykpLnN1YnN0",
            "cmluZygwLCAxMjApOwogICAgICAgICAgICBqLmI2NCA9IHIub2sgPyAoci5iNjQgfHwgbnVsbCkgOiBudWxsOwogICAgICAgICAgICBqLm5hbWUgPSByLm9r",
            "ID8gKHIubmFtZSB8fCAnc2lnbmVkXycgKyBqLmZpbGUubmFtZSkgOiBudWxsOwogICAgICAgICAgICBqLmxhc3REZXRhaWwgPSByLm1lc3NhZ2UgfHwgJyc7",
            "CiAgICAgICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgICAgIGouc3RhdGUgPSAnZXJyJzsgai5tc2cgPSAn6K+35rGC5aSx6LSlOiAnICsgZTsgai5sYXN0",
            "RGV0YWlsID0gJyc7CiAgICAgICAgICB9CiAgICAgICAgICByZW5kZXJFeGVMaXN0KCk7CiAgICAgICAgICAkKCdzZ0V4ZU91dCcpLmhpZGRlbiA9IGZhbHNl",
            "OwogICAgICAgICAgJCgnc2dFeGVPdXQnKS5jbGFzc05hbWUgPSAnb3V0ICcgKyAoai5zdGF0ZSA9PT0gJ29rJyA/ICdvaycgOiAnZXJyJyk7CiAgICAgICAg",
            "ICAkKCdzZ0V4ZU91dCcpLnRleHRDb250ZW50ID0gJ1snICsgai5maWxlLm5hbWUgKyAnXSAnICsgKGoubGFzdERldGFpbCB8fCBqLm1zZyk7CiAgICAgICAg",
            "fQogICAgICAgIGFzeW5jIGZ1bmN0aW9uIGV4ZVZlcmlmeU9uZShpKSB7CiAgICAgICAgICBjb25zdCBqID0gZXhlSm9ic1tpXTsKICAgICAgICAgIGlmICgh",
            "aikgcmV0dXJuOwogICAgICAgICAgai5zdGF0ZSA9ICdzaWduaW5nJzsgai5tc2cgPSAn6aqM6K+B5LitLi4uJzsgcmVuZGVyRXhlTGlzdCgpOwogICAgICAg",
            "ICAgY29uc3QgZmQgPSBuZXcgRm9ybURhdGEoKTsKICAgICAgICAgIGZkLmFwcGVuZCgnZmlsZScsIGouZmlsZSk7CiAgICAgICAgICB0cnkgewogICAgICAg",
            "ICAgICBjb25zdCByZXNwID0gYXdhaXQgZmV0Y2goJy9hcGkvdmVyaWZ5L2V4ZScsIHsgbWV0aG9kOiAnUE9TVCcsIGJvZHk6IGZkIH0pOwogICAgICAgICAg",
            "ICBjb25zdCByID0gYXdhaXQgcmVzcC5qc29uKCk7CiAgICAgICAgICAgIGouc3RhdGUgPSByLm9rID8gJ29rJyA6ICdlcnInOwogICAgICAgICAgICBqLm1z",
            "ZyA9IChyLm9rID8gJ+KckyDpqozor4HlrozmiJAnIDogJ+KclyDpqozor4HlpLHotKUnKS5zdWJzdHJpbmcoMCwgMTIwKTsKICAgICAgICAgICAgai5sYXN0",
            "RGV0YWlsID0gci5tZXNzYWdlIHx8ICcnOwogICAgICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgICAgICBqLnN0YXRlID0gJ2Vycic7IGoubXNnID0gJ+iv",
            "t+axguWksei0pTogJyArIGU7IGoubGFzdERldGFpbCA9ICcnOwogICAgICAgICAgfQogICAgICAgICAgcmVuZGVyRXhlTGlzdCgpOwogICAgICAgICAgJCgn",
            "c2dFeGVPdXQnKS5oaWRkZW4gPSBmYWxzZTsKICAgICAgICAgICQoJ3NnRXhlT3V0JykuY2xhc3NOYW1lID0gJ291dCAnICsgKGouc3RhdGUgPT09ICdvaycg",
            "PyAnb2snIDogJ2VycicpOwogICAgICAgICAgJCgnc2dFeGVPdXQnKS50ZXh0Q29udGVudCA9ICdbJyArIGouZmlsZS5uYW1lICsgJ10gJyArIChqLmxhc3RE",
            "ZXRhaWwgfHwgai5tc2cpOwogICAgICAgIH0KICAgICAgICBhc3luYyBmdW5jdGlvbiBleGVTaWduQWxsKCkgewogICAgICAgICAgY29uc3Qgb3V0ID0gJCgn",
            "c2dFeGVPdXQnKTsKICAgICAgICAgIGlmICghZXhlSm9icy5sZW5ndGgpIHsgb3V0LmhpZGRlbiA9IGZhbHNlOyBvdXQuY2xhc3NOYW1lID0gJ291dCBlcnIn",
            "OyBvdXQudGV4dENvbnRlbnQgPSAn5b6F562+5ZCN5YiX6KGo5Li656m677yM6K+35YWI5re75Yqg5paH5Lu2JzsgcmV0dXJuOyB9CiAgICAgICAgICBsZXQg",
            "b2tOID0gMCwgZXJyTiA9IDA7IGNvbnN0IGxpbmVzID0gW107CiAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IGV4ZUpvYnMubGVuZ3RoOyBpKyspIHsK",
            "ICAgICAgICAgICAgY29uc3QgaiA9IGV4ZUpvYnNbaV07CiAgICAgICAgICAgIGNvbnN0IGVyciA9IGV4ZVByZUNoZWNrKCk7CiAgICAgICAgICAgIGlmIChl",
            "cnIpIHsgai5zdGF0ZSA9ICdlcnInOyBqLm1zZyA9IGVycjsgZXJyTisrOyBsaW5lcy5wdXNoKCfinJcgJyArIGouZmlsZS5uYW1lICsgJyDihpIgJyArIGVy",
            "cik7IHJlbmRlckV4ZUxpc3QoKTsgY29udGludWU7IH0KICAgICAgICAgICAgai5zdGF0ZSA9ICdzaWduaW5nJzsgai5tc2cgPSAn562+5ZCN5LitLi4uJzsg",
            "cmVuZGVyRXhlTGlzdCgpOwogICAgICAgICAgICBjb25zdCBmZCA9IGV4ZVBhcmFtcygpOwogICAgICAgICAgICBmZC5hcHBlbmQoJ25hbWUnLCBqLmZpbGUu",
            "bmFtZSk7CiAgICAgICAgICAgIGZkLmFwcGVuZCgnZmlsZScsIGouZmlsZSk7CiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgY29uc3QgcmVzcCA9",
            "IGF3YWl0IGZldGNoKCcvYXBpL3NpZ24vZXhlJywgeyBtZXRob2Q6ICdQT1NUJywgYm9keTogZmQgfSk7CiAgICAgICAgICAgICAgY29uc3QgciA9IGF3YWl0",
            "IHJlc3AuanNvbigpOwogICAgICAgICAgICAgIGouc3RhdGUgPSByLm9rID8gJ29rJyA6ICdlcnInOwogICAgICAgICAgICAgIGoubXNnID0gci5vayA/ICfi",
            "nJMg562+5ZCN5oiQ5YqfJyA6ICgn4pyXICcgKyAoci5tZXNzYWdlIHx8ICflpLHotKUnKSkuc3Vic3RyaW5nKDAsIDEwMCk7CiAgICAgICAgICAgICAgai5i",
            "NjQgPSByLm9rID8gKHIuYjY0IHx8IG51bGwpIDogbnVsbDsKICAgICAgICAgICAgICBqLm5hbWUgPSByLm9rID8gKHIubmFtZSB8fCAnc2lnbmVkXycgKyBq",
            "LmZpbGUubmFtZSkgOiBudWxsOwogICAgICAgICAgICAgIGlmIChyLm9rKSBva04rKzsgZWxzZSB7IGVyck4rKzsgbGluZXMucHVzaCgn4pyXICcgKyBqLmZp",
            "bGUubmFtZSArICcg4oaSICcgKyAoci5tZXNzYWdlIHx8ICflpLHotKUnKSk7IH0KICAgICAgICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgICAgICAgIGou",
            "c3RhdGUgPSAnZXJyJzsgai5tc2cgPSAn6K+35rGC5aSx6LSlOiAnICsgZTsgZXJyTisrOyBsaW5lcy5wdXNoKCfinJcgJyArIGouZmlsZS5uYW1lICsgJyDi",
            "hpIgJyArIGUpOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHJlbmRlckV4ZUxpc3QoKTsKICAgICAgICAgIH0KICAgICAgICAgIG91dC5oaWRkZW4gPSBm",
            "YWxzZTsKICAgICAgICAgIG91dC5jbGFzc05hbWUgPSAnb3V0ICcgKyAoZXJyTiA/ICdlcnInIDogJ29rJyk7CiAgICAgICAgICBvdXQudGV4dENvbnRlbnQg",
            "PSAn5om56YeP562+5ZCN5a6M5oiQ77ya5oiQ5YqfICcgKyBva04gKyAnIOS4qu+8jOWksei0pSAnICsgZXJyTiArICcg5LiqJyArIChsaW5lcy5sZW5ndGgg",
            "PyAnXG4nICsgbGluZXMuam9pbignXG4nKSA6ICcnKTsKICAgICAgICB9CiAgICAgICAgYXN5bmMgZnVuY3Rpb24gZXhlVmVyaWZ5QWxsKCkgewogICAgICAg",
            "ICAgY29uc3Qgb3V0ID0gJCgnc2dFeGVPdXQnKTsKICAgICAgICAgIGlmICghZXhlSm9icy5sZW5ndGgpIHsgb3V0LmhpZGRlbiA9IGZhbHNlOyBvdXQuY2xh",
            "c3NOYW1lID0gJ291dCBlcnInOyBvdXQudGV4dENvbnRlbnQgPSAn5b6F562+5ZCN5YiX6KGo5Li656m677yM6K+35YWI5re75Yqg5paH5Lu2JzsgcmV0dXJu",
            "OyB9CiAgICAgICAgICBsZXQgb2tOID0gMCwgZXJyTiA9IDA7IGNvbnN0IGxpbmVzID0gW107CiAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IGV4ZUpv",
            "YnMubGVuZ3RoOyBpKyspIHsKICAgICAgICAgICAgY29uc3QgaiA9IGV4ZUpvYnNbaV07CiAgICAgICAgICAgIGouc3RhdGUgPSAnc2lnbmluZyc7IGoubXNn",
            "ID0gJ+mqjOivgeS4rS4uLic7IHJlbmRlckV4ZUxpc3QoKTsKICAgICAgICAgICAgY29uc3QgZmQgPSBuZXcgRm9ybURhdGEoKTsKICAgICAgICAgICAgZmQu",
            "YXBwZW5kKCdmaWxlJywgai5maWxlKTsKICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICBjb25zdCByZXNwID0gYXdhaXQgZmV0Y2goJy9hcGkvdmVy",
            "aWZ5L2V4ZScsIHsgbWV0aG9kOiAnUE9TVCcsIGJvZHk6IGZkIH0pOwogICAgICAgICAgICAgIGNvbnN0IHIgPSBhd2FpdCByZXNwLmpzb24oKTsKICAgICAg",
            "ICAgICAgICBqLnN0YXRlID0gci5vayA/ICdvaycgOiAnZXJyJzsKICAgICAgICAgICAgICBqLm1zZyA9IHIub2sgPyAn4pyTIOmqjOivgeWujOaIkCcgOiAn",
            "4pyXIOmqjOivgeWksei0pSc7CiAgICAgICAgICAgICAgaWYgKHIub2spIG9rTisrOyBlbHNlIHsgZXJyTisrOyBsaW5lcy5wdXNoKCfinJcgJyArIGouZmls",
            "ZS5uYW1lICsgJyDihpIgJyArIChyLm1lc3NhZ2UgfHwgJ+Wksei0pScpKTsgfQogICAgICAgICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgICAgICAgai5z",
            "dGF0ZSA9ICdlcnInOyBqLm1zZyA9ICfor7fmsYLlpLHotKU6ICcgKyBlOyBlcnJOKys7IGxpbmVzLnB1c2goJ+KclyAnICsgai5maWxlLm5hbWUgKyAnIOKG",
            "kiAnICsgZSk7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgcmVuZGVyRXhlTGlzdCgpOwogICAgICAgICAgfQogICAgICAgICAgb3V0LmhpZGRlbiA9IGZh",
            "bHNlOwogICAgICAgICAgb3V0LmNsYXNzTmFtZSA9ICdvdXQgJyArIChlcnJOID8gJ2VycicgOiAnb2snKTsKICAgICAgICAgIG91dC50ZXh0Q29udGVudCA9",
            "ICfmibnph4/pqozor4HlrozmiJDvvJrmiJDlip8gJyArIG9rTiArICcg5Liq77yM5aSx6LSlICcgKyBlcnJOICsgJyDkuKonICsgKGxpbmVzLmxlbmd0aCA/",
            "ICdcbicgKyBsaW5lcy5qb2luKCdcbicpIDogJycpOwogICAgICAgIH0KICAgICAgICAvLyDmi5bmi73kuI7lpJrpgInliJ3lp4vljJYKICAgICAgICAoZnVu",
            "Y3Rpb24gaW5pdEV4ZURyb3AoKSB7CiAgICAgICAgICBjb25zdCBkeiA9ICQoJ2V4ZURyb3AnKTsKICAgICAgICAgIGlmICghZHopIHJldHVybjsKICAgICAg",
            "ICAgIGR6Lm9uZHJhZ292ZXIgPSBlID0+IHsgZS5wcmV2ZW50RGVmYXVsdCgpOyBkei5jbGFzc0xpc3QuYWRkKCdvdmVyJyk7IH07CiAgICAgICAgICBkei5v",
            "bmRyYWdsZWF2ZSA9ICgpID0+IGR6LmNsYXNzTGlzdC5yZW1vdmUoJ292ZXInKTsKICAgICAgICAgIGR6Lm9uZHJvcCA9IGUgPT4geyBlLnByZXZlbnREZWZh",
            "dWx0KCk7IGR6LmNsYXNzTGlzdC5yZW1vdmUoJ292ZXInKTsgYWRkRXhlRmlsZXMoZS5kYXRhVHJhbnNmZXIuZmlsZXMpOyB9OwogICAgICAgICAgY29uc3Qg",
            "ZmkgPSAkKCdzZ0V4ZUZpbGUnKTsKICAgICAgICAgIGlmIChmaSkgZmkub25jaGFuZ2UgPSBlID0+IHsgYWRkRXhlRmlsZXMoZS50YXJnZXQuZmlsZXMpOyBl",
            "LnRhcmdldC52YWx1ZSA9ICcnOyB9OwogICAgICAgIH0pKCk7CgogICAgICAgIC8vID09PT09IOetvuWQjeS4k+WMuu+8mumAieaLqeWkueWIh+aNoiA9PT09",
            "PQogICAgICAgIGZ1bmN0aW9uIHNpZ1RhYihuYW1lLCBidG4pIHsKICAgICAgICAgIFsnZXhlJywgJ3BkZiddLmZvckVhY2gobiA9PiB7CiAgICAgICAgICAg",
            "ICQoJ3NpZ1BhbmUtJyArIG4pLnN0eWxlLmRpc3BsYXkgPSBuID09PSBuYW1lID8gJycgOiAnbm9uZSc7CiAgICAgICAgICAgICQoJ3NpZ1RhYkJ0bi0nICsg",
            "bikuY2xhc3NMaXN0LnRvZ2dsZSgnYWN0aXZlJywgbiA9PT0gbmFtZSk7CiAgICAgICAgICB9KTsKICAgICAgICB9CgogICAgICAgIC8vID09PT09IE9DU1B8",
            "VFNB562+5Y+R77ya5YiG57G75aS55YiH5o2i77yIT0NTUOetvuWPkSAvIFRTQeetvuWPkSAvIOaooeaLn+ivt+axguiwg+ivle+8iSA9PT09PQogICAgICAg",
            "IGZ1bmN0aW9uIG9jc3BUYWIodCkgewogICAgICAgICAgZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnI29jc3BUYWJzIC5zaWctdGFiJykuZm9yRWFjaChi",
            "ID0+IGIuY2xhc3NMaXN0LnRvZ2dsZSgnYWN0aXZlJywgYi5nZXRBdHRyaWJ1dGUoJ2RhdGEtdGFiJykgPT09IHQpKTsKICAgICAgICAgICQoJ29jc3BJc3N1",
            "ZScpLnN0eWxlLmRpc3BsYXkgPSB0ID09PSAnaXNzdWUnID8gJycgOiAnbm9uZSc7CiAgICAgICAgICAkKCd0c2FJc3N1ZScpLnN0eWxlLmRpc3BsYXkgPSB0",
            "ID09PSAndHNhaXNzdWUnID8gJycgOiAnbm9uZSc7CiAgICAgICAgICAkKCdkYmdPY3NwJykuc3R5bGUuZGlzcGxheSA9IHQgPT09ICdkZWJ1Z29jc3AnID8g",
            "JycgOiAnbm9uZSc7CiAgICAgICAgICAkKCdkYmdUc2EnKS5zdHlsZS5kaXNwbGF5ID0gdCA9PT0gJ2RlYnVndHNhJyA/ICcnIDogJ25vbmUnOwogICAgICAg",
            "IH0KCiAgICAgICAgLy8gPT09PT0gUERGIOaJuemHj+W+heetvuWQjemYn+WIl++8iOWkmumAiSArIOaLluaLve+8iSA9PT09PQogICAgICAgIGNvbnN0IHBk",
            "ZkpvYnMgPSBbXTsKICAgICAgICBmdW5jdGlvbiBhZGRQZGZGaWxlcyhmaWxlcykgewogICAgICAgICAgbGV0IGFkZGVkID0gMDsKICAgICAgICAgIFsuLi5m",
            "aWxlc10uZm9yRWFjaChmID0+IHsKICAgICAgICAgICAgaWYgKCEvXC5wZGYkL2kudGVzdChmLm5hbWUpKSByZXR1cm47CiAgICAgICAgICAgIGlmIChwZGZK",
            "b2JzLnNvbWUoaiA9PiBqLmZpbGUubmFtZSA9PT0gZi5uYW1lICYmIGouZmlsZS5zaXplID09PSBmLmZpbGUuc2l6ZSkpIHJldHVybjsKICAgICAgICAgICAg",
            "cGRmSm9icy5wdXNoKHsgZmlsZTogZiwgc3RhdGU6ICd3YWl0JywgbXNnOiAn5b6F5aSE55CGJywgYjY0OiBudWxsLCBuYW1lOiBudWxsIH0pOwogICAgICAg",
            "ICAgICBhZGRlZCsrOwogICAgICAgICAgfSk7CiAgICAgICAgICByZW5kZXJQZGZMaXN0KCk7CiAgICAgICAgICByZXR1cm4gYWRkZWQ7CiAgICAgICAgfQog",
            "ICAgICAgIGZ1bmN0aW9uIGZtdFNpemUobikgewogICAgICAgICAgcmV0dXJuIG4gPiAxMDQ4NTc2ID8gKG4gLyAxMDQ4NTc2KS50b0ZpeGVkKDEpICsgJyBN",
            "QicgOiBNYXRoLm1heCgxLCBNYXRoLnJvdW5kKG4gLyAxMDI0KSkgKyAnIEtCJzsKICAgICAgICB9CiAgICAgICAgZnVuY3Rpb24gcmVuZGVyUGRmTGlzdCgp",
            "IHsKICAgICAgICAgIGNvbnN0IGJveCA9ICQoJ3BkZkxpc3QnKTsKICAgICAgICAgIGJveC5pbm5lckhUTUwgPSAnJzsKICAgICAgICAgIHBkZkpvYnMuZm9y",
            "RWFjaCgoaiwgaSkgPT4gewogICAgICAgICAgICBjb25zdCByb3cgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgICAgICAgcm93LmNs",
            "YXNzTmFtZSA9ICdwZGYtcm93JzsKICAgICAgICAgICAgcm93LmlubmVySFRNTCA9ICc8c3BhbiBjbGFzcz0ibm0iIHRpdGxlPSInICsgZXNjKGouZmlsZS5u",
            "YW1lKSArICciPicgKyBlc2Moai5maWxlLm5hbWUpICsgJ++8iCcgKyBmbXRTaXplKGouZmlsZS5zaXplKSArICfvvIk8L3NwYW4+JwogICAgICAgICAgICAg",
            "ICsgJzxzcGFuIGNsYXNzPSJzdCAnICsgKGouc3RhdGUgPT09ICdvaycgPyAnb2snIDogai5zdGF0ZSA9PT0gJ2VycicgPyAnZXJyJyA6ICcnKSArICciPicg",
            "KyBlc2Moai5tc2cpICsgJzwvc3Bhbj4nCiAgICAgICAgICAgICAgKyAoai5zdGF0ZSA9PT0gJ29rJyAmJiBqLmI2NCA/ICc8YSBjbGFzcz0iZGwiIGhyZWY9",
            "ImRhdGE6YXBwbGljYXRpb24vcGRmO2Jhc2U2NCwnICsgai5iNjQgKyAnIiBkb3dubG9hZD0iJyArIGVzYyhqLm5hbWUpICsgJyI+4qyHIOS4i+i9vTwvYT4n",
            "IDogJycpCiAgICAgICAgICAgICAgKyAnPGJ1dHRvbiBvbmNsaWNrPSJwZGZTaWduT25lKCcgKyBpICsgJykiPuetvuWQjTwvYnV0dG9uPicKICAgICAgICAg",
            "ICAgICArICc8YnV0dG9uIGNsYXNzPSJnaG9zdCIgb25jbGljaz0icGRmVmVyaWZ5T25lKCcgKyBpICsgJykiPumqjOivgTwvYnV0dG9uPicKICAgICAgICAg",
            "ICAgICArICc8YnV0dG9uIGNsYXNzPSJnaG9zdCIgb25jbGljaz0icGRmUmVtb3ZlKCcgKyBpICsgJykiPuenu+mZpDwvYnV0dG9uPic7CiAgICAgICAgICAg",
            "IGJveC5hcHBlbmRDaGlsZChyb3cpOwogICAgICAgICAgfSk7CiAgICAgICAgICAkKCdwZGZDb3VudCcpLnRleHRDb250ZW50ID0gcGRmSm9icy5sZW5ndGg7",
            "CiAgICAgICAgfQogICAgICAgIGZ1bmN0aW9uIHBkZlJlbW92ZShpKSB7IHBkZkpvYnMuc3BsaWNlKGksIDEpOyByZW5kZXJQZGZMaXN0KCk7IH0KICAgICAg",
            "ICBmdW5jdGlvbiBwZGZDbGVhcigpIHsgcGRmSm9icy5sZW5ndGggPSAwOyByZW5kZXJQZGZMaXN0KCk7ICQoJ3NnUGRmT3V0JykuaGlkZGVuID0gdHJ1ZTsg",
            "fQogICAgICAgIGZ1bmN0aW9uIHBkZlBhcmFtcygpIHsKICAgICAgICAgIGNvbnN0IGZkID0gbmV3IEZvcm1EYXRhKCk7CiAgICAgICAgICBmZC5hcHBlbmQo",
            "J3NlcmlhbCcsICQoJ3NnUGRmQ2VydCcpLnZhbHVlKTsKICAgICAgICAgIGZkLmFwcGVuZCgnc2VhbFR5cGUnLCAkKCdzZ1BkZlNlYWwnKS52YWx1ZSk7CiAg",
            "ICAgICAgICBmZC5hcHBlbmQoJ3RzVXJsJywgJCgnc2dQZGZUc1VybCcpLnZhbHVlKTsKICAgICAgICAgIGNvbnN0IGltZyA9ICQoJ3NnUGRmSW1hZ2UnKS5m",
            "aWxlcyAmJiAkKCdzZ1BkZkltYWdlJykuZmlsZXNbMF07CiAgICAgICAgICBpZiAoaW1nKSBmZC5hcHBlbmQoJ2ltYWdlJywgaW1nKTsKICAgICAgICAgIHJl",
            "dHVybiBmZDsKICAgICAgICB9CiAgICAgICAgZnVuY3Rpb24gcGRmUHJlQ2hlY2soKSB7CiAgICAgICAgICBjb25zdCBzZXJpYWwgPSAkKCdzZ1BkZkNlcnQn",
            "KS52YWx1ZTsKICAgICAgICAgIGNvbnN0IHNlYWwgPSAkKCdzZ1BkZlNlYWwnKS52YWx1ZTsKICAgICAgICAgIGlmICghc2VyaWFsKSB7CiAgICAgICAgICAg",
            "IGlmIChzZWFsICE9PSAnQURPQkUnKSByZXR1cm4gJ+e6r+aWh+aho+aXtumXtOaIs++8iOS4jemAieivgeS5pu+8ieS7heaUr+aMgSBBZG9iZSDmoIflh4Yn",
            "OwogICAgICAgICAgICBpZiAoJCgnc2dQZGZJbWFnZScpLmZpbGVzICYmICQoJ3NnUGRmSW1hZ2UnKS5maWxlc1swXSkgcmV0dXJuICfnuq/mlofmoaPml7bp",
            "l7TmiLPvvIjkuI3pgInor4HkuabvvInkuI3og73pmYTliqDnrb7nq6Dlm77niYcnOwogICAgICAgICAgfQogICAgICAgICAgcmV0dXJuIG51bGw7CiAgICAg",
            "ICAgfQogICAgICAgIGFzeW5jIGZ1bmN0aW9uIHBkZlNpZ25PbmUoaSkgewogICAgICAgICAgY29uc3QgaiA9IHBkZkpvYnNbaV07CiAgICAgICAgICBpZiAo",
            "IWopIHJldHVybjsKICAgICAgICAgIGNvbnN0IGVyciA9IHBkZlByZUNoZWNrKCk7CiAgICAgICAgICBpZiAoZXJyKSB7IGouc3RhdGUgPSAnZXJyJzsgai5t",
            "c2cgPSBlcnI7IHJlbmRlclBkZkxpc3QoKTsgcmV0dXJuOyB9CiAgICAgICAgICBqLnN0YXRlID0gJ3NpZ25pbmcnOyBqLm1zZyA9ICfnrb7lkI3kuK0uLi4n",
            "OyByZW5kZXJQZGZMaXN0KCk7CiAgICAgICAgICBjb25zdCBmZCA9IHBkZlBhcmFtcygpOwogICAgICAgICAgZmQuYXBwZW5kKCduYW1lJywgai5maWxlLm5h",
            "bWUpOwogICAgICAgICAgZmQuYXBwZW5kKCdmaWxlJywgai5maWxlKTsKICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgIGNvbnN0IHJlc3AgPSBhd2FpdCBm",
            "ZXRjaCgnL2FwaS9zaWduL3BkZicsIHsgbWV0aG9kOiAnUE9TVCcsIGJvZHk6IGZkIH0pOwogICAgICAgICAgICBjb25zdCByID0gYXdhaXQgcmVzcC5qc29u",
            "KCk7CiAgICAgICAgICAgIGouc3RhdGUgPSByLm9rID8gJ29rJyA6ICdlcnInOwogICAgICAgICAgICBqLm1zZyA9IChyLm9rID8gJ+KckyDnrb7lkI3miJDl",
            "ip8nIDogJ+KclyAnICsgKHIubWVzc2FnZSB8fCAn5aSx6LSlJykpLnN1YnN0cmluZygwLCAxMjApOwogICAgICAgICAgICBqLmI2NCA9IHIub2sgPyAoci5i",
            "NjQgfHwgbnVsbCkgOiBudWxsOwogICAgICAgICAgICBqLm5hbWUgPSByLm9rID8gKHIubmFtZSB8fCAnc2lnbmVkXycgKyBqLmZpbGUubmFtZSkgOiBudWxs",
            "OwogICAgICAgICAgICBqLmxhc3REZXRhaWwgPSByLm1lc3NhZ2UgfHwgJyc7CiAgICAgICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgICAgIGouc3RhdGUg",
            "PSAnZXJyJzsgai5tc2cgPSAn6K+35rGC5aSx6LSlOiAnICsgZTsgai5sYXN0RGV0YWlsID0gJyc7CiAgICAgICAgICB9CiAgICAgICAgICByZW5kZXJQZGZM",
            "aXN0KCk7CiAgICAgICAgICAkKCdzZ1BkZk91dCcpLmhpZGRlbiA9IGZhbHNlOwogICAgICAgICAgJCgnc2dQZGZPdXQnKS5jbGFzc05hbWUgPSAnb3V0ICcg",
            "KyAoai5zdGF0ZSA9PT0gJ29rJyA/ICdvaycgOiAnZXJyJyk7CiAgICAgICAgICAkKCdzZ1BkZk91dCcpLnRleHRDb250ZW50ID0gJ1snICsgai5maWxlLm5h",
            "bWUgKyAnXSAnICsgKGoubGFzdERldGFpbCB8fCBqLm1zZyk7CiAgICAgICAgfQogICAgICAgIGFzeW5jIGZ1bmN0aW9uIHBkZlZlcmlmeU9uZShpKSB7CiAg",
            "ICAgICAgICBjb25zdCBqID0gcGRmSm9ic1tpXTsKICAgICAgICAgIGlmICghaikgcmV0dXJuOwogICAgICAgICAgai5zdGF0ZSA9ICdzaWduaW5nJzsgai5t",
            "c2cgPSAn6aqM6K+B5LitLi4uJzsgcmVuZGVyUGRmTGlzdCgpOwogICAgICAgICAgY29uc3QgZmQgPSBuZXcgRm9ybURhdGEoKTsKICAgICAgICAgIGZkLmFw",
            "cGVuZCgnZmlsZScsIGouZmlsZSk7CiAgICAgICAgICB0cnkgewogICAgICAgICAgICBjb25zdCByZXNwID0gYXdhaXQgZmV0Y2goJy9hcGkvdmVyaWZ5L3Bk",
            "ZicsIHsgbWV0aG9kOiAnUE9TVCcsIGJvZHk6IGZkIH0pOwogICAgICAgICAgICBjb25zdCByID0gYXdhaXQgcmVzcC5qc29uKCk7CiAgICAgICAgICAgIGou",
            "c3RhdGUgPSByLm9rID8gJ29rJyA6ICdlcnInOwogICAgICAgICAgICBqLm1zZyA9IChyLm9rID8gJ+KckyDpqozor4HlrozmiJAnIDogJ+KclyDpqozor4Hl",
            "pLHotKUnKS5zdWJzdHJpbmcoMCwgMTIwKTsKICAgICAgICAgICAgai5sYXN0RGV0YWlsID0gci5tZXNzYWdlIHx8ICcnOwogICAgICAgICAgfSBjYXRjaCAo",
            "ZSkgewogICAgICAgICAgICBqLnN0YXRlID0gJ2Vycic7IGoubXNnID0gJ+ivt+axguWksei0pTogJyArIGU7IGoubGFzdERldGFpbCA9ICcnOwogICAgICAg",
            "ICAgfQogICAgICAgICAgcmVuZGVyUGRmTGlzdCgpOwogICAgICAgICAgJCgnc2dQZGZPdXQnKS5oaWRkZW4gPSBmYWxzZTsKICAgICAgICAgICQoJ3NnUGRm",
            "T3V0JykuY2xhc3NOYW1lID0gJ291dCAnICsgKGouc3RhdGUgPT09ICdvaycgPyAnb2snIDogJ2VycicpOwogICAgICAgICAgJCgnc2dQZGZPdXQnKS50ZXh0",
            "Q29udGVudCA9ICdbJyArIGouZmlsZS5uYW1lICsgJ10gJyArIChqLmxhc3REZXRhaWwgfHwgai5tc2cpOwogICAgICAgIH0KICAgICAgICBhc3luYyBmdW5j",
            "dGlvbiBwZGZTaWduQWxsKCkgewogICAgICAgICAgY29uc3Qgb3V0ID0gJCgnc2dQZGZPdXQnKTsKICAgICAgICAgIGlmICghcGRmSm9icy5sZW5ndGgpIHsg",
            "b3V0LmhpZGRlbiA9IGZhbHNlOyBvdXQuY2xhc3NOYW1lID0gJ291dCBlcnInOyBvdXQudGV4dENvbnRlbnQgPSAn5b6F562+5ZCN5YiX6KGo5Li656m677yM",
            "6K+35YWI5re75YqgIFBERiDmlofku7YnOyByZXR1cm47IH0KICAgICAgICAgIGxldCBva04gPSAwLCBlcnJOID0gMDsgY29uc3QgbGluZXMgPSBbXTsKICAg",
            "ICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgcGRmSm9icy5sZW5ndGg7IGkrKykgewogICAgICAgICAgICBjb25zdCBqID0gcGRmSm9ic1tpXTsKICAgICAg",
            "ICAgICAgY29uc3QgZXJyID0gcGRmUHJlQ2hlY2soKTsKICAgICAgICAgICAgaWYgKGVycikgeyBqLnN0YXRlID0gJ2Vycic7IGoubXNnID0gZXJyOyBlcnJO",
            "Kys7IGxpbmVzLnB1c2goJ+KclyAnICsgai5maWxlLm5hbWUgKyAnIOKGkiAnICsgZXJyKTsgcmVuZGVyUGRmTGlzdCgpOyBjb250aW51ZTsgfQogICAgICAg",
            "ICAgICBqLnN0YXRlID0gJ3NpZ25pbmcnOyBqLm1zZyA9ICfnrb7lkI3kuK0uLi4nOyByZW5kZXJQZGZMaXN0KCk7CiAgICAgICAgICAgIGNvbnN0IGZkID0g",
            "cGRmUGFyYW1zKCk7CiAgICAgICAgICAgIGZkLmFwcGVuZCgnbmFtZScsIGouZmlsZS5uYW1lKTsKICAgICAgICAgICAgZmQuYXBwZW5kKCdmaWxlJywgai5m",
            "aWxlKTsKICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICBjb25zdCByZXNwID0gYXdhaXQgZmV0Y2goJy9hcGkvc2lnbi9wZGYnLCB7IG1ldGhvZDog",
            "J1BPU1QnLCBib2R5OiBmZCB9KTsKICAgICAgICAgICAgICBjb25zdCByID0gYXdhaXQgcmVzcC5qc29uKCk7CiAgICAgICAgICAgICAgai5zdGF0ZSA9IHIu",
            "b2sgPyAnb2snIDogJ2Vycic7CiAgICAgICAgICAgICAgai5tc2cgPSByLm9rID8gJ+KckyDnrb7lkI3miJDlip8nIDogKCfinJcgJyArIChyLm1lc3NhZ2Ug",
            "fHwgJ+Wksei0pScpKS5zdWJzdHJpbmcoMCwgMTAwKTsKICAgICAgICAgICAgICBqLmI2NCA9IHIub2sgPyAoci5iNjQgfHwgbnVsbCkgOiBudWxsOwogICAg",
            "ICAgICAgICAgIGoubmFtZSA9IHIub2sgPyAoci5uYW1lIHx8ICdzaWduZWRfJyArIGouZmlsZS5uYW1lKSA6IG51bGw7CiAgICAgICAgICAgICAgaWYgKHIu",
            "b2spIG9rTisrOyBlbHNlIHsgZXJyTisrOyBsaW5lcy5wdXNoKCfinJcgJyArIGouZmlsZS5uYW1lICsgJyDihpIgJyArIChyLm1lc3NhZ2UgfHwgJ+Wksei0",
            "pScpKTsgfQogICAgICAgICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgICAgICAgai5zdGF0ZSA9ICdlcnInOyBqLm1zZyA9ICfor7fmsYLlpLHotKU6ICcg",
            "KyBlOyBlcnJOKys7IGxpbmVzLnB1c2goJ+KclyAnICsgai5maWxlLm5hbWUgKyAnIOKGkiAnICsgZSk7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgcmVu",
            "ZGVyUGRmTGlzdCgpOwogICAgICAgICAgfQogICAgICAgICAgb3V0LmhpZGRlbiA9IGZhbHNlOwogICAgICAgICAgb3V0LmNsYXNzTmFtZSA9ICdvdXQgJyAr",
            "IChlcnJOID8gJ2VycicgOiAnb2snKTsKICAgICAgICAgIG91dC50ZXh0Q29udGVudCA9ICfmibnph4/nrb7lkI3lrozmiJDvvJrmiJDlip8gJyArIG9rTiAr",
            "ICcg5Liq77yM5aSx6LSlICcgKyBlcnJOICsgJyDkuKonICsgKGxpbmVzLmxlbmd0aCA/ICdcbicgKyBsaW5lcy5qb2luKCdcbicpIDogJycpOwogICAgICAg",
            "IH0KICAgICAgICBhc3luYyBmdW5jdGlvbiBwZGZWZXJpZnlBbGwoKSB7CiAgICAgICAgICBjb25zdCBvdXQgPSAkKCdzZ1BkZk91dCcpOwogICAgICAgICAg",
            "aWYgKCFwZGZKb2JzLmxlbmd0aCkgeyBvdXQuaGlkZGVuID0gZmFsc2U7IG91dC5jbGFzc05hbWUgPSAnb3V0IGVycic7IG91dC50ZXh0Q29udGVudCA9ICfl",
            "voXnrb7lkI3liJfooajkuLrnqbrvvIzor7flhYjmt7vliqAgUERGIOaWh+S7tic7IHJldHVybjsgfQogICAgICAgICAgbGV0IG9rTiA9IDAsIGVyck4gPSAw",
            "OyBjb25zdCBsaW5lcyA9IFtdOwogICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCBwZGZKb2JzLmxlbmd0aDsgaSsrKSB7CiAgICAgICAgICAgIGNvbnN0",
            "IGogPSBwZGZKb2JzW2ldOwogICAgICAgICAgICBqLnN0YXRlID0gJ3NpZ25pbmcnOyBqLm1zZyA9ICfpqozor4HkuK0uLi4nOyByZW5kZXJQZGZMaXN0KCk7",
            "CiAgICAgICAgICAgIGNvbnN0IGZkID0gbmV3IEZvcm1EYXRhKCk7CiAgICAgICAgICAgIGZkLmFwcGVuZCgnZmlsZScsIGouZmlsZSk7CiAgICAgICAgICAg",
            "IHRyeSB7CiAgICAgICAgICAgICAgY29uc3QgcmVzcCA9IGF3YWl0IGZldGNoKCcvYXBpL3ZlcmlmeS9wZGYnLCB7IG1ldGhvZDogJ1BPU1QnLCBib2R5OiBm",
            "ZCB9KTsKICAgICAgICAgICAgICBjb25zdCByID0gYXdhaXQgcmVzcC5qc29uKCk7CiAgICAgICAgICAgICAgai5zdGF0ZSA9IHIub2sgPyAnb2snIDogJ2Vy",
            "cic7CiAgICAgICAgICAgICAgai5tc2cgPSByLm9rID8gJ+KckyDpqozor4HlrozmiJAnIDogJ+KclyDpqozor4HlpLHotKUnOwogICAgICAgICAgICAgIGlm",
            "IChyLm9rKSBva04rKzsgZWxzZSB7IGVyck4rKzsgbGluZXMucHVzaCgn4pyXICcgKyBqLmZpbGUubmFtZSArICcg4oaSICcgKyAoci5tZXNzYWdlIHx8ICfl",
            "pLHotKUnKSk7IH0KICAgICAgICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgICAgICAgIGouc3RhdGUgPSAnZXJyJzsgai5tc2cgPSAn6K+35rGC5aSx6LSl",
            "OiAnICsgZTsgZXJyTisrOyBsaW5lcy5wdXNoKCfinJcgJyArIGouZmlsZS5uYW1lICsgJyDihpIgJyArIGUpOwogICAgICAgICAgICB9CiAgICAgICAgICAg",
            "IHJlbmRlclBkZkxpc3QoKTsKICAgICAgICAgIH0KICAgICAgICAgIG91dC5oaWRkZW4gPSBmYWxzZTsKICAgICAgICAgIG91dC5jbGFzc05hbWUgPSAnb3V0",
            "ICcgKyAoZXJyTiA/ICdlcnInIDogJ29rJyk7CiAgICAgICAgICBvdXQudGV4dENvbnRlbnQgPSAn5om56YeP6aqM6K+B5a6M5oiQ77ya5oiQ5YqfICcgKyBv",
            "a04gKyAnIOS4qu+8jOWksei0pSAnICsgZXJyTiArICcg5LiqJyArIChsaW5lcy5sZW5ndGggPyAnXG4nICsgbGluZXMuam9pbignXG4nKSA6ICcnKTsKICAg",
            "ICAgICB9CiAgICAgICAgLy8g5ouW5ou95LiO5aSa6YCJ5Yid5aeL5YyWCiAgICAgICAgKGZ1bmN0aW9uIGluaXRQZGZEcm9wKCkgewogICAgICAgICAgY29u",
            "c3QgZHogPSAkKCdwZGZEcm9wJyk7CiAgICAgICAgICBpZiAoIWR6KSByZXR1cm47CiAgICAgICAgICBkei5vbmRyYWdvdmVyID0gZSA9PiB7IGUucHJldmVu",
            "dERlZmF1bHQoKTsgZHouY2xhc3NMaXN0LmFkZCgnb3ZlcicpOyB9OwogICAgICAgICAgZHoub25kcmFnbGVhdmUgPSAoKSA9PiBkei5jbGFzc0xpc3QucmVt",
            "b3ZlKCdvdmVyJyk7CiAgICAgICAgICBkei5vbmRyb3AgPSBlID0+IHsgZS5wcmV2ZW50RGVmYXVsdCgpOyBkei5jbGFzc0xpc3QucmVtb3ZlKCdvdmVyJyk7",
            "IGFkZFBkZkZpbGVzKGUuZGF0YVRyYW5zZmVyLmZpbGVzKTsgfTsKICAgICAgICAgIGNvbnN0IGZpID0gJCgnc2dQZGZGaWxlJyk7CiAgICAgICAgICBpZiAo",
            "ZmkpIGZpLm9uY2hhbmdlID0gZSA9PiB7IGFkZFBkZkZpbGVzKGUudGFyZ2V0LmZpbGVzKTsgZS50YXJnZXQudmFsdWUgPSAnJzsgfTsKICAgICAgICB9KSgp",
            "OwoKICAgICAgICAvLyA9PT09PSDpobXpnaLliIfmjaIgPT09PT0KICAgICAgICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcjbmF2IGEnKS5mb3JFYWNo",
            "KGEgPT4gewogICAgICAgICAgYS5vbmNsaWNrID0gKCkgPT4gewogICAgICAgICAgICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcjbmF2IGEnKS5mb3JF",
            "YWNoKHggPT4geC5jbGFzc0xpc3QucmVtb3ZlKCdhY3RpdmUnKSk7CiAgICAgICAgICAgIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJy5wYWdlJykuZm9y",
            "RWFjaCh4ID0+IHguY2xhc3NMaXN0LnJlbW92ZSgnYWN0aXZlJykpOwogICAgICAgICAgICBhLmNsYXNzTGlzdC5hZGQoJ2FjdGl2ZScpOwogICAgICAgICAg",
            "ICBjb25zdCBwID0gYS5kYXRhc2V0LnBhZ2U7CiAgICAgICAgICAgICQoJ3BhZ2UtJyArIHApLmNsYXNzTGlzdC5hZGQoJ2FjdGl2ZScpOwogICAgICAgICAg",
            "ICAkKCdwYWdlVGl0bGUnKS50ZXh0Q29udGVudCA9IFRJVExFU1twXSB8fCBwOwogICAgICAgICAgICBpZiAocCA9PT0gJ2Rhc2hib2FyZCcpIGxvYWRTdGF0",
            "dXMoKTsKICAgICAgICAgICAgaWYgKHAgPT09ICdjZXJ0cycpIHsgbG9hZENlcnRzKCk7IGxvYWRJc3N1ZXJzKCk7IH0KICAgICAgICAgICAgaWYgKHAgPT09",
            "ICdjb25maWcnKSBsb2FkQ29uZmlnKCk7CiAgICAgICAgICAgIGlmIChwID09PSAnbG9ncycpIGxvYWRMb2dzKCk7CiAgICAgICAgICAgIGlmIChwID09PSAn",
            "c2lnbicpIGxvYWRTaWduQ2VydHMoKTsKICAgICAgICAgICAgaWYgKHAgPT09ICd0ZW1wbGF0ZScpIHsgbG9hZFRlbXBsYXRlcygpOyBsb2FkQ2VydHMoKTsg",
            "bG9hZElzc3VlcnMoKTsgfQogICAgICAgICAgICBpZiAocCA9PT0gJ2N0bG9nJykgbG9hZEN0TG9nKCk7CiAgICAgICAgICAgIGlmIChwID09PSAndXNlcnMn",
            "KSBsb2FkVXNlcnMoKTsKICAgICAgICAgICAgaWYgKHAgPT09ICdyYWRpdXMnKSB7IGxvYWRSYWRpdXMoKTsgfQogICAgICAgICAgICBpZiAocCA9PT0gJ3Bw",
            "cG9lJykgeyBsb2FkUHBwb2UoKTsgbG9hZFBwcG9lTG9ncygpOyB9CiAgICAgICAgICB9OwogICAgICAgIH0pOwoKICAgICAgICAvLyA9PT09PSDku6rooajn",
            "m5ggPT09PT0KICAgICAgICBmdW5jdGlvbiBmbXRVcHRpbWUocykgewogICAgICAgICAgaWYgKHMgPCA2MCkgcmV0dXJuIHMgKyAnIOenkic7CiAgICAgICAg",
            "ICBpZiAocyA8IDM2MDApIHJldHVybiBNYXRoLmZsb29yKHMvNjApICsgJyDliIYgJyArIChzJTYwKSArICcg56eSJzsKICAgICAgICAgIGlmIChzIDwgODY0",
            "MDApIHJldHVybiBNYXRoLmZsb29yKHMvMzYwMCkgKyAnIOaXtiAnICsgTWF0aC5mbG9vcihzJTM2MDAvNjApICsgJyDliIYnOwogICAgICAgICAgcmV0dXJu",
            "IE1hdGguZmxvb3Iocy84NjQwMCkgKyAnIOWkqSAnICsgTWF0aC5mbG9vcihzJTg2NDAwLzM2MDApICsgJyDml7YnOwogICAgICAgIH0KICAgICAgICBhc3lu",
            "YyBmdW5jdGlvbiBsb2FkU3RhdHVzKCkgewogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgY29uc3QgciA9IGF3YWl0IGFwaSgnL2FwaS9zdGF0dXMnKTsK",
            "ICAgICAgICAgICAgaWYgKCFyLm9rKSByZXR1cm47CiAgICAgICAgICAgIGNvbnN0IGQgPSByLmRhdGE7CiAgICAgICAgICAgIGlmICgkKCdzdFBvcnQnKSkg",
            "JCgnc3RQb3J0JykudGV4dENvbnRlbnQgPSBkLm1haW5Qb3J0OwogICAgICAgICAgICBpZiAoJCgnc3RVcHRpbWUnKSkgJCgnc3RVcHRpbWUnKS50ZXh0Q29u",
            "dGVudCA9IGZtdFVwdGltZShkLnVwdGltZVNlY29uZHMpOwogICAgICAgICAgICBpZiAoJCgnc3RBZG1pbicpKSAkKCdzdEFkbWluJykudGV4dENvbnRlbnQg",
            "PSBkLmFkbWluUG9ydDsKICAgICAgICAgICAgaWYgKCQoJ3N0Q2FsbHMnKSkgJCgnc3RDYWxscycpLnRleHRDb250ZW50ID0gZC50b3RhbENhbGxzOwogICAg",
            "ICAgICAgICBpZiAoJCgnc3RMb2dzJykpICQoJ3N0TG9ncycpLnRleHRDb250ZW50ID0gZC5sb2dMaW5lczsKICAgICAgICAgICAgaWYgKCQoJ3N0QmFzZScp",
            "KSAkKCdzdEJhc2UnKS50ZXh0Q29udGVudCA9IGQuYmFzZURpcjsKICAgICAgICAgICAgaWYgKCQoJ21haW5Qb3J0JykpICQoJ21haW5Qb3J0JykudGV4dENv",
            "bnRlbnQgPSAnTUFJTjogJyArIGQubWFpblBvcnQ7CiAgICAgICAgICAgIGNvbnN0IHN0ID0gJCgnbWFpblN0YXRlJyk7CiAgICAgICAgICAgIGlmIChzdCkg",
            "ewogICAgICAgICAgICAgIHN0LnRleHRDb250ZW50ID0gZC5tYWluUnVubmluZyA/ICfil48g6L+Q6KGM5LitJyA6ICfil4sg5pyq6L+Q6KGMJzsKICAgICAg",
            "ICAgICAgICBzdC5jbGFzc05hbWUgPSAnYmFkZ2UgJyArIChkLm1haW5SdW5uaW5nID8gJ29rJyA6ICdlcnInKTsKICAgICAgICAgICAgfQogICAgICAgICAg",
            "ICBpZiAoJCgnc2lkZVZlcnNpb24nKSkgJCgnc2lkZVZlcnNpb24nKS50ZXh0Q29udGVudCA9IGQudmVyc2lvbjsKICAgICAgICAgICAgLy8g5pyA6L+R5pel",
            "5b+X77yI5LuF5Luq6KGo55uY6aG15ouJ5Y+W77yM6YG/5YWN5YW25a6D6aG16Z2i55m96ICX5rWB6YeP77yJCiAgICAgICAgICAgIGlmICgkKCdwYWdlLWRh",
            "c2hib2FyZCcpICYmICQoJ3BhZ2UtZGFzaGJvYXJkJykuY2xhc3NMaXN0LmNvbnRhaW5zKCdhY3RpdmUnKSkgewogICAgICAgICAgICAgIGNvbnN0IGxyID0g",
            "YXdhaXQgYXBpKCcvYXBpL2xvZ3M/bGluZXM9MzAnKTsKICAgICAgICAgICAgICBpZiAobHIub2sgJiYgJCgnZGFzaExvZ3MnKSkgJCgnZGFzaExvZ3MnKS50",
            "ZXh0Q29udGVudCA9IGxyLmRhdGE7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgICAgICAgY29uc3Qgc3QgPSAkKCdtYWlu",
            "U3RhdGUnKTsKICAgICAgICAgICAgaWYgKHN0KSB7IHN0LnRleHRDb250ZW50ID0gJ+i/nuaOpeWksei0pSc7IHN0LmNsYXNzTmFtZSA9ICdiYWRnZSBlcnIn",
            "OyB9CiAgICAgICAgICB9CiAgICAgICAgfQoKICAgICAgICAvLyA9PT09PSDor4HkuablupMgPT09PT0KICAgICAgICBsZXQgY2VydERhdGEgPSBbXTsKICAg",
            "ICAgICBhc3luYyBmdW5jdGlvbiBsb2FkQ2VydHMoKSB7CiAgICAgICAgICB0cnkgewogICAgICAgICAgICBjb25zdCByID0gYXdhaXQgYXBpKCcvYXBpL2Nl",
            "cnRzJyk7CiAgICAgICAgICAgIGlmIChyLm9rKSB7IGNlcnREYXRhID0gci5kYXRhOyByZW5kZXJDZXJ0cygpOyB9CiAgICAgICAgICB9IGNhdGNoIChlKSB7",
            "IC8qIGlnbm9yZSAqLyB9CiAgICAgICAgfQogICAgICAgIGZ1bmN0aW9uIHJlbmRlckNlcnRzKCkgewogICAgICAgICAgY29uc3QgZiA9IHYoJ2NlcnRzRmls",
            "dGVyJykudG9Mb3dlckNhc2UoKTsKICAgICAgICAgIGNvbnN0IHJvd3MgPSBjZXJ0RGF0YS5maWx0ZXIoZSA9PiAhZiB8fCBKU09OLnN0cmluZ2lmeShlKS50",
            "b0xvd2VyQ2FzZSgpLmluY2x1ZGVzKGYpKTsKICAgICAgICAgIGNvbnN0IHRiID0gJCgnY2VydHNUYWJsZScpLnF1ZXJ5U2VsZWN0b3IoJ3Rib2R5Jyk7CiAg",
            "ICAgICAgICB0Yi5pbm5lckhUTUwgPSAnJzsKICAgICAgICAgIHJvd3MuZm9yRWFjaChlID0+IHsKICAgICAgICAgICAgY29uc3QgdHIgPSBkb2N1bWVudC5j",
            "cmVhdGVFbGVtZW50KCd0cicpOwogICAgICAgICAgICB0ci5kYXRhc2V0LnNlcmlhbCA9IGUuc2VyaWFsOwogICAgICAgICAgICAvLyDnirbmgIHmlofmnKzv",
            "vJpWLuato+W4uCAvIFIu5bey5ZCK6ZSAIC8gTi7mnKrnn6XvvJvphY3oibLvvJrmraPluLjnu7/jgIHlt7LlkIrplIDmt7HnuqLjgIHmnKrnn6XmqZkKICAg",
            "ICAgICAgICAgY29uc3Qgc3RUeHQgPSB7VjonVi7mraPluLgnLCBSOidSLuW3suWQiumUgCcsIE46J04u5pyq55+lJ31bZS5zdGF0dXNdIHx8IGUuc3RhdHVz",
            "OwogICAgICAgICAgICBjb25zdCBzdENscyA9IGUuc3RhdHVzID09PSAnUicgPyAnY29sb3I6I2RjMjYyNicgOiBlLnN0YXR1cyA9PT0gJ1YnID8gJ2NvbG9y",
            "OnZhcigtLW9rKScgOiBlLnN0YXR1cyA9PT0gJ04nID8gJ2NvbG9yOiNmNTllMGInIDogJyc7CiAgICAgICAgICAgIC8vIOW6j+WIl+WPt+WIl++8mum8oOag",
            "h+aCrOa1ruaYvuekuuivgeS5puivpuaDhe+8iOS4juS7quihqOebmOivgeS5pumTvuWQjOasvuaCrOa1rueql++8iQogICAgICAgICAgICBjb25zdCB0aXAg",
            "PSBjZXJ0VGlwKGUuc2VyaWFsKTsKICAgICAgICAgICAgdHIuaW5uZXJIVE1MID0gJzx0ZCBjbGFzcz0idC1ib3giIGRhdGEtdGlwPSInICsgZXNjKHRpcCkg",
            "KyAnIj4nICsgZXNjKGUuc2VyaWFsKSArICc8L3RkPicgKwogICAgICAgICAgICAgICc8dGQ+JyArIGVzYyh0eXBlTmFtZShlLnR5cGUpKSArICc8L3RkPjx0",
            "ZCBzdHlsZT0iJyArIHN0Q2xzICsgJztmb250LXdlaWdodDo3MDAiPicgKyBlc2Moc3RUeHQpICsgJzwvdGQ+JyArCiAgICAgICAgICAgICAgJzx0ZD4nICsg",
            "ZXNjKGUucmVhc29uKSArICc8L3RkPjx0ZD4nICsgZXNjKGUudGltZSkgKyAnPC90ZD4nICsKICAgICAgICAgICAgICAnPHRkIGNsYXNzPSJ0LWJveCIgZGF0",
            "YS10aXA9IicgKyBlc2MoY2VydFRpcChlLmlzc3VlcikpICsgJyI+JyArIGVzYyhlLmlzc3VlcikgKyAnPC90ZD48dGQ+JyArIGVzYyhlLmFsZ28pICsgJzwv",
            "dGQ+JyArCiAgICAgICAgICAgICAgJzx0ZD48YnV0dG9uIGNsYXNzPSJnaG9zdCIgZGF0YS1zZXJpYWw9IicgKyBlLnNlcmlhbCArICciIHN0eWxlPSJwYWRk",
            "aW5nOjRweCAxMnB4O2ZvbnQtc2l6ZToxMnB4Ij7or6bmg4U8L2J1dHRvbj4gJyArCiAgICAgICAgICAgICAgJzxidXR0b24gY2xhc3M9Imdob3N0IiBkYXRh",
            "LXZlcmlmeT0iJyArIGUuc2VyaWFsICsgJyIgc3R5bGU9InBhZGRpbmc6NHB4IDEycHg7Zm9udC1zaXplOjEycHgiPumqjOivgTwvYnV0dG9uPiAnICsKICAg",
            "ICAgICAgICAgICAnPGJ1dHRvbiBjbGFzcz0iZ2hvc3QiIGRhdGEtb3A9IicgKyBlLnNlcmlhbCArICciIHN0eWxlPSJwYWRkaW5nOjRweCAxMnB4O2ZvbnQt",
            "c2l6ZToxMnB4Ij7mk43kvZw8L2J1dHRvbj48L3RkPic7CiAgICAgICAgICAgIHRiLmFwcGVuZENoaWxkKHRyKTsKICAgICAgICAgIH0pOwogICAgICAgICAg",
            "aWYgKCFyb3dzLmxlbmd0aCkgdGIuaW5uZXJIVE1MID0gJzx0cj48dGQgY29sc3Bhbj0iOCIgc3R5bGU9ImNvbG9yOnZhcigtLWRpbSkiPu+8iOaXoOWMuemF",
            "jeiusOW9le+8iTwvdGQ+PC90cj4nOwogICAgICAgIH0KICAgICAgICAvLyDor4Hkuabmgqzmta7nqpfvvJrkvJjlhYjnlKjor4Hkuabpk77moJHnmoTor6bm",
            "g4XvvIhETi/lr4bpkqUv5ZOI5biML+mVv+W6pi9PQ1NQL0NSTO+8ie+8jOacqueZu+iusOmTvuaVsOaNruaXtuWbnumAgOeZu+iusOihqOS/oeaBrwogICAg",
            "ICAgIGZ1bmN0aW9uIGNlcnRUaXAoc2VyaWFsKSB7CiAgICAgICAgICBjb25zdCBuID0gaXNzdWVyTWFwW3NlcmlhbF07CiAgICAgICAgICBpZiAobikgcmV0",
            "dXJuIGlzc3VlclRpcChzZXJpYWwpOwogICAgICAgICAgY29uc3QgZSA9IGNlcnREYXRhLmZpbmQoeCA9PiB4LnNlcmlhbC50b0xvd2VyQ2FzZSgpID09PSBT",
            "dHJpbmcoc2VyaWFsKS50b0xvd2VyQ2FzZSgpKTsKICAgICAgICAgIGlmICghZSkgcmV0dXJuICc8ZGl2IGNsYXNzPSJrdiI+PGI+6K+B5Lmm5L+h5oGv77ya",
            "PC9iPuacquaJvuWIsO+8iOivpeW6j+WIl+WPt+acqueZu+iusOivpuaDhe+8iTwvZGl2Pic7CiAgICAgICAgICBjb25zdCBzdFR4dCA9IHtWOifmraPluLgn",
            "LCBSOiflt7LlkIrplIAnLCBOOifmnKrnn6UnfVtlLnN0YXR1c10gfHwgZS5zdGF0dXM7CiAgICAgICAgICByZXR1cm4gJzxkaXYgY2xhc3M9Imt2Ij48Yj7l",
            "uo/liJflj7fvvJo8L2I+JyArIGVzYyhlLnNlcmlhbCkgKyAnPC9kaXY+JyArCiAgICAgICAgICAgICc8ZGl2IGNsYXNzPSJrdiI+PGI+6K+B5Lmm57G75Z6L",
            "77yaPC9iPicgKyBlc2ModHlwZU5hbWUoZS50eXBlKSkgKyAnPC9kaXY+JyArCiAgICAgICAgICAgICc8ZGl2IGNsYXNzPSJrdiI+PGI+54q25oCB77yaPC9i",
            "PicgKyBlc2Moc3RUeHQpICsgJyAvIOeul+azle+8micgKyBlc2MoZS5hbGdvIHx8ICctJykgKyAnPC9kaXY+JyArCiAgICAgICAgICAgICc8ZGl2IGNsYXNz",
            "PSJrdiI+PGI+6aKB5Y+R6ICF77yaPC9iPicgKyBlc2MoZS5pc3N1ZXIpICsgJzwvZGl2PicgKwogICAgICAgICAgICAnPGRpdiBjbGFzcz0ia3YiPjxiPuaX",
            "tumXtO+8mjwvYj4nICsgZXNjKGUudGltZSkgKyAnPC9kaXY+JzsKICAgICAgICB9CgogICAgICAgIC8vID09PT09IOivgeS5puW6k++8muWPr+S/oeWFrOe9",
            "kSBjYWNlcnRzIOmAieaLqeWkue+8iOe7k+aehOWQjCBDRVJUUy50eHQg5YiX6KGo77yJID09PT09CiAgICAgICAgbGV0IGNhRGF0YSA9IFtdOwogICAgICAg",
            "IGZ1bmN0aW9uIGNzU3dpdGNoVGFiKHQpIHsKICAgICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjc1RhYkJ0bkxvY2FsJykuY2xhc3NOYW1lID0g",
            "J2N0LXRhYicgKyAodD09PSdsb2NhbCcgPyAnIGFjdGl2ZScgOiAnJyk7CiAgICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY3NUYWJCdG5DYScp",
            "LmNsYXNzTmFtZSA9ICdjdC10YWInICsgKHQ9PT0nY2FjZXJ0cycgPyAnIGFjdGl2ZScgOiAnJyk7CiAgICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJ",
            "ZCgnY3NUYWJCdG5NeScpLmNsYXNzTmFtZSA9ICdjdC10YWInICsgKHQ9PT0nbXknID8gJyBhY3RpdmUnIDogJycpOwogICAgICAgICAgZG9jdW1lbnQuZ2V0",
            "RWxlbWVudEJ5SWQoJ2NzUGFuZUxvY2FsJykuc3R5bGUuZGlzcGxheSA9IHQ9PT0nbG9jYWwnID8gJycgOiAnbm9uZSc7CiAgICAgICAgICBkb2N1bWVudC5n",
            "ZXRFbGVtZW50QnlJZCgnY3NQYW5lQ2EnKS5zdHlsZS5kaXNwbGF5ID0gdD09PSdjYWNlcnRzJyA/ICcnIDogJ25vbmUnOwogICAgICAgICAgZG9jdW1lbnQu",
            "Z2V0RWxlbWVudEJ5SWQoJ2NzUGFuZU15Jykuc3R5bGUuZGlzcGxheSA9IHQ9PT0nbXknID8gJycgOiAnbm9uZSc7CiAgICAgICAgICBpZiAodD09PSdjYWNl",
            "cnRzJykgbG9hZENhY2VydHMoKTsKICAgICAgICAgIGlmICh0PT09J215JykgbG9hZE15KCk7CiAgICAgICAgfQogICAgICAgIGFzeW5jIGZ1bmN0aW9uIGxv",
            "YWRDYWNlcnRzKCkgewogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgY29uc3QgciA9IGF3YWl0IGFwaSgnL2FwaS9jZXJ0cy9jYWNlcnRzJyk7CiAgICAg",
            "ICAgICAgIGlmIChyLm9rKSB7IGNhRGF0YSA9IHIuZGF0YTsgcmVuZGVyQ2FjZXJ0cygpOyB9CiAgICAgICAgICB9IGNhdGNoIChlKSB7IC8qIGlnbm9yZSAq",
            "LyB9CiAgICAgICAgfQogICAgICAgIGZ1bmN0aW9uIHJlbmRlckNhY2VydHMoKSB7CiAgICAgICAgICBjb25zdCBmID0gdignY2FGaWx0ZXInKS50b0xvd2Vy",
            "Q2FzZSgpOwogICAgICAgICAgY29uc3Qgcm93cyA9IGNhRGF0YS5maWx0ZXIoZSA9PiAhZiB8fCBKU09OLnN0cmluZ2lmeShlKS50b0xvd2VyQ2FzZSgpLmlu",
            "Y2x1ZGVzKGYpKTsKICAgICAgICAgIGNvbnN0IHRiID0gJCgnY2FUYWJsZScpLnF1ZXJ5U2VsZWN0b3IoJ3Rib2R5Jyk7CiAgICAgICAgICB0Yi5pbm5lckhU",
            "TUwgPSAnJzsKICAgICAgICAgIHJvd3MuZm9yRWFjaChlID0+IHsKICAgICAgICAgICAgY29uc3QgdHIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCd0cicp",
            "OwogICAgICAgICAgICB0ci5kYXRhc2V0LnNlcmlhbCA9IGUuc2VyaWFsOwogICAgICAgICAgICB0ci5pbm5lckhUTUwgPSAnPHRkIHN0eWxlPSJmb250LWZh",
            "bWlseTp2YXIoLS1tb25vKTtmb250LXNpemU6MTJweDttYXgtd2lkdGg6MTMwcHg7b3ZlcmZsb3c6aGlkZGVuO3RleHQtb3ZlcmZsb3c6ZWxsaXBzaXM7d2hp",
            "dGUtc3BhY2U6bm93cmFwIiB0aXRsZT0iJyArIGVzYyhlLnNlcmlhbCkgKyAnIj4nICsgZXNjKGUuc2VyaWFsKSArICc8L3RkPicgKwogICAgICAgICAgICAg",
            "ICc8dGQ+JyArIGVzYyhlLmFsZ28pICsgJzwvdGQ+JyArCiAgICAgICAgICAgICAgJzx0ZD4nICsgZXNjKGUubm90QmVmb3JlKSArICc8L3RkPjx0ZD4nICsg",
            "ZXNjKGUubm90QWZ0ZXIpICsgJzwvdGQ+JyArCiAgICAgICAgICAgICAgJzx0ZCBzdHlsZT0ibWF4LXdpZHRoOjM2MHB4O292ZXJmbG93OmhpZGRlbjt0ZXh0",
            "LW92ZXJmbG93OmVsbGlwc2lzO3doaXRlLXNwYWNlOm5vd3JhcCIgdGl0bGU9IicgKyBlc2MoZS5zdWJqZWN0KSArICciPicgKyBlc2MoZS5zdWJqZWN0KSAr",
            "ICc8L3RkPicgKwogICAgICAgICAgICAgICc8dGQ+PGJ1dHRvbiBjbGFzcz0iZ2hvc3QiIGRhdGEtc2VyaWFsPSInICsgZXNjKGUuc2VyaWFsKSArICciIHN0",
            "eWxlPSJwYWRkaW5nOjRweCAxMnB4O2ZvbnQtc2l6ZToxMnB4Ij7or6bmg4U8L2J1dHRvbj48L3RkPic7CiAgICAgICAgICAgIHRiLmFwcGVuZENoaWxkKHRy",
            "KTsKICAgICAgICAgIH0pOwogICAgICAgICAgaWYgKCFyb3dzLmxlbmd0aCkgdGIuaW5uZXJIVE1MID0gJzx0cj48dGQgY29sc3Bhbj0iNiIgc3R5bGU9ImNv",
            "bG9yOnZhcigtLWRpbSkiPu+8iOaXoOWMuemFjeiusOW9le+8iTwvdGQ+PC90cj4nOwogICAgICAgIH0KCiAgICAgICAgLy8gPT09PT0g6K+B5Lmm5bqT77ya",
            "5oiR55qE6K+B5Lmm77yIUEtJL01ZIOWvvOWFpeW6k++8iSA9PT09PQogICAgICAgIGxldCBteURhdGEgPSBbXTsKICAgICAgICBsZXQgbXlQZW5kaW5nRmls",
            "ZSA9IG51bGw7CiAgICAgICAgbGV0IG15UGVuZGluZ05hbWUgPSAnJzsKICAgICAgICBsZXQgbXlEZWxldGVTZXJpYWwgPSAnJzsKICAgICAgICBhc3luYyBm",
            "dW5jdGlvbiBsb2FkTXkoKSB7CiAgICAgICAgICB0cnkgewogICAgICAgICAgICBjb25zdCByID0gYXdhaXQgYXBpKCcvYXBpL215L2xpc3QnKTsKICAgICAg",
            "ICAgICAgaWYgKHIub2spIHsgbXlEYXRhID0gci5kYXRhIHx8IFtdOyByZW5kZXJNeSgpOyB9CiAgICAgICAgICB9IGNhdGNoIChlKSB7IC8qIGlnbm9yZSAq",
            "LyB9CiAgICAgICAgfQogICAgICAgIGZ1bmN0aW9uIG15VHlwZVR4dCh0KSB7IHJldHVybiB7Ujon5qC56K+B5LmmJywgQzonQ0Hor4HkuaYnLCBFOifnu4jn",
            "q6/or4HkuaYnfVt0XSB8fCB0OyB9CiAgICAgICAgZnVuY3Rpb24gcmVuZGVyTXkoKSB7CiAgICAgICAgICBjb25zdCBmID0gdignbXlGaWx0ZXInKS50b0xv",
            "d2VyQ2FzZSgpOwogICAgICAgICAgY29uc3Qgcm93cyA9IG15RGF0YS5maWx0ZXIoZSA9PiAhZiB8fCBKU09OLnN0cmluZ2lmeShlKS50b0xvd2VyQ2FzZSgp",
            "LmluY2x1ZGVzKGYpKTsKICAgICAgICAgIGNvbnN0IHRiID0gJCgnbXlUYWJsZScpLnF1ZXJ5U2VsZWN0b3IoJ3Rib2R5Jyk7CiAgICAgICAgICB0Yi5pbm5l",
            "ckhUTUwgPSAnJzsKICAgICAgICAgIHJvd3MuZm9yRWFjaChlID0+IHsKICAgICAgICAgICAgY29uc3QgdHIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCd0",
            "cicpOwogICAgICAgICAgICB0ci5kYXRhc2V0LnNlcmlhbCA9IGUuc2VyaWFsOwogICAgICAgICAgICB0ci5pbm5lckhUTUwgPQogICAgICAgICAgICAgICc8",
            "dGQgY2xhc3M9InQtYm94IiBkYXRhLXRpcD0iJyArIGVzYyhteVRpcChlKSkgKyAnIj4nICsgZXNjKGUuc2VyaWFsKSArICc8L3RkPicgKwogICAgICAgICAg",
            "ICAgICc8dGQ+JyArIGVzYyhteVR5cGVUeHQoZS50eXBlKSkgKyAnPC90ZD4nICsKICAgICAgICAgICAgICAnPHRkPicgKyBlc2MoZS5hbGdvKSArICc8L3Rk",
            "PicgKwogICAgICAgICAgICAgICc8dGQ+JyArIChlLmhhc0tleSA9PT0gJ1knID8gJ+aYrycgOiAn5ZCmJykgKyAnPC90ZD4nICsKICAgICAgICAgICAgICAn",
            "PHRkPicgKyBlc2MoZS5ub3RCZWZvcmUpICsgJzwvdGQ+PHRkPicgKyBlc2MoZS5ub3RBZnRlcikgKyAnPC90ZD4nICsKICAgICAgICAgICAgICAnPHRkPjxi",
            "dXR0b24gY2xhc3M9Imdob3N0IiBkYXRhLW1zZXJpYWw9IicgKyBlc2MoZS5zZXJpYWwpICsgJyIgZGF0YS1hY3Q9ImRldGFpbCIgc3R5bGU9InBhZGRpbmc6",
            "NHB4IDEycHg7Zm9udC1zaXplOjEycHgiPuivpuaDhTwvYnV0dG9uPiAnICsKICAgICAgICAgICAgICAnPGJ1dHRvbiBjbGFzcz0iZ2hvc3QiIGRhdGEtbXNl",
            "cmlhbD0iJyArIGVzYyhlLnNlcmlhbCkgKyAnIiBkYXRhLWFjdD0idmVyaWZ5IiBzdHlsZT0icGFkZGluZzo0cHggMTJweDtmb250LXNpemU6MTJweCI+6aqM",
            "6K+BPC9idXR0b24+ICcgKwogICAgICAgICAgICAgICc8YnV0dG9uIGNsYXNzPSJnaG9zdCIgZGF0YS1tc2VyaWFsPSInICsgZXNjKGUuc2VyaWFsKSArICci",
            "IGRhdGEtYWN0PSJkZWwiIHN0eWxlPSJwYWRkaW5nOjRweCAxMnB4O2ZvbnQtc2l6ZToxMnB4O2NvbG9yOiNkYzI2MjY7Zm9udC13ZWlnaHQ6NzAwIj7liKDp",
            "maQ8L2J1dHRvbj48L3RkPic7CiAgICAgICAgICAgIHRiLmFwcGVuZENoaWxkKHRyKTsKICAgICAgICAgIH0pOwogICAgICAgICAgaWYgKCFyb3dzLmxlbmd0",
            "aCkgdGIuaW5uZXJIVE1MID0gJzx0cj48dGQgY29sc3Bhbj0iNyIgc3R5bGU9ImNvbG9yOnZhcigtLWRpbSkiPu+8iOaXoOiusOW9le+8jOeCueWHuyLlr7zl",
            "haXor4HkuaYi5re75Yqg77yJPC90ZD48L3RyPic7CiAgICAgICAgfQogICAgICAgIGZ1bmN0aW9uIG15VGlwKGUpIHsKICAgICAgICAgIHJldHVybiAnPGRp",
            "diBjbGFzcz0ia3YiPjxiPuW6j+WIl+WPt++8mjwvYj4nICsgZXNjKGUuc2VyaWFsKSArICc8L2Rpdj4nICsKICAgICAgICAgICAgJzxkaXYgY2xhc3M9Imt2",
            "Ij48Yj7or4HkuabnsbvlnovvvJo8L2I+JyArIGVzYyhteVR5cGVUeHQoZS50eXBlKSkgKyAnPC9kaXY+JyArCiAgICAgICAgICAgICc8ZGl2IGNsYXNzPSJr",
            "diI+PGI+566X5rOV77yaPC9iPicgKyBlc2MoZS5hbGdvKSArICcgLyDnp4HpkqXvvJonICsgKGUuaGFzS2V5ID09PSAnWScgPyAn5pyJJyA6ICfml6AnKSAr",
            "ICc8L2Rpdj4nICsKICAgICAgICAgICAgJzxkaXYgY2xhc3M9Imt2Ij48Yj7mnInmlYjmnJ/vvJo8L2I+JyArIGVzYyhlLm5vdEJlZm9yZSkgKyAnIH4gJyAr",
            "IGVzYyhlLm5vdEFmdGVyKSArICc8L2Rpdj4nOwogICAgICAgIH0KICAgICAgICBmdW5jdGlvbiBteUZpbGVDaG9zZW4oKSB7CiAgICAgICAgICBjb25zdCBp",
            "bnAgPSAkKCdteUZpbGUnKTsKICAgICAgICAgIGlmICghaW5wLmZpbGVzIHx8ICFpbnAuZmlsZXMubGVuZ3RoKSByZXR1cm47CiAgICAgICAgICBjb25zdCBm",
            "aWxlID0gaW5wLmZpbGVzWzBdOwogICAgICAgICAgY29uc3QgbmFtZSA9IChmaWxlLm5hbWUgfHwgJycpLnRvTG93ZXJDYXNlKCk7CiAgICAgICAgICBteVBl",
            "bmRpbmdGaWxlID0gZmlsZTsgbXlQZW5kaW5nTmFtZSA9IGZpbGUubmFtZSB8fCAnY2VydCc7CiAgICAgICAgICBpZiAobmFtZS5lbmRzV2l0aCgnLnBmeCcp",
            "IHx8IG5hbWUuZW5kc1dpdGgoJy5wMTInKSB8fCBuYW1lLmVuZHNXaXRoKCcuamtzJykpIHsKICAgICAgICAgICAgJCgnbXlQd2RGaWxlJykudGV4dENvbnRl",
            "bnQgPSAn5paH5Lu277yaJyArIGZpbGUubmFtZTsKICAgICAgICAgICAgJCgnbXlQd2QnKS52YWx1ZSA9ICcnOwogICAgICAgICAgICAkKCdteVB3ZE1vZGFs",
            "Jykuc3R5bGUuZGlzcGxheSA9ICdmbGV4JzsKICAgICAgICAgICAgc2V0VGltZW91dChmdW5jdGlvbigpeyAkKCdteVB3ZCcpLmZvY3VzKCk7IH0sIDYwKTsK",
            "ICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgIG15RG9JbXBvcnQoJycpOwogICAgICAgICAgfQogICAgICAgICAgaW5wLnZhbHVlID0gJyc7CiAgICAg",
            "ICAgfQogICAgICAgIGZ1bmN0aW9uIGNsb3NlTXlQd2QoKSB7ICQoJ215UHdkTW9kYWwnKS5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnOyB9CiAgICAgICAgZnVu",
            "Y3Rpb24gbXlQd2RPaygpIHsgbXlEb0ltcG9ydCgkKCdteVB3ZCcpLnZhbHVlKTsgY2xvc2VNeVB3ZCgpOyB9CiAgICAgICAgYXN5bmMgZnVuY3Rpb24gbXlE",
            "b0ltcG9ydChwYXNzd29yZCkgewogICAgICAgICAgaWYgKCFteVBlbmRpbmdGaWxlKSByZXR1cm47CiAgICAgICAgICBjb25zdCBtc2cgPSAkKCdteU1zZycp",
            "OwogICAgICAgICAgbXNnLmNsYXNzTmFtZSA9ICdoaW50JzsgbXNnLnN0eWxlLmNvbG9yID0gJ3ZhcigtLWRpbSknOwogICAgICAgICAgbXNnLnRleHRDb250",
            "ZW50ID0gJ+ato+WcqOWvvOWFpSAnICsgbXlQZW5kaW5nTmFtZSArICcgLi4uJzsKICAgICAgICAgIGNvbnN0IGZkID0gbmV3IEZvcm1EYXRhKCk7CiAgICAg",
            "ICAgICBmZC5hcHBlbmQoJ2ZpbGUnLCBteVBlbmRpbmdGaWxlKTsKICAgICAgICAgIGlmIChwYXNzd29yZCAhPT0gJycpIGZkLmFwcGVuZCgncGFzc3dvcmQn",
            "LCBwYXNzd29yZCk7CiAgICAgICAgICB0cnkgewogICAgICAgICAgICBjb25zdCByZXNwID0gYXdhaXQgZmV0Y2goJy9hcGkvbXkvaW1wb3J0JywgeyBtZXRo",
            "b2Q6ICdQT1NUJywgYm9keTogZmQgfSk7CiAgICAgICAgICAgIGNvbnN0IGogPSBhd2FpdCByZXNwLmpzb24oKTsKICAgICAgICAgICAgaWYgKGoub2spIHsK",
            "ICAgICAgICAgICAgICBtc2cuc3R5bGUuY29sb3IgPSAndmFyKC0tb2spJzsKICAgICAgICAgICAgICBtc2cudGV4dENvbnRlbnQgPSAoai5tZXNzYWdlIHx8",
            "ICflr7zlhaXmiJDlip8nKSArICfvvIzor4HkuabvvJonICsgKGouY2VydFBhdGggfHwgJycpICsgKGoua2V5UGF0aCA/ICfvvIznp4HpkqXvvJonICsgai5r",
            "ZXlQYXRoIDogJycpOwogICAgICAgICAgICAgIGxvYWRNeSgpOwogICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgIG1zZy5zdHlsZS5jb2xvciA9",
            "ICd2YXIoLS1lcnIpJzsKICAgICAgICAgICAgICBtc2cudGV4dENvbnRlbnQgPSAn5a+85YWl5aSx6LSl77yaJyArIChqLm1lc3NhZ2UgfHwgJ+acquefpemU",
            "meivrycpOwogICAgICAgICAgICB9CiAgICAgICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgICAgIG1zZy5zdHlsZS5jb2xvciA9ICd2YXIoLS1lcnIpJzsK",
            "ICAgICAgICAgICAgbXNnLnRleHRDb250ZW50ID0gJ+WvvOWFpeivt+axguW8guW4uO+8micgKyBlOwogICAgICAgICAgfQogICAgICAgIH0KICAgICAgICBm",
            "dW5jdGlvbiBteUFza0RlbGV0ZShzZXJpYWwpIHsKICAgICAgICAgIG15RGVsZXRlU2VyaWFsID0gc2VyaWFsOwogICAgICAgICAgJCgnbXlEZWxUZXh0Jyku",
            "dGV4dENvbnRlbnQgPSAn5piv5ZCm5Yig6ZmkIOW6j+WIl+WPt+S4uiAnICsgc2VyaWFsICsgJyDnmoTor4HkuabvvJ8nOwogICAgICAgICAgJCgnbXlEZWxN",
            "b2RhbCcpLnN0eWxlLmRpc3BsYXkgPSAnZmxleCc7CiAgICAgICAgfQogICAgICAgIGZ1bmN0aW9uIGNsb3NlTXlEZWwoKSB7ICQoJ215RGVsTW9kYWwnKS5z",
            "dHlsZS5kaXNwbGF5ID0gJ25vbmUnOyB9CiAgICAgICAgYXN5bmMgZnVuY3Rpb24gbXlEb0RlbGV0ZSgpIHsKICAgICAgICAgIGNvbnN0IHMgPSBteURlbGV0",
            "ZVNlcmlhbDsKICAgICAgICAgIGNsb3NlTXlEZWwoKTsKICAgICAgICAgIGlmICghcykgcmV0dXJuOwogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgY29u",
            "c3QgciA9IGF3YWl0IGFwaSgnL2FwaS9teS9kZWxldGUnLCB7IHNlcmlhbDogcyB9KTsKICAgICAgICAgICAgY29uc3QgbXNnID0gJCgnbXlNc2cnKTsKICAg",
            "ICAgICAgICAgbXNnLmNsYXNzTmFtZSA9ICdoaW50JzsKICAgICAgICAgICAgbXNnLnN0eWxlLmNvbG9yID0gci5vayA/ICd2YXIoLS1vayknIDogJ3Zhcigt",
            "LWVyciknOwogICAgICAgICAgICBtc2cudGV4dENvbnRlbnQgPSByLm1lc3NhZ2UgfHwgKHIub2sgPyAn5Yig6Zmk5oiQ5YqfJyA6ICfliKDpmaTlpLHotKUn",
            "KTsKICAgICAgICAgICAgbG9hZE15KCk7CiAgICAgICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgICAgIGNvbnN0IG1zZyA9ICQoJ215TXNnJyk7CiAgICAg",
            "ICAgICAgIG1zZy5jbGFzc05hbWUgPSAnaGludCc7IG1zZy5zdHlsZS5jb2xvciA9ICd2YXIoLS1lcnIpJzsKICAgICAgICAgICAgbXNnLnRleHRDb250ZW50",
            "ID0gJ+WIoOmZpOivt+axguW8guW4uO+8micgKyBlOwogICAgICAgICAgfQogICAgICAgIH0KCiAgICAgICAgLy8g562+5Y+R6K+B5Lmm55qE6aKB5Y+R6ICF",
            "5LiL5ouJ77yaQ0VSVFMudHh0IOS4rSBSL0Mg57G75Z6L5bqP5YiX5Y+377yI5oKs5YGc5pi+56S66K+B5Lmm6K+m5oOF77yJCiAgICAgICAgbGV0IGlzc3Vl",
            "ck1hcCA9IHt9OwogICAgICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRJc3N1ZXJzKCkgewogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgY29uc3QgW3JpLCBy",
            "Y10gPSBhd2FpdCBQcm9taXNlLmFsbChbYXBpKCcvYXBpL2lzc3VlcnMnKSwgYXBpKCcvYXBpL2NoYWluJyldKTsKICAgICAgICAgICAgaWYgKCFyaS5vaykg",
            "cmV0dXJuOwogICAgICAgICAgICBpc3N1ZXJNYXAgPSB7fTsKICAgICAgICAgICAgaWYgKHJjLm9rKSB7CiAgICAgICAgICAgICAgLy8gL2FwaS9jaGFpbiDo",
            "v5Tlm57ltYzlpZfmoJHvvIzlsZXlubPkuLogc2VyaWFsIOKGkiDoioLngrkK"
    });

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
