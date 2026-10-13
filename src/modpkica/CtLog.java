package modpkica;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CtLog —— 本地 CT 日志服务器核心（RFC 6962 / Certificate Transparency）。
 *
 * <p>功能：
 * <ul>
 *   <li>密钥管理：生成 ECDSA-P256 日志密钥对，写入
 *       {@code PKI/CTLOG/modpkica_ct_list.json}（结构参考 Google log_list v3，
 *       附加 {@code private_key} 字段供本地签名）；支持删除 / 启用（usable）/ 暂停（disable）。</li>
 *   <li>SCT 签发：按 RFC 6962 §3.1/§3.2 构造 precert_entry 签名输入
 *       （issuer_key_hash + 去 poison 的 TBS），用全部 usable 日志密钥逐一 ECDSA-P256
 *       签名，组装 SCTList（TLS 编码），可直接作为证书 1.3.6.1.4.1.11129.2.4.2 扩展值。</li>
 *   <li>请求日志：追加写入 {@code PKI/CTLOG/ctlogs.txt}，每行格式：
 *       {@code SCT待签名数据SHA256 || 毫秒时间戳 || 使用者SKI || 颁发者AKI || 日志公钥ID(base64)}。</li>
 * </ul>
 */
public final class CtLog {

    /** poison 扩展 OID（RFC 6962 §3.1）。 */
    public static final String OID_POISON = "1.3.6.1.4.1.11129.2.4.3";
    /** SCT 列表扩展 OID（RFC 6962 §3.2）。 */
    public static final String OID_SCT = "1.3.6.1.4.1.11129.2.4.2";

    private CtLog() {
    }

    /** 密钥库文件路径。 */
    public static String keysJsonPath(String baseDir) {
        return baseDir + "/PKI/CTLOG/modpkica_ct_list.json";
    }

    /** 请求日志文件路径。 */
    public static String logsTxtPath(String baseDir) {
        return baseDir + "/PKI/CTLOG/ctlogs.txt";
    }

    /** 可信公网 CT 日志列表文件路径（Google CT log list v3）。 */
    public static String publicListPath(String baseDir) {
        return baseDir + "/PKI/CTLOG/log_list.json";
    }

    /** 公网 CT 日志列表的远程地址。 */
    public static final String PUBLIC_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json";

    /** 公网 CT 日志单条记录（只读参考数据，不含密钥）。 */
    public static final class PubLog {
        public String description = "";
        public String logIdHex = "";   // log_id base64 -> hex（SHA-256(公钥 SPKI)）
        public String state = "";      // usable / readonly / retired / pending / rejected
        public String url = "";
    }

    /**
     * 读取可信公网 CT 日志列表（log_list.json，Google log_list v3）。
     * 文件不存在返回空列表；state 为对象形式 {@code {"usable": {...}}} 时提取键名。
     * P2-12：改用 MiniJson DOM 解析（替代脆弱的正则提取）。
     */
    public static synchronized List<PubLog> loadPublicList(String baseDir) {
        List<PubLog> out = new ArrayList<>();
        Path p = Paths.get(publicListPath(baseDir));
        if (!Files.exists(p)) {
            return out;
        }
        try {
            String json = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
            Map<String, Object> root = MiniJson.parse(json);
            java.util.List<Map<String, Object>> logs = MiniJson.collectLogs(root);
            if (!logs.isEmpty()) {
                for (Map<String, Object> lo : logs) {
                    PubLog k = new PubLog();
                    k.description = MiniJson.strVal(lo.get("description"));
                    k.url = MiniJson.strVal(lo.get("url"));
                    String b64 = MiniJson.strVal(lo.get("log_id"));
                    if (b64 != null && !b64.isEmpty()) {
                        try {
                            byte[] raw = Base64.getDecoder().decode(b64);
                            StringBuilder sb = new StringBuilder();
                            for (byte b : raw) {
                                sb.append(String.format("%02x", b & 0xff));
                            }
                            k.logIdHex = sb.toString();
                        } catch (Exception ex) {
                            k.logIdHex = b64;
                        }
                    }
                    Object st = lo.get("state");
                    if (st instanceof Map) {
                        for (Object key : ((Map<?, ?>) st).keySet()) {
                            k.state = String.valueOf(key);
                            break;
                        }
                    } else {
                        k.state = MiniJson.strVal(st);
                    }
                    if (!k.logIdHex.isEmpty()) {
                        out.add(k);
                    }
                }
            }
        } catch (Exception e) {
            MLog.appendErr(baseDir, "CT公网日志列表读取异常", publicListPath(baseDir), String.valueOf(e));
        }
        return out;
    }

    /** 读取 log_list.json 的数据日期（log_list_timestamp）。文件不存在返回空串。 */
    public static synchronized String publicListTimestamp(String baseDir) {
        Path p = Paths.get(publicListPath(baseDir));
        if (!Files.exists(p)) {
            return "";
        }
        try {
            String json = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
            Object ts = MiniJson.parse(json).get("log_list_timestamp");
            String v = MiniJson.strVal(ts);
            return v == null ? "" : v;
        } catch (Exception e) {
            return "";
        }
    }

    /** 从 gstatic 拉取最新 log_list.json 并保存到 PKI/CTLOG/log_list.json。返回结果描述。 */
    public static synchronized String fetchPublicList(String baseDir) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new java.net.URI(PUBLIC_LIST_URL).toURL().openConnection();
        c.setConnectTimeout(15000);
        c.setReadTimeout(30000);
        c.setRequestMethod("GET");
        c.setRequestProperty("User-Agent", "MODPKICA/1.0 (CT log_list fetcher)");
        c.setRequestProperty("Accept", "application/json");
        int code = c.getResponseCode();
        if (code != 200) {
            c.disconnect();
            throw new IOException("远程返回 HTTP " + code);
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (InputStream in = c.getInputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                bos.write(buf, 0, n);
            }
        }
        c.disconnect();
        byte[] data = bos.toByteArray();
        String txt = new String(data, StandardCharsets.UTF_8);
        if (!txt.contains("log_list_timestamp") || !txt.contains("\"log_id\"")) {
            throw new IOException("返回内容不是有效的 CT log_list v3 JSON");
        }
        Path p = Paths.get(publicListPath(baseDir));
        Files.createDirectories(p.getParent());
        Files.write(p, data);
        String ts = publicListTimestamp(baseDir);
        MLog.append(baseDir, "CTLog拉取公网日志列表", PUBLIC_LIST_URL,
                "已保存 " + data.length + " 字节，数据日期 " + ts);
        return "已保存 " + data.length + " 字节，数据日期 " + ts;
    }

    /** 单条日志密钥对（含私钥，仅本地使用）。 */
    public static final class LogKey {
        public String description = "";
        public String logId = "";       // base64：SHA-256(公钥 SPKI DER)
        public String key = "";         // base64：公钥 SPKI DER
        public String privateKey = "";  // base64：PKCS#8 私钥（本地签名用）
        public String state = "usable"; // usable / disable
        public String type = "ECDSA";   // ECDSA / RSA / SM2
        public String url = "";
        public String created = "";
    }

    // ============================================================
    // 密钥库读写（modpkica_ct_list.json，v3 风格）
    // ============================================================

    /** 读取全部日志密钥对。文件不存在返回空列表。P2-12：MiniJson DOM 解析。 */
    public static synchronized List<LogKey> loadKeys(String baseDir) {
        List<LogKey> out = new ArrayList<>();
        Path p = Paths.get(keysJsonPath(baseDir));
        if (!Files.exists(p)) {
            return out;
        }
        try {
            String json = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
            Map<String, Object> root = MiniJson.parse(json);
            java.util.List<Map<String, Object>> logs = MiniJson.collectLogs(root);
            if (!logs.isEmpty()) {
                for (Map<String, Object> lo : logs) {
                    LogKey k = new LogKey();
                    k.logId = MiniJson.strVal(lo.get("log_id"));
                    k.description = MiniJson.strVal(lo.get("description"));
                    k.key = MiniJson.strVal(lo.get("key"));
                    k.privateKey = MiniJson.strVal(lo.get("private_key"));
                    String st = MiniJson.strVal(lo.get("state"));
                    k.state = (st == null || st.isEmpty()) ? "usable" : st;
                    String ty = MiniJson.strVal(lo.get("type"));
                    k.type = (ty == null || ty.isEmpty()) ? "ECDSA" : ty;
                    k.url = MiniJson.strVal(lo.get("url"));
                    k.created = MiniJson.strVal(lo.get("created"));
                    if (k.key != null && !k.key.isEmpty()) {
                        out.add(k);
                    }
                }
            }
        } catch (Exception e) {
            MLog.appendErr(baseDir, "CTLog密钥库读取异常", keysJsonPath(baseDir), String.valueOf(e));
        }
        return out;
    }

    /** 极简 JSON DOM 解析器（P2-12：替代脆弱的正则提取，支持对象/数组/字符串转义）。
     *  仅供本项目离线环境使用，无外部依赖。 */
    static final class MiniJson {
        static Map<String, Object> parse(String s) throws Exception {
            if (s == null) {
                throw new IllegalArgumentException("JSON 为空");
            }
            Ctx c = new Ctx(s);
            Object v = c.value();
            if (!(v instanceof Map)) {
                throw new IllegalArgumentException("JSON 顶层必须是对象");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) v;
            return m;
        }

        static String strVal(Object o) {
            return o == null ? null : String.valueOf(o);
        }

        /** 递归收集 JSON 树中所有日志对象（兼容顶层 logs 与 operators[].logs 两种 v3 结构）。 */
        static java.util.List<Map<String, Object>> collectLogs(Object node) {
            java.util.List<Map<String, Object>> out = new ArrayList<>();
            if (node instanceof Map) {
                Map<?, ?> m = (Map<?, ?>) node;
                if (m.containsKey("log_id") || m.containsKey("key") || m.containsKey("description")) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> asLog = (Map<String, Object>) m;
                    out.add(asLog);
                }
                for (Object v : m.values()) {
                    out.addAll(collectLogs(v));
                }
            } else if (node instanceof List) {
                for (Object o : (List<?>) node) {
                    out.addAll(collectLogs(o));
                }
            }
            return out;
        }

        private static final class Ctx {
            final String s;
            int i;

            Ctx(String s) {
                this.s = s;
            }

            void ws() {
                while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                    i++;
                }
            }

            Object value() throws Exception {
                ws();
                if (i >= s.length()) {
                    throw new IllegalArgumentException("JSON 意外结尾");
                }
                char c = s.charAt(i);
                if (c == '{') {
                    return obj();
                }
                if (c == '[') {
                    return arr();
                }
                if (c == '"') {
                    return str();
                }
                if (c == 't') {
                    expect("true");
                    return Boolean.TRUE;
                }
                if (c == 'f') {
                    expect("false");
                    return Boolean.FALSE;
                }
                if (c == 'n') {
                    expect("null");
                    return null;
                }
                return num();
            }

            Map<String, Object> obj() throws Exception {
                Map<String, Object> m = new java.util.LinkedHashMap<>();
                i++;
                ws();
                if (i < s.length() && s.charAt(i) == '}') {
                    i++;
                    return m;
                }
                while (true) {
                    ws();
                    if (i >= s.length() || s.charAt(i) != '"') {
                        throw new IllegalArgumentException("JSON 对象键应为字符串");
                    }
                    String key = str();
                    ws();
                    if (i >= s.length() || s.charAt(i) != ':') {
                        throw new IllegalArgumentException("JSON 缺冒号");
                    }
                    i++;
                    m.put(key, value());
                    ws();
                    if (i >= s.length()) {
                        throw new IllegalArgumentException("JSON 对象未闭合");
                    }
                    char c = s.charAt(i);
                    if (c == ',') {
                        i++;
                        continue;
                    }
                    if (c == '}') {
                        i++;
                        return m;
                    }
                    throw new IllegalArgumentException("JSON 对象分隔符错误: " + c);
                }
            }

            List<Object> arr() throws Exception {
                List<Object> l = new ArrayList<>();
                i++;
                ws();
                if (i < s.length() && s.charAt(i) == ']') {
                    i++;
                    return l;
                }
                while (true) {
                    l.add(value());
                    ws();
                    if (i >= s.length()) {
                        throw new IllegalArgumentException("JSON 数组未闭合");
                    }
                    char c = s.charAt(i);
                    if (c == ',') {
                        i++;
                        continue;
                    }
                    if (c == ']') {
                        i++;
                        return l;
                    }
                    throw new IllegalArgumentException("JSON 数组分隔符错误: " + c);
                }
            }

            String str() throws Exception {
                if (s.charAt(i) != '"') {
                    throw new IllegalArgumentException("JSON 应为字符串");
                }
                i++;
                StringBuilder sb = new StringBuilder();
                while (true) {
                    if (i >= s.length()) {
                        throw new IllegalArgumentException("JSON 字符串未闭合");
                    }
                    char c = s.charAt(i++);
                    if (c == '"') {
                        return sb.toString();
                    }
                    if (c == '\\') {
                        if (i >= s.length()) {
                            throw new IllegalArgumentException("JSON 转义未闭合");
                        }
                        char e = s.charAt(i++);
                        switch (e) {
                            case '"': sb.append('"'); break;
                            case '\\': sb.append('\\'); break;
                            case '/': sb.append('/'); break;
                            case 'b': sb.append('\b'); break;
                            case 'f': sb.append('\f'); break;
                            case 'n': sb.append('\n'); break;
                            case 'r': sb.append('\r'); break;
                            case 't': sb.append('\t'); break;
                            case 'u': {
                                if (i + 4 > s.length()) {
                                    throw new IllegalArgumentException("JSON \\u 转义截断");
                                }
                                String h = s.substring(i, i + 4);
                                i += 4;
                                sb.append((char) Integer.parseInt(h, 16));
                                break;
                            }
                            default: throw new IllegalArgumentException("JSON 非法转义 \\" + e);
                        }
                    } else {
                        sb.append(c);
                    }
                }
            }

            Object num() throws Exception {
                int st = i;
                while (i < s.length() && (Character.isDigit(s.charAt(i))
                        || s.charAt(i) == '+' || s.charAt(i) == '-'
                        || s.charAt(i) == '.' || s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                    i++;
                }
                String t = s.substring(st, i);
                if (t.isEmpty()) {
                    throw new IllegalArgumentException("JSON 非法数字");
                }
                try {
                    return Long.parseLong(t);
                } catch (Exception ignore) {
                }
                try {
                    return Double.parseDouble(t);
                } catch (Exception e2) {
                    throw new IllegalArgumentException("JSON 非法数字: " + t);
                }
            }

            void expect(String w) throws Exception {
                if (!s.startsWith(w, i)) {
                    throw new IllegalArgumentException("JSON 非法字面量: " + w);
                }
                i += w.length();
            }
        }
    }

    /** 从 JSON 片段中提取字符串字段值。 */
    private static String grab(String seg, String field) {
        Pattern p = Pattern.compile(Pattern.quote(field) + "\\s*:\\s*\"([^\"]*)\"");
        Matcher m = p.matcher(seg);
        return m.find() ? m.group(1) : "";
    }

    /** 写回密钥库（v3 风格结构）。 */
    public static synchronized void saveKeys(String baseDir, List<LogKey> keys) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"operators\": [\n");
        sb.append("    {\n");
        sb.append("      \"name\": \"MODPKICA Local CT Log\",\n");
        sb.append("      \"logs\": [\n");
        for (int i = 0; i < keys.size(); i++) {
            LogKey k = keys.get(i);
            sb.append("        {\n");
            sb.append("          \"description\": \"").append(esc(k.description)).append("\",\n");
            sb.append("          \"log_id\": \"").append(k.logId).append("\",\n");
            sb.append("          \"key\": \"").append(k.key).append("\",\n");
            sb.append("          \"state\": \"").append(esc(k.state)).append("\",\n");
            sb.append("          \"type\": \"").append(esc(k.type)).append("\",\n");
            sb.append("          \"url\": \"").append(esc(k.url)).append("\",\n");
            sb.append("          \"created\": \"").append(esc(k.created)).append("\",\n");
            sb.append("          \"private_key\": \"").append(k.privateKey).append("\"\n");
            sb.append("        }").append(i < keys.size() - 1 ? "," : "").append("\n");
        }
        sb.append("      ]\n");
        sb.append("    }\n");
        sb.append("  ]\n");
        sb.append("}\n");
        Path p = Paths.get(keysJsonPath(baseDir));
        if (p.getParent() != null && !Files.exists(p.getParent())) {
            Files.createDirectories(p.getParent());
        }
        Files.write(p, sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    /** JSON 字符串转义：反斜杠/引号之外，控制字符（\n \r \t 及其它 <0x20）也必须转义，
     *  否则密钥库 modpkica_ct_list.json 会被"描述"里的换行写成非法 JSON，整库读取失败。 */
    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
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

    // ============================================================
    // 密钥操作：生成 / 删除 / 启用 / 暂停
    // ============================================================

    /** 生成日志密钥对并追加写入密钥库（type：ECDSA-P256 / RSA-2048 / SM2-P256）。返回新密钥。 */
    public static synchronized LogKey generateKey(String baseDir, String desc, String type)
            throws Exception {
        String t = type == null || type.isEmpty() ? "ECDSA" : type;
        KeyPair kp;
        if ("RSA".equalsIgnoreCase(t)) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(2048);
            kp = kpg.generateKeyPair();
        } else if ("SM2".equalsIgnoreCase(t)) {
            t = "SM2";
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
            kpg.initialize(new java.security.spec.ECGenParameterSpec("sm2p256v1"));
            kp = kpg.generateKeyPair();
        } else {
            t = "ECDSA";
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
            kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
            kp = kpg.generateKeyPair();
        }
        byte[] spki = kp.getPublic().getEncoded();
        byte[] pkcs8 = kp.getPrivate().getEncoded();
        byte[] logId = sha256(spki);

        LogKey k = new LogKey();
        k.description = desc == null || desc.isEmpty() ? "MODPKICA CT Log " + t : desc;
        k.logId = Base64.getEncoder().encodeToString(logId);
        k.key = Base64.getEncoder().encodeToString(spki);
        k.privateKey = Base64.getEncoder().encodeToString(pkcs8);
        k.state = "usable";
        k.type = t;
        k.url = "http://localhost:80/ct/add";
        k.created = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        List<LogKey> keys = loadKeys(baseDir);
        keys.add(k);
        saveKeys(baseDir, keys);
        MLog.append(baseDir, "CTLog生成密钥",
                "描述=" + k.description + " 类型=" + t + " log_id=" + k.logId,
                "已写入 " + keysJsonPath(baseDir));
        return k;
    }

    /** 按 log_id 删除密钥对。返回是否删除成功。 */
    public static synchronized boolean deleteKey(String baseDir, String logIdB64) {
        List<LogKey> keys = loadKeys(baseDir);
        boolean removed = keys.removeIf(k -> k.logId.equals(logIdB64));
        if (removed) {
            try {
                saveKeys(baseDir, keys);
                MLog.append(baseDir, "CTLog删除密钥", "log_id=" + logIdB64, "已删除");
            } catch (Exception e) {
                MLog.appendErr(baseDir, "CTLog删除密钥异常", "log_id=" + logIdB64, String.valueOf(e));
                return false;
            }
        }
        return removed;
    }

    /** 设置密钥状态：usable（启用）/ disable（暂停）。 */
    public static synchronized boolean setState(String baseDir, String logIdB64, String state) {
        List<LogKey> keys = loadKeys(baseDir);
        boolean found = false;
        for (LogKey k : keys) {
            if (k.logId.equals(logIdB64)) {
                k.state = "usable".equalsIgnoreCase(state) ? "usable" : "disable";
                found = true;
                break;
            }
        }
        if (found) {
            try {
                saveKeys(baseDir, keys);
                MLog.append(baseDir, "CTLog设置密钥状态", "log_id=" + logIdB64
                        + " 状态=" + ("usable".equals(state) ? "usable" : "disable"), "OK");
            } catch (Exception e) {
                MLog.appendErr(baseDir, "CTLog设置状态异常", "log_id=" + logIdB64, String.valueOf(e));
                return false;
            }
        }
        return found;
    }

    // ============================================================
    // SCT 签发（RFC 6962 §3.1 / §3.2，precert_entry）
    // ============================================================

    /**
     * 按预证书类型随机选出参与 SCT 签名的日志密钥组（最多 3 组，仅 usable）：
     * SM2 预证书 → 只选 SM2 密钥；RSA/ECDSA 预证书 → 只选 RSA 或 ECDSA 密钥。
     */
    public static List<LogKey> pickLogKeys(String baseDir, boolean sm2Precert) {
        List<LogKey> keys = loadKeys(baseDir);
        List<LogKey> pool = new ArrayList<>();
        for (LogKey k : keys) {
            if (!"usable".equals(k.state) || k.privateKey.isEmpty()) {
                continue;
            }
            if (sm2Precert) {
                if ("SM2".equalsIgnoreCase(k.type)) {
                    pool.add(k);
                }
            } else if ("RSA".equalsIgnoreCase(k.type) || "ECDSA".equalsIgnoreCase(k.type)) {
                pool.add(k);
            }
        }
        Collections.shuffle(pool);
        return pool.size() > 3 ? new ArrayList<>(pool.subList(0, 3)) : pool;
    }

    /** 判断预证书是否 SM2 类型（签名算法 SM3withSM2，或公钥 named curve = SM2 曲线）。 */
    public static boolean isSm2Precert(X509Certificate cert) {
        try {
            String sigOid = cert.getSigAlgOID();
            if (sigOid != null && sigOid.startsWith("1.2.156.10197.1.501")) {
                return true;
            }
            // EC 公钥 SPKI 的算法 OID 固定为 id-ecPublicKey(1.2.840.10045.2.1)，
            // SM2 特性体现在 named curve 参数 OID：1.2.156.10197.1.301（sm2p256v1）
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
                    cert.getPublicKey().getEncoded());
            ASN1ObjectIdentifier curveOid = null;
            ASN1Encodable params = spki.getAlgorithm().getParameters();
            if (params != null) {
                ASN1Primitive p = params.toASN1Primitive();
                if (p instanceof ASN1Sequence) {
                    ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(
                            ((ASN1Sequence) p).getObjectAt(0));
                    curveOid = oid;
                } else if (p instanceof ASN1ObjectIdentifier) {
                    curveOid = (ASN1ObjectIdentifier) p;
                }
            }
            return curveOid != null && curveOid.getId().startsWith("1.2.156.10197.1.301");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 用选定的一组日志密钥对同一 precert 签发 SCT，组装 SCTList（TLS 编码）。
     *
     * @param baseDir        MODPKICA 根目录
     * @param tbsNoPoison    预证书 TBS 删除 poison 扩展后的 DER（RFC 6962 §3.1）
     * @param issuerKeyHash  颁发者公钥 SPKI 的 SHA-256（32 字节）
     * @param pool           本次参与签名的日志密钥（usable、类型匹配、≤3）
     * @return SCTList 字节（可直接作为 1.3.6.1.4.1.11129.2.4.2 扩展的 OCTET STRING 内容）
     */
    public static byte[] signSctList(String baseDir, byte[] tbsNoPoison, byte[] issuerKeyHash,
            List<LogKey> pool) throws Exception {
        if (pool == null || pool.isEmpty()) {
            throw new IllegalStateException("没有 usable 且类型匹配的 CT 日志密钥，请先在「SCT服务管理」生成并启用密钥");
        }
        ByteArrayOutputStream list = new ByteArrayOutputStream();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        int total = 0;
        for (LogKey k : pool) {
            long ts = System.currentTimeMillis();
            byte[] input = buildSctInput(ts, tbsNoPoison, issuerKeyHash);
            byte[] sig = signInput(Base64.getDecoder().decode(k.privateKey), input, k.type);
            byte[] sct = buildSerializedSct(k.logId, ts, sig, k.type);
            body.write((sct.length >> 8) & 0xff);
            body.write(sct.length & 0xff);
            body.write(sct, 0, sct.length);
            total += sct.length + 2;
        }
        list.write((total >> 8) & 0xff);
        list.write(total & 0xff);
        list.write(body.toByteArray());
        return list.toByteArray();
    }

    /** 构造 RFC 6962 §3.2 签名输入（precert_entry）：TLS 编码。 */
    static byte[] buildSctInput(long ts, byte[] tbsNoPoison, byte[] issuerKeyHash) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(0);                                  // sct_version = v1
        bos.write(0);                                  // signature_type = certificate_timestamp
        writeU64(bos, ts);
        writeU16(bos, 1);                              // entry_type = precert_entry
        bos.write(issuerKeyHash, 0, 32);               // issuer_key_hash
        writeU24(bos, tbsNoPoison.length);
        bos.write(tbsNoPoison, 0, tbsNoPoison.length); // tbs_certificate（去 poison）
        writeU16(bos, 0);                              // CtExtensions（空）
        return bos.toByteArray();
    }

    /** 按日志密钥类型对输入签名：ECDSA=SHA256withECDSA、RSA=SHA256withRSA、SM2=SM3withSM2。 */
    static byte[] signInput(byte[] pkcs8, byte[] input, String type) throws Exception {
        boolean rsa = "RSA".equalsIgnoreCase(type);
        java.security.KeyFactory kf = java.security.KeyFactory.getInstance(
                rsa ? "RSA" : "EC", "BC");
        java.security.PrivateKey priv = kf.generatePrivate(
                new java.security.spec.PKCS8EncodedKeySpec(pkcs8));
        String alg = rsa ? "SHA256withRSA"
                : "SM2".equalsIgnoreCase(type) ? "SM3withSM2" : "SHA256withECDSA";
        Signature sig = Signature.getInstance(alg, "BC");
        sig.initSign(priv);
        sig.update(input);
        return sig.sign();
    }

    /** 组装 SerializedSCT（RFC 6962 §3.2）：version + log_id + ts + ext + hash/sig 枚举 + 签名。
     *  ECDSA→SHA256/ECDSA(4,3)；RSA→SHA256/RSA(4,1)；SM2→SM3/SM2(7,4，国密 CT 实现枚举，对齐零信 sm2ct.cn)。 */
    static byte[] buildSerializedSct(String logIdB64, long ts, byte[] signature, String type) {
        byte[] logId = Base64.getDecoder().decode(logIdB64);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0);                                   // version = v1
        out.write(logId, 0, 32);                        // log_id
        writeU64(out, ts);                              // timestamp
        writeU16(out, 0);                               // extensions（空）
        if ("SM2".equalsIgnoreCase(type)) {
            out.write(7);                               // hash = SM3
            out.write(4);                               // sig = SM2（国密 CT 实现枚举，对齐零信 sm2ct.cn）
        } else if ("RSA".equalsIgnoreCase(type)) {
            out.write(4);                               // hash = SHA-256
            out.write(1);                               // sig = RSA
        } else {
            out.write(4);                               // hash = SHA-256
            out.write(3);                               // sig = ECDSA
        }
        writeU16(out, signature.length);
        out.write(signature, 0, signature.length);
        return out.toByteArray();
    }

    // ============================================================
    // 提交预证书到自身 CT 日志服务
    // ============================================================

    /**
     * 读取 CONFIG.txt 的 CTLOGapi 参数（大小写不敏感），决定签发证书时向 CT 日志
     * 服务提交预证书所用的接口。缺省或非法值回退 {@code /ct/add}。
     */
    public static String readCtlogApi(String baseDir) {
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
                    if (t.substring(0, idx).trim().equalsIgnoreCase("CTLOGapi")) {
                        String v = t.substring(idx + 1).trim();
                        if (v.equals("/ct/add") || v.equals("/ct/v1/add-chain")
                                || v.equals("/ct/v1/add-pre-chain")) {
                            return v;
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return "/ct/add";
    }

    /**
     * 将 PEM 预证书 + PEM 颁发者证书提交到自身 MAIN CT 日志服务，返回 SCTList
     * （二进制，直接作为 1.3.6.1.4.1.11129.2.4.2 扩展值）。
     * <p>提交接口由 CONFIG.txt {@code CTLOGapi} 决定：
     * <ul>
     *   <li>{@code /ct/add}（默认）：PEM 预证书 + PEM 颁发者，text/plain，响应=SCTList 二进制；</li>
     *   <li>{@code /ct/v1/add-pre-chain}：RFC 6962 §4.2 JSON {@code {chain:[b64(预证书DER),b64(颁发者DER)]}}；</li>
     *   <li>{@code /ct/v1/add-chain}：RFC 6962 §4.1 JSON {@code {chain:[b64(去poison正式证书DER),b64(颁发者DER)]}}。</li>
     * </ul>
     * 后两者响应为 JSON，客户端主动请求 3 次（服务端每次换用不同 usable 日志密钥），
     * 按日志公钥 ID 去重后拼装 SCTList（最多 3 条，密钥池不足 3 组时按可用组数）。
     * MAIN 服务未启动（HTTP 失败）时回退本地签名，保证签发流程可用。
     */
    public static byte[] submitPrecert(String baseDir, X509CertificateHolder precert,
                                       X509Certificate issuerCert, java.security.PrivateKey issuerKey,
                                       String issuerAlgo, String hash, String port) throws Exception {
        String api = readCtlogApi(baseDir);
        String url;
        String body;
        String contentType;
        boolean v1Json = "/ct/v1/add-pre-chain".equalsIgnoreCase(api)
                || "/ct/v1/add-chain".equalsIgnoreCase(api);
        if ("/ct/v1/add-pre-chain".equalsIgnoreCase(api)) {
            url = "http://127.0.0.1:" + port + "/ct/v1/add-pre-chain";
            body = "{\"chain\":[\"" + Base64.getEncoder().encodeToString(precert.getEncoded())
                    + "\",\"" + Base64.getEncoder().encodeToString(issuerCert.getEncoded()) + "\"]}";
            contentType = "application/json";
        } else if ("/ct/v1/add-chain".equalsIgnoreCase(api)) {
            url = "http://127.0.0.1:" + port + "/ct/v1/add-chain";
            // RFC 6962 §4.1：add-chain 不接受含 poison 扩展的预证书；
            // 用颁发者私钥对"去 poison 的 TBS"重新签名，构造临时正式证书
            // （其 TBS 与最终证书 TBS 一致，链签名校验可通过，SCT 按 x509_entry 签发）
            X509Certificate pc = new JcaX509CertificateConverter().setProvider("BC")
                    .getCertificate(precert);
            byte[] tbs = tbsWithoutPoison(pc);
            ContentSigner signer = CertUtil.createContentSigner(issuerKey, issuerAlgo,
                    "SM2".equalsIgnoreCase(issuerAlgo) ? "sm3" : hash);
            java.io.OutputStream sos = signer.getOutputStream();
            sos.write(tbs);
            sos.close();
            org.bouncycastle.asn1.ASN1EncodableVector v = new org.bouncycastle.asn1.ASN1EncodableVector();
            v.add(org.bouncycastle.asn1.ASN1Primitive.fromByteArray(tbs));
            v.add(signer.getAlgorithmIdentifier());
            v.add(new org.bouncycastle.asn1.DERBitString(signer.getSignature()));
            X509CertificateHolder tmp = new X509CertificateHolder(
                    org.bouncycastle.asn1.x509.Certificate.getInstance(
                            new org.bouncycastle.asn1.DERSequence(v)));
            body = "{\"chain\":[\"" + Base64.getEncoder().encodeToString(tmp.getEncoded())
                    + "\",\"" + Base64.getEncoder().encodeToString(issuerCert.getEncoded()) + "\"]}";
            contentType = "application/json";
        } else {
            url = "http://127.0.0.1:" + port + "/ct/add";
            body = pemCert(precert.getEncoded()) + pemCert(issuerCert.getEncoded());
            contentType = "text/plain";
        }
        try {
            if (v1Json) {
                // 请求 3 次：服务端每次换用不同 usable 日志密钥（SM2 证书仅 SM2 密钥可用），
                // 按日志公钥 ID 去重后拼装 SCTList；密钥池不足 3 组时按可用组数嵌入。
                ByteArrayOutputStream acc = new ByteArrayOutputStream();
                int total = 0;
                java.util.Set<String> seen = new java.util.HashSet<>();
                String lastJson = null;
                for (int i = 0; i < 3; i++) {
                    String json = new String(
                            postAndRead(url, body, contentType, api, baseDir), StandardCharsets.UTF_8);
                    lastJson = json;
                    java.util.Map<String, Object> m = MiniJson.parse(json);
                    String id = m.get("id") == null ? "" : String.valueOf(m.get("id"));
                    if (!seen.add(id)) {
                        continue;   // 与已嵌入的日志重复 → 跳过（下一轮服务端自动换组）
                    }
                    byte[] one = sctListFromV1Json(json);
                    acc.write(one, 2, one.length - 2);
                    total += one.length - 2;
                }
                if (total == 0 && lastJson != null) {
                    // 密钥池仅 1 组时三次响应同组 → 至少嵌入 1 条
                    byte[] one = sctListFromV1Json(lastJson);
                    acc.write(one, 2, one.length - 2);
                    total += one.length - 2;
                }
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                out.write((total >> 8) & 0xff);
                out.write(total & 0xff);
                out.write(acc.toByteArray());
                return out.toByteArray();
            }
            return postAndRead(url, body, contentType, api, baseDir);
        } catch (Exception e) {
            // 本地回退：MAIN 未运行或连接失败时直接本地签名
            MLog.append(baseDir, "CTLog本地回退", "url=" + url + " 接口=" + api + " 错误=" + e.getMessage(),
                    "改用本地签名生成 SCT 列表");
            X509Certificate pc = new JcaX509CertificateConverter().setProvider("BC")
                    .getCertificate(precert);
            byte[] tbs = tbsWithoutPoison(pc);
            byte[] ikh = sha256(issuerCert.getPublicKey().getEncoded());
            return signSctList(baseDir, tbs, ikh, pickLogKeys(baseDir, isSm2Precert(pc)));
        }
    }

    /**
     * 保存提交的原始证书（DER→PEM）到 {@code PKI/CTLOG/crtRAW/}，
     * 文件名格式 {@code {序列号}_{毫秒时间戳}.crt}，便于审计 add-chain / add-pre-chain 的原始提交物。
     */
    public static void saveRawCert(String baseDir, byte[] der, long ts) throws Exception {
        java.nio.file.Path dir = java.nio.file.Paths.get(baseDir, "PKI", "CTLOG", "crtRAW");
        java.nio.file.Files.createDirectories(dir);
        X509CertificateHolder h = new X509CertificateHolder(der);
        String sn = h.getSerialNumber().toString(16);
        java.nio.file.Path out = dir.resolve(sn + "_" + ts + ".crt");
        java.nio.file.Files.write(out, pemCert(der).getBytes(StandardCharsets.UTF_8));
        MLog.append(baseDir, "CTLog保存原始证书", "接口原始证书", "文件=" + out.getFileName()
                + " 序列号=" + sn + " 时间戳=" + ts);
    }

    /** POST 一次 CT 日志接口并读取响应字节，记录操作日志。状态非 200 抛异常。 */
    private static byte[] postAndRead(String url, String body, String contentType,
            String api, String baseDir) throws Exception {
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection)
                java.net.URI.create(url).toURL().openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(20000);
        conn.setRequestProperty("Content-Type", contentType);
        try (java.io.OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }
        int code = conn.getResponseCode();
        java.io.InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
        byte[] resp;
        try (java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) {
                bos.write(buf, 0, n);
            }
            resp = bos.toByteArray();
        }
        if (code != 200) {
            throw new IOException("CT 日志服务 " + api + " 返回 " + code + ": "
                    + new String(resp, StandardCharsets.UTF_8));
        }
        MLog.append(baseDir, "CTLog提交预证书", "url=" + url + " 接口=" + api + " 长度=" + body.length() + "字节",
                "获取 SCT 列表 " + resp.length + "字节");
        return resp;
    }

    /**
     * 解析 /ct/v1/add-chain / add-pre-chain 的 JSON 响应，组装单条 SCTList
     * （TLS 编码：u16 总长 + u16 长度 + SerializedSCT，可直接作为证书扩展值）。
     */
    static byte[] sctListFromV1Json(String json) throws Exception {
        java.util.Map<String, Object> m = MiniJson.parse(json);
        String id = m.get("id") == null ? "" : String.valueOf(m.get("id"));
        long ts = Long.parseLong(String.valueOf(m.get("timestamp")));
        byte[] sig = Base64.getDecoder().decode(String.valueOf(m.get("signature")));
        String type = m.get("type") == null ? "ECDSA" : String.valueOf(m.get("type"));
        byte[] sct = buildSerializedSct(id, ts, sig, type);
        ByteArrayOutputStream list = new ByteArrayOutputStream();
        int len = sct.length + 2;
        list.write((len >> 8) & 0xff);
        list.write(len & 0xff);
        list.write((sct.length >> 8) & 0xff);
        list.write(sct.length & 0xff);
        list.write(sct, 0, sct.length);
        return list.toByteArray();
    }
    // ============================================================
    // 请求日志（ctlogs.txt，只追加）
    // ============================================================

    /**
     * 追加一行 CT 请求日志。行格式：
     * {@code SCT待签名数据SHA256 || 毫秒时间戳 || 使用者SKI || 颁发者AKI || 日志公钥ID(base64)}
     */
    public static synchronized void appendRequestLog(String baseDir, String line) {
        try {
            Path p = Paths.get(logsTxtPath(baseDir));
            if (p.getParent() != null && !Files.exists(p.getParent())) {
                Files.createDirectories(p.getParent());
            }
            // P2-11：轮转——超过 10MB 时归档为 ctlogs.old.txt（覆盖旧档，仅保留最近两份）
            if (Files.exists(p) && Files.size(p) > 10L * 1024 * 1024) {
                Path old = Paths.get(logsTxtPath(baseDir) + ".old");
                Files.move(p, old, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            Files.writeString(p, line + "\n", StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception ignored) {
            // 日志失败不中断业务
        }
    }

    /** 读取全部 CT 请求日志行（按行拆分，供 Web 面板只读展示）。 */
    public static List<String> readLogs(String baseDir) {
        List<String> out = new ArrayList<>();
        try {
            Path p = Paths.get(logsTxtPath(baseDir));
            if (Files.exists(p)) {
                String text = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                for (String line : text.split("\n", -1)) {
                    if (!line.trim().isEmpty()) {
                        out.add(line.trim());
                    }
                }
            }
        } catch (Exception e) {
            MLog.appendErr(baseDir, "CTLog日志读取异常", logsTxtPath(baseDir), String.valueOf(e));
        }
        return out;
    }

    // ============================================================
    // 工具
    // ============================================================

    /** 从 PEM 文本中解析全部证书（按块顺序）。 */
    public static List<X509Certificate> parsePemCerts(byte[] pemBytes) throws Exception {
        String text = new String(pemBytes, StandardCharsets.UTF_8);
        List<X509Certificate> out = new ArrayList<>();
        try (PemReader reader = new PemReader(new StringReader(text))) {
            PemObject po;
            while ((po = reader.readPemObject()) != null) {
                if ("CERTIFICATE".equals(po.getType())) {
                    X509CertificateHolder holder = new X509CertificateHolder(po.getContent());
                    out.add(new JcaX509CertificateConverter().setProvider("BC")
                            .getCertificate(holder));
                }
            }
        }
        if (out.isEmpty()) {
            // 兼容"非标准头"：手动正则提取
            Pattern p = Pattern.compile("-----BEGIN CERTIFICATE-----\\s*([A-Za-z0-9+/=\\r\\n]+?)-----END CERTIFICATE-----",
                    Pattern.DOTALL);
            Matcher m = p.matcher(text);
            while (m.find()) {
                byte[] der = Base64.getDecoder().decode(m.group(1).replaceAll("\\s", ""));
                out.add(new JcaX509CertificateConverter().setProvider("BC")
                        .getCertificate(new X509CertificateHolder(der)));
            }
        }
        return out;
    }

    /** 证书 PEM 序列化。 */
    public static String pemCert(byte[] der) {
        String b64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        sb.append("-----END CERTIFICATE-----\n");
        return sb.toString();
    }

    /** 从证书 TBS 中删除 poison 扩展（RFC 6962 §3.1），其余扩展原样保真。 */
    public static byte[] tbsWithoutPoison(X509Certificate cert) throws Exception {
        byte[] tbs = cert.getTBSCertificate();
        ASN1Sequence seq = ASN1Sequence.getInstance(tbs);
        ASN1EncodableVector v = new ASN1EncodableVector();
        boolean removed = false;
        for (int i = 0; i < seq.size(); i++) {
            Object el = seq.getObjectAt(i);
            if (el instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) el;
                if (tagged.getTagNo() == 3) {
                    ASN1Sequence extSeq = ASN1Sequence.getInstance(tagged, true);
                    ASN1EncodableVector newExts = new ASN1EncodableVector();
                    for (int j = 0; j < extSeq.size(); j++) {
                        Extension ext = Extension.getInstance(extSeq.getObjectAt(j));
                        if (!OID_POISON.equals(ext.getExtnId().getId())) {
                            newExts.add(ext);
                        } else {
                            removed = true;
                        }
                    }
                    v.add(new DERTaggedObject(true, 3, new DERSequence(newExts)));
                    continue;
                }
            }
            v.add((org.bouncycastle.asn1.ASN1Encodable) el);
        }
        // RFC 6962 SS3.1: a precertificate MUST carry the poison extension.
        if (!removed) {
            throw new IOException("precert is missing poison extension " + OID_POISON
                    + ", not a valid RFC 6962 precertificate");
        }
        return new DERSequence(v).getEncoded();
    }

    /** 证书扩展值（OCTET STRING 解壳后的内容）→ hex；无此扩展返回空串。 */
    public static String extHex(X509Certificate cert, String oid) {
        try {
            byte[] v = cert.getExtensionValue(oid);
            if (v == null) {
                return "";
            }
            ASN1Primitive p = ASN1Primitive.fromByteArray(v);
            DEROctetString os = (DEROctetString) p;
            return toHex(os.getOctets());
        } catch (Exception e) {
            return "";
        }
    }

    static byte[] sha256(byte[] b) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(b);
    }

    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x & 0xff));
        }
        return sb.toString();
    }

    static void writeU16(ByteArrayOutputStream bos, int v) {
        bos.write((v >>> 8) & 0xff);
        bos.write(v & 0xff);
    }

    static void writeU24(ByteArrayOutputStream bos, int v) {
        bos.write((v >>> 16) & 0xff);
        bos.write((v >>> 8) & 0xff);
        bos.write(v & 0xff);
    }

    static void writeU64(ByteArrayOutputStream bos, long v) {
        for (int i = 7; i >= 0; i--) {
            bos.write((int) ((v >>> (8 * i)) & 0xff));
        }
    }

    // ============================================================
    // RFC 6962 全套 HTTP API 支持（独立新增，不影响现有 /ct/add）
    //
    // 数据结构：每个日志密钥（log_id）维护一棵独立的 append-only Merkle 树，
    // 树文件 PKI/CTLOG/trees/{log_id_hex}.json 采用 JSON Lines 格式，
    // 每行一个条目 {"leaf_input":"base64(MerkleTreeLeaf)","extra_data":"base64"}，
    // 只追加不修改（RFC 6962 §3.4 append-only 属性）。
    // ============================================================

    /** 日志 Merkle 树文件路径（按 log_id 的 hex 命名，避免 base64 的 +/= 字符）。 */
    public static String treeFilePath(String baseDir, String logIdB64) {
        byte[] id;
        try {
            id = Base64.getDecoder().decode(logIdB64);
        } catch (Exception e) {
            id = logIdB64.getBytes(StandardCharsets.UTF_8);
        }
        return baseDir + "/PKI/CTLOG/trees/" + toHex(id) + ".json";
    }

    /** 树条目（leaf_input = MerkleTreeLeaf TLS 编码；extra_data = 证书链向量编码）。 */
    public static final class TreeEntry {
        public String leafInput = "";   // base64
        public String extraData = "";   // base64
    }

    /** 读取指定日志的 Merkle 树全部条目（JSON Lines，逐行解析）。 */
    public static synchronized List<TreeEntry> loadTreeEntries(String baseDir, String logIdB64) {
        List<TreeEntry> out = new ArrayList<>();
        Path p = Paths.get(treeFilePath(baseDir, logIdB64));
        if (!Files.exists(p)) {
            return out;
        }
        try {
            String text = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
            for (String line : text.split("\n", -1)) {
                String t = line.trim();
                if (t.isEmpty()) {
                    continue;
                }
                Map<String, Object> m = MiniJson.parse(t);
                TreeEntry e = new TreeEntry();
                e.leafInput = MiniJson.strVal(m.get("leaf_input"));
                e.extraData = MiniJson.strVal(m.get("extra_data"));
                if (e.leafInput != null && !e.leafInput.isEmpty()) {
                    out.add(e);
                }
            }
        } catch (Exception e) {
            MLog.appendErr(baseDir, "CTLog树读取异常", treeFilePath(baseDir, logIdB64), String.valueOf(e));
        }
        return out;
    }

    /** 向指定日志的 Merkle 树追加一个条目（JSON Lines 追加一行，O(1)）。 */
    public static synchronized void appendTreeEntry(String baseDir, String logIdB64,
            byte[] leafInput, byte[] extraData) {
        try {
            Path p = Paths.get(treeFilePath(baseDir, logIdB64));
            if (p.getParent() != null && !Files.exists(p.getParent())) {
                Files.createDirectories(p.getParent());
            }
            String line = "{\"leaf_input\":\"" + Base64.getEncoder().encodeToString(leafInput)
                    + "\",\"extra_data\":\"" + (extraData == null ? "" : Base64.getEncoder().encodeToString(extraData))
                    + "\"}\n";
            Files.writeString(p, line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception e) {
            MLog.appendErr(baseDir, "CTLog树写入异常", treeFilePath(baseDir, logIdB64), String.valueOf(e));
        }
    }

    /**
     * 构造 x509_entry 的 MerkleTreeLeaf（RFC 6962 §3.4）与 extra_data。
     * chainDer：完整证书链 DER（[0]=叶子证书，其余为颁发者链）。
     * 返回 [leaf_input, extra_data]。
     */
    public static byte[][] buildX509LeafAndExtra(long ts, List<byte[]> chainDer) throws Exception {
        ByteArrayOutputStream leaf = new ByteArrayOutputStream();
        leaf.write(0);                                   // version = v1
        leaf.write(0);                                   // leaf_type = timestamped_entry
        writeU64(leaf, ts);                              // timestamp
        writeU16(leaf, 0);                               // entry_type = x509_entry
        byte[] tbs = tbsOf(chainDer.get(0));             // leaf_certificate = TBSCertificate（RFC 6962 §3.4）
        writeU24(leaf, tbs.length);
        leaf.write(tbs, 0, tbs.length);
        writeU16(leaf, 0);                               // CtExtensions（空）
        // extra_data = certificate_chain 向量（从颁发者开始，每证书 3 字节长度前缀）
        ByteArrayOutputStream extra = new ByteArrayOutputStream();
        for (int i = 1; i < chainDer.size(); i++) {
            byte[] c = chainDer.get(i);
            writeU24(extra, c.length);
            extra.write(c, 0, c.length);
        }
        return new byte[][] {leaf.toByteArray(), extra.toByteArray()};
    }

    /**
     * 构造 precert_entry 的 MerkleTreeLeaf（RFC 6962 §3.4）与 extra_data。
     * chainDer：完整链 DER（[0]=预证书，其余为颁发者链）。
     * 返回 [leaf_input, extra_data]。
     */
    public static byte[][] buildPrecertLeafAndExtra(long ts, byte[] issuerKeyHash,
            byte[] tbsNoPoison, List<byte[]> chainDer) {
        ByteArrayOutputStream leaf = new ByteArrayOutputStream();
        leaf.write(0);                                   // version = v1
        leaf.write(0);                                   // leaf_type = timestamped_entry
        writeU64(leaf, ts);                              // timestamp
        writeU16(leaf, 1);                               // entry_type = precert_entry
        leaf.write(issuerKeyHash, 0, 32);                // issuer_key_hash
        writeU24(leaf, tbsNoPoison.length);              // tbs_certificate（去 poison）
        leaf.write(tbsNoPoison, 0, tbsNoPoison.length);
        writeU16(leaf, 0);                               // CtExtensions（空）
        // extra_data = 整个 PrecertChainEntry（pre_certificate + precertificate_chain 向量）
        ByteArrayOutputStream extra = new ByteArrayOutputStream();
        byte[] pre = chainDer.get(0);
        writeU24(extra, pre.length);
        extra.write(pre, 0, pre.length);
        for (int i = 1; i < chainDer.size(); i++) {
            byte[] c = chainDer.get(i);
            writeU24(extra, c.length);
            extra.write(c, 0, c.length);
        }
        return new byte[][] {leaf.toByteArray(), extra.toByteArray()};
    }

    /** MerkleTreeLeaf 的叶子哈希 = SHA-256(0x00 || leaf_input)（RFC 6962 §3.4）。 */
    public static byte[] leafHash(byte[] leafInput) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(0);
        b.write(leafInput, 0, leafInput.length);
        return sha256(b.toByteArray());
    }

    /** 计算 D[start,end) 的 Merkle Tree Hash（RFC 6962 §3.4.1，k = 小于区间长的最大 2 的幂）。 */
    static byte[] mthNode(List<byte[]> hashes, int start, int end) throws Exception {
        if (end - start == 1) {
            return hashes.get(start);
        }
        int k = Integer.highestOneBit(end - start - 1);
        byte[] l = mthNode(hashes, start, start + k);
        byte[] r = mthNode(hashes, start + k, end);
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(1);
        b.write(l, 0, 32);
        b.write(r, 0, 32);
        return sha256(b.toByteArray());
    }

    /** 整棵树根哈希 MTH(D[0:n])；空树返回 32 字节全零。 */
    public static byte[] mthRoot(List<byte[]> hashes) throws Exception {
        if (hashes.isEmpty()) {
            return new byte[32];
        }
        return mthNode(hashes, 0, hashes.size());
    }

    /** 叶子索引 m 的 Merkle 审计路径（RFC 6962 §3.4.2，顺序：近叶 → 近根）。 */
    public static List<byte[]> auditPath(List<byte[]> hashes, int m) throws Exception {
        List<byte[]> out = new ArrayList<>();
        pathNode(hashes, m, 0, hashes.size(), out);
        return out;
    }

    static void pathNode(List<byte[]> hashes, int m, int start, int end, List<byte[]> out)
            throws Exception {
        if (end - start == 1) {
            return;
        }
        int k = Integer.highestOneBit(end - start - 1);
        if (m - start < k) {
            out.add(mthNode(hashes, start + k, end));
            pathNode(hashes, m, start, start + k, out);
        } else {
            out.add(mthNode(hashes, start, start + k));
            pathNode(hashes, m, start + k, end, out);
        }
    }

    /**
     * 两棵树头之间的一致性证明（RFC 6962 §3.4.3 CONSISTENCY_PROOF）。
     * hashes：当前树（size=second）的全部叶子哈希；first/second 为两个 tree_size（first<second）。
     */
    public static List<byte[]> consistencyProof(List<byte[]> hashes, int first, int second)
            throws Exception {
        List<byte[]> out = new ArrayList<>();
        consNode(hashes, 0, second, first, out);
        return out;
    }

    static void consNode(List<byte[]> hashes, int start, int end, int m, List<byte[]> out)
            throws Exception {
        // m == 0：空树到任意树的一致性证明为空（Google CT API 对 first=0 返回 []）；
        // m == end - start：前缀即整棵子树，证明为空。
        if (m == 0 || m == end - start) {
            return;
        }
        int k = Integer.highestOneBit(end - start - 1);
        if (m <= k) {
            out.add(mthNode(hashes, start + k, end));
            consNode(hashes, start, start + k, m, out);
        } else {
            out.add(mthNode(hashes, start, start + k));
            consNode(hashes, start + k, end, m - k, out);
        }
    }

    /**
     * TreeHeadSignature（RFC 6962 §3.5）：version(0) + signature_type=tree_hash(1) + timestamp(8)
     * + root_hash(32)，用日志密钥签名。
     */
    public static byte[] treeHeadSignature(LogKey k, long ts, byte[] rootHash) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(0);                                     // version = v1
        b.write(1);                                     // signature_type = tree_hash
        writeU64(b, ts);                                // timestamp
        b.write(rootHash, 0, 32);                       // MerkleTreeHash
        return signInput(Base64.getDecoder().decode(k.privateKey), b.toByteArray(), k.type);
    }

    /** RFC 6962 §3.2 SCT 签名输入（x509_entry 版：signed_entry = 叶子证书 TBSCertificate 的 DER）。 */
    public static byte[] buildSctInputX509(long ts, byte[] leafTbsDer) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(0);                                  // sct_version = v1
        bos.write(0);                                  // signature_type = certificate_timestamp
        writeU64(bos, ts);
        writeU16(bos, 0);                              // entry_type = x509_entry
        writeU24(bos, leafTbsDer.length);
        bos.write(leafTbsDer, 0, leafTbsDer.length);
        writeU16(bos, 0);                              // CtExtensions（空）
        return bos.toByteArray();
    }

    /** 提取证书 DER 的 TBSCertificate（RFC 6962 x509_entry 的 signed_entry 用）。 */
    public static byte[] tbsOf(byte[] certDer) throws Exception {
        return new X509CertificateHolder(certDer).getTBSCertificate().getEncoded();
    }

    /** 单条 SCT 签发结果（RFC 6962 §4.1/§4.2 响应用）。 */
    public static final class SctOutcome {
        public String logId = "";       // base64（= 日志密钥 log_id）
        public long timestamp;
        public byte[] sct;              // SerializedSCT 全量
        public byte[] signature;        // 原始签名（响应 JSON 的 signature 字段）
    }

    /**
     * 用单个日志密钥签发 SCT（RFC 6962 §4.1/§4.2 add-chain/add-pre-chain 语义），
     * 并把 MerkleTreeLeaf 追加到该日志的 Merkle 树（leaf 与 SCT 使用同一 timestamp）。
     *
     * @param entryType     0=x509_entry（add-chain），1=precert_entry（add-pre-chain）
     * @param tbsNoPoison   预证书 TBS 去 poison 后的 DER（仅 precert_entry 需要）
     * @param issuerKeyHash 颁发者公钥 SPKI 的 SHA-256（仅 precert_entry 需要）
     * @param chainDer      完整链 DER（[0]=叶子证书/预证书，其余为颁发者链）
     */
    public static SctOutcome signOneSct(String baseDir, LogKey k, int entryType, long ts,
            byte[] tbsNoPoison, byte[] issuerKeyHash, List<byte[]> chainDer) throws Exception {
        byte[] input = (entryType == 0)
                ? buildSctInputX509(ts, tbsOf(chainDer.get(0)))
                : buildSctInput(ts, tbsNoPoison, issuerKeyHash);
        byte[] sig = signInput(Base64.getDecoder().decode(k.privateKey), input, k.type);
        byte[] sct = buildSerializedSct(k.logId, ts, sig, k.type);
        byte[][] leafExtra = (entryType == 0)
                ? buildX509LeafAndExtra(ts, chainDer)
                : buildPrecertLeafAndExtra(ts, issuerKeyHash, tbsNoPoison, chainDer);
        appendTreeEntry(baseDir, k.logId, leafExtra[0], leafExtra[1]);
        SctOutcome o = new SctOutcome();
        o.logId = k.logId;
        o.timestamp = ts;
        o.sct = sct;
        o.signature = sig;
        return o;
    }

    /** 从 MerkleTreeLeaf 解析 timestamp（version+leaf_type 各 1 字节后的 8 字节大端）。 */
    public static long treeEntryTimestamp(byte[] leafInput) {
        long ts = 0;
        for (int i = 2; i < 10 && i < leafInput.length; i++) {
            ts = (ts << 8) | (leafInput[i] & 0xff);
        }
        return ts;
    }

    /** base64 → hex。 */
    public static String b64ToHex(String b64) {
        try {
            return toHex(Base64.getDecoder().decode(b64));
        } catch (Exception e) {
            return "";
        }
    }

    // ==================== RFC 6962 树分析（仪表盘 / 调试区专用，v1.28-r3 新增） ====================

    /** 从 MerkleTreeLeaf 解析 LogEntryType（[10..12) 大端 u16）：0=x509_entry，1=precert_entry。 */
    public static int parseLeafEntryType(byte[] leafInput) {
        if (leafInput == null || leafInput.length < 12) {
            return -1;
        }
        return ((leafInput[10] & 0xff) << 8) | (leafInput[11] & 0xff);
    }

    /**
     * 从 x509_entry 的 MerkleTreeLeaf 解析叶子证书 DER（leaf_certificate 字段）。
     * 布局：[0]version [1]leaf_type [2..10)ts [10..12)entry_type [12..15)cert_len(u24) [15..)cert [..)extensions(u16)
     * （RFC 6962 §3.4：x509_entry 的 signed_entry = ASN.1Cert，无 cert_type 字节）
     */
    public static byte[] leafCertFromLeafInput(byte[] leafInput) {
        if (leafInput == null || leafInput.length < 17 || parseLeafEntryType(leafInput) != 0) {
            return null;
        }
        int len = ((leafInput[12] & 0xff) << 16) | ((leafInput[13] & 0xff) << 8) | (leafInput[14] & 0xff);
        if (len < 1 || 15 + len > leafInput.length) {
            return null;
        }
        return java.util.Arrays.copyOfRange(leafInput, 15, 15 + len);
    }

    /** 从 extra_data（ASN.1Cert 向量：u24 长度前缀 + DER）解析首个证书 DER。 */
    public static byte[] extraDataFirstCert(byte[] extraData) {
        if (extraData == null || extraData.length < 3) {
            return null;
        }
        int len = ((extraData[0] & 0xff) << 16) | ((extraData[1] & 0xff) << 8) | (extraData[2] & 0xff);
        if (len < 1 || 3 + len > extraData.length) {
            return null;
        }
        return java.util.Arrays.copyOfRange(extraData, 3, 3 + len);
    }

    /** 从 extra_data 解析全部证书 DER（u24 长度前缀序列）。 */
    public static List<byte[]> extraDataCerts(byte[] extraData) {
        List<byte[]> out = new ArrayList<>();
        if (extraData == null) {
            return out;
        }
        int off = 0;
        while (off + 3 <= extraData.length) {
            int len = ((extraData[off] & 0xff) << 16) | ((extraData[off + 1] & 0xff) << 8) | (extraData[off + 2] & 0xff);
            if (len < 1 || off + 3 + len > extraData.length) {
                break;
            }
            out.add(java.util.Arrays.copyOfRange(extraData, off + 3, off + 3 + len));
            off += 3 + len;
        }
        return out;
    }

    /** MTH 内部节点（Merkle 树结构节点，不含叶子层）。 */
    public static final class MthNode {
        public int level;   // 0 = 根，越大越深
        public int start;   // 叶子区间起点（含）
        public int end;     // 叶子区间终点（不含）
        public byte[] hash;
    }

    /** 计算整棵 Merkle 树的全部内部节点（RFC 6962 §3.4.1 MTH，自顶向下枚举）。 */
    public static List<MthNode> computeMthNodes(List<byte[]> leafHashes) throws Exception {
        List<MthNode> out = new ArrayList<>();
        if (leafHashes == null || leafHashes.isEmpty()) {
            return out;
        }
        collectMth(leafHashes, 0, leafHashes.size(), 0, out);
        return out;
    }

    private static byte[] collectMth(List<byte[]> leafHashes, int start, int end, int level,
            List<MthNode> out) throws Exception {
        int n = end - start;
        if (n == 1) {
            return leafHashes.get(start);
        }
        int k = Integer.highestOneBit(n - 1);
        byte[] left = collectMth(leafHashes, start, start + k, level + 1, out);
        byte[] right = collectMth(leafHashes, start + k, end, level + 1, out);
        byte[] node = sha256(concat(new byte[]{0x01}, left, right));
        out.add(new MthNode());
        MthNode nd = out.get(out.size() - 1);
        nd.level = level;
        nd.start = start;
        nd.end = end;
        nd.hash = node;
        return node;
    }

    private static byte[] concat(byte[] a, byte[] b, byte[] c) {
        byte[] r = new byte[a.length + b.length + c.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        System.arraycopy(c, 0, r, a.length + b.length, c.length);
        return r;
    }
}
