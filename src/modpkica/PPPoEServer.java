package modpkica;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * PPPoE 服务器 + 客户端拨号模拟器（RFC 2516 + PPP LCP/PAP/CHAP）。
 *
 * 说明：JVM 无法直接收发原始以太网帧，本实现采用 UDP 封装模拟标准 PPPoE 报文结构，
 * 供学习调试与拨号流程验证使用。UDP payload 结构：
 *   Discovery:  [0x88 0x63][PPPoE 头(6B)][标签区]
 *   Session:    [0x88 0x64][PPPoE 头(6B)][PPP 帧(ff 03 + 协议 + 信息)]
 * PPPoE 头: VER(4)|TYPE(4)=0x11, CODE(1), SESSION_ID(2), LENGTH(2)
 * 标签: TAG_TYPE(2) TAG_LENGTH(2) TAG_VALUE
 * 认证账号复用 PKI/USERS.txt（与 RADIUS 用户管理一致）。
 */
public class PPPoEServer {

    // ===== 常量 =====
    /** 默认 Discovery 端口（UDP，0x0200=512）。 */
    public static final int DEFAULT_DISC_PORT = 512;
    /** 默认 Session 端口（UDP 模拟）。 */
    public static final int DEFAULT_SESS_PORT = 513;
    public static final int MAX_LOG_ENTRIES = 500;
    /** AC 名称（Access Concentrator）。 */
    public static final String AC_NAME = "MODPKICA-PPPoE";

    // PPPoE 以太网类型
    private static final int ETYPE_DISC = 0x8863;
    private static final int ETYPE_SESS = 0x8864;
    // PPPoE Code
    private static final int CODE_PADI = 0x09, CODE_PADO = 0x07, CODE_PADR = 0x19,
            CODE_PADS = 0x65, CODE_PADT = 0xa7;
    // PPPoE Tag
    private static final int TAG_SERVICE_NAME = 0x0101, TAG_AC_NAME = 0x0102,
            TAG_HOST_UNIQ = 0x0103, TAG_AC_COOKIE = 0x0104, TAG_EOL = 0x0201;
    // PPP 协议
    private static final int PPP_LCP = 0xc021, PPP_PAP = 0xc023, PPP_CHAP = 0xc223;
    // LCP Code
    private static final int LCP_CONF_REQ = 1, LCP_CONF_ACK = 2, LCP_CONF_NAK = 3,
            LCP_CONF_REJ = 4, LCP_TERM_REQ = 5, LCP_TERM_ACK = 6;
    // PAP Code
    private static final int PAP_AUTH_REQ = 1, PAP_AUTH_ACK = 2, PAP_AUTH_NAK = 3;
    // CHAP Code
    private static final int CHAP_CHALLENGE = 1, CHAP_RESPONSE = 2, CHAP_SUCCESS = 3, CHAP_FAILURE = 4;
    // LCP 选项类型
    private static final int OPT_MRU = 0x01, OPT_AUTH_PROTO = 0x03, OPT_MAGIC = 0x05;

    // ===== 运行状态 =====
    private final String baseDir;
    private volatile boolean running;
    private volatile int discPort, sessPort;
    private DatagramSocket discSocket, sessSocket;
    private Thread discThread, sessThread;
    private volatile long startTime;
    private final AtomicLong totalAuth = new AtomicLong();
    private final AtomicLong okAuth = new AtomicLong();
    private final AtomicLong failAuth = new AtomicLong();
    private final AtomicInteger activeSessions = new AtomicInteger();
    /** addr:port -> sessionId */
    private final Map<String, Integer> sessions = new ConcurrentHashMap<>();
    /** addr:port -> 最近一次活动时刻（毫秒），用于空闲会话回收（无 PADT 的掉线客户端）。 */
    private final Map<String, Long> sessionLastSeen = new ConcurrentHashMap<>();
    /** 空闲会话超时（毫秒）：超过该时长无任何报文即回收，避免 sessions/计数无限增长。 */
    private static final long SESSION_IDLE_TIMEOUT_MS = 10 * 60_000L;
    /** addr:port -> CHAP challenge（byte[0]=id, byte[1..]=challenge value） */
    private final Map<String, byte[]> chapChallenges = new ConcurrentHashMap<>();
    private final Deque<LogEntry> logs = new ArrayDeque<>();
    private long logSeq = 0;

    /** 环形日志条目。 */
    public static final class LogEntry {
        public long id;
        public String time;
        public String message;
    }

    public PPPoEServer(String baseDir) {
        this.baseDir = baseDir == null ? "." : baseDir;
    }

    // ===== 日志 =====
    private synchronized void log(String msg) {
        LogEntry e = new LogEntry();
        e.id = ++logSeq;
        e.time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        e.message = msg;
        logs.addFirst(e);
        while (logs.size() > MAX_LOG_ENTRIES) {
            logs.removeLast();
        }
    }

    public synchronized List<LogEntry> logs(int n) {
        List<LogEntry> out = new ArrayList<>();
        int i = 0;
        for (LogEntry e : logs) {
            if (i++ >= n) {
                break;
            }
            out.add(e);
        }
        return out;
    }

    /** 清空环形日志。 */
    public synchronized void clearLogs() {
        logs.clear();
    }

    // ===== 状态 =====
    public boolean isRunning() {
        return running;
    }

    public Map<String, Object> statusJson() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("running", running);
        m.put("discPort", running ? discPort : DEFAULT_DISC_PORT);
        m.put("sessPort", running ? sessPort : DEFAULT_SESS_PORT);
        m.put("acName", AC_NAME);
        m.put("startTimeText", startTime > 0
                ? new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(startTime)) : "");
        m.put("totalAuth", totalAuth.get());
        m.put("authOk", okAuth.get());
        m.put("authFail", failAuth.get());
        m.put("activeSessions", activeSessions.get());
        m.put("accounts", UsersDB.load(baseDir).size());
        return m;
    }

    /** 启动服务器（端口<=0 用默认 512/513）。 */
    public String start(int disc, int sess) throws IOException {
        if (running) {
            return "PPPoE 服务已在运行";
        }
        discPort = disc > 0 ? disc : DEFAULT_DISC_PORT;
        sessPort = sess > 0 ? sess : DEFAULT_SESS_PORT;
        discSocket = new DatagramSocket(discPort);
        sessSocket = new DatagramSocket(sessPort);
        discSocket.setSoTimeout(500);
        sessSocket.setSoTimeout(500);
        running = true;
        startTime = System.currentTimeMillis();
        totalAuth.set(0);
        okAuth.set(0);
        failAuth.set(0);
        activeSessions.set(0);
        sessions.clear();
        chapChallenges.clear();
        discThread = new Thread(this::discLoop, "pppoe-disc");
        sessThread = new Thread(this::sessLoop, "pppoe-sess");
        discThread.setDaemon(true);
        sessThread.setDaemon(true);
        discThread.start();
        sessThread.start();
        log("PPPoE 服务器已启动，Discovery=UDP/" + discPort + "，Session=UDP/" + sessPort
                + "（RFC 2516，账号 PKI/USERS.txt，共 " + UsersDB.load(baseDir).size() + " 个）");
        log("正在等待 PADI 拨号请求...");
        return "PPPoE 服务已启动（Discovery/UDP " + discPort + "，Session/UDP " + sessPort + "）";
    }

    public void stop() {
        running = false;
        if (discSocket != null) {
            try {
                discSocket.close();
            } catch (Exception ignored) {
            }
        }
        if (sessSocket != null) {
            try {
                sessSocket.close();
            } catch (Exception ignored) {
            }
        }
        discSocket = null;
        sessSocket = null;
        log("PPPoE 服务已停止");
    }

    public void reset() {
        totalAuth.set(0);
        okAuth.set(0);
        failAuth.set(0);
        activeSessions.set(0);
        sessions.clear();
        chapChallenges.clear();
        log("PPPoE 统计已清零");
    }

    // ============================================================
    // Discovery 阶段（RFC 2516 §5）
    // ============================================================
    private void discLoop() {
        byte[] buf = new byte[2048];
        while (running) {
            try {
                DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                discSocket.receive(pkt);
                handleDiscovery(pkt);
            } catch (SocketTimeoutException ignored) {
            } catch (Exception e) {
                if (running) {
                    log("Discovery 接收异常: " + e.getMessage());
                }
            }
        }
    }

    private void handleDiscovery(DatagramPacket pkt) {
        byte[] data = Arrays.copyOfRange(pkt.getData(), pkt.getOffset(),
                pkt.getOffset() + pkt.getLength());
        if (data.length < 8) {
            return;
        }
        int etype = ((data[0] & 0xff) << 8) | (data[1] & 0xff);
        if (etype != ETYPE_DISC) {
            return;
        }
        int code = data[3] & 0xff;
        int sessionId = ((data[4] & 0xff) << 8) | (data[5] & 0xff);
        int len = ((data[6] & 0xff) << 8) | (data[7] & 0xff);
        byte[] payload = len > 0 && len <= data.length - 8
                ? Arrays.copyOfRange(data, 8, 8 + len) : new byte[0];
        String key = pkt.getAddress().getHostAddress() + ":" + pkt.getPort();
        try {
            if (code == CODE_PADI) {
                String svc = getTagString(payload, TAG_SERVICE_NAME);
                log("收到 PADI（客户端 " + key + "，Service-Name="
                        + (svc == null ? "(任意)" : svc) + "）");
                byte[] pado = buildDiscovery(ETYPE_DISC, CODE_PADO, 0,
                        tag(TAG_SERVICE_NAME, svc == null ? new byte[0]
                                : svc.getBytes(StandardCharsets.UTF_8)),
                        tag(TAG_AC_NAME, AC_NAME.getBytes(StandardCharsets.UTF_8)),
                        copyTag(payload, TAG_HOST_UNIQ));
                send(discSocket, pkt.getAddress(), pkt.getPort(), pado);
                log("已响应 PADO（AC-Name=" + AC_NAME + "）");
            } else if (code == CODE_PADR) {
                String svc = getTagString(payload, TAG_SERVICE_NAME);
                int sid = allocSessionId();
                // 同一来源重复 PADR：只替换映射，不重复计数（否则 activeSessions 只增不减）
                Integer prev = sessions.put(key, sid);
                if (prev == null) {
                    activeSessions.incrementAndGet();
                }
                sessionLastSeen.put(key, System.currentTimeMillis());
                byte[] pads = buildDiscovery(ETYPE_DISC, CODE_PADS, sid,
                        tag(TAG_SERVICE_NAME, svc == null ? new byte[0]
                                : svc.getBytes(StandardCharsets.UTF_8)),
                        tag(TAG_AC_NAME, AC_NAME.getBytes(StandardCharsets.UTF_8)),
                        copyTag(payload, TAG_HOST_UNIQ));
                send(discSocket, pkt.getAddress(), pkt.getPort(), pads);
                log("收到 PADR，分配 Session-ID=" + sid + "，已响应 PADS（会话建立）");
            } else if (code == CODE_PADT) {
                Integer sid = sessions.remove(key);
                if (sid != null) {
                    activeSessions.decrementAndGet();
                }
                sessionLastSeen.remove(key);
                chapChallenges.remove(key);
                log("收到 PADT，会话 " + (sid == null ? "(未知)" : sid) + " 已断开");
            } else {
                log("Discovery 收到未知 CODE=0x" + Integer.toHexString(code));
            }
        } catch (Exception e) {
            log("Discovery 处理异常: " + e.getMessage());
        }
    }

    /** 回收空闲会话（客户端掉线未发 PADT）：sessions 与 activeSessions 只增不减会导致计数失真。 */
    private void reapIdleSessions() {
        long now = System.currentTimeMillis();
        for (Map.Entry<String, Long> e : sessionLastSeen.entrySet()) {
            if (now - e.getValue() > SESSION_IDLE_TIMEOUT_MS) {
                String key = e.getKey();
                sessionLastSeen.remove(key);
                Integer sid = sessions.remove(key);
                chapChallenges.remove(key);
                if (sid != null) {
                    activeSessions.decrementAndGet();
                    log("会话 " + sid + " 空闲超时（" + (SESSION_IDLE_TIMEOUT_MS / 60000)
                            + " 分钟无报文），已回收");
                }
            }
        }
    }

    private int allocSessionId() {
        RandomHolder r = new RandomHolder();
        for (int i = 0; i < 65535; i++) {
            int sid = 0x4000 + r.nextInt(0x3fff); // 0x4001..0x7fff 会话 ID 空间
            if (!sessions.containsValue(sid)) {
                return sid;
            }
        }
        return 0x4001;
    }

    private static final class RandomHolder {
        final java.util.Random rnd = new java.util.Random();

        int nextInt(int bound) {
            return rnd.nextInt(bound);
        }
    }

    // ============================================================
    // Session 阶段（PPP LCP / PAP / CHAP）
    // ============================================================
    private void sessLoop() {
        byte[] buf = new byte[2048];
        while (running) {
            try {
                DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                sessSocket.receive(pkt);
                handleSession(pkt);
            } catch (SocketTimeoutException ignored) {
                reapIdleSessions();
            } catch (Exception e) {
                if (running) {
                    log("Session 接收异常: " + e.getMessage());
                }
            }
        }
    }

    private void handleSession(DatagramPacket pkt) {
        byte[] data = Arrays.copyOfRange(pkt.getData(), pkt.getOffset(),
                pkt.getOffset() + pkt.getLength());
        if (data.length < 10) {
            return;
        }
        int etype = ((data[0] & 0xff) << 8) | (data[1] & 0xff);
        if (etype != ETYPE_SESS) {
            return;
        }
        int sessionId = ((data[4] & 0xff) << 8) | (data[5] & 0xff);
        int len = ((data[6] & 0xff) << 8) | (data[7] & 0xff);
        if (len < 4 || len > data.length - 8) {
            return;
        }
        String key = pkt.getAddress().getHostAddress() + ":" + pkt.getPort();
        Integer sid = sessions.get(key);
        if (sid != null) {
            sessionLastSeen.put(key, System.currentTimeMillis());
        }
        // PPP 帧: ff 03 协议(2) 信息
        byte[] ppp = Arrays.copyOfRange(data, 8, 8 + len);
        if (ppp.length < 4 || (ppp[0] & 0xff) != 0xff || (ppp[1] & 0xff) != 0x03) {
            return;
        }
        int proto = ((ppp[2] & 0xff) << 8) | (ppp[3] & 0xff);
        byte[] info = Arrays.copyOfRange(ppp, 4, ppp.length);
        try {
            if (proto == PPP_LCP) {
                handleLcp(pkt, key, sid, info);
            } else if (proto == PPP_PAP) {
                handlePap(pkt, key, sid, info);
            } else if (proto == PPP_CHAP) {
                handleChap(pkt, key, sid, info);
            } else {
                log("会话 " + sid + " 收到未知 PPP 协议 0x" + Integer.toHexString(proto));
            }
        } catch (Exception e) {
            log("Session 处理异常: " + e.getMessage());
        }
    }

    /** LCP 配置/终止。 */
    private void handleLcp(DatagramPacket pkt, String key, Integer sid, byte[] info)
            throws IOException {
        if (info.length < 2) {
            return;
        }
        int code = info[0] & 0xff;
        int id = info[1] & 0xff;
        byte[] options = info.length > 2 ? Arrays.copyOfRange(info, 2, info.length) : new byte[0];
        if (code == LCP_CONF_REQ) {
            // 解析选项，回 ACK（回显）；Auth-Protocol 含 CHAP 时主动下发挑战
            boolean wantChap = hasAuthProto(options, PPP_CHAP);
            byte[] ack = pppFrame(PPP_LCP,
                    new byte[]{(byte) LCP_CONF_ACK, (byte) id}, options);
            send(sessSocket, pkt.getAddress(), pkt.getPort(), sessionFrame(sid, ack));
            log("会话 " + sid + " LCP 配置请求 → 已响应 ACK（"
                    + (wantChap ? "协商 CHAP" : "协商 PAP/无认证") + "）");
            if (wantChap) {
                byte[] chall = new byte[16];
                new java.security.SecureRandom().nextBytes(chall);
                byte[] stored = new byte[17];
                stored[0] = (byte) id;
                System.arraycopy(chall, 0, stored, 1, 16);
                chapChallenges.put(key, stored);
                byte[] ch = pppFrame(PPP_CHAP,
                        new byte[]{(byte) CHAP_CHALLENGE, (byte) id, (byte) chall.length}, chall);
                send(sessSocket, pkt.getAddress(), pkt.getPort(), sessionFrame(sid, ch));
                log("会话 " + sid + " 已下发 CHAP Challenge（id=" + id + "）");
            }
        } else if (code == LCP_TERM_REQ) {
            byte[] ack = pppFrame(PPP_LCP,
                    new byte[]{(byte) LCP_TERM_ACK, (byte) id}, new byte[0]);
            send(sessSocket, pkt.getAddress(), pkt.getPort(), sessionFrame(sid, ack));
            log("会话 " + sid + " LCP 终止请求 → 已响应 ACK");
            closeSession(key, sid);
        } else if (code == LCP_CONF_NAK || code == LCP_CONF_REJ) {
            log("会话 " + sid + " LCP 收到 NAK/REJ（code=" + code + "）");
        } else {
            log("会话 " + sid + " LCP 其他 code=" + code);
        }
    }

    /** PAP 认证（RFC 1334）。 */
    private void handlePap(DatagramPacket pkt, String key, Integer sid, byte[] info)
            throws IOException {
        if (info.length < 3) {
            return;
        }
        int code = info[0] & 0xff;
        int id = info[1] & 0xff;
        if (code != PAP_AUTH_REQ) {
            log("会话 " + sid + " PAP 未知 code=" + code);
            return;
        }
        int peerLen = info[2] & 0xff;
        if (info.length < 3 + peerLen + 1) {
            return;
        }
        String peer = new String(info, 3, peerLen, StandardCharsets.UTF_8);
        int passLen = info[3 + peerLen] & 0xff;
        if (info.length < 3 + peerLen + 1 + passLen) {
            return;
        }
        String pass = new String(info, 3 + peerLen + 1, passLen, StandardCharsets.UTF_8);
        totalAuth.incrementAndGet();
        UsersDB.User u = UsersDB.find(baseDir, peer);
        // 口令用常数时间比较（与 CHAP 分支、RADIUS 一致），避免远程计时侧信道
        boolean passOk = u != null && MessageDigest.isEqual(
                u.password.getBytes(StandardCharsets.UTF_8),
                pass.getBytes(StandardCharsets.UTF_8));
        if (u != null && u.enabled() && passOk) {
            okAuth.incrementAndGet();
            byte[] ack = papFrame(id, PAP_AUTH_ACK, "Welcome to MODPKICA PPPoE");
            send(sessSocket, pkt.getAddress(), pkt.getPort(), sessionFrame(sid, ack));
            log("PAP 认证通过: " + peer + "（会话 " + sid + "）");
        } else {
            failAuth.incrementAndGet();
            byte[] nak = papFrame(id, PAP_AUTH_NAK, "Authentication failed");
            send(sessSocket, pkt.getAddress(), pkt.getPort(), sessionFrame(sid, nak));
            log("PAP 认证失败: " + peer + "（账号不存在、停用或密码错误）");
        }
    }

    /** CHAP 响应校验（RFC 1994）。 */
    private void handleChap(DatagramPacket pkt, String key, Integer sid, byte[] info)
            throws IOException {
        if (info.length < 2) {
            return;
        }
        int code = info[0] & 0xff;
        int id = info[1] & 0xff;
        if (code == CHAP_RESPONSE) {
            byte[] challenge = chapChallenges.remove(key);
            if (challenge == null || info.length < 3) {
                failAuth.incrementAndGet();
                byte[] fail = chapFrame(id, CHAP_FAILURE, new byte[0], "",
                        "No challenge (challenge expired)");
                send(sessSocket, pkt.getAddress(), pkt.getPort(), sessionFrame(sid, fail));
                log("会话 " + sid + " CHAP 响应无有效挑战（超时或非法），已拒绝");
                return;
            }
            int challengeId = challenge[0] & 0xff;
            int valLen = info[2] & 0xff;
            if (info.length < 3 + valLen) {
                return;
            }
            byte[] response = Arrays.copyOfRange(info, 3, 3 + valLen);
            String name = new String(info, 3 + valLen, info.length - 3 - valLen,
                    StandardCharsets.UTF_8);
            byte[] challengeVal = Arrays.copyOfRange(challenge, 1, challenge.length);
            totalAuth.incrementAndGet();
            UsersDB.User u = UsersDB.find(baseDir, name);
            byte[] expected = chapResponse(challengeId, u == null ? "" : u.password, challengeVal);
            if (u != null && u.enabled() && MessageDigest.isEqual(expected, response)) {
                okAuth.incrementAndGet();
                byte[] ok = chapFrame(id, CHAP_SUCCESS, new byte[0], "", "Authenticated");
                send(sessSocket, pkt.getAddress(), pkt.getPort(), sessionFrame(sid, ok));
                log("CHAP 认证通过: " + name + "（会话 " + sid + "）");
            } else {
                failAuth.incrementAndGet();
                byte[] fail = chapFrame(id, CHAP_FAILURE, new byte[0], "",
                        "CHAP authentication failed");
                send(sessSocket, pkt.getAddress(), pkt.getPort(), sessionFrame(sid, fail));
                log("CHAP 认证失败: " + name + "（账号不存在、停用或响应不匹配）");
            }
        } else {
            log("会话 " + sid + " CHAP 未知 code=" + code);
        }
    }

    private void closeSession(String key, Integer sid) {
        sessions.remove(key);
        sessionLastSeen.remove(key);
        chapChallenges.remove(key);
        if (sid != null) {
            activeSessions.decrementAndGet();
        }
    }

    // ============================================================
    // 客户端拨号模拟器（调试专区）：完整 Discovery + PPP 认证流程
    // ============================================================
    /** 客户端模拟拨号。method: PAP / CHAP。返回 {ok, message, log[]}。 */
    public Map<String, Object> dial(String username, String password, String method) {
        List<String> lines = new ArrayList<>();
        boolean ok = false;
        String result = "";
        try (DatagramSocket sock = new DatagramSocket()) {
            sock.setSoTimeout(3000);
            InetAddress target = InetAddress.getByName("127.0.0.1");
            if (!running) {
                return fail("PPPoE 服务未运行，请先在“服务器管理”启动", lines);
            }
            String uname = username == null ? "" : username.trim();
            String pass = password == null ? "" : password;
            String m = method == null || method.trim().isEmpty() ? "PAP" : method.trim().toUpperCase();
            if (uname.isEmpty() || pass.isEmpty()) {
                return fail("用户名/密码不能为空", lines);
            }
            lines.add("=== PPPoE 客户端拨号模拟开始 ===");
            lines.add("账号: " + uname + "，认证方式: " + m + "，目标: " + target.getHostAddress() + ":" + discPort);

            // 1. PADI
            byte[] padi = buildDiscovery(ETYPE_DISC, CODE_PADI, 0,
                    tag(TAG_SERVICE_NAME, new byte[0]));
            send(sock, target, discPort, padi);
            lines.add("[1] 发送 PADI（广播请求）");
            DatagramPacket padoPkt = recv(sock);
            if (padoPkt == null) {
                return fail("等待 PADO 超时（服务器未响应）", lines);
            }
            byte[] pado = payloadOf(padoPkt);
            int padoCode = codeOf(pado);
            if (padoCode != CODE_PADO) {
                return fail("收到非 PADO 响应 code=0x" + Integer.toHexString(padoCode), lines);
            }
            String acName = getTagString(payloadOfBody(pado), TAG_AC_NAME);
            lines.add("[2] 收到 PADO（AC-Name=" + (acName == null ? "(空)" : acName) + "）");

            // 2. PADR
            byte[] padr = buildDiscovery(ETYPE_DISC, CODE_PADR, 0,
                    tag(TAG_SERVICE_NAME, new byte[0]));
            send(sock, target, discPort, padr);
            lines.add("[3] 发送 PADR（请求会话）");
            DatagramPacket padsPkt = recv(sock);
            if (padsPkt == null) {
                return fail("等待 PADS 超时", lines);
            }
            byte[] pads = payloadOf(padsPkt);
            int padsCode = codeOf(pads);
            int sessionId = sessionOf(pads);
            if (padsCode != CODE_PADS) {
                return fail("收到非 PADS 响应 code=0x" + Integer.toHexString(padsCode), lines);
            }
            lines.add("[4] 收到 PADS（Session-ID=" + sessionId + "，会话建立）");

            // 3. LCP 配置请求（含认证协议）
            byte[] authOpt = m.equals("CHAP")
                    ? new byte[]{OPT_AUTH_PROTO, 0x04, (byte) 0xc2, 0x23}
                    : new byte[]{OPT_AUTH_PROTO, 0x04, (byte) 0xc0, 0x23};
            byte[] lcpReq = pppFrame(PPP_LCP, new byte[]{LCP_CONF_REQ, 0x01},
                    concat(new byte[]{OPT_MRU, 0x04, 0x05, (byte) 0xd4}, authOpt));
            send(sock, target, sessPort, sessionFrame(sessionId, lcpReq));
            lines.add("[5] 发送 LCP 配置请求（协商 " + m + "）");
            DatagramPacket lcpAckPkt = recv(sock);
            if (lcpAckPkt == null) {
                return fail("等待 LCP ACK 超时", lines);
            }
            byte[] lcpAck = payloadOf(lcpAckPkt);
            int lcpCode = pppCodeOf(lcpAck);
            if (lcpCode != LCP_CONF_ACK) {
                return fail("LCP 未确认（code=" + lcpCode + "）", lines);
            }
            lines.add("[6] 收到 LCP 配置 ACK");

            // 4. 认证
            if (m.equals("CHAP")) {
                // 连续收包直到同时取得 LCP ACK 与 CHAP Challenge（服务器对含 CHAP 的 LCP 会主动下发）
                byte[] ackInfo = null;
                byte[] challInfo = null;
                for (int i = 0; i < 6; i++) {
                    DatagramPacket p = recv(sock);
                    if (p == null) {
                        break;
                    }
                    byte[] info = pppInfoOf(payloadOf(p));
                    if (info == null || info.length < 1) {
                        continue;
                    }
                    int c = info[0] & 0xff;
                    if (c == LCP_CONF_ACK) {
                        ackInfo = info;
                    }
                    if (c == CHAP_CHALLENGE) {
                        challInfo = info;
                    }
                    if (ackInfo != null && challInfo != null) {
                        break;
                    }
                }
                if (ackInfo != null) {
                    lines.add("[6] 收到 LCP 配置 ACK");
                }
                if (challInfo == null) {
                    return fail("等待 CHAP Challenge 超时（服务器未下发）", lines);
                }
                int chapId = challInfo[1] & 0xff;
                int vLen = challInfo[2] & 0xff;
                if (challInfo.length < 3 + vLen) {
                    return fail("CHAP Challenge 格式异常", lines);
                }
                byte[] challVal = Arrays.copyOfRange(challInfo, 3, 3 + vLen);
                String serverName = new String(challInfo, 3 + vLen, challInfo.length - 3 - vLen,
                        StandardCharsets.UTF_8);
                lines.add("[7] 收到 CHAP Challenge（id=" + chapId + "，来自 "
                        + (serverName.isEmpty() ? "(空)" : serverName) + "）");
                byte[] resp = chapResponse(chapId, pass, challVal);
                byte[] chapResp = pppFrame(PPP_CHAP,
                        new byte[]{(byte) CHAP_RESPONSE, (byte) chapId, (byte) resp.length}, resp);
                byte[] nameBytes = uname.getBytes(StandardCharsets.UTF_8);
                chapResp = concat(chapResp, nameBytes);
                send(sock, target, sessPort, sessionFrame(sessionId, chapResp));
                lines.add("[8] 发送 CHAP Response（MD5 计算响应）");
                DatagramPacket chapRspPkt = recv(sock);
                if (chapRspPkt == null) {
                    return fail("等待 CHAP 结果超时", lines);
                }
                byte[] chapResult = pppInfoOf(payloadOf(chapRspPkt));
                if (chapResult != null && (chapResult[0] & 0xff) == CHAP_SUCCESS) {
                    ok = true;
                    result = "CHAP 认证成功（会话 " + sessionId + "）";
                    lines.add("[9] 收到 CHAP Success → 认证成功");
                } else {
                    String msg = chapResult != null && chapResult.length > 3
                            ? new String(chapResult, 3, chapResult.length - 3, StandardCharsets.UTF_8) : "";
                    result = "CHAP 认证失败：" + msg;
                    lines.add("[9] 收到 CHAP Failure → 认证失败");
                }
            } else {
                // PAP
                byte[] peerBytes = uname.getBytes(StandardCharsets.UTF_8);
                byte[] passBytes = pass.getBytes(StandardCharsets.UTF_8);
                byte[] papReq = pppFrame(PPP_PAP,
                        new byte[]{PAP_AUTH_REQ, 0x01, (byte) peerBytes.length}, peerBytes);
                papReq = concat(papReq, new byte[]{(byte) passBytes.length});
                papReq = concat(papReq, passBytes);
                send(sock, target, sessPort, sessionFrame(sessionId, papReq));
                lines.add("[7] 发送 PAP Authenticate-Request（账号 " + uname + "）");
                DatagramPacket papRspPkt = recv(sock);
                if (papRspPkt == null) {
                    return fail("等待 PAP 结果超时", lines);
                }
                byte[] papResult = pppInfoOf(payloadOf(papRspPkt));
                if (papResult != null && (papResult[0] & 0xff) == PAP_AUTH_ACK) {
                    ok = true;
                    result = "PAP 认证成功（会话 " + sessionId + "）";
                    lines.add("[8] 收到 PAP ACK → 认证成功");
                } else {
                    String msg = papResult != null && papResult.length > 3
                            ? new String(papResult, 3, papResult.length - 3, StandardCharsets.UTF_8) : "";
                    result = "PAP 认证失败：" + msg;
                    lines.add("[8] 收到 PAP NAK → 认证失败");
                }
            }

            // 5. 断开
            byte[] padT = buildDiscovery(ETYPE_DISC, CODE_PADT, sessionId, new byte[0]);
            send(sock, target, discPort, padT);
            lines.add("[10] 发送 PADT（断开会话）");
            lines.add("=== 拨号流程结束 ===");
        } catch (Exception e) {
            return fail("拨号异常: " + e.getMessage(), lines);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", ok);
        m.put("message", result);
        m.put("log", lines);
        return m;
    }

    private Map<String, Object> fail(String msg, List<String> lines) {
        lines.add("结果: " + msg);
        lines.add("=== 拨号流程结束 ===");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("message", msg);
        m.put("log", lines);
        return m;
    }

    // ============================================================
    // 包编解码工具
    // ============================================================
    /** UDP payload = [以太网类型 2B][PPPoE 头 6B][体]。 */
    private static byte[] buildDiscovery(int etype, int code, int sessionId, byte[]... tags) {
        int bodyLen = 0;
        for (byte[] t : tags) {
            bodyLen += t == null ? 0 : t.length;
        }
        byte[] out = new byte[8 + bodyLen];
        out[0] = (byte) (etype >> 8);
        out[1] = (byte) etype;
        out[2] = 0x11; // VER=1 TYPE=1
        out[3] = (byte) code;
        out[4] = (byte) (sessionId >> 8);
        out[5] = (byte) sessionId;
        out[6] = (byte) (bodyLen >> 8);
        out[7] = (byte) bodyLen;
        int p = 8;
        for (byte[] t : tags) {
            if (t != null) {
                System.arraycopy(t, 0, out, p, t.length);
                p += t.length;
            }
        }
        return out;
    }

    /** 构造标签：TAG_TYPE(2) + LENGTH(2) + VALUE。 */
    private static byte[] tag(int type, byte[] value) {
        int vlen = value == null ? 0 : value.length;
        byte[] t = new byte[4 + vlen];
        t[0] = (byte) (type >> 8);
        t[1] = (byte) type;
        t[2] = (byte) (vlen >> 8);
        t[3] = (byte) vlen;
        if (vlen > 0) {
            System.arraycopy(value, 0, t, 4, vlen);
        }
        return t;
    }

    /** 从标签区复制指定类型标签（找不到返回空数组）。 */
    private static byte[] copyTag(byte[] body, int wantType) {
        int p = 0;
        while (p + 4 <= body.length) {
            int type = ((body[p] & 0xff) << 8) | (body[p + 1] & 0xff);
            int len = ((body[p + 2] & 0xff) << 8) | (body[p + 3] & 0xff);
            if (p + 4 + len > body.length) {
                break;
            }
            if (type == wantType) {
                return Arrays.copyOfRange(body, p + 4, p + 4 + len);
            }
            p += 4 + len;
        }
        return new byte[0];
    }

    /** 提取标签字符串值（找不到返回 null）。 */
    private static String getTagString(byte[] body, int wantType) {
        byte[] v = copyTag(body, wantType);
        return v.length == 0 ? null : new String(v, StandardCharsets.UTF_8);
    }

    /** Session UDP payload = [0x88 0x64][PPPoE 头][PPP 帧]。 */
    private static byte[] sessionFrame(int sessionId, byte[] ppp) {
        byte[] out = new byte[8 + ppp.length];
        out[0] = (byte) (ETYPE_SESS >> 8);
        out[1] = (byte) ETYPE_SESS;
        out[2] = 0x11;
        out[3] = 0x00;
        out[4] = (byte) (sessionId >> 8);
        out[5] = (byte) sessionId;
        out[6] = (byte) (ppp.length >> 8);
        out[7] = (byte) ppp.length;
        System.arraycopy(ppp, 0, out, 8, ppp.length);
        return out;
    }

    /** PPP 帧 = ff 03 协议(2) 信息。 */
    private static byte[] pppFrame(int protocol, byte[] codeId, byte[] info) {
        byte[] out = new byte[4 + codeId.length + info.length];
        out[0] = (byte) 0xff;
        out[1] = (byte) 0x03;
        out[2] = (byte) (protocol >> 8);
        out[3] = (byte) protocol;
        System.arraycopy(codeId, 0, out, 4, codeId.length);
        System.arraycopy(info, 0, out, 4 + codeId.length, info.length);
        return out;
    }

    /** PAP 帧（code=ACK/NAK，带消息）。 */
    private static byte[] papFrame(int id, int code, String message) {
        byte[] msg = message.getBytes(StandardCharsets.UTF_8);
        return pppFrame(PPP_PAP,
                new byte[]{(byte) code, (byte) id, (byte) msg.length}, msg);
    }

    /** CHAP 帧（RFC 1994）：code(1) id(1) value-size(1) value name [message]。 */
    private static byte[] chapFrame(int id, int code, byte[] value, String name, String message) {
        byte[] nm = name.getBytes(StandardCharsets.UTF_8);
        byte[] msg = message.getBytes(StandardCharsets.UTF_8);
        byte[] info = concat(concat(value, nm), msg);
        return pppFrame(PPP_CHAP,
                new byte[]{(byte) code, (byte) id, (byte) value.length}, info);
    }

    /** 是否包含指定认证协议选项。 */
    private static boolean hasAuthProto(byte[] options, int proto) {
        int p = 0;
        while (p + 2 <= options.length) {
            int type = options[p] & 0xff;
            int len = options[p + 1] & 0xff;
            if (len < 2 || p + len > options.length) {
                break;
            }
            if (type == OPT_AUTH_PROTO && len == 4) {
                int v = ((options[p + 2] & 0xff) << 8) | (options[p + 3] & 0xff);
                if (v == proto) {
                    return true;
                }
            }
            p += len;
        }
        return false;
    }

    /** CHAP 响应 = MD5(id + secret + challenge)。 */
    private static byte[] chapResponse(int id, String secret, byte[] challenge) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update((byte) id);
            md.update(secret.getBytes(StandardCharsets.UTF_8));
            md.update(challenge);
            return md.digest();
        } catch (Exception e) {
            return new byte[16];
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /** 从收到的 DatagramPacket 提取 payload。 */
    private static byte[] payloadOf(DatagramPacket pkt) {
        return Arrays.copyOfRange(pkt.getData(), pkt.getOffset(),
                pkt.getOffset() + pkt.getLength());
    }

    /** PPPoE 头 body（第 8 字节起）。 */
    private static byte[] payloadOfBody(byte[] data) {
        return data.length > 8 ? Arrays.copyOfRange(data, 8, data.length) : new byte[0];
    }

    private static int codeOf(byte[] data) {
        return data.length > 3 ? data[3] & 0xff : -1;
    }

    private static int sessionOf(byte[] data) {
        return data.length > 5 ? ((data[4] & 0xff) << 8) | (data[5] & 0xff) : 0;
    }

    /** 提取 PPP 帧信息（ff 03 后）。 */
    private static byte[] pppInfoOf(byte[] data) {
        byte[] body = payloadOfBody(data);
        if (body.length < 4) {
            return null;
        }
        return Arrays.copyOfRange(body, 4, body.length);
    }

    private static int pppCodeOf(byte[] data) {
        byte[] body = payloadOfBody(data);
        if (body.length < 5) {
            return -1;
        }
        return body[4] & 0xff;
    }

    private static void send(DatagramSocket sock, InetAddress addr, int port, byte[] data)
            throws IOException {
        sock.send(new DatagramPacket(data, data.length, addr, port));
    }

    private static DatagramPacket recv(DatagramSocket sock) {
        try {
            byte[] buf = new byte[2048];
            DatagramPacket pkt = new DatagramPacket(buf, buf.length);
            sock.receive(pkt);
            return pkt;
        } catch (SocketTimeoutException e) {
            return null;
        } catch (IOException e) {
            return null;
        }
    }
}
