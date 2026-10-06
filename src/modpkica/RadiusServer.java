package modpkica;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.tls.AbstractTlsClient;
import org.bouncycastle.tls.AbstractTlsServer;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.DefaultTlsCredentialedSigner;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

/**
 * RADIUS 服务器（RFC 2865 认证 / RFC 2866 计费）+ EAP（RFC 3748 / RFC 2284）。
 *
 * <p>参考 WinRadius：认证端口默认 1812、计费端口默认 1813、共享密钥可配置；
 * 支持 PPP / PPPoE / PPTP / VPN / VoIP / ADSL / Cable Modem / CDMA / GSM / GPRS /
 * WEB / WAP / WLAN 等 NAS 接入（由 NAS-Port-Type / NAS-IP-Address 属性标识，服务端无需区分）。
 *
 * <p>认证方法（按 Access-Request 携带属性自动识别）：
 * <ul>
 *   <li><b>PAP</b>：User-Password 属性（RFC 2865 §5.2 MD5 混淆）解密比对；</li>
 *   <li><b>CHAP</b>：CHAP-Password + CHAP-Challenge → MD5(chapId || password || challenge)；</li>
 *   <li><b>MS-CHAPv1</b>：Vendor-Specific(Microsoft) MS-CHAP-Response（RFC 2433，
 *       MD4 NT-Password-Hash + 2×DES 加密 8 字节挑战比对，PPTP/拨号场景）；</li>
 *   <li><b>MS-CHAPv2</b>：Vendor-Specific(Microsoft) MS-CHAP2-Response（RFC 2759，
 *       MD4 NT-Password-Hash + DES 三重加密挑战哈希比对）；</li>
 *   <li><b>EAP</b>（RFC 3748）：EAP-Message 属性承载，服务端状态机（挑战缓存 30s 超时）：
 *       EAP-Identity → EAP-MD5（type=4）/ EAP-MSCHAPv2（type=26）挑战-响应 →
 *       EAP-Success / EAP-Failure；EAP-TLS（type=13）/ PEAP / TTLS 预留（返回 Failure 并提示）。</li>
 * </ul>
 *
 * <p>隧道属性（RFC 2867 / 2868）：Tunnel-Type / Tunnel-Medium-Type / Tunnel-Client|Server-Endpoint /
 * Tunnel-Password 自动解析记录（PPTP / L2TP / IPsec / GRE 等 VPN 场景可见）。
 *
 * <p>计费（RFC 2866）：Accounting-Request（Start / Stop / Interim）记录会话并写 logs.log。
 *
 * <p>日志：内存环形缓冲（WinRadius 风格 ID / 时间 / 消息，面板读取）+ logs.log 持久化。
 * 用户账号来自 {@link UsersDB}（PKI/USERS.txt）。
 */
public class RadiusServer {

    // ==================== RADIUS 常量（RFC 2865 / 2866） ====================

    public static final int DEFAULT_AUTH_PORT = 1812;
    public static final int DEFAULT_ACCT_PORT = 1813;

    /** 解析端口字符串（非法/越界回退默认值）。 */
    public static int portOf(String s, int def) {
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
    public static final int MAX_LOG_ENTRIES = 500;

    /** 包 Code。 */
    static final int CODE_ACCESS_REQUEST = 1;
    static final int CODE_ACCESS_ACCEPT = 2;
    static final int CODE_ACCESS_REJECT = 3;
    static final int CODE_ACCT_REQUEST = 4;
    static final int CODE_ACCT_RESPONSE = 5;
    static final int CODE_ACCESS_CHALLENGE = 11;

    /** 属性 Type。 */
    static final int ATTR_USER_NAME = 1;
    static final int ATTR_USER_PASSWORD = 2;
    static final int ATTR_CHAP_PASSWORD = 3;
    static final int ATTR_NAS_IP_ADDRESS = 4;
    static final int ATTR_NAS_PORT = 5;
    static final int ATTR_SERVICE_TYPE = 6;
    static final int ATTR_FRAMED_PROTOCOL = 7;
    static final int ATTR_FRAMED_IP_ADDRESS = 8;
    static final int ATTR_SESSION_TIMEOUT = 27;
    static final int ATTR_ACCT_STATUS_TYPE = 40;
    static final int ATTR_ACCT_INPUT_OCTETS = 42;
    static final int ATTR_ACCT_OUTPUT_OCTETS = 43;
    static final int ATTR_ACCT_SESSION_ID = 44;
    static final int ATTR_ACCT_SESSION_TIME = 46;
    static final int ATTR_ACCT_TERMINATE_CAUSE = 49;
    static final int ATTR_CHAP_CHALLENGE = 60;
    static final int ATTR_NAS_PORT_TYPE = 61;
    static final int ATTR_VENDOR_SPECIFIC = 26;
    static final int ATTR_EAP_MESSAGE = 79;
    static final int ATTR_MESSAGE_AUTHENTICATOR = 80;

    /** 隧道属性（RFC 2867 / 2868）。 */
    static final int ATTR_TUNNEL_TYPE = 64;
    static final int ATTR_TUNNEL_MEDIUM_TYPE = 65;
    static final int ATTR_TUNNEL_CLIENT_ENDPOINT = 66;
    static final int ATTR_TUNNEL_SERVER_ENDPOINT = 67;
    static final int ATTR_TUNNEL_PASSWORD = 69;

    /** Vendor-Specific 微软厂商 ID（RFC 2548）。 */
    static final int VENDOR_MICROSOFT = 0x00000137;
    /** MS-CHAP 挑战（Vendor-Type=11，v1 为 8 字节、v2 为 16 字节）。 */
    static final int MS_CHAP_CHALLENGE = 11;
    /** MS-CHAPv1 响应（Vendor-Type=24，RFC 2433：Ident+LM-Response24+NT-Response24）。 */
    static final int MS_CHAP1_RESPONSE = 24;
    /** MS-CHAPv2 响应（Vendor-Type=25）。 */
    static final int MS_CHAP2_RESPONSE = 25;

    // ==================== EAP 常量（RFC 3748 / 2284） ====================

    static final int EAP_CODE_REQUEST = 1;
    static final int EAP_CODE_RESPONSE = 2;
    static final int EAP_CODE_SUCCESS = 3;
    static final int EAP_CODE_FAILURE = 4;

    static final int EAP_TYPE_IDENTITY = 1;
    /** EAP-NAK（RFC 3748 §5.3）：客户端拒绝当前方法并列出其支持的 EAP 类型。 */
    static final int EAP_TYPE_NAK = 3;
    static final int EAP_TYPE_MD5 = 4;
    /** GTC（RFC 3748 §5.6）：服务器发提示文本，客户端回明文令牌/口令。 */
    static final int EAP_TYPE_GTC = 6;
    static final int EAP_TYPE_TLS = 13;
    /** TTLS（RFC 5281）：外层 TLS 隧道 + 内层传统协议（PAP AVP 交换）。 */
    static final int EAP_TYPE_TTLS = 21;
    /** PEAP（RFC 5216）：外层 TLS 隧道 + 内层 EAP。 */
    static final int EAP_TYPE_PEAP = 25;
    static final int EAP_TYPE_MSCHAPV2 = 26;
    /** EAP-pwd（RFC 5931）：基于口令的 EAP。 */
    static final int EAP_TYPE_PWD = 52;

    /** EAP-TLS flags（RFC 5216 §2.1）。 */
    static final int EAP_TLS_FLAG_LENGTH = 0x40;   // 含 4 字节总长度
    static final int EAP_TLS_FLAG_MORE = 0x20;     // 还有后续分片
    static final int EAP_TLS_FLAG_START = 0x10;    // EAP-TLS Start

    /** 服务器 → 客户端每条 EAP-Request/TLS 的载荷上限（RADIUS EAP-Message 属性 253-头 留余量）。 */
    static final int EAP_TLS_FRAG = 240;
    /** 客户端 → 服务器单条 EAP-Response/TLS 重组上限（防恶意超长，16KB TLS 记录够用）。 */
    static final int EAP_TLS_MAX_IN = 65536;
    /** 握手超时（秒）。 */
    static final int EAP_TLS_TIMEOUT_S = 8;

    static final long EAP_STATE_TTL_MS = 30_000L;

    // ==================== 实例状态 ====================

    private final String baseDir;
    private volatile boolean running;
    private volatile int authPort = DEFAULT_AUTH_PORT;
    private volatile int acctPort = DEFAULT_ACCT_PORT;
    private volatile String secret = "mytestkey";
    private DatagramSocket authSock;
    private DatagramSocket acctSock;
    private Thread authThread;
    private Thread acctThread;
    private long startTime;

    /** EAP 挑战状态缓存：来源 "ip:port" → 状态（RADIUS Identifier 每请求递增，不可作会话 key）。 */
    private final Map<String, EapState> eapStates = new HashMap<>();

    /** EAP-TLS 会话缓存：RADIUS Identifier → 会话（RFC 5216，BC TLS 1.2 握手线程）。 */
    private final Map<Integer, EapTlsSession> tlsSessions = new ConcurrentHashMap<>();

    /** 服务端 TLS 凭据（懒加载，来自 PKI 证书库 CA/ROOT 的 RSA/ECC 证书）。 */
    private volatile TlsServerCred tlsServerCred;
    private final Object tlsCredLock = new Object();

    /** WinRadius 风格环形日志。 */
    private final Deque<LogEntry> logs = new ConcurrentLinkedDeque<>();
    private long logSeq = 0;

    /** 统计。 */
    private long totalAuthRequests, authOk, authFail, totalAcct;

    /** 单条日志。 */
    public static final class LogEntry {
        public final long id;
        public final String time;
        public final String message;

        LogEntry(long id, String time, String message) {
            this.id = id;
            this.time = time;
            this.message = message;
        }
    }

    /** EAP 挑战状态。 */
    private static final class EapState {
        String username;
        byte[] challenge;
        String method;       // "MD5" / "MSCHAPV2" / "GTC" / "MSCHAPV2_OK"
        byte[] msk;          // MSCHAPV2 认证通过后的 MSK（第二阶段 Access-Accept 下发 MS-MPPE）
        long expires;        // 过期时间戳
    }

    /** EAP-pwd（RFC 5931）状态机：ID → Commit（标量/元素交换）→ Confirm → Success。 */
    private static final class EapPwdState {
        String username;
        int phase;                       // 0=已发 ID/Request，1=已发 Commit，2=已发 Confirm
        ECPoint pwe;
        BigInteger scalarS;              // 服务器标量
        ECPoint elementS;                // 服务器元素
        BigInteger scalarP;              // 客户端标量（Commit/Response 解析）
        ECPoint elementP;                // 客户端元素
        byte[] kx;                       // 共享密钥 = k 点 x 坐标（32B）
        byte[] confirmC;                 // 客户端 Confirm（验证用）
        long expires;
    }

    private final Map<Integer, EapPwdState> pwdStates = new HashMap<>();

    // ==================== EAP-TLS（RFC 5216 + BC TLS 1.2） ====================

    /** 服务端 TLS 凭据：证书链（叶→根）+ 私钥（RSA/ECC）。 */
    static final class TlsServerCred {
        final BcTlsCrypto crypto;
        final AsymmetricKeyParameter key;
        final X509Certificate[] chain;

        TlsServerCred(BcTlsCrypto crypto, AsymmetricKeyParameter key, X509Certificate[] chain) {
            this.crypto = crypto;
            this.key = key;
            this.chain = chain;
        }
    }

    /** 阻塞式输入流：握手线程从队列取客户端 EAP 数据；空数组=EOF。 */
    static final class BlockingInput extends InputStream {
        private final LinkedBlockingQueue<byte[]> q;
        private byte[] cur;
        private int curOff;
        private boolean eof;

        BlockingInput(LinkedBlockingQueue<byte[]> q) {
            this.q = q;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : (one[0] & 0xff);
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len <= 0) {
                return 0;
            }
            while (cur == null || curOff >= cur.length) {
                if (eof) {
                    return -1;
                }
                byte[] d;
                try {
                    d = q.poll(10, TimeUnit.SECONDS);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new IOException("EAP-TLS 输入流中断");
                }
                if (d == null) {
                    throw new IOException("EAP-TLS 客户端数据超时");
                }
                if (d.length == 0) {
                    eof = true;
                    cur = null;
                    return -1;
                }
                cur = d;
                curOff = 0;
            }
            int n = Math.min(len, cur.length - curOff);
            System.arraycopy(cur, curOff, b, off, n);
            curOff += n;
            return n;
        }
    }

    /** EAP-TLS 会话：BC 握手线程 + 输入队列 + 输出缓冲（游标 sent）。 */
    static final class EapTlsSession {
        final String username;
        final LinkedBlockingQueue<byte[]> inQ = new LinkedBlockingQueue<>();
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final BlockingInput inStream;
        final OutputStream outStream;
        final Object lock = new Object();
        volatile boolean done;
        volatile boolean ok;
        volatile String err = "";
        Thread thread;
        /** 待分片下发的服务器 TLS 输出缓冲（RFC 5216 §2.1：每片一个 EAP 包）。 */
        byte[] outBuf;
        int outSent;
        /** PEAP：TLS 握手完成后进入内层 EAP 认证（RFC 5216 §3.2）。 */
        volatile boolean innerEap;
        /** PEAP 内层方法：MD5 / MSCHAPV2。 */
        volatile String innerMethod = "MD5";
        /** PEAP 内层认证通过时记用户。 */
        volatile String innerUser = "";
        /** TLS 协议对象（PEAP 内层读写隧道用）。 */
        volatile TlsServerProtocol tlsProto;
        /** 客户端 TLS 协议对象（PEAP 客户端内层读写隧道用）。 */
        volatile TlsClientProtocol clientTlsProto;

        /** 取下一片（首片带 L|len，未发完带 M）；发完即清空缓冲并返回 null。 */
        byte[] nextOutFrag() {
            if (outBuf == null) {
                return null;
            }
            int n = Math.min(EAP_TLS_FRAG, outBuf.length - outSent);
            int flags = (outSent == 0 ? EAP_TLS_FLAG_LENGTH : 0)
                    | (outSent + n < outBuf.length ? EAP_TLS_FLAG_MORE : 0);
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            b.write(flags);
            if ((flags & EAP_TLS_FLAG_LENGTH) != 0) {
                b.write((outBuf.length >> 24) & 0xff);
                b.write((outBuf.length >> 16) & 0xff);
                b.write((outBuf.length >> 8) & 0xff);
                b.write(outBuf.length & 0xff);
            }
            b.write(outBuf, outSent, n);
            outSent += n;
            if (outSent >= outBuf.length) {
                outBuf = null;
            }
            return b.toByteArray();
        }

        EapTlsSession(String username) {
            this.username = username;
            this.inStream = new BlockingInput(inQ);
            this.outStream = new OutputStream() {
                @Override
                public void write(int b) {
                    out.write(b);
                }

                @Override
                public void write(byte[] b, int o, int l) {
                    out.write(b, o, l);
                }
            };
        }

        /** 追加一段客户端数据（EOF 哨兵=空数组表示握手线程应结束读取）。 */
        void feed(byte[] data) {
            inQ.add(data == null ? new byte[0] : data);
        }

        /** 读取自 sent 游标后的全部新输出；无新输出且未完成时阻塞等待最多 timeoutMs。 */
        byte[] pollOutput(long timeoutMs) {
            long deadline = System.currentTimeMillis() + timeoutMs;
            synchronized (lock) {
                while (!done) {
                    byte[] all = out.toByteArray();
                    if (all.length > sent) {
                        byte[] fresh = Arrays.copyOfRange(all, sent, all.length);
                        sent = all.length;
                        return fresh;
                    }
                    long remain = deadline - System.currentTimeMillis();
                    if (remain <= 0) {
                        return null;
                    }
                    try {
                        // 250ms 轮询：握手线程产出后不主动 notify 也能及时取回
                        lock.wait(Math.min(remain, 250));
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return null;
                    }
                }
                byte[] all = out.toByteArray();
                if (all.length > sent) {
                    byte[] fresh = Arrays.copyOfRange(all, sent, all.length);
                    sent = all.length;
                    return fresh;
                }
                return new byte[0];
            }
        }

        private int sent;

        /** 客户端 → 服务器 分片重组缓冲（RFC 5216：M 位 + 可选 L 位总长）。 */
        private byte[] pendingIn;
        private int pendingOff;

        /**
         * 重组客户端 EAP-TLS 分片。
         * @return null=还需更多分片；byte[]=完整 TLS 记录（可提交握手线程）。
         */
        byte[] reassemble(byte[] frag, int flags, long totalLen) {
            if (totalLen >= 0 && totalLen > EAP_TLS_MAX_IN) {
                throw new IllegalArgumentException("EAP-TLS 数据超限");
            }
            boolean more = (flags & EAP_TLS_FLAG_MORE) != 0;
            if (pendingIn == null) {
                if (!more) {
                    if (totalLen >= 0 && frag.length != totalLen) {
                        throw new IllegalArgumentException("EAP-TLS 长度不符");
                    }
                    return frag;
                }
                int cap = totalLen >= 0 ? (int) totalLen : frag.length;
                if (cap > EAP_TLS_MAX_IN) {
                    throw new IllegalArgumentException("EAP-TLS 重组超限");
                }
                pendingIn = new byte[cap];
                System.arraycopy(frag, 0, pendingIn, 0, frag.length);
                pendingOff = frag.length;
                return null;
            }
            if (pendingOff + frag.length > pendingIn.length) {
                throw new IllegalArgumentException("EAP-TLS 重组溢出");
            }
            System.arraycopy(frag, 0, pendingIn, pendingOff, frag.length);
            pendingOff += frag.length;
            if (more) {
                return null;
            }
            byte[] full = pendingIn.length == pendingOff ? pendingIn : Arrays.copyOf(pendingIn, pendingOff);
            pendingIn = null;
            pendingOff = 0;
            return full;
        }

        /** 握手线程完成时唤醒等待方。 */
        void notifyOutput() {
            synchronized (lock) {
                lock.notifyAll();
            }
        }
    }

    /** 基于 BC 私钥的 TlsSigner：generateRawSignature 用 BC 原生引擎签名 TLS 握手哈希（TLS 1.2）。 */
    static final class ModpkicaTlsSigner implements TlsSigner {
        private final BcTlsCrypto crypto;
        private final AsymmetricKeyParameter key;

        ModpkicaTlsSigner(BcTlsCrypto crypto, AsymmetricKeyParameter key) {
            this.crypto = crypto;
            this.key = key;
        }

        @Override
        public byte[] generateRawSignature(SignatureAndHashAlgorithm alg, byte[] hash) throws IOException {
            try {
                if (key instanceof RSAKeyParameters) {
                    // PKCS#1 v1.5：对 DigestInfo(hash) 做原始 RSA 私钥运算（RSAEngine）
                    ASN1ObjectIdentifier oid;
                    switch (alg.getHash()) {
                        case HashAlgorithm.sha1: oid = new ASN1ObjectIdentifier("1.3.14.3.2.26"); break;
                        case HashAlgorithm.sha256: oid = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"); break;
                        case HashAlgorithm.sha384: oid = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.2"); break;
                        case HashAlgorithm.sha512: oid = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.3"); break;
                        default: throw new IOException("不支持的 TLS 签名哈希: " + alg.getHash());
                    }
                    byte[] di = new DERSequence(new ASN1Encodable[]{
                            new AlgorithmIdentifier(oid),
                            new DEROctetString(hash)
                    }).getEncoded();
                    // TLS 1.2 RSA 签名 = PKCS#1 v1.5 填充的 DigestInfo 模幂（EM=0x00 01 FF..FF 00 || DI）
                    RSAKeyParameters rsaKey = (RSAKeyParameters) key;
                    int modLen = (rsaKey.getModulus().bitLength() + 7) / 8;
                    if (di.length > modLen - 11) {
                        throw new IOException("RSA 模长不足容纳 DigestInfo");
                    }
                    byte[] em = new byte[modLen];
                    em[0] = 0x00;
                    em[1] = 0x01;
                    int psLen = modLen - di.length - 3;
                    Arrays.fill(em, 2, 2 + psLen, (byte) 0xFF);
                    em[2 + psLen] = 0x00;
                    System.arraycopy(di, 0, em, 3 + psLen, di.length);
                    org.bouncycastle.crypto.engines.RSAEngine engine =
                            new org.bouncycastle.crypto.engines.RSAEngine();
                    engine.init(true, key);
                    return engine.processBlock(em, 0, em.length);
                }
                // ECDSA：对握手哈希直接 ECDSA 签名（r||s DER 编码，RFC 3279）
                org.bouncycastle.crypto.signers.ECDSASigner signer =
                        new org.bouncycastle.crypto.signers.ECDSASigner(
                                new org.bouncycastle.crypto.signers.HMacDSAKCalculator(
                                        new org.bouncycastle.crypto.digests.SHA256Digest()));
                signer.init(true, new org.bouncycastle.crypto.params.ParametersWithRandom(
                        key, new SecureRandom()));
                java.math.BigInteger[] rs = signer.generateSignature(hash);
                return new DERSequence(new ASN1Encodable[]{
                        new org.bouncycastle.asn1.ASN1Integer(rs[0]),
                        new org.bouncycastle.asn1.ASN1Integer(rs[1])
                }).getEncoded();
            } catch (IOException ioe) {
                throw ioe;
            } catch (Exception e) {
                throw new IOException("TLS 签名失败: " + e, e);
            }
        }

        @Override
        public org.bouncycastle.tls.crypto.TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm alg)
                throws IOException {
            // TLS 1.2 使用 generateRawSignature；流式签名（TLS 1.3）不需要
            return null;
        }
    }

    /** EAP-TLS 服务端 TlsServer：证书来自 PKI 证书库（CA 优先，回退 ROOT），仅协商 TLS 1.2。 */
    static final class ModpkicaTlsServer extends AbstractTlsServer {
        private final TlsServerCred cred;

        ModpkicaTlsServer(TlsServerCred cred) {
            super(cred.crypto);
            this.cred = cred;
        }

        @Override
        protected ProtocolVersion[] getSupportedVersions() {
            // EAP-TLS（RFC 5216）基于 TLS ≤1.2；TLS 1.3 属 RFC 9190 另行实现
            return new ProtocolVersion[]{ProtocolVersion.TLSv12};
        }

        @Override
        protected int[] getSupportedCipherSuites() {
            return new int[]{
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            };
        }

        @Override
        public TlsCredentials getCredentials() throws IOException {
            SignatureAndHashAlgorithm sig = cred.key instanceof RSAKeyParameters
                    ? new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa)
                    : new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa);
            TlsCryptoParameters cryptoParams = new TlsCryptoParameters(context);
            TlsSigner signer = new ModpkicaTlsSigner(cred.crypto, cred.key);
            TlsCertificate[] list = new TlsCertificate[cred.chain.length];
            for (int i = 0; i < cred.chain.length; i++) {
                try {
                    list[i] = cred.crypto.createCertificate(cred.chain[i].getEncoded());
                } catch (java.security.cert.CertificateEncodingException cee) {
                    throw new IOException("证书编码失败: " + cee, cee);
                }
            }
            return new DefaultTlsCredentialedSigner(cryptoParams, signer, new Certificate(list), sig);
        }

        @Override
        public org.bouncycastle.tls.CertificateRequest getCertificateRequest() throws IOException {
            // EAP-TLS 匿名客户端（RFC 5216 可选客户端证书；此处不强制）
            return null;
        }
    }

    /** EAP-TLS 调试客户端支持的 TLS 1.2 套件（与服务端一致）。 */
    static final int[] EAP_TLS_CIPHERS = new int[]{
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
    };

    /**
     * EAP-TLS 调试客户端：可选「信任锚证书」验证服务器证书链 + 可选「客户端证书/私钥」出示客户端凭据。
     * 未指定证书（trustAnchors 为空）时等同原匿名客户端——不校验服务器证书、无客户端凭据。
     */
    static final class TrustedTlsClient extends AbstractTlsClient {
        private final List<X509Certificate> trustAnchors;
        private final X509Certificate clientCert;
        private final AsymmetricKeyParameter clientKey;
        private final TlsCrypto tlsCrypto;

        TrustedTlsClient(TlsCrypto crypto, List<X509Certificate> trustAnchors,
                         X509Certificate clientCert, AsymmetricKeyParameter clientKey) {
            super(crypto);
            this.tlsCrypto = crypto;
            this.trustAnchors = trustAnchors;
            this.clientCert = clientCert;
            this.clientKey = clientKey;
        }

        @Override
        protected ProtocolVersion[] getSupportedVersions() {
            return new ProtocolVersion[]{ProtocolVersion.TLSv12};
        }

        @Override
        protected int[] getSupportedCipherSuites() {
            return EAP_TLS_CIPHERS;
        }

        @Override
        public TlsAuthentication getAuthentication() throws IOException {
            return new TlsAuthentication() {
                @Override
                public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException {
                    if (trustAnchors == null || trustAnchors.isEmpty()) {
                        return;   // 未指定证书：调试模式不校验
                    }
                    Certificate chain = serverCertificate.getCertificate();
                    if (chain == null || chain.getCertificateList() == null
                            || chain.getCertificateList().length == 0) {
                        throw new IOException("服务器未提供证书链");
                    }
                    try {
                        verifyServerChain(chain.getCertificateList(), trustAnchors);
                    } catch (IOException ioe) {
                        throw ioe;
                    } catch (Exception ex) {
                        throw new IOException("服务器证书验证失败: " + ex.getMessage(), ex);
                    }
                }

                @Override
                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException {
                    if (clientCert == null || clientKey == null) {
                        return null;   // 未指定客户端证书：匿名
                    }
                    SignatureAndHashAlgorithm sig = clientKey instanceof RSAKeyParameters
                            ? new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa)
                            : new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa);
                    TlsCryptoParameters cryptoParams = new TlsCryptoParameters(context);
                    TlsSigner signer = new ModpkicaTlsSigner((BcTlsCrypto) tlsCrypto, clientKey);
                    try {
                        TlsCertificate tc = ((BcTlsCrypto) tlsCrypto).createCertificate(clientCert.getEncoded());
                        return new DefaultTlsCredentialedSigner(cryptoParams, signer,
                                new Certificate(new TlsCertificate[]{tc}), sig);
                    } catch (Exception ex) {
                        throw new IOException("客户端证书准备失败: " + ex.getMessage(), ex);
                    }
                }
            };
        }
    }

    /** 用所选信任锚证书验证服务器证书链（逐级签名校验，链顶必须锚定到某一信任证书）。 */
    private static void verifyServerChain(TlsCertificate[] list, List<X509Certificate> anchors)
            throws Exception {
        if (list == null || list.length == 0) {
            throw new IOException("空证书链");
        }
        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
        X509Certificate[] chain = new X509Certificate[list.length];
        for (int i = 0; i < list.length; i++) {
            try {
                chain[i] = (X509Certificate) cf.generateCertificate(
                        new java.io.ByteArrayInputStream(list[i].getEncoded()));
            } catch (Exception ex) {
                throw new IOException("服务器证书解码失败: " + ex.getMessage(), ex);
            }
        }
        // 逐级验证：每一级由下一级证书签发
        for (int i = 0; i < chain.length - 1; i++) {
            X509Certificate c = chain[i];
            if (!c.getIssuerX500Principal().equals(chain[i + 1].getSubjectX500Principal())) {
                throw new IOException("证书链第 " + (i + 1) + " 级颁发者不连续");
            }
            try {
                c.verify(chain[i + 1].getPublicKey());
            } catch (Exception ex) {
                throw new IOException("证书链第 " + (i + 1) + " 级签名验证失败", ex);
            }
        }
        // 链顶（最后一个）必须被某个信任锚签发，或与某信任锚相同
        X509Certificate top = chain[chain.length - 1];
        for (X509Certificate a : anchors) {
            if (top.equals(a)) {
                return;
            }
            if (top.getIssuerX500Principal().equals(a.getSubjectX500Principal())) {
                top.verify(a.getPublicKey());
                return;
            }
        }
        throw new IOException("证书链未锚定到所选信任证书（序列号不在链顶或未被其签发）");
    }

    /** 解析后的 RADIUS 包。 */
    private static final class Packet {
        int code;
        int identifier;
        byte[] authenticator = new byte[16];
        List<Attr> attrs = new ArrayList<>();

        byte[] getAttr(int type) {
            for (Attr a : attrs) {
                if (a.type == type) {
                    return a.value;
                }
            }
            return null;
        }

        List<byte[]> getAttrs(int type) {
            List<byte[]> out = new ArrayList<>();
            for (Attr a : attrs) {
                if (a.type == type) {
                    out.add(a.value);
                }
            }
            return out;
        }

        String getString(int type) {
            byte[] v = getAttr(type);
            return v == null ? null : new String(v, StandardCharsets.UTF_8);
        }

        int getInt(int type) {
            byte[] v = getAttr(type);
            if (v == null || v.length == 0) {
                return 0;
            }
            int n = 0;
            for (byte b : v) {
                n = (n << 8) | (b & 0xff);
            }
            return n;
        }
    }

    private static final class Attr {
        int type;
        byte[] value;

        Attr(int type, byte[] value) {
            this.type = type;
            this.value = value;
        }
    }

    // ==================== 构造 ====================

    public RadiusServer(String baseDir) {
        this.baseDir = baseDir;
    }

    // ==================== 启停 ====================

    /** 启动 RADIUS 服务（认证端口 + 计费端口 + 共享密钥）。端口被占用或密钥为空时抛异常。 */
    public synchronized String start(int authPort, int acctPort, String secret) throws Exception {
        if (secret == null || secret.trim().isEmpty()) {
            throw new IllegalArgumentException("共享密钥不能为空");
        }
        if (running) {
            stop();
        }
        this.authPort = authPort <= 0 ? DEFAULT_AUTH_PORT : authPort;
        this.acctPort = acctPort <= 0 ? DEFAULT_ACCT_PORT : acctPort;
        this.secret = secret;

        DatagramSocket a = new DatagramSocket(this.authPort);
        DatagramSocket c = new DatagramSocket(this.acctPort);
        authSock = a;
        acctSock = c;
        running = true;
        startTime = System.currentTimeMillis();

        authThread = new Thread(() -> loop(authSock, true), "radius-auth");
        acctThread = new Thread(() -> loop(acctSock, false), "radius-acct");
        authThread.setDaemon(true);
        acctThread.setDaemon(true);
        authThread.start();
        acctThread.start();

        int n = UsersDB.load(baseDir).size();
        addLog("RADIUS 服务器已启动，认证端口=" + this.authPort
                + "，计费端口=" + this.acctPort + "，密钥=" + this.secret);
        addLog("已加载 " + n + " 个账号（PKI/USERS.txt）");
        addLog("正在等待 NAS 的 request 消息，如果没有，请检查 NAS 配置。");
        MLog.append(baseDir, "Radius 服务启动",
                "authPort=" + this.authPort + " acctPort=" + this.acctPort,
                "RADIUS 服务器已启动，账号数=" + n);
        return "RADIUS 服务器已启动（认证 " + this.authPort + " / 计费 " + this.acctPort
                + "，已加载 " + n + " 个账号）";
    }

    /** 停止 RADIUS 服务。 */
    public synchronized String stop() {
        if (!running) {
            return "RADIUS 服务未在运行";
        }
        running = false;
        closeQuietly(authSock);
        closeQuietly(acctSock);
        authSock = null;
        acctSock = null;
        if (authThread != null) {
            authThread.interrupt();
            authThread = null;
        }
        if (acctThread != null) {
            acctThread.interrupt();
            acctThread = null;
        }
        eapStates.clear();
        addLog("RADIUS 服务器已停止");
        MLog.append(baseDir, "Radius 服务停止", "", "RADIUS 服务器已停止");
        return "RADIUS 服务器已停止";
    }

    public boolean isRunning() {
        return running;
    }

    private static void closeQuietly(DatagramSocket s) {
        if (s != null) {
            try {
                s.close();
            } catch (Exception ignored) {
            }
        }
    }

    // ==================== 接收循环 ====================

    private void loop(DatagramSocket sock, boolean auth) {
        byte[] buf = new byte[4096];
        while (running) {
            try {
                DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                sock.receive(pkt);
                byte[] resp = auth ? handleAccess(pkt) : handleAcct(pkt);
                if (resp != null) {
                    sock.send(new DatagramPacket(resp, resp.length, pkt.getAddress(), pkt.getPort()));
                }
            } catch (SocketException e) {
                break; // socket 已关闭
            } catch (Exception e) {
                addLog("处理请求异常: " + e);
            }
        }
    }

    // ==================== 认证处理 ====================

    private byte[] handleAccess(DatagramPacket pkt) {
        totalAuthRequests++;
        Packet p;
        try {
            p = parsePacket(pkt.getData(), pkt.getLength());
        } catch (Exception e) {
            addLog("认证包解析失败 来源=" + pkt.getAddress().getHostAddress() + " " + e
                    + " hex=" + hexFull(Arrays.copyOfRange(pkt.getData(), 0, pkt.getLength())));
            return null;
        }
        if (p.code != CODE_ACCESS_REQUEST) {
            return null;
        }
        String src = pkt.getAddress().getHostAddress() + ":" + pkt.getPort();
        String username = p.getString(ATTR_USER_NAME);

        // 校验 Message-Authenticator（EAP 请求必须携带；有则校验，失败直接拒绝）
        byte[] ma = p.getAttr(ATTR_MESSAGE_AUTHENTICATOR);
        if (ma != null && !verifyMessageAuthenticator(pkt.getData(), pkt.getLength(), p.identifier, secret)) {
            addLog("Message-Authenticator 校验失败 来源=" + src + " 用户=" + username);
            return buildAuthResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    null, username, pkt.getAddress(), "认证失败");
        }

        // 隧道属性（RFC 2867/2868：PPTP/L2TP/IPsec 等）解析并记录
        logTunnelAttrs(p, src, username, "认证");

        // 1) EAP（RFC 3579 §2.1：EAP-Message 可多属性，按出现顺序拼接还原）
        byte[] eap = getEapMessageConcat(p);
        if (eap != null) {
            addLog("[DBG] EAP 消息进入 type=" + (eap.length > 4 ? (eap[4] & 0xff) : -1)
                    + " len=" + eap.length + " 来源=" + src
                    + " hex=" + hexFull(eap));
            return handleEap(p, eap, src);
        }
        // 2) PAP
        byte[] encPw = p.getAttr(ATTR_USER_PASSWORD);
        if (encPw != null) {
            return handlePap(p, encPw, src);
        }
        // 3) CHAP
        byte[] chap = p.getAttr(ATTR_CHAP_PASSWORD);
        if (chap != null) {
            return handleChap(p, chap, src);
        }
        // 4) MS-CHAP（Vendor-Specific Microsoft，v2 响应 Vendor-Type=25 / v1 响应 Vendor-Type=24）
        List<byte[]> vsas = p.getAttrs(ATTR_VENDOR_SPECIFIC);
        if (!vsas.isEmpty()) {
            if (hasMsChapVsa(MS_CHAP2_RESPONSE, vsas)) {
                return handleMsChapV2(p, vsas, src);
            }
            if (hasMsChapVsa(MS_CHAP1_RESPONSE, vsas)) {
                return handleMsChapV1(p, vsas, src);
            }
        }
        addLog("收到 NAS 请求（无认证属性） 来源=" + src + " 用户=" + username + " 结果=拒绝");
        authFail++;
        return buildAuthResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                null, username, pkt.getAddress(), "缺少认证属性");
    }

    // ---------- PAP ----------

    private byte[] handlePap(Packet p, byte[] encPw, String src) {
        String username = p.getString(ATTR_USER_NAME);
        String clear = decodeUserPassword(encPw, p.authenticator, secret);
        UsersDB.User u = username == null ? null : UsersDB.find(baseDir, username);
        boolean ok = u != null && u.enabled() && clear != null && constantTimeEquals(
                clear.getBytes(StandardCharsets.UTF_8), u.password.getBytes(StandardCharsets.UTF_8));
        logAuthResult(src, username, "PAP", ok, null);
        return buildAuthResponse(ok ? CODE_ACCESS_ACCEPT : CODE_ACCESS_REJECT,
                p.identifier, p.authenticator, u, username, null, ok ? "认证通过" : "认证失败");
    }

    // ---------- CHAP ----------

    private byte[] handleChap(Packet p, byte[] chap, String src) {
        String username = p.getString(ATTR_USER_NAME);
        if (chap.length != 17) {
            authFail++;
            addLog("CHAP 属性长度非法 来源=" + src + " 用户=" + username);
            return buildAuthResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    null, username, null, "CHAP 属性错误");
        }
        byte[] challenge = p.getAttr(ATTR_CHAP_CHALLENGE);
        if (challenge == null) {
            challenge = p.authenticator; // RFC 2865：无 CHAP-Challenge 时用请求 Authenticator
        }
        UsersDB.User u = username == null ? null : UsersDB.find(baseDir, username);
        boolean ok = false;
        if (u != null && u.enabled()) {
            byte[] expect = md5(concat(new byte[]{chap[0]}, u.password.getBytes(StandardCharsets.UTF_8), challenge));
            ok = constantTimeEquals(expect, Arrays.copyOfRange(chap, 1, 17));
        }
        logAuthResult(src, username, "CHAP", ok, null);
        return buildAuthResponse(ok ? CODE_ACCESS_ACCEPT : CODE_ACCESS_REJECT,
                p.identifier, p.authenticator, u, username, null, ok ? "认证通过" : "认证失败");
    }

    // ---------- MS-CHAPv2（RFC 2548 / 2759） ----------

    private byte[] handleMsChapV2(Packet p, List<byte[]> vsas, String src) {
        String username = p.getString(ATTR_USER_NAME);
        byte[] authChallenge = null;
        byte[] ntResponse = null;
        byte[] peerChallenge = null;
        for (byte[] vsa : vsas) {
            MsChapVsa parsed = parseMsChapVsa(vsa);
            if (parsed == null) {
                continue;
            }
            if (parsed.vendorType == MS_CHAP_CHALLENGE && parsed.data.length == 16) {
                authChallenge = parsed.data;
            } else if (parsed.vendorType == MS_CHAP2_RESPONSE && parsed.data.length >= 50) {
                // 结构: Ident(1) Flags(1) PeerChallenge(16) Reserved(8) NT-Response(24) Flags(1)
                peerChallenge = Arrays.copyOfRange(parsed.data, 2, 18);
                ntResponse = Arrays.copyOfRange(parsed.data, 26, 50);
            }
        }
        if (authChallenge == null || ntResponse == null || peerChallenge == null) {
            authFail++;
            addLog("MS-CHAPv2 属性不完整 来源=" + src + " 用户=" + username);
            return buildAuthResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    null, username, null, "MS-CHAPv2 属性缺失");
        }
        UsersDB.User u = username == null ? null : UsersDB.find(baseDir, username);
        boolean ok = false;
        if (u != null && u.enabled()) {
            ok = verifyMsChapV2(u.password, username, peerChallenge, authChallenge, ntResponse);
        }
        logAuthResult(src, username, "MS-CHAPv2", ok, null);
        return buildAuthResponse(ok ? CODE_ACCESS_ACCEPT : CODE_ACCESS_REJECT,
                p.identifier, p.authenticator, u, username, null, ok ? "认证通过" : "认证失败");
    }

    // ---------- MS-CHAPv1（RFC 2433，PPTP/拨号场景） ----------

    /** 判断 VSA 列表中是否存在指定 Vendor-Type。 */
    private static boolean hasMsChapVsa(int vendorType, List<byte[]> vsas) {
        for (byte[] vsa : vsas) {
            MsChapVsa parsed = parseMsChapVsa(vsa);
            if (parsed != null && parsed.vendorType == vendorType) {
                return true;
            }
        }
        return false;
    }

    /** MS-CHAPv1 认证：Challenge（8 字节，Vendor-Type=11）+ MS-CHAP-Response（49 字节，Vendor-Type=24）。 */
    private byte[] handleMsChapV1(Packet p, List<byte[]> vsas, String src) {
        String username = p.getString(ATTR_USER_NAME);
        byte[] challenge = null;
        byte[] ntResponse = null;
        for (byte[] vsa : vsas) {
            MsChapVsa parsed = parseMsChapVsa(vsa);
            if (parsed == null) {
                continue;
            }
            if (parsed.vendorType == MS_CHAP_CHALLENGE && parsed.data.length == 8) {
                challenge = parsed.data;
            } else if (parsed.vendorType == MS_CHAP1_RESPONSE && parsed.data.length >= 49) {
                // 结构: Ident(1) LM-Response(24) NT-Response(24)
                ntResponse = Arrays.copyOfRange(parsed.data, 25, 49);
            }
        }
        if (challenge == null || ntResponse == null) {
            authFail++;
            addLog("MS-CHAPv1 属性不完整 来源=" + src + " 用户=" + username);
            return buildAuthResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    null, username, null, "MS-CHAPv1 属性缺失");
        }
        UsersDB.User u = username == null ? null : UsersDB.find(baseDir, username);
        boolean ok = u != null && u.enabled() && verifyMsChapV1(u.password, challenge, ntResponse);
        logAuthResult(src, username, "MS-CHAPv1", ok, null);
        return buildAuthResponse(ok ? CODE_ACCESS_ACCEPT : CODE_ACCESS_REJECT,
                p.identifier, p.authenticator, u, username, null, ok ? "认证通过" : "认证失败");
    }

    // ---------- EAP（RFC 3748） ----------

    private byte[] handleEap(Packet p, byte[] eap, String src) {
        String username = p.getString(ATTR_USER_NAME);
        // 第二阶段确认（MSCHAPV2_OK pending）：客户端收到方法层 Success 后回的确认 EAP-Response
        // （Len=4 空包，或 Type=26 空数据）→ 回 Access-Accept + MS-MPPE 密钥，完成认证。
        // 注意：Identity 等其它 EAP 类型不得触发 pending（防止新会话的 Identity 被误判为确认）。
        EapState pend = eapStates.get(src);
        if (pend != null && "MSCHAPV2_OK".equals(pend.method)
                && eap.length >= 1 && (eap[0] & 0xff) == EAP_CODE_RESPONSE
                && (eap.length == 4
                    || (eap.length >= 5 && (eap[4] & 0xff) == EAP_TYPE_MSCHAPV2))) {
            synchronized (eapStates) {
                eapStates.remove(src);
            }
            int eapId2 = eap.length > 1 ? (eap[1] & 0xff) : 0;
            List<Attr> mppe2 = List.of(
                    msMppeAttr(MS_MPPE_RECV_KEY, Arrays.copyOfRange(pend.msk, 0, 16),
                            p.authenticator, secret),
                    msMppeAttr(MS_MPPE_SEND_KEY, Arrays.copyOfRange(pend.msk, 16, 32),
                            p.authenticator, secret));
            addLog("[DBG] EAP-MSCHAPV2 客户端确认 Success，已下发 MS-MPPE 密钥（用户=" + pend.username + "）");
            return buildEapResponse(CODE_ACCESS_ACCEPT, p.identifier, p.authenticator,
                    pend.username, eapId2, EAP_CODE_SUCCESS, -1, null,
                    "EAP-MSCHAPV2 认证通过", mppe2);
        }
        if (eap.length < 5 || (eap[0] & 0xff) != EAP_CODE_RESPONSE) {
            authFail++;
            addLog("EAP 响应格式非法 来源=" + src);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eap.length > 1 ? eap[1] & 0xff : 0, EAP_CODE_FAILURE, null, "EAP 格式错误");
        }
        int eapId = eap[1] & 0xff;
        int type = eap[4] & 0xff;
        byte[] data = eap.length > 5 ? Arrays.copyOfRange(eap, 5, eap.length) : new byte[0];

        switch (type) {
            case EAP_TYPE_IDENTITY: {
                String name = new String(data, StandardCharsets.UTF_8).trim();
                // 用户名带 peap-gtc:/eap-peap-gtc: 前缀 → PEAP 内层 GTC
                if (name.regionMatches(true, 0, "peap-gtc:", 0, 9)
                        || name.regionMatches(true, 0, "eap-peap-gtc:", 0, 14)) {
                    return startEapPeap(p, eapId, name, src, "GTC");
                }
                // 用户名带 peap-mschapv2:/eap-peap-mschapv2: 前缀 → PEAP 内层 MS-CHAPv2
                if (name.regionMatches(true, 0, "peap-mschapv2:", 0, 14)
                        || name.regionMatches(true, 0, "eap-peap-mschapv2:", 0, 18)) {
                    return startEapPeap(p, eapId, name, src, "MSCHAPV2");
                }
                // 用户名带 peap:/eap-peap: 前缀 → 走 PEAP（RFC 5216，外层 TLS + 内层 EAP-MD5）
                if (name.regionMatches(true, 0, "peap:", 0, 5)
                        || name.regionMatches(true, 0, "eap-peap:", 0, 9)) {
                    return startEapPeap(p, eapId, name, src, "MD5");
                }
                // 用户名带 tls:/eap-tls: 前缀 → 走 EAP-TLS（RFC 5216）通道
                if (name.regionMatches(true, 0, "tls:", 0, 4)
                        || name.regionMatches(true, 0, "eap-tls:", 0, 8)) {
                    return startEapTls(p, eapId, name, src);
                }
                // 用户名带 ttls:/eap-ttls: 前缀 → 走 EAP-TTLS（RFC 5281）隧道
                if (name.regionMatches(true, 0, "ttls:", 0, 5)
                        || name.regionMatches(true, 0, "eap-ttls:", 0, 9)) {
                    return startEapTtls(p, eapId, name, src);
                }
                // 用户名带 pwd:/eap-pwd: 前缀 → EAP-pwd（RFC 5931，P-256）
                if (name.regionMatches(true, 0, "pwd:", 0, 4)
                        || name.regionMatches(true, 0, "eap-pwd:", 0, 8)) {
                    return startEapPwd(p, eapId, name, src);
                }
                // 用户名带 mschapv2:/eap-mschapv2: 前缀 → 独立 EAP-MSCHAPv2（RFC 2759 / EAP-MSCHAPv2，EAP 类型 26）
                if (name.regionMatches(true, 0, "mschapv2:", 0, 9)
                        || name.regionMatches(true, 0, "eap-mschapv2:", 0, 13)) {
                    return startEapMsChapV2(p, eapId, name, src);
                }
                // 用户名带 md5:/eap-md5: 前缀 → EAP-MD5（RFC 3748 / 2284）
                if (name.regionMatches(true, 0, "md5:", 0, 4)
                        || name.regionMatches(true, 0, "eap-md5:", 0, 8)) {
                    return startEapMd5(p, eapId, name, src);
                }
                // 用户名带 gtc:/eap-gtc: 前缀 → GTC（RFC 3748 §5.6）：回提示文本请求明文令牌
                if (name.regionMatches(true, 0, "gtc:", 0, 4)
                        || name.regionMatches(true, 0, "eap-gtc:", 0, 8)) {
                    String realUser = name.startsWith("gtc:") ? name.substring(4)
                            : name.substring(8);
                    UsersDB.User g = realUser.isEmpty() ? null : UsersDB.find(baseDir, realUser);
                    if (g == null || !g.enabled()) {
                        addLog("EAP-GTC 用户不存在或停用 来源=" + src + " 用户=" + realUser);
                        authFail++;
                        return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                                name, eapId, EAP_CODE_FAILURE, null, "用户不存在或停用");
                    }
                    EapState st = new EapState();
                    st.username = realUser;
                    st.method = "GTC";
                    st.expires = System.currentTimeMillis() + EAP_STATE_TTL_MS;
                    synchronized (eapStates) {
                        eapStates.put(src, st);
                        evictEapStates();
                    }
                    addLog("EAP-Identity 已接受 来源=" + src + " 用户=" + realUser + " → 发送 GTC 提示");
                    return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                            name, eapId, EAP_CODE_REQUEST, EAP_TYPE_GTC,
                            "Enter Password: ".getBytes(StandardCharsets.UTF_8), null);
                }
                // 无前缀（裸用户名）→ 默认 EAP-MSCHAPv2：strongSwan eap-radius / iOS / Windows
                // 拨号客户端只发纯用户名，业界事实标准即 EAP-MSCHAPv2（RFC 2759，EAP 类型 26）
                if (name.isEmpty()) {
                    addLog("EAP-Identity 用户名为空 来源=" + src);
                    authFail++;
                    return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                            name, eapId, EAP_CODE_FAILURE, null, "用户名为空");
                }
                return startEapMsChapV2(p, eapId, name, src);
            }
            case EAP_TYPE_NAK: {
                // RFC 3748 §5.3：客户端 NAK 当前方法（如 MD5）并列出其支持的 EAP 类型列表。
                // 复刻 FreeRADIUS rlm_eap 标准协商：MD5 协商轮被 NAK（数据含 0x1a=MSCHAPV2）后
                // 转入 EAP-MSCHAPv2，挑战 EAP id = NAK id + 1（严格递增）。
                EapState st = takeEapState(src);
                if (st == null || !"MSCHAPV2_PRE".equals(st.method)) {
                    authFail++;
                    addLog("EAP-NAK 状态失效 来源=" + src + " 用户=" + username);
                    return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                            username, eapId, EAP_CODE_FAILURE, null, "EAP-NAK 状态失效");
                }
                boolean wantsMschapV2 = false;
                for (byte b : data) {
                    if ((b & 0xff) == EAP_TYPE_MSCHAPV2) {
                        wantsMschapV2 = true;
                        break;
                    }
                }
                if (!wantsMschapV2) {
                    authFail++;
                    addLog("EAP-NAK 不支持 MSCHAPV2 来源=" + src + " 用户=" + st.username);
                    return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                            username, eapId, EAP_CODE_FAILURE, null, "客户端不支持 EAP-MSCHAPV2");
                }
                st.method = "MSCHAPV2";
                st.expires = System.currentTimeMillis() + EAP_STATE_TTL_MS;
                synchronized (eapStates) {
                    eapStates.put(src, st);
                    evictEapStates();
                }
                // ② EAP-Request/MSCHAPv2 Challenge，EAP id = NAK id + 1（=2）。
                byte[] chalData = buildMschapv2ChallengeData(st);
                addLog("EAP-MSCHAPV2 下发挑战 来源=" + src + " 用户=" + st.username
                        + " EAP-id=" + ((eapId + 1) & 0xff));
                return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                        username, (eapId + 1) & 0xff, EAP_CODE_REQUEST, EAP_TYPE_MSCHAPV2,
                        chalData, null);
            }
            case EAP_TYPE_MD5: {
                EapState st = takeEapState(src);
                if (st == null || !"MD5".equals(st.method) || data.length < 17 || (data[0] & 0xff) != 16) {
                    authFail++;
                    addLog("EAP-MD5 状态失效或响应非法 来源=" + src + " 用户=" + username);
                    return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                            username, eapId, EAP_CODE_FAILURE, null, "EAP-MD5 状态失效");
                }
                UsersDB.User u = UsersDB.find(baseDir, st.username);
                byte[] expect = md5(concat(new byte[]{(byte) eapId},
                        u == null ? new byte[0] : u.password.getBytes(StandardCharsets.UTF_8), st.challenge));
                byte[] got = Arrays.copyOfRange(data, 1, 17);
                boolean ok = u != null && u.enabled() && constantTimeEquals(expect, got);
                logAuthResult(src, st.username, "EAP-MD5", ok, "EAP");
                return buildEapResponse(ok ? CODE_ACCESS_ACCEPT : CODE_ACCESS_REJECT,
                        p.identifier, p.authenticator, st.username, eapId,
                        ok ? EAP_CODE_SUCCESS : EAP_CODE_FAILURE, null,
                        ok ? "EAP-MD5 认证通过" : "EAP-MD5 认证失败");
            }
            case EAP_TYPE_GTC: {
                // RFC 3748 §5.6：EAP-Response/GTC 携带明文令牌/口令（隧道外明文，仅适合受控环境）
                EapState st = takeEapState(src);
                if (st == null || !"GTC".equals(st.method)) {
                    authFail++;
                    addLog("EAP-GTC 状态失效或响应非法 来源=" + src);
                    return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                            username, eapId, EAP_CODE_FAILURE, null, "EAP-GTC 状态失效");
                }
                String token = new String(data, StandardCharsets.UTF_8).trim();
                UsersDB.User u = UsersDB.find(baseDir, st.username);
                boolean ok = u != null && u.enabled() && constantTimeEquals(
                        u.password.getBytes(StandardCharsets.UTF_8), token.getBytes(StandardCharsets.UTF_8));
                logAuthResult(src, st.username, "EAP-GTC", ok, "EAP");
                return buildEapResponse(ok ? CODE_ACCESS_ACCEPT : CODE_ACCESS_REJECT,
                        p.identifier, p.authenticator, st.username, eapId,
                        ok ? EAP_CODE_SUCCESS : EAP_CODE_FAILURE, null,
                        ok ? "EAP-GTC 认证通过" : "EAP-GTC 认证失败");
            }
            case EAP_TYPE_MSCHAPV2: {
                // RFC 2759 §3.4 EAP-MSCHAPv2 Response:
                //   OpCode(1)=2, MS-CHAPv2-ID(1), MS-Length(2), Value-Size(1)=49,
                //   Value(49B = Peer-Challenge(16) + Reserved(8) + NT-Response(24) + Flags(1)), Name
                if (data.length < 5 || (data[0] & 0xff) != 2 /* OpCode=Response */) {
                    authFail++;
                    addLog("EAP-MSCHAPv2 响应格式非法 来源=" + src);
                    return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                            username, eapId, EAP_CODE_FAILURE, null, "EAP-MSCHAPv2 格式错误");
                }
                int valueSize = data[4] & 0xff;
                if (data.length < 5 + valueSize || valueSize < 49) {
                    authFail++;
                    addLog("EAP-MSCHAPv2 响应数据过短 来源=" + src);
                    return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                            username, eapId, EAP_CODE_FAILURE, null, "EAP-MSCHAPv2 数据过短");
                }
                byte[] value = Arrays.copyOfRange(data, 5, 5 + valueSize);
                byte[] peerChallenge = Arrays.copyOfRange(value, 0, 16);
                byte[] ntResponse = Arrays.copyOfRange(value, 24, 48);
                EapState st = takeEapState(src);
                if (st == null || !"MSCHAPV2".equals(st.method)) {
                    authFail++;
                    addLog("EAP-MSCHAPv2 状态失效 来源=" + src);
                    return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                            username, eapId, EAP_CODE_FAILURE, null, "EAP-MSCHAPv2 状态失效");
                }
                UsersDB.User u = UsersDB.find(baseDir, st.username);
                boolean ok = u != null && u.enabled()
                        && verifyMsChapV2(u.password, st.username, peerChallenge, st.challenge, ntResponse);
                logAuthResult(src, st.username, "EAP-MSCHAPv2", ok, "EAP");
                List<Attr> mppe = null;
                byte[] successData = null;
                if (ok) {
                    byte[] ntHash = ntPasswordHash(u.password);
                    // RFC 3079 §3.1 + RFC 2548 §2.4.3：派生 MSK（第二阶段 Access-Accept 下发 MPPE）
                    byte[] msk = deriveMschapv2Msk(ntHash, ntResponse);
                    // RFC 2759 §4.7/§8.1：方法层 Success（EAP-Request/Type=26，OpCode=3 + 42B 验证器）。
                    // strongSwan eap-radius 会丢弃 Access-Accept 中的 EAP-Message、自行生成顶层
                    // EAP-Success；Windows 原生 IKEv2 客户端严格要求先收到方法层 Success 并验证
                    // 凭据。因此按 FreeRADIUS 标准做法分两阶段：
                    //   ① 本阶段回 Access-Challenge（EAP-Message = 方法层 Success），strongSwan 转发给客户端；
                    //   ② 客户端回确认 EAP-Response 后，再回 Access-Accept（EAP-Success + MS-MPPE）。
                    successData = buildMschapv2Success(data[1] & 0xff,
                            peerChallenge, st.challenge, ntResponse, md4(ntHash), st.username);
                    EapState pending = new EapState();
                    pending.username = st.username;
                    pending.method = "MSCHAPV2_OK";
                    pending.msk = msk;
                    pending.expires = System.currentTimeMillis() + EAP_STATE_TTL_MS;
                    synchronized (eapStates) {
                        eapStates.put(src, pending);
                        evictEapStates();
                    }
                    addLog("[DBG] EAP-MSCHAPV2 认证通过，方法层 Success 已下发（等待客户端确认，"
                            + "MSK 前 32 字节 = " + hexFull(Arrays.copyOfRange(msk, 0, 32)) + "）");
                }
                // FreeRADIUS rlm_eap_mschapv2（eap_mschapv2_compose）：
                //   Success 载荷 MS-CHAPv2-ID = 客户端 MS-CHAPv2 消息的 MS-CHAPv2-ID（回显）；
                //   EAP 头 Identifier 由 rlm_eap 状态机每轮递增（response->id + 1）。
                // Windows 原生 IKEv2 客户端严格要求 Success 的 EAP Identifier 比其响应的
                // Identifier 递增（strongSwan App/Mac/Linux 不校验，故此前只有 Windows 失败）。
                return buildEapResponse(ok ? CODE_ACCESS_CHALLENGE : CODE_ACCESS_REJECT,
                        p.identifier, p.authenticator, st.username, (eapId + 1) & 0xff,
                        ok ? EAP_CODE_REQUEST : EAP_CODE_FAILURE,
                        ok ? EAP_TYPE_MSCHAPV2 : -1,
                        ok ? successData : null,
                        ok ? "EAP-MSCHAPv2 认证通过（等待确认）" : "EAP-MSCHAPv2 认证失败", mppe);
            }
            case EAP_TYPE_TLS:
                return handleEapTls(p, eapId, data, src);
            case EAP_TYPE_PEAP:
                return handleEapPeap(p, eapId, data, src);
            case EAP_TYPE_TTLS:
                return handleEapTtls(p, eapId, data, src);
            case EAP_TYPE_PWD:
                return handleEapPwd(p, eapId, data, src);
            default:
                authFail++;
                addLog("不支持的 EAP 类型=" + type + " 来源=" + src + " 用户=" + username);
                return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                        username, eapId, EAP_CODE_FAILURE, null, "不支持的 EAP 类型");
        }
    }

    // ---------- EAP-TLS（RFC 5216：EAP 承载 TLS 1.2 握手，BC TlsServerProtocol） ----------

    /**
     * EAP-TLS 入口（客户端 EAP-Identity 带 tls:/eap-tls: 前缀）：
     * 加载服务端证书 → 建会话 → 启动 BC 握手线程 → 回 EAP-Request/TLS Start。
     */
    private byte[] startEapTls(Packet p, int eapId, String username, String src) {
        TlsServerCred cred = loadTlsServerCred();
        if (cred == null) {
            authFail++;
            addLog("EAP-TLS 无可用服务端证书 来源=" + src + " 用户=" + username);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "EAP-TLS 服务端证书缺失");
        }
        int radiusId = p.identifier;
        EapTlsSession s = new EapTlsSession(username);
        tlsSessions.put(radiusId, s);
        s.thread = new Thread(() -> {
            try {
                ModpkicaTlsServer server = new ModpkicaTlsServer(cred);
                TlsServerProtocol proto = new TlsServerProtocol(s.inStream, s.outStream);
                proto.accept(server);
                s.ok = true;
            } catch (Exception ex) {
                s.err = ex.toString();
            } finally {
                s.done = true;
                s.notifyOutput();
            }
        }, "eap-tls-handshake");
        s.thread.setDaemon(true);
        s.thread.start();
        addLog("EAP-TLS 启动握手 来源=" + src + " 用户=" + username);
        return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                username, eapId, EAP_CODE_REQUEST, EAP_TYPE_TLS,
                eapTlsFragments(new byte[0], 0, true), null);
    }

    /** 启动独立 EAP-MSCHAPv2 认证（RFC 2759，EAP 类型 26）：校验用户并下发 MSCHAPv2 挑战。
     *  支持 mschapv2:/eap-mschapv2: 前缀与裸用户名（strongSwan eap-radius / iOS / Windows 拨号客户端）。
     *  复刻 FreeRADIUS rlm_eap 标准协商流程（2026-10-06 网关对照实验证明 Windows 原生 IKEv2 客户端需要）：
     *    ① 先发 EAP-MD5 挑战（EAP id = identity 响应 id + 1），客户端回 EAP-NAK 并列出可用方法 [MSCHAPV2]；
     *    ② 收到 NAK 后发 EAP-MSCHAPv2 挑战（EAP id = NAK id + 1），客户端回 NT-Response；
     *    ③ 验证通过后发方法层 Success（EAP id = Response id + 1），客户端回确认；
     *    ④ 收到确认后回 Access-Accept（EAP-Success + MS-MPPE 密钥）。
     *  关键：EAP 标识符必须严格递增（identity 由 strongSwan 用 id=0 发起，此处 MD5=1、MSCHAPV2=2、
     *  Success=3）。Windows raschap 严格校验该序列，跳号（如 0→0→3）会被静默丢弃，表现为 645
     *  “内部身份验证错误”；同网关下 FreeRADIUS 用 0→1→2→3 即可成功连接（决定性对照证据）。 */
    private byte[] startEapMsChapV2(Packet p, int eapId, String name, String src) {
        String realUser = name.startsWith("mschapv2:") ? name.substring(9)
                : (name.startsWith("eap-mschapv2:") ? name.substring(13) : name);
        UsersDB.User m = realUser.isEmpty() ? null : UsersDB.find(baseDir, realUser);
        if (m == null || !m.enabled()) {
            addLog("EAP-MSCHAPv2 用户不存在或停用 来源=" + src + " 用户=" + realUser);
            authFail++;
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    name, eapId, EAP_CODE_FAILURE, null, "用户不存在或停用");
        }
        EapState st = new EapState();
        st.username = realUser;
        st.method = "MSCHAPV2_PRE";   // 先走 MD5 协商轮，客户端 NAK 后转入 MSCHAPV2
        st.challenge = new byte[16];  // MSCHAPV2 认证挑战（NAK 后下发）
        new java.security.SecureRandom().nextBytes(st.challenge);
        byte[] md5Challenge = new byte[16];  // 本轮 MD5 协商挑战
        new java.security.SecureRandom().nextBytes(md5Challenge);
        st.expires = System.currentTimeMillis() + EAP_STATE_TTL_MS;
        synchronized (eapStates) {
            eapStates.put(src, st);
            evictEapStates();
        }
        // ① EAP-Request/MD5（Type=4，RFC 3748 §5.4）：Value-Size(1)=16 + Value(16B 挑战)。
        //    EAP 标识符 = identity 响应 id + 1（严格递增）。
        byte[] md5Data = concat(new byte[]{16}, md5Challenge);
        addLog("EAP-MSCHAPv2 下发 MD5 协商挑战 来源=" + src + " 用户=" + realUser
                + " EAP-id=" + ((eapId + 1) & 0xff));
        return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                name, (eapId + 1) & 0xff, EAP_CODE_REQUEST, EAP_TYPE_MD5, md5Data, null);
    }

    /** 构造 EAP-Request/MSCHAPv2 Challenge 载荷（RFC 2759 §3.2）：
     *  OpCode(1)=1, MS-CHAPv2-ID(1), MS-Length(2), Value-Size(1)=16, Value(16B 挑战), Name。 */
    private byte[] buildMschapv2ChallengeData(EapState st) {
        byte mschapId = 0x02;
        byte[] nameB = "MODPKICA-MSCHAPV2".getBytes(StandardCharsets.UTF_8);
        // MS-Length = 整个 MS-CHAPv2 消息长度 = OpCode(1)+ID(1)+Len(2)+ValueSize(1)+Value(16)+Name
        int msLen = 1 + 1 + 2 + 1 + 16 + nameB.length;
        return concat(new byte[]{1, mschapId,
                (byte) (msLen >> 8), (byte) msLen, 16}, st.challenge, nameB);
    }

    /** 启动 EAP-MD5 认证（RFC 3748 §5.4）：下发挑战。支持 md5:/eap-md5: 前缀。 */
    private byte[] startEapMd5(Packet p, int eapId, String name, String src) {
        String realUser = name.startsWith("md5:") ? name.substring(4)
                : (name.startsWith("eap-md5:") ? name.substring(8) : name);
        byte[] challenge = new byte[16];
        new java.security.SecureRandom().nextBytes(challenge);
        EapState st = new EapState();
        st.username = realUser;
        st.challenge = challenge;
        st.method = "MD5";
        st.expires = System.currentTimeMillis() + EAP_STATE_TTL_MS;
        synchronized (eapStates) {
            eapStates.put(src, st);
            evictEapStates();
        }
        // EAP-Request/MD5 属性：Data = Value-Size(1) + 挑战(16) + 名称，
        // Type 由 buildEapResponse 的 eapType 参数写入（RFC 3748 EAP-MD5 挑战结构）
        byte[] eapReq = concat(new byte[]{16}, challenge,
                "MODPKICA".getBytes(StandardCharsets.UTF_8));
        addLog("EAP-Identity 已接受 来源=" + src + " 用户=" + realUser + " → 发送 MD5 挑战");
        return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                name, eapId, EAP_CODE_REQUEST, EAP_TYPE_MD5, eapReq, null);
    }

    /** 从流中读取一个完整 EAP 包（Code/Id/Length 头 + 载荷）。 */
    private static byte[] readEapPacket(InputStream in) throws Exception {
        int b0 = in.read();
        int b1 = in.read();
        int hi = in.read();
        int lo = in.read();
        if (b0 < 0 || b1 < 0 || hi < 0 || lo < 0) {
            throw new java.io.EOFException("EAP 包头不完整");
        }
        int len = ((hi & 0xff) << 8) | (lo & 0xff);
        if (len < 4 || len > EAP_TLS_MAX_IN) {
            throw new java.io.IOException("EAP 包长度非法: " + len);
        }
        byte[] pkt = new byte[len];
        pkt[0] = (byte) b0;
        pkt[1] = (byte) b1;
        pkt[2] = (byte) hi;
        pkt[3] = (byte) lo;
        int got = 4;
        while (got < len) {
            int n = in.read(pkt, got, len - got);
            if (n < 0) {
                throw new java.io.EOFException("EAP 包载荷不完整");
            }
            got += n;
        }
        return pkt;
    }

    /** PEAP 内层 EAP-MD5 认证（RFC 5216 §3.2 + RFC 3748 §5.4）：经 TLS 隧道交换挑战/响应。 */
    private boolean peapInnerMd5(TlsServerProtocol proto, String username) throws Exception {
        byte[] challenge = new byte[16];
        new java.security.SecureRandom().nextBytes(challenge);
        byte[] innerReq = eapPacket(EAP_CODE_REQUEST, (byte) 0x01, EAP_TYPE_MD5,
                concat(new byte[]{16}, challenge, "MODPKICA-PEAP".getBytes(StandardCharsets.UTF_8)));
        proto.getOutputStream().write(innerReq);
        proto.getOutputStream().flush();
        // 读内层 EAP 响应（TLS 应用数据 = EAP 包）
        byte[] pkt = readEapPacket(proto.getInputStream());
        if (pkt.length < 7 || (pkt[0] & 0xff) != EAP_CODE_RESPONSE || (pkt[4] & 0xff) != EAP_TYPE_MD5) {
            return false;
        }
        byte innerId = pkt[1];
        int vsize = pkt[5] & 0xff;
        if (pkt.length < 6 + vsize || vsize != 16) {
            return false;
        }
        byte[] md5Resp = Arrays.copyOfRange(pkt, 6, 6 + vsize);
        // MD5(Id || password || challenge)（RFC 3748）
        UsersDB.User u = UsersDB.find(baseDir, username);
        if (u == null || !u.enabled()) {
            return false;
        }
        byte[] expect = md5(concat(new byte[]{innerId}, u.password.getBytes(StandardCharsets.UTF_8), challenge));
        return java.security.MessageDigest.isEqual(expect, md5Resp);
    }

    /**
     * PEAP 内层 EAP-MS-CHAPv2（RFC 5216 §3.2 + RFC 2759 / EAP-MSCHAPv2）：
     * 隧道内 Identity → MS-CHAPv2 Challenge（OpCode=1）→ Response（OpCode=2）→ 验证 NT-Response。
     */
    private boolean peapInnerMsChapV2(TlsServerProtocol proto, String username) throws Exception {
        InputStream tin = proto.getInputStream();
        // [1] 隧道内 EAP-Request/Identity
        byte[] innerIdReq = eapPacket(EAP_CODE_REQUEST, (byte) 0x01, EAP_TYPE_IDENTITY, new byte[0]);
        proto.getOutputStream().write(innerIdReq);
        proto.getOutputStream().flush();
        byte[] idResp = readEapPacket(tin);
        if ((idResp[0] & 0xff) != EAP_CODE_RESPONSE || (idResp[4] & 0xff) != EAP_TYPE_IDENTITY) {
            return false;
        }
        // [2] EAP-Request/MSCHAPV2 Challenge：OpCode(1)=1, MS-CHAPv2-ID(1), MS-Length(2),
        //     Value-Size(1)=16, Value(16B 认证挑战), Name
        byte[] authChallenge = new byte[16];
        new java.security.SecureRandom().nextBytes(authChallenge);
        byte mschapId = 0x02;
        byte[] name = "MODPKICA-PEAP".getBytes(StandardCharsets.UTF_8);
        int msLen = 1 + 1 + 2 + 1 + 16 + name.length;   // RFC 2759 §3.2：21 + NameLen
        byte[] chalData = concat(new byte[]{1, mschapId,
                (byte) (msLen >> 8), (byte) msLen, 16}, authChallenge, name);
        byte[] chalReq = eapPacket(EAP_CODE_REQUEST, (byte) 0x02, EAP_TYPE_MSCHAPV2, chalData);
        proto.getOutputStream().write(chalReq);
        proto.getOutputStream().flush();
        // [3] EAP-Response/MSCHAPV2：OpCode(1)=2, MS-CHAPv2-ID(1), MS-Length(2),
        //     Value-Size(1)=49, Value(49B: Ident(1) Pad(1) PeerChallenge(16) Reserved(8) NT-Response(24) Flags(1)), Name
        byte[] resp = readEapPacket(tin);
        if (resp.length < 7 || (resp[0] & 0xff) != EAP_CODE_RESPONSE
                || (resp[4] & 0xff) != EAP_TYPE_MSCHAPV2) {
            return false;
        }
        int opCode = resp[5] & 0xff;   // OpCode
        // resp[6]=MS-CHAPv2-ID，resp[7..8]=MS-Length，resp[9]=Value-Size，resp[10..]=Value
        int vsize = resp[9] & 0xff;
        if (opCode != 2 || vsize < 50 || resp.length < 10 + vsize) {
            return false;
        }
        byte[] value = Arrays.copyOfRange(resp, 10, 10 + vsize);
        byte[] peerChallenge = Arrays.copyOfRange(value, 2, 18);
        byte[] ntResponse = Arrays.copyOfRange(value, 26, 50);
        UsersDB.User u = UsersDB.find(baseDir, username);
        if (u == null || !u.enabled()) {
            return false;
        }
        return verifyMsChapV2(u.password, username, peerChallenge, authChallenge, ntResponse);
    }

    /**
     * PEAP 内层 EAP-GTC（RFC 3748 §5.6，RFC 5216 §3.2 隧道内）：Identity → GTC 提示 → 明文令牌比对。
     */
    private boolean peapInnerGtc(TlsServerProtocol proto, String username) throws Exception {
        InputStream tin = proto.getInputStream();
        byte[] innerIdReq = eapPacket(EAP_CODE_REQUEST, (byte) 0x01, EAP_TYPE_IDENTITY, new byte[0]);
        proto.getOutputStream().write(innerIdReq);
        proto.getOutputStream().flush();
        byte[] idResp = readEapPacket(tin);
        if ((idResp[0] & 0xff) != EAP_CODE_RESPONSE || (idResp[4] & 0xff) != EAP_TYPE_IDENTITY) {
            return false;
        }
        byte[] gtcReq = eapPacket(EAP_CODE_REQUEST, (byte) 0x02, EAP_TYPE_GTC,
                "Enter Password: ".getBytes(StandardCharsets.UTF_8));
        proto.getOutputStream().write(gtcReq);
        proto.getOutputStream().flush();
        byte[] gtcResp = readEapPacket(tin);
        if (gtcResp.length < 6 || (gtcResp[0] & 0xff) != EAP_CODE_RESPONSE
                || (gtcResp[4] & 0xff) != EAP_TYPE_GTC) {
            return false;
        }
        String token = new String(Arrays.copyOfRange(gtcResp, 5, gtcResp.length), StandardCharsets.UTF_8).trim();
        UsersDB.User u = UsersDB.find(baseDir, username);
        return u != null && u.enabled() && constantTimeEquals(
                u.password.getBytes(StandardCharsets.UTF_8), token.getBytes(StandardCharsets.UTF_8));
    }

    /** 启动 PEAP（RFC 5216）：建会话 + 启动 TLS 握手线程 + 回 EAP-Request/PEAP/Start（S 位）。 */
    private byte[] startEapPeap(Packet p, int eapId, String username, String src, String innerMethod) {
        TlsServerCred cred = loadTlsServerCred();
        if (cred == null) {
            authFail++;
            addLog("PEAP 无可用服务端证书 来源=" + src + " 用户=" + username);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "PEAP 服务端证书缺失");
        }
        // 剥掉 peap:/eap-peap: 前缀，内层认证用真实用户名（RFC 5216 隧道内不再重复 Identity）
        final String realUser;
        if (username.regionMatches(true, 0, "peap:", 0, 5)) {
            realUser = username.substring(5);
        } else if (username.regionMatches(true, 0, "eap-peap:", 0, 9)) {
            realUser = username.substring(9);
        } else if (username.regionMatches(true, 0, "peap-mschapv2:", 0, 14)) {
            realUser = username.substring(14);
        } else if (username.regionMatches(true, 0, "eap-peap-mschapv2:", 0, 18)) {
            realUser = username.substring(18);
        } else if (username.regionMatches(true, 0, "peap-gtc:", 0, 9)) {
            realUser = username.substring(9);
        } else if (username.regionMatches(true, 0, "eap-peap-gtc:", 0, 14)) {
            realUser = username.substring(14);
        } else {
            realUser = username;
        }
        final String inner = innerMethod == null ? "MD5" : innerMethod.toUpperCase();
        int radiusId = p.identifier;
        EapTlsSession s = new EapTlsSession(realUser);
        s.innerEap = true;
        s.innerMethod = inner;
        tlsSessions.put(radiusId, s);
        s.thread = new Thread(() -> {
            try {
                ModpkicaTlsServer server = new ModpkicaTlsServer(cred);
                TlsServerProtocol proto = new TlsServerProtocol(s.inStream, s.outStream);
                s.tlsProto = proto;
                proto.accept(server);   // 外层 TLS 隧道握手（RFC 5216 §3.1）
                // 隧道建立 → 内层 EAP（RFC 5216 §3.2）：MD5 / GTC / MS-CHAPv2
                s.innerUser = realUser;
                if ("MSCHAPV2".equals(inner)) {
                    s.ok = peapInnerMsChapV2(proto, realUser);
                } else if ("GTC".equals(inner)) {
                    s.ok = peapInnerGtc(proto, realUser);
                } else {
                    s.ok = peapInnerMd5(proto, realUser);
                }
                if (!s.ok) {
                    s.err = "PEAP 内层 " + inner + " 认证失败 用户=" + realUser;
                }
            } catch (Exception ex) {
                s.err = ex.toString();
            } finally {
                s.done = true;
                s.notifyOutput();
            }
        }, "eap-peap-handshake");
        s.thread.setDaemon(true);
        s.thread.start();
        addLog("PEAP 启动握手 来源=" + src + " 用户=" + username + "（内层=" + inner + "，真实用户=" + realUser + "）");
        return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                username, eapId, EAP_CODE_REQUEST, EAP_TYPE_PEAP,
                new byte[]{(byte) EAP_TLS_FLAG_START}, null);
    }

    /**
     * PEAP 状态机（RFC 5216）：Identity → Start 交换 → 外层 TLS 握手（分片/重组同 EAP-TLS）
     * → TLS 隧道建立 → 内层 EAP-MD5（隧道内）→ EAP-Success。
     */
    private byte[] handleEapPeap(Packet p, int eapId, byte[] data, String src) {
        String rawUser = p.getString(ATTR_USER_NAME);
        String username = rawUser;
        if (rawUser != null && rawUser.regionMatches(true, 0, "peap:", 0, 5)) {
            username = rawUser.substring(5);
        } else if (rawUser != null && rawUser.regionMatches(true, 0, "eap-peap:", 0, 9)) {
            username = rawUser.substring(9);
        }
        int radiusId = p.identifier;
        if (data.length < 1) {
            authFail++;
            addLog("PEAP 数据为空 来源=" + src + " 用户=" + username);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "PEAP 数据为空");
        }
        int flags = data[0] & 0xff;
        int off = 1;
        long totalLen = -1;
        if ((flags & EAP_TLS_FLAG_LENGTH) != 0) {
            if (data.length < 5) {
                authFail++;
                addLog("PEAP 长度字段缺失 来源=" + src + " 用户=" + username);
                return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                        username, eapId, EAP_CODE_FAILURE, null, "PEAP 长度字段缺失");
            }
            totalLen = ((long) (data[1] & 0xff) << 24) | ((data[2] & 0xff) << 16)
                    | ((data[3] & 0xff) << 8) | (data[4] & 0xff);
            off = 5;
        }
        // 客户端确认 Start（S 位、无数据）→ 回空挑战，等 ClientHello
        if (data.length == off && (flags & EAP_TLS_FLAG_START) != 0) {
            return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_REQUEST, EAP_TYPE_PEAP,
                    eapTlsFragments(new byte[0], 0, false), null);
        }
        byte[] frag = Arrays.copyOfRange(data, off, data.length);

        EapTlsSession s = tlsSessions.get(radiusId);
        if (s == null) {
            authFail++;
            addLog("PEAP 会话已失效（超时或被清除） 来源=" + src + " 用户=" + username);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "PEAP 会话失效");
        }

        // RFC 5216 §2.1：客户端拉取续片（空 EAP-Response，flags=0）——不下发 TLS 数据、不 feed
        if (data.length == 1 && (data[0] & 0xff) == 0) {
            byte[] next = s.nextOutFrag();
            if (next == null) {
                byte[] o2 = s.pollOutput(2000);
                if (o2 == null || o2.length == 0) {
                    if (s.done) {
                        tlsSessions.remove(radiusId);
                        if (!s.ok) {
                            authFail++;
                            addLog("PEAP 认证失败: " + s.err + " 来源=" + src + " 用户=" + username);
                            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                                    username, eapId, EAP_CODE_FAILURE, null, "PEAP 认证失败");
                        }
                        authOk++;
                        addLog("PEAP 认证通过 来源=" + src + " 用户=" + username);
                        logAuthResult(src, username, "PEAP-" + (s.innerMethod == null ? "MD5" : s.innerMethod), true, "EAP");
                        return buildEapResponse(CODE_ACCESS_ACCEPT, p.identifier, p.authenticator,
                                username, eapId, EAP_CODE_SUCCESS, null, "PEAP 认证通过");
                    }
                    return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                            username, eapId, EAP_CODE_REQUEST, EAP_TYPE_PEAP,
                            eapTlsFragments(new byte[0], 0, false), null);
                }
                s.outBuf = o2;
                s.outSent = 0;
                next = s.nextOutFrag();
            }
            return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_REQUEST, EAP_TYPE_PEAP, next, null);
        }

        byte[] full;
        try {
            full = s.reassemble(frag, flags, totalLen);
        } catch (IllegalArgumentException iae) {
            authFail++;
            addLog("PEAP 重组失败: " + iae.getMessage() + " 来源=" + src);
            tlsSessions.remove(radiusId);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "PEAP 重组失败");
        }
        if (full != null) {
            s.feed(full);
        } else {
            byte[] o2 = s.pollOutput(500);
            if (o2 != null && o2.length > 0) {
                if (s.done) {
                    tlsSessions.remove(radiusId);
                    if (!s.ok) {
                        authFail++;
                        addLog("PEAP 认证失败: " + s.err + " 来源=" + src + " 用户=" + username);
                        return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                                username, eapId, EAP_CODE_FAILURE, null, "PEAP 认证失败");
                    }
                    authOk++;
                    addLog("PEAP 认证通过 来源=" + src + " 用户=" + username);
                    logAuthResult(src, username, "PEAP-" + (s.innerMethod == null ? "MD5" : s.innerMethod), true, "EAP");
                    return buildEapResponse(CODE_ACCESS_ACCEPT, p.identifier, p.authenticator,
                            username, eapId, EAP_CODE_SUCCESS, null, "PEAP 认证通过");
                }
                s.outBuf = o2;
                s.outSent = 0;
                return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                        username, eapId, EAP_CODE_REQUEST, EAP_TYPE_PEAP, s.nextOutFrag(), null);
            }
            return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_REQUEST, EAP_TYPE_PEAP,
                    eapTlsFragments(new byte[0], 0, false), null);
        }
        byte[] out = s.pollOutput(EAP_TLS_TIMEOUT_S * 1000L);
        if (out == null) {
            authFail++;
            addLog("PEAP 握手超时 来源=" + src + " 用户=" + username);
            tlsSessions.remove(radiusId);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "PEAP 握手超时");
        }
        if (s.done) {
            tlsSessions.remove(radiusId);
            if (!s.ok) {
                authFail++;
                addLog("PEAP 认证失败: " + s.err + " 来源=" + src + " 用户=" + username);
                return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                        username, eapId, EAP_CODE_FAILURE, null, "PEAP 认证失败");
            }
            authOk++;
            addLog("PEAP 认证通过 来源=" + src + " 用户=" + username);
            logAuthResult(src, username, "PEAP-MD5", true, "EAP");
            return buildEapResponse(CODE_ACCESS_ACCEPT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_SUCCESS, null, "PEAP 认证通过");
        }
        if (out.length == 0) {
            return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_REQUEST, EAP_TYPE_PEAP,
                    eapTlsFragments(new byte[0], 0, false), null);
        }
        s.outBuf = out;
        s.outSent = 0;
        return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                username, eapId, EAP_CODE_REQUEST, EAP_TYPE_PEAP, s.nextOutFrag(), null);
    }

    /** EAP-TTLS 状态机（RFC 5281）：与 PEAP 同构的 TLS 隧道分片/重组/拉取，EAP Type=21。 */
    private byte[] handleEapTtls(Packet p, int eapId, byte[] data, String src) {
        String rawUser = p.getString(ATTR_USER_NAME);
        String username = rawUser;
        if (rawUser != null && rawUser.regionMatches(true, 0, "ttls:", 0, 5)) {
            username = rawUser.substring(5);
        } else if (rawUser != null && rawUser.regionMatches(true, 0, "eap-ttls:", 0, 9)) {
            username = rawUser.substring(9);
        }
        int radiusId = p.identifier;
        if (data.length < 1) {
            authFail++;
            addLog("TTLS 数据为空 来源=" + src + " 用户=" + username);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "TTLS 数据为空");
        }
        int flags = data[0] & 0xff;
        int off = 1;
        long totalLen = -1;
        if ((flags & EAP_TLS_FLAG_LENGTH) != 0) {
            if (data.length < 5) {
                authFail++;
                addLog("TTLS 长度字段缺失 来源=" + src + " 用户=" + username);
                return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                        username, eapId, EAP_CODE_FAILURE, null, "TTLS 长度字段缺失");
            }
            totalLen = ((long) (data[1] & 0xff) << 24) | ((data[2] & 0xff) << 16)
                    | ((data[3] & 0xff) << 8) | (data[4] & 0xff);
            off = 5;
        }
        if (data.length == off && (flags & EAP_TLS_FLAG_START) != 0) {
            return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_REQUEST, EAP_TYPE_TTLS,
                    eapTlsFragments(new byte[0], 0, false), null);
        }
        byte[] frag = Arrays.copyOfRange(data, off, data.length);

        EapTlsSession s = tlsSessions.get(radiusId);
        if (s == null) {
            authFail++;
            addLog("TTLS 会话已失效（超时或被清除） 来源=" + src + " 用户=" + username);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "TTLS 会话失效");
        }

        if (data.length == 1 && (data[0] & 0xff) == 0) {
            byte[] next = s.nextOutFrag();
            if (next == null) {
                byte[] o2 = s.pollOutput(2000);
                if (o2 == null || o2.length == 0) {
                    if (s.done) {
                        tlsSessions.remove(radiusId);
                        if (!s.ok) {
                            authFail++;
                            addLog("TTLS 认证失败: " + s.err + " 来源=" + src + " 用户=" + username);
                            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                                    username, eapId, EAP_CODE_FAILURE, null, "TTLS 认证失败");
                        }
                        authOk++;
                        addLog("TTLS 认证通过 来源=" + src + " 用户=" + username);
                        logAuthResult(src, username, "EAP-TTLS", true, "EAP");
                        return buildEapResponse(CODE_ACCESS_ACCEPT, p.identifier, p.authenticator,
                                username, eapId, EAP_CODE_SUCCESS, null, "TTLS 认证通过");
                    }
                    return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                            username, eapId, EAP_CODE_REQUEST, EAP_TYPE_TTLS,
                            eapTlsFragments(new byte[0], 0, false), null);
                }
                s.outBuf = o2;
                s.outSent = 0;
                next = s.nextOutFrag();
            }
            return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_REQUEST, EAP_TYPE_TTLS, next, null);
        }

        byte[] full;
        try {
            full = s.reassemble(frag, flags, totalLen);
        } catch (IllegalArgumentException iae) {
            authFail++;
            addLog("TTLS 重组失败: " + iae.getMessage() + " 来源=" + src);
            tlsSessions.remove(radiusId);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "TTLS 重组失败");
        }
        if (full != null) {
            s.feed(full);
        } else {
            byte[] o2 = s.pollOutput(500);
            if (o2 != null && o2.length > 0) {
                if (s.done) {
                    tlsSessions.remove(radiusId);
                    if (!s.ok) {
                        authFail++;
                        addLog("TTLS 认证失败: " + s.err + " 来源=" + src + " 用户=" + username);
                        return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                                username, eapId, EAP_CODE_FAILURE, null, "TTLS 认证失败");
                    }
                    authOk++;
                    addLog("TTLS 认证通过 来源=" + src + " 用户=" + username);
                    logAuthResult(src, username, "EAP-TTLS", true, "EAP");
                    return buildEapResponse(CODE_ACCESS_ACCEPT, p.identifier, p.authenticator,
                            username, eapId, EAP_CODE_SUCCESS, null, "TTLS 认证通过");
                }
                s.outBuf = o2;
                s.outSent = 0;
                return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                        username, eapId, EAP_CODE_REQUEST, EAP_TYPE_TTLS, s.nextOutFrag(), null);
            }
            return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_REQUEST, EAP_TYPE_TTLS,
                    eapTlsFragments(new byte[0], 0, false), null);
        }
        byte[] out = s.pollOutput(EAP_TLS_TIMEOUT_S * 1000L);
        if (out == null) {
            authFail++;
            addLog("TTLS 握手超时 来源=" + src + " 用户=" + username);
            tlsSessions.remove(radiusId);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "TTLS 握手超时");
        }
        if (s.done) {
            tlsSessions.remove(radiusId);
            if (!s.ok) {
                authFail++;
                addLog("TTLS 认证失败: " + s.err + " 来源=" + src + " 用户=" + username);
                return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                        username, eapId, EAP_CODE_FAILURE, null, "TTLS 认证失败");
            }
            authOk++;
            addLog("TTLS 认证通过 来源=" + src + " 用户=" + username);
            logAuthResult(src, username, "EAP-TTLS", true, "EAP");
            return buildEapResponse(CODE_ACCESS_ACCEPT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_SUCCESS, null, "TTLS 认证通过");
        }
        if (out.length == 0) {
            return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_REQUEST, EAP_TYPE_TTLS,
                    eapTlsFragments(new byte[0], 0, false), null);
        }
        s.outBuf = out;
        s.outSent = 0;
        return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                username, eapId, EAP_CODE_REQUEST, EAP_TYPE_TTLS, s.nextOutFrag(), null);
    }

    // ==================== EAP-pwd（RFC 5931，P-256 / Group 19） ====================

    private static final BigInteger PWD_THREE = BigInteger.valueOf(3);

    /** P-256（secp256r1）群参数。 */
    private static X9ECParameters pwdCurve() {
        return ECNamedCurveTable.getByName("secp256r1");
    }

    private static byte[] eapPwdHkdf(byte[] ikm, byte[] salt, byte[] info, int len) throws Exception {
        HKDFBytesGenerator gen = new HKDFBytesGenerator(new SHA256Digest());
        gen.init(new HKDFParameters(ikm, salt, info));
        byte[] out = new byte[len];
        gen.generateBytes(out, 0, len);
        return out;
    }

    /** RFC 5931 §2.8.1：从口令 + 服务器/客户端身份派生 PWE（HKDF 猎取-啄食法）。 */
    static ECPoint eapPwdDerivePwe(String password, String idServer, String idPeer) throws Exception {
        X9ECParameters params = pwdCurve();
        ECCurve curve = params.getCurve();
        BigInteger p = curve.getField().getCharacteristic();
        BigInteger a = curve.getA().toBigInteger();
        BigInteger b = curve.getB().toBigInteger();
        BigInteger order = params.getN();
        ByteArrayOutputStream ikm = new ByteArrayOutputStream();
        ikm.write(password.getBytes(StandardCharsets.UTF_8));
        ikm.write(0x00);
        ikm.write(idServer.getBytes(StandardCharsets.UTF_8));
        ikm.write(0x00);
        ikm.write(idPeer.getBytes(StandardCharsets.UTF_8));
        byte[] ikmB = ikm.toByteArray();
        byte[] salt = new byte[0];
        byte[] baseInfo = "EAP-pwd Hunting And Pecking".getBytes(StandardCharsets.UTF_8);
        byte[] pwdTmp = eapPwdHkdf(ikmB, salt, baseInfo, 32);
        byte[] xb = null;
        for (int counter = 1; counter <= 255; counter++) {
            if (counter == 1) {
                xb = pwdTmp;
            } else {
                byte[] info = new byte[baseInfo.length + 1];
                System.arraycopy(baseInfo, 0, info, 0, baseInfo.length);
                info[baseInfo.length] = (byte) counter;
                xb = eapPwdHkdf(ikmB, salt, info, 32);
            }
            BigInteger x = new BigInteger(1, xb);
            if (x.compareTo(p) >= 0) {
                continue;
            }
            // y² = x³ + a·x + b (mod p)；secp256r1 p ≡ 3 (mod 4) → sqrt = y2^((p+1)/4)
            BigInteger y2 = x.modPow(PWD_THREE, p).add(a.multiply(x)).add(b).mod(p);
            BigInteger y = y2.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p);
            if (!y.multiply(y).mod(p).equals(y2)) {
                continue;
            }
            if (y.testBit(0)) {
                y = p.subtract(y);
            }
            ECPoint pwe = curve.createPoint(x, y);
            if (!pwe.multiply(order).isInfinity()) {
                continue;
            }
            return pwe;
        }
        throw new IllegalStateException("EAP-pwd PWE 派生失败（255 次猎取无解）");
    }

    private static byte[] eapPwdFixedBytes(BigInteger v, int len) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[len];
        if (raw.length > len) {
            System.arraycopy(raw, raw.length - len, out, 0, len);
        } else {
            System.arraycopy(raw, 0, out, len - raw.length, raw.length);
        }
        return out;
    }

    /** RFC 5931 §2.7：元素 = SEC1 压缩点（0x02/0x03 || x 坐标 32B）。 */
    static byte[] eapPwdElementBytes(ECPoint pt) {
        ECPoint n = pt.normalize();
        byte[] x = eapPwdFixedBytes(n.getAffineXCoord().toBigInteger(), 32);
        byte[] out = new byte[33];
        out[0] = n.getAffineYCoord().toBigInteger().testBit(0) ? (byte) 0x03 : (byte) 0x02;
        System.arraycopy(x, 0, out, 1, 32);
        return out;
    }

    static ECPoint eapPwdElementFromBytes(byte[] b) {
        if (b.length != 33 || (b[0] != 0x02 && b[0] != 0x03)) {
            throw new IllegalArgumentException("EAP-pwd 元素格式非法");
        }
        X9ECParameters params = pwdCurve();
        ECCurve curve = params.getCurve();
        BigInteger p = curve.getField().getCharacteristic();
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(b, 1, 33));
        if (x.compareTo(p) >= 0) {
            throw new IllegalArgumentException("EAP-pwd 元素 x 越界");
        }
        BigInteger y2 = x.modPow(PWD_THREE, p)
                .add(curve.getA().toBigInteger().multiply(x)).add(curve.getB().toBigInteger()).mod(p);
        BigInteger y = y2.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p);
        if (!y.multiply(y).mod(p).equals(y2)) {
            throw new IllegalArgumentException("EAP-pwd 元素不在曲线上");
        }
        boolean wantOdd = (b[0] & 0xff) == 0x03;
        if (y.testBit(0) != wantOdd) {
            y = p.subtract(y);
        }
        ECPoint pt = curve.createPoint(x, y);
        if (pt.isInfinity()) {
            throw new IllegalArgumentException("EAP-pwd 元素为无穷点");
        }
        return pt;
    }

    static byte[] eapPwdScalarBytes(BigInteger s) {
        return eapPwdFixedBytes(s, 32);
    }

    static BigInteger eapPwdScalarFromBytes(byte[] b) {
        BigInteger s = new BigInteger(1, b);
        if (s.compareTo(BigInteger.ONE) <= 0 || s.compareTo(pwdCurve().getN()) >= 0) {
            throw new IllegalArgumentException("EAP-pwd 标量越界");
        }
        return s;
    }

    /** RFC 5931 §3.2.2：k = scalar_p·element_s + scalar_s·element_p，取 x 坐标。 */
    static byte[] eapPwdKx(BigInteger scalarS, ECPoint elementS, BigInteger scalarP, ECPoint elementP) {
        ECPoint k = elementP.multiply(scalarS).add(elementS.multiply(scalarP)).normalize();
        return eapPwdFixedBytes(k.getAffineXCoord().toBigInteger(), 32);
    }

    /** RFC 5931 §3.2.2：Confirm = HMAC-SHA256(kx, S || scalar_s || element_s || scalar_p || element_p || tag)。 */
    static byte[] eapPwdConfirm(byte[] kx, byte[] s, byte[] scalarS, byte[] elementS,
            byte[] scalarP, byte[] elementP, String tag) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(s);
        bos.write(scalarS);
        bos.write(elementS);
        bos.write(scalarP);
        bos.write(elementP);
        bos.write(tag.getBytes(StandardCharsets.UTF_8));
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(kx, "HmacSHA256"));
        return mac.doFinal(bos.toByteArray());
    }

    private void evictPwdStates() {
        long now = System.currentTimeMillis();
        pwdStates.entrySet().removeIf(e -> e.getValue().expires < now);
    }

    /** EAP-pwd 启动：校验用户并回 EAP-Request/EAP-pwd/ID（Group=6=P-256）。 */
    private byte[] startEapPwd(Packet p, int eapId, String name, String src) {
        final String realUser;
        if (name.regionMatches(true, 0, "pwd:", 0, 4)) {
            realUser = name.substring(4);
        } else if (name.regionMatches(true, 0, "eap-pwd:", 0, 8)) {
            realUser = name.substring(8);
        } else {
            realUser = name;
        }
        UsersDB.User u = realUser.isEmpty() ? null : UsersDB.find(baseDir, realUser);
        if (u == null || !u.enabled()) {
            authFail++;
            addLog("EAP-pwd 用户不存在或停用 来源=" + src + " 用户=" + realUser);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    name, eapId, EAP_CODE_FAILURE, null, "用户不存在或停用");
        }
        EapPwdState st = new EapPwdState();
        st.username = realUser;
        st.phase = 0;
        st.expires = System.currentTimeMillis() + EAP_STATE_TTL_MS;
        synchronized (pwdStates) {
            pwdStates.put(p.identifier, st);
            evictPwdStates();
        }
        addLog("EAP-pwd 启动 来源=" + src + " 用户=" + realUser + " → 发送 EAP-pwd/ID（Group=P-256）");
        return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                name, eapId, EAP_CODE_REQUEST, EAP_TYPE_PWD, new byte[]{0, 6}, null);
    }

    /** EAP-pwd 状态机：ID → Commit（标量/元素交换）→ Confirm → EAP-Success。 */
    private byte[] handleEapPwd(Packet p, int eapId, byte[] data, String src) {
        String rawUser = p.getString(ATTR_USER_NAME);
        String username = rawUser;
        if (rawUser != null && rawUser.regionMatches(true, 0, "pwd:", 0, 4)) {
            username = rawUser.substring(4);
        } else if (rawUser != null && rawUser.regionMatches(true, 0, "eap-pwd:", 0, 8)) {
            username = rawUser.substring(8);
        }
        EapPwdState st;
        synchronized (pwdStates) {
            st = pwdStates.get(p.identifier);
            if (st != null && st.expires < System.currentTimeMillis()) {
                pwdStates.remove(p.identifier);
                st = null;
            }
        }
        if (st == null) {
            authFail++;
            addLog("EAP-pwd 会话失效 来源=" + src + " 用户=" + username);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "EAP-pwd 会话失效");
        }
        try {
            switch (st.phase) {
                case 0: {
                    // EAP-pwd/ID/Response：Group(2B) 回显 → 派生 PWE、随机标量、发 Commit/Request
                    if (data.length != 2 || data[0] != 0 || data[1] != 6) {
                        authFail++;
                        addLog("EAP-pwd ID/Response 组不匹配 来源=" + src + " 用户=" + username);
                        pwdStates.remove(p.identifier);
                        return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                                username, eapId, EAP_CODE_FAILURE, null, "EAP-pwd 组不匹配");
                    }
                    UsersDB.User u = UsersDB.find(baseDir, st.username);
                    if (u == null || !u.enabled()) {
                        authFail++;
                        addLog("EAP-pwd 用户不存在 来源=" + src + " 用户=" + st.username);
                        pwdStates.remove(p.identifier);
                        return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                                username, eapId, EAP_CODE_FAILURE, null, "用户不存在");
                    }
                    st.pwe = eapPwdDerivePwe(u.password, "MODPKICA-RADIUS", st.username);
                    BigInteger n = pwdCurve().getN();
                    st.scalarS = new BigInteger(256, new SecureRandom()).mod(n.subtract(BigInteger.ONE)).add(BigInteger.ONE);
                    st.elementS = st.pwe.add(pwdCurve().getG().multiply(st.scalarS).negate());
                    byte[] scalarB = eapPwdScalarBytes(st.scalarS);
                    byte[] elemB = eapPwdElementBytes(st.elementS);
                    st.phase = 1;
                    byte[] out = new byte[2 + scalarB.length + elemB.length];
                    out[0] = (byte) (scalarB.length >> 8);
                    out[1] = (byte) scalarB.length;
                    System.arraycopy(scalarB, 0, out, 2, scalarB.length);
                    System.arraycopy(elemB, 0, out, 2 + scalarB.length, elemB.length);
                    addLog("EAP-pwd 发送 Commit/Request（标量+元素） 来源=" + src + " 用户=" + st.username);
                    return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                            username, eapId, EAP_CODE_REQUEST, EAP_TYPE_PWD, out, null);
                }
                case 1: {
                    // EAP-pwd/Commit/Response：解析客户端标量+元素 → 共享密钥 → 发 Confirm/Request
                    if (data.length < 2) {
                        authFail++;
                        addLog("EAP-pwd Commit/Response 长度非法 来源=" + src);
                        pwdStates.remove(p.identifier);
                        return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                                username, eapId, EAP_CODE_FAILURE, null, "EAP-pwd Commit 非法");
                    }
                    int l = ((data[0] & 0xff) << 8) | (data[1] & 0xff);
                    if (l != 32 || data.length != 2 + l + 33) {
                        authFail++;
                        addLog("EAP-pwd Commit/Response 长度非法 来源=" + src + " len=" + data.length);
                        pwdStates.remove(p.identifier);
                        return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                                username, eapId, EAP_CODE_FAILURE, null, "EAP-pwd Commit 非法");
                    }
                    st.scalarP = eapPwdScalarFromBytes(Arrays.copyOfRange(data, 2, 2 + l));
                    st.elementP = eapPwdElementFromBytes(Arrays.copyOfRange(data, 2 + l, data.length));
                    st.kx = eapPwdKx(st.scalarS, st.elementS, st.scalarP, st.elementP);
                    byte[] sData = new byte[]{0, 6, 0, 6};
                    byte[] scalarSB = eapPwdScalarBytes(st.scalarS);
                    byte[] elemSB = eapPwdElementBytes(st.elementS);
                    byte[] scalarPB = eapPwdScalarBytes(st.scalarP);
                    byte[] elemPB = eapPwdElementBytes(st.elementP);
                    st.confirmC = eapPwdConfirm(st.kx, sData, scalarSB, elemSB, scalarPB, elemPB, "client");
                    byte[] confirmS = eapPwdConfirm(st.kx, sData, scalarSB, elemSB, scalarPB, elemPB, "server");
                    st.phase = 2;
                    addLog("EAP-pwd 发送 Confirm/Request 来源=" + src + " 用户=" + st.username);
                    return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                            username, eapId, EAP_CODE_REQUEST, EAP_TYPE_PWD, confirmS, null);
                }
                case 2: {
                    // EAP-pwd/Confirm/Response：验证 Confirm_C → EAP-Success/Failure
                    if (data.length != 32 || !MessageDigest.isEqual(data, st.confirmC)) {
                        authFail++;
                        addLog("EAP-pwd Confirm 校验失败 来源=" + src + " 用户=" + st.username);
                        pwdStates.remove(p.identifier);
                        logAuthResult(src, st.username, "EAP-pwd", false, "EAP");
                        return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                                username, eapId, EAP_CODE_FAILURE, null, "EAP-pwd 确认失败");
                    }
                    authOk++;
                    addLog("EAP-pwd 认证通过 来源=" + src + " 用户=" + st.username);
                    pwdStates.remove(p.identifier);
                    logAuthResult(src, st.username, "EAP-pwd", true, "EAP");
                    return buildEapResponse(CODE_ACCESS_ACCEPT, p.identifier, p.authenticator,
                            username, eapId, EAP_CODE_SUCCESS, null, "EAP-pwd 认证通过");
                }
                default:
                    authFail++;
                    addLog("EAP-pwd 状态非法 来源=" + src);
                    pwdStates.remove(p.identifier);
                    return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                            username, eapId, EAP_CODE_FAILURE, null, "EAP-pwd 状态非法");
            }
        } catch (Exception ex) {
            authFail++;
            addLog("EAP-pwd 处理异常: " + ex + " 来源=" + src + " 用户=" + username);
            pwdStates.remove(p.identifier);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "EAP-pwd 处理异常");
        }
    }

    /**
     * EAP-TLS 状态机：
     * Identity → 服务器建会话并发 Start → 客户端 ClientHello → BC 握手线程推进
     * （握手数据经 EAP 分片/重组交换）→ 握手完成 → EAP-Success。
     */
    private byte[] handleEapTls(Packet p, int eapId, byte[] data, String src) {
        String username = p.getString(ATTR_USER_NAME);
        int radiusId = p.identifier;
        addLog("EAP-TLS 收到 TLS 数据 " + data.length + "B（radiusId=" + radiusId + "） 来源=" + src);
        if (data.length < 1) {
            authFail++;
            addLog("EAP-TLS 数据为空 来源=" + src + " 用户=" + username);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "EAP-TLS 数据为空");
        }
        int flags = data[0] & 0xff;
        int off = 1;
        long totalLen = -1;
        if ((flags & EAP_TLS_FLAG_LENGTH) != 0) {
            if (data.length < 5) {
                authFail++;
                addLog("EAP-TLS 长度字段缺失 来源=" + src + " 用户=" + username);
                return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                        username, eapId, EAP_CODE_FAILURE, null, "EAP-TLS 长度字段缺失");
            }
            totalLen = ((long) (data[1] & 0xff) << 24) | ((data[2] & 0xff) << 16)
                    | ((data[3] & 0xff) << 8) | (data[4] & 0xff);
            off = 5;
        }
        byte[] frag = Arrays.copyOfRange(data, off, data.length);

        // 客户端发来 Start（异常：只有服务器发 Start）
        if ((flags & EAP_TLS_FLAG_START) != 0) {
            authFail++;
            addLog("EAP-TLS 收到异常 Start 来源=" + src);
            tlsSessions.remove(radiusId);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "EAP-TLS Start 异常");
        }

        EapTlsSession s = tlsSessions.get(radiusId);
        if (s == null) {
            authFail++;
            addLog("EAP-TLS 会话已失效（超时或被清除） 来源=" + src + " 用户=" + username);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "EAP-TLS 会话失效");
        }

        // RFC 5216 §2.1：客户端拉取续片（空 EAP-Response/TLS，flags=0）——不下发 TLS 数据、不 feed
        if (data.length == 1 && (data[0] & 0xff) == 0) {
            byte[] next = s.nextOutFrag();
            if (next == null) {
                // 缓冲已发完——尝试取握手线程新输出（若已完成则收尾）
                byte[] o2 = s.pollOutput(2000);
                if (o2 == null || o2.length == 0) {
                    if (s.done) {
                        tlsSessions.remove(radiusId);
                        if (!s.ok) {
                            authFail++;
                            addLog("EAP-TLS 握手失败: " + s.err + " 来源=" + src + " 用户=" + username);
                            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                                    username, eapId, EAP_CODE_FAILURE, null, "EAP-TLS 握手失败");
                        }
                        authOk++;
                        addLog("EAP-TLS 认证通过 来源=" + src + " 用户=" + username);
                        logAuthResult(src, username, "EAP-TLS", true, "EAP");
                        return buildEapResponse(CODE_ACCESS_ACCEPT, p.identifier, p.authenticator,
                                username, eapId, EAP_CODE_SUCCESS, null, "EAP-TLS 认证通过");
                    }
                    return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                            username, eapId, EAP_CODE_REQUEST, EAP_TYPE_TLS,
                            eapTlsFragments(new byte[0], 0, false), null);
                }
                s.outBuf = o2;
                s.outSent = 0;
                next = s.nextOutFrag();
            }
            return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_REQUEST, EAP_TYPE_TLS, next, null);
        }

        // 客户端 → 服务器 分片重组
        byte[] full;
        try {
            full = s.reassemble(frag, flags, totalLen);
        } catch (IllegalArgumentException iae) {
            authFail++;
            addLog("EAP-TLS 重组失败: " + iae.getMessage() + " 来源=" + src);
            tlsSessions.remove(radiusId);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "EAP-TLS 重组失败");
        }
        if (full != null) {
            s.feed(full);   // 完整 TLS 记录：喂给握手线程
        } else {
            // 分片未齐（客户端多片传输中）：不 feed 半记录；短等后发空挑战让客户端继续发下一片
            byte[] o2 = s.pollOutput(500);
            if (o2 != null && o2.length > 0) {
                if (s.done) {
                    tlsSessions.remove(radiusId);
                    if (!s.ok) {
                        authFail++;
                        addLog("EAP-TLS 握手失败: " + s.err + " 来源=" + src + " 用户=" + username);
                        return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                                username, eapId, EAP_CODE_FAILURE, null, "EAP-TLS 握手失败");
                    }
                    authOk++;
                    addLog("EAP-TLS 认证通过 来源=" + src + " 用户=" + username);
                    logAuthResult(src, username, "EAP-TLS", true, "EAP");
                    return buildEapResponse(CODE_ACCESS_ACCEPT, p.identifier, p.authenticator,
                            username, eapId, EAP_CODE_SUCCESS, null, "EAP-TLS 认证通过");
                }
                s.outBuf = o2;
                s.outSent = 0;
                return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                        username, eapId, EAP_CODE_REQUEST, EAP_TYPE_TLS, s.nextOutFrag(), null);
            }
            return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_REQUEST, EAP_TYPE_TLS,
                    eapTlsFragments(new byte[0], 0, false), null);
        }
        byte[] out = s.pollOutput(EAP_TLS_TIMEOUT_S * 1000L);
        if (out == null) {
            authFail++;
            addLog("EAP-TLS 握手超时 来源=" + src + " 用户=" + username);
            tlsSessions.remove(radiusId);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "EAP-TLS 握手超时");
        }

        if (s.done) {
            tlsSessions.remove(radiusId);
            if (!s.ok) {
                authFail++;
                addLog("EAP-TLS 握手失败: " + s.err + " 来源=" + src + " 用户=" + username);
                return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                        username, eapId, EAP_CODE_FAILURE, null, "EAP-TLS 握手失败");
            }
            authOk++;
            addLog("EAP-TLS 认证通过 来源=" + src + " 用户=" + username);
            logAuthResult(src, username, "EAP-TLS", true, "EAP");
            return buildEapResponse(CODE_ACCESS_ACCEPT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_SUCCESS, null, "EAP-TLS 认证通过");
        }

        // 握手未完成：把服务器输出缓冲分片下发，每片一个 EAP 包（RFC 5216 §2.1）
        if (out.length == 0) {
            // 无新输出且未完成——发空挑战维持会话
            return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_REQUEST, EAP_TYPE_TLS, eapTlsFragments(new byte[0], 0, false), null);
        }
        s.outBuf = out;
        s.outSent = 0;
        byte[] first = s.nextOutFrag();
        return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                username, eapId, EAP_CODE_REQUEST, EAP_TYPE_TLS, first, null);
    }

    /** 服务器 → 客户端：把 TLS 输出切成 EAP-TLS 分片（首片带总长度，逐片带 MORE 标志）。 */
    static byte[] eapTlsFragments(byte[] data, int totalLen, boolean server) {
        int flagsBase = server ? EAP_TLS_FLAG_START : 0;
        if (data.length == 0) {
            // EAP-TLS Start：仅 START 标志（RFC 5216 §2.1）
            return new byte[]{(byte) flagsBase};
        }
        ByteArrayOutputStream all = new ByteArrayOutputStream();
        int pos = 0;
        boolean first = true;
        while (true) {
            int flags = flagsBase;
            if (first) {
                flags |= EAP_TLS_FLAG_LENGTH;   // L 位仅首片
                first = false;
            }
            int n = Math.min(EAP_TLS_FRAG, data.length - pos);
            if (pos + n < data.length) {
                flags |= EAP_TLS_FLAG_MORE;
            }
            all.write(flags);
            if ((flags & EAP_TLS_FLAG_LENGTH) != 0) {
                all.write((totalLen >> 24) & 0xff);
                all.write((totalLen >> 16) & 0xff);
                all.write((totalLen >> 8) & 0xff);
                all.write(totalLen & 0xff);
            }
            all.write(data, pos, n);
            pos += n;
            if (pos >= data.length) {
                break;
            }
        }
        return all.toByteArray();
    }

    /** RFC 5216 §2.1：把 TLS 输出拆成单片列表（每片含 flags+[L 时 4B 长度]+数据，单片 ≤253B EAP-Message）。 */
    static byte[][] splitTlsFragments(byte[] data) {
        List<byte[]> list = new ArrayList<>();
        if (data == null || data.length == 0) {
            list.add(new byte[]{0});
            return list.toArray(new byte[0][]);
        }
        int pos = 0;
        boolean first = true;
        while (pos < data.length) {
            int flags = 0;
            if (first) {
                flags |= EAP_TLS_FLAG_LENGTH;
                first = false;
            }
            int n = Math.min(EAP_TLS_FRAG, data.length - pos);
            if (pos + n < data.length) {
                flags |= EAP_TLS_FLAG_MORE;
            }
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            b.write(flags);
            if ((flags & EAP_TLS_FLAG_LENGTH) != 0) {
                b.write((data.length >> 24) & 0xff);
                b.write((data.length >> 16) & 0xff);
                b.write((data.length >> 8) & 0xff);
                b.write(data.length & 0xff);
            }
            b.write(data, pos, n);
            list.add(b.toByteArray());
            pos += n;
        }
        return list.toArray(new byte[0][]);
    }

    /** 从 PKI 证书库加载 EAP-TLS 服务端凭据（CA 优先、回退 ROOT；仅 RSA/ECC，排除 SM2/PQC）。 */
    private TlsServerCred loadTlsServerCred() {
        TlsServerCred c = tlsServerCred;
        if (c != null) {
            return c;
        }
        synchronized (tlsCredLock) {
            if (tlsServerCred != null) {
                return tlsServerCred;
            }
            try {
                java.io.File pkiDir = new java.io.File(baseDir, "PKI");
                CertsDB db = new CertsDB();
                db.load(baseDir);
                for (String dir : new String[]{"CA", "ROOT"}) {
                    java.io.File d = new java.io.File(pkiDir, dir);
                    java.io.File[] files = d.listFiles((f, n) -> n.endsWith(".crt"));
                    if (files == null) {
                        continue;
                    }
                    Arrays.sort(files);
                    for (java.io.File f : files) {
                        String serial = f.getName().substring(0, f.getName().length() - 4);
                        CertsDB.CertEntry e = db.findBySerial(serial);
                        if (e == null || e.status != 'V') {
                            continue;
                        }
                        if (!"RSA".equalsIgnoreCase(e.algo) && !"ECC".equalsIgnoreCase(e.algo)) {
                            continue;   // SM2/PQC 无 TLS 套件支持
                        }
                        java.io.File keyFile = new java.io.File(d, serial + ".key");
                        if (!keyFile.exists()) {
                            continue;
                        }
                        try {
                            X509Certificate cert = PemIO.readCert(f.getAbsolutePath());
                            AsymmetricKeyParameter key = PemIO.readPrivateKey(keyFile.getAbsolutePath());
                            // 组装链：本证书 + 颁发者（CA 类型则追根到 ROOT）
                            List<X509Certificate> chain = new ArrayList<>();
                            chain.add(cert);
                            if (e.type == 'C' && e.issuerId != null) {
                                CertsDB.CertEntry issuer = db.findBySerial(e.issuerId);
                                if (issuer != null && issuer.type == 'R') {
                                    java.io.File rootCert = new java.io.File(new java.io.File(pkiDir, "ROOT"), e.issuerId + ".crt");
                                    if (rootCert.exists()) {
                                        chain.add(PemIO.readCert(rootCert.getAbsolutePath()));
                                    }
                                }
                            }
                            BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());
                            TlsServerCred cred = new TlsServerCred(crypto, key,
                                    chain.toArray(new X509Certificate[0]));
                            tlsServerCred = cred;
                            addLog("EAP-TLS 服务端证书加载成功 证书=" + dir + "/" + serial
                                    + ".crt 算法=" + e.algo + " 链=" + chain.size() + " 级");
                            return cred;
                        } catch (Exception ex) {
                            addLog("EAP-TLS 证书加载失败 " + serial + ": " + ex);
                        }
                    }
                }
                addLog("EAP-TLS 未找到可用服务端证书（需要 PKI/CA 或 PKI/ROOT 中 RSA/ECC 类型证书）");
                return null;
            } catch (Exception ex) {
                addLog("EAP-TLS 凭据加载异常: " + ex);
                return null;
            }
        }
    }

    /**
     * 加载客户端调试用证书凭据（certSerial 可选）。
     * 返回 Object[]{List<X509Certificate> chain, X509Certificate clientCert, AsymmetricKeyParameter clientKey}；
     * 私钥可缺省（仅作信任锚）；序列号无效/未登记返回 null（调用方按匿名处理）。
     */
    private Object[] loadClientTlsCred(String certSerial) {
        if (certSerial == null || certSerial.trim().isEmpty()) {
            return null;
        }
        String serial = certSerial.trim();
        try {
            java.io.File pkiDir = new java.io.File(baseDir, "PKI");
            CertsDB db = new CertsDB();
            db.load(baseDir);
            CertsDB.CertEntry e = db.findBySerial(serial);
            if (e == null) {
                addLog("客户端调试证书未登记: " + serial);
                return null;
            }
            String dir = "CERT";
            if (e.type == 'R') {
                dir = "ROOT";
            } else if (e.type == 'C') {
                dir = "CA";
            }
            java.io.File certFile = new java.io.File(new java.io.File(pkiDir, dir), serial + ".crt");
            if (!certFile.exists()) {
                certFile = new java.io.File(new java.io.File(pkiDir, "WebPublic/CRT"), serial + ".crt");
            }
            if (!certFile.exists()) {
                addLog("客户端调试证书文件缺失: " + serial);
                return null;
            }
            X509Certificate cert = PemIO.readCert(certFile.getAbsolutePath());
            // 组装链：本证书 + 颁发者链（C/E 追到 ROOT）
            List<X509Certificate> chain = new ArrayList<>();
            chain.add(cert);
            if ((e.type == 'C' || e.type == 'E') && e.issuerId != null) {
                CertsDB.CertEntry issuer = db.findBySerial(e.issuerId);
                if (issuer != null) {
                    java.io.File ic = new java.io.File(new java.io.File(pkiDir, "ROOT"), e.issuerId + ".crt");
                    if (!ic.exists() && issuer.type == 'C') {
                        ic = new java.io.File(new java.io.File(pkiDir, "CA"), e.issuerId + ".crt");
                    }
                    if (ic.exists()) {
                        chain.add(PemIO.readCert(ic.getAbsolutePath()));
                        if (issuer.type == 'C' && issuer.issuerId != null) {
                            java.io.File rc = new java.io.File(new java.io.File(pkiDir, "ROOT"), issuer.issuerId + ".crt");
                            if (rc.exists()) {
                                chain.add(PemIO.readCert(rc.getAbsolutePath()));
                            }
                        }
                    }
                }
            }
            // 私钥（可选：ROOT / CA / KEY 目录）
            AsymmetricKeyParameter key = null;
            for (String kd : new String[]{"ROOT", "CA", "KEY"}) {
                java.io.File kf = new java.io.File(new java.io.File(pkiDir, kd), serial + ".key");
                if (kf.exists()) {
                    try {
                        key = PemIO.readPrivateKey(kf.getAbsolutePath());
                    } catch (Exception ex) {
                        addLog("客户端调试私钥解析失败 " + serial + ": " + ex);
                    }
                    break;
                }
            }
            addLog("客户端调试证书加载成功 序列号=" + serial + " 类型=" + e.type
                    + " 链=" + chain.size() + " 级" + (key != null ? " 含私钥" : " 无私钥"));
            return new Object[]{chain, cert, key};
        } catch (Exception ex) {
            addLog("客户端调试证书加载异常 " + serial + ": " + ex);
            return null;
        }
    }


    private EapState takeEapState(String key) {
        synchronized (eapStates) {
            EapState st = eapStates.remove(key);
            if (st == null) {
                return null;
            }
            if (System.currentTimeMillis() > st.expires) {
                return null;
            }
            return st;
        }
    }

    private void evictEapStates() {
        long now = System.currentTimeMillis();
        eapStates.entrySet().removeIf(e -> now > e.getValue().expires);
    }

    // ==================== 隧道属性（RFC 2867 / 2868） ====================

    /** 解析包内隧道属性（Tunnel-Type/Medium/Endpoints/Password）并追加日志。 */
    private void logTunnelAttrs(Packet p, String src, String user, String kind) {
        List<String> parts = new ArrayList<>();
        for (byte[] v : p.getAttrs(ATTR_TUNNEL_TYPE)) {
            parts.add("类型=" + tunnelTypeName(v));
        }
        for (byte[] v : p.getAttrs(ATTR_TUNNEL_MEDIUM_TYPE)) {
            parts.add("介质=" + tunnelMediumName(v));
        }
        for (byte[] v : p.getAttrs(ATTR_TUNNEL_CLIENT_ENDPOINT)) {
            parts.add("客户端端点=" + new String(v, StandardCharsets.UTF_8));
        }
        for (byte[] v : p.getAttrs(ATTR_TUNNEL_SERVER_ENDPOINT)) {
            parts.add("服务端端点=" + new String(v, StandardCharsets.UTF_8));
        }
        for (byte[] v : p.getAttrs(ATTR_TUNNEL_PASSWORD)) {
            parts.add("隧道口令=" + v.length + "B");
        }
        if (!parts.isEmpty()) {
            addLog(kind + "请求携带隧道属性 来源=" + src + " 用户=" + user + " " + String.join(" ", parts));
            MLog.append(baseDir, "Radius 隧道属性", "用户=" + user + " 来源=" + src, String.join(" ", parts));
        }
    }

    /** Tunnel-Type 名称（RFC 2868 §3.1）。 */
    private static String tunnelTypeName(byte[] v) {
        if (v.length != 4) {
            return hexShort(v) + "(非法长度)";
        }
        int n = ((v[0] & 0xff) << 24) | ((v[1] & 0xff) << 16) | ((v[2] & 0xff) << 8) | (v[3] & 0xff);
        switch (n) {
            case 1: return "PPTP(1)";
            case 2: return "L2TP(2)";
            case 3: return "IPsec(3)";
            case 4: return "IP-in-IP(4)";
            case 5: return "GRE(5)";
            case 6: return "Minimal-IP(6)";
            case 7: return "L2F(7)";
            case 8: return "UDP(8)";
            case 9: return "GTP(9)";
            case 10: return "SCTP(10)";
            default: return "未知(" + n + ")";
        }
    }

    /** Tunnel-Medium-Type 名称（RFC 2868 §3.2）。 */
    private static String tunnelMediumName(byte[] v) {
        if (v.length != 4) {
            return hexShort(v) + "(非法长度)";
        }
        int n = ((v[0] & 0xff) << 24) | ((v[1] & 0xff) << 16) | ((v[2] & 0xff) << 8) | (v[3] & 0xff);
        switch (n) {
            case 1: return "IPv4(1)";
            case 2: return "IPv6(2)";
            case 3: return "NSAP(3)";
            case 4: return "HDLC(4)";
            case 5: return "X.25(5)";
            case 6: return "Frame-Relay(6)";
            case 7: return "ATM(7)";
            case 8: return "MPLS(8)";
            case 9: return "Ethernet(9)";
            default: return "未知(" + n + ")";
        }
    }

    // ---------- 计费（RFC 2866） ----------

    private byte[] handleAcct(DatagramPacket pkt) {
        Packet p;
        try {
            p = parsePacket(pkt.getData(), pkt.getLength());
        } catch (Exception e) {
            return null;
        }
        if (p.code != CODE_ACCT_REQUEST) {
            return null;
        }
        totalAcct++;
        String src = pkt.getAddress().getHostAddress() + ":" + pkt.getPort();
        String user = p.getString(ATTR_USER_NAME);
        int status = p.getInt(ATTR_ACCT_STATUS_TYPE);
        String session = p.getString(ATTR_ACCT_SESSION_ID);
        String statusName = status == 1 ? "Start" : status == 2 ? "Stop"
                : status == 3 ? "Interim-Update" : String.valueOf(status);
        int sessionTime = p.getInt(ATTR_ACCT_SESSION_TIME);
        logTunnelAttrs(p, src, user, "计费");
        addLog("计费请求 来源=" + src + " 用户=" + user + " 状态=" + statusName
                + " 会话=" + session + " 时长=" + sessionTime + "s");
        MLog.append(baseDir, "Radius 计费", "用户=" + user + " 状态=" + statusName + " 会话=" + session,
                "计费请求已记录（来源=" + src + "）");
        return buildPacket(CODE_ACCT_RESPONSE, p.identifier, p.authenticator, List.of(), secret);
    }

    // ==================== 响应构造 ====================

    /** 构造认证响应（Accept / Reject / Challenge），记录结果。 */
    private byte[] buildAuthResponse(int code, int id, byte[] reqAuth, UsersDB.User u,
                                     String username, InetAddress from, String resultMsg) {
        List<Attr> attrs = new ArrayList<>();
        if (code == CODE_ACCESS_ACCEPT) {
            attrs.add(new Attr(ATTR_SERVICE_TYPE, new byte[]{0, 0, 0, 2}));       // Framed
            attrs.add(new Attr(ATTR_FRAMED_PROTOCOL, new byte[]{0, 0, 0, 1}));    // PPP
            attrs.add(new Attr(ATTR_SESSION_TIMEOUT, intToBytes(3600)));          // 1 小时会话
        }
        boolean withMa = code == CODE_ACCESS_CHALLENGE;
        return buildPacket(code, id, reqAuth, attrs, secret, withMa);
    }

    /** 构造 EAP 响应包：把 EAP 包放进 EAP-Message 属性；Challenge 需带 Message-Authenticator。 */
    // 旧签名（无 EAP Type，用于 Success/Failure 等无 Type 包），委托新签名。
    private byte[] buildEapResponse(int code, int id, byte[] reqAuth, String username,
                                    int eapId, int eapCode, byte[] eapData, String msg) {
        return buildEapResponse(code, id, reqAuth, username, eapId, eapCode, -1, eapData, msg, null);
    }

    private byte[] buildEapResponse(int code, int id, byte[] reqAuth, String username,
                                    int eapId, int eapCode, int eapType, byte[] eapData, String msg) {
        return buildEapResponse(code, id, reqAuth, username, eapId, eapCode, eapType, eapData, msg, null);
    }

    /** 支持附加属性（如 MS-MPPE-*）的 EAP 响应构造；extraAttrs 仅在 Access-Accept 时并入。 */
    private byte[] buildEapResponse(int code, int id, byte[] reqAuth, String username,
                                    int eapId, int eapCode, int eapType, byte[] eapData, String msg,
                                    List<Attr> extraAttrs) {
        // 组装 EAP 包（Code / Id / Length / [Type] / Data）
        ByteArrayOutputStream e = new ByteArrayOutputStream();
        e.write(eapCode);
        e.write(eapId);
        if (eapData != null) {
            int len = (eapType >= 0 ? 5 : 4) + eapData.length;
            e.write(len >> 8);
            e.write(len);
            if (eapType >= 0) {
                e.write(eapType);
            }
            try {
                e.write(eapData);
            } catch (Exception ignored) {
            }
        } else {
            e.write(0);
            e.write(4);
        }
        byte[] eapPkt = e.toByteArray();
        List<Attr> attrs = new ArrayList<>();
        // RFC 3579 §2.1：EAP-Message 属性可重复且每个 ≤253B，接收端按出现顺序拼接还原 EAP 包
        for (int off = 0; off < eapPkt.length; off += 253) {
            attrs.add(new Attr(ATTR_EAP_MESSAGE,
                    Arrays.copyOfRange(eapPkt, off, Math.min(eapPkt.length, off + 253))));
        }
        if (code == CODE_ACCESS_ACCEPT) {
            attrs.add(new Attr(ATTR_SERVICE_TYPE, new byte[]{0, 0, 0, 2}));
            attrs.add(new Attr(ATTR_FRAMED_PROTOCOL, new byte[]{0, 0, 0, 1}));
            attrs.add(new Attr(ATTR_SESSION_TIMEOUT, intToBytes(3600)));
            if (extraAttrs != null) {
                attrs.addAll(extraAttrs);
            }
        }
        return buildPacket(code, id, reqAuth, attrs, secret, true);
    }

    /** 拼接包内全部 EAP-Message 属性值（RFC 3579 §2.1 多属性还原）；无则返回 null。 */
    static byte[] getEapMessageConcat(Packet p) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Attr a : p.attrs) {
            if (a.type == ATTR_EAP_MESSAGE) {
                out.write(a.value, 0, a.value.length);
            }
        }
        return out.size() == 0 ? null : out.toByteArray();
    }

    // ==================== 包编解码 ====================

    /** 解析 RADIUS 包（Code + Id + Length + Authenticator + 属性）。 */
    static Packet parsePacket(byte[] data, int len) {
        if (len < 20) {
            throw new IllegalArgumentException("RADIUS 包太短: " + len);
        }
        Packet p = new Packet();
        p.code = data[0] & 0xff;
        p.identifier = data[1] & 0xff;
        int length = ((data[2] & 0xff) << 8) | (data[3] & 0xff);
        if (length < 20 || length > len) {
            throw new IllegalArgumentException("RADIUS 包长度非法: " + length);
        }
        System.arraycopy(data, 4, p.authenticator, 0, 16);
        int off = 20;
        while (off + 2 <= length) {
            int t = data[off] & 0xff;
            int al = data[off + 1] & 0xff;
            if (al < 2 || off + al > length) {
                break;
            }
            p.attrs.add(new Attr(t, Arrays.copyOfRange(data, off + 2, off + al)));
            off += al;
        }
        return p;
    }

    /** 组装 RADIUS 包并计算响应 Authenticator = MD5(Code+Id+Length+ReqAuth+Attrs+Secret)。 */
    static byte[] buildPacket(int code, int id, byte[] reqAuth, List<Attr> attrs, String secret) {
        return buildPacket(code, id, reqAuth, attrs, secret, false);
    }

    /** 组装 RADIUS 包；withMa=true 时附加 Message-Authenticator（HMAC-MD5，RFC 2869 §5.14）。 */
    static byte[] buildPacket(int code, int id, byte[] reqAuth, List<Attr> attrs, String secret, boolean withMa) {
        List<Attr> list = new ArrayList<>(attrs);
        int maOffset = -1;
        if (withMa) {
            list.add(new Attr(ATTR_MESSAGE_AUTHENTICATOR, new byte[16]));
        }
        int len = 20;
        for (Attr a : list) {
            len += a.value.length + 2;
        }
        byte[] out = new byte[len];
        out[0] = (byte) code;
        out[1] = (byte) id;
        out[2] = (byte) (len >> 8);
        out[3] = (byte) len;
        System.arraycopy(reqAuth, 0, out, 4, 16);
        int off = 20;
        for (Attr a : list) {
            out[off] = (byte) a.type;
            out[off + 1] = (byte) (a.value.length + 2);
            System.arraycopy(a.value, 0, out, off + 2, a.value.length);
            if (withMa && a.type == ATTR_MESSAGE_AUTHENTICATOR) {
                maOffset = off;
            }
            off += a.value.length + 2;
        }
        if (withMa && maOffset >= 0) {
            byte[] mac = hmacMd5(secret.getBytes(StandardCharsets.UTF_8), out);
            System.arraycopy(mac, 0, out, maOffset + 2, 16);
        }
        byte[] respAuth = md5(out, secret);
        System.arraycopy(respAuth, 0, out, 4, 16);
        return out;
    }

    /** 校验请求包 Message-Authenticator：清掉属性 80 后对整包做 HMAC-MD5(secret)。 */
    static boolean verifyMessageAuthenticator(byte[] data, int len, int id, String secret) {
        byte[] copy = Arrays.copyOf(data, len);
        int off = 20;
        while (off + 2 <= len) {
            int t = copy[off] & 0xff;
            int al = copy[off + 1] & 0xff;
            if (al < 2 || off + al > len) {
                break;
            }
            if (t == ATTR_MESSAGE_AUTHENTICATOR) {
                Arrays.fill(copy, off + 2, off + al, (byte) 0);
            }
            off += al;
        }
        byte[] expect = hmacMd5(secret.getBytes(StandardCharsets.UTF_8), copy);
        // 提取原 mac 比对
        off = 20;
        while (off + 2 <= len) {
            int t = data[off] & 0xff;
            int al = data[off + 1] & 0xff;
            if (al < 2 || off + al > len) {
                break;
            }
            if (t == ATTR_MESSAGE_AUTHENTICATOR) {
                return constantTimeEquals(expect, Arrays.copyOfRange(data, off + 2, off + al));
            }
            off += al;
        }
        return false;
    }

    // ==================== 属性编解码 ====================

    /** 解密 User-Password（RFC 2865 §5.2）：每 16B 块 XOR MD5(secret + 前一块密文)。 */
    static String decodeUserPassword(byte[] enc, byte[] requestAuth, String secret) {
        if (enc == null || enc.length == 0) {
            return "";
        }
        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        int blocks = (enc.length + 15) / 16;
        byte[] out = new byte[blocks * 16];
        byte[] prev = requestAuth;
        for (int i = 0; i < blocks; i++) {
            byte[] hash = md5(concat(secretBytes, prev));
            for (int j = 0; j < 16; j++) {
                int src = i * 16 + j;
                out[src] = (byte) ((src < enc.length ? enc[src] : 0) ^ hash[j]);
            }
            prev = Arrays.copyOfRange(enc, i * 16, Math.min(i * 16 + 16, enc.length));
        }
        // 去尾部零填充
        int end = out.length;
        while (end > 0 && out[end - 1] == 0) {
            end--;
        }
        return new String(out, 0, end, StandardCharsets.UTF_8);
    }

    /** 解析 Vendor-Specific 属性：Vendor-ID(4B) + Vendor-Type(1B) + Vendor-Length(1B) + Data。 */
    private static MsChapVsa parseMsChapVsa(byte[] vsa) {
        if (vsa.length < 8) {
            return null;
        }
        int vendor = ((vsa[0] & 0xff) << 24) | ((vsa[1] & 0xff) << 16)
                | ((vsa[2] & 0xff) << 8) | (vsa[3] & 0xff);
        if (vendor != VENDOR_MICROSOFT) {
            return null;
        }
        MsChapVsa r = new MsChapVsa();
        r.vendorType = vsa[4] & 0xff;
        // RFC 2548：Vendor-Length 含 Vendor-Type(1)+Vendor-Length(1) 头，Vendor-Data 实际长度为 vlen-2
        int vlen = vsa[5] & 0xff;
        int dataLen = Math.max(0, vlen - 2);
        r.data = vsa.length >= 6 + dataLen ? Arrays.copyOfRange(vsa, 6, 6 + dataLen) : new byte[0];
        return r;
    }

    private static final class MsChapVsa {
        int vendorType;
        byte[] data;
    }

    /** MS-CHAPv2 响应验证（RFC 2759 §8.5）。 */
    boolean verifyMsChapV2(String password, String username,
                                  byte[] peerChallenge, byte[] authChallenge, byte[] ntResponse) {
        try {
            byte[] expected = computeNtResponse(password, username, peerChallenge, authChallenge);
            boolean ok = constantTimeEquals(expected, ntResponse);
            if (!ok) {
                addLog("[DBG] MSCHAPV2 校验失败 expected=" + hexFull(expected)
                        + " got=" + hexFull(ntResponse)
                        + " peer=" + hexFull(peerChallenge) + " auth=" + hexFull(authChallenge)
                        + " user=" + username + " chash=" + hexFull(Arrays.copyOf(sha1(
                            concat(peerChallenge, authChallenge,
                                username.getBytes(StandardCharsets.UTF_8))), 8)));
            }
            return ok;
        } catch (Exception e) {
            addLog("[DBG] MSCHAPV2 校验异常 " + e);
            return false;
        }
    }

    /** MS-CHAPv1 NT-Response 验证（RFC 2433 §5.3）：NT 口令哈希 2×DES 加密 8 字节挑战。 */
    static boolean verifyMsChapV1(String password, byte[] challenge, byte[] ntResponse) {
        try {
            byte[] expected = computeNtResponseV1(password, challenge);
            return constantTimeEquals(expected, ntResponse);
        } catch (Exception e) {
            return false;
        }
    }

    /** 计算 MS-CHAPv1 NT-Response（RFC 2433）：DESL(NT-Password-Hash, Challenge)。 */
    static byte[] computeNtResponseV1(String password, byte[] challenge) {
        byte[] passwordHash = ntPasswordHash(password);   // 16 字节 MD4
        byte[] expected = new byte[24];
        for (int i = 0; i < 2; i++) {
            byte[] key = Arrays.copyOfRange(passwordHash, i * 8, i * 8 + 8);
            setOddParity(key);
            DESEngine des = new DESEngine();
            des.init(true, new KeyParameter(key));
            des.processBlock(challenge, 0, expected, i * 8);
        }
        return expected;
    }

    /** 计算 MS-CHAPv2 NT-Response（RFC 2759 §8.5 / strongSwan eap-mschapv2.c）：
     *   Z = MD4(UTF-16LE(密码)) || 0x00×5（21 字节）
     *   ChallengeHash = SHA-1(Peer-Challenge || Authenticator-Challenge || UserName) 前 8 字节
     *   NT-Response = DesEncrypt(Z[0..6],   CHash) ||
     *                 DesEncrypt(Z[7..13],  CHash) ||
     *                 DesEncrypt(Z[14..20], CHash)        （同一 8 字节 CHash 加密三次）
     *  注意：RFC 2759 §8.2 权威定义用 SHA-1（非 MD5），只取前 8 字节。 */
    static byte[] computeNtResponse(String password, String username,
                                    byte[] peerChallenge, byte[] authChallenge) {
        byte[] passwordHash = ntPasswordHash(password);
        byte[] z = new byte[21];
        System.arraycopy(passwordHash, 0, z, 0, 16);
        byte[] challengeHash = Arrays.copyOf(sha1(concat(peerChallenge, authChallenge,
                username.getBytes(StandardCharsets.UTF_8))), 8);
        byte[] expected = new byte[24];
        for (int i = 0; i < 3; i++) {
            byte[] key8 = expandDesKey(Arrays.copyOfRange(z, i * 7, i * 7 + 7));
            DESEngine des = new DESEngine();
            des.init(true, new KeyParameter(key8));
            des.processBlock(challengeHash, 0, expected, i * 8);
        }
        return expected;
    }

    /** MS-CHAP DesEncrypt 密钥扩展：7 字节 key → 8 字节 DES key（RFC 2759 §8.5 位搬移，非标准奇偶位）。
     *  注意：Java byte 有符号，右移前必须 & 0xFF 转无符号，否则高位补 1 导致密钥错误。 */
    private static byte[] expandDesKey(byte[] k7) {
        byte[] key = new byte[8];
        key[0] = k7[0];
        key[1] = (byte) (((k7[0] << 7) & 0xFF) | ((k7[1] & 0xFF) >> 1));
        key[2] = (byte) (((k7[1] << 6) & 0xFF) | ((k7[2] & 0xFF) >> 2));
        key[3] = (byte) (((k7[2] << 5) & 0xFF) | ((k7[3] & 0xFF) >> 3));
        key[4] = (byte) (((k7[3] << 4) & 0xFF) | ((k7[4] & 0xFF) >> 4));
        key[5] = (byte) (((k7[4] << 3) & 0xFF) | ((k7[5] & 0xFF) >> 5));
        key[6] = (byte) (((k7[5] << 2) & 0xFF) | ((k7[6] & 0xFF) >> 6));
        key[7] = (byte) ((k7[6] << 1) & 0xFF);
        return key;
    }

    /** MD4 摘要（RFC 2759 NT Password Hash）。 */
    private static byte[] md4(byte[] data) {
        MD4Digest d = new MD4Digest();
        d.update(data, 0, data.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    /** NT Password Hash = MD4(UTF-16LE(password))。 */
    private static byte[] ntPasswordHash(String password) {
        return md4(password.getBytes(StandardCharsets.UTF_16LE));
    }

    /** DES 密钥奇偶校验位修正。 */
    private static void setOddParity(byte[] key) {
        for (int i = 0; i < key.length; i++) {
            int b = key[i] & 0xff;
            int ones = Integer.bitCount(b & 0xfe);
            key[i] = (byte) ((b & 0xfe) | ((ones & 1) == 0 ? 1 : 0));
        }
    }

    // ==================== 密码学工具 ====================

    private static byte[] md5(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            for (byte[] p : parts) {
                md.update(p);
            }
            return md.digest();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** SHA-1 摘要（RFC 2759 §8.2 ChallengeHash 使用，取前 8 字节）。 */
    private static byte[] sha1(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            for (byte[] p : parts) {
                md.update(p);
            }
            return md.digest();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ==================== MS-MPPE 会话密钥（RFC 3079 §3.1 + RFC 2548 §2.4.3） ====================

    /** RFC 3079 §3.1：MPPE Master Key 魔数 1（"This is the MPPE Master Key"）。 */
    private static final byte[] MSK_MAGIC1 =
            "This is the MPPE Master Key".getBytes(StandardCharsets.UTF_8);
    /** RFC 3079 §3.1：客户端发送 / 服务器接收密钥魔数 2。 */
    private static final byte[] MSK_MAGIC2 =
            "On the client side, this is the send key; on the server side, it is the receive key."
                    .getBytes(StandardCharsets.UTF_8);
    /** RFC 3079 §3.1：客户端接收 / 服务器发送密钥魔数 3。 */
    private static final byte[] MSK_MAGIC3 =
            "On the client side, this is the receive key; on the server side, it is the send key."
                    .getBytes(StandardCharsets.UTF_8);
    private static final byte[] MSK_SHAPAD1 = new byte[40];          // 40 × 0x00
    private static final byte[] MSK_SHAPAD2 = new byte[40];          // 40 × 0xF2
    static {
        java.util.Arrays.fill(MSK_SHAPAD2, (byte) 0xF2);
    }

    // 微软厂商 ID（RFC 2548）：311（已定义于常量区 VENDOR_MICROSOFT）。
    /** MS-MPPE-Send-Key（RFC 2548 §2.4.2：NAS 向客户端发送数据的密钥）。 */
    static final int MS_MPPE_SEND_KEY = 16;
    /** MS-MPPE-Recv-Key（RFC 2548 §2.4.2：NAS 从客户端接收数据的密钥）。 */
    static final int MS_MPPE_RECV_KEY = 17;

    /**
     * RFC 3079 §3.1：由 NT-Hash 与 NT-Response 派生 64 字节 EAP MSK。
     *   passwordHashHash = MD4(NT-Hash)
     *   master           = SHA1(passwordHashHash || NT-Response || magic1)[0..16]
     *   receiveKey       = SHA1(master || shapad1 || magic2 || shapad2)[0..16]   （客户端 send / 服务器 receive）
     *   sendKey          = SHA1(master || shapad1 || magic3 || shapad2)[0..16]   （客户端 recv  / 服务器 send）
     *   MSK = receiveKey || sendKey || 16×0x00 || 16×0x00（64 字节，RFC 5247）
     * 与 strongSwan eap-mschapv2.c GenerateMSK() 完全一致。
     */
    static byte[] deriveMschapv2Msk(byte[] ntHash, byte[] ntResponse) {
        byte[] passwordHashHash = md4(ntHash);
        byte[] master = Arrays.copyOf(sha1(passwordHashHash, ntResponse, MSK_MAGIC1), 16);
        byte[] receiveKey = Arrays.copyOf(sha1(master, MSK_SHAPAD1, MSK_MAGIC2, MSK_SHAPAD2), 16);
        byte[] sendKey = Arrays.copyOf(sha1(master, MSK_SHAPAD1, MSK_MAGIC3, MSK_SHAPAD2), 16);
        byte[] msk = new byte[64];
        System.arraycopy(receiveKey, 0, msk, 0, 16);
        System.arraycopy(sendKey, 0, msk, 16, 16);
        return msk;
    }

    /**
     * RFC 2759 §5 + §8.7：构造 MS-CHAPv2 方法层 Success 消息的 Data 部分
     * （EAP Type=26 之后的载荷，长度 4+42=46 字节）。
     *   结构：OpCode(1)=3 | MS-CHAPv2-ID(1) | MS-Length(2)=46 | Authenticator(42)
     *   Authenticator(42B) = AuthenticatorResponse(20B SHA1) || 22×0x00
     *   AuthenticatorResponse（RFC 2759 §8.7 GenerateAuthenticatorResponse，与 strongSwan
     *   eap-mschapv2.c AuthenticatorResponse() 逐字节一致）：
     *     Magic1(39B "Magic server to client signing constant")
     *     Magic2(41B "Pad to make it do more than one iteration")   ← 注意含 "do"，不是 "Magic client to server signing constant"
     *     challengeHash(8B) = SHA1(PeerChallenge || AuthenticatorChallenge || UserName)[0..8]
     *     digest1(20B)      = SHA1(NtHashHash || NT-Response || Magic1)
     *     AuthenticatorResponse(20B) = SHA1(digest1 || challengeHash || Magic2)
     *   其中 NtHashHash = MD4(NT-Hash)（即对密码做两次 MD4）。
     * 说明：EAP-MSCHAPv2 方法层 Success 的 Message 字段为 RFC 2759 §5 文本格式
     * "S=" + 40 个大写十六进制字符（= AuthenticatorResponse 20B），" M=<message>" 可选。
     * 2026-10-06 实机对照证实：同一 Windows 客户端 + strongSwan 网关下，FreeRADIUS 下发
     * 42B "S=40hex"（无 M=）即可成功；MODPKICA 此前因 Magic2 常量写错（漏 "do"）导致
     * AuthenticatorResponse 计算错误，Windows 按 §8.8 CheckAuthenticatorResponse 校验失败，
     * 静默丢弃方法层 Success → 645 内部身份验证错误。此处已修正并去掉 M= 以与
     * FreeRADIUS 成功链路逐字节一致（" S=" 后内容、长度、大小写全部相同）。
     */
    static byte[] buildMschapv2Success(int mschapId, byte[] peerChallenge,
                                       byte[] authChallenge, byte[] ntResponse,
                                       byte[] ntHashHash, String username) {
        byte[] magic1 = "Magic server to client signing constant".getBytes(StandardCharsets.US_ASCII);
        byte[] magic2 = "Pad to make it do more than one iteration".getBytes(StandardCharsets.US_ASCII);
        byte[] challengeHash = Arrays.copyOf(
                sha1(peerChallenge, authChallenge,
                        username.getBytes(StandardCharsets.US_ASCII)), 8);
        byte[] digest1 = sha1(ntHashHash, ntResponse, magic1);
        byte[] digest2 = sha1(digest1, challengeHash, magic2);   // 20B AuthenticatorResponse
        // RFC 2759 §5：Success 消息 Message 字段 = "S=<auth_string>"（42B，大写十六进制）。
        // <auth_string> = 20B SHA1 AuthenticatorResponse 的 40 个大写十六进制字符。
        StringBuilder sb = new StringBuilder(64);
        sb.append("S=");
        for (byte b : digest2) {
            sb.append(Character.toUpperCase(Character.forDigit((b >> 4) & 0x0f, 16)));
            sb.append(Character.toUpperCase(Character.forDigit(b & 0x0f, 16)));
        }
        byte[] msg = sb.toString().getBytes(StandardCharsets.US_ASCII);
        // MSCHAPV2 数据 = OpCode(1)+ID(1)+MS-Length(2)+Message(msgLen)
        byte[] data = new byte[4 + msg.length];
        data[0] = 3;                        // OpCode = Success
        data[1] = (byte) mschapId;
        int msLen = 4 + msg.length;         // 整条 Success 消息长度（含本字段）
        data[2] = (byte) (msLen >> 8);
        data[3] = (byte) msLen;
        System.arraycopy(msg, 0, data, 4, msg.length);
        return data;
    }

    /**
     * RFC 2548 §2.4.3：MS-MPPE 密钥加密。
     *   plain = keyLen(1B) || key || 0x00…（补齐到 16 的倍数）
     *   b(1) = MD5(Secret || Request-Authenticator || Salt)
     *   c(1) = p(1) ⊕ b(1)；
     *   b(i) = MD5(Secret || c(i-1))，c(i) = p(i) ⊕ b(i)
     * 返回 2 字节 Salt || 密文（Salt 首字节 MSB=0、整体非零）。
     */
    static byte[] encryptMppeKey(byte[] key, byte[] reqAuth, String secret) {
        int total = (1 + key.length + 15) / 16 * 16;
        byte[] plain = new byte[total];
        plain[0] = (byte) key.length;
        System.arraycopy(key, 0, plain, 1, key.length);
        byte[] salt = new byte[2];
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        do {
            rnd.nextBytes(salt);
            salt[0] &= 0x7f;
        } while (salt[0] == 0 && salt[1] == 0);
        byte[] sec = secret.getBytes(StandardCharsets.UTF_8);
        byte[] b = md5(sec, reqAuth, salt);
        byte[] cipher = new byte[total];
        for (int i = 0; i < total; i += 16) {
            for (int j = 0; j < 16 && i + j < total; j++) {
                cipher[i + j] = (byte) (plain[i + j] ^ b[j]);
            }
            if (i + 16 < total) {
                b = md5(sec, Arrays.copyOfRange(cipher, i, i + 16));
            }
        }
        byte[] out = new byte[2 + total];
        System.arraycopy(salt, 0, out, 0, 2);
        System.arraycopy(cipher, 0, out, 2, total);
        return out;
    }

    /**
     * 构造 MS-MPPE Vendor-Specific 属性（strongSwan mppe_key_t 布局）：
     *   Vendor-ID(4B)=311 || Type(1B: 16/17) || Length(1B: 4+N) || Salt(2B) || Cipher(NB)
     * vendorType：MS_MPPE_SEND_KEY(16) / MS_MPPE_RECV_KEY(17)。
     */
    static Attr msMppeAttr(int vendorType, byte[] key, byte[] reqAuth, String secret) {
        byte[] salted = encryptMppeKey(key, reqAuth, secret);
        byte[] v = new byte[4 + 1 + 1 + salted.length];
        v[0] = 0; v[1] = 0; v[2] = 1; v[3] = 0x37;                      // 311
        v[4] = (byte) vendorType;
        v[5] = (byte) (1 + 1 + 2 + (salted.length - 2));                 // 4 + N（Length 含 Type+Length+Salt+Cipher）
        System.arraycopy(salted, 0, v, 6, salted.length);
        return new Attr(ATTR_VENDOR_SPECIFIC, v);
    }

    /** MD5(data || secret)。 */
    private static byte[] md5(byte[] data, String secret) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(data);
            md.update(secret.getBytes(StandardCharsets.UTF_8));
            return md.digest();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] hmacMd5(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(new SecretKeySpec(key, "HmacMD5"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            try {
                b.write(p);
            } catch (Exception ignored) {
            }
        }
        return b.toByteArray();
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) {
            return false;
        }
        int r = 0;
        for (int i = 0; i < a.length; i++) {
            r |= a[i] ^ b[i];
        }
        return r == 0;
    }

    private static byte[] intToBytes(int v) {
        return new byte[]{(byte) (v >> 24), (byte) (v >> 16), (byte) (v >> 8), (byte) v};
    }

    // ==================== 日志与状态 ====================

    private void addLog(String msg) {
        LogEntry e = new LogEntry(++logSeq, timeNow(), msg);
        logs.addFirst(e);
        while (logs.size() > MAX_LOG_ENTRIES) {
            logs.removeLast();
        }
    }

    private void logAuthResult(String src, String username, String method, boolean ok, String via) {
        totalAuthRequests++;
        if (ok) {
            authOk++;
        } else {
            authFail++;
        }
        String prefix = via == null ? method : via + "(" + method + ")";
        addLog("收到 NAS 请求 来源=" + src + " 用户=" + username + " 认证方法=" + prefix
                + " 结果=" + (ok ? "通过" : "拒绝"));
        MLog.append(baseDir, "Radius 认证", "来源=" + src + " 用户=" + username + " 方法=" + prefix,
                ok ? "认证通过" : "认证失败");
    }

    private static String timeNow() {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
    }

    /** 当前状态（供面板 /api/radius/status）。 */
    public Map<String, Object> statusJson() {
        Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("running", running);
        m.put("authPort", authPort);
        m.put("acctPort", acctPort);
        m.put("secret", secret);
        m.put("accounts", UsersDB.load(baseDir).size());
        m.put("totalAuthRequests", totalAuthRequests);
        m.put("authOk", authOk);
        m.put("authFail", authFail);
        m.put("totalAcct", totalAcct);
        m.put("startTime", startTime == 0 ? 0 : startTime);
        m.put("startTimeText", startTime == 0 ? "" : timeNow());
        return m;
    }

    /** 环形日志（最新在前）。 */
    public List<LogEntry> logs(int limit) {
        List<LogEntry> out = new ArrayList<>();
        int n = 0;
        for (LogEntry e : logs) {
            out.add(e);
            if (++n >= limit) {
                break;
            }
        }
        return out;
    }

    /** 清空环形日志。 */
    public void clearLogs() {
        logs.clear();
    }

    /** 清空统计（可选）。 */
    public void resetStats() {
        totalAuthRequests = 0;
        authOk = 0;
        authFail = 0;
        totalAcct = 0;
    }

    // ==================== 客户端调试（模拟 NAS 发起认证） ====================

    /**
     * 模拟 RADIUS 客户端发起一次认证，返回步骤化日志与结果。
     *
     * @param method   PAP / CHAP / MS-CHAPv2 / EAP-MD5
     * @param username 用户名
     * @param password 密码
     * @param secret   共享密钥（必须与服务端一致）
     * @param authPort 认证端口（UDP，&lt;=0 用默认 1812）
     */
    public Map<String, Object> clientDial(String method, String username, String password,
                                          String secret, int authPort) {
        return clientDial(method, username, password, secret, authPort, null);
    }

    /** 客户端调试入口（certSerial 可选：TLS 族认证用该证书作为信任锚验证服务器证书，若含私钥同时作为客户端证书）。 */
    public Map<String, Object> clientDial(String method, String username, String password,
                                          String secret, int authPort, String certSerial) {
        List<String> steps = new ArrayList<>();
        if (username == null || username.isEmpty() || password == null) {
            throw new IllegalArgumentException("用户名与密码不能为空");
        }
        if (secret == null || secret.isEmpty()) {
            throw new IllegalArgumentException("共享密钥不能为空");
        }
        int port = authPort > 0 ? authPort : DEFAULT_AUTH_PORT;
        steps.add("=== RADIUS 客户端认证模拟开始 ===");
        steps.add("账号: " + username + "，认证方式: " + method + "，目标: 127.0.0.1:" + port);
        try (DatagramSocket sock = new DatagramSocket()) {
            sock.setSoTimeout(3000);
            InetAddress host = InetAddress.getByName("127.0.0.1");
            java.security.SecureRandom rnd = new java.security.SecureRandom();
            int id = rnd.nextInt(256);
            byte[] reqAuth = new byte[16];
            rnd.nextBytes(reqAuth);
            switch (method == null ? "" : method.trim().toUpperCase()) {
                case "PAP":
                    return papClientDial(sock, host, port, id, reqAuth, username, password, secret, steps);
                case "CHAP":
                    return chapClientDial(sock, host, port, id, reqAuth, username, password, secret, steps);
                case "MS-CHAPV2":
                case "MS-CHAP-V2":
                    return msChapV2ClientDial(sock, host, port, id, reqAuth, username, password, secret, steps);
                case "MS-CHAPV1":
                case "MS-CHAP-V1":
                case "MSCHAPV1":
                    return msChapV1ClientDial(sock, host, port, id, reqAuth, username, password, secret, steps);
                case "EAP-MD5":
                case "EAPMD5":
                    return eapMd5ClientDial(sock, host, port, id, reqAuth, username, password, secret, steps);
                case "EAP-GTC":
                case "EAPGTC":
                    return eapGtcClientDial(sock, host, port, id, reqAuth, username, password, secret, steps);
                case "EAP-MSCHAPV2":
                case "EAP-MSCHAP-V2":
                case "EAPMSCHAPV2":
                    return eapMsChapV2ClientDial(sock, host, port, id, reqAuth, username, password, secret, steps);
                case "EAP-TLS":
                case "EAPTLS":
                    return eapTlsClientDial(sock, host, port, id, reqAuth, username, secret, steps, certSerial);
                case "EAP-TTLS":
                case "EAPTTLS":
                    return eapTtlsClientDial(sock, host, port, id, reqAuth, username, password, secret, steps, certSerial);
                case "EAP-PWD":
                case "EAPPWD":
                    return eapPwdClientDial(sock, host, port, id, reqAuth, username, password, secret, steps);
                case "PEAP-MD5":
                case "PEAPMD5":
                    return eapPeapClientDial(sock, host, port, id, reqAuth, username, password, secret, "MD5", steps, certSerial);
                case "PEAP-MSCHAPV2":
                case "PEAP-MSCHAP-V2":
                case "PEAPMSCHAPV2":
                    return eapPeapClientDial(sock, host, port, id, reqAuth, username, password, secret, "MSCHAPV2", steps, certSerial);
                case "PEAP-GTC":
                case "PEAPGTC":
                    return eapPeapClientDial(sock, host, port, id, reqAuth, username, password, secret, "GTC", steps, certSerial);
                default:
                    throw new IllegalArgumentException("不支持的认证方式: " + method
                            + "（可选 PAP / CHAP / MS-CHAPv1 / MS-CHAPv2 / EAP-MD5 / EAP-GTC / EAP-TLS / EAP-TTLS / PEAP-MD5 / PEAP-MSCHAPv2 / PEAP-GTC / EAP-pwd）");
            }
        } catch (java.net.SocketTimeoutException e) {
            steps.add("结果: 等待响应超时（服务未运行、端口错误或共享密钥不匹配）");
            return clientResult(false, "超时无响应", steps);
        } catch (java.net.PortUnreachableException e) {
            steps.add("结果: 端口不可达 " + e.getMessage());
            return clientResult(false, "端口不可达", steps);
        } catch (Exception e) {
            java.io.StringWriter sw = new java.io.StringWriter();
            e.printStackTrace(new java.io.PrintWriter(sw));
            steps.add("结果: 异常 " + e.getMessage());
            steps.add(sw.toString());
            return clientResult(false, "异常: " + e.getMessage() + " | " + sw.toString(), steps);
        }
    }

    private static Map<String, Object> clientResult(boolean ok, String message, List<String> steps) {
        steps.add("=== 流程结束 ===");
        steps.add("结果: " + message);
        Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("ok", ok);
        m.put("message", message);
        m.put("logs", steps);
        return m;
    }

    /** PAP：User-Name + User-Password（RFC 2865 §5.2 MD5 混淆）。 */
    private static Map<String, Object> papClientDial(DatagramSocket sock, InetAddress host, int port,
            int id, byte[] reqAuth, String username, String password, String secret, List<String> steps)
            throws Exception {
        byte[] encPw = encodeUserPassword(password, reqAuth, secret);
        List<Attr> attrs = new ArrayList<>();
        attrs.add(new Attr(ATTR_USER_NAME, username.getBytes(StandardCharsets.UTF_8)));
        attrs.add(new Attr(ATTR_USER_PASSWORD, encPw));
        byte[] req = buildRequestPacket(id, reqAuth, attrs, null, false);
        steps.add("[1] 构造 Access-Request：User-Name(" + username + ") + User-Password(" + encPw.length
                + "B，RFC 2865 §5.2 用 MD5(secret+Authenticator) 混淆)");
        byte[] resp = sendRecv(sock, req, host, port, steps, "[2]");
        Packet p = parsePacket(resp, resp.length);
        steps.add("[3] 收到 " + respName(p.code) + "（ID=" + p.identifier + "，"
                + (verifyRespAuth(resp, reqAuth, secret) ? "响应 Authenticator 校验通过" : "响应 Authenticator 校验失败") + "）");
        boolean ok = p.code == CODE_ACCESS_ACCEPT;
        return clientResult(ok, ok ? "PAP 认证通过" : "PAP 认证失败", steps);
    }

    /** CHAP：User-Name + CHAP-Password + CHAP-Challenge（RFC 1994 / 2865 §5.3）。 */
    private static Map<String, Object> chapClientDial(DatagramSocket sock, InetAddress host, int port,
            int id, byte[] reqAuth, String username, String password, String secret, List<String> steps)
            throws Exception {
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        byte[] challenge = new byte[16];
        rnd.nextBytes(challenge);
        byte chapId = (byte) rnd.nextInt(256);
        byte[] resp16 = md5(new byte[]{chapId}, password.getBytes(StandardCharsets.UTF_8), challenge);
        byte[] chapPw = new byte[17];
        chapPw[0] = chapId;
        System.arraycopy(resp16, 0, chapPw, 1, 16);
        List<Attr> attrs = new ArrayList<>();
        attrs.add(new Attr(ATTR_USER_NAME, username.getBytes(StandardCharsets.UTF_8)));
        attrs.add(new Attr(ATTR_CHAP_PASSWORD, chapPw));
        attrs.add(new Attr(ATTR_CHAP_CHALLENGE, challenge));
        byte[] req = buildRequestPacket(id, reqAuth, attrs, null, false);
        steps.add("[1] 构造 Access-Request：User-Name(" + username + ") + CHAP-Password("
                + hexShort(chapPw) + "，MD5(chapId||密码||挑战)) + CHAP-Challenge(" + hexShort(challenge) + ")");
        byte[] resp = sendRecv(sock, req, host, port, steps, "[2]");
        Packet p = parsePacket(resp, resp.length);
        steps.add("[3] 收到 " + respName(p.code) + "（ID=" + p.identifier + "，"
                + (verifyRespAuth(resp, reqAuth, secret) ? "响应 Authenticator 校验通过" : "响应 Authenticator 校验失败") + "）");
        boolean ok = p.code == CODE_ACCESS_ACCEPT;
        return clientResult(ok, ok ? "CHAP 认证通过" : "CHAP 认证失败", steps);
    }

    /** MS-CHAPv2：Vendor-Specific Microsoft（RFC 2548 / 2759 §8.5，单包携带挑战+响应）。 */
    private static Map<String, Object> msChapV2ClientDial(DatagramSocket sock, InetAddress host, int port,
            int id, byte[] reqAuth, String username, String password, String secret, List<String> steps)
            throws Exception {
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        byte[] peerChallenge = new byte[16];
        rnd.nextBytes(peerChallenge);
        byte[] authChallenge = new byte[16];
        rnd.nextBytes(authChallenge);
        byte ntResp = (byte) rnd.nextInt(256);
        byte[] ntResponse = computeNtResponse(password, username, peerChallenge, authChallenge);
        // MS-CHAP2-Response: Ident(1) Flags(1) PeerChallenge(16) Reserved(8) NT-Response(24) Flags(1)
        byte[] chapData = new byte[51];
        chapData[0] = ntResp;
        chapData[1] = 0;
        System.arraycopy(peerChallenge, 0, chapData, 2, 16);
        System.arraycopy(ntResponse, 0, chapData, 26, 24);
        List<Attr> attrs = new ArrayList<>();
        attrs.add(new Attr(ATTR_USER_NAME, username.getBytes(StandardCharsets.UTF_8)));
        attrs.add(new Attr(ATTR_VENDOR_SPECIFIC, msChapVsa(MS_CHAP_CHALLENGE, authChallenge)));
        attrs.add(new Attr(ATTR_VENDOR_SPECIFIC, msChapVsa(MS_CHAP2_RESPONSE, chapData)));
        byte[] req = buildRequestPacket(id, reqAuth, attrs, null, false);
        steps.add("[1] 构造 Access-Request：User-Name(" + username + ") + MS-CHAP-Challenge("
                + hexShort(authChallenge) + ") + MS-CHAP2-Response(" + hexShort(ntResponse)
                + "，MD4口令哈希+3×DES 挑战加密)");
        steps.add("    说明：RFC 2759 标准为两阶段（服务器先发挑战）；本服务器实现为单包携带挑战+响应，客户端自生成挑战并计算 NT-Response");
        byte[] resp = sendRecv(sock, req, host, port, steps, "[2]");
        Packet p = parsePacket(resp, resp.length);
        steps.add("[3] 收到 " + respName(p.code) + "（ID=" + p.identifier + "，"
                + (verifyRespAuth(resp, reqAuth, secret) ? "响应 Authenticator 校验通过" : "响应 Authenticator 校验失败") + "）");
        boolean ok = p.code == CODE_ACCESS_ACCEPT;
        return clientResult(ok, ok ? "MS-CHAPv2 认证通过" : "MS-CHAPv2 认证失败", steps);
    }

    /** MS-CHAPv1：Vendor-Specific Microsoft（RFC 2548 / 2433，单包携带 8 字节挑战 + 49 字节响应）。 */
    private static Map<String, Object> msChapV1ClientDial(DatagramSocket sock, InetAddress host, int port,
            int id, byte[] reqAuth, String username, String password, String secret, List<String> steps)
            throws Exception {
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        byte[] challenge = new byte[8];                       // MS-CHAPv1 挑战为 8 字节
        rnd.nextBytes(challenge);
        byte ntResp = (byte) rnd.nextInt(256);
        byte[] ntResponse = computeNtResponseV1(password, challenge);   // 24 字节
        // MS-CHAP-Response: Ident(1) LM-Response(24) NT-Response(24)，LM 置零（服务器只验 NT 部分）
        byte[] chapData = new byte[49];
        chapData[0] = ntResp;
        System.arraycopy(ntResponse, 0, chapData, 25, 24);
        List<Attr> attrs = new ArrayList<>();
        attrs.add(new Attr(ATTR_USER_NAME, username.getBytes(StandardCharsets.UTF_8)));
        attrs.add(new Attr(ATTR_VENDOR_SPECIFIC, msChapVsa(MS_CHAP_CHALLENGE, challenge)));
        attrs.add(new Attr(ATTR_VENDOR_SPECIFIC, msChapVsa(MS_CHAP1_RESPONSE, chapData)));
        byte[] req = buildRequestPacket(id, reqAuth, attrs, null, false);
        steps.add("[1] 构造 Access-Request：User-Name(" + username + ") + MS-CHAP-Challenge("
                + hexShort(challenge) + "，8字节) + MS-CHAP-Response(" + hexShort(ntResponse)
                + "，DESL(NT-Password-Hash, Challenge) RFC 2433)");
        byte[] resp = sendRecv(sock, req, host, port, steps, "[2]");
        Packet p = parsePacket(resp, resp.length);
        steps.add("[3] 收到 " + respName(p.code) + "（ID=" + p.identifier + "，"
                + (verifyRespAuth(resp, reqAuth, secret) ? "响应 Authenticator 校验通过" : "响应 Authenticator 校验失败") + "）");
        boolean ok = p.code == CODE_ACCESS_ACCEPT;
        return clientResult(ok, ok ? "MS-CHAPv1 认证通过" : "MS-CHAPv1 认证失败", steps);
    }

    /** EAP-TLS：EAP-Identity(tls:前缀) → Start → BC TlsClientProtocol 握手（RFC 5216，多轮分片交换）。 */
    private Map<String, Object> eapTlsClientDial(DatagramSocket sock, InetAddress host, int port,
            int id, byte[] reqAuth, String username, String secret, List<String> steps, String certSerial) throws Exception {
        String eapUser = username.startsWith("tls:") ? username : "tls:" + username;
        // [1] EAP-Identity
        byte[] eapIdPkt = eapPacket(EAP_CODE_RESPONSE, id, EAP_TYPE_IDENTITY,
                eapUser.getBytes(StandardCharsets.UTF_8));
        List<Attr> attrs = new ArrayList<>();
        attrs.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
        attrs.add(new Attr(ATTR_EAP_MESSAGE, eapIdPkt));
        byte[] req1 = buildRequestPacket(id, reqAuth, attrs, secret, true);
        steps.add("[1] 发送 Access-Request：EAP-Response/Identity(" + eapUser + ") + Message-Authenticator");
        byte[] resp1 = sendRecv(sock, req1, host, port, steps, "[2]");
        Packet p1 = parsePacket(resp1, resp1.length);
        if (p1.code != CODE_ACCESS_CHALLENGE) {
            return clientResult(false, "EAP-TLS 服务器未返回 Start（收到 " + respName(p1.code) + "）", steps);
        }
        byte[] eapStart = getEapMessageConcat(p1);
        if (eapStart == null || eapStart.length < 6 || (eapStart[0] & 0xff) != EAP_CODE_REQUEST
                || (eapStart[4] & 0xff) != EAP_TYPE_TLS) {
            return clientResult(false, "EAP-TLS Start 格式非法", steps);
        }
        steps.add("[3] 收到 EAP-Request/TLS Start（RADIUS=Access-Challenge）");
        int eapId = eapStart[1] & 0xff;

        // [4] 加载可选客户端证书（信任锚 + 客户端凭据）→ 启动 BC TLS 客户端握手线程
        Object[] cred = loadClientTlsCred(certSerial);
        @SuppressWarnings("unchecked")
        List<X509Certificate> anchors = cred != null ? (List<X509Certificate>) cred[0] : null;
        X509Certificate cCert = cred != null ? (X509Certificate) cred[1] : null;
        AsymmetricKeyParameter cKey = cred != null ? (AsymmetricKeyParameter) cred[2] : null;
        if (cred != null) {
            steps.add("已加载客户端证书（信任锚链 " + anchors.size() + " 级"
                    + (cKey != null ? "，含私钥作客户端凭据" : "") + "）");
        }
        EapTlsSession cs = new EapTlsSession(eapUser);
        Thread t = new Thread(() -> {
            try {
                TlsClientProtocol proto = new TlsClientProtocol(cs.inStream, cs.outStream);
                cs.clientTlsProto = proto;
                TrustedTlsClient client = new TrustedTlsClient(new BcTlsCrypto(new SecureRandom()),
                        anchors, cCert, cKey);
                proto.connect(client);
                cs.ok = true;
            } catch (Exception ex) {
                cs.err = ex.toString();
            } finally {
                cs.done = true;
                cs.notifyOutput();
            }
        }, "eap-tls-client");
        t.setDaemon(true);
        t.start();

        // [5] 多轮：ClientHello → 服务器 TLS 输出 → 重组 → 喂回 TLS → …
        int round = 4;
        byte[] clientOut = cs.pollOutput(6000);
        if (clientOut == null) {
            return clientResult(false, "EAP-TLS 客户端握手无输出", steps);
        }
        for (int i = 0; i < 16; i++) {
            // —— 发送阶段：clientOut 按 RFC 5216 逐片发送（每片一个 EAP 包） ——
            byte[][] frags = splitTlsFragments(clientOut);
            Packet p2 = null;
            byte[] srvData = null;
            for (int fi = 0; fi < frags.length; fi++) {
                byte[] eapResp = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_TLS, frags[fi]);
                List<Attr> a2 = new ArrayList<>();
                a2.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
                a2.add(new Attr(ATTR_EAP_MESSAGE, eapResp));   // 单片 ≤253B → 单 EAP-Message 属性
                byte[] req2 = buildRequestPacket(id, reqAuth, a2, secret, true);
                steps.add("[" + round++ + "] 发送 EAP-Response/TLS（片 " + (fi + 1) + "/" + frags.length
                        + "，" + clientOut.length + "B 拆 " + frags.length + " 片）");
                byte[] resp2 = sendRecv(sock, req2, host, port, steps, "[" + round++ + "]");
                p2 = parsePacket(resp2, resp2.length);
                if (p2.code == CODE_ACCESS_ACCEPT) {
                    return clientResult(true, "EAP-TLS 认证通过（EAP-Success）", steps);
                }
                if (p2.code == CODE_ACCESS_REJECT) {
                    return clientResult(false, "EAP-TLS 认证失败（Access-Reject）", steps);
                }
                byte[] eapSrv = getEapMessageConcat(p2);
                if (eapSrv == null || eapSrv.length < 6 || (eapSrv[0] & 0xff) != EAP_CODE_REQUEST
                        || (eapSrv[4] & 0xff) != EAP_TYPE_TLS) {
                    return clientResult(false, "EAP-TLS 服务器响应格式非法（" + respName(p2.code) + "）", steps);
                }
                srvData = Arrays.copyOfRange(eapSrv, 5, eapSrv.length);
                if (srvData.length > 1) {
                    break;   // 服务器返回真实 TLS 输出，进入解析
                }
                // 空挑战：继续发下一片
            }
            // —— 服务器输出解析 + 拉取，直到拿到一段完整 TLS 记录 ——
            byte[] full = null;
            for (int pf = 0; pf < 8; pf++) {
                if (srvData == null || srvData.length < 1) {
                    return clientResult(false, "EAP-TLS 服务器数据为空", steps);
                }
                int sFlags = srvData[0] & 0xff;
                int sOff = 1;
                long sTotal = -1;
                if ((sFlags & EAP_TLS_FLAG_LENGTH) != 0) {
                    if (srvData.length < 5) {
                        return clientResult(false, "EAP-TLS 服务器长度字段缺失", steps);
                    }
                    sTotal = ((long) (srvData[1] & 0xff) << 24) | ((srvData[2] & 0xff) << 16)
                            | ((srvData[3] & 0xff) << 8) | (srvData[4] & 0xff);
                    sOff = 5;
                }
                // 空挑战（START 标志、无数据）：服务器暂无输出——直接拉取
                if (srvData.length == sOff && (sFlags & EAP_TLS_FLAG_START) != 0) {
                    full = null;
                } else {
                    byte[] sFrag = Arrays.copyOfRange(srvData, sOff, srvData.length);
                    full = cs.reassemble(sFrag, sFlags, sTotal);
                }
                if (full != null) {
                    break;
                }
                // 未完整（M=1 或空挑战）——发空 EAP-Response/TLS 拉取续片
                steps.add("[" + round++ + "] 收到服务器 TLS 分片（M=1，继续拉取）");
                byte[] pull = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_TLS, new byte[]{(byte) 0});
                List<Attr> a3 = new ArrayList<>();
                a3.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
                a3.add(new Attr(ATTR_EAP_MESSAGE, pull));
                byte[] req3 = buildRequestPacket(id, reqAuth, a3, secret, true);
                byte[] resp3 = sendRecv(sock, req3, host, port, steps, "[" + round++ + "]");
                Packet p3 = parsePacket(resp3, resp3.length);
                if (p3.code == CODE_ACCESS_ACCEPT) {
                    return clientResult(true, "EAP-TLS 认证通过（EAP-Success）", steps);
                }
                if (p3.code == CODE_ACCESS_REJECT) {
                    return clientResult(false, "EAP-TLS 认证失败（Access-Reject）", steps);
                }
                byte[] eapSrv2 = getEapMessageConcat(p3);
                if (eapSrv2 == null || eapSrv2.length < 6 || (eapSrv2[0] & 0xff) != EAP_CODE_REQUEST
                        || (eapSrv2[4] & 0xff) != EAP_TYPE_TLS) {
                    return clientResult(false, "EAP-TLS 服务器续片格式非法", steps);
                }
                srvData = Arrays.copyOfRange(eapSrv2, 5, eapSrv2.length);
            }
            if (full == null) {
                return clientResult(false, "EAP-TLS 服务器分片重组未完成", steps);
            }
            cs.feed(full);
            clientOut = cs.pollOutput(6000);
            if (clientOut == null) {
                return clientResult(false, "EAP-TLS 握手超时", steps);
            }
            if (cs.done && !cs.ok) {
                return clientResult(false, "EAP-TLS 客户端握手失败: " + cs.err, steps);
            }
            if (cs.done && cs.ok) {
                // 握手完成：发空 EAP-Response/TLS 让服务器收尾发 EAP-Success
                byte[] fin = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_TLS, new byte[]{(byte) 0});
                List<Attr> a4 = new ArrayList<>();
                a4.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
                a4.add(new Attr(ATTR_EAP_MESSAGE, fin));
                byte[] req4 = buildRequestPacket(id, reqAuth, a4, secret, true);
                steps.add("[" + round++ + "] 握手完成，发送 EAP-Response/TLS(空)");
                byte[] resp4 = sendRecv(sock, req4, host, port, steps, "[" + round++ + "]");
                Packet p4 = parsePacket(resp4, resp4.length);
                if (p4.code == CODE_ACCESS_ACCEPT) {
                    return clientResult(true, "EAP-TLS 认证通过（EAP-Success）", steps);
                }
                return clientResult(false, "EAP-TLS 认证失败（" + respName(p4.code) + "）", steps);
            }
        }
        return clientResult(false, "EAP-TLS 握手轮次超限", steps);
    }

    /**
     * 启动 EAP-TTLS（RFC 5281）：外层 TLS 隧道握手后，内层以 AVP 帧交换 PAP 认证
     * （RFC 5281 §8.3 属性格式：Type(1)+Length(1)+Value；§8.5 内层 User-Password 明文）。
     */
    private byte[] startEapTtls(Packet p, int eapId, String username, String src) {
        TlsServerCred cred = loadTlsServerCred();
        if (cred == null) {
            authFail++;
            addLog("EAP-TTLS 无可用服务端证书 来源=" + src + " 用户=" + username);
            return buildEapResponse(CODE_ACCESS_REJECT, p.identifier, p.authenticator,
                    username, eapId, EAP_CODE_FAILURE, null, "EAP-TTLS 服务端证书缺失");
        }
        final String realUser;
        if (username.regionMatches(true, 0, "ttls:", 0, 5)) {
            realUser = username.substring(5);
        } else if (username.regionMatches(true, 0, "eap-ttls:", 0, 9)) {
            realUser = username.substring(9);
        } else {
            realUser = username;
        }
        int radiusId = p.identifier;
        EapTlsSession s = new EapTlsSession(realUser);
        s.innerEap = true;
        s.innerMethod = "TTLS-PAP";
        tlsSessions.put(radiusId, s);
        s.thread = new Thread(() -> {
            try {
                ModpkicaTlsServer server = new ModpkicaTlsServer(cred);
                TlsServerProtocol proto = new TlsServerProtocol(s.inStream, s.outStream);
                s.tlsProto = proto;
                proto.accept(server);   // 外层 TLS 隧道握手（RFC 5281 §7）
                s.innerUser = realUser;
                s.ok = ttlsInnerPap(proto, realUser);
                if (!s.ok) {
                    s.err = "TTLS 内层 PAP 认证失败 用户=" + realUser;
                }
            } catch (Exception ex) {
                s.err = ex.toString();
            } finally {
                s.done = true;
                s.notifyOutput();
            }
        }, "eap-ttls-handshake");
        s.thread.setDaemon(true);
        s.thread.start();
        addLog("EAP-TTLS 启动握手 来源=" + src + " 用户=" + username + "（内层=PAP，真实用户=" + realUser + "）");
        return buildEapResponse(CODE_ACCESS_CHALLENGE, p.identifier, p.authenticator,
                username, eapId, EAP_CODE_REQUEST, EAP_TYPE_TTLS,
                new byte[]{(byte) EAP_TLS_FLAG_START}, null);
    }

    /**
     * TTLS 内层 PAP（RFC 5281 §8.5）：隧道内 AVP 帧交换——
     * 服务器发 User-Name AVP 请求（Type=1，Len=2 空值），客户端回 User-Name + User-Password(明文) AVP。
     */
    private boolean ttlsInnerPap(TlsServerProtocol proto, String username) throws Exception {
        InputStream tin = proto.getInputStream();
        byte[] avpReq = new byte[]{1, 2};   // Type=1(User-Name) Length=2（请求客户端提供用户名/密码）
        proto.getOutputStream().write(avpReq);
        proto.getOutputStream().flush();
        // 读 AVP 帧：逐 AVP 解析（Type(1)+Length(1)+Value），直到拿到 User-Password
        byte[] avpUser = null;
        byte[] avpPass = null;
        for (int i = 0; i < 16; i++) {
            int t = tin.read();
            int l = tin.read();
            if (t < 0 || l < 2 || l > 255) {
                return false;
            }
            byte[] v = new byte[l - 2];
            for (int j = 0; j < v.length; j++) {
                int b = tin.read();
                if (b < 0) {
                    return false;
                }
                v[j] = (byte) b;
            }
            if (t == 1 && v.length > 0) {
                avpUser = v;
            } else if (t == 2) {
                avpPass = v;
                break;
            }
        }
        if (avpPass == null) {
            return false;
        }
        UsersDB.User u = UsersDB.find(baseDir, username);
        return u != null && u.enabled() && constantTimeEquals(
                u.password.getBytes(StandardCharsets.UTF_8), avpPass);
    }

    /**
     * 客户端 PEAP 隧道交换：把一段 TLS 输出逐片发送给服务器并持续拉取，
     * 直到收到一段完整服务器 TLS 输出（返回该数据，调用方 feed 进客户端 TLS）。
     * 若服务器直接 ACCEPT/REJECT，settled[0]=true 且 settledOk[0] 记录结果，返回 null。
     */
    private static byte[] tunnelExchange(DatagramSocket sock, InetAddress host, int port, int id,
            byte[] reqAuth, String eapUser, String secret, int eapId, EapTlsSession cs,
            List<String> steps, int[] round, byte[] out, boolean[] settled, boolean[] settledOk)
            throws Exception {
        byte[][] frags = splitTlsFragments(out);
        byte[] srvData = null;
        for (int fi = 0; fi < frags.length; fi++) {
            byte[] eapResp = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_PEAP, frags[fi]);
            List<Attr> a = new ArrayList<>();
            a.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
            a.add(new Attr(ATTR_EAP_MESSAGE, eapResp));
            byte[] req = buildRequestPacket(id, reqAuth, a, secret, true);
            steps.add("[" + round[0]++ + "] 发送 PEAP 隧道分片（片 " + (fi + 1) + "/" + frags.length + "）");
            byte[] resp = sendRecv(sock, req, host, port, steps, "[" + round[0]++ + "]");
            Packet p = parsePacket(resp, resp.length);
            if (p.code == CODE_ACCESS_ACCEPT) {
                settled[0] = true;
                settledOk[0] = true;
                return null;
            }
            if (p.code == CODE_ACCESS_REJECT) {
                settled[0] = true;
                settledOk[0] = false;
                return null;
            }
            byte[] eapSrv = getEapMessageConcat(p);
            if (eapSrv == null || eapSrv.length < 6 || (eapSrv[0] & 0xff) != EAP_CODE_REQUEST
                    || (eapSrv[4] & 0xff) != EAP_TYPE_PEAP) {
                settled[0] = true;
                settledOk[0] = false;
                return null;
            }
            srvData = Arrays.copyOfRange(eapSrv, 5, eapSrv.length);
            if (srvData.length > 1) {
                break;
            }
        }
        // 服务器输出解析 + 拉取，直到拿到一段完整 TLS 记录
        byte[] full = null;
        for (int pf = 0; pf < 8; pf++) {
            if (srvData == null || srvData.length < 1) {
                settled[0] = true;
                settledOk[0] = false;
                return null;
            }
            int sFlags = srvData[0] & 0xff;
            int sOff = 1;
            long sTotal = -1;
            if ((sFlags & EAP_TLS_FLAG_LENGTH) != 0) {
                if (srvData.length < 5) {
                    settled[0] = true;
                    settledOk[0] = false;
                    return null;
                }
                sTotal = ((long) (srvData[1] & 0xff) << 24) | ((srvData[2] & 0xff) << 16)
                        | ((srvData[3] & 0xff) << 8) | (srvData[4] & 0xff);
                sOff = 5;
            }
            if (srvData.length == sOff && (sFlags & EAP_TLS_FLAG_START) != 0) {
                full = null;   // 空挑战：拉取续片
            } else {
                byte[] sFrag = Arrays.copyOfRange(srvData, sOff, srvData.length);
                full = cs.reassemble(sFrag, sFlags, sTotal);
            }
            if (full != null) {
                break;
            }
            byte[] pull = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_PEAP, new byte[]{(byte) 0});
            List<Attr> a2 = new ArrayList<>();
            a2.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
            a2.add(new Attr(ATTR_EAP_MESSAGE, pull));
            byte[] req2 = buildRequestPacket(id, reqAuth, a2, secret, true);
            steps.add("[" + round[0]++ + "] 收到服务器隧道分片（M=1，继续拉取）");
            byte[] resp2 = sendRecv(sock, req2, host, port, steps, "[" + round[0]++ + "]");
            Packet p2 = parsePacket(resp2, resp2.length);
            if (p2.code == CODE_ACCESS_ACCEPT) {
                settled[0] = true;
                settledOk[0] = true;
                return null;
            }
            if (p2.code == CODE_ACCESS_REJECT) {
                settled[0] = true;
                settledOk[0] = false;
                return null;
            }
            byte[] eapSrv2 = getEapMessageConcat(p2);
            if (eapSrv2 == null || eapSrv2.length < 6 || (eapSrv2[0] & 0xff) != EAP_CODE_REQUEST
                    || (eapSrv2[4] & 0xff) != EAP_TYPE_PEAP) {
                settled[0] = true;
                settledOk[0] = false;
                return null;
            }
            srvData = Arrays.copyOfRange(eapSrv2, 5, eapSrv2.length);
        }
        if (full == null) {
            settled[0] = true;
            settledOk[0] = false;
            return null;
        }
        return full;
    }

    /**
     * PEAP（RFC 5216）：EAP-Identity(peap:前缀) → Start 交换 → 外层 TLS 握手（BC TlsClientProtocol，
     * 多轮分片交换同 EAP-TLS）→ TLS 隧道建立 → 内层 EAP（MD5 或 MS-CHAPv2，隧道内挑战/响应）→ EAP-Success。
     */
    private Map<String, Object> eapPeapClientDial(DatagramSocket sock, InetAddress host, int port,
            int id, byte[] reqAuth, String username, String password, String secret, String innerMethod,
            List<String> steps, String certSerial) throws Exception {
        String inner = innerMethod == null ? "MD5" : innerMethod.toUpperCase();
        boolean innerMschapv2 = "MSCHAPV2".equals(inner);
        boolean innerGtc = "GTC".equals(inner);
        String prefix = innerMschapv2 ? "peap-mschapv2:" : (innerGtc ? "peap-gtc:" : "peap:");
        String eapUser = username.startsWith(prefix) ? username : prefix + username;
        // [1] EAP-Identity(peap:xxx)
        byte[] eapIdPkt = eapPacket(EAP_CODE_RESPONSE, id, EAP_TYPE_IDENTITY,
                eapUser.getBytes(StandardCharsets.UTF_8));
        List<Attr> attrs = new ArrayList<>();
        attrs.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
        attrs.add(new Attr(ATTR_EAP_MESSAGE, eapIdPkt));
        byte[] req1 = buildRequestPacket(id, reqAuth, attrs, secret, true);
        steps.add("[1] 发送 Access-Request：EAP-Response/Identity(" + eapUser + ") + Message-Authenticator");
        byte[] resp1 = sendRecv(sock, req1, host, port, steps, "[2]");
        Packet p1 = parsePacket(resp1, resp1.length);
        if (p1.code != CODE_ACCESS_CHALLENGE) {
            return clientResult(false, "PEAP 服务器未返回 Start（收到 " + respName(p1.code) + "）", steps);
        }
        byte[] eapStart = getEapMessageConcat(p1);
        if (eapStart == null || eapStart.length < 6 || (eapStart[0] & 0xff) != EAP_CODE_REQUEST
                || (eapStart[4] & 0xff) != EAP_TYPE_PEAP) {
            return clientResult(false, "PEAP Start 格式非法", steps);
        }
        steps.add("[3] 收到 EAP-Request/PEAP/Start（RADIUS=Access-Challenge，S 位）");
        int eapId = eapStart[1] & 0xff;

        // [4] 客户端确认 Start（EAP-Response/PEAP/Start，S 位）
        byte[] startResp = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_PEAP,
                new byte[]{(byte) EAP_TLS_FLAG_START});
        List<Attr> a1 = new ArrayList<>();
        a1.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
        a1.add(new Attr(ATTR_EAP_MESSAGE, startResp));
        byte[] reqS = buildRequestPacket(id, reqAuth, a1, secret, true);
        steps.add("[4] 发送 EAP-Response/PEAP/Start（S 位确认）");
        byte[] respS = sendRecv(sock, reqS, host, port, steps, "[5]");
        Packet pS = parsePacket(respS, respS.length);
        if (pS.code == CODE_ACCESS_ACCEPT) {
            return clientResult(true, "PEAP 认证通过（EAP-Success）", steps);
        }
        if (pS.code == CODE_ACCESS_REJECT) {
            return clientResult(false, "PEAP 认证失败（Access-Reject）", steps);
        }

        // [6] 加载可选客户端证书（信任锚 + 客户端凭据）→ 启动 BC TLS 客户端握手线程
        Object[] cred = loadClientTlsCred(certSerial);
        @SuppressWarnings("unchecked")
        List<X509Certificate> anchors = cred != null ? (List<X509Certificate>) cred[0] : null;
        X509Certificate cCert = cred != null ? (X509Certificate) cred[1] : null;
        AsymmetricKeyParameter cKey = cred != null ? (AsymmetricKeyParameter) cred[2] : null;
        if (cred != null) {
            steps.add("已加载客户端证书（信任锚链 " + anchors.size() + " 级"
                    + (cKey != null ? "，含私钥作客户端凭据" : "") + "）");
        }
        EapTlsSession cs = new EapTlsSession(eapUser);
        Thread t = new Thread(() -> {
            try {
                TlsClientProtocol proto = new TlsClientProtocol(cs.inStream, cs.outStream);
                cs.clientTlsProto = proto;
                TrustedTlsClient client = new TrustedTlsClient(new BcTlsCrypto(new SecureRandom()),
                        anchors, cCert, cKey);
                proto.connect(client);
                cs.ok = true;
            } catch (Exception ex) {
                cs.err = ex.toString();
            } finally {
                cs.done = true;
                cs.notifyOutput();
            }
        }, "eap-peap-client");
        t.setDaemon(true);
        t.start();

        // [7] 多轮：ClientHello → 服务器 TLS 输出 → 重组 → 喂回 TLS → …
        int round = 6;
        byte[] clientOut = cs.pollOutput(6000);
        if (clientOut == null) {
            return clientResult(false, "PEAP 客户端握手无输出", steps);
        }
        for (int i = 0; i < 16; i++) {
            // —— 发送阶段：clientOut 逐片发送（每片一个 EAP 包，RFC 5216 §2.1） ——
            byte[][] frags = splitTlsFragments(clientOut);
            Packet p2 = null;
            byte[] srvData = null;
            for (int fi = 0; fi < frags.length; fi++) {
                byte[] eapResp = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_PEAP, frags[fi]);
                List<Attr> a2 = new ArrayList<>();
                a2.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
                a2.add(new Attr(ATTR_EAP_MESSAGE, eapResp));
                byte[] req2 = buildRequestPacket(id, reqAuth, a2, secret, true);
                steps.add("[" + round++ + "] 发送 EAP-Response/PEAP/TLS（片 " + (fi + 1) + "/" + frags.length
                        + "，" + clientOut.length + "B 拆 " + frags.length + " 片）");
                byte[] resp2 = sendRecv(sock, req2, host, port, steps, "[" + round++ + "]");
                p2 = parsePacket(resp2, resp2.length);
                if (p2.code == CODE_ACCESS_ACCEPT) {
                    return clientResult(true, "PEAP 认证通过（EAP-Success）", steps);
                }
                if (p2.code == CODE_ACCESS_REJECT) {
                    return clientResult(false, "PEAP 认证失败（Access-Reject）", steps);
                }
                byte[] eapSrv = getEapMessageConcat(p2);
                if (eapSrv == null || eapSrv.length < 6 || (eapSrv[0] & 0xff) != EAP_CODE_REQUEST
                        || (eapSrv[4] & 0xff) != EAP_TYPE_PEAP) {
                    return clientResult(false, "PEAP 服务器响应格式非法（" + respName(p2.code) + "）", steps);
                }
                srvData = Arrays.copyOfRange(eapSrv, 5, eapSrv.length);
                if (srvData.length > 1) {
                    break;   // 服务器返回真实 TLS 输出，进入解析
                }
                // 空挑战：继续发下一片
            }
            // —— 服务器输出解析 + 拉取，直到拿到一段完整 TLS 记录 ——
            byte[] full = null;
            for (int pf = 0; pf < 8; pf++) {
                if (srvData == null || srvData.length < 1) {
                    return clientResult(false, "PEAP 服务器数据为空", steps);
                }
                int sFlags = srvData[0] & 0xff;
                int sOff = 1;
                long sTotal = -1;
                if ((sFlags & EAP_TLS_FLAG_LENGTH) != 0) {
                    if (srvData.length < 5) {
                        return clientResult(false, "PEAP 服务器长度字段缺失", steps);
                    }
                    sTotal = ((long) (srvData[1] & 0xff) << 24) | ((srvData[2] & 0xff) << 16)
                            | ((srvData[3] & 0xff) << 8) | (srvData[4] & 0xff);
                    sOff = 5;
                }
                if (srvData.length == sOff && (sFlags & EAP_TLS_FLAG_START) != 0) {
                    full = null;   // 空挑战：直接拉取
                } else {
                    byte[] sFrag = Arrays.copyOfRange(srvData, sOff, srvData.length);
                    full = cs.reassemble(sFrag, sFlags, sTotal);
                }
                if (full != null) {
                    break;
                }
                // 未完整（M=1 或空挑战）——发空 EAP-Response/PEAP 拉取续片
                steps.add("[" + round++ + "] 收到服务器 PEAP TLS 分片（M=1，继续拉取）");
                byte[] pull = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_PEAP, new byte[]{(byte) 0});
                List<Attr> a3 = new ArrayList<>();
                a3.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
                a3.add(new Attr(ATTR_EAP_MESSAGE, pull));
                byte[] req3 = buildRequestPacket(id, reqAuth, a3, secret, true);
                byte[] resp3 = sendRecv(sock, req3, host, port, steps, "[" + round++ + "]");
                Packet p3 = parsePacket(resp3, resp3.length);
                if (p3.code == CODE_ACCESS_ACCEPT) {
                    return clientResult(true, "PEAP 认证通过（EAP-Success）", steps);
                }
                if (p3.code == CODE_ACCESS_REJECT) {
                    return clientResult(false, "PEAP 认证失败（Access-Reject）", steps);
                }
                byte[] eapSrv2 = getEapMessageConcat(p3);
                if (eapSrv2 == null || eapSrv2.length < 6 || (eapSrv2[0] & 0xff) != EAP_CODE_REQUEST
                        || (eapSrv2[4] & 0xff) != EAP_TYPE_PEAP) {
                    return clientResult(false, "PEAP 服务器续片格式非法", steps);
                }
                srvData = Arrays.copyOfRange(eapSrv2, 5, eapSrv2.length);
            }
            if (full == null) {
                return clientResult(false, "PEAP 服务器分片重组未完成", steps);
            }
            cs.feed(full);
            clientOut = cs.pollOutput(6000);
            if (clientOut == null) {
                return clientResult(false, "PEAP 握手超时", steps);
            }
            if (cs.done && !cs.ok) {
                return clientResult(false, "PEAP 客户端握手失败: " + cs.err, steps);
            }
            if (cs.done && cs.ok) {
                // [8] TLS 隧道建立 → 内层 EAP（RFC 5216 §3.2）
                steps.add("[" + round++ + "] 外层 TLS 隧道建立，进入内层 EAP-" + inner);
                if (innerMschapv2) {
                    // —— 内层 MS-CHAPv2：Identity → Challenge → NT-Response（每轮隧道内 TLS 输出都要回传） ——
                    byte[] innerIdReq = readEapPacket(cs.clientTlsProto.getInputStream());
                    if ((innerIdReq[0] & 0xff) != EAP_CODE_REQUEST
                            || (innerIdReq[4] & 0xff) != EAP_TYPE_IDENTITY) {
                        return clientResult(false, "PEAP 内层 Identity 请求格式非法", steps);
                    }
                    String realUser = username;
                    if (realUser.startsWith("peap-mschapv2:")) {
                        realUser = realUser.substring(14);
                    } else if (realUser.startsWith("eap-peap-mschapv2:")) {
                        realUser = realUser.substring(18);
                    }
                    byte[] innerIdResp = eapPacket(EAP_CODE_RESPONSE, innerIdReq[1], EAP_TYPE_IDENTITY,
                            realUser.getBytes(StandardCharsets.UTF_8));
                    cs.clientTlsProto.getOutputStream().write(innerIdResp);
                    cs.clientTlsProto.getOutputStream().flush();
                    steps.add("[" + round++ + "] 内层 EAP-Response/Identity(" + realUser + ") 已写入隧道");
                    boolean[] settled = new boolean[1];
                    boolean[] settledOk = new boolean[1];
                    byte[] out1 = cs.pollOutput(6000);
                    if (out1 == null) {
                        return clientResult(false, "PEAP 内层 Identity TLS 输出超时", steps);
                    }
                    byte[] feed1 = tunnelExchange(sock, host, port, id, reqAuth, eapUser, secret, eapId,
                            cs, steps, new int[]{round}, out1, settled, settledOk);
                    round = steps.size();
                    if (settled[0]) {
                        return clientResult(settledOk[0], settledOk[0]
                                ? "PEAP 认证通过（EAP-Success）" : "PEAP 认证失败（Access-Reject）", steps);
                    }
                    cs.feed(feed1);
                    byte[] chalReq = readEapPacket(cs.clientTlsProto.getInputStream());
                    if ((chalReq[0] & 0xff) != EAP_CODE_REQUEST || (chalReq[4] & 0xff) != EAP_TYPE_MSCHAPV2) {
                        return clientResult(false, "PEAP 内层 MS-CHAPv2 挑战格式非法", steps);
                    }
                    // Data: OpCode(1)=1, MS-CHAPv2-ID(1), MS-Length(2), Value-Size(1)=16, Value(16B 挑战), Name
                    int mschapId = chalReq[6] & 0xff;
                    int vsize = chalReq[9] & 0xff;
                    if (vsize != 16 || chalReq.length < 10 + vsize) {
                        return clientResult(false, "PEAP 内层 MS-CHAPv2 挑战长度非法", steps);
                    }
                    byte[] authChallenge = Arrays.copyOfRange(chalReq, 10, 10 + vsize);
                    byte[] peerChallenge = new byte[16];
                    new java.security.SecureRandom().nextBytes(peerChallenge);
                    byte[] ntResp = computeNtResponse(password, realUser, peerChallenge, authChallenge);
                    // 标准 EAP-MSCHAPv2 Response（RFC 2759 §3.4）：
                    //   OpCode(1)=2, MS-CHAPv2-ID(1), MS-Length(2), Value-Size(1)=49,
                    //   Value(49B) = Peer-Challenge(16) + Reserved(8) + NT-Response(24) + Flags(1), Name
                    byte[] value = new byte[49];
                    System.arraycopy(peerChallenge, 0, value, 0, 16);
                    System.arraycopy(ntResp, 0, value, 24, 24);
                    byte[] respNameB = realUser.getBytes(StandardCharsets.UTF_8);
                    int msLen = 1 + 1 + 2 + 1 + 49 + respNameB.length;
                    byte[] respData = concat(new byte[]{2, (byte) mschapId,
                            (byte) (msLen >> 8), (byte) msLen, 49}, value, respNameB);
                    byte[] innerResp = eapPacket(EAP_CODE_RESPONSE, chalReq[1], EAP_TYPE_MSCHAPV2, respData);
                    cs.clientTlsProto.getOutputStream().write(innerResp);
                    cs.clientTlsProto.getOutputStream().flush();
                    steps.add("[" + round++ + "] 内层 EAP-Response/MSCHAPV2 已写入隧道（NT-Response "
                            + hexShort(ntResp) + "）");
                    byte[] out2 = cs.pollOutput(6000);
                    if (out2 == null) {
                        return clientResult(false, "PEAP 内层响应 TLS 输出超时", steps);
                    }
                    byte[] feed2 = tunnelExchange(sock, host, port, id, reqAuth, eapUser, secret, eapId,
                            cs, steps, new int[]{round}, out2, settled, settledOk);
                    round = steps.size();
                    if (settled[0]) {
                        return clientResult(settledOk[0], settledOk[0]
                                ? "PEAP 认证通过（EAP-Success）" : "PEAP 认证失败（Access-Reject）", steps);
                    }
                    if (feed2 != null) {
                        cs.feed(feed2);
                    }
                } else if (innerGtc) {
                    // —— 内层 GTC：Identity → 提示 → 明文令牌（RFC 3748 §5.6 隧道内） ——
                    byte[] innerIdReq = readEapPacket(cs.clientTlsProto.getInputStream());
                    if ((innerIdReq[0] & 0xff) != EAP_CODE_REQUEST
                            || (innerIdReq[4] & 0xff) != EAP_TYPE_IDENTITY) {
                        return clientResult(false, "PEAP 内层 Identity 请求格式非法", steps);
                    }
                    String realUser = username;
                    if (realUser.startsWith("peap-gtc:")) {
                        realUser = realUser.substring(9);
                    } else if (realUser.startsWith("eap-peap-gtc:")) {
                        realUser = realUser.substring(14);
                    }
                    byte[] innerIdResp = eapPacket(EAP_CODE_RESPONSE, innerIdReq[1], EAP_TYPE_IDENTITY,
                            realUser.getBytes(StandardCharsets.UTF_8));
                    cs.clientTlsProto.getOutputStream().write(innerIdResp);
                    cs.clientTlsProto.getOutputStream().flush();
                    steps.add("[" + round++ + "] 内层 EAP-Response/Identity(" + realUser + ") 已写入隧道");
                    boolean[] settled = new boolean[1];
                    boolean[] settledOk = new boolean[1];
                    byte[] out1 = cs.pollOutput(6000);
                    if (out1 == null) {
                        return clientResult(false, "PEAP 内层 Identity TLS 输出超时", steps);
                    }
                    byte[] feed1 = tunnelExchange(sock, host, port, id, reqAuth, eapUser, secret, eapId,
                            cs, steps, new int[]{round}, out1, settled, settledOk);
                    round = steps.size();
                    if (settled[0]) {
                        return clientResult(settledOk[0], settledOk[0]
                                ? "PEAP 认证通过（EAP-Success）" : "PEAP 认证失败（Access-Reject）", steps);
                    }
                    cs.feed(feed1);
                    byte[] gtcReq = readEapPacket(cs.clientTlsProto.getInputStream());
                    if ((gtcReq[0] & 0xff) != EAP_CODE_REQUEST || (gtcReq[4] & 0xff) != EAP_TYPE_GTC) {
                        return clientResult(false, "PEAP 内层 GTC 提示格式非法", steps);
                    }
                    byte[] gtcResp = eapPacket(EAP_CODE_RESPONSE, gtcReq[1], EAP_TYPE_GTC,
                            password.getBytes(StandardCharsets.UTF_8));
                    cs.clientTlsProto.getOutputStream().write(gtcResp);
                    cs.clientTlsProto.getOutputStream().flush();
                    steps.add("[" + round++ + "] 内层 EAP-Response/GTC 已写入隧道（明文令牌，RFC 3748 §5.6）");
                    byte[] out2 = cs.pollOutput(6000);
                    if (out2 == null) {
                        return clientResult(false, "PEAP 内层 GTC TLS 输出超时", steps);
                    }
                    byte[] feed2 = tunnelExchange(sock, host, port, id, reqAuth, eapUser, secret, eapId,
                            cs, steps, new int[]{round}, out2, settled, settledOk);
                    round = steps.size();
                    if (settled[0]) {
                        return clientResult(settledOk[0], settledOk[0]
                                ? "PEAP 认证通过（EAP-Success）" : "PEAP 认证失败（Access-Reject）", steps);
                    }
                    if (feed2 != null) {
                        cs.feed(feed2);
                    }
                } else {
                    // —— 内层 MD5 ——
                    byte[] innerReq = readEapPacket(cs.clientTlsProto.getInputStream());
                    if ((innerReq[0] & 0xff) != EAP_CODE_REQUEST || (innerReq[4] & 0xff) != EAP_TYPE_MD5) {
                        return clientResult(false, "PEAP 内层挑战格式非法", steps);
                    }
                    int innerId = innerReq[1] & 0xff;
                    int vsize = innerReq[5] & 0xff;
                    if (vsize != 16 || innerReq.length < 6 + vsize) {
                        return clientResult(false, "PEAP 内层 MD5 挑战长度非法", steps);
                    }
                    byte[] challenge = Arrays.copyOfRange(innerReq, 6, 6 + vsize);
                    byte[] md5resp = md5(new byte[]{(byte) innerId},
                            password.getBytes(StandardCharsets.UTF_8), challenge);
                    byte[] innerData = new byte[17];
                    innerData[0] = 16;
                    System.arraycopy(md5resp, 0, innerData, 1, 16);
                    byte[] innerResp = eapPacket(EAP_CODE_RESPONSE, innerId, EAP_TYPE_MD5, innerData);
                    cs.clientTlsProto.getOutputStream().write(innerResp);
                    cs.clientTlsProto.getOutputStream().flush();
                    steps.add("[" + round++ + "] 内层 EAP-Response/MD5 已写入隧道（" + hexShort(md5resp) + "）");
                }
                // [9] 取 TLS 加密输出（内层响应记录）并逐片发给服务器（每片一个 EAP 包）
                byte[] innerOut = cs.pollOutput(6000);
                if (innerOut == null) {
                    return clientResult(false, "PEAP 内层响应 TLS 输出超时", steps);
                }
                byte[][] innerFrags = splitTlsFragments(innerOut);
                Packet p4 = null;
                for (int fi = 0; fi < innerFrags.length; fi++) {
                    byte[] eapResp = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_PEAP, innerFrags[fi]);
                    List<Attr> a4 = new ArrayList<>();
                    a4.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
                    a4.add(new Attr(ATTR_EAP_MESSAGE, eapResp));
                    byte[] req4 = buildRequestPacket(id, reqAuth, a4, secret, true);
                    steps.add("[" + round++ + "] 发送内层响应 TLS 分片（片 " + (fi + 1) + "/" + innerFrags.length + "）");
                    byte[] resp4 = sendRecv(sock, req4, host, port, steps, "[" + round++ + "]");
                    p4 = parsePacket(resp4, resp4.length);
                    if (p4.code == CODE_ACCESS_ACCEPT) {
                        return clientResult(true, "PEAP 认证通过（EAP-Success）", steps);
                    }
                    if (p4.code == CODE_ACCESS_REJECT) {
                        return clientResult(false, "PEAP 认证失败（Access-Reject）", steps);
                    }
                }
                // [10] 外层空响应让服务器收尾发 EAP-Success
                byte[] fin = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_PEAP, new byte[]{(byte) 0});
                List<Attr> a5 = new ArrayList<>();
                a5.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
                a5.add(new Attr(ATTR_EAP_MESSAGE, fin));
                byte[] req5 = buildRequestPacket(id, reqAuth, a5, secret, true);
                steps.add("[" + round++ + "] 内层认证完成，发送 EAP-Response/PEAP(空)");
                byte[] resp5 = sendRecv(sock, req5, host, port, steps, "[" + round++ + "]");
                Packet p5 = parsePacket(resp5, resp5.length);
                if (p5.code == CODE_ACCESS_ACCEPT) {
                    return clientResult(true, "PEAP 认证通过（EAP-Success）", steps);
                }
                return clientResult(false, "PEAP 认证失败（" + respName(p5.code) + "）", steps);
            }
        }
        return clientResult(false, "PEAP 握手轮次超限", steps);
    }

    /** 读一个 TTLS 内层 AVP（RFC 5281 §8.3：Type(1)+Length(1)+Value）。 */
    private static byte[] readTtlsAvpFrame(InputStream tin) throws Exception {
        int t = tin.read();
        int l = tin.read();
        if (t < 0 || l < 2 || l > 255) {
            throw new IOException("TTLS AVP 帧非法（t=" + t + " l=" + l + "）");
        }
        byte[] v = new byte[l - 2];
        for (int j = 0; j < v.length; j++) {
            int b = tin.read();
            if (b < 0) {
                throw new IOException("TTLS AVP 帧截断");
            }
            v[j] = (byte) b;
        }
        return concat(new byte[]{(byte) t, (byte) l}, v);
    }

    /**
     * EAP-TTLS（RFC 5281）：外层 TLS 隧道（与 PEAP 同构分片交换），隧道建立后内层以
     * AVP 帧交换 PAP（§8.5 内层 User-Password 明文）：服务器发 User-Name 请求，客户端回
     * User-Name + User-Password AVP → 服务器验证 → EAP-Success。
     */
    private Map<String, Object> eapTtlsClientDial(DatagramSocket sock, InetAddress host, int port,
            int id, byte[] reqAuth, String username, String password, String secret, List<String> steps,
            String certSerial) throws Exception {
        String eapUser = username.startsWith("ttls:") ? username : "ttls:" + username;
        byte[] eapIdPkt = eapPacket(EAP_CODE_RESPONSE, id, EAP_TYPE_IDENTITY,
                eapUser.getBytes(StandardCharsets.UTF_8));
        List<Attr> attrs = new ArrayList<>();
        attrs.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
        attrs.add(new Attr(ATTR_EAP_MESSAGE, eapIdPkt));
        byte[] req1 = buildRequestPacket(id, reqAuth, attrs, secret, true);
        steps.add("[1] 发送 Access-Request：EAP-Response/Identity(" + eapUser + ") + Message-Authenticator");
        byte[] resp1 = sendRecv(sock, req1, host, port, steps, "[2]");
        Packet p1 = parsePacket(resp1, resp1.length);
        if (p1.code != CODE_ACCESS_CHALLENGE) {
            return clientResult(false, "TTLS 服务器未返回 Start（收到 " + respName(p1.code) + "）", steps);
        }
        byte[] eapStart = getEapMessageConcat(p1);
        if (eapStart == null || eapStart.length < 6 || (eapStart[0] & 0xff) != EAP_CODE_REQUEST
                || (eapStart[4] & 0xff) != EAP_TYPE_TTLS) {
            return clientResult(false, "TTLS Start 格式非法", steps);
        }
        steps.add("[3] 收到 EAP-Request/TTLS/Start（RADIUS=Access-Challenge，S 位）");
        int eapId = eapStart[1] & 0xff;
        byte[] startResp = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_TTLS,
                new byte[]{(byte) EAP_TLS_FLAG_START});
        List<Attr> a1 = new ArrayList<>();
        a1.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
        a1.add(new Attr(ATTR_EAP_MESSAGE, startResp));
        byte[] reqS = buildRequestPacket(id, reqAuth, a1, secret, true);
        steps.add("[4] 发送 EAP-Response/TTLS/Start（S 位确认）");
        byte[] respS = sendRecv(sock, reqS, host, port, steps, "[5]");
        Packet pS = parsePacket(respS, respS.length);
        if (pS.code == CODE_ACCESS_ACCEPT) {
            return clientResult(true, "TTLS 认证通过（EAP-Success）", steps);
        }
        if (pS.code == CODE_ACCESS_REJECT) {
            return clientResult(false, "TTLS 认证失败（Access-Reject）", steps);
        }
        // 加载可选客户端证书（信任锚 + 客户端凭据）→ 启动 BC TLS 客户端握手线程
        Object[] cred = loadClientTlsCred(certSerial);
        @SuppressWarnings("unchecked")
        List<X509Certificate> anchors = cred != null ? (List<X509Certificate>) cred[0] : null;
        X509Certificate cCert = cred != null ? (X509Certificate) cred[1] : null;
        AsymmetricKeyParameter cKey = cred != null ? (AsymmetricKeyParameter) cred[2] : null;
        if (cred != null) {
            steps.add("已加载客户端证书（信任锚链 " + anchors.size() + " 级"
                    + (cKey != null ? "，含私钥作客户端凭据" : "") + "）");
        }
        EapTlsSession cs = new EapTlsSession(eapUser);
        Thread t = new Thread(() -> {
            try {
                TlsClientProtocol proto = new TlsClientProtocol(cs.inStream, cs.outStream);
                cs.clientTlsProto = proto;
                TrustedTlsClient client = new TrustedTlsClient(new BcTlsCrypto(new SecureRandom()),
                        anchors, cCert, cKey);
                proto.connect(client);
                cs.ok = true;
            } catch (Exception ex) {
                cs.err = ex.toString();
            } finally {
                cs.done = true;
                cs.notifyOutput();
            }
        }, "eap-ttls-client");
        t.setDaemon(true);
        t.start();
        int round = 6;
        byte[] clientOut = cs.pollOutput(6000);
        if (clientOut == null) {
            return clientResult(false, "TTLS 客户端握手无输出", steps);
        }
        for (int i = 0; i < 16; i++) {
            byte[][] frags = splitTlsFragments(clientOut);
            byte[] srvData = null;
            for (int fi = 0; fi < frags.length; fi++) {
                byte[] eapResp = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_TTLS, frags[fi]);
                List<Attr> a2 = new ArrayList<>();
                a2.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
                a2.add(new Attr(ATTR_EAP_MESSAGE, eapResp));
                byte[] req2 = buildRequestPacket(id, reqAuth, a2, secret, true);
                steps.add("[" + round++ + "] 发送 EAP-Response/TTLS/TLS（片 " + (fi + 1) + "/" + frags.length
                        + "，" + clientOut.length + "B 拆 " + frags.length + " 片）");
                byte[] resp2 = sendRecv(sock, req2, host, port, steps, "[" + round++ + "]");
                Packet p2 = parsePacket(resp2, resp2.length);
                if (p2.code == CODE_ACCESS_ACCEPT) {
                    return clientResult(true, "TTLS 认证通过（EAP-Success）", steps);
                }
                if (p2.code == CODE_ACCESS_REJECT) {
                    return clientResult(false, "TTLS 认证失败（Access-Reject）", steps);
                }
                byte[] eapSrv = getEapMessageConcat(p2);
                if (eapSrv == null || eapSrv.length < 6 || (eapSrv[0] & 0xff) != EAP_CODE_REQUEST
                        || (eapSrv[4] & 0xff) != EAP_TYPE_TTLS) {
                    return clientResult(false, "TTLS 服务器响应格式非法（" + respName(p2.code) + "）", steps);
                }
                srvData = Arrays.copyOfRange(eapSrv, 5, eapSrv.length);
                if (srvData.length > 1) {
                    break;
                }
            }
            byte[] full = null;
            for (int pf = 0; pf < 8; pf++) {
                if (srvData == null || srvData.length < 1) {
                    return clientResult(false, "TTLS 服务器数据为空", steps);
                }
                int sFlags = srvData[0] & 0xff;
                int sOff = 1;
                long sTotal = -1;
                if ((sFlags & EAP_TLS_FLAG_LENGTH) != 0) {
                    if (srvData.length < 5) {
                        return clientResult(false, "TTLS 服务器长度字段缺失", steps);
                    }
                    sTotal = ((long) (srvData[1] & 0xff) << 24) | ((srvData[2] & 0xff) << 16)
                            | ((srvData[3] & 0xff) << 8) | (srvData[4] & 0xff);
                    sOff = 5;
                }
                if (srvData.length == sOff && (sFlags & EAP_TLS_FLAG_START) != 0) {
                    full = null;
                } else {
                    full = cs.reassemble(Arrays.copyOfRange(srvData, sOff, srvData.length), sFlags, sTotal);
                }
                if (full != null) {
                    break;
                }
                steps.add("[" + round++ + "] 收到服务器 TTLS TLS 分片（M=1，继续拉取）");
                byte[] pull = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_TTLS, new byte[]{(byte) 0});
                List<Attr> a3 = new ArrayList<>();
                a3.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
                a3.add(new Attr(ATTR_EAP_MESSAGE, pull));
                byte[] req3 = buildRequestPacket(id, reqAuth, a3, secret, true);
                byte[] resp3 = sendRecv(sock, req3, host, port, steps, "[" + round++ + "]");
                Packet p3 = parsePacket(resp3, resp3.length);
                if (p3.code == CODE_ACCESS_ACCEPT) {
                    return clientResult(true, "TTLS 认证通过（EAP-Success）", steps);
                }
                if (p3.code == CODE_ACCESS_REJECT) {
                    return clientResult(false, "TTLS 认证失败（Access-Reject）", steps);
                }
                byte[] eapSrv2 = getEapMessageConcat(p3);
                if (eapSrv2 == null || eapSrv2.length < 6 || (eapSrv2[0] & 0xff) != EAP_CODE_REQUEST
                        || (eapSrv2[4] & 0xff) != EAP_TYPE_TTLS) {
                    return clientResult(false, "TTLS 服务器续片格式非法", steps);
                }
                srvData = Arrays.copyOfRange(eapSrv2, 5, eapSrv2.length);
            }
            if (full == null) {
                return clientResult(false, "TTLS 服务器分片重组未完成", steps);
            }
            cs.feed(full);
            clientOut = cs.pollOutput(6000);
            if (clientOut == null) {
                return clientResult(false, "TTLS 握手超时", steps);
            }
            if (cs.done && !cs.ok) {
                return clientResult(false, "TTLS 客户端握手失败: " + cs.err, steps);
            }
            if (cs.done && cs.ok) {
                steps.add("[" + round++ + "] 外层 TLS 隧道建立，进入内层 PAP（RFC 5281 §8.5）");
                // 读服务器 AVP 请求帧（User-Name 空值请求）
                byte[] avpReq = readTtlsAvpFrame(cs.clientTlsProto.getInputStream());
                if (avpReq.length < 2 || (avpReq[0] & 0xff) != 1) {
                    return clientResult(false, "TTLS 内层请求 AVP 非法", steps);
                }
                String realUser = username;
                if (realUser.startsWith("ttls:")) {
                    realUser = realUser.substring(5);
                } else if (realUser.startsWith("eap-ttls:")) {
                    realUser = realUser.substring(9);
                }
                byte[] uNameB = realUser.getBytes(StandardCharsets.UTF_8);
                byte[] passB = password.getBytes(StandardCharsets.UTF_8);
                if (uNameB.length > 253 || passB.length > 253) {
                    return clientResult(false, "TTLS 内层用户名/密码过长", steps);
                }
                byte[] respFrame = concat(
                        new byte[]{1, (byte) (uNameB.length + 2)}, uNameB,
                        new byte[]{2, (byte) (passB.length + 2)}, passB);
                cs.clientTlsProto.getOutputStream().write(respFrame);
                cs.clientTlsProto.getOutputStream().flush();
                steps.add("[" + round++ + "] 内层 User-Name + User-Password(明文) AVP 已写入隧道");
                // 回传 TLS 密文分片
                byte[] innerOut = cs.pollOutput(6000);
                if (innerOut == null) {
                    return clientResult(false, "TTLS 内层响应 TLS 输出超时", steps);
                }
                byte[][] innerFrags = splitTlsFragments(innerOut);
                for (int fi = 0; fi < innerFrags.length; fi++) {
                    byte[] eapResp = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_TTLS, innerFrags[fi]);
                    List<Attr> a4 = new ArrayList<>();
                    a4.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
                    a4.add(new Attr(ATTR_EAP_MESSAGE, eapResp));
                    byte[] req4 = buildRequestPacket(id, reqAuth, a4, secret, true);
                    steps.add("[" + round++ + "] 发送内层响应 TLS 分片（片 " + (fi + 1) + "/" + innerFrags.length + "）");
                    byte[] resp4 = sendRecv(sock, req4, host, port, steps, "[" + round++ + "]");
                    Packet p4 = parsePacket(resp4, resp4.length);
                    if (p4.code == CODE_ACCESS_ACCEPT) {
                        return clientResult(true, "TTLS 认证通过（EAP-Success）", steps);
                    }
                    if (p4.code == CODE_ACCESS_REJECT) {
                        return clientResult(false, "TTLS 认证失败（Access-Reject）", steps);
                    }
                }
                // 外层空响应让服务器收尾发 EAP-Success
                byte[] fin = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_TTLS, new byte[]{(byte) 0});
                List<Attr> a5 = new ArrayList<>();
                a5.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
                a5.add(new Attr(ATTR_EAP_MESSAGE, fin));
                byte[] req5 = buildRequestPacket(id, reqAuth, a5, secret, true);
                steps.add("[" + round++ + "] 内层认证完成，发送 EAP-Response/TTLS(空)");
                byte[] resp5 = sendRecv(sock, req5, host, port, steps, "[" + round++ + "]");
                Packet p5 = parsePacket(resp5, resp5.length);
                if (p5.code == CODE_ACCESS_ACCEPT) {
                    return clientResult(true, "TTLS 认证通过（EAP-Success）", steps);
                }
                return clientResult(false, "TTLS 认证失败（" + respName(p5.code) + "）", steps);
            }
        }
        return clientResult(false, "TTLS 握手轮次超限", steps);
    }

    /**
     * EAP-pwd（RFC 5931，P-256）：ID → Commit（标量/元素）→ Confirm → EAP-Success。
     * 客户端镜像：Identity(pwd:前缀) → ID/Response → Commit/Response → Confirm/Response。
     */
    private static Map<String, Object> eapPwdClientDial(DatagramSocket sock, InetAddress host, int port,
            int id, byte[] reqAuth, String username, String password, String secret, List<String> steps)
            throws Exception {
        String eapUser = username.startsWith("pwd:") ? username : "pwd:" + username;
        String realUser = eapUser.startsWith("pwd:") ? eapUser.substring(4) : eapUser.substring(8);
        byte[] eapIdPkt = eapPacket(EAP_CODE_RESPONSE, id, EAP_TYPE_IDENTITY,
                eapUser.getBytes(StandardCharsets.UTF_8));
        List<Attr> attrs = new ArrayList<>();
        attrs.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
        attrs.add(new Attr(ATTR_EAP_MESSAGE, eapIdPkt));
        byte[] req1 = buildRequestPacket(id, reqAuth, attrs, secret, true);
        steps.add("[1] 发送 Access-Request：EAP-Response/Identity(" + eapUser + ") + Message-Authenticator");
        byte[] resp1 = sendRecv(sock, req1, host, port, steps, "[2]");
        Packet p1 = parsePacket(resp1, resp1.length);
        if (p1.code != CODE_ACCESS_CHALLENGE) {
            return clientResult(false, "EAP 服务器未下发 EAP-pwd/ID（收到 " + respName(p1.code) + "）", steps);
        }
        byte[] eapIdReq = p1.getAttr(ATTR_EAP_MESSAGE);
        if (eapIdReq == null || eapIdReq.length < 6 || (eapIdReq[0] & 0xff) != EAP_CODE_REQUEST
                || (eapIdReq[4] & 0xff) != EAP_TYPE_PWD) {
            return clientResult(false, "EAP-pwd/ID 请求格式非法", steps);
        }
        int eapId = eapIdReq[1] & 0xff;
        steps.add("[3] 收到 EAP-Request/EAP-pwd/ID（Group=" + ((eapIdReq[5] & 0xff) * 256 + (eapIdReq[6] & 0xff)) + "）");
        // [4] ID/Response：Group 回显（2B）——S = Request组(2B) || Response组(2B)
        byte[] idResp = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_PWD, new byte[]{0, 6});
        List<Attr> a1 = new ArrayList<>();
        a1.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
        a1.add(new Attr(ATTR_EAP_MESSAGE, idResp));
        byte[] reqS = buildRequestPacket(id, reqAuth, a1, secret, true);
        steps.add("[4] 发送 EAP-Response/EAP-pwd/ID（Group=P-256）");
        byte[] respS = sendRecv(sock, reqS, host, port, steps, "[5]");
        Packet pS = parsePacket(respS, respS.length);
        if (pS.code != CODE_ACCESS_CHALLENGE) {
            return clientResult(false, "EAP 服务器未下发 Commit/Request（收到 " + respName(pS.code) + "）", steps);
        }
        byte[] eapCommitReq = pS.getAttr(ATTR_EAP_MESSAGE);
        if (eapCommitReq == null || eapCommitReq.length < 6 || (eapCommitReq[0] & 0xff) != EAP_CODE_REQUEST
                || (eapCommitReq[4] & 0xff) != EAP_TYPE_PWD) {
            return clientResult(false, "EAP-pwd Commit/Request 格式非法", steps);
        }
        byte[] commitData = Arrays.copyOfRange(eapCommitReq, 5, eapCommitReq.length);
        if (commitData.length < 2 + 32 + 33) {
            return clientResult(false, "EAP-pwd Commit/Request 数据长度非法", steps);
        }
        int l = ((commitData[0] & 0xff) << 8) | (commitData[1] & 0xff);
        if (l != 32 || commitData.length != 2 + l + 33) {
            return clientResult(false, "EAP-pwd Commit/Request 长度字段非法", steps);
        }
        BigInteger scalarS = eapPwdScalarFromBytes(Arrays.copyOfRange(commitData, 2, 2 + l));
        ECPoint elementS = eapPwdElementFromBytes(Arrays.copyOfRange(commitData, 2 + l, commitData.length));
        steps.add("[5] 收到 EAP-Request/EAP-pwd/Commit（标量=" + scalarS + "，元素=" + hexShort(
                Arrays.copyOfRange(commitData, 2 + l, commitData.length)) + "）");
        // 派生 PWE + 随机标量 + 元素（PWE - scalar·G）
        ECPoint pwe = eapPwdDerivePwe(password, "MODPKICA-RADIUS", realUser);
        BigInteger n = pwdCurve().getN();
        BigInteger scalarP = new BigInteger(256, new SecureRandom()).mod(n.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        ECPoint elementP = pwe.add(pwdCurve().getG().multiply(scalarP).negate());
        // 共享密钥 + Confirm 值
        byte[] kx = eapPwdKx(scalarS, elementS, scalarP, elementP);
        byte[] sData = new byte[]{0, 6, 0, 6};
        byte[] scalarSB = eapPwdScalarBytes(scalarS);
        byte[] elemSB = eapPwdElementBytes(elementS);
        byte[] scalarPB = eapPwdScalarBytes(scalarP);
        byte[] elemPB = eapPwdElementBytes(elementP);
        byte[] confirmC = eapPwdConfirm(kx, sData, scalarSB, elemSB, scalarPB, elemPB, "client");
        byte[] confirmS = eapPwdConfirm(kx, sData, scalarSB, elemSB, scalarPB, elemPB, "server");
        steps.add("[6] PWE 派生完成，发送 EAP-Response/EAP-pwd/Commit（标量=" + scalarP + "）");
        byte[] commitResp = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_PWD,
                concat(new byte[]{0, 32}, scalarPB, elemPB));
        List<Attr> a2 = new ArrayList<>();
        a2.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
        a2.add(new Attr(ATTR_EAP_MESSAGE, commitResp));
        byte[] req2 = buildRequestPacket(id, reqAuth, a2, secret, true);
        byte[] resp2 = sendRecv(sock, req2, host, port, steps, "[7]");
        Packet p2 = parsePacket(resp2, resp2.length);
        if (p2.code != CODE_ACCESS_CHALLENGE) {
            return clientResult(false, "EAP 服务器未下发 Confirm/Request（收到 " + respName(p2.code) + "）", steps);
        }
        byte[] eapConfirmReq = p2.getAttr(ATTR_EAP_MESSAGE);
        if (eapConfirmReq == null || eapConfirmReq.length < 6 || (eapConfirmReq[0] & 0xff) != EAP_CODE_REQUEST
                || (eapConfirmReq[4] & 0xff) != EAP_TYPE_PWD) {
            return clientResult(false, "EAP-pwd Confirm/Request 格式非法", steps);
        }
        byte[] confirmData = Arrays.copyOfRange(eapConfirmReq, 5, eapConfirmReq.length);
        steps.add("[8] 收到 EAP-Request/EAP-pwd/Confirm（" + hexShort(confirmData) + "）");
        if (confirmData.length != 32 || !MessageDigest.isEqual(confirmData, confirmS)) {
            return clientResult(false, "EAP-pwd 服务器 Confirm 校验失败（数据=" + hexShort(confirmData)
                    + " 期望=" + hexShort(confirmS) + "）", steps);
        }
        steps.add("[9] 服务器 Confirm 校验通过，发送 EAP-Response/EAP-pwd/Confirm（" + hexShort(confirmC) + "）");
        byte[] confirmResp = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_PWD, confirmC);
        List<Attr> a3 = new ArrayList<>();
        a3.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
        a3.add(new Attr(ATTR_EAP_MESSAGE, confirmResp));
        byte[] req3 = buildRequestPacket(id, reqAuth, a3, secret, true);
        byte[] resp3 = sendRecv(sock, req3, host, port, steps, "[10]");
        Packet p3 = parsePacket(resp3, resp3.length);
        steps.add("[11] 收到 " + respName(p3.code) + "（ID=" + p3.identifier + "，"
                + (verifyRespAuth(resp3, reqAuth, secret) ? "响应 Authenticator 校验通过" : "响应 Authenticator 校验失败") + "）");
        boolean ok = p3.code == CODE_ACCESS_ACCEPT;
        return clientResult(ok, ok ? "EAP-pwd 认证通过" : "EAP-pwd 认证失败", steps);
    }

    /** EAP-MD5：EAP-Identity → EAP-MD5 挑战 → 响应（RFC 3748 / 2284，两阶段）。 */    private static Map<String, Object> eapMd5ClientDial(DatagramSocket sock, InetAddress host, int port,
            int id, byte[] reqAuth, String username, String password, String secret, List<String> steps)
            throws Exception {
        // 阶段 1：EAP-Identity（Access-Request + EAP-Message + Message-Authenticator）
        String eapUser = username.startsWith("md5:") ? username : "md5:" + username;
        byte[] eapIdPkt = eapPacket(EAP_CODE_RESPONSE, id, EAP_TYPE_IDENTITY,
                eapUser.getBytes(StandardCharsets.UTF_8));
        List<Attr> attrs = new ArrayList<>();
        attrs.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
        attrs.add(new Attr(ATTR_EAP_MESSAGE, eapIdPkt));
        byte[] req1 = buildRequestPacket(id, reqAuth, attrs, secret, true);
        steps.add("[1] 发送 Access-Request：User-Name(" + eapUser + ") + EAP-Response/Identity"
                + " + Message-Authenticator(HMAC-MD5)");
        byte[] resp1 = sendRecv(sock, req1, host, port, steps, "[2]");
        Packet p1 = parsePacket(resp1, resp1.length);
        if (p1.code != CODE_ACCESS_CHALLENGE) {
            return clientResult(false, "EAP 服务器未下发挑战（收到 " + respName(p1.code) + "）", steps);
        }
        byte[] eap1 = p1.getAttr(ATTR_EAP_MESSAGE);
        if (eap1 == null || eap1.length < 6 || (eap1[0] & 0xff) != EAP_CODE_REQUEST
                || (eap1[4] & 0xff) != EAP_TYPE_MD5) {
            return clientResult(false, "EAP-MD5 挑战格式非法（RADIUS=" + respName(p1.code)
                    + "，EAP字节=" + (eap1 == null ? "null" : "len=" + eap1.length + " hex=" + hexFull(eap1)) + "）", steps);
        }
        int eapId = eap1[1] & 0xff;
        byte[] challenge = Arrays.copyOfRange(eap1, 6, Math.min(eap1.length, 22));
        steps.add("[3] 收到 Access-Challenge + EAP-Request/MD5（ID=" + eapId + "，挑战 "
                + hexShort(challenge) + "）");
        // 阶段 2：EAP-MD5 响应 = 0x10 + MD5(eapId || 密码 || 挑战)
        byte[] md5resp = md5(new byte[]{(byte) eapId}, password.getBytes(StandardCharsets.UTF_8), challenge);
        byte[] eapData = new byte[17];
        eapData[0] = 16;
        System.arraycopy(md5resp, 0, eapData, 1, 16);
        byte[] eapResp = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_MD5, eapData);
        List<Attr> attrs2 = new ArrayList<>();
        attrs2.add(new Attr(ATTR_USER_NAME, username.getBytes(StandardCharsets.UTF_8)));
        attrs2.add(new Attr(ATTR_EAP_MESSAGE, eapResp));
        byte[] req2 = buildRequestPacket(id, reqAuth, attrs2, secret, true);
        steps.add("[4] 发送 Access-Request：EAP-Response/MD5（" + hexShort(md5resp) + "）");
        byte[] resp2 = sendRecv(sock, req2, host, port, steps, "[5]");
        Packet p2 = parsePacket(resp2, resp2.length);
        steps.add("[6] 收到 " + respName(p2.code) + "（ID=" + p2.identifier + "，"
                + (verifyRespAuth(resp2, reqAuth, secret) ? "响应 Authenticator 校验通过" : "响应 Authenticator 校验失败") + "）");
        boolean ok = p2.code == CODE_ACCESS_ACCEPT;
        return clientResult(ok, ok ? "EAP-MD5 认证通过" : "EAP-MD5 认证失败", steps);
    }

    /** EAP-GTC（RFC 3748 §5.6）：EAP-Identity(gtc:前缀) → 提示文本 → 明文令牌/口令 → EAP-Success。 */
    private static Map<String, Object> eapGtcClientDial(DatagramSocket sock, InetAddress host, int port,
            int id, byte[] reqAuth, String username, String password, String secret, List<String> steps)
            throws Exception {
        String eapUser = username.startsWith("gtc:") ? username : "gtc:" + username;
        byte[] eapIdPkt = eapPacket(EAP_CODE_RESPONSE, id, EAP_TYPE_IDENTITY,
                eapUser.getBytes(StandardCharsets.UTF_8));
        List<Attr> attrs = new ArrayList<>();
        attrs.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
        attrs.add(new Attr(ATTR_EAP_MESSAGE, eapIdPkt));
        byte[] req1 = buildRequestPacket(id, reqAuth, attrs, secret, true);
        steps.add("[1] 发送 Access-Request：User-Name(" + eapUser + ") + EAP-Response/Identity"
                + " + Message-Authenticator");
        byte[] resp1 = sendRecv(sock, req1, host, port, steps, "[2]");
        Packet p1 = parsePacket(resp1, resp1.length);
        if (p1.code != CODE_ACCESS_CHALLENGE) {
            return clientResult(false, "EAP 服务器未下发 GTC 提示（收到 " + respName(p1.code) + "）", steps);
        }
        byte[] eap1 = p1.getAttr(ATTR_EAP_MESSAGE);
        if (eap1 == null || eap1.length < 6 || (eap1[0] & 0xff) != EAP_CODE_REQUEST
                || (eap1[4] & 0xff) != EAP_TYPE_GTC) {
            return clientResult(false, "EAP-GTC 提示格式非法（EAP字节=" + (eap1 == null ? "null" : hexFull(eap1)) + "）", steps);
        }
        int eapId = eap1[1] & 0xff;
        String prompt = new String(Arrays.copyOfRange(eap1, 5, eap1.length), StandardCharsets.UTF_8).trim();
        steps.add("[3] 收到 Access-Challenge + EAP-Request/GTC（ID=" + eapId + "，提示=\"" + prompt + "\"）");
        byte[] eapResp = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_GTC,
                password.getBytes(StandardCharsets.UTF_8));
        List<Attr> attrs2 = new ArrayList<>();
        attrs2.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
        attrs2.add(new Attr(ATTR_EAP_MESSAGE, eapResp));
        byte[] req2 = buildRequestPacket(id, reqAuth, attrs2, secret, true);
        steps.add("[4] 发送 Access-Request：EAP-Response/GTC（明文令牌，RFC 3748 §5.6）");
        byte[] resp2 = sendRecv(sock, req2, host, port, steps, "[5]");
        Packet p2 = parsePacket(resp2, resp2.length);
        steps.add("[6] 收到 " + respName(p2.code) + "（ID=" + p2.identifier + "，"
                + (verifyRespAuth(resp2, reqAuth, secret) ? "响应 Authenticator 校验通过" : "响应 Authenticator 校验失败") + "）");
        boolean ok = p2.code == CODE_ACCESS_ACCEPT;
        return clientResult(ok, ok ? "EAP-GTC 认证通过" : "EAP-GTC 认证失败", steps);
    }

    /** EAP-MSCHAPV2（RFC 2759 / EAP-MSCHAPv2，EAP 类型 26）：Identity(mschapv2:前缀) → MS-CHAPv2 挑战 → NT-Response → EAP-Success。 */
    private static Map<String, Object> eapMsChapV2ClientDial(DatagramSocket sock, InetAddress host, int port,
            int id, byte[] reqAuth, String username, String password, String secret, List<String> steps)
            throws Exception {
        String eapUser = username.startsWith("mschapv2:") ? username : "mschapv2:" + username;
        byte[] eapIdPkt = eapPacket(EAP_CODE_RESPONSE, id, EAP_TYPE_IDENTITY,
                eapUser.getBytes(StandardCharsets.UTF_8));
        List<Attr> attrs = new ArrayList<>();
        attrs.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
        attrs.add(new Attr(ATTR_EAP_MESSAGE, eapIdPkt));
        byte[] req1 = buildRequestPacket(id, reqAuth, attrs, secret, true);
        steps.add("[1] 发送 Access-Request：User-Name(" + eapUser + ") + EAP-Response/Identity"
                + " + Message-Authenticator");
        byte[] resp1 = sendRecv(sock, req1, host, port, steps, "[2]");
        Packet p1 = parsePacket(resp1, resp1.length);
        if (p1.code != CODE_ACCESS_CHALLENGE) {
            return clientResult(false, "EAP 服务器未下发 MS-CHAPv2 挑战（收到 " + respName(p1.code) + "）", steps);
        }
        byte[] eap1 = p1.getAttr(ATTR_EAP_MESSAGE);
        if (eap1 == null || eap1.length < 10 || (eap1[0] & 0xff) != EAP_CODE_REQUEST
                || (eap1[4] & 0xff) != EAP_TYPE_MSCHAPV2) {
            return clientResult(false, "EAP-MSCHAPv2 挑战格式非法（RADIUS=" + respName(p1.code)
                    + "，EAP字节=" + (eap1 == null ? "null" : "len=" + eap1.length + " hex=" + hexFull(eap1)) + "）", steps);
        }
        int eapId = eap1[1] & 0xff;
        int mschapId = eap1[6] & 0xff;
        int vsize = eap1[9] & 0xff;
        if (vsize != 16 || eap1.length < 10 + vsize) {
            return clientResult(false, "EAP-MSCHAPv2 挑战长度非法（Value-Size=" + vsize + "）", steps);
        }
        byte[] authChallenge = Arrays.copyOfRange(eap1, 10, 10 + vsize);
        steps.add("[3] 收到 Access-Challenge + EAP-Request/MSCHAPV2（ID=" + eapId + "，MS-CHAPv2-ID=" + mschapId
                + "，挑战 " + hexShort(authChallenge) + "）");
        byte[] peerChallenge = new byte[16];
        new java.security.SecureRandom().nextBytes(peerChallenge);
        String realUser = eapUser.startsWith("mschapv2:") ? eapUser.substring(9) : username;
        byte[] ntResp = computeNtResponse(password, realUser, peerChallenge, authChallenge);
        // 标准 EAP-MSCHAPv2 Response（RFC 2759 §3.4）：
        //   OpCode(1)=2, MS-CHAPv2-ID(1), MS-Length(2), Value-Size(1)=49,
        //   Value(49B) = Peer-Challenge(16) + Reserved(8) + NT-Response(24) + Flags(1), Name
        // 注意：EAP 内层不带 PPP 的 Ident/Pad 头（与 RFC 2548 MS-CHAP-Response 布局一致）
        byte[] value = new byte[49];
        System.arraycopy(peerChallenge, 0, value, 0, 16);   // Peer-Challenge
        System.arraycopy(ntResp, 0, value, 24, 24);          // NT-Response
        // value[16..24) Reserved = 0x00，value[48] Flags = 0x00（数组默认 0）
        byte[] respNameB = realUser.getBytes(StandardCharsets.UTF_8);
        int msLen = 1 + 1 + 2 + 1 + 49 + respNameB.length;  // OpCode+ID+MS-Length+Value-Size+Value+Name
        byte[] respData = concat(new byte[]{2, (byte) mschapId,
                (byte) (msLen >> 8), (byte) msLen, 49}, value, respNameB);
        byte[] eapResp = eapPacket(EAP_CODE_RESPONSE, eapId, EAP_TYPE_MSCHAPV2, respData);
        List<Attr> attrs2 = new ArrayList<>();
        attrs2.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
        attrs2.add(new Attr(ATTR_EAP_MESSAGE, eapResp));
        byte[] req2 = buildRequestPacket(id, reqAuth, attrs2, secret, true);
        steps.add("[4] 发送 Access-Request：EAP-Response/MSCHAPV2（NT-Response " + hexShort(ntResp) + "）");
        byte[] resp2 = sendRecv(sock, req2, host, port, steps, "[5]");
        Packet p2 = parsePacket(resp2, resp2.length);
        boolean ok;
        if (p2.code == CODE_ACCESS_CHALLENGE) {
            // 两阶段流程（FreeRADIUS 标准）：服务器验证凭据后先回 Access-Challenge，
            // 携带方法层 MS-CHAPv2 Success（RFC 2759 §4.7，EAP-Request/Type=26/OpCode=3）。
            byte[] eap2 = p2.getAttr(ATTR_EAP_MESSAGE);
            if (eap2 == null || eap2.length < 7 || (eap2[0] & 0xff) != EAP_CODE_REQUEST
                    || (eap2[4] & 0xff) != EAP_TYPE_MSCHAPV2 || (eap2[5] & 0xff) != 3) {
                return clientResult(false, "EAP-MSCHAPv2 方法层 Success 格式非法（RADIUS=" + respName(p2.code)
                        + "，EAP字节=" + (eap2 == null ? "null" : "len=" + eap2.length + " hex=" + hexFull(eap2)) + "）", steps);
            }
            int ackId = eap2[1] & 0xff;
            // 验证方法层 Success 的 42B Authenticator（RFC 2759 §8.7 + §8.8，与 Windows 原生
            // 客户端行为一致）：EAP 封装下为文本格式 "S=" + 40 个大写十六进制字符
            // （FreeRADIUS rlm_mschap mschap_auth_response 输出格式）。
            byte[] ntHashC = ntPasswordHash(password);
            byte[] ntHashHashC = md4(ntHashC);
            byte[] challengeHashC = Arrays.copyOf(sha1(peerChallenge, authChallenge,
                    realUser.getBytes(StandardCharsets.US_ASCII)), 8);
            byte[] digest1C = sha1(ntHashHashC, ntResp,
                    "Magic server to client signing constant".getBytes(StandardCharsets.US_ASCII));
            byte[] expectAuth = sha1(digest1C, challengeHashC,
                    "Pad to make it do more than one iteration".getBytes(StandardCharsets.US_ASCII));
            boolean authOk = false;
            if (eap2.length >= 51 && eap2[9] == 'S' && eap2[10] == '=') {
                String got = new String(eap2, 11, 40, StandardCharsets.US_ASCII);
                authOk = got.equalsIgnoreCase(hexFull(expectAuth));
            }
            steps.add("[6] 收到 Access-Challenge + 方法层 MS-CHAPv2 Success（OpCode=3，MS-Length="
                    + (((eap2[7] & 0xff) << 8) | (eap2[8] & 0xff))
                    + "，" + (authOk ? "Authenticator 验证通过" : "Authenticator 验证失败！") + "）");
            if (!authOk) {
                return clientResult(false, "EAP-MSCHAPv2 方法层 Success 验证器不匹配（服务器计算错误）", steps);
            }
            // 客户端回空 EAP-Response（Len=4）确认方法层 Success
            byte[] ack = new byte[]{(byte) EAP_CODE_RESPONSE, (byte) ackId, 0, 4};
            List<Attr> attrs3 = new ArrayList<>();
            attrs3.add(new Attr(ATTR_USER_NAME, eapUser.getBytes(StandardCharsets.UTF_8)));
            attrs3.add(new Attr(ATTR_EAP_MESSAGE, ack));
            byte[] req3 = buildRequestPacket(id, reqAuth, attrs3, secret, true);
            steps.add("[7] 发送 Access-Request：空 EAP-Response 确认 Success");
            byte[] resp3 = sendRecv(sock, req3, host, port, steps, "[8]");
            Packet p3 = parsePacket(resp3, resp3.length);
            steps.add("[9] 收到 " + respName(p3.code) + "（ID=" + p3.identifier + "，"
                    + (verifyRespAuth(resp3, reqAuth, secret) ? "响应 Authenticator 校验通过" : "响应 Authenticator 校验失败") + "）");
            ok = p3.code == CODE_ACCESS_ACCEPT;
        } else {
            steps.add("[6] 收到 " + respName(p2.code) + "（ID=" + p2.identifier + "，"
                    + (verifyRespAuth(resp2, reqAuth, secret) ? "响应 Authenticator 校验通过" : "响应 Authenticator 校验失败") + "）");
            ok = p2.code == CODE_ACCESS_ACCEPT;
        }
        return clientResult(ok, ok ? "EAP-MSCHAPv2 认证通过（EAP-Success）" : "EAP-MSCHAPv2 认证失败", steps);
    }

    // ---------- 客户端包/属性工具 ----------

    /** 构造 Access-Request 包（Authenticator 保持随机值；withMa=true 时附 Message-Authenticator）。 */
    static byte[] buildRequestPacket(int id, byte[] reqAuth, List<Attr> attrs, String secret, boolean withMa) {
        List<Attr> list = new ArrayList<>(attrs);
        int maOffset = -1;
        if (withMa) {
            list.add(new Attr(ATTR_MESSAGE_AUTHENTICATOR, new byte[16]));
        }
        int len = 20;
        for (Attr a : list) {
            len += a.value.length + 2;
        }
        byte[] out = new byte[len];
        out[0] = (byte) CODE_ACCESS_REQUEST;
        out[1] = (byte) id;
        out[2] = (byte) (len >> 8);
        out[3] = (byte) len;
        System.arraycopy(reqAuth, 0, out, 4, 16);
        int off = 20;
        for (Attr a : list) {
            out[off] = (byte) a.type;
            out[off + 1] = (byte) (a.value.length + 2);
            System.arraycopy(a.value, 0, out, off + 2, a.value.length);
            if (withMa && a.type == ATTR_MESSAGE_AUTHENTICATOR) {
                maOffset = off;
            }
            off += a.value.length + 2;
        }
        if (withMa && maOffset >= 0) {
            byte[] mac = hmacMd5(secret.getBytes(StandardCharsets.UTF_8), out);
            System.arraycopy(mac, 0, out, maOffset + 2, 16);
        }
        return out;
    }

    /** User-Password 加密（RFC 2865 §5.2）：每 16B 块 XOR MD5(secret + 前一块密文)。 */
    static byte[] encodeUserPassword(String password, byte[] requestAuth, String secret) {
        byte[] pw = password.getBytes(StandardCharsets.UTF_8);
        int blocks = (pw.length + 15) / 16;
        byte[] padded = new byte[blocks * 16];
        System.arraycopy(pw, 0, padded, 0, pw.length);
        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[blocks * 16];
        byte[] prev = requestAuth;
        for (int i = 0; i < blocks; i++) {
            byte[] hash = md5(concat(secretBytes, prev));
            for (int j = 0; j < 16; j++) {
                out[i * 16 + j] = (byte) (padded[i * 16 + j] ^ hash[j]);
            }
            prev = Arrays.copyOfRange(out, i * 16, i * 16 + 16);
        }
        return out;
    }

    /** 构造 Vendor-Specific(Microsoft) 属性：Vendor-ID(4) + Vendor-Type(1) + Vendor-Length(1) + Data。 */
    static byte[] msChapVsa(int vendorType, byte[] data) {
        byte[] out = new byte[6 + data.length];
        out[0] = (byte) (VENDOR_MICROSOFT >> 24);
        out[1] = (byte) (VENDOR_MICROSOFT >> 16);
        out[2] = (byte) (VENDOR_MICROSOFT >> 8);
        out[3] = (byte) VENDOR_MICROSOFT;
        out[4] = (byte) vendorType;
        out[5] = (byte) (data.length + 2);
        System.arraycopy(data, 0, out, 6, data.length);
        return out;
    }

    /** 构造 EAP 包（Code + ID + Length + Type + Data）。 */
    static byte[] eapPacket(int code, int id, int type, byte[] data) {
        int len = 5 + (data == null ? 0 : data.length);
        byte[] out = new byte[len];
        out[0] = (byte) code;
        out[1] = (byte) id;
        out[2] = (byte) (len >> 8);
        out[3] = (byte) len;
        out[4] = (byte) type;
        if (data != null) {
            System.arraycopy(data, 0, out, 5, data.length);
        }
        return out;
    }

    /** 发送 Access-Request 并等待响应。 */
    private static byte[] sendRecv(DatagramSocket sock, byte[] req, InetAddress host, int port,
            List<String> steps, String tag) throws Exception {
        sock.send(new DatagramPacket(req, req.length, host, port));
        steps.add(tag + " 已发送 Access-Request（" + req.length + " 字节）→ 127.0.0.1:" + port);
        byte[] buf = new byte[4096];
        DatagramPacket rp = new DatagramPacket(buf, buf.length);
        sock.receive(rp);
        return Arrays.copyOf(rp.getData(), rp.getLength());
    }

    /** 校验响应 Authenticator = MD5(Code+Id+Length+请求Authenticator+属性+Secret)（RFC 2865 §3）。 */
    static boolean verifyRespAuth(byte[] resp, byte[] reqAuth, String secret) {
        try {
            if (resp.length < 20) {
                return false;
            }
            byte[] expected = Arrays.copyOfRange(resp, 4, 20);
            byte[] copy = resp.clone();
            System.arraycopy(reqAuth, 0, copy, 4, 16);
            byte[] calc = md5(copy, secret);
            return constantTimeEquals(expected, calc);
        } catch (Exception e) {
            return false;
        }
    }

    private static String respName(int code) {
        switch (code) {
            case 1:
                return "Access-Request";
            case 2:
                return "Access-Accept";
            case 3:
                return "Access-Reject";
            case 11:
                return "Access-Challenge";
            case 5:
                return "Accounting-Response";
            default:
                return "Code=" + code;
        }
    }

    private static String hexShort(byte[] b) {
        StringBuilder sb = new StringBuilder();
        int n = Math.min(b.length, 16);
        for (int i = 0; i < n; i++) {
            sb.append(String.format("%02x", b[i] & 0xff));
        }
        if (b.length > 16) {
            sb.append("…");
        }
        return sb.toString();
    }

    private static String hexFull(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x & 0xff));
        }
        return sb.toString();
    }
}
