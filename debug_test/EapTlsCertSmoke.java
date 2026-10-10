import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.*;
import org.bouncycastle.tls.crypto.impl.bc.*;
import org.bouncycastle.crypto.params.*;
import modpkica.PemIO;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * EAP-TLS 证书登录全链路冒烟测试（模拟 Windows 原生 IKEv2「证书」登录）：
 *   ① Access-Request：User-Name=localhost + EAP-Identity(localhost)（无前缀，与 Windows 一致）
 *   ② 服务器应下发 EAP-Request/MSCHAPV2
 *   ③ 客户端以 EAP-NAK 声明仅支持 EAP-TLS(Type 13)
 *   ④ 服务器应切换到 EAP-TLS：下发 EAP-Request/TLS Start
 *   ⑤ 客户端出示证书 a66de5fea3df44c8f8687f31d75384d（信任锚 ROOT 7712d935...）完成 TLS 握手
 *   ⑥ 期望最终 Access-Accept + EAP-Success
 *
 * 运行：java -cp "out;BC185\*;debug_test" EapTlsCertSmoke
 */
public class EapTlsCertSmoke {

    static final int ATTR_USER_NAME = 1;
    static final int ATTR_EAP_MESSAGE = 79;
    static final int ATTR_MESSAGE_AUTHENTICATOR = 80;
    static final int CODE_ACCESS_REQUEST = 1;
    static final int CODE_ACCESS_ACCEPT = 2;
    static final int CODE_ACCESS_REJECT = 3;
    static final int CODE_ACCESS_CHALLENGE = 11;

    static final int EAP_CODE_REQUEST = 1;
    static final int EAP_CODE_RESPONSE = 2;
    static final int EAP_CODE_SUCCESS = 3;
    static final int EAP_CODE_FAILURE = 4;
    static final int EAP_TYPE_IDENTITY = 1;
    static final int EAP_TYPE_NAK = 3;
    static final int EAP_TYPE_MD5 = 4;
    static final int EAP_TYPE_TLS = 13;
    static final int EAP_TYPE_MSCHAPV2 = 26;

    // RFC 5216 §2.1：Bit7(0x80)=L 长度字段；Bit6(0x40)=M 后续分片；Bit5(0x20)=S Start
    static final int EAP_TLS_FLAG_LENGTH = 0x80;
    static final int EAP_TLS_FLAG_MORE = 0x40;
    static final int EAP_TLS_FLAG_START = 0x20;
    static final int EAP_TLS_FRAG = 240;

    static final String BASE = "C:\\Users\\28299\\Desktop\\modpkica4JAVA";
    static final String CLIENT_SERIAL = "a66de5fea3df44c8f8687f31d75384d";
    static final String ROOT_SERIAL = "7712d9352e6038ce78e57e3f572cec74";

    static final class Attr {
        int type;
        byte[] value;
        Attr(int t, byte[] v) { type = t; value = v; }
    }

    static byte[] md5(byte[] d) throws Exception {
        return MessageDigest.getInstance("MD5").digest(d);
    }

    static byte[] hmacMd5(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(new SecretKeySpec(key, "HmacMD5"));
        return mac.doFinal(data);
    }

    static byte[] concat(byte[]... a) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        for (byte[] x : a) b.write(x);
        return b.toByteArray();
    }

    static byte[] buildRequestPacket(int id, byte[] reqAuth, List<Attr> attrs, String secret, boolean withMa) throws Exception {
        List<Attr> list = new ArrayList<>(attrs);
        int maOffset = -1;
        if (withMa) {
            list.add(new Attr(ATTR_MESSAGE_AUTHENTICATOR, new byte[16]));
        }
        int len = 20;
        for (Attr a : list) len += a.value.length + 2;
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
            if (withMa && a.type == ATTR_MESSAGE_AUTHENTICATOR) maOffset = off;
            off += a.value.length + 2;
        }
        if (withMa && maOffset >= 0) {
            byte[] mac = hmacMd5(secret.getBytes("UTF-8"), out);
            System.arraycopy(mac, 0, out, maOffset + 2, 16);
        }
        return out;
    }

    static byte[] eapPacket(int code, int id, int type, byte[] data) throws Exception {
        int len = 5 + (data == null ? 0 : data.length);
        byte[] out = new byte[len];
        out[0] = (byte) code;
        out[1] = (byte) id;
        out[2] = (byte) (len >> 8);
        out[3] = (byte) len;
        out[4] = (byte) type;
        if (data != null) System.arraycopy(data, 0, out, 5, data.length);
        return out;
    }

    /** 解析 RADIUS 响应：返回 {code, id, auth, List<Attr>}。 */
    static Object[] parseResp(byte[] buf) throws Exception {
        int code = buf[0] & 0xff;
        int id = buf[1] & 0xff;
        byte[] auth = Arrays.copyOfRange(buf, 4, 20);
        List<Attr> attrs = new ArrayList<>();
        int off = 20;
        while (off + 2 <= buf.length) {
            int t = buf[off] & 0xff;
            int l = buf[off + 1] & 0xff;
            if (l < 2 || off + l > buf.length) break;
            attrs.add(new Attr(t, Arrays.copyOfRange(buf, off + 2, off + l)));
            off += l;
        }
        return new Object[]{code, id, auth, attrs};
    }

    static boolean verifyRespAuth(byte[] resp, byte[] reqAuth, String secret) throws Exception {
        byte[] expected = md5(concat(secret.getBytes("UTF-8"), resp, reqAuth));
        return Arrays.equals(expected, Arrays.copyOfRange(resp, 4, 20));
    }

    static byte[] sendRecv(DatagramSocket sock, byte[] req, InetAddress host, int port, int timeoutMs) throws Exception {
        sock.send(new DatagramPacket(req, req.length, host, port));
        sock.setSoTimeout(timeoutMs);
        byte[] buf = new byte[65535];
        DatagramPacket p = new DatagramPacket(buf, buf.length);
        sock.receive(p);
        return Arrays.copyOf(p.getData(), p.getLength());
    }

    // ---------- EAP-TLS 客户端传输层（与服务器 EapTlsSession 同构） ----------

    static final class BlockingInput extends InputStream {
        private final LinkedBlockingQueue<byte[]> q;
        private byte[] cur;
        private int curOff;
        private boolean eof;
        BlockingInput(LinkedBlockingQueue<byte[]> q) { this.q = q; }
        public int read() throws IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : (one[0] & 0xff);
        }
        public int read(byte[] b, int off, int len) throws IOException {
            if (len <= 0) return 0;
            while (cur == null || curOff >= cur.length) {
                if (eof) return -1;
                byte[] d;
                try {
                    d = q.poll(10, java.util.concurrent.TimeUnit.SECONDS);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new IOException("输入流中断");
                }
                if (d == null) throw new IOException("EAP-TLS 数据超时");
                if (d.length == 0) { eof = true; cur = null; return -1; }
                cur = d;
                curOff = 0;
            }
            int n = Math.min(len, cur.length - curOff);
            System.arraycopy(cur, curOff, b, off, n);
            curOff += n;
            return n;
        }
    }

    static final class CliTlsSession {
        final LinkedBlockingQueue<byte[]> inQ = new LinkedBlockingQueue<>();
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final BlockingInput inStream = new BlockingInput(inQ);
        Thread thread;
        volatile boolean done;
        volatile String err;
        volatile String errStack;
        volatile byte[] outBuf;
        volatile int outSent;
        volatile byte[] clientMsk;
    }

    /** EAP-TLS 客户端：验证服务器链到 ROOT + 出示客户端证书/私钥。 */
    static final class Cli extends AbstractTlsClient {
        final List<X509Certificate> anchors;
        final X509Certificate clientCert;
        final AsymmetricKeyParameter clientKey;
        Cli(TlsCrypto crypto, List<X509Certificate> anchors,
            X509Certificate clientCert, AsymmetricKeyParameter clientKey) {
            super(crypto);
            this.anchors = anchors;
            this.clientCert = clientCert;
            this.clientKey = clientKey;
        }
        protected ProtocolVersion[] getSupportedVersions() {
            return new ProtocolVersion[]{ProtocolVersion.TLSv12};
        }
        // 模拟 strongSwan 手机：不发 RFC 7627 EMS(0x0017) 扩展，验证服务端不强求 EMS
        @Override
        public boolean shouldUseExtendedMasterSecret() {
            return false;
        }
        protected int[] getSupportedCipherSuites() {
            return new int[]{
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256 };
        }
        public TlsAuthentication getAuthentication() throws IOException {
            return new TlsAuthentication() {
                public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException {
                    org.bouncycastle.tls.crypto.TlsCertificate[] chain =
                            serverCertificate.getCertificate().getCertificateList();
                    if (chain == null || chain.length == 0) throw new IOException("服务器未提供证书");
                    try {
                        java.security.cert.CertificateFactory cf =
                                java.security.cert.CertificateFactory.getInstance("X.509");
                        X509Certificate leaf = (X509Certificate) cf.generateCertificate(
                                new ByteArrayInputStream(chain[0].getEncoded()));
                        // 服务器证书必须锚定到 ROOT 信任
                        boolean ok = false;
                        for (X509Certificate a : anchors) {
                            if (leaf.equals(a)) { ok = true; break; }
                            if (leaf.getIssuerX500Principal().equals(a.getSubjectX500Principal())) {
                                try { leaf.verify(a.getPublicKey()); ok = true; } catch (Exception ignore) {}
                            }
                        }
                        if (!ok) throw new IOException("服务器证书未锚定到 ROOT 信任");
                    } catch (IOException e) {
                        throw e;
                    } catch (Exception e) {
                        throw new IOException("服务器证书验证失败: " + e, e);
                    }
                }
                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException {
                    if (clientCert == null || clientKey == null) return null;
                    SignatureAndHashAlgorithm sig = clientKey instanceof RSAKeyParameters
                            ? new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa)
                            : new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa);
                    TlsCryptoParameters cp = new TlsCryptoParameters(context);
                    TlsSigner signer = new TlsSigner() {
                        public byte[] generateRawSignature(SignatureAndHashAlgorithm alg, byte[] hash) throws IOException {
                            return generateRawSignature(alg, null, null, hash);
                        }
                        public byte[] generateRawSignature(SignatureAndHashAlgorithm alg, byte[] clientRandom,
                                                          byte[] serverRandom, byte[] hash) throws IOException {
                            try {
                                if (clientKey instanceof RSAKeyParameters) {
                                    return rsaSign((RSAKeyParameters) clientKey, hash);
                                }
                                return ecdsaSign((ECPrivateKeyParameters) clientKey, hash);
                            } catch (Exception e) {
                                throw new IOException(e);
                            }
                        }
                        public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm alg) throws IOException { return null; }
                    };
                    try {
                        TlsCertificate tc = context.getCrypto().createCertificate(clientCert.getEncoded());
                        return new DefaultTlsCredentialedSigner(cp, signer,
                                new Certificate(new org.bouncycastle.tls.crypto.TlsCertificate[]{tc}), sig);
                    } catch (Exception e) {
                        throw new IOException(e);
                    }
                }
            };
        }
    }

    static byte[] rsaSign(RSAKeyParameters key, byte[] hash) throws Exception {
        org.bouncycastle.asn1.ASN1ObjectIdentifier oid = new org.bouncycastle.asn1.ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");
        byte[] di = new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[]{
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(oid),
                new org.bouncycastle.asn1.DEROctetString(hash)}).getEncoded();
        int modLen = (key.getModulus().bitLength() + 7) / 8;
        byte[] em = new byte[modLen];
        em[0] = 0x00; em[1] = 0x01;
        int psLen = modLen - di.length - 3;
        Arrays.fill(em, 2, 2 + psLen, (byte) 0xFF);
        em[2 + psLen] = 0x00;
        System.arraycopy(di, 0, em, 3 + psLen, di.length);
        org.bouncycastle.crypto.engines.RSAEngine eng = new org.bouncycastle.crypto.engines.RSAEngine();
        eng.init(true, key);
        return eng.processBlock(em, 0, em.length);
    }

    static byte[] ecdsaSign(ECPrivateKeyParameters key, byte[] hash) throws Exception {
        org.bouncycastle.crypto.signers.ECDSASigner s =
                new org.bouncycastle.crypto.signers.ECDSASigner(
                        new org.bouncycastle.crypto.signers.HMacDSAKCalculator(new org.bouncycastle.crypto.digests.SHA256Digest()));
        s.init(true, new org.bouncycastle.crypto.params.ParametersWithRandom(key, new SecureRandom()));
        java.math.BigInteger[] rs = s.generateSignature(hash);
        return new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[]{
                new org.bouncycastle.asn1.ASN1Integer(rs[0]),
                new org.bouncycastle.asn1.ASN1Integer(rs[1])}).getEncoded();
    }

    /** 服务器 EAP-TLS 分片重组：flags + [len4] + data，累积至完整。 */
    static byte[] reassembleServer(byte[] data, int[] pendingLen, ByteArrayOutputStream pending) throws Exception {
        int flags = data[0] & 0xff;
        int off = 1;
        if ((flags & EAP_TLS_FLAG_LENGTH) != 0) {
            if (data.length < 5) throw new IOException("TLS 长度字段缺失");
            pendingLen[0] = ((data[1] & 0xff) << 24) | ((data[2] & 0xff) << 16)
                    | ((data[3] & 0xff) << 8) | (data[4] & 0xff);
            off = 5;
            pending.reset();
        }
        int payloadLen = data.length - off;
        if (payloadLen == 0) {
            // 空数据包（服务器维持/挑战，RFC 5216 无数据）：不产生任何 TLS 数据，
            // 返回 null 且不动 pending——绝不能把 0 字节喂给 TLS 线程。
            return null;
        }
        pending.write(data, off, payloadLen);
        if ((flags & EAP_TLS_FLAG_MORE) == 0) {
            byte[] full = pending.toByteArray();
            pending.reset();
            return full;
        }
        return null;
    }

    /** 客户端 → 服务器分片发送：首片带 LENGTH + MORE。 */
    static byte[] clientFragments(byte[] data, int[] sent) {
        int n = Math.min(EAP_TLS_FRAG, data.length - sent[0]);
        int flags = (sent[0] == 0 ? EAP_TLS_FLAG_LENGTH : 0)
                | (sent[0] + n < data.length ? EAP_TLS_FLAG_MORE : 0);
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(flags);
        if ((flags & EAP_TLS_FLAG_LENGTH) != 0) {
            b.write((data.length >> 24) & 0xff);
            b.write((data.length >> 16) & 0xff);
            b.write((data.length >> 8) & 0xff);
            b.write(data.length & 0xff);
        }
        b.write(data, sent[0], n);
        sent[0] += n;
        return b.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        String secret = "mytestkey";
        int authPort = 1812;
        try {
            for (String line : java.nio.file.Files.readAllLines(
                    java.nio.file.Paths.get(BASE, "PKI", "CONFIG.txt"))) {
                if (line.startsWith("RADIUSKEY=")) secret = line.substring(10).trim();
                if (line.startsWith("RADIUSPORT=")) authPort = Integer.parseInt(line.substring(11).trim());
            }
        } catch (Exception e) {
            System.out.println("CONFIG 读取失败，使用默认 mytestkey/1812: " + e);
        }

        System.out.println("=== EAP-TLS 证书登录全链路冒烟测试（模拟 Windows 原生 IKEv2 证书模式）===");
        System.out.println("RADIUS " + authPort + " secret=" + secret + " 客户端证书=" + CLIENT_SERIAL);

        // 加载客户端证书/私钥 + 信任锚
        X509Certificate clientCert = PemIO.readCert(BASE + "/PKI/CERT/" + CLIENT_SERIAL + ".crt");
        AsymmetricKeyParameter clientKey = PemIO.readPrivateKey(BASE + "/PKI/KEY/" + CLIENT_SERIAL + ".key");
        X509Certificate rootCert = PemIO.readCert(BASE + "/PKI/ROOT/" + ROOT_SERIAL + ".crt");
        List<X509Certificate> anchors = new ArrayList<>();
        anchors.add(rootCert);
        System.out.println("[0] 客户端证书 CN=" + clientCert.getSubjectX500Principal()
                + " 算法=" + clientCert.getPublicKey().getAlgorithm());

        DatagramSocket sock = new DatagramSocket();
        InetAddress host = InetAddress.getByName("127.0.0.1");
        SecureRandom rnd = new SecureRandom();
        int id = 1;
        byte[] reqAuth = new byte[16];
        rnd.nextBytes(reqAuth);

        // [1] Identity（无前缀，与 Windows 一致）
        byte[] eapIdPkt = eapPacket(EAP_CODE_RESPONSE, 1, EAP_TYPE_IDENTITY, "localhost".getBytes("UTF-8"));
        List<Attr> attrs = new ArrayList<>();
        attrs.add(new Attr(ATTR_USER_NAME, "localhost".getBytes("UTF-8")));
        attrs.add(new Attr(ATTR_EAP_MESSAGE, eapIdPkt));
        byte[] req1 = buildRequestPacket(id, reqAuth, attrs, secret, true);
        System.out.println("[1] 发送 Access-Request：User-Name=localhost + EAP-Identity(localhost)");
        byte[] resp1 = sendRecv(sock, req1, host, authPort, 5000);
        Object[] r1 = parseResp(resp1);
        byte[] eap1 = findAttr((List<Attr>) r1[3], ATTR_EAP_MESSAGE);
        if ((Integer) r1[0] != CODE_ACCESS_CHALLENGE || eap1 == null || (eap1[0] & 0xff) != EAP_CODE_REQUEST) {
            System.out.println("FAIL [1] 未收到 EAP-Request（code=" + r1[0] + "）");
            return;
        }
        int eapType1 = eap1[4] & 0xff;
        System.out.println("[2] 收到 EAP-Request type=" + eapType1 + "（期望 26=MSCHAPV2，实际=" + eapType1 + "）");
        if (eapType1 != EAP_TYPE_MSCHAPV2) {
            System.out.println("FAIL [2] 服务器未先发 MSCHAPV2（type=" + eapType1 + "）——与 Windows 期望不一致");
            return;
        }
        int eapId = eap1[1] & 0xff;

        // [3] NAK 声明仅支持 EAP-TLS（Type 13）
        byte[] nak = eapPacket(EAP_CODE_RESPONSE, (eapId + 1) & 0xff, EAP_TYPE_NAK, new byte[]{(byte) EAP_TYPE_TLS});
        List<Attr> nakAttrs = new ArrayList<>();
        nakAttrs.add(new Attr(ATTR_USER_NAME, "localhost".getBytes("UTF-8")));
        nakAttrs.add(new Attr(ATTR_EAP_MESSAGE, nak));
        byte[] nakReq = buildRequestPacket(++id, reqAuth, nakAttrs, secret, true);
        System.out.println("[3] 发送 EAP-NAK（声明支持 EAP-TLS Type=13）");
        byte[] resp2 = sendRecv(sock, nakReq, host, authPort, 5000);
        Object[] r2 = parseResp(resp2);
        byte[] eap2 = findAttr((List<Attr>) r2[3], ATTR_EAP_MESSAGE);
        if ((Integer) r2[0] != CODE_ACCESS_CHALLENGE || eap2 == null || (eap2[0] & 0xff) != EAP_CODE_REQUEST
                || (eap2[4] & 0xff) != EAP_TYPE_TLS) {
            System.out.println("FAIL [4] NAK 后未切换 EAP-TLS（code=" + r2[0]
                    + " eapType=" + (eap2 != null && eap2.length > 4 ? (eap2[4] & 0xff) : "null") + "）");
            return;
        }
        eapId = eap2[1] & 0xff;
        byte[] tlsStart = eap2.length > 5 ? Arrays.copyOfRange(eap2, 5, eap2.length) : new byte[0];
        int startFlags = tlsStart.length > 0 ? (tlsStart[0] & 0xff) : 0;
        System.out.println("[4] 收到 EAP-Request/TLS Start（flags=0x" + Integer.toHexString(startFlags) + "）——服务器已切换到 EAP-TLS");

        // [5] 启动 TLS 客户端握手线程
        BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());
        CliTlsSession s = new CliTlsSession();
        s.thread = new Thread(() -> {
            try {
                TlsClientProtocol proto = new TlsClientProtocol(s.inStream, s.out);
                Cli cli = new Cli(crypto, anchors, clientCert, clientKey);
                proto.connect(cli);
                // RFC 5216 §2.4：客户端导出 MSK 与服务端对照
                // （BC exporter 要求 EMS，strongSwan 场景无 EMS，手工 PRF 计算）
                try {
                    java.lang.reflect.Method gm = org.bouncycastle.tls.TlsProtocol.class.getDeclaredMethod("getContext");
                    gm.setAccessible(true);
                    org.bouncycastle.tls.TlsContext tctx =
                            (org.bouncycastle.tls.TlsContext) gm.invoke(proto);
                    org.bouncycastle.tls.SecurityParameters sp = tctx.getSecurityParameters();
                    org.bouncycastle.tls.crypto.TlsSecret ms = sp.getMasterSecret();
                    if (ms == null) {
                        java.lang.reflect.Field f = org.bouncycastle.tls.TlsProtocol.class.getDeclaredField("sessionMasterSecret");
                        f.setAccessible(true);
                        ms = (org.bouncycastle.tls.crypto.TlsSecret) f.get(proto);
                    }
                    if (ms == null) {
                        org.bouncycastle.tls.TlsSession sess = tctx.getSession();
                        if (sess != null) {
                            org.bouncycastle.tls.SessionParameters sp2 = sess.exportSessionParameters();
                            if (sp2 != null) ms = sp2.getMasterSecret();
                        }
                    }
                    byte[] master = ms.extract();
                    byte[] cr = sp.getClientRandom();
                    byte[] sr = sp.getServerRandom();
                    byte[] seed = new byte[cr.length + sr.length];
                    System.arraycopy(cr, 0, seed, 0, cr.length);
                    System.arraycopy(sr, 0, seed, cr.length, sr.length);
                    s.clientMsk = tls12Prf(master, "client EAP encryption", seed, 64);
                    System.out.println("[handshake] 客户端导出 MSK(64B)=" + hex(s.clientMsk, 64));
                } catch (Exception mex) {
                    System.out.println("[handshake] 客户端 MSK 导出失败: " + mex);
                }
            } catch (Exception ex) {
                s.err = ex.toString();
                StringBuilder sb = new StringBuilder();
                for (StackTraceElement ste : ex.getStackTrace()) {
                    sb.append("\n      at " + ste);
                }
                s.errStack = sb.toString();
            } finally {
                s.done = true;
                synchronized (s) { s.notifyAll(); }
            }
        }, "eap-tls-client");
        s.thread.setDaemon(true);
        s.thread.start();
        // 等待 ClientHello 输出
        byte[] hello = pollOutput(s, 5000);
        if (hello == null || hello.length == 0) {
            System.out.println("FAIL [5] ClientHello 生成失败: " + s.err);
            return;
        }
        System.out.println("[5] 客户端 ClientHello " + hello.length + "B hex=" + hex(hello, Math.min(80, hello.length)));

        // [6] 握手循环：RFC 5216 §2.1 拉取式分片交换。
        // 服务器每收到一个客户端 EAP-TLS 包只回一片；客户端逐片发送、逐片拉取，
        // 收到 MORE 片时以空包（flags=0）拉取续片，收齐后喂给 TLS 线程取新输出。
        int[] sent = new int[]{0};
        int[] pendingLen = new int[]{-1};
        ByteArrayOutputStream pending = new ByteArrayOutputStream();
        boolean success = false;
        boolean serverMore = false;
        boolean hasPendingResp = false;
        byte[] pendingFrag = null;
        byte[] toSend = hello;
        long deadline = System.currentTimeMillis() + 60000;
        int idle = 0;
        while (System.currentTimeMillis() < deadline) {
            byte[] eapResp = null;
            if (sent[0] < toSend.length || hasPendingResp) {
                // 有客户端数据待发：发一片（首片带 LENGTH）
                if (!hasPendingResp) {
                    pendingFrag = clientFragments(toSend, sent);
                    System.out.println("[CLI→] TLS片 " + pendingFrag.length + "B flags=0x" + Integer.toHexString(pendingFrag[0] & 0xff)
                            + " total=" + (pendingFrag.length > 4 ? ((pendingFrag[1]&0xff)<<24|(pendingFrag[2]&0xff)<<16|(pendingFrag[3]&0xff)<<8|(pendingFrag[4]&0xff)) : -1)
                            + " sent=" + sent[0] + "/" + toSend.length);
                }
                eapResp = eapPacket(EAP_CODE_RESPONSE, (eapId + 1) & 0xff, EAP_TYPE_TLS, pendingFrag);
                hasPendingResp = false;
                if (sent[0] >= toSend.length && s.thread != null) {
                    System.out.println("[发完] 客户端线程=" + s.thread.getState() + " done=" + s.done + " err=" + s.err
                            + " out.size=" + s.out.size() + " inQ=" + s.inQ.size());
                    if (s.out.size() > 1867) {
                        byte[] all = s.out.toByteArray();
                        System.out.println("[out剩余hex] " + hex(Arrays.copyOfRange(all, 1867, all.length), all.length - 1867));
                    }
                if (s.errStack != null) {
                    System.out.println("  客户端异常堆栈:" + s.errStack);
                }
                    for (StackTraceElement ste : s.thread.getStackTrace()) {
                        System.out.println("      at " + ste);
                    }
                }
            } else if (serverMore) {
                // 服务器数据未收齐：空包拉取续片
                System.out.println("[CLI→] 拉取续片（空包 flags=0）");
                eapResp = eapPacket(EAP_CODE_RESPONSE, (eapId + 1) & 0xff, EAP_TYPE_TLS, new byte[]{0});
            } else {
                // 客户端数据发完、服务器数据收齐：等 TLS 线程新输出；无输出则空包维持
                byte[] nxt = pollOutput(s, 2500);
                if (nxt != null && nxt.length > 0) {
                    toSend = nxt;
                    sent[0] = 0;
                    // 打印 TLS record 结构（type + 长度）
                    int p = 0;
                    StringBuilder rb = new StringBuilder("[增量] " + nxt.length + "B records:");
                    while (p + 5 <= nxt.length) {
                        int t = nxt[p] & 0xff;
                        int l = ((nxt[p+3] & 0xff) << 8) | (nxt[p+4] & 0xff);
                        rb.append(" type=" + t + " len=" + l);
                        p += 5 + l;
                    }
                    System.out.println(rb.toString());
                    if (nxt.length > 1666) {
                        System.out.println("[record2 hex] " + hex(nxt, nxt.length));
                    }
                    // 解析 Handshake record 内的消息类型
                    if (nxt[0] == 22 && nxt.length > 5) {
                        int hp = 5; StringBuilder hb = new StringBuilder("[handshake]");
                        while (hp + 4 <= nxt.length) {
                            int mt = nxt[hp] & 0xff;
                            int ml = ((nxt[hp+1]&0xff)<<16)|((nxt[hp+2]&0xff)<<8)|(nxt[hp+3]&0xff);
                            hb.append(" msg=" + mt + " len=" + ml);
                            hp += 4 + ml;
                        }
                        System.out.println(hb.toString() + " 已解析=" + hp + "/" + nxt.length);
                    }
                    // 取到新增量：立即构造第一片（不能沿用上一轮 eapResp），
                    // continue 跳过维持包覆盖，下一轮发分片分支直接发送该片。
                    pendingFrag = clientFragments(toSend, sent);
                    System.out.println("[CLI→] TLS片 " + pendingFrag.length + "B flags=0x" + Integer.toHexString(pendingFrag[0] & 0xff)
                            + " total=" + (pendingFrag.length > 4 ? ((pendingFrag[1]&0xff)<<24|(pendingFrag[2]&0xff)<<16|(pendingFrag[3]&0xff)<<8|(pendingFrag[4]&0xff)) : -1)
                            + " sent=" + sent[0] + "/" + toSend.length);
                    hasPendingResp = true;
                    continue;
                }
                if (s.done) {
                    if (s.err != null) {
                        System.out.println("FAIL [6] TLS 握手失败: " + s.err);
                        return;
                    }
                    // 握手完成：发空包触发服务器收尾（EAP-Success）
                }
                System.out.println("[CLI→] 维持包（flags=0） done=" + s.done + " err=" + s.err
                        + " 线程=" + (s.thread == null ? "null" : s.thread.getState().toString()));
                if (s.thread != null) {
                    for (StackTraceElement ste : s.thread.getStackTrace()) {
                        System.out.println("      at " + ste);
                    }
                }
                eapResp = eapPacket(EAP_CODE_RESPONSE, (eapId + 1) & 0xff, EAP_TYPE_TLS, new byte[]{0});
            }
            List<Attr> a = new ArrayList<>();
            a.add(new Attr(ATTR_USER_NAME, "localhost".getBytes("UTF-8")));
            a.add(new Attr(ATTR_EAP_MESSAGE, eapResp));
            byte[] rq = buildRequestPacket(++id, reqAuth, a, secret, true);
            byte[] rs = sendRecv(sock, rq, host, authPort, 8000);
            System.out.println("[sendRecv] 返回 " + rs.length + "B code=" + (rs.length > 0 ? (rs[0] & 0xff) : -1)
                    + " hex=" + (rs.length > 0 ? hex(rs, Math.min(16, rs.length)) : ""));
            Object[] rr = parseResp(rs);
            byte[] ee = findAttr((List<Attr>) rr[3], ATTR_EAP_MESSAGE);
            if ((Integer) rr[0] == CODE_ACCESS_ACCEPT && ee != null && ee.length > 0
                    && (ee[0] & 0xff) == EAP_CODE_SUCCESS) {
                success = true;
                break;
            }
            if ((Integer) rr[0] == CODE_ACCESS_REJECT) {
                System.out.println("FAIL [6] 服务器 Access-Reject: "
                        + (ee == null ? "无 EAP" : "EAP code=" + (ee[0] & 0xff)
                        + (ee.length > 4 ? " type=" + (ee[4] & 0xff) : " (Failure)")) + " err=" + s.err);
                return;
            }
            if ((Integer) rr[0] != CODE_ACCESS_CHALLENGE || ee == null || ee.length <= 0
                    || (ee[0] & 0xff) != EAP_CODE_REQUEST || (ee[4] & 0xff) != EAP_TYPE_TLS) {
                idle++;
                if (idle > 10) {
                    System.out.println("FAIL [6] 服务器响应异常: code=" + rr[0] + " eap="
                            + (ee == null ? "null" : hex(ee, 8)));
                    return;
                }
                continue;
            }
            idle = 0;
            byte[] payload = ee.length > 5 ? Arrays.copyOfRange(ee, 5, ee.length) : new byte[0];
            if (payload.length == 0 || ((payload[0] & 0xff) & EAP_TLS_FLAG_START) != 0) {
                continue;   // Start 不应重复出现
            }
            System.out.println("[SVR←] TLS片 " + payload.length + "B flags=0x"
                    + Integer.toHexString(payload[0] & 0xff));
            byte[] full = reassembleServer(payload, pendingLen, pending);
            if (full == null) {
                // 空数据包（服务器维持/挑战）：忽略，不改变 serverMore
                if (payload.length > 1) {
                    serverMore = true;   // 还有续片：下次循环空包拉取
                }
                continue;
            }
            serverMore = false;
            // 解析服务器 flight record 结构
            {
                int p = 0; StringBuilder sb = new StringBuilder("[SVR flight] " + full.length + "B");
                while (p + 5 <= full.length) {
                    int t = full[p] & 0xff;
                    int l = ((full[p+3] & 0xff) << 8) | (full[p+4] & 0xff);
                    sb.append(" rec type=" + t + " len=" + l);
                    if (t == 22 && p + 9 <= full.length) {
                        int mt = full[p+5] & 0xff;
                        int ml = ((full[p+6]&0xff)<<16)|((full[p+7]&0xff)<<8)|(full[p+8]&0xff);
                        sb.append("(hs msg=" + mt + " len=" + ml + ")");
                    }
                    p += 5 + l;
                }
                System.out.println(sb.toString());
            }
            s.inQ.add(full);   // 完整 TLS record 喂给握手线程
        }

        if (!success) {
            System.out.println("FAIL [6] 未收到 Access-Accept（最后 err=" + s.err + " done=" + s.done + "）");
            return;
        }
        System.out.println("[6] 收到 Access-Accept + EAP-Success —— EAP-TLS 证书认证通过");
        System.out.println("\nRESULT=PASS");
        sock.close();
    }

    static byte[] findAttr(List<Attr> attrs, int type) {
        for (Attr a : attrs) {
            if (a.type == type) return a.value;
        }
        return null;
    }

    /** 轮询 TLS 会话输出缓冲：只返回自上次读取以来的增量（握手线程写入 out）。 */
    static byte[] pollOutput(CliTlsSession s, int timeoutMs) throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            synchronized (s) {
                byte[] cur = s.out.toByteArray();
                int start = (s.outBuf == null) ? 0 : s.outBuf.length;
                System.out.println("[pollOutput] cur=" + cur.length + " start=" + start + " done=" + s.done + " err=" + s.err);
                if (cur.length > start) {
                    byte[] inc = Arrays.copyOfRange(cur, start, cur.length);
                    s.outBuf = cur;
                    return inc;
                }
            }
            if (s.done) break;
            Thread.sleep(50);
        }
        return null;
    }

    /** TLS 1.2 PRF（RFC 5246 §5）：PRF(secret,label,seed) = P_SHA256(secret, label + seed)。 */
    static byte[] tls12Prf(byte[] secret, String label, byte[] seed, int len) {
        try {
            byte[] labelSeed = new byte[label.length() + seed.length];
            byte[] lb = label.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            System.arraycopy(lb, 0, labelSeed, 0, lb.length);
            System.arraycopy(seed, 0, labelSeed, lb.length, seed.length);
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            byte[] a = null;
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            while (out.size() < len) {
                mac.init(new javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256"));
                a = a == null ? mac.doFinal(labelSeed) : mac.doFinal(a);
                mac.init(new javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256"));
                byte[] block = new byte[a.length + labelSeed.length];
                System.arraycopy(a, 0, block, 0, a.length);
                System.arraycopy(labelSeed, 0, block, a.length, labelSeed.length);
                byte[] p = mac.doFinal(block);
                out.write(p, 0, Math.min(p.length, len - out.size()));
            }
            return out.toByteArray();
        } catch (Exception ex) {
            System.out.println("[handshake] PRF 计算异常: " + ex);
            return null;
        }
    }

    static String hex(byte[] d, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(n, d.length); i++) {
            sb.append(String.format("%02x", d[i] & 0xff));
        }
        return sb.toString();
    }
}
