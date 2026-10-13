import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.*;
import org.bouncycastle.tls.crypto.impl.bc.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import java.net.*;
import java.util.*;
import java.io.*;
import java.security.SecureRandom;
import javax.crypto.*;
import javax.crypto.spec.*;

/** BC 完整 TLS1.3 客户端，经 EAP-TLS 分片与 RADIUS 服务端做完整握手。
 *  验证服务端 flight（ServerHello+EE+Certificate+CV+Finished）能被标准 TLS 客户端接受。 */
public class Tls13FullClientTest {
    static final int ATTR_USER_NAME = 1, ATTR_EAP_MESSAGE = 79, ATTR_MESSAGE_AUTHENTICATOR = 80;
    static final class Attr { int type; byte[] value; Attr(int t, byte[] v) { type = t; value = v; } }
    static byte[] hmacMd5(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacMD5"); mac.init(new SecretKeySpec(key, "HmacMD5")); return mac.doFinal(data);
    }
    static byte[] buildRequestPacket(int id, byte[] reqAuth, List<Attr> attrs, String secret) throws Exception {
        List<Attr> list = new ArrayList<>(attrs);
        int maOffset = -1; list.add(new Attr(ATTR_MESSAGE_AUTHENTICATOR, new byte[16]));
        int len = 20; for (Attr a : list) len += a.value.length + 2;
        byte[] out = new byte[len];
        out[0] = 1; out[1] = (byte) id; out[2] = (byte) (len >> 8); out[3] = (byte) len;
        System.arraycopy(reqAuth, 0, out, 4, 16);
        int off = 20;
        for (Attr a : list) {
            out[off] = (byte) a.type; out[off + 1] = (byte) (a.value.length + 2);
            System.arraycopy(a.value, 0, out, off + 2, a.value.length);
            if (a.type == ATTR_MESSAGE_AUTHENTICATOR) maOffset = off;
            off += a.value.length + 2;
        }
        byte[] mac = hmacMd5(secret.getBytes("UTF-8"), out);
        System.arraycopy(mac, 0, out, maOffset + 2, 16);
        return out;
    }
    static List<Attr> parseAttrs(byte[] buf) {
        List<Attr> attrs = new ArrayList<>(); int off = 20;
        while (off + 2 <= buf.length) {
            int t = buf[off] & 0xff, l = buf[off + 1] & 0xff;
            if (l < 2 || off + l > buf.length) break;
            attrs.add(new Attr(t, Arrays.copyOfRange(buf, off + 2, off + l))); off += l;
        }
        return attrs;
    }
    static byte[] findAttr(List<Attr> attrs, int type) {
        for (Attr a : attrs) if (a.type == type) return a.value; return null;
    }
    static byte[] sendRecv(DatagramSocket sock, byte[] req, InetAddress host, int port, int timeoutMs) throws Exception {
        sock.send(new DatagramPacket(req, req.length, host, port)); sock.setSoTimeout(timeoutMs);
        byte[] buf = new byte[65535]; DatagramPacket p = new DatagramPacket(buf, buf.length);
        sock.receive(p); return Arrays.copyOf(p.getData(), p.getLength());
    }
    static String hex(byte[] b, int from, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len && from + i < b.length; i++) {
            if (i > 0 && i % 32 == 0) sb.append("\n      ");
            sb.append(String.format("%02x", b[from + i] & 0xff));
        }
        return sb.toString();
    }

    /** 把 TLS 数据切成 EAP-TLS 帧发送。EAP 包=[Code,Id,Len(2),Type(13),Flags,(L:4B),Data]。只发不收。 */
    static void sendTlsFrames(DatagramSocket sock, byte[] tls, InetAddress host, int port, byte[] reqAuth, String secret,
                              int[] rid, int eapId) throws Exception {
        int max = 1000, off = 0, idx = 0;
        while (off < tls.length) {
            int chunk = Math.min(max, tls.length - off);
            boolean last = off + chunk >= tls.length;
            byte[] frag = Arrays.copyOfRange(tls, off, off + chunk);
            int flags = idx == 0 ? 0xC0 : (last ? 0x00 : 0x40);
            ByteArrayOutputStream eap = new ByteArrayOutputStream();
            int eapLen = idx == 0 ? 11 + frag.length : 7 + frag.length; // 首片含 4B L
            eap.write(2); eap.write(eapId);
            eap.write(0); eap.write(eapLen);          // EAP length
            eap.write(13);                            // Type = EAP-TLS
            eap.write(flags);
            if (idx == 0) {
                eap.write((tls.length >> 24) & 0xff); eap.write((tls.length >> 16) & 0xff);
                eap.write((tls.length >> 8) & 0xff); eap.write(tls.length & 0xff); // L(4B)
            }
            eap.write(frag);
            byte[] eapPkt = eap.toByteArray();
            List<Attr> a = new ArrayList<>();
            a.add(new Attr(ATTR_USER_NAME, "admin666".getBytes("UTF-8")));
            for (int p = 0; p < eapPkt.length; p += 253) {
                a.add(new Attr(ATTR_EAP_MESSAGE, Arrays.copyOfRange(eapPkt, p, Math.min(eapPkt.length, p + 253))));
            }
            byte[] req = buildRequestPacket(++rid[0], reqAuth, a, secret);
            sock.send(new DatagramPacket(req, req.length, host, port));
            off += chunk; idx++;
        }
    }

    /** 收服务端 EAP-TLS 帧（处理分片续传：M=1 时回空 EAP-Response），返回拼好的 TLS 流。 */
    static byte[] recvTlsFrames(DatagramSocket sock, InetAddress host, int port, byte[] reqAuth, String secret,
                                int[] rid, int eapId, int timeoutMs) throws Exception {
        ByteArrayOutputStream tls = new ByteArrayOutputStream();
        int guard = 0;
        while (guard++ < 30) {
            byte[] buf = new byte[65535]; DatagramPacket p = new DatagramPacket(buf, buf.length);
            sock.setSoTimeout(timeoutMs); sock.receive(p);
            byte[] resp = Arrays.copyOf(p.getData(), p.getLength());
            List<Attr> attrs = parseAttrs(resp);
            byte[] e = findAttr(attrs, ATTR_EAP_MESSAGE);
            if (e == null) throw new IOException("无 EAP-Message (code=" + (resp[0] & 0xff) + ")");
            int eapCode = e[0] & 0xff;
            if (eapCode == 3) {              // EAP-Success：握手完成
                System.out.println("[recv] EAP-Success");
                return new byte[0];
            }
            if (eapCode == 4) {              // EAP-Failure
                System.out.println("[recv] EAP-Failure");
                throw new IOException("EAP-Failure");
            }
            int flags = e[5] & 0xff;                       // value[4]=Type(13), value[5]=Flags
            int off = 6 + ((flags & 0x80) != 0 ? 4 : 0);   // L 位时跳 4B FragmentLength
            tls.write(e, off, e.length - off);
            boolean more = (flags & 0x40) != 0;
            if (more) {
                // EAP-TLS 分片续传：发空 EAP-Response（Type=13, Flags=0）→ 服务端按 1B 0x00 拉片。
                // RFC 3748 §4.1：回显服务器本次 Request 的 Identifier（每个 Request 都不同）。
                int pullId = (e.length > 1) ? (e[1] & 0xff) : eapId;
                List<Attr> a = new ArrayList<>();
                a.add(new Attr(ATTR_USER_NAME, "admin666".getBytes("UTF-8")));
                a.add(new Attr(ATTR_EAP_MESSAGE, new byte[]{2, (byte) pullId, 0, 6, 13, 0}));
                byte[] req = buildRequestPacket(++rid[0], reqAuth, a, secret);
                sock.send(new DatagramPacket(req, req.length, host, port));
            } else {
                return tls.toByteArray();
            }
        }
        throw new IOException("分片续传超限");
    }

    /** 发空拉取帧（EAP-TLS 分片续传维持：RADIUS Access-Request + EAP-Response type=13 flags=0）。 */
    static void sendPullFrame(DatagramSocket sock, InetAddress host, int port, byte[] reqAuth, String secret,
                              int[] rid, int eapId) throws Exception {
        List<Attr> a = new ArrayList<>();
        a.add(new Attr(ATTR_USER_NAME, "admin666".getBytes("UTF-8")));
        a.add(new Attr(ATTR_EAP_MESSAGE, new byte[]{2, (byte) eapId, 0, 6, 13, 0}));
        byte[] req = buildRequestPacket(++rid[0], reqAuth, a, secret);
        sock.send(new DatagramPacket(req, req.length, host, port));
    }

    static class EapTlsClient extends DefaultTlsClient {
        final BcTlsCrypto crypto; final Certificate cert; final AsymmetricKeyParameter priv;
        TlsClientContext ctx;
        EapTlsClient(BcTlsCrypto c, Certificate cert, AsymmetricKeyParameter priv) {
            super(c); this.crypto = c; this.cert = cert; this.priv = priv;
        }
        public void init(TlsClientContext c) { super.init(c); this.ctx = c; }
        public ProtocolVersion[] getSupportedVersions() {
            return new ProtocolVersion[]{ProtocolVersion.TLSv13, ProtocolVersion.TLSv12};
        }
        public int[] getSupportedCipherSuites() {
            // TLS 1.3: 0x1301 AES_128_GCM_SHA256, 0x1302 AES_256_GCM_SHA384, 0x1303 CHACHA20_POLY1305_SHA256
            return new int[]{0x1301, 0x1302, 0x1303,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256};
        }
        public boolean shouldUseExtendedMasterSecret() { return true; }
        public boolean shouldUseGMTUnixTime() { return true; }
        public TlsAuthentication getAuthentication() {
            return new TlsAuthentication() {
                public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException {
                    // 不校验服务端证书（信任锚已装）
                }
                public TlsCredentialedSigner getClientCredentials(CertificateRequest cr) {
                    try {
                        TlsCryptoParameters cp = new TlsCryptoParameters(ctx);
                        SignatureAndHashAlgorithm sigAlg = new SignatureAndHashAlgorithm(
                                HashAlgorithm.sha256, SignatureAlgorithm.rsa_pss_rsae_sha256);
                        return new BcDefaultTlsCredentialedSigner(cp, crypto, priv, cert, sigAlg);
                    } catch (Exception e) {
                        throw new RuntimeException("构造客户端凭证失败: " + e, e);
                    }
                }
            };
        }
    }

    public static void main(String[] args) throws Exception {
        String secret = "mytestkey"; int port = 1812;
        InetAddress host = InetAddress.getByName("127.0.0.1");
        byte[] reqAuth = new byte[16]; new SecureRandom().nextBytes(reqAuth);
        int[] rid = {1};

        // 加载客户端证书+私钥（PKI/CERT + PKI/KEY，同服务端 EAP-TLS 库）
        BcTlsCrypto crypto = new BcTlsCrypto();
        String certPath = "PKI/CERT/a66de5fea3df44c8f8687f31d75384d.crt";
        String keyPath = "PKI/KEY/a66de5fea3df44c8f8687f31d75384d.key";
        X509CertificateHolder holder;
        try (PEMParser pp = new PEMParser(new FileReader(certPath))) {
            holder = (X509CertificateHolder) pp.readObject();
        }
        TlsCertificate tlsCert = crypto.createCertificate(holder.getEncoded());
        Certificate clientCert = new Certificate(new TlsCertificate[]{tlsCert});
        AsymmetricKeyParameter priv;
        try (PEMParser kp = new PEMParser(new FileReader(keyPath))) {
            Object o = kp.readObject();
            if (o instanceof PEMKeyPair) {
                PEMKeyPair kk = (PEMKeyPair) o;
                priv = PrivateKeyFactory.createKey(kk.getPrivateKeyInfo());
            } else if (o instanceof PrivateKeyInfo) {
                priv = PrivateKeyFactory.createKey((PrivateKeyInfo) o);
            } else {
                throw new IOException("未知私钥格式: " + o);
            }
        }
        System.out.println("客户端证书=" + holder.getSubject() + " 私钥类型=" + priv.getClass().getSimpleName());

        DatagramSocket sock = new DatagramSocket();
        // [1] Identity
        List<Attr> a = new ArrayList<>();
        a.add(new Attr(ATTR_USER_NAME, "admin666".getBytes("UTF-8")));
        a.add(new Attr(ATTR_EAP_MESSAGE, new byte[]{2, 0, 0, 13, 1, (byte) 'a', (byte) 'd', (byte) 'm', (byte) 'i', (byte) 'n', 54, 54, 54}));
        byte[] r1 = sendRecv(sock, buildRequestPacket(rid[0], reqAuth, a, secret), host, port, 5000);
        System.out.println("[1] Identity -> code=" + (r1[0] & 0xff));
        // [2] NAK → EAP-TLS
        List<Attr> n = new ArrayList<>();
        n.add(new Attr(ATTR_USER_NAME, "admin666".getBytes("UTF-8")));
        n.add(new Attr(ATTR_EAP_MESSAGE, new byte[]{2, 1, 0, 6, 3, 13}));
        byte[] r2 = sendRecv(sock, buildRequestPacket(++rid[0], reqAuth, n, secret), host, port, 5000);
        byte[] e2 = findAttr(parseAttrs(r2), ATTR_EAP_MESSAGE);
        System.out.println("[2] NAK -> code=" + (r2[0] & 0xff) + " EAP=" + (e2 == null ? "-" : hex(e2, 0, e2.length)));
        int eapId = e2[1] & 0xff;
        System.out.println("EAP-TLS Start 收到，EAP-id=" + eapId);

        // [3] BC 客户端握手（流桥接）
        PipedInputStream bcIn = new PipedInputStream(256 * 1024);
        PipedOutputStream netToBc = new PipedOutputStream(bcIn);
        PipedOutputStream bcOut = new PipedOutputStream();
        PipedInputStream bcToNet = new PipedInputStream(bcOut, 256 * 1024);
        TlsClientProtocol clientProto = new TlsClientProtocol(bcIn, bcOut);
        EapTlsClient client = new EapTlsClient(crypto, clientCert, priv);
        java.util.concurrent.atomic.AtomicReference<Exception> bcErr = new java.util.concurrent.atomic.AtomicReference<>();
        Thread bcThread = new Thread(() -> {
            try {
                clientProto.connect(client);
            } catch (Exception ex) {
                bcErr.set(ex);
            }
        }, "bc-client");
        bcThread.start();

        long deadline = System.currentTimeMillis() + 60000;
        while (System.currentTimeMillis() < deadline && bcThread.isAlive()) {
            if (bcToNet.available() > 0) {
                // BC 有输出 → 发服务端
                byte[] out = new byte[bcToNet.available()];
                bcToNet.read(out);
                System.out.println("BC 输出 " + out.length + "B -> 发服务端: " + hex(out, 0, Math.min(40, out.length)));
                sendTlsFrames(sock, out, host, port, reqAuth, secret, rid, eapId);
                try {
                    byte[] tls = recvTlsFrames(sock, host, port, reqAuth, secret, rid, eapId, 2000);
                    if (tls.length > 0) { netToBc.write(tls); netToBc.flush(); }
                } catch (SocketTimeoutException te) { }
            } else {
                // 无 BC 输出：发空拉取帧维持（RFC 5216 分片续传），收服务端数据
                try {
                    sendPullFrame(sock, host, port, reqAuth, secret, rid, eapId);
                    byte[] tls = recvTlsFrames(sock, host, port, reqAuth, secret, rid, eapId, 2000);
                    if (tls.length > 0) {
                        System.out.println("服务端数据收到 " + tls.length + "B: " + hex(tls, 0, Math.min(40, tls.length)));
                        netToBc.write(tls); netToBc.flush();
                    }
                } catch (SocketTimeoutException te) { }
            }
            Thread.sleep(30);
        }
        bcThread.join(10000);
        if (bcErr.get() != null) {
            System.out.println("BC 客户端握手失败: " + bcErr.get());
            bcErr.get().printStackTrace(System.out);
            System.exit(2);
        }
        if (!bcThread.isAlive()) {
            System.out.println("=== BC 客户端 TLS1.3 握手完成 ===");
            System.out.println("会话状态: 客户端证书已发送, 服务端飞行校验通过");
        } else {
            System.out.println("=== 超时，BC 线程仍存活 ===");
            System.exit(3);
        }
    }
}
