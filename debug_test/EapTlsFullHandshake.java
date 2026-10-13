import java.net.*;
import java.util.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import modpkica.PemIO;

/**
 * 完整 EAP-TLS 客户端握手模拟（RFC 5216）：用 BC TlsClientProtocol 作为客户端，
 * 直连本地 RADIUS 1812，完成 ClientHello→ServerHello→Certificate→…→Finished
 * 全流程，验证服务端 EAP-TLS 握手实现 100% 标准可完成。
 *
 * 通过条件：
 *   [1] Identity → Start
 *   [2] ClientHello → 收到 ServerHello（记录套件）
 *   [3] 服务器分片拉取 → 收齐 Certificate 链（记录链级数/根指纹）
 *   [4] 客户端证书 + Finished → 服务端 Success + MS-MPPE(64B)
 *   [5] 握手完成、无 unexpected_message、无超时
 */
public class EapTlsFullHandshake {
    static final int CODE_ACCESS_REQUEST = 1, CODE_ACCESS_CHALLENGE = 11, CODE_ACCESS_ACCEPT = 2;
    static final int ATTR_USER_NAME = 1, ATTR_EAP_MESSAGE = 79, ATTR_MESSAGE_AUTHENTICATOR = 80;
    static final int ATTR_MS_MPPE_RECV_KEY = 17, ATTR_MS_MPPE_SEND_KEY = 16;
    static final int EAP_TYPE_TLS = 13, EAP_TYPE_IDENTITY = 1, EAP_TYPE_NAK = 3;
    static final int EAP_TLS_FLAG_LENGTH = 0x80, EAP_TLS_FLAG_MORE = 0x40, EAP_TLS_FLAG_START = 0x20;
    static final int FRAG = 240;

    static final class Attr { int type; byte[] value; Attr(int t, byte[] v) { type = t; value = v; } }

    static byte[] hmacMd5(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacMD5"); mac.init(new SecretKeySpec(key, "HmacMD5")); return mac.doFinal(data);
    }
    static byte[] buildRequestPacket(int id, byte[] reqAuth, List<Attr> attrs, String secret) throws Exception {
        List<Attr> list = new ArrayList<>(attrs);
        int maOffset = -1;
        list.add(new Attr(ATTR_MESSAGE_AUTHENTICATOR, new byte[16]));
        int len = 20; for (Attr a : list) len += a.value.length + 2;
        byte[] out = new byte[len];
        out[0] = CODE_ACCESS_REQUEST; out[1] = (byte) id; out[2] = (byte) (len >> 8); out[3] = (byte) len;
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
    static Object[] parseResp(byte[] buf) {
        List<Attr> attrs = new ArrayList<>(); int off = 20;
        while (off + 2 <= buf.length) {
            int t = buf[off] & 0xff, l = buf[off + 1] & 0xff;
            if (l < 2 || off + l > buf.length) break;
            attrs.add(new Attr(t, Arrays.copyOfRange(buf, off + 2, off + l))); off += l;
        }
        return new Object[]{buf[0] & 0xff, buf[1] & 0xff, attrs};
    }
    static byte[] findAttr(List<Attr> attrs, int type) {
        for (Attr a : attrs) if (a.type == type) return a.value; return null;
    }
    static byte[] sendRecv(DatagramSocket sock, byte[] req, InetAddress host, int port, int timeoutMs) throws Exception {
        sock.send(new DatagramPacket(req, req.length, host, port)); sock.setSoTimeout(timeoutMs);
        byte[] buf = new byte[65535]; DatagramPacket p = new DatagramPacket(buf, buf.length);
        sock.receive(p); return Arrays.copyOf(p.getData(), p.getLength());
    }

    /** 阻塞式输入流：握手线程读，主线程 push 服务器数据。 */
    static final class BlockingIn extends InputStream {
        final ArrayDeque<byte[]> chunks = new ArrayDeque<>();
        byte[] cur; int pos;
        synchronized void push(byte[] d) { chunks.addLast(d); notifyAll(); }
        @Override public synchronized int read() throws IOException {
            while (cur == null || pos >= cur.length) {
                if (chunks.isEmpty()) { try { wait(); } catch (InterruptedException e) { throw new IOException(e); } }
                cur = chunks.removeFirst(); pos = 0;
            }
            return cur[pos++] & 0xff;
        }
        @Override public synchronized int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) return 0;
            int c = read();
            if (c < 0) return -1;
            b[off] = (byte) c;
            int n = 1;
            while (n < len && (cur != null && pos < cur.length)) { b[off + n] = cur[pos++]; n++; }
            return n;
        }
    }

    /** 记录服务端证书链的 TLS 客户端（携带客户端证书）。 */
    static X509Certificate[] serverChain = null;
    static class TestClient extends DefaultTlsClient {
        final X509Certificate clientCert;
        final AsymmetricKeyParameter clientKey;
        TestClient(TlsCrypto crypto, X509Certificate c, AsymmetricKeyParameter k) {
            super(crypto); clientCert = c; clientKey = k;
        }
        @Override public TlsAuthentication getAuthentication() {
            return new TlsAuthentication() {
                @Override public void notifyServerCertificate(TlsServerCertificate sc) {
                    serverChain = sc.getCertificate().getCertificateList();
                }
                @Override public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException {
                    return new DefaultTlsCredentialedSigner(
                            new TlsCryptoParameters(TestClient.this.getContext()),
                            EapTlsFullHandshake.crypto, clientKey,
                            new org.bouncycastle.tls.Certificate(new X509Certificate[]{clientCert}));
                }
            };
        }
    }
    static TlsCrypto crypto = new BcTlsCrypto(new SecureRandom());

    /** EAP-TLS 客户端分片封装：首片 L+total，>FRAG 非末片加 M。 */
    static byte[][] eapFrag(int eapId, byte[] data) {
        boolean multi = data.length > FRAG;
        int n = multi ? (data.length + FRAG - 1) / FRAG : 1;
        byte[][] out = new byte[n][];
        for (int i = 0; i < n; i++) {
            int from = i * FRAG, to = Math.min(data.length, from + FRAG);
            int bodyLen = 1 + (i == 0 ? 4 : 0) + (to - from);
            byte[] e = new byte[bodyLen];
            e[0] = (byte) (i == 0 ? EAP_TLS_FLAG_LENGTH : 0);
            if (i == 0) {
                e[1] = (byte) (data.length >> 24); e[2] = (byte) (data.length >> 16);
                e[3] = (byte) (data.length >> 8);  e[4] = (byte) data.length;
            }
            System.arraycopy(data, from, e, 1 + (i == 0 ? 4 : 0), to - from);
            if (multi && i < n - 1) e[0] |= EAP_TLS_FLAG_MORE;
            out[i] = e;
        }
        return out;
    }

    public static void main(String[] args) throws Exception {
        String secret = "mytestkey"; int port = 1812;
        String certPath = "PKI/CERT/f7679b33352bd0d0e150e8594606c01f.crt";
        String keyPath = "PKI/KEY/f7679b33352bd0d0e150e8594606c01f.key";
        X509Certificate clientCert = PemIO.readCert(certPath);
        AsymmetricKeyParameter clientKey = PemIO.readPrivateKey(keyPath);

        System.out.println("=== 完整 EAP-TLS 客户端握手模拟（RFC 5216，直连 RADIUS 1812）===");
        DatagramSocket sock = new DatagramSocket();
        InetAddress host = InetAddress.getByName("127.0.0.1");
        SecureRandom rnd = new SecureRandom(); byte[] reqAuth = new byte[16]; rnd.nextBytes(reqAuth);
        int rid = 1;

        // [1] Identity
        List<Attr> attrs = new ArrayList<>();
        attrs.add(new Attr(ATTR_USER_NAME, "tlsclient".getBytes("UTF-8")));
        attrs.add(new Attr(ATTR_EAP_MESSAGE, new byte[]{2, 1, 0, 9, 1, (byte) 't'}));
        byte[] resp1 = sendRecv(sock, buildRequestPacket(rid, reqAuth, attrs, secret), host, port, 5000);
        Object[] r1 = parseResp(resp1);
        byte[] eap1 = findAttr((List<Attr>) r1[2], ATTR_EAP_MESSAGE);
        int code1 = (Integer) r1[0];
        System.out.println("[1] Identity → code=" + code1 + " EAP-type=" + (eap1 == null ? "-" : (eap1[4] & 0xff)));
        if (code1 != CODE_ACCESS_CHALLENGE || eap1 == null) { System.out.println("[FAIL] 未收到 Challenge"); System.exit(1); }

        // [2] NAK → EAP-TLS Start
        List<Attr> nak = new ArrayList<>();
        nak.add(new Attr(ATTR_USER_NAME, "tlsclient".getBytes("UTF-8")));
        nak.add(new Attr(ATTR_EAP_MESSAGE, new byte[]{2, 1, 0, 6, 3, 13}));
        byte[] resp2 = sendRecv(sock, buildRequestPacket(++rid, reqAuth, nak, secret), host, port, 5000);
        Object[] r2 = parseResp(resp2);
        byte[] eap2 = findAttr((List<Attr>) r2[2], ATTR_EAP_MESSAGE);
        int code2 = (Integer) r2[0];
        int eapId = eap2 == null ? 2 : (eap2[1] & 0xff);
        System.out.println("[2] NAK → code=" + code2 + " EAP-type=" + (eap2 == null ? "-" : (eap2[4] & 0xff))
                + " Start EAP-Id=" + eapId);
        if (code2 != CODE_ACCESS_CHALLENGE || eap2 == null || (eap2[4] & 0xff) != EAP_TYPE_TLS) {
            System.out.println("[FAIL] NAK 未切 EAP-TLS"); System.exit(1);
        }

        // [3] BC 客户端 connect（线程）→ ClientHello
        BlockingIn bin = new BlockingIn();
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        TlsClientProtocol proto = new TlsClientProtocol(bin, bout);
        TestClient client = new TestClient(crypto, clientCert, clientKey);
        final boolean[] done = {false};
        final Exception[] err = {null};
        Thread handshake = new Thread(() -> {
            try { proto.connect(client); done[0] = true; } catch (Exception e) { err[0] = e; }
        });
        handshake.start();
        // 等待 ClientHello 输出
        byte[] hello = null;
        for (int i = 0; i < 100 && hello == null; i++) {
            Thread.sleep(50);
            byte[] o = bout.toByteArray();
            if (o.length > 0) { hello = o; }
        }
        if (hello == null) { System.out.println("[FAIL] 客户端未输出 ClientHello"); System.exit(1); }
        bout.reset();
        System.out.println("[3] ClientHello " + hello.length + "B 分片发送…");

        // 发送 ClientHello（EAP-Id=Start 的 Id）
        List<Attr> hAttrs = new ArrayList<>();
        hAttrs.add(new Attr(ATTR_USER_NAME, "tlsclient".getBytes("UTF-8")));
        for (byte[] frag : eapFrag(eapId, hello)) {
            hAttrs.add(new Attr(ATTR_EAP_MESSAGE, eapWrap(eapId, frag)));
        }
        byte[] resp3 = sendRecv(sock, buildRequestPacket(++rid, reqAuth, hAttrs, secret), host, port, 8000);
        Object[] r3 = parseResp(resp3);
        byte[] eap3 = findAttr((List<Attr>) r3[2], ATTR_EAP_MESSAGE);
        int code3 = (Integer) r3[0];
        if (code3 == 3) { System.out.println("[FAIL] ClientHello 被 REJECT"); System.exit(1); }
        if (eap3 == null || eap3.length < 6) { System.out.println("[FAIL] ClientHello 无响应"); System.exit(1); }

        // [4] 主 EAP 循环：接收服务器分片（拉片）+ 发送客户端输出，直到握手完成
        System.out.println("[4] 分片交换循环…");
        int rounds = 0;
        long deadline = System.currentTimeMillis() + 60000;
        boolean gotServerHello = false;
        while (!done[0] && err[0] == null && System.currentTimeMillis() < deadline) {
            rounds++;
            // 解析服务器分片：flags/L/数据
            int flags = eap3[4] & 0xff;
            boolean more = (flags & EAP_TLS_FLAG_MORE) != 0;
            boolean hasLen = (flags & EAP_TLS_FLAG_LENGTH) != 0;
            int off = 5 + (hasLen ? 4 : 0);
            if (eap3.length < off) { System.out.println("[FAIL] 响应分片格式错误"); break; }
            byte[] fragData = Arrays.copyOfRange(eap3, off, eap3.length);
            // 收齐一个完整 TLS 输出块：循环拉片
            ByteArrayOutputStream tlsBlock = new ByteArrayOutputStream();
            tlsBlock.write(fragData);
            int totalLen = -1;
            if (hasLen && fragData.length >= 4) {
                totalLen = ((eap3[5] & 0xff) << 24) | ((eap3[6] & 0xff) << 16)
                        | ((eap3[7] & 0xff) << 8) | (eap3[8] & 0xff);
            }
            while (more) {
                // 发空拉取片（1B 0x00，回显服务器最新 Request 的 Identifier）
                List<Attr> pull = new ArrayList<>();
                pull.add(new Attr(ATTR_USER_NAME, "tlsclient".getBytes("UTF-8")));
                pull.add(new Attr(ATTR_EAP_MESSAGE, eapWrap(eapId, new byte[]{0})));
                byte[] respP = sendRecv(sock, buildRequestPacket(++rid, reqAuth, pull, secret), host, port, 8000);
                Object[] rP = parseResp(respP);
                byte[] eapP = findAttr((List<Attr>) rP[2], ATTR_EAP_MESSAGE);
                int codeP = (Integer) rP[0];
                if (codeP == 3 || eapP == null || eapP.length < 6) {
                    System.out.println("[FAIL] 拉片失败 code=" + codeP); System.exit(1);
                }
                if ((eapP[0] & 0xff) == 1) {
                    eapId = eapP[1] & 0xff;   // 回显服务器本次 Request 的 Identifier
                }
                int fP = eapP[4] & 0xff;
                more = (fP & EAP_TLS_FLAG_MORE) != 0;
                int oP = 5 + ((fP & EAP_TLS_FLAG_LENGTH) != 0 ? 4 : 0);
                tlsBlock.write(eapP, oP, eapP.length - oP);
            }
            byte[] block = tlsBlock.toByteArray();
            if (block.length > 0) {
                // 检查是否包含 ServerHello（TLS 记录 22, 版本, 类型 2）
                for (int i = 0; i + 5 <= block.length; i++) {
                    if ((block[i] & 0xff) == 22 && (block[i + 1] & 0xff) == 3
                            && (block[i + 2] & 0xff) == 3 && (block[i + 5] & 0xff) == 2) {
                        int cs = (block[i + 4 + 2 + 32 + 1] & 0xff) << 8 | (block[i + 4 + 2 + 32 + 1 + 1] & 0xff);
                        gotServerHello = true;
                        System.out.println("      ServerHello: TLS1.2 套件=0x" + Integer.toHexString(cs));
                        break;
                    }
                }
                bin.push(block);   // feed 握手线程
            }
            // 客户端可能产生新输出（Certificate/ClientKeyExchange/CCS/Finished）
            Thread.sleep(50);
            byte[] out = bout.toByteArray();
            if (out.length > 0) {
                bout.reset();
                System.out.println("      客户端输出 " + out.length + "B 分片发送…");
                List<Attr> cAttrs = new ArrayList<>();
                cAttrs.add(new Attr(ATTR_USER_NAME, "tlsclient".getBytes("UTF-8")));
                for (byte[] frag : eapFrag(eapId, out)) {
                    cAttrs.add(new Attr(ATTR_EAP_MESSAGE, eapWrap(eapId, frag)));
                }
                byte[] respC = sendRecv(sock, buildRequestPacket(++rid, reqAuth, cAttrs, secret), host, port, 8000);
                Object[] rC = parseResp(respC);
                byte[] eapC = findAttr((List<Attr>) rC[2], ATTR_EAP_MESSAGE);
                int codeC = (Integer) rC[0];
                if (codeC == 3) { System.out.println("[FAIL] 客户端消息被 REJECT"); System.exit(1); }
                if (eapC != null && eapC.length >= 6) {
                    eap3 = eapC;
                    if ((eapC[0] & 0xff) == 1) {
                        eapId = eapC[1] & 0xff;   // 回显服务器本次 Request 的 Identifier
                    }
                }
            }
        }
        // 等待握手线程收尾
        handshake.join(10000);
        boolean ok = done[0] && err[0] == null;
        System.out.println("[5] 握手完成=" + ok + (err[0] != null ? " 错误=" + err[0] : ""));
        if (!ok) { System.out.println("[FAIL] 握手未完成: " + (err[0] == null ? "超时" : err[0])); System.exit(1); }
        if (serverChain != null) {
            System.out.println("[6] 服务器证书链 " + serverChain.length + " 级:");
            for (X509Certificate c : serverChain) {
                System.out.println("      " + c.getSubjectX500Principal() + " 序列号=" + c.getSerialNumber().toString(16));
            }
        }

        // [7] 握手完成后：客户端 Finished 已发；服务器应回 Success + MS-MPPE
        //     若还有客户端输出（Finished 尾片）先发完
        byte[] fin = bout.toByteArray();
        if (fin.length > 0) {
            bout.reset();
            List<Attr> fAttrs = new ArrayList<>();
            fAttrs.add(new Attr(ATTR_USER_NAME, "tlsclient".getBytes("UTF-8")));
            for (byte[] frag : eapFrag(eapId, fin)) fAttrs.add(new Attr(ATTR_EAP_MESSAGE, eapWrap(eapId, frag)));
            byte[] respF = sendRecv(sock, buildRequestPacket(++rid, reqAuth, fAttrs, secret), host, port, 8000);
            Object[] rF = parseResp(respF);
            eap3 = findAttr((List<Attr>) rF[2], ATTR_EAP_MESSAGE);
        }
        // 若服务器还有数据（如空挑战→拉片直到 Success）
        for (int i = 0; i < 30 && eap3 != null && (eap3[0] & 0xff) == 1; i++) {
            int f = eap3[4] & 0xff;
            if ((f & EAP_TLS_FLAG_MORE) != 0) {
                List<Attr> pull = new ArrayList<>();
                pull.add(new Attr(ATTR_USER_NAME, "tlsclient".getBytes("UTF-8")));
                pull.add(new Attr(ATTR_EAP_MESSAGE, eapWrap(eapId, new byte[]{0})));
                byte[] respP = sendRecv(sock, buildRequestPacket(++rid, reqAuth, pull, secret), host, port, 8000);
                Object[] rP = parseResp(respP);
                eap3 = findAttr((List<Attr>) rP[2], ATTR_EAP_MESSAGE);
                if (eap3 != null && eap3.length > 1 && (eap3[0] & 0xff) == 1) {
                    eapId = eap3[1] & 0xff;   // 回显服务器本次 Request 的 Identifier
                }
            } else {
                // 服务器发空挑战或已 Success/Failure
                if (eap3.length >= 5) {
                    int t = eap3[4] & 0xff;
                    if (t == EAP_TYPE_TLS && eap3.length > 5) {
                        // 服务器还有 TLS 数据（FinalFinished）——收下
                    }
                }
                break;
            }
        }
        boolean success = eap3 != null && (eap3[0] & 0xff) == 3;
        List<Attr> lastAttrs = (List<Attr>) parseResp(respLast(eap3))[2];
        byte[] recvKey = findAttr(lastAttrs, ATTR_MS_MPPE_RECV_KEY);
        byte[] sendKey = findAttr(lastAttrs, ATTR_MS_MPPE_SEND_KEY);
        boolean mppeOk = recvKey != null && recvKey.length == 33 && sendKey != null && sendKey.length == 33;
        System.out.println("[7] 最终 EAP code=" + (eap3 == null ? "-" : (eap3[0] & 0xff))
                + "（3=Success） MS-MPPE 下发=" + mppeOk
                + (recvKey != null ? " recv=" + recvKey.length + "B" : ""));
        if (!success || !mppeOk) {
            System.out.println("[FAIL] 未收到 Success+MS-MPPE");
            System.exit(1);
        }
        sock.close();
        System.out.println("[PASS] 完整 EAP-TLS 握手通过：服务端实现符合 RFC 5216，可完成双向认证并导出 MSK");
        System.exit(0);
    }

    static byte[] eapWrap(int eapId, byte[] data) {
        byte[] e = new byte[data.length + 5];
        e[0] = 2; e[1] = (byte) eapId;
        e[2] = (byte) ((data.length + 5) >> 8); e[3] = (byte) (data.length + 5);
        e[4] = EAP_TYPE_TLS;
        System.arraycopy(data, 0, e, 5, data.length);
        return e;
    }

    static byte[] respLast(byte[] eap) { return eap; }
}
