import java.net.*;
import java.util.*;
import java.security.*;
import java.security.cert.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.sec.SECNamedCurves;

/**
 * EAP-TLS ServerKeyExchange 签名 OpenSSL 兼容性验证。
 * 用手机原始 ClientHello 直连本地 RADIUS，重组 TLS 握手，
 * 用 SunJCE SHA256withRSA（与 OpenSSL 同为严格 PKCS#1 v1.5 验证）
 * 验证 ECDHE_RSA 的 ServerKeyExchange 签名。
 * PASS => strongSwan OpenSSL 应能通过；FAIL => 定位到具体原因。
 */
public class SKEVerify {
    static final int CODE_ACCESS_REQUEST = 1, CODE_ACCESS_CHALLENGE = 11;
    static final int ATTR_USER_NAME = 1, ATTR_EAP_MESSAGE = 79, ATTR_MESSAGE_AUTHENTICATOR = 80;
    static final int EAP_CODE_RESPONSE = 2, EAP_TYPE_IDENTITY = 1, EAP_TYPE_NAK = 3, EAP_TYPE_TLS = 13;
    // RFC 5216 EAP-TLS flags
    static final int FLAG_LENGTH_INCLUDED = 0x80, FLAG_MORE_FRAGMENTS = 0x40, FLAG_START = 0x20;

    static final class Attr { int type; byte[] value; Attr(int t, byte[] v) { type = t; value = v; } }

    static byte[] md5(byte[] d) throws Exception { return MessageDigest.getInstance("MD5").digest(d); }
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
    static byte[] eapPacket(int code, int id, int type, byte[] data) throws Exception {
        int len = 5 + (data == null ? 0 : data.length);
        byte[] out = new byte[len]; out[0] = (byte) code; out[1] = (byte) id;
        out[2] = (byte) (len >> 8); out[3] = (byte) len; out[4] = (byte) type;
        if (data != null) System.arraycopy(data, 0, out, 5, data.length);
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
    static byte[] sendRecv(DatagramSocket sock, byte[] req, InetAddress host, int port, int timeoutMs) throws Exception {
        sock.send(new DatagramPacket(req, req.length, host, port)); sock.setSoTimeout(timeoutMs);
        byte[] buf = new byte[65535]; DatagramPacket p = new DatagramPacket(buf, buf.length);
        sock.receive(p); return Arrays.copyOf(p.getData(), p.getLength());
    }
    static byte[] findAttr(List<Attr> attrs, int type) {
        for (Attr a : attrs) if (a.type == type) return a.value; return null;
    }
    static String hex(byte[] b, int max) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length && i < max; i++) { if (i > 0 && i % 32 == 0) sb.append('\n'); sb.append(String.format("%02x", b[i] & 0xff)); }
        if (b.length > max) sb.append("...(+").append(b.length - max).append("B)");
        return sb.toString();
    }
    static byte[] hexToBytes(String s) {
        s = s.replaceAll("\\s", ""); byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
    static byte[] concat(byte[]... a) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream(); for (byte[] x : a) b.write(x); return b.toByteArray();
    }
    static byte[] readNB(byte[] b, int[] off, int n) {
        byte[] o = Arrays.copyOfRange(b, off[0], off[0] + n); off[0] += n; return o;
    }
    static int readInt(byte[] b, int[] off, int n) {
        int v = 0; for (int i = 0; i < n; i++) v = (v << 8) | (b[off[0]++] & 0xff); return v;
    }

    /** 从 EAP 分片流重组完整 TLS record。每个分片：EAP头(5B) + flags(1B) + [len(4B if L)] + payload。 */
    static byte[] reassemble(List<byte[]> fragments) {
        ByteArrayOutputStream all = new ByteArrayOutputStream();
        for (byte[] f : fragments) {
            int off = 6; // EAP code/id/len/type 头(5B) + flags(1B)
            int flags = f[5] & 0xff;
            if ((flags & FLAG_LENGTH_INCLUDED) != 0) off += 4;
            all.write(f, off, f.length - off);
        }
        return all.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        String secret = "mytestkey"; int port = 1812;
        byte[] idEap = hexToBytes("0200005b0130541311301106035504070c0a6e6577657220796f726b31163014060355040a0c0d4368696e6120495420426f79733111300f060355040b0c08495420436c7562733112301006035504030c0976706e2e6c6f63616c");
        byte[] nakEap = hexToBytes("02010006030d");
        byte[] helloEap = hexToBytes("020200e20d80000000d816030300d3010000cf03036aca475423be48c6942a2b0cfc56053db8ddb51cdd2d5593523807c256a0d645000048c02cc024c00ac02bc023c009c030c028c014c02fc027c013009f006b003900c40088009e0067003300be0045009d003d0035009c003c002f00c0008400ba0041c006c010003b00020100005e000a0010000e00170018001900150013001d001e000b00020100000d001e001c040305030603080708080804080508060809080a080b0401050106010032001e001c040305030603080708080804080508060809080a080b040105010601");
        // 手机 ClientHello 中 client_random（TLS 层：EAP头5B + flags1B + len4B + TLS record头5B + handshake头4B + legacy_version2B 之后）
        byte[] clientRandom = Arrays.copyOfRange(helloEap, 5 + 1 + 4 + 5 + 4 + 2, 5 + 1 + 4 + 5 + 4 + 2 + 32);

        System.out.println("=== EAP-TLS SKE 签名 OpenSSL 兼容性验证（SunJCE 严格 PKCS#1）===");
        DatagramSocket sock = new DatagramSocket();
        InetAddress host = InetAddress.getByName("127.0.0.1");
        SecureRandom rnd = new SecureRandom(); byte[] reqAuth = new byte[16]; rnd.nextBytes(reqAuth);
        int id = 1;

        // [1] Identity
        List<Attr> attrs = new ArrayList<>();
        attrs.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
        attrs.add(new Attr(ATTR_EAP_MESSAGE, idEap));
        byte[] req1 = buildRequestPacket(id, reqAuth, attrs, secret);
        sendRecv(sock, req1, host, port, 5000);

        // [2] NAK -> TLS
        List<Attr> nakAttrs = new ArrayList<>();
        nakAttrs.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
        nakAttrs.add(new Attr(ATTR_EAP_MESSAGE, nakEap));
        byte[] nakReq = buildRequestPacket(++id, reqAuth, nakAttrs, secret);
        sendRecv(sock, nakReq, host, port, 5000);

        // [3] ClientHello -> 收集服务端 TLS 分片直到重组出完整握手（ServerHelloDone）
        List<Attr> hAttrs = new ArrayList<>();
        hAttrs.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
        hAttrs.add(new Attr(ATTR_EAP_MESSAGE, helloEap));
        byte[] hReq = buildRequestPacket(++id, reqAuth, hAttrs, secret);
        byte[] resp3 = sendRecv(sock, hReq, host, port, 8000);
        Object[] r3 = parseResp(resp3);
        byte[] eap3 = findAttr((List<Attr>) r3[2], ATTR_EAP_MESSAGE);

        if (eap3 == null || (eap3[4] & 0xff) != EAP_TYPE_TLS) {
            System.out.println("FAIL: 未收到 EAP-TLS 响应 code=" + r3[0]);
            return;
        }
        List<byte[]> fragments = new ArrayList<>();
        fragments.add(eap3);
        int flags0 = eap3[5] & 0xff;
        int guard = 0;
        while ((flags0 & FLAG_MORE_FRAGMENTS) != 0 && guard++ < 60) {
            List<Attr> fa = new ArrayList<>();
            fa.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
            fa.add(new Attr(ATTR_EAP_MESSAGE, eapPacket(2, eap3[1] & 0xff, EAP_TYPE_TLS, new byte[]{0x00}))); // ACK 空分片
            byte[] ack = buildRequestPacket(++id, reqAuth, fa, secret);
            byte[] rn = sendRecv(sock, ack, host, port, 8000);
            Object[] rr = parseResp(rn);
            byte[] en = findAttr((List<Attr>) rr[2], ATTR_EAP_MESSAGE);
            if (en == null || (en[4] & 0xff) != EAP_TYPE_TLS) { System.out.println("FAIL: 分片中断"); return; }
            fragments.add(en);
            flags0 = en[5] & 0xff;
        }
        byte[] tls = reassemble(fragments);
        System.out.println("重组 TLS 数据 " + tls.length + "B, 分片数=" + fragments.size());
        for (int fi = 0; fi < fragments.size(); fi++) {
            byte[] f = fragments.get(fi);
            System.out.println("  分片[" + fi + "] flags=0x" + String.format("%02x", f[0] & 0xff)
                    + " len=" + f.length + " 首16B=" + hex(f, 16));
        }

        // 解析 TLS records -> 握手消息
        int off = 0;
        byte[] serverRandom = null;
        byte[] skeBody = null;
        byte[] skeSig = null;
        byte[] serverCert = null;
        boolean gotDone = false;
        while (off + 5 <= tls.length && !gotDone) {
            int type = tls[off] & 0xff, verH = tls[off + 1] & 0xff, verL = tls[off + 2] & 0xff;
            int len = ((tls[off + 3] & 0xff) << 8) | (tls[off + 4] & 0xff);
            if (off + 5 + len > tls.length) { System.out.println("FAIL: TLS record 截断"); return; }
            byte[] body = Arrays.copyOfRange(tls, off + 5, off + 5 + len);
            off += 5 + len;
            if (type != 22) { System.out.println("skip record type=" + type); continue; }
            int p = 0;
            while (p + 4 <= body.length) {
                int mtype = body[p] & 0xff;
                int mlen = ((body[p + 1] & 0xff) << 16) | ((body[p + 2] & 0xff) << 8) | (body[p + 3] & 0xff);
                if (p + 4 + mlen > body.length) { System.out.println("FAIL: 握手消息截断"); return; }
                byte[] m = Arrays.copyOfRange(body, p + 4, p + 4 + mlen);
                p += 4 + mlen;
                if (mtype == 2) { // ServerHello
                    serverRandom = Arrays.copyOfRange(m, 2, 34);
                    System.out.println("ServerHello random=" + hex(serverRandom, 8));
                } else if (mtype == 11) { // Certificate
                    int cl = ((m[0] & 0xff) << 16) | ((m[1] & 0xff) << 8) | (m[2] & 0xff);
                    int c0 = 3;
                    int clen = ((m[c0] & 0xff) << 16) | ((m[c0 + 1] & 0xff) << 8) | (m[c0 + 2] & 0xff);
                    serverCert = Arrays.copyOfRange(m, c0 + 3, c0 + 3 + clen);
                    System.out.println("Certificate 链条数=1 证书=" + clen + "B");
                } else if (mtype == 12) { // ServerKeyExchange
                    skeBody = m;
                    System.out.println("ServerKeyExchange " + m.length + "B");
                } else if (mtype == 14) {
                    gotDone = true;
                    System.out.println("ServerHelloDone");
                }
            }
        }
        if (skeBody == null || serverRandom == null || serverCert == null) {
            System.out.println("FAIL: 未解析到 ServerKeyExchange/ServerHello/证书");
            return;
        }

        // 解析 SKE（ECDHE_RSA TLS1.2）：curve_type(1) named_curve(2) pubkey_len(1) pubkey sigalg(2) siglen(2) sig
        int sp = 0;
        int curveType = skeBody[sp++] & 0xff;
        int namedCurve = ((skeBody[sp] & 0xff) << 8) | (skeBody[sp + 1] & 0xff); sp += 2;
        int pkLen = skeBody[sp++] & 0xff;
        byte[] pubkey = Arrays.copyOfRange(skeBody, sp, sp + pkLen); sp += pkLen;
        int sigAlg = ((skeBody[sp] & 0xff) << 8) | (skeBody[sp + 1] & 0xff); sp += 2;
        int sigLen = ((skeBody[sp] & 0xff) << 8) | (skeBody[sp + 1] & 0xff); sp += 2;
        byte[] sig = Arrays.copyOfRange(skeBody, sp, sp + sigLen);
        System.out.println("SKE: curveType=" + curveType + " namedCurve=" + String.format("0x%04x", namedCurve)
                + " sigAlg=" + String.format("0x%04x", sigAlg) + " sigLen=" + sigLen);

        // 证书公钥
        Certificate bcCert = Certificate.getInstance(serverCert);
        byte[] spkiDer = bcCert.getSubjectPublicKeyInfo().getEncoded();
        String algoName = bcCert.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId();
        System.out.println("证书公钥算法=" + algoName);
        java.security.spec.X509EncodedKeySpec xks = new java.security.spec.X509EncodedKeySpec(spkiDer);
        PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(xks);

        // hashInput = client_random + server_random + SKE_params（ECParameters+ECPoint，不含 sig_alg 与签名）
        byte[] skeParams = Arrays.copyOfRange(skeBody, 0, skeBody.length - 2 - sigLen - 2);
        byte[] hashInput = concat(clientRandom, serverRandom, skeParams);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(hashInput);
        System.out.println("client_random=" + hex(clientRandom, 32));
        System.out.println("server_random=" + hex(serverRandom, 32));
        System.out.println("skeParams=" + hex(skeParams, 96));
        // 输出 openssl 验证所需文件
        java.nio.file.Files.write(java.nio.file.Paths.get("tmp", "ske_hash_input.bin"), hashInput);
        java.nio.file.Files.write(java.nio.file.Paths.get("tmp", "ske_sig.bin"), sig);
        java.nio.file.Files.write(java.nio.file.Paths.get("tmp", "ske_pub.der"),
                bcCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
        System.out.println("已写出 tmp/ske_hash_input.bin, tmp/ske_sig.bin, tmp/ske_pub.der");

        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(pub);
        s.update(hashInput);   // 原始数据（内部做 SHA-256）
        boolean ok = s.verify(sig);
        System.out.println("SunJCE 严格验证 ECDHE_RSA SKE 签名: " + (ok ? "PASS ✅（OpenSSL 应可验证）" : "FAIL ❌"));
        if (!ok) {
            System.out.println("  hashInput=" + hashInput.length + "B hash=" + hex(hash, 8));
            System.out.println("  sig=" + hex(sig, 16));
        }
        sock.close();
    }
}
