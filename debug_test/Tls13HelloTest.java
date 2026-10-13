import java.net.*;
import java.util.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** 验证 BC 服务器（仅 TLS1.2）能否正确处理 iOS 实机 432B TLS1.3 混合 ClientHello。 */
public class Tls13HelloTest {
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
    static byte[] hexToBytes(String s) {
        s = s.replaceAll("\\s", ""); byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    public static void main(String[] args) throws Exception {
        String secret = "mytestkey"; int port = 1812;
        byte[] hello432 = hexToBytes("020201b50d80000001ab16030101a6010001a2030323302ac739c8d74f56477039d5ff7d20a6fe49636a512f1687d4644af7afca85201b490247b2b851eaa7f8b71560ed3d6a91afb967adf2024c7e6b65fa1333fd07002813021301c02cc02bc030c02fc024c023c028c027c00ac009c014c013009d009c003d003c0035002f01000131000500050100000000002b0009080304030303020301000d001a001808040805080604010501020104030503020302020601060300230000000a00080006001d00170018000b00020100003300d000ce001d00203d332b4f8d199e2e3f4d79a0a07b86750fd4ba092fcfee1e7c6fc24b5913a85300170041041bd65262876a525caa7d2507e5acdf7fd9ad98e222f6e0accd4ad0b195224b55f5743bf51ba3ea786c6d07953e614325ba53e78ce41022819c34e5dbb6b18194001800610454133ae831ffa3861dd2fbdfa026a597b2313c920b124704068dd1eced8e41c3356de09076569012ca9359b2aa2bbc530671eec681883fd50b52161f0e873c8c5e51e0bc7d17a603a1243913bb85d87f3e23af70732afc47497b72091dd8b01f0031000000170000ff01000100002d00020101");
        System.out.println("=== TLS1.3 混合 ClientHello 服务端响应验证 ===");
        DatagramSocket sock = new DatagramSocket();
        InetAddress host = InetAddress.getByName("127.0.0.1");
        byte[] reqAuth = new byte[16]; new SecureRandom().nextBytes(reqAuth);
        int rid = 1;
        List<Attr> a = new ArrayList<>();
        a.add(new Attr(ATTR_USER_NAME, "admin666".getBytes("UTF-8")));
        a.add(new Attr(ATTR_EAP_MESSAGE, hexToBytes("0200000d0161646d696e363636")));
        byte[] r1 = sendRecv(sock, buildRequestPacket(rid, reqAuth, a, secret), host, port, 5000);
        Object[] p1 = parseResp(r1);
        System.out.println("[1] Identity -> code=" + p1[0]);
        List<Attr> n = new ArrayList<>();
        n.add(new Attr(ATTR_USER_NAME, "admin666".getBytes("UTF-8")));
        n.add(new Attr(ATTR_EAP_MESSAGE, hexToBytes("02010006030d")));
        byte[] r2 = sendRecv(sock, buildRequestPacket(++rid, reqAuth, n, secret), host, port, 5000);
        Object[] p2 = parseResp(r2);
        byte[] e2 = findAttr((List<Attr>) p2[2], ATTR_EAP_MESSAGE);
        System.out.println("[2] NAK -> type=" + (e2 == null ? "-" : (e2[4] & 0xff)) + " Start-Id=" + (e2 == null ? "-" : (e2[1] & 0xff)));

        // [3.5] iOS 实机 156B 纯 TLS1.2 ClientHello（13:04 风暴同款）——完整响应分析
        byte[] hello156 = hexToBytes("020200a10d800000009716030100920100008e03036acb18b61c8041e7f55d130c1d2ba0bcc3c22c605578f0f4fcd8cb9217594e1c00002c00ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d003c0035002f000a01000039000a00080006001700180019000b00020100000d00120010040102010501060104030203050306030005000501000000000012000000170000");
        List<Attr> h156 = new ArrayList<>();
        h156.add(new Attr(ATTR_USER_NAME, "admin666".getBytes("UTF-8")));
        for (int off = 0; off < hello156.length; off += 253) {
            h156.add(new Attr(ATTR_EAP_MESSAGE,
                    Arrays.copyOfRange(hello156, off, Math.min(hello156.length, off + 253))));
        }
        byte[] r156 = sendRecv(sock, buildRequestPacket(++rid, reqAuth, h156, secret), host, port, 8000);
        Object[] p156 = parseResp(r156);
        List<Attr> attrs156 = (List<Attr>) p156[2];
        byte[] e156 = findAttr(attrs156, ATTR_EAP_MESSAGE);
        System.out.println("\n=== [3.5] iOS 156B ClientHello 完整响应 ===");
        System.out.println("code=" + p156[0] + " EAP属性数=" + attrs156.size()
                + " EAP-len=" + (e156 == null ? 0 : e156.length));
        // 拼接所有 EAP-Message 属性，解析完整 TLS 记录序列
        ByteArrayOutputStream tls156 = new ByteArrayOutputStream();
        for (Attr at : attrs156) {
            if (at.type == ATTR_EAP_MESSAGE) {
                int f = at.value[4] & 0xff;
                int o = 5 + ((f & 0x80) != 0 ? 4 : 0);
                tls156.write(at.value, o, at.value.length - o);
            }
        }
        byte[] tlsAll = tls156.toByteArray();
        System.out.println("[3.5] TLS 数据总长=" + tlsAll.length);
        int tp = 0, recIdx = 0;
        while (tp + 5 <= tlsAll.length) {
            int rt = tlsAll[tp] & 0xff, rl = ((tlsAll[tp + 3] & 0xff) << 8) | (tlsAll[tp + 4] & 0xff);
            if (tp + 5 + rl > tlsAll.length) { System.out.println("[3.5] 记录" + recIdx + " 截断 len=" + rl); break; }
            String extra = "";
            if (rt == 22 && rl >= 4) {
                int hst = tlsAll[tp + 5] & 0xff;
                String hsName = hst == 2 ? "ServerHello" : hst == 11 ? "Certificate" : hst == 22 ? "CertificateStatus"
                        : hst == 12 ? "ServerKeyExchange" : hst == 13 ? "CertificateRequest" : hst == 14 ? "ServerHelloDone"
                        : hst == 15 ? "CertificateVerify" : hst == 20 ? "Finished" : "hs=" + hst;
                extra = " handshake=" + hsName;
            }
            System.out.println("[3.5] 记录" + recIdx + ": type=" + rt + " ver=0x"
                    + String.format("%02x%02x", tlsAll[tp + 1], tlsAll[tp + 2]) + " len=" + rl + extra);
            tp += 5 + rl; recIdx++;
        }
        System.out.println("[3.5] TLS 记录总数=" + recIdx);
        dumpFull("[3.5]", e156);

        List<Attr> h = new ArrayList<>();
        h.add(new Attr(ATTR_USER_NAME, "admin666".getBytes("UTF-8")));
        // RFC 3579 §2.1：EAP-Message 属性 ≤253B，超长按序拆多个属性
        for (int off = 0; off < hello432.length; off += 253) {
            h.add(new Attr(ATTR_EAP_MESSAGE,
                    Arrays.copyOfRange(hello432, off, Math.min(hello432.length, off + 253))));
        }
        byte[] r3 = sendRecv(sock, buildRequestPacket(++rid, reqAuth, h, secret), host, port, 8000);
        Object[] p3 = parseResp(r3);
        byte[] e3 = findAttr((List<Attr>) p3[2], ATTR_EAP_MESSAGE);
        int code3 = (Integer) p3[0];
        System.out.println("[3] 432B ClientHello -> code=" + code3 + " EAP-len=" + (e3 == null ? 0 : e3.length)
                + " first=" + (e3 == null ? "-" : (e3[0] & 0xff)));
        if (e3 == null || e3.length < 6) { System.out.println("[FAIL] 无响应"); System.exit(1); }
        StringBuilder sb = new StringBuilder();
        int lim = Math.min(e3.length, 200);
        for (int i = 0; i < lim; i++) { if (i > 0 && i % 32 == 0) sb.append("\n      "); sb.append(String.format("%02x", e3[i] & 0xff)); }
        System.out.println("      响应hex(前" + lim + "B):\n      " + sb);
        int f = e3[4] & 0xff;
        int o = 5 + ((f & 0x80) != 0 ? 4 : 0);
        if (e3.length > o && (e3[o] & 0xff) == 22) {
            int hsType = e3[o + 5] & 0xff;
            System.out.println("      → TLS 握手记录 handshake-type=" + hsType + "（2=ServerHello）");
            if (hsType == 2 && e3.length > o + 43) {
                int cs = ((e3[o + 40] & 0xff) << 8) | (e3[o + 41] & 0xff);
                System.out.println("      套件=0x" + Integer.toHexString(cs));
            }
            System.out.println("[PASS] 服务端正确处理 TLS1.3 混合 ClientHello 并回 ServerHello");
            System.exit(0);
        } else if (code3 == 3 || (e3[0] & 0xff) == 4) {
            System.out.println("[FAIL] 服务端拒绝：code=" + code3 + " EAP=" + (e3[0] & 0xff));
            System.exit(1);
        } else {
            System.out.println("[INFO] 非 ServerHello 响应，人工判断（可能是分片或异常）");
            System.exit(2);
        }
    }

    /** 完整打印 EAP-Request/TLS 响应的分片信息 + ServerHello 扩展列表（用于 iOS 兼容分析）。 */
    static void dumpFull(String tag, byte[] eap) {
        if (eap == null || eap.length < 5) { System.out.println(tag + " 无 EAP 数据"); return; }
        int flags = eap[4] & 0xff;
        StringBuilder hdr = new StringBuilder(tag + " EAP头: code=" + (eap[0] & 0xff) + " id=" + (eap[1] & 0xff)
                + " len=" + eap.length + " type=" + (eap[3] & 0xff) + " flags=0x" + String.format("%02x", flags));
        int off = 5;
        if ((flags & 0x80) != 0 && eap.length >= 9) {
            long total = ((long)(eap[5] & 0xff) << 24) | ((eap[6] & 0xff) << 16) | ((eap[7] & 0xff) << 8) | (eap[8] & 0xff);
            hdr.append(" total=" + total); off = 9;
        }
        System.out.println(hdr + " 数据=" + (eap.length - off) + "B");
        // TLS 记录头
        if (eap.length > off + 5) {
            int recType = eap[off] & 0xff, ver = ((eap[off + 1] & 0xff) << 8) | (eap[off + 2] & 0xff);
            int recLen = ((eap[off + 3] & 0xff) << 8) | (eap[off + 4] & 0xff);
            System.out.println(tag + " TLS记录: type=" + recType + " ver=0x" + String.format("%04x", ver) + " len=" + recLen);
            if (recType == 22 && eap.length > off + 9) {
                int hsType = eap[off + 5] & 0xff;
                int hsLen = ((eap[off + 6] & 0xff) << 16) | ((eap[off + 7] & 0xff) << 8) | (eap[off + 8] & 0xff);
                System.out.println(tag + " 握手: type=" + hsType + " len=" + hsLen);
                if (hsType == 2) { // ServerHello
                    int p = off + 9;
                    int sessLen = eap[p + 34] & 0xff; p += 35 + sessLen;
                    int cs = ((eap[p] & 0xff) << 8) | (eap[p + 1] & 0xff); p += 2;
                    int comp = eap[p] & 0xff; p += 1;
                    int extLen = ((eap[p] & 0xff) << 8) | (eap[p + 1] & 0xff); p += 2;
                    System.out.println(tag + " ServerHello: 套件=0x" + String.format("%04x", cs)
                            + " compression=" + comp + " 扩展总长=" + extLen);
                    int end = p + extLen;
                    while (p + 4 <= end) {
                        int et = ((eap[p] & 0xff) << 8) | (eap[p + 1] & 0xff);
                        int el = ((eap[p + 2] & 0xff) << 8) | (eap[p + 3] & 0xff);
                        System.out.println(tag + "   扩展 type=0x" + String.format("%04x", et) + " len=" + el
                                + (el > 0 ? " data=" + hex(eap, p + 4, Math.min(el, 24)) : ""));
                        p += 4 + el;
                    }
                    if (p != end) System.out.println(tag + "   [WARN] 扩展解析偏移=" + (p - end));
                }
            }
        }
        System.out.println(tag + " 完整hex(" + eap.length + "B):\n      " + hex(eap, 0, eap.length));
    }

    static String hex(byte[] b, int from, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len && from + i < b.length; i++) {
            if (i > 0 && i % 32 == 0) sb.append("\n      ");
            sb.append(String.format("%02x", b[from + i] & 0xff));
        }
        return sb.toString();
    }
}
