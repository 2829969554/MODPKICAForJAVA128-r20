import java.net.*;
import java.util.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** 干净的单会话 TLS1.3 ClientHello 测试：Identity→NAK→432B TLS1.3 ClientHello→收完整 flight。 */
public class Tls13CleanTest {
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
    static String hex(byte[] b, int from, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len && from + i < b.length; i++) {
            if (i > 0 && i % 32 == 0) sb.append("\n      ");
            sb.append(String.format("%02x", b[from + i] & 0xff));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        String secret = "mytestkey"; int port = 1812;
        InetAddress host = InetAddress.getByName("127.0.0.1");
        byte[] reqAuth = new byte[16]; new SecureRandom().nextBytes(reqAuth);
        int rid = 1;

        // [1] Identity
        DatagramSocket sock = new DatagramSocket();
        List<Attr> a = new ArrayList<>();
        a.add(new Attr(ATTR_USER_NAME, "admin666".getBytes("UTF-8")));
        a.add(new Attr(ATTR_EAP_MESSAGE, hexToBytes("0200000d0161646d696e363636")));
        Object[] p1 = parseResp(sendRecv(sock, buildRequestPacket(rid, reqAuth, a, secret), host, port, 5000));
        System.out.println("[1] Identity -> code=" + p1[0]);

        // [2] NAK → EAP-TLS
        List<Attr> n = new ArrayList<>();
        n.add(new Attr(ATTR_USER_NAME, "admin666".getBytes("UTF-8")));
        n.add(new Attr(ATTR_EAP_MESSAGE, hexToBytes("02010006030d")));
        Object[] p2 = parseResp(sendRecv(sock, buildRequestPacket(++rid, reqAuth, n, secret), host, port, 5000));
        byte[] e2 = findAttr((List<Attr>) p2[2], ATTR_EAP_MESSAGE);
        System.out.println("[2] NAK -> code=" + p2[0] + " EAP-Message(" + (e2 == null ? 0 : e2.length) + "B)="
                + (e2 == null ? "-" : hex(e2, 0, e2.length)));

        // [3] 432B TLS1.3 ClientHello（iOS/Win11 实机抓包）
        byte[] hello = hexToBytes("020201b50d80000001ab16030101a6010001a2030323302ac739c8d74f56477039d5ff7d20a6fe49636a512f1687d4644af7afca85201b490247b2b851eaa7f8b71560ed3d6a91afb967adf2024c7e6b65fa1333fd07002813021301c02cc02bc030c02fc024c023c028c027c00ac009c014c013009d009c003d003c0035002f01000131000500050100000000002b0009080304030303020301000d001a001808040805080604010501020104030503020302020601060300230000000a00080006001d00170018000b00020100003300d000ce001d00203d332b4f8d199e2e3f4d79a0a07b86750fd4ba092fcfee1e7c6fc24b5913a85300170041041bd65262876a525caa7d2507e5acdf7fd9ad98e222f6e0accd4ad0b195224b55f5743bf51ba3ea786c6d07953e614325ba53e78ce41022819c34e5dbb6b18194001800610454133ae831ffa3861dd2fbdfa026a597b2313c920b124704068dd1eced8e41c3356de09076569012ca9359b2aa2bbc530671eec681883fd50b52161f0e873c8c5e51e0bc7d17a603a1243913bb85d87f3e23af70732afc47497b72091dd8b01f0031000000170000ff01000100002d00020101");
        List<Attr> h = new ArrayList<>();
        h.add(new Attr(ATTR_USER_NAME, "admin666".getBytes("UTF-8")));
        for (int off = 0; off < hello.length; off += 253) {
            h.add(new Attr(ATTR_EAP_MESSAGE, Arrays.copyOfRange(hello, off, Math.min(hello.length, off + 253))));
        }
        Object[] p3 = parseResp(sendRecv(sock, buildRequestPacket(++rid, reqAuth, h, secret), host, port, 8000));
        List<Attr> attrs3 = (List<Attr>) p3[2];
        byte[] e3 = findAttr(attrs3, ATTR_EAP_MESSAGE);
        System.out.println("[3] TLS1.3 ClientHello -> code=" + p3[0] + " EAP属性数=" + attrs3.size()
                + " EAP-len=" + (e3 == null ? 0 : e3.length));
        // 拼接所有 EAP-Message 属性 → TLS 记录流
        ByteArrayOutputStream tls = new ByteArrayOutputStream();
        for (Attr at : attrs3) {
            if (at.type == ATTR_EAP_MESSAGE) {
                int f = at.value[4] & 0xff;
                int o = 5 + ((f & 0x80) != 0 ? 4 : 0);
                tls.write(at.value, o, at.value.length - o);
            }
        }
        byte[] all = tls.toByteArray();
        System.out.println("TLS 数据总长=" + all.length);
        int tp = 0, recIdx = 0;
        while (tp + 5 <= all.length) {
            int rt = all[tp] & 0xff, rl = ((all[tp + 3] & 0xff) << 8) | (all[tp + 4] & 0xff);
            if (tp + 5 + rl > all.length) { System.out.println("记录" + recIdx + " 截断 len=" + rl); break; }
            String extra = "";
            if (rt == 22 && rl >= 4) {
                int hst = all[tp + 5] & 0xff;
                String hsName = hst == 2 ? "ServerHello" : hst == 4 ? "NewSessionTicket" : hst == 11 ? "Certificate"
                        : hst == 13 ? "CertificateRequest" : hst == 15 ? "CertificateVerify" : hst == 20 ? "Finished"
                        : "hs=" + hst;
                extra = " handshake=" + hsName + " hsLen=" + (((all[tp+6]&0xff)<<16)|((all[tp+7]&0xff)<<8)|(all[tp+8]&0xff));
            } else if (rt == 21) {
                extra = " ALERT len=" + rl + " data=" + hex(all, tp+5, rl);
            }
            System.out.println("记录" + recIdx + ": type=" + rt + " ver=0x" + String.format("%02x%02x", all[tp+1], all[tp+2])
                    + " len=" + rl + extra);
            tp += 5 + rl; recIdx++;
        }
        System.out.println("TLS 记录总数=" + recIdx);
        if (all.length > 0) System.out.println("hex前120B:\n      " + hex(all, 0, Math.min(120, all.length)));
    }
}
