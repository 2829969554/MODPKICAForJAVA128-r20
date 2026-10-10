import java.net.*;
import java.util.*;
import java.security.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * 精确复现 strongSwan 手机 EAP-TLS 失败：直接向本地 RADIUS 发送
 * 与手机完全相同的 EAP 序列（Identity DER-DN → NAK → 手机原始 ClientHello hex）。
 * 用于在无手机环境下本地迭代定位 handshake_failure(40) 根因。
 */
public class PhoneHelloRepro {
    static final int CODE_ACCESS_REQUEST = 1, CODE_ACCESS_CHALLENGE = 11;
    static final int ATTR_USER_NAME = 1, ATTR_EAP_MESSAGE = 79, ATTR_MESSAGE_AUTHENTICATOR = 80, ATTR_STATE = 24;
    static final int EAP_CODE_RESPONSE = 2, EAP_TYPE_IDENTITY = 1, EAP_TYPE_NAK = 3, EAP_TYPE_MSCHAPV2 = 26, EAP_TYPE_TLS = 13;

    static final class Attr { int type; byte[] value; Attr(int t, byte[] v) { type = t; value = v; } }

    static byte[] md5(byte[] d) throws Exception { return MessageDigest.getInstance("MD5").digest(d); }
    static byte[] hmacMd5(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacMD5"); mac.init(new SecretKeySpec(key, "HmacMD5")); return mac.doFinal(data);
    }
    static byte[] concat(byte[]... a) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream(); for (byte[] x : a) b.write(x); return b.toByteArray();
    }
    static byte[] buildRequestPacket(int id, byte[] reqAuth, List<Attr> attrs, String secret, boolean withMa) throws Exception {
        List<Attr> list = new ArrayList<>(attrs);
        int maOffset = -1;
        if (withMa) { list.add(new Attr(ATTR_MESSAGE_AUTHENTICATOR, new byte[16])); }
        int len = 20; for (Attr a : list) len += a.value.length + 2;
        byte[] out = new byte[len];
        out[0] = CODE_ACCESS_REQUEST; out[1] = (byte) id; out[2] = (byte) (len >> 8); out[3] = (byte) len;
        System.arraycopy(reqAuth, 0, out, 4, 16);
        int off = 20;
        for (Attr a : list) {
            out[off] = (byte) a.type; out[off + 1] = (byte) (a.value.length + 2);
            System.arraycopy(a.value, 0, out, off + 2, a.value.length);
            if (withMa && a.type == ATTR_MESSAGE_AUTHENTICATOR) maOffset = off;
            off += a.value.length + 2;
        }
        if (withMa && maOffset >= 0) { byte[] mac = hmacMd5(secret.getBytes("UTF-8"), out); System.arraycopy(mac, 0, out, maOffset + 2, 16); }
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

    public static void main(String[] args) throws Exception {
        String secret = "mytestkey"; int port = 1812;
        // 手机原始 EAP 序列（strongSwan 6.0.3，22:10 抓取）
        byte[] idEap = hexToBytes("0200005b0130541311301106035504070c0a6e6577657220796f726b31163014060355040a0c0d4368696e6120495420426f79733111300f060355040b0c08495420436c7562733112301006035504030c0976706e2e6c6f63616c");
        byte[] nakEap = hexToBytes("02010006030d");
        byte[] helloEap = hexToBytes("020200e20d80000000d816030300d3010000cf03036aca475423be48c6942a2b0cfc56053db8ddb51cdd2d5593523807c256a0d645000048c02cc024c00ac02bc023c009c030c028c014c02fc027c013009f006b003900c40088009e0067003300be0045009d003d0035009c003c002f00c0008400ba0041c006c010003b00020100005e000a0010000e00170018001900150013001d001e000b00020100000d001e001c040305030603080708080804080508060809080a080b0401050106010032001e001c040305030603080708080804080508060809080a080b040105010601");

        System.out.println("=== 手机原始 EAP-TLS 序列复现（直连本地 RADIUS 1812）===");
        DatagramSocket sock = new DatagramSocket();
        InetAddress host = InetAddress.getByName("127.0.0.1");
        SecureRandom rnd = new SecureRandom(); byte[] reqAuth = new byte[16]; rnd.nextBytes(reqAuth);
        int id = 1;

        // [1] Identity（手机 DER-DN 原文）
        List<Attr> attrs = new ArrayList<>();
        attrs.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
        attrs.add(new Attr(ATTR_EAP_MESSAGE, idEap));
        byte[] req1 = buildRequestPacket(id, reqAuth, attrs, secret, true);
        System.out.println("[1] 发送 Identity(" + idEap.length + "B EAP)");
        byte[] resp1 = sendRecv(sock, req1, host, port, 5000);
        Object[] r1 = parseResp(resp1);
        byte[] eap1 = findAttr((List<Attr>) r1[2], ATTR_EAP_MESSAGE);
        System.out.println("    响应 code=" + r1[0] + " EAP=" + (eap1 == null ? "null" : hex(eap1, 40)));
        int eapId = eap1 == null ? 1 : (eap1[1] & 0xff);

        // [2] NAK → EAP-TLS
        List<Attr> nakAttrs = new ArrayList<>();
        nakAttrs.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
        nakAttrs.add(new Attr(ATTR_EAP_MESSAGE, nakEap));
        byte[] nakReq = buildRequestPacket(++id, reqAuth, nakAttrs, secret, true);
        System.out.println("[2] 发送 NAK(仅EAP-TLS)");
        byte[] resp2 = sendRecv(sock, nakReq, host, port, 5000);
        Object[] r2 = parseResp(resp2);
        byte[] eap2 = findAttr((List<Attr>) r2[2], ATTR_EAP_MESSAGE);
        System.out.println("    响应 code=" + r2[0] + " EAP=" + (eap2 == null ? "null" : hex(eap2, 40)));

        // [3] 手机原始 ClientHello（含 0x0032 异常 ALPN + 0x000d 签名算法）
        List<Attr> hAttrs = new ArrayList<>();
        hAttrs.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
        hAttrs.add(new Attr(ATTR_EAP_MESSAGE, helloEap));
        byte[] hReq = buildRequestPacket(++id, reqAuth, hAttrs, secret, true);
        System.out.println("[3] 发送手机 ClientHello(" + (helloEap.length - 5) + "B TLS, flags=0x80 total=0xd8)");
        byte[] resp3 = sendRecv(sock, hReq, host, port, 8000);
        Object[] r3 = parseResp(resp3);
        byte[] eap3 = findAttr((List<Attr>) r3[2], ATTR_EAP_MESSAGE);
        System.out.println("    响应 code=" + r3[0] + " EAP-len=" + (eap3 == null ? 0 : eap3.length));
        if (eap3 != null) {
            System.out.println("    EAP hex:\n" + hex(eap3, 512));
            int t = eap3[4] & 0xff;
            System.out.println("    EAP type=" + t + (t == 4 ? " (FAILURE!)" : t == EAP_TYPE_TLS ? " (TLS 数据)" : ""));
        }
        sock.close();
        System.out.println("=== 复现完成 ===");
    }
}
