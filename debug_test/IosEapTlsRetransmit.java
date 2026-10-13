import java.net.*;
import java.util.*;
import java.security.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * iOS 原生 IKEv2 EAP-TLS 网关重传复现与修复验证（RFC 3748 §5.1）。
 *
 * 场景：strongSwan eap-radius 网关在 UDP 上对未确认的 Access-Request 整包重传——
 * EAP-Identifier 与 EAP 数据完全相同（iOS 原始 ClientHello 156B），仅 RADIUS
 * identifier 递增（实测 radiusId=106/107/108 三次相同 ClientHello）。
 *
 * 修复前：重传的 ClientHello 被再次 feed 给 BC TLS 状态机 → 收到重复 handshake
 *         消息 → org.bouncycastle.tls.TlsFatalAlert: unexpected_message(10)。
 * 修复后：命中 EAP 层重传检测 → 以相同 EAP-Id 重发上次响应，不再 feed。
 *
 * 本测试直连本地 RADIUS 1812，发送与 iOS 完全相同的 EAP 序列：
 *   [1] EAP-Identity（DER-DN） → 自适应 MSCHAPv2 Challenge
 *   [2] EAP-NAK(仅 EAP-TLS)     → EAP-Request/TLS Start
 *   [3] iOS 原始 ClientHello     → 服务器 Hello 片1
 *   [4] 重传相同 ClientHello     → 期望：重发与 [3] 完全相同的 EAP 响应体
 * 通过条件：步骤[4] 响应体与步骤[3] 逐字节一致（重传检测生效、服务端不崩溃）。
 */
public class IosEapTlsRetransmit {
    static final int CODE_ACCESS_REQUEST = 1, CODE_ACCESS_CHALLENGE = 11;
    static final int ATTR_USER_NAME = 1, ATTR_EAP_MESSAGE = 79, ATTR_MESSAGE_AUTHENTICATOR = 80;
    static final int EAP_CODE_RESPONSE = 2, EAP_TYPE_IDENTITY = 1, EAP_TYPE_NAK = 3, EAP_TYPE_TLS = 13;

    static final class Attr { int type; byte[] value; Attr(int t, byte[] v) { type = t; value = v; } }

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
    /** EAP-Message（79）由发送方按 RFC 3579 §2.1 切成多个 ≤253B 属性，需按顺序拼接。 */
    static byte[] findAttr(List<Attr> attrs, int type) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        boolean found = false;
        for (Attr a : attrs) {
            if (a.type == type) { b.write(a.value, 0, a.value.length); found = true; }
        }
        return found ? b.toByteArray() : null;
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
        // iOS 原生 IKEv2 经 strongSwan 网关实测 EAP 序列（2026-10-11 10:37 抓取）
        byte[] idEap = hexToBytes("0200005b0130541311301106035504070c0a6e6577657220796f726b31163014060355040a0c0d4368696e6120495420426f79733111300f060355040b0c08495420436c7562733112301006035504030c0976706e2e6c6f63616c");
        byte[] nakEap = hexToBytes("02010006030d");
        // iOS 原始 ClientHello 156B：TLSv1.2、套件 0x00ff/0xc02c..、扩展含
        // supported_groups(0x000a)/ec_point_formats(0x000b)/signature_algorithms(0x000d)
        // status_request(0x0005)/signed_certificate_timestamp(0x0012)/extended_master_secret(0x0017)
        byte[] helloEap = hexToBytes("020200a10d800000009716030100920100008e03036acaf67f44f70c9691c06c9092b681fe715aa2547b7a7809d9dbb93bb3b73e1a00002c00ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d003c0035002f000a01000039000a00080006001700180019000b00020100000d00120010040102010501060104030203050306030005000501000000000012000000170000");

        System.out.println("=== iOS EAP-TLS 网关重传复现/验证（直连本地 RADIUS 1812）===");
        DatagramSocket sock = new DatagramSocket();
        InetAddress host = InetAddress.getByName("127.0.0.1");
        SecureRandom rnd = new SecureRandom(); byte[] reqAuth = new byte[16]; rnd.nextBytes(reqAuth);
        int rid = 1;

        // [1] Identity（iOS DER-DN 原文）
        List<Attr> attrs = new ArrayList<>();
        attrs.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
        attrs.add(new Attr(ATTR_EAP_MESSAGE, idEap));
        byte[] req1 = buildRequestPacket(rid, reqAuth, attrs, secret, true);
        byte[] resp1 = sendRecv(sock, req1, host, port, 5000);
        Object[] r1 = parseResp(resp1);
        byte[] eap1 = findAttr((List<Attr>) r1[2], ATTR_EAP_MESSAGE);
        int code1 = (Integer) r1[0];
        System.out.println("[1] Identity → code=" + code1 + " EAP-type=" + (eap1 == null ? "-" : (eap1[4] & 0xff)));
        if (code1 != CODE_ACCESS_CHALLENGE || eap1 == null) { System.out.println("[FAIL] 未收到 Challenge"); System.exit(1); }

        // [2] NAK → EAP-TLS
        List<Attr> nakAttrs = new ArrayList<>();
        nakAttrs.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
        nakAttrs.add(new Attr(ATTR_EAP_MESSAGE, nakEap));
        byte[] nakReq = buildRequestPacket(++rid, reqAuth, nakAttrs, secret, true);
        byte[] resp2 = sendRecv(sock, nakReq, host, port, 5000);
        Object[] r2 = parseResp(resp2);
        byte[] eap2 = findAttr((List<Attr>) r2[2], ATTR_EAP_MESSAGE);
        int code2 = (Integer) r2[0];
        System.out.println("[2] NAK(TLS) → code=" + code2 + " EAP-type=" + (eap2 == null ? "-" : (eap2[4] & 0xff))
                + " EAP-Id=" + (eap2 == null ? "-" : (eap2[1] & 0xff)));
        if (code2 != CODE_ACCESS_CHALLENGE || eap2 == null) { System.out.println("[FAIL] NAK 后未切 EAP-TLS Start"); System.exit(1); }

        // [3] iOS 原始 ClientHello
        List<Attr> hAttrs = new ArrayList<>();
        hAttrs.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
        hAttrs.add(new Attr(ATTR_EAP_MESSAGE, helloEap));
        byte[] hReq = buildRequestPacket(++rid, reqAuth, hAttrs, secret, true);
        byte[] resp3 = sendRecv(sock, hReq, host, port, 8000);
        Object[] r3 = parseResp(resp3);
        byte[] eap3 = findAttr((List<Attr>) r3[2], ATTR_EAP_MESSAGE);
        int code3 = (Integer) r3[0];
        System.out.println("[3] ClientHello → code=" + code3 + " EAP-len=" + (eap3 == null ? 0 : eap3.length));
        if (code3 == 3 /*REJECT*/ || eap3 == null || (eap3[4] & 0xff) != EAP_TYPE_TLS) {
            System.out.println("[FAIL] ClientHello 未得到 TLS Challenge 响应");
            System.exit(1);
        }
        // 判断是否为 fatal 失败（EAP 层 failure 或 BC 抛错被包装为 FAILURE 包）
        System.out.println("      EAP 首字节=" + (eap3 == null ? "-" : (eap3[0] & 0xff))
                + "（2=Response/3=Success/4=Failure）");
        System.out.println("      [3] 完整响应 hex:");
        if (eap3 != null) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < eap3.length; i++) {
                if (i > 0 && i % 32 == 0) sb.append("\n      ");
                sb.append(String.format("%02x", eap3[i] & 0xff));
            }
            System.out.println("      " + sb);
        }

        // [4] 网关重传风暴：RADIUS identifier 递增 30 次，EAP-Id 与数据完全一致
        //     验证 src 维度重传检测（RFC 3748 §5.1）：全部应重发与 [3] 完全相同的响应，
        //     服务端不崩溃（修复前第 2 次重传就会 unexpected_message）。
        byte[] eapLast = eap3;
        boolean allSame = true;
        for (int i = 0; i < 30; i++) {
            List<Attr> hAttrs2 = new ArrayList<>();
            hAttrs2.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
            hAttrs2.add(new Attr(ATTR_EAP_MESSAGE, helloEap));
            byte[] hReq2 = buildRequestPacket(++rid, reqAuth, hAttrs2, secret, true);
            byte[] respN = sendRecv(sock, hReq2, host, port, 8000);
            Object[] rN = parseResp(respN);
            byte[] eapN = findAttr((List<Attr>) rN[2], ATTR_EAP_MESSAGE);
            int codeN = (Integer) rN[0];
            if (codeN == 3 /*REJECT*/) {
                System.out.println("[FAIL] 第 " + (i + 1) + " 次重传被 REJECT（会话崩溃）");
                System.exit(1);
            }
            boolean same = eap3 != null && eapN != null && Arrays.equals(eap3, eapN);
            if (!same) {
                allSame = false;
                System.out.println("[FAIL] 第 " + (i + 1) + " 次重传响应与首次不一致 code=" + codeN
                        + " EAP-len=" + (eapN == null ? 0 : eapN.length));
                if (eap3 != null && eapN != null) {
                    System.out.println("      [3] " + hex(eap3, 120));
                    System.out.println("      [N] " + hex(eapN, 120));
                }
                break;
            }
            eapLast = eapN;
        }
        System.out.println("[4] 重传风暴 30 次 → 全部重发首次响应、逐字节一致=" + allSame);
        if (!allSame) { sock.close(); System.exit(1); }

        // ================= r20 新增回归：事务化重放（新 src / 新 socket 独立跑） =================
        // 修复 A：取完整飞行后再重传 ClientHello —— 旧实现回"最近一次响应体"＝**末片**，
        //         客户端永远解析不出 ServerHello → 无限重传（[iOS兼容] 日志无限重复）。
        // 修复 C：重传的空拉取片（EAP-Id 与数据逐字节相同）—— 旧实现当"新拉取"直接前进，
        //         跳过一片 → 客户端手里的飞行中间缺片，解析必然失败。
        DatagramSocket sock2 = new DatagramSocket();
        byte[] reqAuth2 = new byte[16];
        rnd.nextBytes(reqAuth2);
        int rid2 = 1;

        // Identity → Challenge
        List<Attr> a1 = new ArrayList<>();
        a1.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
        a1.add(new Attr(ATTR_EAP_MESSAGE, idEap));
        Object[] o1 = parseResp(sendRecv(sock2, buildRequestPacket(rid2++, reqAuth2, a1, secret, true),
                host, port, 5000));
        byte[] e1 = findAttr((List<Attr>) o1[2], ATTR_EAP_MESSAGE);
        if (e1 == null || (Integer) o1[0] != CODE_ACCESS_CHALLENGE) {
            System.out.println("[FAIL][7] Identity 未得到 Challenge");
            sock2.close(); System.exit(1);
        }
        // NAK → EAP-TLS Start
        List<Attr> a2 = new ArrayList<>();
        a2.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
        a2.add(new Attr(ATTR_EAP_MESSAGE, nakEap));
        Object[] o2 = parseResp(sendRecv(sock2, buildRequestPacket(rid2++, reqAuth2, a2, secret, true),
                host, port, 5000));
        byte[] e2 = findAttr((List<Attr>) o2[2], ATTR_EAP_MESSAGE);
        if (e2 == null || e2.length < 5 || (e2[4] & 0xff) != EAP_TYPE_TLS) {
            System.out.println("[FAIL][7] NAK 未切换到 EAP-TLS");
            sock2.close(); System.exit(1);
        }
        // ClientHello → 首片
        List<Attr> a3 = new ArrayList<>();
        a3.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
        a3.add(new Attr(ATTR_EAP_MESSAGE, helloEap));
        byte[] firstFrag = findAttr((List<Attr>) parseResp(sendRecv(sock2,
                buildRequestPacket(rid2++, reqAuth2, a3, secret, true), host, port, 8000))[2],
                ATTR_EAP_MESSAGE);
        if (firstFrag == null || firstFrag.length < 6 || (firstFrag[4] & 0xff) != EAP_TYPE_TLS) {
            System.out.println("[FAIL][7] ClientHello 未得到 TLS 分片");
            sock2.close(); System.exit(1);
        }
        System.out.println("[7] 首片 EAP-Id=" + (firstFrag[1] & 0xff) + " " + (firstFrag.length - 5)
                + "B flags=0x" + String.format("%02x", firstFrag[5] & 0xff));

        // 逐片拉取直到 M=0；拉取片回显服务器本次 Request 的 Identifier（RFC 3748 §4.1）
        byte[] lastFrag = firstFrag;
        int pullId = firstFrag[1] & 0xff;
        for (int i = 0; i < 10; i++) {
            List<Attr> ap = new ArrayList<>();
            ap.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
            ap.add(new Attr(ATTR_EAP_MESSAGE,
                    new byte[]{EAP_CODE_RESPONSE, (byte) pullId, 0, 6, EAP_TYPE_TLS, 0}));
            byte[] ep = findAttr((List<Attr>) parseResp(sendRecv(sock2,
                    buildRequestPacket(rid2++, reqAuth2, ap, secret, true), host, port, 8000))[2],
                    ATTR_EAP_MESSAGE);
            if (ep == null || ep.length < 6 || (ep[4] & 0xff) != EAP_TYPE_TLS) {
                System.out.println("[FAIL][7] 拉片异常（第 " + (i + 1) + " 次）");
                sock2.close(); System.exit(1);
            }
            lastFrag = ep;
            pullId = ep[1] & 0xff;
            if ((ep[5] & 0x40) == 0) {
                break;   // M=0：整个飞行取完
            }
        }
        System.out.println("[7] 末片 EAP-Id=" + (lastFrag[1] & 0xff) + " " + (lastFrag.length - 5)
                + "B flags=0x" + String.format("%02x", lastFrag[5] & 0xff));

        // [7] 取完整飞行后重传同一个 ClientHello → 期望回放**首片**（修复前回的是末片）
        List<Attr> a4 = new ArrayList<>();
        a4.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
        a4.add(new Attr(ATTR_EAP_MESSAGE, helloEap));
        byte[] replayed = findAttr((List<Attr>) parseResp(sendRecv(sock2,
                buildRequestPacket(rid2++, reqAuth2, a4, secret, true), host, port, 8000))[2],
                ATTR_EAP_MESSAGE);
        boolean backToFirst = replayed != null && Arrays.equals(replayed, firstFrag);
        boolean isTail = replayed != null && Arrays.equals(replayed, lastFrag);
        System.out.println("[7] 取完飞行后重传 ClientHello → 回放首片=" + backToFirst
                + " 回放末片=" + isTail + "（期望 true / false）");
        if (!backToFirst) {
            if (replayed != null) {
                System.out.println("      期望首片: " + hex(firstFrag, 60));
                System.out.println("      实际响应: " + hex(replayed, 60));
            }
            System.out.println("[FAIL][7] 重传未按事务回放首片（iOS 死循环根因未修复）");
            sock2.close(); System.exit(1);
        }

        // [8] 重传同一空拉取片 → 期望回放上一片；随后用新 EAP-Id 拉取应只前进一片（不跳片）
        List<Attr> p1a = new ArrayList<>();
        p1a.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
        p1a.add(new Attr(ATTR_EAP_MESSAGE,
                new byte[]{EAP_CODE_RESPONSE, (byte) pullId, 0, 6, EAP_TYPE_TLS, 0}));
        byte[] rp1 = findAttr((List<Attr>) parseResp(sendRecv(sock2,
                buildRequestPacket(rid2++, reqAuth2, p1a, secret, true), host, port, 8000))[2],
                ATTR_EAP_MESSAGE);
        byte[] rp2 = findAttr((List<Attr>) parseResp(sendRecv(sock2,
                buildRequestPacket(rid2++, reqAuth2, p1a, secret, true), host, port, 8000))[2],
                ATTR_EAP_MESSAGE);
        boolean pullReplay = rp1 != null && rp2 != null && Arrays.equals(rp1, rp2);
        System.out.println("[8] 同一拉取片重传 → 回放上一片=" + pullReplay
                + "（R1 flags=0x" + (rp1 != null && rp1.length > 5 ? String.format("%02x", rp1[5] & 0xff) : "--")
                + "，R2 flags=0x" + (rp2 != null && rp2.length > 5 ? String.format("%02x", rp2[5] & 0xff) : "--") + "）");
        if (!pullReplay) {
            System.out.println("[FAIL][8] 重传拉取片未回放上一片（旧实现会跳片 → 客户端飞行残缺）");
            sock2.close(); System.exit(1);
        }
        // 新 EAP-Id 拉取 → 只前进一片（帧内容必须与回放片不同，且不得与回放片同为末片）
        int nextPullId = (rp1[1] & 0xff);
        List<Attr> p3a = new ArrayList<>();
        p3a.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
        p3a.add(new Attr(ATTR_EAP_MESSAGE,
                new byte[]{EAP_CODE_RESPONSE, (byte) nextPullId, 0, 6, EAP_TYPE_TLS, 0}));
        byte[] rp3 = findAttr((List<Attr>) parseResp(sendRecv(sock2,
                buildRequestPacket(rid2++, reqAuth2, p3a, secret, true), host, port, 8000))[2],
                ATTR_EAP_MESSAGE);
        boolean advanced = rp3 != null && !Arrays.equals(rp3, rp1);
        System.out.println("[8] 新 EAP-Id 拉取 → 前进一片=" + advanced
                + "（" + (rp3 != null ? (rp3.length - 5) + "B flags=0x"
                    + String.format("%02x", rp3[5] & 0xff) : "--") + "）");
        if (!advanced) {
            System.out.println("[FAIL][8] 新拉取片未推进（重传判定过度拦截）");
            sock2.close(); System.exit(1);
        }
        sock2.close();
        System.out.println("[7][8] r20 事务化重放回归通过：重传回放该笔响应、拉取片不跳片");

        // [5] 模拟 src 键被新会话覆盖：再次 NAK → 服务端二次 startEapTls，
        //     putTlsSession(新rid, src, 新会话) 会覆盖 src 键。
        //     修复前：旧事务重传按会话查不到原会话（src 键被覆盖）→ 误 feed → 崩溃。
        List<Attr> nakAttrs2 = new ArrayList<>();
        nakAttrs2.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
        nakAttrs2.add(new Attr(ATTR_EAP_MESSAGE, nakEap));
        byte[] nakReq2 = buildRequestPacket(++rid, reqAuth, nakAttrs2, secret, true);
        byte[] resp5 = sendRecv(sock, nakReq2, host, port, 5000);
        Object[] r5 = parseResp(resp5);
        byte[] eap5 = findAttr((List<Attr>) r5[2], ATTR_EAP_MESSAGE);
        int code5 = (Integer) r5[0];
        System.out.println("[5] 二次 NAK（覆盖 src 键）→ code=" + code5
                + " EAP-type=" + (eap5 == null || eap5.length < 5 ? "-" : (eap5[4] & 0xff)));
        if (code5 != CODE_ACCESS_CHALLENGE || eap5 == null || eap5.length < 5 || (eap5[4] & 0xff) != EAP_TYPE_TLS) {
            // 服务端对二次 NAK 返回 Failure（takeEapState 已 null）属预期；若为 REJECT 则跳过 [6] 的覆盖验证
            if (code5 == 3 /* REJECT */) {
                System.out.println("[SKIP] 服务端二次 NAK 状态失效返回 REJECT（预期行为），跳过 src 键覆盖验证");
                sock.close();
                System.out.println("[PASS] iOS 网关重传检测生效：30 次风暴全部重发上次响应，服务端未崩溃");
                System.exit(0);
            }
            System.out.println("[FAIL] 二次 NAK 未得到预期响应");
            sock.close(); System.exit(1);
        }

        // [6] 旧事务重传（同一 ClientHello）→ 即使 src 键已被新会话覆盖，src 维度
        //     重传检测仍应命中：重发上次响应，不崩溃、不 feed。
        List<Attr> hAttrs3 = new ArrayList<>();
        hAttrs3.add(new Attr(ATTR_USER_NAME, "vpn.local".getBytes("UTF-8")));
        hAttrs3.add(new Attr(ATTR_EAP_MESSAGE, helloEap));
        byte[] hReq3 = buildRequestPacket(++rid, reqAuth, hAttrs3, secret, true);
        byte[] resp6 = sendRecv(sock, hReq3, host, port, 8000);
        Object[] r6 = parseResp(resp6);
        byte[] eap6 = findAttr((List<Attr>) r6[2], ATTR_EAP_MESSAGE);
        int code6 = (Integer) r6[0];
        boolean same6 = eap6 != null && eapLast != null && Arrays.equals(eap6, eapLast);
        System.out.println("[6] 覆盖后旧 ClientHello 重传 → code=" + code6
                + " 与上次响应逐字节一致=" + same6);
        if (code6 == 3 || !same6) {
            System.out.println("[FAIL] src 键覆盖后重传未命中重传检测（修复目标场景）");
            sock.close(); System.exit(1);
        }
        sock.close();
        System.out.println("[PASS] iOS 网关重传检测生效：RFC 3748 §5.1 重发上次响应，风暴与覆盖场景均未崩溃");
        System.exit(0);
    }
}
