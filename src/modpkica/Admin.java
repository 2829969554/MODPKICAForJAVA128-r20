package modpkica;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Scanner;

/**
 * ADMIN —— 管理控制台（对应 Go 版 cmd/admin）。
 *
 * <p>交互式命令（输入命令后按提示逐项填写）：
 * <ul>
 *   <li><b>init</b>：初始化环境（备份 CERTS.txt、写入模板、生成根、签发 OCSP/TSA 全家桶）</li>
 *   <li><b>makeroot</b>：签发根证书（调用 MakeRoot）</li>
 *   <li><b>list / ls</b>：列出证书库</li>
 *   <li><b>signCERT / CRT</b>：签发证书（调用 MakeCert 普通模式）</li>
 *   <li><b>RevokeCERT</b>：吊销证书（改写 CERTS.txt + 刷新 CRL）</li>
 *   <li><b>signCRL / CRL</b>：签发 CRL（调用 RootGetCrl）</li>
 *   <li><b>initOCSP</b>：为证书库中全部 R/C 证书签发 OCSP 签名证书</li>
 *   <li><b>initTIMSTAMP</b>：为全部根证书签发时间戳证书（rsa/ecc_sha1/sha256、sm2_sm3）</li>
 *   <li><b>verifyCERT</b>：验证证书（调用 CertVerify）</li>
 *   <li><b>VERSION</b>：版本信息</li>
 * </ul>
 *
 * <p>所有操作均写入 PKI/logs.log 操作日志。
 *
 * <p>各命令核心逻辑抽为 public static doXxx 方法，供交互控制台与
 * 可视化 WebAdmin（浏览器 GUI）共用，保证两条入口行为完全一致。
 */
public final class Admin {

    /** 版本信息（r 编号与 README「更新记录」/ CHANGELOG.md 对齐）。 */
    public static final String VERSION = "MODPKICA Java 复刻版 v1.28-r20 (BC 1.85 离线)";

    private Admin() {
    }

    public static void main(String[] args) throws Exception {
        String baseDir = AppPaths.baseDir();
        System.out.println("============================================");
        System.out.println("  MODPKICA Java 管理控制台 (BC 1.85 离线)");
        System.out.println("============================================");
        printHelp();

        Scanner sc = new Scanner(System.in, StandardCharsets.UTF_8.name());
        while (true) {
            System.out.print("\nADMIN> ");
            if (!sc.hasNextLine()) {
                break;
            }
            String cmd = sc.nextLine().trim();
            if (cmd.isEmpty()) {
                continue;
            }
            String[] parts = cmd.split("\\s+");
            String op = parts[0].toLowerCase();
            try {
                switch (op) {
                    case "init":
                        cmdInit(sc, baseDir);
                        break;
                    case "makeroot":
                        cmdMakeRoot(sc, baseDir);
                        break;
                    case "list":
                    case "ls":
                        System.out.println(doList(baseDir));
                        break;
                    case "signcert":
                    case "crt":
                        cmdSignCert(sc, baseDir);
                        break;
                    case "revokecert":
                        cmdRevoke(sc, baseDir);
                        break;
                    case "signcrl":
                    case "crl":
                        System.out.println(doSignCrl(baseDir));
                        break;
                    case "initocsp":
                        cmdInitOcsp(sc, baseDir);
                        break;
                    case "inittimestamp":
                        cmdInitTimestamp(sc, baseDir);
                        break;
                    case "verifycert":
                        cmdVerifyCert(sc, baseDir);
                        break;
                    case "version":
                        System.out.println(VERSION);
                        break;
                    case "help":
                        printHelp();
                        break;
                    case "exit":
                    case "quit":
                        System.out.println("再见。");
                        return;
                    default:
                        System.out.println("未知命令: " + cmd);
                        printHelp();
                }
            } catch (Exception e) {
                System.out.println("执行出错: " + e.getMessage());
                MLog.appendErr(baseDir, "ADMIN " + op + " 异常", cmd, String.valueOf(e));
            }
        }
    }

    private static void printHelp() {
        System.out.println("可用命令:");
        System.out.println("  init           初始化环境（备份+模板+根+OCSP+TSA）");
        System.out.println("  makeroot       签发根证书");
        System.out.println("  list / ls      列出证书库");
        System.out.println("  signCERT       签发证书");
        System.out.println("  RevokeCERT     吊销证书");
        System.out.println("  signCRL        签发 CRL");
        System.out.println("  initOCSP       为全部根/中间CA签发 OCSP 签名证书");
        System.out.println("  initTIMSTAMP   为全部根签发时间戳证书");
        System.out.println("  verifyCERT     验证证书");
        System.out.println("  VERSION        版本信息");
        System.out.println("  help           帮助");
        System.out.println("  exit / quit    退出");
    }

    // ------------------------------------------------------------
    // 各命令实现（交互式输入对齐 Go 版 admin；核心逻辑走 doXxx 公共方法）
    // ------------------------------------------------------------

    /** init：备份 + 模板 + 根 + OCSP + TSA。 */
    private static void cmdInit(Scanner sc, String baseDir) throws Exception {
        System.out.print("根证书 DN (CN=...,O=...,C=...): ");
        String dn = sc.nextLine().trim();
        System.out.print("密钥位数 [2048/4096/256...]: ");
        String bit = sc.nextLine().trim();
        System.out.print("哈希算法 [sha256/sha1/sha384/sha512/SM3]: ");
        String hash = sc.nextLine().trim();
        System.out.print("密钥算法 [RSA/ECC/SM2]: ");
        String algo = sc.nextLine().trim();
        System.out.println(doInit(baseDir, dn, bit, hash, algo));
    }

    private static void cmdMakeRoot(Scanner sc, String baseDir) throws Exception {
        System.out.print("根证书 DN (CN=...,O=...,C=...): ");
        String dn = sc.nextLine().trim();
        System.out.print("密钥位数 [2048/4096/256...]: ");
        String bit = sc.nextLine().trim();
        System.out.print("哈希算法 [sha256/sha1/sha384/sha512/SM3]: ");
        String hash = sc.nextLine().trim();
        System.out.print("密钥算法 [RSA/ECC/SM2]: ");
        String algo = sc.nextLine().trim();
        System.out.println(doMakeRoot(baseDir, dn, bit, hash, algo));
    }

    /** signCERT：签发证书（普通模式，参数对齐 Go 版 MODML[1..12]）。 */
    private static void cmdSignCert(Scanner sc, String baseDir) throws Exception {
        System.out.print("证书 DN (CN=...,O=...,C=...): ");
        String dn = sc.nextLine().trim();
        System.out.print("密钥位数 [2048/4096/256...]: ");
        String bit = sc.nextLine().trim();
        System.out.print("哈希算法 [sha1/sha256/sha384/sha512/SM3]: ");
        String hash = sc.nextLine().trim();
        System.out.print("密钥用法编号 [1~8, 如 1=数字签名]: ");
        String keyUsage = sc.nextLine().trim();
        System.out.print("扩展密钥用法编号 [0~11 或自定义OID, 逗号分隔]: ");
        String exUsage = sc.nextLine().trim();
        System.out.print("证书类型 [0=终端证书, 1=中间CA]: ");
        String isCa = sc.nextLine().trim();
        System.out.print("有效期年数 [如 1=1年, 10=10年]: ");
        String days = sc.nextLine().trim();
        System.out.print("SAN 域名 [多个用逗号分隔, 无则输入 null]: ");
        String dns = sc.nextLine().trim();
        System.out.print("SAN IP [多个用逗号分隔, 无则输入 null]: ");
        String ips = sc.nextLine().trim();
        System.out.print("颁发者序列号 [根证书输入 root]: ");
        String issuer = sc.nextLine().trim();
        System.out.print("密钥算法 [RSA/ECC/SM2]: ");
        String algo = sc.nextLine().trim();

        System.out.println(doSignCert(baseDir, dn, bit, hash, keyUsage, exUsage,
                isCa, days, dns, ips, issuer, algo));
    }

    /** RevokeCERT：吊销证书并刷新 CRL。 */
    private static void cmdRevoke(Scanner sc, String baseDir) throws Exception {
        System.out.print("要吊销的证书序列号: ");
        String serial = sc.nextLine().trim();
        System.out.print("吊销原因编号 [0~9, 默认0]: ");
        String reason = sc.nextLine().trim();
        if (reason.isEmpty()) {
            reason = "0";
        }
        System.out.println(doRevoke(baseDir, serial, reason));
    }

    /** initOCSP：无参时为证书库中全部 R/C 证书签发 OCSP 签名证书。 */
    private static void cmdInitOcsp(Scanner sc, String baseDir) throws Exception {
        System.out.print("密钥算法 [RSA/ECC/SM2] (直接回车=全部证书): ");
        String algo = sc.nextLine().trim();
        System.out.println(doInitOcsp(baseDir, algo));
    }

    /** initTIMSTAMP：无参时为全部根证书签发时间戳证书。 */
    private static void cmdInitTimestamp(Scanner sc, String baseDir) throws Exception {
        System.out.print("哈希算法 [SHA1/SHA256/SM3] (直接回车=全部根证书): ");
        String hash = sc.nextLine().trim();
        System.out.println(doInitTimestamp(baseDir, hash));
    }

    private static void cmdVerifyCert(Scanner sc, String baseDir) throws Exception {
        System.out.print("证书文件路径或序列号: ");
        String target = sc.nextLine().trim();
        System.out.println(doVerifyCert(baseDir, target));
    }

    // ============================================================
    // 公共操作入口（控制台与 WebAdmin 共用，行为一致）
    // ============================================================

    /** 捕获被调程序输出到 stdout 的内容，返回字符串。
     *  P2-05：System.setOut 是全局替换，多个请求并发 capture 会互相污染 stdout，
     *  故用进程内互斥锁串行化 capture 段（可重入，同一线程嵌套调用安全）。 */
    private static final Object STDOUT_LOCK = new Object();

    static String captureStdout(ThrowingRunnable r) throws Exception {
        synchronized (STDOUT_LOCK) {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            PrintStream old = System.out;
            System.setOut(new PrintStream(buf, true, StandardCharsets.UTF_8));
            try {
                r.run();
            } finally {
                System.setOut(old);
            }
            return buf.toString(StandardCharsets.UTF_8);
        }
    }

    /** 无返回值、可抛异常的动作（避免到处写 try/catch）。 */
    interface ThrowingRunnable {
        void run() throws Exception;
    }

    /** init：备份 + 模板 + 签发根证书 + 全量 OCSP + 全量 TSA。 */
    public static String doInit(String baseDir, String dn, String bit, String hash, String algo)
            throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append(captureStdout(() -> Auto.runInit(baseDir)));
        String[] ma = {dn, bit, hash, algo};
        sb.append(captureStdout(() -> MakeRoot.run(baseDir, ma)));
        sb.append('\n').append(doInitOcsp(baseDir, ""));
        sb.append('\n').append(doInitTimestamp(baseDir, ""));
        MLog.append(baseDir, "ADMIN init",
                "init \"" + dn + "\" " + bit + " " + hash + " " + algo,
                "初始化环境完成");
        return sb.toString();
    }

    /** makeroot：签发根证书（签发后自动刷新 CRL），organizationIdentifier 扩展用旧版 OID。 */
    public static String doMakeRoot(String baseDir, String dn, String bit, String hash, String algo)
            throws Exception {
        return doMakeRoot(baseDir, dn, bit, hash, algo, "old");
    }

    /** makeroot：可指定 organizationIdentifier 扩展 OID 版本（new=2.23.140.3.1 / old=1.3.6.1.4.1.57264.1.8）。 */
    public static String doMakeRoot(String baseDir, String dn, String bit, String hash, String algo, String evoid)
            throws Exception {
        String[] ma = {dn, bit, hash, algo, evoid == null || evoid.isEmpty() ? "old" : evoid};
        String out = captureStdout(() -> MakeRoot.run(baseDir, ma));
        MLog.append(baseDir, "ADMIN makeroot",
                "makeroot \"" + dn + "\" " + bit + " " + hash + " " + algo,
                "根证书签发完成 " + dn);
        return out;
    }

    /** list：列出证书库（返回表格文本）。 */
    public static String doList(String baseDir) throws Exception {
        StringBuilder sb = new StringBuilder();
        List<String> lines = Files.readAllLines(
                Paths.get(baseDir, "PKI", "CERTS.txt"), StandardCharsets.UTF_8);
        sb.append("序列号          类型  状态  原因  时间                颁发者ID        算法\n");
        for (String line : lines) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) {
                continue;
            }
            sb.append("  ").append(t).append('\n');
        }
        return sb.toString();
    }

    /** signCERT：签发证书（普通模式 12 参数，对齐 Go 版 MODML[1..12]）。 */
    public static String doSignCert(String baseDir, String dn, String bit, String hash,
            String keyUsage, String exUsage, String isCa, String days, String dns,
            String ips, String issuer, String algo) throws Exception {
        return doSignCert(baseDir, dn, bit, hash, keyUsage, exUsage, isCa, days, dns,
                ips, issuer, algo, null, null);
    }

    /** signCERT 扩展版：pathLen=中间CA路径长度(null/0-9)；policy=终端证书策略OID(逗号分隔，勾选才写入)。 */
    public static String doSignCert(String baseDir, String dn, String bit, String hash,
            String keyUsage, String exUsage, String isCa, String days, String dns,
            String ips, String issuer, String algo, String pathLen, String policy)
            throws Exception {
        String[] a = {dn, bit, hash, keyUsage, exUsage, isCa, days, dns, ips, "null", issuer, algo,
                pathLen == null || pathLen.isEmpty() ? "null" : pathLen,
                policy == null || policy.isEmpty() ? "" : policy};
        String out = captureStdout(() -> MakeCert.run(baseDir, a));
        MLog.append(baseDir, "ADMIN signCERT",
                "signCERT \"" + dn + "\" " + bit + " " + hash + " " + keyUsage + " "
                        + exUsage + " " + isCa + " " + days + " " + dns + " " + ips
                        + " " + issuer + " " + algo + " pathLen=" + pathLen + " policy=" + policy,
                "签发证书 " + dn + " 算法=" + algo + " 颁发者=" + issuer);
        return out;
    }

    /** RevokeCERT：吊销证书并刷新 CRL。 */
    public static String doRevoke(String baseDir, String serial, String reason)
            throws Exception {
        if (reason == null || reason.isEmpty()) {
            reason = "0";
        }
        Auto.revoke(baseDir, serial, reason);
        String out = captureStdout(() -> RootGetCrl.run(baseDir));
        MLog.append(baseDir, "ADMIN RevokeCERT",
                "revokecert " + serial + " " + reason,
                "吊销证书 " + serial + " 原因=" + reason);
        return "已吊销证书 " + serial + "（原因=" + reason + "），CRL 已刷新。\n" + out;
    }

    /** RestoreCERT：恢复证书（撤销吊销，R→V、原因 0）并刷新 CRL。 */
    public static String doRestore(String baseDir, String serial) throws Exception {
        Auto.restore(baseDir, serial);
        String out = captureStdout(() -> RootGetCrl.run(baseDir));
        MLog.append(baseDir, "ADMIN RestoreCERT",
                "restorecert " + serial,
                "恢复证书 " + serial + "（状态 R→V，原因置 0）");
        return "已恢复证书 " + serial + "（状态 V，原因 0），CRL 已刷新。\n" + out;
    }

    /** signCRL：刷新全部 CRL。 */
    public static String doSignCrl(String baseDir) throws Exception {
        String out = captureStdout(() -> RootGetCrl.run(baseDir));
        MLog.append(baseDir, "ADMIN signCRL", "signCRL", "CRL 已刷新");
        return out;
    }

    /**
     * initOCSP：为证书库中全部 R/C 证书签发 OCSP 签名证书。
     *
     * @param algo 指定算法（RSA/ECC/SM2）；空串表示按各证书自身算法
     */
    public static String doInitOcsp(String baseDir, String algo) throws Exception {
        CertsDB db = new CertsDB();
        db.load(baseDir);
        List<CertsDB.CertEntry> entries = db.getAllRootAndCA();
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (CertsDB.CertEntry e : entries) {
            String useAlgo = (algo == null || algo.isEmpty()) ? e.algo : algo;
            String[] a = {"initOCSP", useAlgo, e.serial};
            sb.append(captureStdout(() -> MakeCert.run(baseDir, a)));
            count++;
            MLog.append(baseDir, "ADMIN initOCSP",
                    "initOCSP " + useAlgo + " " + e.serial,
                    "OCSP 签名证书 " + e.serial + " 算法=" + useAlgo);
        }
        sb.append("initOCSP 完成，共 ").append(count).append(" 张\n");
        return sb.toString();
    }

    /**
     * initTIMSTAMP：为全部根证书签发时间戳证书。
     *
     * @param hash 指定哈希（SHA1/SHA256/SM3）；空串表示按各根证书算法全量
     */
    public static String doInitTimestamp(String baseDir, String hash) throws Exception {
        CertsDB db = new CertsDB();
        db.load(baseDir);
        List<CertsDB.CertEntry> roots = db.getAllRootAndCA();
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (CertsDB.CertEntry r : roots) {
            if (r.type != 'R') {
                continue;
            }
            if (hash == null || hash.isEmpty()) {
                switch (r.algo.toUpperCase()) {
                    case "RSA":
                    case "RSA-PSS":
                        makeTsa(baseDir, "SHA1", r.algo, r.serial);
                        makeTsa(baseDir, "SHA256", r.algo, r.serial);
                        break;
                    case "ECC":
                        makeTsa(baseDir, "SHA1", "ECC", r.serial);
                        makeTsa(baseDir, "SHA256", "ECC", r.serial);
                        break;
                    case "SM2":
                        makeTsa(baseDir, "SM3", "SM2", r.serial);
                        break;
                    default:
                        makeTsa(baseDir, "SHA256", r.algo, r.serial);
                }
            } else {
                makeTsa(baseDir, hash, r.algo, r.serial);
            }
            count++;
        }
        sb.append("initTIMSTAMP 完成，共 ").append(count).append(" 张\n");
        return sb.toString();
    }

    private static void makeTsa(String baseDir, String hash, String algo, String rootSerial)
            throws Exception {
        // MakeCert initTIMSTAMP 参数: a[0]=initTIMSTAMP a[1]=hash a[2]=算法 a[3]=颁发者根序列号
        String[] a = {"initTIMSTAMP", hash, algo, rootSerial};
        MakeCert.run(baseDir, a);
        MLog.append(baseDir, "ADMIN initTIMSTAMP",
                "initTIMSTAMP " + hash + " " + algo + " " + rootSerial,
                "TSA 证书 " + algo + "_" + hash.toLowerCase() + " 根=" + rootSerial);
    }

    /** verifyCERT：验证证书，返回完整输出。 */
    public static String doVerifyCert(String baseDir, String target) throws Exception {
        return captureStdout(() -> CertVerify.run(target));
    }
}
