package modpkica;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * auto —— 自动化证书库操作（对应 Go 版 cmd/auto）。
 *
 * <p>提供三个子命令（Java 版直接操作 PKI/CERTS.txt，不派生进程）：
 * <ul>
 *   <li><b>auto init</b>：初始化环境——把现有 CERTS.txt 备份为
 *       {@code CERTS.txt.old.<Unix时间戳>}，然后写入 CERTS.txt 模板与模板副本
 *       CERTS.txt.sm。</li>
 *   <li><b>auto revoke 序列号 [原因编号]</b>：吊销证书——把对应记录状态改为 R、
 *       原因与时间（时间 = 当前时间 - 3 天，对齐 Go 版）。</li>
 *   <li><b>auto newcert 序列号 类型 状态 原因 时间 颁发者ID 算法</b>：
 *       追加一条证书记录（时间为 "null" 时用当前时间 - 3 天）。</li>
 * </ul>
 */
public final class Auto {

    /** CERTS.txt 行时间格式 */
    private static final DateTimeFormatter MOD_TIME =
            DateTimeFormatter.ofPattern("yyyy/MM/dd-HH:mm:ss");

    /** CERTS.txt 模板内容（对齐 Go 版 echo 出的字节内容） */
    private static final String CERTS_TEMPLATE =
            "# 序列号    类型        状态         状态原因编号   签发时间/吊销时间\r\n"
                    + "#    ROOT/CA/END   V正常R吊销N未知     0-9     例如 2000/06/17-12:12:12\r\n";

    private Auto() {
    }

    public static void main(String[] args) throws Exception {
        String baseDir = AppPaths.baseDir();
        String cmd = args.length >= 1 ? args[0] : "";

        if ("init".equalsIgnoreCase(cmd)) {
            initEnv(baseDir);
            System.out.println("初始化环境完成");
            return;
        }
        if ("revoke".equalsIgnoreCase(cmd) && args.length >= 2) {
            String reason = args.length >= 3 ? args[2] : "0";
            revokeCert(baseDir, args[1], reason);
            return;
        }
        if ("newcert".equalsIgnoreCase(cmd) && args.length >= 5) {
            // 参数：序列号 类型 状态 原因 时间 颁发者ID 算法
            String time = "null".equals(args[4]) ? now() : args[4];
            addCert(baseDir, args[1], args[2], args[3], time, args[5], args[6]);
            return;
        }
        System.out.println("错误:无效操作");
        System.out.println("用法: auto init | auto revoke 序列号 [原因] | auto newcert 序列号 类型 状态 原因 时间 颁发者ID 算法");
    }

    /** 当前真实时间（登记/吊销时间戳，用户确认不偏移）。 */
    private static String now() {
        return LocalDateTime.now().format(MOD_TIME);
    }

    /** 供 ADMIN 内部调用：初始化环境（备份 + 模板）。 */
    public static void runInit(String baseDir) throws Exception {
        initEnv(baseDir);
    }

    /** 供 ADMIN 内部调用：吊销证书。 */
    public static void revoke(String baseDir, String serial, String reason) throws Exception {
        revokeCert(baseDir, serial, reason);
    }

    /** 供 ADMIN/WebAdmin 内部调用：恢复证书（R→V、原因 0、时间刷新为当前时间）。 */
    public static void restore(String baseDir, String serial) throws Exception {
        restoreCert(baseDir, serial);
    }

    /** auto init：清理证书目录旧文件、备份 CERTS.txt 并写入模板。 */
    private static void initEnv(String baseDir) throws Exception {
        // 1) 清理各证书目录下所有 cer/crt/key/crl/der 文件（初始化环境即清空重来）
        String[] dirs = {
            "PKI/CERT", "PKI/CA", "PKI/ROOT", "PKI/KEY",
            "PKI/OCSP", "PKI/TIMSTAMP",
            "PKI/WebPublic/CRT", "PKI/WebPublic/CRL"
        };
        String[] exts = {"cer", "crt", "key", "crl", "der"};
        int deleted = 0;
        for (String d : dirs) {
            java.io.File folder = new java.io.File(baseDir, d);
            java.io.File[] files = folder.listFiles();
            if (files == null) {
                continue;
            }
            for (java.io.File f : files) {
                if (!f.isFile()) {
                    continue;
                }
                String name = f.getName().toLowerCase();
                for (String ext : exts) {
                    if (name.endsWith("." + ext)) {
                        f.delete();
                        deleted++;
                        break;
                    }
                }
            }
        }
        System.out.println("已清理 " + deleted + " 个证书/密钥/吊销列表文件");
        // 2) 备份 CERTS.txt 并重建模板——整体放入跨进程文件锁（与 CertsDB 同一把锁）：
        //    备份用 copy 而非 move + 模板用原子替换，避免出现"文件不存在"窗口
        //    （MAIN 每请求 reload，看到空台账会把有效证书答成"未知"），
        //    也避免并发签发/吊销的记录被模板覆盖。
        Path certs = Paths.get(baseDir, "PKI", "CERTS.txt");
        Path sm = Paths.get(baseDir, "PKI", "CERTS.txt.sm");
        Files.createDirectories(certs.getParent());   // 全新工作目录：锁文件/模板都需要 PKI 目录存在
        CertsDB.withCertsLock(baseDir, () -> {
            try {
                if (Files.exists(certs)) {
                    String backup = certs + ".old." + (System.currentTimeMillis() / 1000L);
                    Files.copy(certs, Paths.get(backup));
                }
                // 清理历史 .old 备份：仅保留最近一份，避免 init 多次后堆积
                try {
                    Path pkiDir = certs.getParent();
                    java.util.List<java.nio.file.Path> olds = new java.util.ArrayList<>();
                    if (pkiDir != null && java.nio.file.Files.isDirectory(pkiDir)) {
                        try (java.util.stream.Stream<java.nio.file.Path> st =
                                     java.nio.file.Files.list(pkiDir)) {
                            st.filter(p2 -> p2.getFileName().toString().startsWith("CERTS.txt.old."))
                              .forEach(olds::add);
                        }
                        olds.sort(java.util.Comparator.comparing(p2 -> p2.getFileName().toString()));
                        for (int i = 0; i < olds.size() - 1; i++) {
                            java.nio.file.Files.deleteIfExists(olds.get(i));
                        }
                    }
                } catch (Exception ignore) {
                    // 清理失败不影响初始化主流程
                }
                PemIO.atomicWrite(certs, CERTS_TEMPLATE.getBytes(StandardCharsets.UTF_8));
                PemIO.atomicWrite(sm, CERTS_TEMPLATE.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                throw new IllegalStateException("重建 CERTS.txt 模板失败", e);
            }
        });
        System.out.println("CERTS.txt 已备份并重建模板");
    }

    /** auto revoke：把 CERTS.txt 中指定序列号记录改为 R 状态。
     *  读-改-写整体在 CertsDB 同一把跨进程锁内，避免与并发签发/吊销互相覆盖。 */
    private static void revokeCert(String baseDir, String serial, String reason) throws Exception {
        Path certs = Paths.get(baseDir, "PKI", "CERTS.txt");
        String newTime = now();
        boolean[] found = {false};
        CertsDB.withCertsLock(baseDir, () -> {
            try {
                List<String> lines = Files.readAllLines(certs, StandardCharsets.UTF_8);
                StringBuilder sb = new StringBuilder();
                for (String line : lines) {
                    String t = line.trim();
                    if (t.isEmpty() || t.startsWith("#")) {
                        sb.append(line).append(System.lineSeparator());
                        continue;
                    }
                    String[] f = t.split("\\s+");
                    if (f[0].equals(serial) && f.length >= 7) {
                        // 新行：序列号 类型 R 原因 时间 颁发者ID 算法
                        sb.append(f[0]).append(' ').append(f[1]).append(" R ").append(reason)
                                .append(' ').append(newTime).append(' ')
                                .append(f[5]).append(' ').append(f[6])
                                .append(System.lineSeparator());
                        found[0] = true;
                    } else {
                        sb.append(line).append(System.lineSeparator());
                    }
                }
                if (found[0]) {
                    atomicWrite(certs, sb.toString());
                }
            } catch (Exception e) {
                throw new IllegalStateException("吊销证书失败: " + serial, e);
            }
        });
        if (!found[0]) {
            System.out.println("吊销失败:CERTS.txt证书库不存在此编号");
            return;
        }
        System.out.println("吊销成功");
    }

    /** auto restore：把 CERTS.txt 中指定序列号记录改为 V 状态、原因 0（撤销吊销）。 */
    private static void restoreCert(String baseDir, String serial) throws Exception {
        Path certs = Paths.get(baseDir, "PKI", "CERTS.txt");
        String newTime = LocalDateTime.now().format(MOD_TIME);
        boolean[] found = {false};
        CertsDB.withCertsLock(baseDir, () -> {
            try {
                List<String> lines = Files.readAllLines(certs, StandardCharsets.UTF_8);
                StringBuilder sb = new StringBuilder();
                for (String line : lines) {
                    String t = line.trim();
                    if (t.isEmpty() || t.startsWith("#")) {
                        sb.append(line).append(System.lineSeparator());
                        continue;
                    }
                    String[] f = t.split("\\s+");
                    if (f[0].equals(serial) && f.length >= 7) {
                        // 新行：序列号 类型 V 0 时间 颁发者ID 算法
                        sb.append(f[0]).append(' ').append(f[1]).append(" V 0 ")
                                .append(newTime).append(' ')
                                .append(f[5]).append(' ').append(f[6])
                                .append(System.lineSeparator());
                        found[0] = true;
                    } else {
                        sb.append(line).append(System.lineSeparator());
                    }
                }
                if (found[0]) {
                    atomicWrite(certs, sb.toString());
                }
            } catch (Exception e) {
                throw new IllegalStateException("恢复证书失败: " + serial, e);
            }
        });
        if (!found[0]) {
            System.out.println("恢复失败:CERTS.txt证书库不存在此编号");
            return;
        }
        System.out.println("恢复成功");
    }

    /** auto newcert：追加一条证书记录（在 CertsDB 同一把跨进程锁内追加）。 */
    private static void addCert(String baseDir, String serial, String type, String status,
                                String time, String issuerId, String algo) throws Exception {
        String newline = serial + " " + type + " " + status + " " + "0" + " "
                + time + " " + issuerId + " " + algo + "\r\n";
        Path certs = Paths.get(baseDir, "PKI", "CERTS.txt");
        CertsDB.withCertsLock(baseDir, () -> {
            try {
                Files.write(certs, newline.getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (Exception e) {
                throw new IllegalStateException("增加证书失败: " + serial, e);
            }
        });
        System.out.println("增加证书成功: " + serial);
    }

    /** 原子写 CERTS.txt（tmp → fsync → .bak → move），与 CertsDB.rewriteAll 同策略。 */
    private static void atomicWrite(Path p, String content) throws Exception {
        Path tmp = Paths.get(p.toString() + ".tmp");
        java.nio.file.Files.writeString(tmp, content, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(tmp.toString(), true)) {
            fos.getFD().sync();
        }
        if (java.nio.file.Files.exists(p)) {
            java.nio.file.Files.copy(p, Paths.get(p.toString() + ".bak"),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
        java.nio.file.Files.move(tmp, p, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }
}
