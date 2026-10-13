package modpkica;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * CertsDB —— 证书台账 CERTS.txt 的读取 / 追加 / 吊销修改。
 *
 * <p>文件每行格式（# 开头为注释行）：
 * <pre>
 *   序列号  类型  状态  原因  时间  颁发者ID  算法
 *   13fbe865867a8ed R V 0 2026/09/04-20:07:09 13fbe865867a8ed SM2
 * </pre>
 * <ul>
 *   <li>类型 type：R=根证书, C=中间 CA, E=终端证书</li>
 *   <li>状态 status：V=正常(valid), R=吊销(revoked), N=未知(unknown)</li>
 *   <li>原因 reason：整数，RFC5280 吊销原因码，未吊销时为 0</li>
 *   <li>时间 time：yyyy/MM/dd-HH:mm:ss</li>
 *   <li>颁发者ID issuerId：签发该证书的证书序列号，自签根证书等于自身序列号</li>
 *   <li>算法 algo：RSA / ECC / SM2</li>
 * </ul>
 */
public class CertsDB {

    /** 时间列的解析格式 */
    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("yyyy/MM/dd-HH:mm:ss");

    /** 内存中缓存的全部台账条目。写方在文件锁内构建新列表后**整体替换引用**，
     *  读方拿到的永远是完整快照——不会观察到"清空后尚未重填"的空表，
     *  也不会因并发重载读到半更新的数据。 */
    private volatile List<CertEntry> entries = new ArrayList<>();

    /** 原文件中 # 注释行与空行（用户"删除证书=行首 # 注释"的语义载体）。
     *  与 entries 一样按不可变快照整体替换；rewriteAll 时原样保留，避免重写抹掉注释。 */
    private volatile List<String> preservedLines = new ArrayList<>();

    /** CERTS.txt 的完整路径 */
    private volatile Path dbPath;

    /** 最近一次加载的警告信息（坏行 / IO 失败），空串表示正常（P2-14）。 */
    public String lastLoadWarning = "";

    /** 进程内互斥（配合跨进程文件锁，见 withLock）。 */
    private static final Object FILE_LOCK = new Object();

    /** 跨进程 + 进程内双重互斥：通过 CERTS.txt.lock 文件锁实现（P2-02）。
     *  动作内部抛出的 RuntimeException（含 UncheckedIOException）原样上抛。 */
    private void withLock(Runnable action) {
        withFileLock(dbPath, action);
    }

    /** 在指定 CERTS.txt 的跨进程文件锁（&lt;path&gt;.lock）内执行读-改-写。
     *  供直接改写同一文件的程序（MakeCert 删除旧登记行 / Auto 吊销）复用，
     *  避免与 CertsDB.addEntry/rewriteAll 互相用旧快照覆盖对方的新记录。 */
    public static void withCertsLock(String baseDir, Runnable action) {
        withFileLock(Paths.get(baseDir, "PKI", "CERTS.txt"), action);
    }

    private static void withFileLock(Path certsPath, Runnable action) {
        synchronized (FILE_LOCK) {
            Path lockPath = Paths.get(certsPath.toString() + ".lock");
            try (FileChannel lc = FileChannel.open(lockPath,
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                 FileLock fl = lc.lock()) {
                if (!fl.isValid()) {
                    throw new IOException("lock invalid: " + lockPath);
                }
                action.run();
            } catch (IOException ex) {
                throw new java.io.UncheckedIOException("lock CERTS.txt failed: " + lockPath, ex);
            }
        }
    }

    /**
     * 单条证书台账记录。
     */
    public static class CertEntry {
        /** 证书序列号（hex，小写，无冒号） */
        public String serial;
        /** 类型：R / C / E */
        public char type;
        /** 状态：V / R / N */
        public char status;
        /** 吊销原因码（未吊销为 0） */
        public int reason;
        /** 时间 */
        public LocalDateTime time;
        /** 颁发者序列号 */
        public String issuerId;
        /** 算法：RSA / ECC / SM2 */
        public String algo;
    }

    /**
     * 加载 &lt;baseDir&gt;/PKI/CERTS.txt。
     *
     * @param baseDir MODPKICA 根目录
     */
    public void load(String baseDir) {
        Path path = Paths.get(baseDir, "PKI", "CERTS.txt");
        dbPath = path;
        List<CertEntry> newEntries = new ArrayList<>();
        List<String> newPreserved = new ArrayList<>();
        String warning = "";
        if (Files.exists(path)) {
            List<String> lines;
            try {
                lines = Files.readAllLines(path, StandardCharsets.UTF_8);
            } catch (IOException e) {
                warning = "CERTS.txt 读取失败: " + e;
                System.err.println("[CertsDB] " + warning);
                lines = null;
            }
            if (lines != null) {
                int bad = 0;
                for (String raw : lines) {
                    String line = stripCrLf(raw).trim();
                    // 防御 UTF-8 BOM：外部工具（如记事本/PowerShell）可能写入 BOM，剥掉后注释行才能被识别
                    if (!line.isEmpty() && line.charAt(0) == '\uFEFF') {
                        line = line.substring(1).trim();
                    }
                    if (line.isEmpty() || line.startsWith("#")) {
                        // 保留注释/空行：重写文件时不丢失（用户"删除=行首 # 注释"语义）
                        newPreserved.add(raw);
                        continue;
                    }
                    // 按空白切分：serial type status reason time issuerId algo
                    String[] p = line.split("\\s+");
                    if (p.length < 7) {
                        bad++;
                        continue;
                    }
                    try {
                        CertEntry e = new CertEntry();
                        e.serial = p[0];
                        e.type = p[1].charAt(0);
                        e.status = p[2].charAt(0);
                        e.reason = Integer.parseInt(p[3]);
                        e.time = LocalDateTime.parse(p[4], TIME_FMT);
                        e.issuerId = p[5];
                        e.algo = p[6];
                        newEntries.add(e);
                    } catch (Exception ignore) {
                        bad++;
                    }
                }
                if (bad > 0) {
                    warning = "CERTS.txt 有 " + bad + " 行无法解析（已跳过）";
                    System.err.println("[CertsDB] " + warning);
                }
            }
        }
        // 整体替换引用：并发读者要么看到旧快照、要么看到新快照，绝不会看到空表/半表
        entries = newEntries;
        preservedLines = newPreserved;
        lastLoadWarning = warning;
    }

    /** 重新从磁盘加载（外部修改后调用）。 */
    public void reload() {
        if (dbPath == null) {
            return;
        }
        String baseDir = dbPath.getParent().getParent().toString();
        load(baseDir);
    }

    /** 按序列号查找条目。
     *
     * @param serial 证书序列号
     * @return 命中的条目，未命中返回 null
     */
    public CertEntry findBySerial(String serial) {
        if (serial == null) {
            return null;
        }
        for (CertEntry e : entries) {
            if (e.serial.equalsIgnoreCase(serial)) {
                return e;
            }
        }
        return null;
    }

    /**
     * 按颁发者序列号 + 证书序列号查找（issuer+serial 才是全局唯一键）。
     *
     * @param issuerId 颁发者序列号
     * @param serial   证书序列号
     * @return 命中的条目，未命中返回 null
     */
    public CertEntry findByIssuerAndSerial(String issuerId, String serial) {
        if (issuerId == null || serial == null) {
            return null;
        }
        for (CertEntry e : entries) {
            if (serial.equalsIgnoreCase(e.serial)
                    && issuerId.equalsIgnoreCase(e.issuerId)) {
                return e;
            }
        }
        return null;
    }

    /**
     * 按序列号查找其颁发者序列号。
     *
     * @param serial 证书序列号
     * @return 颁发者序列号；找不到时返回 "null"（与 Go 版字符串约定一致）
     */
    public String findIssuerIdBySerial(String serial) {
        CertEntry e = findBySerial(serial);
        if (e == null) {
            return "null";
        }
        return e.issuerId == null ? "null" : e.issuerId;
    }

    /**
     * 追加一条新条目到内存并写回 CERTS.txt 文件末尾。
     * 内存 add 与文件写同在锁内，保证并发追加不会出现内存/磁盘不一致。
     *
     * @param e 新条目
     */
    public void addEntry(CertEntry e) {
        String line = formatLine(e);
        withLock(() -> {
            try {
                Files.createDirectories(dbPath.getParent());
                Files.writeString(dbPath, line + System.lineSeparator(),
                        StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE,
                        StandardOpenOption.APPEND);
            } catch (IOException ex) {
                // 写文件失败必须暴露：否则内存记录与磁盘不一致（重启后记录丢失）
                throw new java.io.UncheckedIOException("写 CERTS.txt 失败: " + dbPath, ex);
            }
            // 写成功后才加入内存（锁内整体替换，避免并发 add 丢条目）
            List<CertEntry> copy = new ArrayList<>(entries);
            copy.add(e);
            entries = copy;
        });
    }

    /**
     * 把指定序列号证书状态改为 R（吊销），更新原因与时间，并整文件重写。
     * 内存采用"新对象替换"而非改字段，读方不会看到半更新状态。
     * 内存替换与文件重写在同一把锁内完成，避免并发下用旧快照覆盖新增记录。
     *
     * @param serial 证书序列号
     * @param reason 吊销原因码
     * @param time   吊销时间
     */
    public void revokeCert(String serial, int reason, LocalDateTime time) {
        withLock(() -> {
            CertEntry e = findBySerial(serial);
            if (e == null) {
                return;
            }
            CertEntry n = cloneEntry(e);
            n.status = 'R';
            n.reason = reason;
            n.time = time;
            int idx = entries.indexOf(e);
            if (idx >= 0) {
                List<CertEntry> copy = new ArrayList<>(entries);
                copy.set(idx, n);
                entries = copy;
            }
            rewriteAllLocked();
        });
    }

    /**
     * 返回所有类型为 R（根）或 C（中间 CA）的条目。
     */
    public List<CertEntry> getAllRootAndCA() {
        List<CertEntry> out = new ArrayList<>();
        for (CertEntry e : entries) {
            if (e.type == 'R' || e.type == 'C') {
                out.add(e);
            }
        }
        return out;
    }

    /**
     * 返回所有状态为 R（吊销）的条目。
     */
    public List<CertEntry> getAllRevoked() {
        List<CertEntry> out = new ArrayList<>();
        for (CertEntry e : entries) {
            if (e.status == 'R') {
                out.add(e);
            }
        }
        return out;
    }

    /** 返回全部条目（只读快照，调用方修改不影响库内数据）。 */
    public List<CertEntry> getAll() {
        return new ArrayList<>(entries);
    }

    /** 复制条目（吊销/恢复时以新对象替换旧对象，避免读方看到半更新字段）。 */
    private static CertEntry cloneEntry(CertEntry e) {
        CertEntry n = new CertEntry();
        n.serial = e.serial;
        n.type = e.type;
        n.status = e.status;
        n.reason = e.reason;
        n.time = e.time;
        n.issuerId = e.issuerId;
        n.algo = e.algo;
        return n;
    }

    /** 把内存中全部条目按行重写回文件（P2-01：tmp → fsync → .bak → 原子替换，锁内执行）。
     *  注释/空行（preservedLines）按原顺序写回最前，保证"行首 # 注释"的删除语义不被重写抹掉。 */
    private void rewriteAll() {
        withLock(this::rewriteAllLocked);
    }

    /** 必须在 withLock 内调用：快照取自锁内，避免"先取快照后进锁"期间并发写入被旧快照覆盖。 */
    private void rewriteAllLocked() {
        StringBuilder sb = new StringBuilder();
        for (String cl : preservedLines) {
            sb.append(cl).append(System.lineSeparator());
        }
        for (CertEntry e : entries) {
            sb.append(formatLine(e)).append(System.lineSeparator());
        }
        String content = sb.toString();
        Path tmp = Paths.get(dbPath.toString() + ".tmp");
        try {
            Files.writeString(tmp, content, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING);
            // fsync 落盘，避免断电/崩溃后半文件
            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(tmp.toString(), true)) {
                fos.getFD().sync();
            }
            // 保留 .bak 备份
            if (Files.exists(dbPath)) {
                Files.copy(dbPath, Paths.get(dbPath.toString() + ".bak"),
                        StandardCopyOption.REPLACE_EXISTING);
            }
            Files.move(tmp, dbPath, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException ex) {
            throw new java.io.UncheckedIOException("rewrite CERTS.txt failed: " + dbPath, ex);
        }
    }

    /** 把条目格式化为文件中的一行（不补换行）。 */
    private static String formatLine(CertEntry e) {
        String timeStr = e.time == null
                ? LocalDateTime.now().format(TIME_FMT)
                : e.time.format(TIME_FMT);
        return e.serial + " " + e.type + " " + e.status + " " + e.reason
                + " " + timeStr + " " + e.issuerId + " " + e.algo;
    }

    /** 去掉行尾 \r\n。 */
    private static String stripCrLf(String s) {
        int end = s.length();
        while (end > 0) {
            char c = s.charAt(end - 1);
            if (c == '\r' || c == '\n') {
                end--;
            } else {
                break;
            }
        }
        return s.substring(0, end);
    }
}
