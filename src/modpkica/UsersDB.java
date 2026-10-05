package modpkica;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

/**
 * PKI/USERS.txt —— RADIUS 用户账号库（明文存储，遵循项目"文件不加密"约定）。
 *
 * <p>文件格式（空格分隔；# 注释行 / 空行按原顺序保留在文件最前）：
 * <pre>
 *   # MODPKICA RADIUS 用户库
 *   # 字段顺序: 用户名 密码 状态 组 备注   (状态: E=启用 D=停用)
 *   # 删除 = 行首加 # 注释（不真正删除，与 CERTS.txt 惯例一致）
 *   alice 123456 E users 测试账号
 * </pre>
 *
 * <p>用户名 / 密码 / 组 不允许包含空白；备注允许空格（解析时前 4 个字段切分后剩余全部并入备注）。
 * 线程安全：公开方法内部 synchronized；写文件走 tmp → 原子替换（保留 .bak 备份）。
 */
public class UsersDB {

    public static final String FILE_NAME = "USERS.txt";

    private static final Object GLOBAL_LOCK = new Object();

    /** 单个用户记录。 */
    public static final class User {
        public final String username;
        public final String password;
        public final String state;   // "E"=启用 / "D"=停用
        public final String group;
        public final String note;

        public User(String username, String password, String state, String group, String note) {
            this.username = username == null ? "" : username.trim();
            this.password = password == null ? "" : password;
            this.state = (state == null || state.trim().isEmpty()) ? "E" : state.trim().toUpperCase();
            this.group = group == null || group.trim().isEmpty() ? "users" : group.trim();
            this.note = note == null ? "" : note.trim();
        }

        public boolean enabled() {
            return "E".equals(state);
        }

        /** 序列化为文件行：前 4 个字段空白符压缩，备注保留原样。 */
        public String toLine() {
            return sanitize(username) + " " + sanitize(password) + " " + state + " " + sanitize(group) + " " + note;
        }

        private static String sanitize(String s) {
            return s == null ? "" : s.replaceAll("\\s+", "_");
        }
    }

    private UsersDB() {
    }

    /** 返回 USERS.txt 完整路径。 */
    public static Path filePath(String baseDir) {
        return Paths.get(baseDir, "PKI", FILE_NAME);
    }

    /** 若文件不存在则创建带表头模板。 */
    public static void ensureFile(String baseDir) {
        synchronized (GLOBAL_LOCK) {
            try {
                Path p = filePath(baseDir);
                if (!Files.exists(p)) {
                    Files.createDirectories(p.getParent());
                    Files.writeString(p, header(), StandardCharsets.UTF_8);
                }
            } catch (Exception e) {
                throw new IllegalStateException("创建 USERS.txt 失败: " + e);
            }
        }
    }

    private static String header() {
        return "# MODPKICA RADIUS 用户库\n"
                + "# 字段顺序: 用户名 密码 状态 组 备注   (状态: E=启用 D=停用)\n"
                + "# 删除 = 行首加 # 注释（不真正删除）\n";
    }

    /** 加载全部启用 + 停用用户（跳过 # 注释与空行），未创建文件时自动创建。 */
    public static List<User> load(String baseDir) {
        synchronized (GLOBAL_LOCK) {
            ensureFile(baseDir);
            List<User> out = new ArrayList<>();
            try {
                List<String> lines = Files.readAllLines(filePath(baseDir), StandardCharsets.UTF_8);
                for (String raw : lines) {
                    String line = raw.trim();
                    if (line.isEmpty() || line.startsWith("#")) {
                        continue;
                    }
                    // 前 4 个字段切分，剩余全部并入备注
                    String[] parts = line.split("\\s+", 5);
                    if (parts.length < 2) {
                        continue; // 无效行跳过
                    }
                    String username = parts[0];
                    String password = parts[1];
                    String state = parts.length > 2 ? parts[2] : "E";
                    String group = parts.length > 3 ? parts[3] : "users";
                    String note = parts.length > 4 ? parts[4] : "";
                    out.add(new User(username, password, state, group, note));
                }
            } catch (Exception e) {
                throw new IllegalStateException("读取 USERS.txt 失败: " + e);
            }
            return out;
        }
    }

    /** 按用户名查找；不存在返回 null。 */
    public static User find(String baseDir, String username) {
        if (username == null) {
            return null;
        }
        String target = username.trim();
        for (User u : load(baseDir)) {
            if (u.username.equalsIgnoreCase(target)) {
                return u;
            }
        }
        return null;
    }

    /** 用户名是否已存在（含停用与已注释删除的记录）。 */
    public static boolean exists(String baseDir, String username) {
        synchronized (GLOBAL_LOCK) {
            try {
                List<String> lines = Files.readAllLines(filePath(baseDir), StandardCharsets.UTF_8);
                for (String raw : lines) {
                    String line = raw.trim();
                    if (line.isEmpty() || line.startsWith("#")) {
                        continue;
                    }
                    String[] parts = line.split("\\s+", 2);
                    if (parts.length > 0 && parts[0].equalsIgnoreCase(username.trim())) {
                        return true;
                    }
                }
            } catch (Exception ignored) {
            }
            return false;
        }
    }

    /** 新增用户；用户名重复抛 IllegalArgumentException。 */
    public static void add(String baseDir, String username, String password, String state, String group, String note) {
        synchronized (GLOBAL_LOCK) {
            ensureFile(baseDir);
            String name = username == null ? "" : username.trim();
            if (name.isEmpty()) {
                throw new IllegalArgumentException("用户名不能为空");
            }
            if (password == null || password.isEmpty()) {
                throw new IllegalArgumentException("密码不能为空");
            }
            if (exists(baseDir, name)) {
                throw new IllegalArgumentException("用户名已存在: " + name);
            }
            User u = new User(name, password, state, group, note);
            try {
                Files.writeString(filePath(baseDir), u.toLine() + "\n", StandardCharsets.UTF_8,
                        java.nio.file.StandardOpenOption.APPEND);
            } catch (Exception e) {
                throw new IllegalStateException("写入 USERS.txt 失败: " + e);
            }
        }
    }

    /** 修改用户（按原用户名定位；可改用户名/密码/状态/组/备注）。 */
    public static void update(String baseDir, String oldUsername, String username, String password,
                              String state, String group, String note) {
        synchronized (GLOBAL_LOCK) {
            ensureFile(baseDir);
            String oldName = oldUsername == null ? "" : oldUsername.trim();
            if (oldName.isEmpty()) {
                throw new IllegalArgumentException("缺少原用户名");
            }
            String newName = username == null ? "" : username.trim();
            if (newName.isEmpty()) {
                throw new IllegalArgumentException("用户名不能为空");
            }
            if (!newName.equalsIgnoreCase(oldName) && exists(baseDir, newName)) {
                throw new IllegalArgumentException("用户名已存在: " + newName);
            }
            try {
                Path p = filePath(baseDir);
                List<String> lines = Files.readAllLines(p, StandardCharsets.UTF_8);
                boolean hit = false;
                List<String> preserved = new ArrayList<>();
                List<String> entries = new ArrayList<>();
                for (String raw : lines) {
                    String line = raw.trim();
                    if (line.isEmpty() || line.startsWith("#")) {
                        preserved.add(raw);
                        continue;
                    }
                    String[] parts = line.split("\\s+", 2);
                    if (parts.length > 0 && parts[0].equalsIgnoreCase(oldName)) {
                        User u = new User(newName, password, state, group, note);
                        entries.add(u.toLine());
                        hit = true;
                    } else {
                        entries.add(raw);
                    }
                }
                if (!hit) {
                    throw new IllegalArgumentException("未找到用户: " + oldName);
                }
                rewrite(p, preserved, entries);
            } catch (IllegalArgumentException e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException("修改用户失败: " + e);
            }
        }
    }

    /** 删除用户 = 行首加 "# " 注释（保留原行内容，不真删）。 */
    public static void remove(String baseDir, String username) {
        synchronized (GLOBAL_LOCK) {
            ensureFile(baseDir);
            String name = username == null ? "" : username.trim();
            if (name.isEmpty()) {
                throw new IllegalArgumentException("缺少用户名");
            }
            try {
                Path p = filePath(baseDir);
                List<String> lines = Files.readAllLines(p, StandardCharsets.UTF_8);
                boolean hit = false;
                List<String> preserved = new ArrayList<>();
                List<String> entries = new ArrayList<>();
                for (String raw : lines) {
                    String line = raw.trim();
                    if (line.isEmpty() || line.startsWith("#")) {
                        preserved.add(raw);
                        continue;
                    }
                    String[] parts = line.split("\\s+", 2);
                    if (parts.length > 0 && parts[0].equalsIgnoreCase(name)) {
                        entries.add("# " + raw);   // 注释式删除
                        hit = true;
                    } else {
                        entries.add(raw);
                    }
                }
                if (!hit) {
                    throw new IllegalArgumentException("未找到用户: " + name);
                }
                rewrite(p, preserved, entries);
            } catch (IllegalArgumentException e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException("删除用户失败: " + e);
            }
        }
    }

    /** 启用 / 停用切换（状态字段改 E/D）。 */
    public static void setState(String baseDir, String username, boolean enabled) {
        synchronized (GLOBAL_LOCK) {
            ensureFile(baseDir);
            String name = username == null ? "" : username.trim();
            if (name.isEmpty()) {
                throw new IllegalArgumentException("缺少用户名");
            }
            try {
                Path p = filePath(baseDir);
                List<String> lines = Files.readAllLines(p, StandardCharsets.UTF_8);
                boolean hit = false;
                List<String> preserved = new ArrayList<>();
                List<String> entries = new ArrayList<>();
                for (String raw : lines) {
                    String line = raw.trim();
                    if (line.isEmpty() || line.startsWith("#")) {
                        preserved.add(raw);
                        continue;
                    }
                    String[] parts = line.split("\\s+", 5);
                    if (parts.length > 0 && parts[0].equalsIgnoreCase(name)) {
                        User u = new User(parts[0],
                                parts.length > 1 ? parts[1] : "",
                                enabled ? "E" : "D",
                                parts.length > 3 ? parts[3] : "users",
                                parts.length > 4 ? parts[4] : "");
                        entries.add(u.toLine());
                        hit = true;
                    } else {
                        entries.add(raw);
                    }
                }
                if (!hit) {
                    throw new IllegalArgumentException("未找到用户: " + name);
                }
                rewrite(p, preserved, entries);
            } catch (IllegalArgumentException e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException("修改用户状态失败: " + e);
            }
        }
    }

    /** 原子重写：注释/空行在前（原顺序），条目行随后；tmp → .bak → move。 */
    private static void rewrite(Path p, List<String> preserved, List<String> entries) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (String s : preserved) {
            sb.append(s).append('\n');
        }
        for (String s : entries) {
            sb.append(s).append('\n');
        }
        Path tmp = Paths.get(p.toString() + ".tmp");
        Path bak = Paths.get(p.toString() + ".bak");
        Files.writeString(tmp, sb.toString(), StandardCharsets.UTF_8);
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(tmp.toString(), true)) {
            fos.getFD().sync();
        }
        if (Files.exists(bak)) {
            Files.delete(bak);
        }
        Files.move(p, bak, StandardCopyOption.REPLACE_EXISTING);
        Files.move(tmp, p, StandardCopyOption.REPLACE_EXISTING);
    }
}
