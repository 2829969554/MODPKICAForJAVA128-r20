package modpkica;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.encoders.Hex;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSDocument;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSObjectKey;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * SignTool —— 签名专区（微软代码签名 + PDF 文档签名）。
 *
 * <p><b>1) 微软代码签名（Windows Authenticode）</b>：
 * 对齐 signtool 标准结构，手动构造 ASN.1（不经 BC CMS 生成器，避免 OCTET STRING 包装 /
 * signingTime / SpcIndirectData 标签不合规）：
 * <ul>
 *   <li>encapContentInfo.contentType = 1.3.6.1.4.1.311.2.1.4 (spcIndirectDataContext)</li>
 *   <li>eContent = [0] EXPLICIT SpcIndirectDataContent（直接 SEQUENCE，无 OCTET STRING 包装）</li>
 *   <li>SpcPeImageData.file = [0] EXPLICIT → [2] EXPLICIT → SpcString(空 80 00)（对齐 signtool 标准）</li>
 *   <li>SpcAttributeTypeAndOptionalValue.value = 直接 SEQUENCE（微软实测，无 [0] 包装）</li>
 *   <li>DigestInfo = AlgorithmIdentifier(摘要OID, NULL) + 文件哈希（parameters 必须带 NULL）</li>
 *   <li>signedAttrs = { contentType, messageDigest }，messageDigest = hash(SpcIndirectData 内容字节)</li>
 *   <li>签名算法：SM2 → SM3withSM2；RSA → SHA256withRSA；ECC → SHA256withECDSA</li>
 *   <li>certificates = 链按根在前顺序（[根 … 叶子]）</li>
 *   <li>RFC3161 时间戳：messageImprint = SHA-256(签名值)，请求本机 MAIN /rfc3161，
 *       以 SPC_RFC3161_TS (1.3.6.1.4.1.311.3.3.1) 作为 unsignedAttr 嵌入；失败降级不影响签名</li>
 * </ul>
 *
 * <p><b>2) PDF 文档签名</b>：标准 PKCS#7 detached（adbe.pkcs7.detached），PDFBox 3.0.4 外部签名
 * 两段式；可选可见签章（png/jpg/bmp/gif 图片作为印章外观）。
 */
public final class SignTool {

    static {
        Bc.init();
    }

    private SignTool() {
    }

    // ============================ OID 常量 ============================

    /** spcIndirectDataContext：Authenticode 的 encapContentInfo.contentType */
    public static final String OID_SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4";
    /** SpcPeImageData */
    public static final String OID_SPC_PE_IMAGE_DATA = "1.3.6.1.4.1.311.2.1.15";
    /** Authenticode 时间戳属性（RFC3161 timestamp） */
    public static final String OID_SPC_RFC3161_TS = "1.3.6.1.4.1.311.3.3.1";

    // ---- 国密 PDF 电子签章（GB/T 35275-2017 / GB/T 38540-2020）----
    /** SM3 摘要算法 OID */
    public static final String OID_SM3 = "1.2.156.10197.1.401";
    /** SM2withSM3 签名算法 OID */
    public static final String OID_SM2 = "1.2.156.10197.1.501";
    /** 政务体系私有扩展 OID（SESeal / 印章承载，GB/T 38540 extDatas / 35275 signedAttrs） */
    public static final String OID_GOV_EXT = "1.2.156.112600.8.1";
    /** id-aa-timeStampToken（CAdES-T/PAdES-T 签名时间戳：SignerInfo unsignedAttrs） */
    public static final String OID_TSA_TOKEN = "1.2.840.113549.1.9.16.2.14";
    /** PDF 国密签章 SubFilter（GB/T 38540-2020：SES_Signature 结构） */
    public static final String SUBFILTER_GM_SEAL = "GM.sm2seal";
    /** PDF 国密签章 SubFilter（GB/T 35275-2017：CMS SignedData + 私有 OID 印章） */
    public static final String SUBFILTER_GM_CMS = "GM.sm2cms.detached";
    /** PAdES 文档时间戳 SubFilter（RFC 3161 TimeStampToken 独立签名）。 */
    public static final String SUBFILTER_ETSI_RFC3161 = "ETSI.RFC3161";

    /** 最近一次 EXE 签名的时间戳状态（供上层展示日志）。 */
    public static volatile String lastTsInfo = "未请求";

    /** 代码签名相关 EKU（用于证书筛选） */
    public static final String EKU_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";      // 代码签名
    public static final String EKU_KERNEL_MODE = "1.3.6.1.4.1.311.61.1.1";   // 内核模式代码签名
    public static final String EKU_DRIVER_VERIFY = "1.3.6.1.4.1.311.10.3.5"; // Windows 硬件驱动程序验证
    public static final String EKU_SYS_COMPONENT = "1.3.6.1.4.1.311.10.3.6"; // Windows 系统组件验证
    public static final String EKU_OEM_SYS = "1.3.6.1.4.1.311.10.3.7";       // OEM 系统组件
    public static final String EKU_EMBED_SYS = "1.3.6.1.4.1.311.10.3.8";     // 内嵌系统组件
    public static final String EKU_DOC_MICROSOFT = "1.3.6.1.4.1.311.10.3.12";// 微软文档签名
    public static final String EKU_DOC_GENERIC = "1.3.6.1.5.5.7.3.36";       // 通用文档签名

    /** 判定证书是否可用于代码签名（EKU 含标准或微软代码签名 OID）。 */
    public static boolean isCodeSignCert(X509Certificate cert) {
        Set<String> ekus = ekusOf(cert);
        if (ekus == null || ekus.isEmpty()) {
            return false;
        }
        return ekus.contains(EKU_CODE_SIGNING)
                || ekus.contains(EKU_KERNEL_MODE)
                || ekus.contains(EKU_DRIVER_VERIFY)
                || ekus.contains(EKU_SYS_COMPONENT)
                || ekus.contains(EKU_OEM_SYS)
                || ekus.contains(EKU_EMBED_SYS);
    }

    /** 判定证书是否可用于 PDF 文档签名（EKU 含微软文档签名或通用文档签名 OID 即可）。 */
    public static boolean isDocSignCert(X509Certificate cert) {
        Set<String> ekus = ekusOf(cert);
        if (ekus == null || ekus.isEmpty()) {
            return false;
        }
        return ekus.contains(EKU_DOC_MICROSOFT)
                || ekus.contains(EKU_DOC_GENERIC);
    }

    /** 读取证书 EKU OID 集合（无 EKU 扩展返回空集合）。 */
    public static Set<String> ekusOf(X509Certificate cert) {
        try {
            List<String> ext = cert.getExtendedKeyUsage();
            if (ext == null) {
                return Collections.emptySet();
            }
            return new HashSet<>(ext);
        } catch (Exception e) {
            return Collections.emptySet();
        }
    }

    /** 证书密钥位数（RSA modulus bit 数；ECC/SM2 曲线位宽）。 */
    public static int keyBits(X509Certificate cert) {
        try {
            java.security.PublicKey pk = cert.getPublicKey();
            if (pk instanceof java.security.interfaces.RSAPublicKey) {
                return ((java.security.interfaces.RSAPublicKey) pk).getModulus().bitLength();
            }
            if (pk instanceof java.security.interfaces.ECPublicKey) {
                return ((java.security.interfaces.ECPublicKey) pk).getParams().getCurve().getField().getFieldSize();
            }
        } catch (Exception ignored) {
        }
        return 0;
    }

    // ============================ 证书 / 密钥 / 链加载 ============================

    /** 按序列号从 CERTS.txt 台账定位并加载证书（R→ROOT、C→CA、E→CERT，兜底 WebPublic/CRT）。 */
    public static X509Certificate loadCertBySerial(String baseDir, String serial) throws Exception {
        String p = certFilePath(baseDir, serial);
        if (p == null) {
            throw new IllegalArgumentException("未找到证书 " + serial + "（CERTS.txt 无记录或文件缺失）");
        }
        return PemIO.readCert(p);
    }

    /** 按序列号加载私钥（R→ROOT、C→CA、E→KEY）。 */
    public static PrivateKey loadKeyBySerial(String baseDir, String serial) throws Exception {
        CertsDB db = new CertsDB();
        db.load(baseDir);
        CertsDB.CertEntry e = db.findBySerial(serial);
        String dir;
        if (e == null) {
            dir = null;
        } else if (e.type == 'R') {
            dir = "ROOT";
        } else if (e.type == 'C') {
            dir = "CA";
        } else {
            dir = "KEY";
        }
        String p = null;
        if (dir != null) {
            Path path = Paths.get(baseDir, "PKI", dir, serial + ".key");
            if (Files.exists(path)) {
                p = path.toString();
            }
        }
        if (p == null) {
            for (String d : new String[]{"KEY", "ROOT", "CA"}) {
                Path path = Paths.get(baseDir, "PKI", d, serial + ".key");
                if (Files.exists(path)) {
                    p = path.toString();
                    break;
                }
            }
        }
        if (p == null) {
            throw new IllegalArgumentException("未找到私钥 " + serial + ".key");
        }
        return CertUtil.readJcaPrivateKey(p);
    }

    /** 按序列号加载完整证书链（签名证书 + 按 CERTS.txt 颁发者关系逐级上级，直到自签根）。 */
    public static List<X509Certificate> loadChain(String baseDir, String serial) throws Exception {
        CertsDB db = new CertsDB();
        db.load(baseDir);
        List<X509Certificate> chain = new ArrayList<>();
        String cur = serial;
        Set<String> seen = new HashSet<>();
        int guard = 0;
        while (cur != null && guard++ < 32 && seen.add(cur)) {
            String p = certFilePath(baseDir, cur);
            if (p == null) {
                break;
            }
            chain.add(PemIO.readCert(p));
            CertsDB.CertEntry e = db.findBySerial(cur);
            if (e == null) {
                break;
            }
            String issuer = e.issuerId;
            if (issuer == null || issuer.isEmpty() || issuer.equalsIgnoreCase(cur)) {
                break;
            }
            cur = issuer;
        }
        return chain;
    }

    private static String certFilePath(String baseDir, String serial) {
        CertsDB db = new CertsDB();
        db.load(baseDir);
        CertsDB.CertEntry e = db.findBySerial(serial);
        if (e != null) {
            String dir = e.type == 'R' ? "ROOT" : (e.type == 'C' ? "CA" : "CERT");
            Path p = Paths.get(baseDir, "PKI", dir, serial + ".crt");
            if (Files.exists(p)) {
                return p.toString();
            }
        }
        for (String d : new String[]{"ROOT", "CA", "CERT", "WebPublic/CRT"}) {
            Path p = Paths.get(baseDir, "PKI", d, serial + ".crt");
            if (Files.exists(p)) {
                return p.toString();
            }
        }
        return null;
    }

    // ============================ 摘要 / 签名算法推导 ============================

    /** 密钥类型 → 摘要名（"SHA256" / "SM3"）。 */
    public static String digestName(String keyType) {
        return "SM2".equalsIgnoreCase(keyType) ? "SM3" : "SHA256";
    }

    /** 密钥类型 → JCA 摘要算法名。 */
    public static String digestJca(String keyType) {
        return "SM2".equalsIgnoreCase(keyType) ? "SM3" : "SHA-256";
    }

    /** 密钥类型 → 摘要算法 OID。 */
    public static String digestOid(String keyType) {
        return "SM2".equalsIgnoreCase(keyType) ? Sm2Util.OID_SM3 : "2.16.840.1.101.3.4.2.1";
    }

    /** 密钥类型 → 签名算法 OID（Authenticode SignerInfo.signatureAlgorithm）。 */
    public static String sigAlgOid(String keyType) {
        if ("SM2".equalsIgnoreCase(keyType)) {
            return "1.2.156.10197.1.501";          // SM3withSM2
        }
        if ("ECC".equalsIgnoreCase(keyType)) {
            return "1.2.840.10045.4.3.2";          // ecdsa-with-SHA256
        }
        return "1.2.840.113549.1.1.1";             // rsaEncryption
    }

    /** 密钥类型 → JCA 签名算法名。 */
    public static String jcaSigAlg(String keyType) {
        if ("SM2".equalsIgnoreCase(keyType)) {
            return "SM3withSM2";
        }
        if ("ECC".equalsIgnoreCase(keyType)) {
            return "SHA256withECDSA";
        }
        return "SHA256withRSA";
    }

    /** 摘要算法 OID → JCA 名（验证时从 CMS 读取）。 */
    private static String digestJcaFromOid(String oid) {
        if (oid == null) {
            return "SHA-256";
        }
        switch (oid) {
            case "1.3.14.3.2.26":
                return "SHA-1";
            case "2.16.840.1.101.3.4.2.2":
                return "SHA-384";
            case "2.16.840.1.101.3.4.2.3":
                return "SHA-512";
            case Sm2Util.OID_SM3:
                return "SM3";
            case "2.16.840.1.101.3.4.2.1":
            default:
                return "SHA-256";
        }
    }

    /** 签名算法 OID → JCA 名（验证时使用）。 */
    private static String jcaSigFromOid(String oid) {
        if (oid == null) {
            return "SHA256withRSA";
        }
        switch (oid) {
            case "1.2.156.10197.1.501":
                return "SM3withSM2";
            case "1.2.840.10045.4.3.2":
            case "1.2.840.10045.4.3.1":
                return "SHA256withECDSA";
            case "1.2.840.113549.1.1.1":
            case "1.2.840.113549.1.1.11":
            case "1.2.840.113549.1.1.13":
            default:
                return "SHA256withRSA";
        }
    }

    // ============================ EXE Authenticode 签名 ============================

    /**
     * 对 PE 文件（exe/dll/sys）做 Windows Authenticode 代码签名。
     * 结构对齐 signtool 标准：手动 ASN.1（直接 SEQUENCE eContent、signedAttrs={contentType,messageDigest}、
     * DigestInfo 带 NULL、SpcPeImageData 空 SpcLink），并自动请求时间戳嵌入。
     *
     * @param file     原始 PE 字节
     * @param keyType  RSA / ECC / SM2
     * @param cert     签名证书
     * @param key      签名私钥
     * @param chain    证书链（含签名证书，顺序任意，写入时自动根在前）
     * @param baseDir  PKI 基目录（读 CONFIG.txt 的 WEBPORT 定位本机 TSA）
     * @return 已签名 PE 字节
     */
    public static byte[] signExe(byte[] file, String keyType,
                                 X509Certificate cert, PrivateKey key,
                                 List<X509Certificate> chain, String baseDir) throws Exception {
        return signExe(file, keyType, cert, key, chain, baseDir, "RFC3161", null);
    }

    /**
     * 对 PE 文件做 Authenticode 签名（可指定时间戳类型与地址）。
     *
     * @param tsType RFC3161（标准 TimeStampToken，默认）/ AUTHENTICODE（微软老式 PKCS#7 时间戳）
     * @param tsUrl  时间戳请求地址；null/空 = 默认本机 MAIN（RFC3161→/rfc3161，Authenticode→/timestamp）
     */
    public static byte[] signExe(byte[] file, String keyType,
                                 X509Certificate cert, PrivateKey key,
                                 List<X509Certificate> chain, String baseDir,
                                 String tsType, String tsUrl) throws Exception {
        if (file.length < 0x40 || file[0] != 'M' || file[1] != 'Z') {
            throw new IllegalArgumentException("不是有效 PE 文件（缺 MZ 头）");
        }
        long eLfanew = readU32(file, 0x3C);
        // PE 头偏移来自文件内容，必须做边界校验：畸形文件会让 readU16/writeU32
        // 越界（ArrayIndexOutOfBoundsException）而不是给出可读的错误信息
        if (eLfanew <= 0 || eLfanew + 24 + 2 > file.length) {
            throw new IllegalArgumentException("PE 头偏移非法（e_lfanew=" + eLfanew
                    + "，文件长度 " + file.length + "）");
        }
        int magic = readU16(file, (int) eLfanew + 24);
        if (magic != 0x10B && magic != 0x20B) {
            throw new IllegalArgumentException("无法识别的 PE 魔术字: 0x" + Integer.toHexString(magic));
        }
        boolean is64 = magic == 0x20B;
        int dataDirStart = is64 ? 112 : 96;
        long checksumOff = eLfanew + 24 + 64;                              // OptionalHeader.Checksum
        long secDirOff = eLfanew + 24 + dataDirStart + 4 * 8;              // DataDirectory[4] Certificate Table
        // Security Directory（8 字节）必须落在文件内，后续 writeU32 才能安全写入
        if (secDirOff + 8 > file.length) {
            throw new IllegalArgumentException("PE 可选头截断：安全目录偏移 " + secDirOff
                    + " 超出文件长度 " + file.length);
        }

        // 证书表起始 = 原文件长度 8 字节对齐
        long certTableOffset = (file.length + 7) & ~7L;

        // 先把 Security Directory 8 字节写入 header（占位 size=0）
        byte[] exe = Arrays.copyOf(file, file.length);
        writeU32(exe, (int) secDirOff, (int) certTableOffset);
        writeU32(exe, (int) secDirOff + 4, 0);

        // 计算 Authenticode 文件哈希
        MessageDigest md = MessageDigest.getInstance(digestJca(keyType));
        authenticodeDigest(md, exe, checksumOff, secDirOff, certTableOffset, 0);
        byte[] fileHash = md.digest();

        // 构建 SpcIndirectDataContent（对齐 signtool 标准结构）
        byte[] spcIndirectData = buildSpcIndirectData(fileHash, digestOid(keyType));

        // 手写 CMS SignedData（对齐 signtool，eContent 直接 SEQUENCE）
        byte[] signedData = buildExeCms(spcIndirectData, keyType, cert, key, chain,
                baseDir, tsType, tsUrl);

        // WIN_CERTIFICATE 表：头 8 字节 + CMS，8 字节对齐
        long certHeaderLen = 8;
        long certTableSize = ((certHeaderLen + signedData.length + 7) & ~7L);
        writeU32(exe, (int) secDirOff + 4, (int) certTableSize);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(exe);
        for (long i = file.length; i < certTableOffset; i++) {
            out.write(0);
        }
        writeU32(out, (int) certTableSize);  // dwLength（含头、对齐后总长）
        writeU16(out, 0x0200);               // wRevision = WIN_CERT_REVISION_2_0
        writeU16(out, 0x0002);               // wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA
        out.write(signedData);
        while ((out.size() & 7) != 0) {
            out.write(0);
        }
        return out.toByteArray();
    }

    /** Authenticode 哈希：跳过 checksum(4B)、Security Directory entry(8B)、证书表区域。 */
    private static void authenticodeDigest(MessageDigest md, byte[] file,
                                           long checksumOff, long secDirOff,
                                           long certTableOff, long certTableSize) {
        md.update(file, 0, (int) checksumOff);
        md.update(file, (int) checksumOff + 4, (int) (secDirOff - checksumOff - 4));
        md.update(file, (int) secDirOff + 8, (int) (certTableOff - secDirOff - 8));
        long tableEnd = certTableOff + certTableSize;
        if (tableEnd < file.length) {
            md.update(file, (int) tableEnd, file.length - (int) tableEnd);
        }
    }

    /**
     * 构建 SpcIndirectDataContent（对齐 signtool 标准样本）：
     * SpcPeImageData.file = [0] EXPLICIT → [2] EXPLICIT → SpcString(空 80 00)；
     * SpcAttributeTypeAndOptionalValue.value = 直接 SEQUENCE（微软实测无 [0] 包装）；
     * DigestInfo = 摘要算法(NULL) + 文件哈希。
     */
    private static byte[] buildSpcIndirectData(byte[] fileHash, String digestOid) throws Exception {
        // SpcString 空 = [0] IMPLICIT OCTET STRING(空) → 80 00
        DERTaggedObject spcStringEmpty = new DERTaggedObject(false, 0, new DEROctetString(new byte[0]));
        // SpcLink.file = [2] EXPLICIT SpcString
        DERTaggedObject spcLinkFile = new DERTaggedObject(true, 2, spcStringEmpty);
        // SpcPeImageData: flags + file [0] EXPLICIT SpcLink
        ASN1EncodableVector peImage = new ASN1EncodableVector();
        peImage.add(new DERBitString(0));
        peImage.add(new DERTaggedObject(true, 0, spcLinkFile));
        byte[] peImageDer = new DERSequence(peImage).getEncoded();

        // SpcAttributeTypeAndOptionalValue: OID + value（直接，无 [0] 包装）
        ASN1EncodableVector attr = new ASN1EncodableVector();
        attr.add(new ASN1ObjectIdentifier(OID_SPC_PE_IMAGE_DATA));
        attr.add(ASN1Primitive.fromByteArray(peImageDer));
        byte[] dataDer = new DERSequence(attr).getEncoded();

        // DigestInfo: 摘要算法 + NULL + 文件哈希
        ASN1EncodableVector di = new ASN1EncodableVector();
        di.add(new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestOid), DERNull.INSTANCE));
        di.add(new DEROctetString(fileHash));
        byte[] digestInfoDer = new DERSequence(di).getEncoded();

        ASN1EncodableVector spc = new ASN1EncodableVector();
        spc.add(ASN1Primitive.fromByteArray(dataDer));
        spc.add(ASN1Primitive.fromByteArray(digestInfoDer));
        return new DERSequence(spc).getEncoded();
    }

    /**
     * 手动构造 Authenticode SignedData（对齐 signtool 标准，eContent 直接 SEQUENCE 无 OCTET STRING 包装）：
     * SignedData v1, digestAlgorithms={摘要+NULL}, encapContentInfo={spcIndirectDataContext,
     * [0] EXPLICIT SpcIndirectData}, certificates[0]={根在前}, signerInfos=1(
     * signedAttrs={contentType, messageDigest}, signatureAlgorithm=算法+NULL, 签名 over signedAttrs)。
     * 自动请求时间戳（RFC3161 或 Authenticode，地址可配置）嵌入 unsignedAttrs，失败降级。
     */
    private static byte[] buildExeCms(byte[] spcDer, String keyType,
                                      X509Certificate cert, PrivateKey key,
                                      List<X509Certificate> chain, String baseDir,
                                      String tsType, String tsUrl) throws Exception {
        String digestOid = digestOid(keyType);
        String sigAlgOid = sigAlgOid(keyType);
        String jcaSig = jcaSigAlg(keyType);
        String jcaHash = digestJca(keyType);

        // messageDigest = hash(SpcIndirectData SEQUENCE 内容字节, 不含 30xx 头) —— 对齐 signtool 标准
        MessageDigest md = MessageDigest.getInstance(jcaHash);
        byte[] digest = md.digest(stripSequenceHeader(spcDer));

        // signedAttrs: { contentType(spcIndirectDataContext), messageDigest }（DER SET 按 OID 排序）
        ASN1EncodableVector attrs = new ASN1EncodableVector();
        attrs.add(new Attribute(CMSAttributes.contentType,
                new DERSet(new ASN1ObjectIdentifier(OID_SPC_INDIRECT_DATA))));
        attrs.add(new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(digest))));
        byte[] signedAttrsDer = new DERSet(attrs).getEncoded();

        // 签名 over signedAttrs DER
        Signature sigEngine = Signature.getInstance(jcaSig);
        sigEngine.initSign(key);
        sigEngine.update(signedAttrsDer);
        byte[] sig = sigEngine.sign();

        // 时间戳：失败降级不影响签名
        //   RFC3161（/tr 风格）：messageImprint = SHA-256(签名值) → 标准 TimeStampToken，嵌入 SPC_RFC3161_TS
        //   Authenticode（/t 风格）：请求体 = ContentInfo{SPC_TIME_STAMP_REQUEST, id-data + 主签名值}，
        //     响应 token 提取 SignerInfo 后以 countersignature 嵌入（对齐 signtool /t 与 Go 版 MAIN 协议）
        byte[] tsToken = null;
        String tsInfo = null;
        boolean authTs = "AUTHENTICODE".equalsIgnoreCase(tsType);
        String tsLabel = authTs ? "Authenticode" : "RFC3161";
        try {
            if (authTs) {
                tsToken = requestAuthenticodeTimestamp(sig, baseDir, tsUrl);
            } else {
                byte[] imprint = MessageDigest.getInstance("SHA-256").digest(sig);
                tsToken = requestTimestamp(imprint, baseDir, "RFC3161", tsUrl);
            }
            tsInfo = "已附加 " + tsLabel + " 时间戳 (" + tsToken.length + "B)"
                    + (tsUrl != null && !tsUrl.trim().isEmpty() ? " @ " + tsUrl : " @ 本机MAIN");
        } catch (Exception ex) {
            tsInfo = tsLabel + " 时间戳请求失败，跳过（不影响签名）: " + ex.getMessage();
        }
        lastTsInfo = tsInfo;

        // SignerInfo v1: sid=(issuer=上级证书 subject, serial=签名证书 serial)
        X509Certificate issuer = (chain != null && chain.size() >= 2) ? chain.get(1) : cert;
        ASN1EncodableVector ias = new ASN1EncodableVector();
        ias.add(X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()));
        ias.add(new ASN1Integer(cert.getSerialNumber()));
        ASN1EncodableVector si = new ASN1EncodableVector();
        si.add(new ASN1Integer(1));
        si.add(new DERSequence(ias));
        si.add(new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestOid), DERNull.INSTANCE));
        si.add(new DERTaggedObject(false, 0, ASN1Primitive.fromByteArray(signedAttrsDer))); // [0] IMPLICIT signedAttrs
        si.add(new AlgorithmIdentifier(new ASN1ObjectIdentifier(sigAlgOid), DERNull.INSTANCE));
        si.add(new DEROctetString(sig));
        if (tsToken != null) {
            ASN1EncodableVector uattrs = new ASN1EncodableVector();
            if (authTs) {
                // Authenticode 老式时间戳：countersignature（1.2.840.113549.1.9.6），值为 token 内首个 SignerInfo
                uattrs.add(new Attribute(new ASN1ObjectIdentifier("1.2.840.113549.1.9.6"),
                        new DERSet(ASN1Primitive.fromByteArray(extractFirstSignerInfo(tsToken)))));
            } else {
                uattrs.add(new Attribute(new ASN1ObjectIdentifier(OID_SPC_RFC3161_TS),
                        new DERSet(ASN1Primitive.fromByteArray(tsToken))));
            }
            si.add(new DERTaggedObject(false, 1, new DERSet(uattrs)));
        }
        byte[] signerInfoDer = new DERSequence(si).getEncoded();

        // SignedData v1
        ASN1EncodableVector sd = new ASN1EncodableVector();
        sd.add(new ASN1Integer(1));
        sd.add(new DERSet(new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestOid), DERNull.INSTANCE)));
        ASN1EncodableVector eci = new ASN1EncodableVector();
        eci.add(new ASN1ObjectIdentifier(OID_SPC_INDIRECT_DATA));
        eci.add(new DERTaggedObject(true, 0, ASN1Primitive.fromByteArray(spcDer))); // [0] EXPLICIT 直接 SEQUENCE
        sd.add(new DERSequence(eci));
        ASN1EncodableVector certs = new ASN1EncodableVector();
        List<X509Certificate> ordered = (chain == null || chain.isEmpty())
                ? Collections.singletonList(cert) : chain;
        for (int i = ordered.size() - 1; i >= 0; i--) {   // 根在前
            certs.add(ASN1Primitive.fromByteArray(ordered.get(i).getEncoded()));
        }
        // Authenticode：把时间戳 token 内的 TSA 证书（及上级）合并进证书集合，
        // 否则 Windows 无法验证 countersignature 的签名（0x80096003）
        if (authTs && tsToken != null) {
            try {
                java.util.Set<String> seen = new java.util.HashSet<>();
                for (int i = 0; i < certs.size(); i++) {
                    seen.add(serialOf(certs.get(i).toASN1Primitive().getEncoded("DER")));
                }
                for (byte[] tc : extractCertificates(tsToken)) {
                    if (seen.add(serialOf(tc))) {
                        certs.add(ASN1Primitive.fromByteArray(tc));
                    }
                }
            } catch (Exception ignored) {
            }
        }
        sd.add(new DERTaggedObject(false, 0, new DERSet(certs)));
        sd.add(new DERSet(ASN1Primitive.fromByteArray(signerInfoDer)));

        ASN1EncodableVector ci = new ASN1EncodableVector();
        ci.add(new ASN1ObjectIdentifier("1.2.840.113549.1.7.2"));  // pkcs7-signedData
        ci.add(new DERTaggedObject(true, 0, new DERSequence(sd)));
        return new DERSequence(ci).getEncoded();
    }

    /**
     * Authenticode 老式时间戳请求（对齐 signtool /t 与 Go 版 MAIN /timestamp 协议）：
     * 请求体 = base64( ContentInfo{ 1.3.6.1.4.1.311.3.2.1, SEQUENCE{ id-data, [0] OCTET STRING(主签名值) } } )，
     * 响应 = base64( PKCS#7 ContentInfo )，解码后返回 token DER。
     *
     * @param signatureValue 主签名值（被签名内容，TSA 直接对其签名）
     */
    static byte[] requestAuthenticodeTimestamp(byte[] signatureValue, String baseDir,
                                               String tsUrl) throws Exception {
        String url = (tsUrl == null || tsUrl.trim().isEmpty()) ? null : tsUrl.trim();
        if (url == null) {
            String port = "80";
            if (baseDir != null) {
                try {
                    Path cfg = Paths.get(baseDir, "PKI", "CONFIG.txt");
                    if (Files.exists(cfg)) {
                        for (String line : Files.readAllLines(cfg, StandardCharsets.UTF_8)) {
                            String t = line.trim();
                            if (t.startsWith("WEBPORT=")) {
                                String v = t.substring("WEBPORT=".length()).trim();
                                if (!v.isEmpty()) {
                                    port = v;
                                }
                            }
                        }
                    }
                } catch (Exception ignored) {
                }
            }
            url = "http://127.0.0.1:" + port + "/timestamp";
        }

        // ContentInfo{ 1.3.6.1.4.1.311.3.2.1, SEQUENCE{ OID id-data, [0] EXPLICIT OCTET STRING(sig) } }
        ASN1EncodableVector inner = new ASN1EncodableVector();
        inner.add(new ASN1ObjectIdentifier("1.2.840.113549.1.7.1")); // id-data
        inner.add(new DERTaggedObject(true, 0, new DEROctetString(signatureValue)));
        ASN1EncodableVector ci = new ASN1EncodableVector();
        ci.add(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.3.2.1"));   // SPC_TIME_STAMP_REQUEST
        ci.add(new DERSequence(inner));
        byte[] reqDer = new DERSequence(ci).getEncoded("DER");
        byte[] payload = Base64.getEncoder().encodeToString(reqDer).getBytes(StandardCharsets.UTF_8);

        HttpURLConnection conn = (HttpURLConnection) new java.net.URI(url).toURL().openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(30000);
        conn.setRequestProperty("Content-Type", "application/octet-stream");
        conn.setRequestProperty("Content-Length", String.valueOf(payload.length));
        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload);
        }
        int code = conn.getResponseCode();
        if (code != HttpURLConnection.HTTP_OK) {
            throw new IOException("Authenticode TSA HTTP 状态码 " + code + " @ " + url);
        }
        ByteArrayOutputStream resp = new ByteArrayOutputStream();
        try (InputStream is = conn.getInputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) {
                resp.write(buf, 0, n);
            }
        }
        byte[] respBytes = resp.toByteArray();
        // 响应：本机 MAIN 返回 PKCS#7 DER 的 base64 PEM 正文；外部 TSA 可能直接回 DER
        try {
            ASN1Primitive.fromByteArray(respBytes);
            return respBytes;
        } catch (Exception derFail) {
            String b64 = new String(respBytes, StandardCharsets.UTF_8)
                    .replaceAll("[^A-Za-z0-9+/=]", "");
            if (b64.isEmpty()) {
                throw new IOException("Authenticode TSA 响应既非 DER 也非 base64（@ " + url + "）");
            }
            return Base64.getDecoder().decode(b64);
        }
    }

    /** 从 CMS ContentInfo 中提取第一个 SignerInfo 的 DER（countersignature 嵌入用）。 */
    static byte[] extractFirstSignerInfo(byte[] cmsDer) throws Exception {
        ASN1Sequence ci = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(cmsDer));
        if (ci.size() < 2) {
            throw new IOException("时间戳 token 结构异常（缺 SignedData）");
        }
        ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(ci.getObjectAt(1));
        ASN1Sequence sd = ASN1Sequence.getInstance(
                tagged.getBaseUniversal(true, org.bouncycastle.asn1.BERTags.SEQUENCE));
        ASN1Set signerInfos = ASN1Set.getInstance(sd.getObjectAt(sd.size() - 1));
        if (signerInfos.size() == 0) {
            throw new IOException("时间戳 token 无 SignerInfo");
        }
        return ASN1Sequence.getInstance(signerInfos.getObjectAt(0)).getEncoded("DER");
    }

    /** 从 CMS ContentInfo 中提取证书集合（每个证书的 DER）。 */
    static java.util.List<byte[]> extractCertificates(byte[] cmsDer) throws Exception {
        java.util.List<byte[]> out = new java.util.ArrayList<>();
        ASN1Sequence ci = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(cmsDer));
        if (ci.size() < 2) {
            return out;
        }
        ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(ci.getObjectAt(1));
        ASN1Sequence sd = ASN1Sequence.getInstance(
                tagged.getBaseUniversal(true, org.bouncycastle.asn1.BERTags.SEQUENCE));
        for (int i = 0; i < sd.size(); i++) {
            if (sd.getObjectAt(i) instanceof ASN1TaggedObject) {
                ASN1TaggedObject tt = (ASN1TaggedObject) sd.getObjectAt(i);
                if (tt.getTagNo() == 0) {
                    // SignedData.certificates 是 IMPLICIT [0] SET OF Certificate
                    ASN1Set certs = ASN1Set.getInstance(tt, false);
                    for (int j = 0; j < certs.size(); j++) {
                        out.add(certs.getObjectAt(j).toASN1Primitive().getEncoded("DER"));
                    }
                }
            }
        }
        return out;
    }

    /** 证书 DER → 十六进制序列号（证书集合去重用）。 */
    static String serialOf(byte[] certDer) throws Exception {
        java.security.cert.CertificateFactory cf =
                java.security.cert.CertificateFactory.getInstance("X.509");
        X509Certificate c = (X509Certificate) cf.generateCertificate(
                new java.io.ByteArrayInputStream(certDer));
        return c.getSerialNumber().toString(16);
    }

    /**
     * RFC3161 时间戳请求（默认本机 MAIN /rfc3161）。messageImprint 用 SHA-256。
     * 校验 PKIStatus，返回 TimeStampToken 的 ContentInfo DER。
     */
    static byte[] requestTimestamp(byte[] messageImprint, String baseDir) throws Exception {
        return requestTimestamp(messageImprint, baseDir, "RFC3161", null);
    }

    /**
     * 时间戳请求（RFC3161 / Authenticode 两种类型，地址可配置）。
     *
     * @param messageImprint 消息摘要（SHA-256 计算后）
     * @param baseDir        PKI 基目录（tsUrl 为空时读 CONFIG.txt 的 WEBPORT 定位本机 MAIN）
     * @param tsType         RFC3161（默认，标准 TimeStampToken）/ AUTHENTICODE（微软老式 PKCS#7）
     * @param tsUrl          时间戳服务地址；null/空 = 默认本机 MAIN
     * @return RFC3161 → TimeStampToken ContentInfo DER；Authenticode → 服务端 PKCS#7 CMS 字节
     */
    static byte[] requestTimestamp(byte[] messageImprint, String baseDir,
                                   String tsType, String tsUrl) throws Exception {
        return requestTimestamp(messageImprint, baseDir, tsType, tsUrl,
                new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1")); // 默认 SHA-256
    }

    /**
     * 时间戳请求（RFC3161 / Authenticode 两种类型，地址与摘要算法可配置）。
     *
     * @param messageImprint 消息摘要（按 hashAlg 计算后传入）
     * @param baseDir        PKI 基目录（tsUrl 为空时读 CONFIG.txt 的 WEBPORT 定位本机 MAIN）
     * @param tsType         RFC3161（默认，标准 TimeStampToken）/ AUTHENTICODE（微软老式 PKCS#7）
     * @param tsUrl          时间戳服务地址；null/空 = 默认本机 MAIN
     * @param hashAlg        时间戳请求摘要算法 OID（如 SHA-256、SM3）；必须与 messageImprint 一致
     * @return RFC3161 → TimeStampToken ContentInfo DER；Authenticode → 服务端 PKCS#7 CMS 字节
     */
    static byte[] requestTimestamp(byte[] messageImprint, String baseDir,
                                   String tsType, String tsUrl,
                                   ASN1ObjectIdentifier hashAlg) throws Exception {
        boolean auth = "AUTHENTICODE".equalsIgnoreCase(tsType);
        String url = (tsUrl == null || tsUrl.trim().isEmpty()) ? null : tsUrl.trim();
        if (url == null) {
            String port = "80";
            if (baseDir != null) {
                try {
                    Path cfg = Paths.get(baseDir, "PKI", "CONFIG.txt");
                    if (Files.exists(cfg)) {
                        for (String line : Files.readAllLines(cfg, StandardCharsets.UTF_8)) {
                            String t = line.trim();
                            if (t.startsWith("WEBPORT=")) {
                                String v = t.substring("WEBPORT=".length()).trim();
                                if (!v.isEmpty()) {
                                    port = v;
                                }
                            }
                        }
                    }
                } catch (Exception ignored) {
                }
            }
            url = "http://127.0.0.1:" + port + (auth ? "/timestamp" : "/rfc3161");
        }

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        reqGen.setCertReq(true);
        AlgorithmIdentifier hashAlgId = new AlgorithmIdentifier(hashAlg, DERNull.INSTANCE);
        TimeStampRequest tsReq = reqGen.generate(hashAlgId, messageImprint);
        byte[] reqDer = tsReq.getEncoded();

        // Authenticode：请求体 = base64(TimeStampReq) 文本（对齐本机 MAIN /timestamp 与 signtool /t 旧格式）
        byte[] payload = auth
                ? Base64.getEncoder().encodeToString(reqDer).getBytes(StandardCharsets.UTF_8) : reqDer;

        HttpURLConnection conn = (HttpURLConnection) new java.net.URI(url).toURL().openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(30000);
        conn.setRequestProperty("Content-Type",
                auth ? "application/octet-stream" : "application/timestamp-query");
        conn.setRequestProperty("Content-Length", String.valueOf(payload.length));
        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload);
        }
        int code = conn.getResponseCode();
        if (code != HttpURLConnection.HTTP_OK) {
            throw new IOException("TSA HTTP 状态码 " + code + " @ " + url);
        }
        ByteArrayOutputStream resp = new ByteArrayOutputStream();
        try (InputStream is = conn.getInputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) {
                resp.write(buf, 0, n);
            }
        }
        byte[] respBytes = resp.toByteArray();
        if (auth) {
            // Authenticode 响应：本机 MAIN 返回 PKCS#7 DER 的 base64 PEM 正文（对齐 Go 版），
            // 外部 TSA 可能直接回 DER。先试 DER，失败再按 base64 解码。
            try {
                ASN1Primitive.fromByteArray(respBytes);
                return respBytes;
            } catch (Exception derFail) {
                String b64 = new String(respBytes, StandardCharsets.UTF_8)
                        .replaceAll("[^A-Za-z0-9+/=]", "");
                if (b64.isEmpty()) {
                    throw new IOException("Authenticode TSA 响应既非 DER 也非 base64（@ " + url + "）");
                }
                return Base64.getDecoder().decode(b64);
            }
        }
        TimeStampResponse tsResp = new TimeStampResponse(respBytes);
        int st = tsResp.getStatus();
        if (st != PKIStatus.GRANTED && st != PKIStatus.GRANTED_WITH_MODS) {
            throw new IOException("TSA 拒绝时间戳, PKIStatus=" + st + " @ " + url);
        }
        TimeStampToken token = tsResp.getTimeStampToken();
        if (token == null) {
            throw new IOException("TSA 响应缺少时间戳令牌 @ " + url);
        }
        return token.getEncoded();
    }

    /** 去掉 DER SEQUENCE 的标签+长度头，返回内容字节（content octets）。 */
    static byte[] stripSequenceHeader(byte[] der) {
        if (der.length < 2 || (der[0] & 0xff) != 0x30) {
            return der;
        }
        int off = 1;
        int l = der[off++] & 0xff;
        if ((l & 0x80) != 0) {
            int n = l & 0x7f;
            l = 0;
            for (int i = 0; i < n; i++) {
                l = (l << 8) | (der[off + i] & 0xff);
            }
            off += n;
        }
        return Arrays.copyOfRange(der, off, off + l);
    }

    // ============================ EXE Authenticode 验证 ============================

    /**
     * 验证 PE 文件代码签名：CMS 签名有效、Authenticode 文件哈希一致、证书链可建立。
     * eContent 为直接 SEQUENCE（无 OCTET STRING），故先手工提取内容字节，再以带 signedContent
     * 的 CMSSignedData 构造验证（BC 才能按内容字节计算 messageDigest 比对）。
     */
    @SuppressWarnings("unchecked")
    public static String verifyExe(byte[] exe) throws Exception {
        StringBuilder sb = new StringBuilder();
        if (exe.length < 0x40 || exe[0] != 'M' || exe[1] != 'Z') {
            return "[失败] 不是有效 PE 文件（缺 MZ 头）";
        }
        long eLfanew = readU32(exe, 0x3C);
        int magic = readU16(exe, (int) eLfanew + 24);
        boolean is64 = magic == 0x20B;
        int dataDirStart = is64 ? 112 : 96;
        long checksumOff = eLfanew + 24 + 64;
        long secDirOff = eLfanew + 24 + dataDirStart + 4 * 8;
        long certTableOffset = readU32(exe, (int) secDirOff);
        long certTableSize = readU32(exe, (int) secDirOff + 4);
        sb.append("PE格式: ").append(is64 ? "PE32+ (64位)" : "PE32 (32位)").append('\n');
        sb.append("Security Directory: offset=0x").append(Long.toHexString(certTableOffset))
                .append(" size=0x").append(Long.toHexString(certTableSize)).append('\n');
        if (certTableOffset == 0 || certTableSize == 0) {
            return sb.append("\n[结论] 该文件未包含代码签名证书表").toString();
        }
        if (certTableOffset + certTableSize > exe.length) {
            return sb.append("[失败] 证书表越界").toString();
        }

        byte[] certTable = Arrays.copyOfRange(exe, (int) certTableOffset,
                (int) (certTableOffset + certTableSize));
        long dwLength = readU32(certTable, 0);
        int wRevision = readU16(certTable, 4);
        int wCertType = readU16(certTable, 6);
        boolean winCertOk = dwLength == certTableSize && wRevision == 0x0200 && wCertType == 0x0002;
        sb.append("WIN_CERTIFICATE: dwLength=").append(dwLength)
                .append(" wRevision=0x").append(Integer.toHexString(wRevision))
                .append(" wCertificateType=0x").append(Integer.toHexString(wCertType))
                .append(" → ").append(winCertOk ? "符合规范" : "不符合规范").append('\n');
        int cmsLen = asn1ObjectTotalLength(certTable, 8);
        byte[] signedData = Arrays.copyOfRange(certTable, 8, 8 + cmsLen);
        sb.append("CMS 实际长度: ").append(cmsLen).append(" 字节（偏移 +8）\n");

        // 手工解析 ContentInfo → SignedData → encapContentInfo → eContent（直接 SEQUENCE）
        ASN1Sequence ci = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(signedData));
        ASN1TaggedObject sdTag = ASN1TaggedObject.getInstance(ci.getObjectAt(1));
        ASN1Sequence sd = ASN1Sequence.getInstance(sdTag.getBaseObject());
        ASN1Sequence eci = ASN1Sequence.getInstance(sd.getObjectAt(2));
        ASN1ObjectIdentifier eciType = ASN1ObjectIdentifier.getInstance(eci.getObjectAt(0));
        ASN1Primitive eContent = null;
        if (eci.size() > 1) {
            eContent = ASN1TaggedObject.getInstance(eci.getObjectAt(1)).getBaseObject().toASN1Primitive();
        }
        sb.append("\n[1] CMS SignedData 解析\n");
        sb.append("  contentType: ").append(eciType.getId())
                .append(OID_SPC_INDIRECT_DATA.equals(eciType.getId())
                        ? "  <-- spcIndirectDataContext (Authenticode)" : "")
                .append('\n');

        // 带 signedContent 的 CMSSignedData：content = eContent 内容字节（messageDigest 的哈希对象）
        CMSSignedData cms;
        if (eContent != null) {
            byte[] contentBytes = eContent instanceof ASN1OctetString
                    ? ((ASN1OctetString) eContent).getOctets()
                    : stripSequenceHeader(eContent.getEncoded("DER"));
            cms = new CMSSignedData(
                    new CMSProcessableByteArray(eciType, contentBytes), signedData);
        } else {
            cms = new CMSSignedData(signedData);
        }

        Collection<X509CertificateHolder> certs = cms.getCertificates().getMatches(null);
        sb.append("  证书数量: ").append(certs.size()).append('\n');
        JcaX509CertificateConverter conv = new JcaX509CertificateConverter().setProvider("BC");
        for (X509CertificateHolder h : certs) {
            sb.append("    - ").append(h.getSubject()).append('\n');
        }

        SignerInformationStore sis = cms.getSignerInfos();
        if (sis.size() == 0) {
            return sb.append("[失败] 无 SignerInfo").toString();
        }
        SignerInformation si = sis.getSigners().iterator().next();
        Collection<X509CertificateHolder> matched = cms.getCertificates().getMatches(si.getSID());
        if (matched.isEmpty()) {
            return sb.append("[失败] 找不到签名者证书").toString();
        }
        X509Certificate signerCert = conv.getCertificate(matched.iterator().next());
        sb.append("  签名者证书: ").append(signerCert.getSubjectX500Principal()).append('\n');
        sb.append("  摘要算法: ").append(si.getDigestAlgOID())
                .append("  签名算法: ").append(si.getEncryptionAlgOID()).append('\n');
        boolean sigOk;
        try {
            sigOk = si.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC")
                    .build(signerCert));
            sb.append("  CMS 签名验证: ").append(sigOk ? "通过 ✓" : "失败 ✗").append('\n');
        } catch (Exception e) {
            sigOk = false;
            sb.append("  CMS 签名验证异常: ").append(e).append('\n');
        }

        // 时间戳检查（unsignedAttrs 中 SPC_RFC3161_TS）
        try {
            org.bouncycastle.asn1.cms.AttributeTable ua = si.getUnsignedAttributes();
            if (ua != null && ua.get(new ASN1ObjectIdentifier(OID_SPC_RFC3161_TS)) != null) {
                sb.append("  RFC3161 时间戳: 已嵌入（SPC_RFC3161_TS 1.3.6.1.4.1.311.3.3.1）\n");
            } else {
                sb.append("  RFC3161 时间戳: 未嵌入\n");
            }
        } catch (Exception e) {
            sb.append("  时间戳检查异常: ").append(e).append('\n');
        }

        // Authenticode 文件哈希比对
        sb.append("\n[2] Authenticode 文件哈希验证\n");
        String digestJca = digestJcaFromOid(si.getDigestAlgOID());
        sb.append("  摘要算法: ").append(digestJca).append('\n');
        MessageDigest md = MessageDigest.getInstance(digestJca);
        authenticodeDigest(md, exe, checksumOff, secDirOff, certTableOffset, certTableSize);
        byte[] computed = md.digest();
        sb.append("  计算摘要: ").append(Hex.toHexString(computed)).append('\n');
        byte[] embedded = null;
        try {
            byte[] spcDer = eContent.getEncoded("DER");
            ASN1Sequence spc = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(spcDer));
            ASN1Sequence digestInfo = ASN1Sequence.getInstance(spc.getObjectAt(1));
            embedded = ASN1OctetString.getInstance(digestInfo.getObjectAt(1)).getOctets();
            sb.append("  内嵌摘要: ").append(Hex.toHexString(embedded)).append('\n');
        } catch (Exception e) {
            sb.append("  内容摘要提取失败: ").append(e).append('\n');
        }
        boolean contentOk = embedded != null && MessageDigest.isEqual(computed, embedded);
        sb.append("  文件哈希比对: ").append(contentOk ? "通过 ✓" : "失败 ✗").append('\n');

        // 证书链验证（自签根检测）
        sb.append("\n[3] 证书链验证\n");
        boolean chainOk = verifyChain(sb, signerCert, certs, conv);
        sb.append("  证书链: ").append(chainOk ? "通过 ✓" : "失败 ✗").append('\n');

        sb.append("\n========================================\n");
        sb.append("最终结论: ").append((sigOk && contentOk && chainOk)
                ? "代码签名有效 ✓" : "代码签名无效 ✗").append('\n');
        return sb.toString();
    }

    /** 逐级验证签名证书 → 颁发者 → … → 自签根。 */
    private static boolean verifyChain(StringBuilder sb, X509Certificate signerCert,
                                       Collection<X509CertificateHolder> certs,
                                       JcaX509CertificateConverter conv) {
        if (signerCert == null) {
            sb.append("  无签名者证书，无法验证链\n");
            return false;
        }
        try {
            List<X509Certificate> pool = new ArrayList<>();
            for (X509CertificateHolder h : certs) {
                pool.add(conv.getCertificate(h));
            }
            X509Certificate cur = signerCert;
            int guard = 0;
            while (cur != null && guard++ < 32) {
                try {
                    cur.verify(cur.getPublicKey());
                    sb.append("  链顶: ").append(cur.getSubjectX500Principal()).append("（自签根）\n");
                    return true;
                } catch (Exception ignored) {
                }
                X509Certificate issuer = null;
                for (X509Certificate c : pool) {
                    try {
                        cur.verify(c.getPublicKey());
                        issuer = c;
                        break;
                    } catch (Exception ignored) {
                    }
                }
                if (issuer == null) {
                    sb.append("  链中断：").append(cur.getSubjectX500Principal())
                            .append(" 的颁发者不在 CMS 证书集中\n");
                    return false;
                }
                sb.append("  ").append(shortDn(cur.getSubjectX500Principal().toString()))
                        .append("\n    └─ 由 ").append(shortDn(issuer.getSubjectX500Principal().toString()))
                        .append(" 签发 ✓\n");
                cur = issuer;
            }
            return false;
        } catch (Exception e) {
            sb.append("  证书链验证失败: ").append(e).append('\n');
            return false;
        }
    }

    // ============================ PDF 签名（可选可见签章） ============================

    /**
     * 对 PDF 做标准 PKCS#7 detached 签名（adbe.pkcs7.detached）。
     * 基于 PDFBox 3.0.4 外部签名两段式：先得到 ByteRange 待签数据，签名后 setSignature 写入。
     *
     * @param imageBytes 可选签章图片（png/jpg/bmp/gif）；null 或空 = 不可见签名
     */
    public static byte[] signPdf(byte[] pdf, String keyType, X509Certificate cert,
                                 PrivateKey key, List<X509Certificate> chain,
                                 byte[] imageBytes) throws Exception {
        return signPdf(pdf, keyType, cert, key, chain, imageBytes, "ADOBE", "");
    }

    /**
     * 对 PDF 签名（可选签章类型与时间戳地址）。
     *
     * @param sealType ADOBE（标准 PKCS#7 detached，默认）/ GM38540（GB/T 38540-2020 SES_Signature）/
     *                 GM35275（GB/T 35275-2017 CMS+私有OID印章）/ GM0031（GM/T 0031-2025 两层 SES_Signature）
     * @param tsUrl    PDF 时间戳地址（RFC3161）；null/空 = 本机 MAIN /rfc3161。
     *                 嵌入方式：ADOBE/GM35275 → SignerInfo unsignedAttrs（CAdES-T）；
     *                 GM38540 → SES_Signature 可选第 5 字段 timeStamp（GB/T 38540 7.1.6，
     *                 对签名值盖时间戳，GB/T 20520= RFC3161，SM3）；GM0031 无标准时间戳字段，忽略。
     */
    public static byte[] signPdf(byte[] pdf, String keyType, X509Certificate cert,
                                 PrivateKey key, List<X509Certificate> chain,
                                 byte[] imageBytes, String sealType, String tsUrl) throws Exception {
        if (sealType != null && ("GM38540".equalsIgnoreCase(sealType)
                || "GM35275".equalsIgnoreCase(sealType)
                || "GM0031".equalsIgnoreCase(sealType))) {
            return signPdfGm(pdf, sealType, keyType, cert, key, chain, imageBytes, tsUrl,
                    AppPaths.baseDir());
        }
        // Adobe 标准文档签名（选中数字证书）：时间戳按 CAdES-T/PAdES-T 标准嵌入签名内部
        // （SignerInfo unsignedAttrs 的 id-aa-timeStampToken，messageImprint=SHA-256(签名值)），
        // 不做独立 DocTimeStamp；DSS/LTV 数据与数字签名同一次保存（被签名覆盖，签名后零增量）。
        return signPdfAdobeFinal(pdf, keyType, cert, key, chain, imageBytes, tsUrl, AppPaths.baseDir());
    }

    /**
     * 纯文档时间戳（无签名证书场景）：独立 DocTimeStamp 签名字段，
     * Filter=Adobe.PPKLite、SubFilter=ETSI.RFC3161、Contents=RFC 3161 TimeStampToken（覆盖整个文档）。
     * 适用于"不选证书、仅对文档盖时间戳"。
     *
     * @param tsUrl RFC3161 时间戳地址；null/空 = 本机 MAIN /rfc3161
     */
    public static byte[] signPdfTimestampOnly(byte[] pdf, String tsUrl) throws Exception {
        return addDocTimeStamp(pdf, tsUrl, AppPaths.baseDir());
    }

    /**
     * PAdES 文档时间戳（DocTimeStamp）：独立签名字段，Filter=Adobe.PPKLite、
     * SubFilter=ETSI.RFC3161、Contents=RFC 3161 TimeStampToken（覆盖整个文档）。
     * 仅在"无签名证书、纯文档时间戳"场景使用。
     * <p>同时嵌入 LTV（DSS：TSA 证书链 + 链上 OCSP 响应 + CRL），与时间戳同一次保存
     * （被 DocTimeStamp 覆盖，签名后零增量）；TSA 链通过一次探测时间戳请求获取，
     * 探测或采集失败降级为纯时间戳（不阻断）。
     */
    private static byte[] addDocTimeStamp(byte[] pdf, String tsUrl, String base) throws Exception {
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            if (doc.isEncrypted()) {
                throw new IllegalArgumentException("加密 PDF 暂不支持时间戳");
            }
            // LTV：探测请求获取 TSA 证书链（与正式请求同参数，同一 TSA 通常返回同链）
            LtvData ltv = null;
            try {
                byte[] probeImprint = MessageDigest.getInstance("SHA-256")
                        .digest("modpkica-ltv-probe".getBytes(StandardCharsets.UTF_8));
                byte[] probeTok = requestTimestamp(probeImprint, base, "RFC3161", tsUrl);
                List<X509Certificate> tsaChain = extractTsaChain(probeTok);
                ltv = collectLtvData(tsaChain, base);
            } catch (Exception ltvEx) {
                MLog.append(base, "DocTimeStamp LTV 降级", String.valueOf(ltvEx));
            }

            PDSignature ts = new PDSignature();
            ts.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            ts.setSubFilter(COSName.getPDFName(SUBFILTER_ETSI_RFC3161));
            ts.setName("MODPKICA TSA");
            ts.setSignDate(Calendar.getInstance());
            doc.addSignature(ts);
            if (ltv != null) {
                installDss(doc, ltv, null);
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ExternalSigningSupport es = doc.saveIncrementalForExternalSigning(out);
            byte[] toSign = readAllBytes(es.getContent());
            if (toSign.length == 0) {
                throw new IOException("DocTimeStamp: ByteRange 为空");
            }
            // RFC 3161 messageImprint = 摘要(待盖时间戳内容)
            byte[] imprint = MessageDigest.getInstance("SHA-256").digest(toSign);
            byte[] tok = requestTimestamp(imprint, base, "RFC3161", tsUrl);
            if (tok == null || tok.length == 0) {
                throw new IOException("DocTimeStamp: TSA 未返回令牌");
            }
            es.setSignature(tok);
            return out.toByteArray();
        }
    }

    /**
     * 从 RFC3161 TimeStampToken 提取 TSA 证书链（叶子在前、根在后）。
     * token 内证书不全时返回单元素链（TSA 证书自身）。
     */
    private static List<X509Certificate> extractTsaChain(byte[] tok) throws Exception {
        TimeStampToken tst = new TimeStampToken(new CMSSignedData(tok));
        JcaX509CertificateConverter conv = new JcaX509CertificateConverter().setProvider("BC");
        List<X509Certificate> chain = new ArrayList<>();
        @SuppressWarnings("unchecked")
        java.util.Collection<org.bouncycastle.cert.X509CertificateHolder> matched =
                (java.util.Collection<org.bouncycastle.cert.X509CertificateHolder>)
                        (java.util.Collection<?>) tst.getCertificates().getMatches(tst.getSID());
        X509Certificate current = conv.getCertificate(matched.iterator().next());
        chain.add(current);
        Set<String> used = new HashSet<>();
        used.add(serialHex(current));
        while (true) {
            X509Certificate issuer = null;
            for (org.bouncycastle.cert.X509CertificateHolder h : tst.getCertificates().getMatches(null)) {
                X509Certificate c = conv.getCertificate(h);
                if (c.getSubjectX500Principal().equals(current.getIssuerX500Principal())
                        && !used.contains(serialHex(c))) {
                    issuer = c;
                    break;
                }
            }
            if (issuer == null) {
                break; // 颁发者不在 token 内
            }
            chain.add(issuer);
            used.add(serialHex(issuer));
            if (issuer.getSubjectX500Principal().equals(issuer.getIssuerX500Principal())) {
                break; // 自签根，到顶
            }
            current = issuer;
        }
        return chain;
    }

    /** 证书序列号十六进制（小写，无 0x 前缀）。 */
    private static String serialHex(X509Certificate c) {
        return c.getSerialNumber().toString(16);
    }

    /**
     * Adobe 标准签名最终保存：数字签名 + DSS 同一次保存（数字签名是文档最后一次修改，签名后零增量）。
     * 时间戳已按标准嵌入签名内部（CAdES-T unsignedAttrs 的 id-aa-timeStampToken）；DSS 的 Certs/OCSPs/CRLs
     * 作为 PAdES 全局验证数据被签名覆盖（数字签名 ByteRange 无法在保存前预知，故省略 VRI 索引，
     * 验证器按证书/响应内容匹配 DSS 数据）。
     * LTV 采集失败时降级为纯签名（不阻断）。
     */
    private static byte[] signPdfAdobeFinal(byte[] pdf, String keyType, X509Certificate cert,
                                            PrivateKey key, List<X509Certificate> chain,
                                            byte[] imageBytes, String tsUrl, String base) throws Exception {
        // 1) 收集 LTV 数据（OCSP/CRL/证书链 DER）
        LtvData ltv = collectLtvData(chain, base);
        // 2) 正式保存：数字签名（内嵌时间戳属性）+ DSS 同保存（无 VRI，签名后零增量）
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            if (doc.isEncrypted()) {
                throw new IllegalArgumentException("加密 PDF 暂不支持签名");
            }
            PDSignature sig = buildAdobeSignature(cert);
            SignatureOptions sigOptions = null;
            if (imageBytes != null && imageBytes.length > 0) {
                sigOptions = buildVisibleSignatureOptions(doc, imageBytes);
            }
            if (sigOptions != null) {
                doc.addSignature(sig, sigOptions);
            } else {
                doc.addSignature(sig);
            }
            if (ltv != null) {
                installDss(doc, ltv, null);
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ExternalSigningSupport es = doc.saveIncrementalForExternalSigning(out);
            byte[] toSign = readAllBytes(es.getContent());
            if (toSign.length == 0) {
                throw new IOException("PDFBox 未提供待签名数据（ByteRange 为空）");
            }
            // 数字签名：eContentType = id-data，分离签名；时间戳按标准嵌入 unsignedAttrs（CAdES-T）
            byte[] cms = buildCms(toSign, "1.2.840.113549.1.7.1", false,
                    keyType, cert, key, chain, tsUrl);
            es.setSignature(cms);
            return out.toByteArray();
        }
    }

    /** 构建 Adobe 数字签名字段。 */
    private static PDSignature buildAdobeSignature(X509Certificate cert) {
        PDSignature sig = new PDSignature();
        sig.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        sig.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        sig.setName(shortDn(cert.getSubjectX500Principal().toString()));
        sig.setLocation("MODPKICA");
        sig.setReason("MODPKICA PDF Document Signing");
        sig.setSignDate(Calendar.getInstance());
        return sig;
    }

    /**
     * 构建可见签章选项（参考 java-lening 的 SignatureOptions 外观文档模式）：
     * 独立外观 PDF 内放置带 Rect 与 AP 的签名 widget，PDFBox 会把 Rect/外观搬到
     * 主文档第 1 页右下角，避免在 addSignature 之后改动文档破坏 ByteRange。
     */
    private static SignatureOptions buildVisibleSignatureOptions(PDDocument doc,
                                                                 byte[] imageBytes) throws Exception {
        BufferedImage bi = ImageIO.read(new ByteArrayInputStream(imageBytes));
        if (bi == null) {
            throw new IllegalArgumentException("无法解码签章图片（支持 png/jpg/bmp/gif）");
        }
        float imgW = bi.getWidth();
        float imgH = bi.getHeight();
        float maxW = 150f;
        float maxH = 80f;
        float scale = Math.min(maxW / imgW, maxH / imgH);
        float w = Math.max(20f, imgW * scale);
        float h = Math.max(14f, imgH * scale);

        // 主文档第 1 页右下角的签章矩形（PDF 坐标系原点在左下）
        PDPage page = doc.getPage(0);
        float pageW = page.getMediaBox().getWidth();
        float pageH = page.getMediaBox().getHeight();
        float x = pageW - w - 30f;
        float y = 30f;
        if (y + h > pageH) {
            y = Math.max(0f, pageH - h - 5f);
        }
        PDRectangle rect = new PDRectangle(x, y, w, h);

        // 独立外观文档：签章图 + 文本，widget 带 Rect 与 AP（PDFBox 会拷贝到主文档）
        PDDocument visDoc = new PDDocument();
        try {
            PDPage visPage = new PDPage(new PDRectangle(w, h));
            visDoc.addPage(visPage);

            PDAppearanceStream aps = new PDAppearanceStream(visDoc);
            aps.setBBox(new PDRectangle(w, h));
            aps.setResources(new PDResources());
            PDImageXObject img = PDImageXObject.createFromByteArray(visDoc, imageBytes, "MODPKICA_STAMP");
            try (org.apache.pdfbox.pdmodel.PDPageContentStream pcs =
                         new org.apache.pdfbox.pdmodel.PDPageContentStream(visDoc, aps)) {
                pcs.drawImage(img, 0, 0, w, h);
                pcs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 7);
                pcs.beginText();
                pcs.newLineAtOffset(2, 2);
                pcs.showText("Signed by MODPKICA");
                pcs.endText();
            }

            PDAnnotationWidget visWidget = new PDAnnotationWidget();
            visWidget.setRectangle(rect);
            visWidget.getCOSObject().setItem(COSName.FT, COSName.SIG);
            PDAppearanceDictionary ad = new PDAppearanceDictionary();
            ad.setNormalAppearance(aps);
            visWidget.setAppearance(ad);
            visPage.getAnnotations().add(visWidget);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            visDoc.save(baos);
            byte[] visPdfBytes = baos.toByteArray();

            SignatureOptions so = new SignatureOptions();
            so.setPage(0);
            so.setVisualSignature(new ByteArrayInputStream(visPdfBytes));
            return so;
        } finally {
            visDoc.close();
        }
    }

    // ============================ 国密 PDF 电子签章（GB/T 35275-2017 / GB/T 38540-2020 / GM/T 0031-2025） ============================

    /**
     * 国密 PDF 电子签章。
     * <ul>
     *   <li>GM38540：Contents = GB/T 38540-2020 SES_Signature（toSign TBS_Sign 内嵌 SESeal 电子印章），
     *       Filter=Adobe.SM2，SubFilter=GM.sm2seal，DM=SM3 OID，SM=SM2 OID</li>
     *   <li>GM0031：Contents = GM/T 0031-2025 两层 SES_Signature（SESeal={SES_SealInfo, SES_SignInfo}，
     *       TBS_Sign 7 字段含 cert/signatureAlgorithm），SubFilter=GM.sm2seal，Filter/DM/SM 同上</li>
     *   <li>GM35275：Contents = 标准 CMS SignedData（detached），SESeal 挂在 signedAttrs 私有 OID
     *       1.2.156.112600.8.1，SubFilter=GM.sm2cms.detached</li>
     * </ul>
     * 仅支持 SM2 证书；必须提供签章图片（印章数据嵌入签名结构，同时作为可见签章）。
     */
    private static byte[] signPdfGm(byte[] pdf, String sealType, String keyType,
                                    X509Certificate cert, PrivateKey key,
                                    List<X509Certificate> chain,
                                    byte[] imageBytes, String tsUrl, String base) throws Exception {
        if (!"SM2".equalsIgnoreCase(keyType)) {
            throw new IllegalArgumentException(
                    "国密 PDF 签章（" + sealType + "）需要 SM2 证书，当前证书算法: " + keyType);
        }
        if (imageBytes == null || imageBytes.length == 0) {
            throw new IllegalArgumentException("国密 PDF 签章需要选择签章图片（png/jpg/bmp/gif）");
        }
        BufferedImage bi = ImageIO.read(new ByteArrayInputStream(imageBytes));
        if (bi == null) {
            throw new IllegalArgumentException("无法解码签章图片（支持 png/jpg/bmp/gif）");
        }
        final int imgW = bi.getWidth();
        final int imgH = bi.getHeight();
        final boolean is38540 = sealType.contains("38540") || sealType.contains("0031");
        final boolean is0031 = sealType.contains("0031");
        final String gmStd = is0031 ? "0031-2025" : is38540 ? "38540-2020" : "35275-2017";
        final boolean isSeal = is38540 || is0031; // 独立 SES_Signature 结构（GM.sm2seal）
        final String fTsUrl = tsUrl;
        final String fBase = base;

        // 预先构建印章信息 SES_SealInfo 与制章签名（避免在签名回调里重复构建）
        // GM/T 0031-2025 与 GB/T 38540-2020 数据结构一致（官方解读），统一走 38540 结构
        byte[] eSealInfo = is38540
                ? buildGmSealInfo38540(cert, chain, imageBytes, imgW, imgH)
                : buildGmSealInfo35275(cert, chain, imageBytes, imgW, imgH);
        byte[] sealSigned = sm2Sign(key, eSealInfo);
        byte[] certChainBytes = buildGmCertChainBytes(cert, chain);

        try (PDDocument doc = Loader.loadPDF(pdf)) {
            if (doc.isEncrypted()) {
                throw new IllegalArgumentException("加密 PDF 暂不支持签名");
            }
            PDSignature sig = new PDSignature();
            sig.setFilter(COSName.getPDFName("Adobe.SM2"));
            sig.setSubFilter(COSName.getPDFName(isSeal ? SUBFILTER_GM_SEAL : SUBFILTER_GM_CMS));
            sig.setName(shortDn(cert.getSubjectX500Principal().toString()));
            sig.setLocation("MODPKICA");
            sig.setReason("GM/T " + gmStd + " 国密电子签章");
            sig.setSignDate(Calendar.getInstance());
            sig.getCOSObject().setString("DM", OID_SM3);
            sig.getCOSObject().setString("SM", OID_SM2);

            SignatureOptions sigOptions = buildVisibleSignatureOptions(doc, imageBytes);
            // 动态预留签名空间：签名 Contents = 印章图片字节 + 证书链 + ASN.1 结构/签名值开销
            // 固定 65536 在印章图较大时（> ~55KB）会导致
            // "Can't write signature, not enough space"，故按实际输入估算并留 1.5x 余量
            int estContents = imageBytes.length;
            List<X509Certificate> allCerts = (chain == null || chain.isEmpty())
                    ? Collections.singletonList(cert) : chain;
            for (X509Certificate c : allCerts) {
                estContents += c.getEncoded().length;
            }
            estContents += 8192; // 结构头 / 摘要 / 签名值 / 属性
            int pref = Math.max(65536, (int) (estContents * 1.5) + 32768);
            sigOptions.setPreferredSignatureSize(pref);
            doc.addSignature(sig, new SignatureInterface() {
                @Override
                public byte[] sign(InputStream content) throws IOException {
                    try {
                        byte[] rangeData = readAllBytes(content);
                        MessageDigest sm3 = MessageDigest.getInstance("SM3", "BC");
                        byte[] docHash = sm3.digest(rangeData);
                        if (is38540) {
                            return buildGm38540Signature(docHash, cert, key, eSealInfo,
                                    sealSigned, fTsUrl, fBase);
                        }
                        return buildGm35275Signature(rangeData, docHash, cert, key,
                                chain, eSealInfo, sealSigned, certChainBytes, fTsUrl, fBase);
                    } catch (Exception e) {
                        throw new IOException("国密签名构造失败: " + e, e);
                    }
                }
            }, sigOptions);
            // LTV（DSS：签名证书链 + OCSP 响应 + CRL）：GB/T 35275（CMS）、GB/T 38540-2020
            // 与 GM/T 0031 均支持——DSS 是 PDF 层标准（ISO 32000 DSS 字典），与签名格式无关；
            // 与签名同一次保存（被签名覆盖，签名后零增量）。采集失败降级为纯签名（不阻断）。
            try {
                LtvData ltv = collectLtvData(chain, fBase);
                if (ltv != null) {
                    installDss(doc, ltv, null);
                }
            } catch (Exception ltvEx) {
                MLog.append(fBase, "GM LTV 降级", String.valueOf(ltvEx));
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.saveIncremental(out);
            return out.toByteArray();
        }
    }

    /** GB/T 38540-2020：构建 SES_SealInfo 印章信息（header + esID + property + picture + extDatas）。 */
    private static byte[] buildGmSealInfo38540(X509Certificate cert, List<X509Certificate> chain,
                                               byte[] imageBytes, int w, int h) throws Exception {
        ASN1EncodableVector v = new ASN1EncodableVector();
        // [0] header SES_Header { ID="ES", version=4, Vid }
        ASN1EncodableVector header = new ASN1EncodableVector();
        header.add(new DERIA5String("ES"));
        header.add(new ASN1Integer(4));
        header.add(new DERIA5String("MODPKICA"));
        v.add(new DERSequence(header));
        // [1] esID 印章标识
        v.add(new DERIA5String(UUID.randomUUID().toString()));
        // [2] property SES_ESPropertyInfo { type, name, certListType, certList, createDate, validStart, validEnd }
        ASN1EncodableVector property = new ASN1EncodableVector();
        property.add(new ASN1Integer(1));                         // type=1 单位印章
        property.add(new DERUTF8String("MODPKICA 电子印章"));
        property.add(new ASN1Integer(1));                         // certListType=1 证书列表
        ASN1EncodableVector certList = new ASN1EncodableVector(); // SEQUENCE OF Cert（一张证书一个 OCTET STRING）
        List<X509Certificate> all = (chain == null || chain.isEmpty())
                ? Collections.singletonList(cert) : chain;
        for (X509Certificate c : all) {
            certList.add(new DEROctetString(c.getEncoded()));
        }
        property.add(new DERSequence(certList));
        Date now = new Date();
        property.add(new ASN1GeneralizedTime(now));               // createDate
        property.add(new ASN1GeneralizedTime(cert.getNotBefore())); // validStart
        property.add(new ASN1GeneralizedTime(cert.getNotAfter()));  // validEnd
        v.add(new DERSequence(property));
        // [3] picture SES_ESPictureInfo { type, data, width, height }
        ASN1EncodableVector picture = new ASN1EncodableVector();
        picture.add(new DERIA5String("PNG"));
        picture.add(new DEROctetString(imageBytes));
        picture.add(new ASN1Integer(w));
        picture.add(new ASN1Integer(h));
        v.add(new DERSequence(picture));
        // [4] extDatas ExtensionDatas（政务私有 OID 扩展）
        ASN1EncodableVector ext = new ASN1EncodableVector();
        ext.add(new ASN1ObjectIdentifier(OID_GOV_EXT));           // extnID
        ext.add(ASN1Boolean.FALSE);                               // critical
        ext.add(new DEROctetString(
                "sealMakingUnitInfo=MODPKICA".getBytes(StandardCharsets.UTF_8))); // extnValue
        ASN1EncodableVector extDatas = new ASN1EncodableVector();
        extDatas.add(new DERSequence(ext));
        v.add(new DERSequence(extDatas));
        return new DERSequence(v).getEncoded("DER");
    }

    /** GB/T 35275-2017：构建 eSealInfo（sealId + UUID + certInfo + imgInfo + 扩展）。 */
    private static byte[] buildGmSealInfo35275(X509Certificate cert, List<X509Certificate> chain,
                                               byte[] imageBytes, int w, int h) throws Exception {
        ASN1EncodableVector v = new ASN1EncodableVector();
        // [0] 印章头 SEQUENCE { IA5String, INTEGER, IA5String }
        ASN1EncodableVector sealId = new ASN1EncodableVector();
        sealId.add(new DERIA5String("ES"));
        sealId.add(new ASN1Integer(4));
        sealId.add(new DERIA5String("MODPKICA"));
        v.add(new DERSequence(sealId));
        // [1] 印章 UUID
        v.add(new DERIA5String(UUID.randomUUID().toString()));
        // [2] 印章证书信息 SEQUENCE(7)：type / issuer / certListType / certWrap(链字节) / 时间 x3
        ASN1EncodableVector certInfo = new ASN1EncodableVector();
        certInfo.add(new ASN1Integer(1));
        certInfo.add(new DERUTF8String(cert.getIssuerX500Principal().getName()));
        certInfo.add(new ASN1Integer(1));
        ASN1EncodableVector certWrap = new ASN1EncodableVector();
        certWrap.add(new DEROctetString(buildGmCertChainBytes(cert, chain)));
        certInfo.add(new DERSequence(certWrap));
        Date now = new Date();
        certInfo.add(new ASN1GeneralizedTime(now));
        certInfo.add(new ASN1GeneralizedTime(cert.getNotBefore()));
        certInfo.add(new ASN1GeneralizedTime(cert.getNotAfter()));
        v.add(new DERSequence(certInfo));
        // [3] 印章图片 SEQUENCE(4) { IA5String, OCTET STRING, INTEGER, INTEGER }
        ASN1EncodableVector imgInfo = new ASN1EncodableVector();
        imgInfo.add(new DERIA5String("PNG"));
        imgInfo.add(new DEROctetString(imageBytes));
        imgInfo.add(new ASN1Integer(w));
        imgInfo.add(new ASN1Integer(h));
        v.add(new DERSequence(imgInfo));
        // [4] 扩展属性 SEQUENCE { SEQUENCE { OID, BOOLEAN, OCTET STRING } }
        ASN1EncodableVector extItem = new ASN1EncodableVector();
        extItem.add(new ASN1ObjectIdentifier("1.2.840.113549.1.9.15"));
        extItem.add(ASN1Boolean.TRUE);
        extItem.add(new DEROctetString("<colour>0</colour>".getBytes(StandardCharsets.UTF_8)));
        ASN1EncodableVector ext = new ASN1EncodableVector();
        ext.add(new DERSequence(extItem));
        v.add(new DERSequence(ext));
        return new DERSequence(v).getEncoded("DER");
    }

    /* GB/T 38540-2020：构造 SES_Signature（toSign TBS_Sign + cert + signatureAlgID + signature）。 */
    /**
     * GB/T 38540-2020 电子签章。时间戳支持（标准 7.1.6）：SES_Signature 可选第 5 字段
     * <b>timeStamp</b>（OCTET STRING）——对签名值的时间戳，符合 GB/T 20520（= RFC3161），
     * DER 编码存放；SM2/SM3 场景 messageImprint 用 SM3。
     *
     * @param tsUrl RFC3161 时间戳地址；null = 不嵌时间戳；空串 = 本机 MAIN /rfc3161
     */
    private static byte[] buildGm38540Signature(byte[] docHash, X509Certificate cert,
                                                PrivateKey key, byte[] eSealInfo,
                                                byte[] sealSigned, String tsUrl, String base) throws Exception {
        // SESeal：eSealInfo + 制章者证书 + 签名算法 + 制章签名
        ASN1EncodableVector sesEal = new ASN1EncodableVector();
        sesEal.add(new ASN1InputStream(eSealInfo).readObject());
        sesEal.add(new DEROctetString(cert.getEncoded()));
        sesEal.add(new ASN1ObjectIdentifier(OID_SM2));
        sesEal.add(new DERBitString(sealSigned));
        byte[] sesEalDer = new DERSequence(sesEal).getEncoded("DER");

        // TBS_Sign：version=4 + eseal + timeInfo + dataHash + propertyInfo
        ASN1EncodableVector tbs = new ASN1EncodableVector();
        tbs.add(new ASN1Integer(4));
        tbs.add(new ASN1InputStream(sesEalDer).readObject());
        tbs.add(new ASN1GeneralizedTime(new Date()));
        tbs.add(new DERBitString(docHash));
        tbs.add(new DERIA5String("PDF-SM2-SEAL"));
        DERSequence tbsSeq = new DERSequence(tbs);
        byte[] tbsDer = tbsSeq.getEncoded("DER");

        // 签章签名：SM2 对 TBS_Sign 签名
        byte[] signature = sm2Sign(key, tbsDer);

        // SES_Signature（可选第 5 字段 timeStamp：对签名值的时间戳，GB/T 38540 7.1.6）
        ASN1EncodableVector sesSig = new ASN1EncodableVector();
        sesSig.add(tbsSeq);
        sesSig.add(new DEROctetString(cert.getEncoded()));
        sesSig.add(new ASN1ObjectIdentifier(OID_SM2));
        sesSig.add(new DERBitString(signature));
        if (tsUrl != null) {
            try {
                byte[] imprint = MessageDigest.getInstance("SM3", "BC").digest(signature);
                byte[] tok = requestTimestamp(imprint, base, "RFC3161", tsUrl,
                        new ASN1ObjectIdentifier(OID_SM3));
                // GB/T 38540 7.1.1：timeStamp[0] BIT STRING OPTIONAL（对签名值的时间戳，
                // GB/T 20520 = RFC3161，DER 编码存放）。ASN.1 默认 EXPLICIT 标签：
                // [0] 上下文标签（constructed, tag 0 = 0xA0）包 BIT STRING。
                sesSig.add(new DERTaggedObject(true, 0, new DERBitString(tok)));
            } catch (Exception tsEx) {
                // 时间戳失败降级：不带时间戳继续签名（不阻断）
                MLog.append(base, "GM38540 时间戳降级",
                        "请求 " + (tsUrl.trim().isEmpty() ? "本机 MAIN /rfc3161" : tsUrl)
                                + " 失败: " + tsEx);
            }
        }
        return new DERSequence(sesSig).getEncoded("DER");
    }

    /*
     * GB/T 35275-2017：构造 CMS SignedData（detached）。
     * signedAttrs = { contentType, messageDigest, signingTime, 私有OID(SESeal-DER) }，
     * 签名算法 SM3withSM2；证书链完整写入 CMS certificates。
     */
    /**
     * GB/T 35275-2017 CMS 签名。时间戳支持：标准 CMS SignerInfo 的 unsignedAttrs 可承载
     * CAdES-T 签名时间戳（id-aa-timeStampToken）——GB/T 35275 基于 CMS（ISO 8825），
     * unsignedAttrs 为通用结构；messageImprint 用 SM3（SM2/SM3 证书固定 SM3）。
     *
     * @param tsUrl RFC3161 时间戳地址；null = 不嵌时间戳；空串 = 本机 MAIN /rfc3161
     */
    private static byte[] buildGm35275Signature(byte[] rangeData, byte[] docHash,
                                                X509Certificate cert, PrivateKey key,
                                                List<X509Certificate> chain,
                                                byte[] eSealInfo, byte[] sealSigned,
                                                byte[] certChainBytes, String tsUrl, String base) throws Exception {
        // SESeal：eSealInfo + 印章证书块 + signAlgID + 制章签名
        ASN1EncodableVector sesEalV = new ASN1EncodableVector();
        sesEalV.add(new ASN1InputStream(eSealInfo).readObject());
        sesEalV.add(new DEROctetString(certChainBytes));
        sesEalV.add(new ASN1ObjectIdentifier(OID_SM2));
        sesEalV.add(new DERBitString(sealSigned));
        byte[] sesEalDer = new DERSequence(sesEalV).getEncoded("DER");

        // signedAttrs：contentType / messageDigest / signingTime / 私有OID(SESeal)
        ASN1EncodableVector attrs = new ASN1EncodableVector();
        attrs.add(new Attribute(CMSAttributes.contentType,
                new DERSet(new ASN1ObjectIdentifier("1.2.840.113549.1.7.1"))));
        attrs.add(new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(docHash))));
        attrs.add(new Attribute(CMSAttributes.signingTime, new DERSet(new DERUTCTime(new Date()))));
        attrs.add(new Attribute(new ASN1ObjectIdentifier(OID_GOV_EXT),
                new DERSet(new DEROctetString(sesEalDer))));
        AttributeTable signedAttrTable = new AttributeTable(attrs);

        // CMS SignedData 生成
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        JcaDigestCalculatorProviderBuilder dcBuilder =
                new JcaDigestCalculatorProviderBuilder().setProvider("BC");
        JcaSignerInfoGeneratorBuilder siBuilder =
                new JcaSignerInfoGeneratorBuilder(dcBuilder.build());
        siBuilder.setSignedAttributeGenerator(
                new DefaultSignedAttributeTableGenerator(signedAttrTable));
        ContentSigner cs = CertUtil.createContentSigner(key, "SM2", "SM3");
        gen.addSignerInfoGenerator(siBuilder.build(cs, cert));
        List<X509Certificate> all = (chain == null || chain.isEmpty())
                ? Collections.singletonList(cert) : chain;
        gen.addCertificates(new JcaCertStore(all));

        CMSSignedData cms = gen.generate(new CMSProcessableByteArray(rangeData), false); // detached

        // CAdES-T 签名时间戳：SM3(签名值) → RFC3161(SM3) → unsignedAttrs 的 id-aa-timeStampToken
        if (tsUrl != null) {
            try {
                SignerInformation si = cms.getSignerInfos().getSigners().iterator().next();
                byte[] imprint = MessageDigest.getInstance("SM3", "BC").digest(si.getSignature());
                byte[] tok = requestTimestamp(imprint, base, "RFC3161", tsUrl,
                        new ASN1ObjectIdentifier(OID_SM3));
                AttributeTable unsigned = new AttributeTable(
                        new Attribute(new ASN1ObjectIdentifier(OID_TSA_TOKEN),
                                new DERSet(ASN1Primitive.fromByteArray(tok))));
                SignerInformation newSi = SignerInformation.replaceUnsignedAttributes(si, unsigned);
                List<SignerInformation> newList = new ArrayList<>();
                for (SignerInformation o : cms.getSignerInfos().getSigners()) {
                    newList.add(o.getSID().equals(newSi.getSID()) ? newSi : o);
                }
                cms = CMSSignedData.replaceSigners(cms, new SignerInformationStore(newList));
            } catch (Exception tsEx) {
                // 时间戳失败降级：不带时间戳继续签名（不阻断）
                MLog.append(base, "GM35275 时间戳降级",
                        "请求 " + (tsUrl.trim().isEmpty() ? "本机 MAIN /rfc3161" : tsUrl)
                                + " 失败: " + tsEx);
            }
        }
        return cms.getEncoded("DER");
    }

    /** 证书链字节块：叶子在前、根在后顺序拼接（对齐参考项目 sm2sign||ca）。 */
    private static byte[] buildGmCertChainBytes(X509Certificate cert,
                                                List<X509Certificate> chain) throws Exception {
        List<X509Certificate> all = (chain == null || chain.isEmpty())
                ? Collections.singletonList(cert) : chain;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (X509Certificate c : all) {
            out.write(c.getEncoded());
        }
        return out.toByteArray();
    }

    /** SM2 签名（SM3withSM2，BC 实现含 ZA 计算，符合 GB/T 32918）。 */
    private static byte[] sm2Sign(PrivateKey privateKey, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("SM3WITHSM2", "BC");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    /** 生成 CMS SignedData（PDF detached 用 BC 生成器即可，标准 id-data 结构）。 */
    private static byte[] buildCms(byte[] content, String contentType, boolean encapsulate,
                                   String keyType, X509Certificate cert, PrivateKey key,
                                   List<X509Certificate> chain) throws Exception {
        return buildCms(content, contentType, encapsulate, keyType, cert, key, chain, null);
    }

    /**
     * 生成 CMS SignedData（PDF detached 用 BC 生成器即可，标准 id-data 结构）。
     *
     * @param tsUrl PDF 时间戳地址（RFC3161）；<b>null = 不嵌时间戳</b>；
     *              非 null（含空串）= 嵌入，空串 = 本机 MAIN /rfc3161。
     *              嵌入方式：CAdES-T / PAdES-T 签名时间戳——token 放入 SignerInfo 的
     *              <b>unsignedAttrs</b>（id-aa-timeStampToken，1.2.840.113549.1.9.16.2.14），
     *              messageImprint = SHA-256(签名值)，对齐主流签名工具（Wosign 等）。
     */
    private static byte[] buildCms(byte[] content, String contentType, boolean encapsulate,
                                   String keyType, X509Certificate cert, PrivateKey key,
                                   List<X509Certificate> chain, String tsUrl) throws Exception {
        ContentSigner signer = CertUtil.createContentSigner(key, keyType, digestName(keyType));
        DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        SignerInfoGeneratorBuilder b = new SignerInfoGeneratorBuilder(dcp);
        // BC 默认 signedAttrs：contentType / messageDigest / signingTime
        SignerInfoGenerator sigGen = b.build(signer, new JcaX509CertificateHolder(cert));

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(sigGen);
        gen.addCertificates(new JcaCertStore(chain != null && !chain.isEmpty() ? chain
                : Collections.singletonList(cert)));

        CMSTypedData cmsContent = new CMSTypedData() {
            @Override
            public ASN1ObjectIdentifier getContentType() {
                return new ASN1ObjectIdentifier(contentType);
            }

            @Override
            public void write(OutputStream out) throws IOException {
                out.write(content);
            }

            @Override
            public Object getContent() {
                return content;
            }
        };
        CMSSignedData signed = gen.generate(cmsContent, encapsulate);

        if (tsUrl != null) {
            try {
                SignerInformation si = signed.getSignerInfos().getSigners().iterator().next();
                // CAdES-T：messageImprint = SHA-256(签名值)
                byte[] imprint = MessageDigest.getInstance("SHA-256").digest(si.getSignature());
                byte[] tok = requestTimestamp(imprint, AppPaths.baseDir(), "RFC3161", tsUrl);
                AttributeTable unsigned = new AttributeTable(
                        new Attribute(new ASN1ObjectIdentifier(OID_TSA_TOKEN),
                                new DERSet(ASN1Primitive.fromByteArray(tok))));
                SignerInformation newSi = SignerInformation.replaceUnsignedAttributes(si, unsigned);
                List<SignerInformation> newList = new ArrayList<>();
                for (SignerInformation o : signed.getSignerInfos().getSigners()) {
                    newList.add(o.getSID().equals(newSi.getSID()) ? newSi : o);
                }
                signed = CMSSignedData.replaceSigners(signed, new SignerInformationStore(newList));
            } catch (Exception tsEx) {
                // 时间戳失败降级：不带时间戳继续签名（与 EXE 一致，不阻断签名）
                MLog.append(AppPaths.baseDir(), "PDF 时间戳降级",
                        "请求 " + (tsUrl.trim().isEmpty() ? "本机 MAIN /rfc3161" : tsUrl)
                                + " 失败: " + tsEx);
            }
        }
        return signed.getEncoded("DER");
    }

    // ============================ PAdES LTV（DSS / VRI） ============================

    /**
     * PAdES LTV 长期验证：对已签名 PDF 增量追加 DSS（Document Security Store）+ VRI 字典，
     * 嵌入签名证书链、链上各证书的 OCSP 响应与链上 CA/根证书的 CRL，
     * 使验证器可离线长期验证（Acrobat 显示"签名有效，已启用 LTV"）。
     *
     * <p>实现要点：
     * <ul>
     *   <li>VRI 字典 key = ByteRange 覆盖内容 SHA-1 十六进制大写（PAdES 规定，兼容 Acrobat）</li>
     *   <li>DSS /OCSPs 元素为完整 OCSPResp DER（RFC 6960，含响应者签名）</li>
     *   <li>DSS /CRLs 元素为颁发者 CRL DER（优先 CONFIG CRL URL 的 .der.crl 变体，回退原 URL 与本地文件）</li>
     *   <li>OCSP / CRL 来源：CONFIG.txt 的 OCSP= / CRL=（缺省 http://127.0.0.1:WEBPORT/...）</li>
     *   <li>所有对象为新增间接对象 + catalog 加 /DSS，PDFBox 增量保存，不触碰原签名区（ByteRange 不变）</li>
     * </ul>
     *
     * @param signedPdf 已签名 PDF 字节
     * @param chain     签名证书链（叶子在前，根在后）
     * @param baseDir   PKI 基目录（读 CONFIG.txt；null/空 或任一采集失败均返回原 PDF，不阻断签名）
     * @return 追加 LTV 数据后的 PDF
     */
    public static byte[] applyLtvPdf(byte[] signedPdf, List<X509Certificate> chain, String baseDir) {
        if (signedPdf == null || chain == null || chain.isEmpty()
                || baseDir == null || baseDir.trim().isEmpty()) {
            return signedPdf;
        }
        try (PDDocument doc = Loader.loadPDF(signedPdf)) {
            List<PDSignature> sigs = doc.getSignatureDictionaries();
            if (sigs == null || sigs.isEmpty()) {
                return signedPdf;
            }
            PDSignature sig = sigs.get(0);
            int[] br = sig.getByteRange();
            if (br == null || br.length != 4 || br[1] <= 0 || br[3] <= 0) {
                return signedPdf;
            }
            // VRI key：ByteRange 覆盖内容 SHA-1 十六进制大写
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(signedPdf, br[0], br[1]);
            md.update(signedPdf, br[2], br[3]);
            String vriKey = Hex.toHexString(md.digest()).toUpperCase();

            LtvData ltv = collectLtvData(chain, baseDir);
            if (ltv == null) {
                return signedPdf;
            }
            installDss(doc, ltv, vriKey);

            COSDictionary catalog = doc.getDocumentCatalog().getCOSObject();
            Set<COSDictionary> updated = new HashSet<>();
            updated.add(catalog);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.saveIncremental(out, updated);
            return out.toByteArray();
        } catch (Exception e) {
            return signedPdf; // LTV 失败不影响签名
        }
    }

    /** 一次性收集 LTV 数据：证书链 DER + 链上各证书 OCSP 响应 + 链上 CA/根 CRL。失败返回 null。 */
    private static LtvData collectLtvData(List<X509Certificate> chain, String baseDir) {
        if (chain == null || chain.isEmpty()) {
            return null;
        }
        try {
            // 1) 证书链 DER（去重）
            List<byte[]> certs = new ArrayList<>();
            Set<String> seenCerts = new HashSet<>();
            for (X509Certificate c : chain) {
                byte[] der = c.getEncoded();
                if (seenCerts.add(Hex.toHexString(der))) {
                    certs.add(der);
                }
            }
            // 2) OCSP 响应：链上每张证书（叶子的颁发者为上一级，自签根用自己）
            List<byte[]> ocspList = new ArrayList<>();
            for (int i = 0; i < chain.size(); i++) {
                X509Certificate target = chain.get(i);
                X509Certificate issuer = (i + 1 < chain.size()) ? chain.get(i + 1) : chain.get(i);
                byte[] resp = requestOcspResponse(target, issuer, baseDir);
                if (resp != null) {
                    ocspList.add(resp);
                }
            }
            // 3) CRL：链上每个 CA/根（chain[1..size-1]，CRL 文件名 = 颁发者序列号）
            List<byte[]> crlList = new ArrayList<>();
            for (int i = 1; i < chain.size(); i++) {
                byte[] crl = fetchIssuerCrl(chain.get(i), baseDir);
                if (crl != null) {
                    crlList.add(crl);
                }
            }
            if (certs.isEmpty() && ocspList.isEmpty() && crlList.isEmpty()) {
                return null;
            }
            return new LtvData(certs, ocspList, crlList);
        } catch (Exception e) {
            return null;
        }
    }

    /** LTV 采集数据（证书链 / OCSP 响应 / CRL）。 */
    private static final class LtvData {
        final List<byte[]> certs;
        final List<byte[]> ocspList;
        final List<byte[]> crlList;

        LtvData(List<byte[]> certs, List<byte[]> ocspList, List<byte[]> crlList) {
            this.certs = certs;
            this.ocspList = ocspList;
            this.crlList = crlList;
        }
    }

    /** 在文档中安装 DSS/VRI 对象（新增间接对象 + catalog /DSS 修订 + root 标记更新）。 */
    private static void installDss(PDDocument doc, LtvData ltv, String vriKey) throws Exception {
        COSDocument cosDoc = doc.getDocument();
        long nextNum = cosDoc.getHighestXRefObjectNumber() + 1;
        COSArray certArr = new COSArray();
        for (byte[] b : ltv.certs) {
            certArr.add(new COSObject(newLtvStream(b), new COSObjectKey(nextNum++, 0)));
        }
        COSArray ocspArr = new COSArray();
        for (byte[] b : ltv.ocspList) {
            ocspArr.add(new COSObject(newLtvStream(b), new COSObjectKey(nextNum++, 0)));
        }
        COSArray crlArr = new COSArray();
        for (byte[] b : ltv.crlList) {
            crlArr.add(new COSObject(newLtvStream(b), new COSObjectKey(nextNum++, 0)));
        }

        COSDictionary dss = new COSDictionary();
        dss.setItem(COSName.TYPE, COSName.getPDFName("DSS"));
        if (certArr.size() > 0) {
            dss.setItem(COSName.getPDFName("Certs"), certArr);
        }
        if (ocspArr.size() > 0) {
            dss.setItem(COSName.getPDFName("OCSPs"), ocspArr);
        }
        if (crlArr.size() > 0) {
            dss.setItem(COSName.getPDFName("CRLs"), crlArr);
        }

        COSDictionary vri = new COSDictionary();
        vri.setItem(COSName.TYPE, COSName.getPDFName("VRI"));
        if (ocspArr.size() > 0) {
            vri.setItem(COSName.getPDFName("OCSP"), ocspArr);
        }
        if (crlArr.size() > 0) {
            vri.setItem(COSName.getPDFName("CRL"), crlArr);
        }
        if (certArr.size() > 0) {
            vri.setItem(COSName.getPDFName("Cert"), certArr);
        }
        if (vriKey != null && vriKey.length() == 40) {
            // VRI key = DocTimeStamp 的 ByteRange SHA-1（PAdES 规范；无时间戳时省略 VRI，DSS 数组仍全局可用）
            COSDictionary vris = new COSDictionary();
            vris.setItem(COSName.getPDFName(vriKey), vri);
            dss.setItem(COSName.getPDFName("VRI"), vris);
        }
        COSObject dssRef = new COSObject(dss, new COSObjectKey(nextNum++, 0));

        // catalog 加 /DSS 并标记间接对象为需要更新（外部签名保存才会写出修订）
        COSDictionary catalog = doc.getDocumentCatalog().getCOSObject();
        catalog.setItem(COSName.getPDFName("DSS"), dssRef);
        COSBase root = cosDoc.getTrailer().getItem(COSName.ROOT);
        if (root instanceof COSObject) {
            ((COSObject) root).setNeedToBeUpdated(true);
        }
    }

    /** 创建承载 LTV 数据的流对象（字节写入，保存时由 COSObject 包装为间接对象）。 */
    private static COSStream newLtvStream(byte[] data) throws IOException {
        COSStream s = new COSStream();
        try (OutputStream os = s.createRawOutputStream()) {
            os.write(data);
        }
        return s;
    }

    /** RFC 6960 OCSP 请求（SHA-1 CertID + Nonce）→ 完整 OCSPResp DER；失败返回 null。 */
    private static byte[] requestOcspResponse(X509Certificate target, X509Certificate issuer,
                                              String baseDir) {
        try {
            AlgorithmIdentifier algId = new AlgorithmIdentifier(
                    new ASN1ObjectIdentifier("1.3.14.3.2.26")); // SHA-1
            DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder()
                    .setProvider("BC").build();
            CertificateID cid = new CertificateID(dcp.get(algId),
                    new JcaX509CertificateHolder(issuer), target.getSerialNumber());
            OCSPReqBuilder gen = new OCSPReqBuilder();
            gen.addRequest(cid);
            byte[] nonce = new byte[8];
            new SecureRandom().nextBytes(nonce);
            gen.setRequestExtensions(new Extensions(new Extension(
                    OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce))));
            byte[] reqDer = gen.build().getEncoded();

            String url = configValue(baseDir, "OCSP");
            if (url == null || url.isEmpty()) {
                url = "http://127.0.0.1:" + configValue(baseDir, "WEBPORT", "80") + "/OCSP";
            }
            return httpPost(url, "application/ocsp-request", reqDer);
        } catch (Exception e) {
            return null;
        }
    }

    /** 下载颁发者 CRL（DER）。优先 CONFIG CRL URL 的 .der.crl 变体，回退原 URL 与本地文件。 */
    private static byte[] fetchIssuerCrl(X509Certificate issuer, String baseDir) {
        String serial = issuer.getSerialNumber().toString(16);
        String url = configValue(baseDir, "CRL");
        if (url != null && !url.isEmpty()) {
            String u = url.replace("{CID}", serial).replace("{cid}", serial);
            String derUrl = u.endsWith(".crl")
                    ? u.substring(0, u.length() - 4) + ".der.crl" : u + ".der.crl";
            byte[] b = httpGet(derUrl);
            if (b != null && isDer(b)) {
                return b;
            }
            byte[] b2 = httpGet(u);
            if (b2 != null) {
                byte[] der = toDerCrl(b2);
                if (der != null) {
                    return der;
                }
            }
        }
        // 本地兜底（MAIN 未启动 / 外部 URL 不可达时）
        try {
            Path p = Paths.get(baseDir, "PKI", "WebPublic", "CRL", serial + ".der.crl");
            if (Files.exists(p)) {
                return Files.readAllBytes(p);
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /** 读取 CONFIG.txt 键值（缺省返回 def）。 */
    private static String configValue(String baseDir, String key) {
        return configValue(baseDir, key, null);
    }

    private static String configValue(String baseDir, String key, String def) {
        try {
            Path cfg = Paths.get(baseDir, "PKI", "CONFIG.txt");
            if (Files.exists(cfg)) {
                for (String line : Files.readAllLines(cfg, StandardCharsets.UTF_8)) {
                    String t = line.trim();
                    if (t.startsWith(key + "=")) {
                        String v = t.substring(key.length() + 1).trim();
                        if (!v.isEmpty()) {
                            return v;
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return def;
    }

    /** HTTP POST（二进制），非 200 或异常返回 null。 */
    private static byte[] httpPost(String url, String contentType, byte[] body) {
        try {
            HttpURLConnection conn = (HttpURLConnection) new java.net.URI(url).toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(20000);
            conn.setRequestProperty("Content-Type", contentType);
            conn.setRequestProperty("Content-Length", String.valueOf(body.length));
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body);
            }
            int code = conn.getResponseCode();
            if (code != HttpURLConnection.HTTP_OK) {
                System.err.println("[SignTool] HTTP POST 返回 " + code + "（" + url + "）");
                return null;
            }
            ByteArrayOutputStream resp = new ByteArrayOutputStream();
            try (InputStream is = conn.getInputStream()) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) != -1) {
                    resp.write(buf, 0, n);
                }
            }
            return resp.toByteArray();
        } catch (Exception e) {
            // 静默返回 null 会让"时间戳降级 / LTV 缺失"无从排查，必须留下原因
            System.err.println("[SignTool] HTTP POST 失败（" + url + "）: " + e);
            return null;
        }
    }

    /** HTTP GET，非 200 或异常返回 null。 */
    private static byte[] httpGet(String url) {
        try {
            HttpURLConnection conn = (HttpURLConnection) new java.net.URI(url).toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(20000);
            int code = conn.getResponseCode();
            if (code != HttpURLConnection.HTTP_OK) {
                System.err.println("[SignTool] HTTP GET 返回 " + code + "（" + url + "）");
                return null;
            }
            ByteArrayOutputStream resp = new ByteArrayOutputStream();
            try (InputStream is = conn.getInputStream()) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) != -1) {
                    resp.write(buf, 0, n);
                }
            }
            return resp.toByteArray();
        } catch (Exception e) {
            System.err.println("[SignTool] HTTP GET 失败（" + url + "）: " + e);
            return null;
        }
    }

    /** 判断字节是否为 DER 编码（可解析 ASN.1）。 */
    private static boolean isDer(byte[] b) {
        try {
            ASN1Primitive.fromByteArray(b);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** PEM CRL（-----BEGIN X509 CRL-----）→ DER；非 PEM 原样返回。 */
    private static byte[] toDerCrl(byte[] pem) {
        try {
            String s = new String(pem, StandardCharsets.US_ASCII);
            int i = s.indexOf("-----BEGIN");
            int j = s.indexOf("-----END");
            if (i < 0 || j < 0) {
                return isDer(pem) ? pem : null;
            }
            String b64 = s.substring(s.indexOf('\n', i) + 1, j)
                    .replaceAll("[^A-Za-z0-9+/=]", "");
            if (b64.isEmpty()) {
                return null;
            }
            return Base64.getDecoder().decode(b64);
        } catch (Exception e) {
            return null;
        }
    }

    // ============================ PDF 验证 ============================

    /** 验证 PDF 签名：逐个签名字段（DocTimeStamp / 数字签名 / 国密），CMS 验签、ByteRange 摘要比对、证书链。 */
    @SuppressWarnings("unchecked")
    public static String verifyPdf(byte[] pdf) throws Exception {
        StringBuilder sb = new StringBuilder();
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            List<PDSignature> sigs = doc.getSignatureDictionaries();
            if (sigs == null || sigs.isEmpty()) {
                return "未找到 PDF 签名";
            }
            sb.append("PDF 页数: ").append(doc.getNumberOfPages()).append('\n');
            sb.append("签名数量: ").append(sigs.size()).append('\n');

            // PAdES LTV 状态（DSS / VRI 字典）
            COSDictionary dss = doc.getDocumentCatalog().getCOSObject()
                    .getCOSDictionary(COSName.getPDFName("DSS"));
            if (dss != null) {
                COSArray ce = dss.getCOSArray(COSName.getPDFName("Certs"));
                COSArray oc = dss.getCOSArray(COSName.getPDFName("OCSPs"));
                COSArray cr = dss.getCOSArray(COSName.getPDFName("CRLs"));
                COSDictionary vris = dss.getCOSDictionary(COSName.getPDFName("VRI"));
                StringBuilder ltv = new StringBuilder("LTV: 已启用（DSS 字典");
                if (ce != null) ltv.append("，Certs=").append(ce.size());
                if (oc != null) ltv.append("，OCSPs=").append(oc.size());
                if (cr != null) ltv.append("，CRLs=").append(cr.size());
                if (vris != null && vris.size() > 0) {
                    ltv.append("，VRI=").append(vris.keySet().iterator().next().getName());
                }
                ltv.append("）\n");
                sb.append(ltv);
            } else {
                sb.append("LTV: 未启用（无 DSS 字典）\n");
            }

            // 主签名 = 最后一个非文档时间戳签名（数字签名/国密签章）
            PDSignature mainSig = null;
            for (int i = sigs.size() - 1; i >= 0; i--) {
                PDSignature s = sigs.get(i);
                if (!SUBFILTER_ETSI_RFC3161.equals(printable(s.getSubFilter()))) {
                    mainSig = s;
                    break;
                }
            }
            // 逐个验证文档时间戳（DocTimeStamp）
            boolean tsOk = true;
            for (PDSignature s : sigs) {
                if (SUBFILTER_ETSI_RFC3161.equals(printable(s.getSubFilter()))) {
                    tsOk = verifyDocTimeStamp(sb, pdf, s) && tsOk;
                }
            }
            if (mainSig == null) {
                sb.append("\n========================================\n");
                sb.append("最终结论: ").append(tsOk
                        ? "PDF 文档时间戳有效 ✓（未发现数字签名）"
                        : "PDF 文档时间戳无效 ✗").append('\n');
                return sb.toString();
            }

            // 主签名（数字签名/国密签章）验证
            PDSignature sig = mainSig;
            sb.append("签名者: ").append(printable(sig.getName())).append('\n');
            sb.append("原因: ").append(printable(sig.getReason())).append('\n');
            if (sig.getSignDate() != null) {
                sb.append("签名时间: ").append(sig.getSignDate().getTime()).append('\n');
            }
            sb.append("SubFilter: ").append(printable(sig.getSubFilter())).append('\n');

            byte[] contents = sig.getContents();
            if (contents == null || contents.length == 0) {
                return sb.append("[失败] 无签名内容").toString();
            }
            int realLen = contents.length;
            while (realLen > 0 && contents[realLen - 1] == 0) {
                realLen--;
            }
            byte[] cmsBytes = Arrays.copyOf(contents, realLen);
            sb.append("签名区长度: ").append(contents.length)
                    .append(" 字节（去除填充后 ").append(cmsBytes.length).append(" 字节）\n");
            int[] br = sig.getByteRange();
            if (br == null || br.length != 4 || br[1] <= 0) {
                return sb.append("[失败] ByteRange 缺失或非法").toString();
            }
            sb.append("ByteRange: [").append(br[0]).append(", ").append(br[1])
                    .append(", ").append(br[2]).append(", ").append(br[3]).append("]\n");

            ByteArrayOutputStream rangeOut = new ByteArrayOutputStream();
            rangeOut.write(pdf, br[0], br[1]);
            rangeOut.write(pdf, br[2], br[3]);
            byte[] range = rangeOut.toByteArray();
            sb.append("待签名数据长度: ").append(range.length).append(" 字节\n");

            // 国密 GB/T 38540-2020 / GM/T 0031：Contents = SES_Signature（非 CMS），走专用解析
            if (SUBFILTER_GM_SEAL.equals(sig.getSubFilter())) {
                return verifyGmSeal38540(sb, cmsBytes, range);
            }

            CMSSignedData cms;
            try {
                cms = new CMSSignedData(new CMSProcessableByteArray(range), cmsBytes);
            } catch (Exception e) {
                return sb.append("[失败] CMS 解析异常: ").append(e).toString();
            }
            sb.append("contentType: ").append(cms.getSignedContentTypeOID()).append('\n');

            SignerInformationStore sis = cms.getSignerInfos();
            if (sis.size() == 0) {
                return sb.append("[失败] 无 SignerInfo").toString();
            }
            SignerInformation si = sis.getSigners().iterator().next();
            JcaX509CertificateConverter conv = new JcaX509CertificateConverter().setProvider("BC");
            Collection<X509CertificateHolder> certs = cms.getCertificates().getMatches(null);
            sb.append("证书数量: ").append(certs.size()).append('\n');
            X509Certificate signerCert = null;
            Collection<X509CertificateHolder> matched = cms.getCertificates().getMatches(si.getSID());
            if (!matched.isEmpty()) {
                signerCert = conv.getCertificate(matched.iterator().next());
                sb.append("签名者证书: ").append(signerCert.getSubjectX500Principal()).append('\n');
            }
            sb.append("摘要算法: ").append(si.getDigestAlgOID())
                    .append("  签名算法: ").append(si.getEncryptionAlgOID()).append('\n');

            // 签名时间戳（CAdES-T/PAdES-T：SignerInfo unsignedAttrs 的 id-aa-timeStampToken，
            // messageImprint = 按 token 哈希算法的签名值摘要，对齐主流签名工具结构）
            Attribute tsAttr = si.getUnsignedAttributes() == null ? null
                    : si.getUnsignedAttributes().get(new ASN1ObjectIdentifier(OID_TSA_TOKEN));
            if (tsAttr != null && tsAttr.getAttrValues().size() > 0) {
                try {
                    byte[] tokBytes = tsAttr.getAttrValues().getObjectAt(0)
                            .toASN1Primitive().getEncoded("DER");
                    TimeStampToken tst = new TimeStampToken(new CMSSignedData(tokBytes));
                    TimeStampTokenInfo info = tst.getTimeStampInfo();
                    sb.append("签名时间戳(CAdES-T unsignedAttrs): TSA=")
                            .append(info.getTsa() == null ? "（未命名）" : info.getTsa().getName())
                            .append("  时间=").append(info.getGenTime())
                            .append("  算法=").append(info.getHashAlgorithm().getAlgorithm().getId())
                            .append("  绑定签名值=")
                            .append(boundToSignature(info, si.getSignature()))
                            .append('\n');
                } catch (Exception tsE) {
                    sb.append("签名时间戳(CAdES-T unsignedAttrs) 解析异常: ").append(tsE).append('\n');
                }
            } else {
                sb.append("签名时间戳(CAdES-T unsignedAttrs): 无（未嵌入）\n");
            }

            boolean sigOk = false;
            if (signerCert != null) {
                try {
                    sigOk = si.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC")
                            .build(signerCert));
                } catch (Exception e) {
                    sb.append("  签名验证异常: ").append(e).append('\n');
                }
            }
            sb.append("CMS 签名验证: ").append(sigOk ? "通过 ✓" : "失败 ✗").append('\n');

            String digestJca = digestJcaFromOid(si.getDigestAlgOID());
            MessageDigest md = MessageDigest.getInstance(digestJca);
            byte[] calc = md.digest(range);
            byte[] msgDigest = si.getContentDigest();
            boolean hashOk = msgDigest != null && MessageDigest.isEqual(calc, msgDigest);
            sb.append("文档摘要(").append(digestJca).append("): ").append(Hex.toHexString(calc)).append('\n');
            sb.append("messageDigest      : ")
                    .append(Hex.toHexString(msgDigest == null ? new byte[0] : msgDigest)).append('\n');
            sb.append("文档摘要比对: ").append(hashOk ? "通过 ✓" : "失败 ✗").append('\n');

            sb.append("\n[3] 证书链验证\n");
            boolean chainOk = false;
            if (signerCert != null) {
                chainOk = verifyChain(sb, signerCert, certs, conv);
            } else {
                sb.append("  无签名者证书，无法验证链\n");
            }
            sb.append("  证书链: ").append(chainOk ? "通过 ✓" : "失败 ✗").append('\n');

            sb.append("\n========================================\n");
            sb.append("最终结论: ").append((sigOk && hashOk && chainOk)
                    ? "PDF 签名有效 ✓" : "PDF 签名无效 ✗").append('\n');
            return sb.toString();
        }
    }

    /**
     * 验证 PAdES 文档时间戳（DocTimeStamp，SubFilter=ETSI.RFC3161）：
     * Contents 为 RFC 3161 TimeStampToken；校验 messageImprint 与 ByteRange 摘要一致，
     * 并用 token 内 TSA 证书验证签名。
     */
    private static boolean verifyDocTimeStamp(StringBuilder sb, byte[] pdf, PDSignature sig) {
        sb.append("\n[文档时间戳 DocTimeStamp（ETSI.RFC3161）]\n");
        try {
            sb.append("签名者: ").append(printable(sig.getName())).append('\n');
            int[] br = sig.getByteRange();
            if (br == null || br.length != 4 || br[1] <= 0) {
                sb.append("  [失败] ByteRange 缺失或非法\n");
                return false;
            }
            ByteArrayOutputStream rangeOut = new ByteArrayOutputStream();
            rangeOut.write(pdf, br[0], br[1]);
            rangeOut.write(pdf, br[2], br[3]);
            byte[] range = rangeOut.toByteArray();
            sb.append("ByteRange: [").append(br[0]).append(", ").append(br[1])
                    .append(", ").append(br[2]).append(", ").append(br[3]).append("]\n");
            sb.append("待盖章数据长度: ").append(range.length).append(" 字节\n");

            byte[] contents = sig.getContents();
            if (contents == null || contents.length == 0) {
                sb.append("  [失败] 无时间戳内容\n");
                return false;
            }
            int realLen = contents.length;
            while (realLen > 0 && contents[realLen - 1] == 0) {
                realLen--;
            }
            byte[] tokBytes = Arrays.copyOf(contents, realLen);
            sb.append("时间戳区长度: ").append(contents.length)
                    .append(" 字节（去除填充后 ").append(tokBytes.length).append(" 字节）\n");

            TimeStampToken tst = new TimeStampToken(new CMSSignedData(tokBytes));
            TimeStampTokenInfo info = tst.getTimeStampInfo();
            sb.append("TSA: ").append(info.getTsa() == null ? "（未命名）" : info.getTsa().getName()).append('\n');
            sb.append("时间戳时间: ").append(info.getGenTime()).append('\n');
            sb.append("序列号: ").append(info.getSerialNumber()).append('\n');
            sb.append("哈希算法: ").append(info.getHashAlgorithm().getAlgorithm().getId()).append('\n');

            // messageImprint 与 ByteRange 摘要比对
            byte[] imprint = info.getMessageImprintDigest();
            String alg = digestJcaFromOid(info.getHashAlgorithm().getAlgorithm().getId());
            byte[] calc = MessageDigest.getInstance(alg).digest(range);
            boolean imprintOk = imprint != null && MessageDigest.isEqual(imprint, calc);
            sb.append("messageImprint(").append(alg).append("): ")
                    .append(Hex.toHexString(imprint == null ? new byte[0] : imprint)).append('\n');
            sb.append("文档摘要         : ").append(Hex.toHexString(calc)).append('\n');
            sb.append("messageImprint 比对: ").append(imprintOk ? "通过 ✓" : "失败 ✗").append('\n');

            // 用 token 内 TSA 证书验证时间戳签名
            boolean sigOk = false;
            try {
                org.bouncycastle.cms.SignerId sid = tst.getSID();
                @SuppressWarnings("unchecked")
                java.util.Collection<X509CertificateHolder> tsaMatch = tst.getCertificates().getMatches(sid);
                if (!tsaMatch.isEmpty()) {
                    X509Certificate tsaCert = new JcaX509CertificateConverter().setProvider("BC")
                            .getCertificate(tsaMatch.iterator().next());
                    sb.append("TSA 证书: ").append(tsaCert.getSubjectX500Principal()).append('\n');
                    sigOk = tst.isSignatureValid(new JcaSimpleSignerInfoVerifierBuilder()
                            .setProvider("BC").build(tsaCert));
                } else {
                    sb.append("  [失败] token 内无 TSA 证书\n");
                }
            } catch (Exception e) {
                sb.append("  时间戳验签异常: ").append(e).append('\n');
            }
            sb.append("时间戳签名验证: ").append(sigOk ? "通过 ✓" : "失败 ✗").append('\n');
            return imprintOk && sigOk;
        } catch (Exception e) {
            sb.append("  [失败] TimeStampToken 解析异常: ").append(e).append('\n');
            return false;
        }
    }

    // ============================ 工具方法 ============================

    /**
     * 验证国密 SES_Signature（PDF Contents 原始结构，非 CMS）：
     * 支持 GB/T 38540-2020（4 字段：toSign/cert/signatureAlgID/signature）与
     * GM/T 0031（2 字段：toSign/signature，证书与算法在 TBS_Sign 内部）：
     * 1) 解析 SES_Signature；2) dataHash 与 SM3(ByteRange) 比对；
     * 3) 用证书公钥 SM3withSM2 验签 TBS_Sign DER。
     */
    @SuppressWarnings("unchecked")
    private static String verifyGmSeal38540(StringBuilder sb, byte[] contents,
                                            byte[] range) throws Exception {
        ASN1Sequence sesSig = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(contents));
        final boolean is0031 = sesSig.size() == 2;
        // 38540 = 4 字段（无时间戳）或 5 字段（可选第 5 字段 timeStamp，GB/T 38540 7.1.6）
        final boolean is38540 = sesSig.size() == 4 || sesSig.size() == 5;
        if (!is0031 && !is38540) {
            return sb.append("[失败] SES_Signature 字段数=").append(sesSig.size())
                    .append("（应为 2: toSign/signature（GM/T 0031）或 4-5: toSign/cert/signatureAlgID/signature[/timeStamp]（GB/T 38540））")
                    .toString();
        }
        sb.append(is0031 ? "\n[国密 GM/T 0031 SES_Signature 验证]\n"
                : "\n[国密 GB/T 38540-2020 SES_Signature 验证]\n");
        try {
            ASN1Sequence tbs = ASN1Sequence.getInstance(sesSig.getObjectAt(0));
            sb.append("TBS_Sign 字段数: ").append(tbs.size()).append('\n');
            sb.append("TBS version: ").append(ASN1Integer.getInstance(tbs.getObjectAt(0)).getValue()).append('\n');
            if (tbs.size() < 4) {
                return sb.append("[失败] TBS_Sign 缺少 dataHash").toString();
            }
            // dataHash（BIT STRING，两种标准均在 TBS_Sign[3]）
            byte[] embeddedHash = DERBitString.getInstance(tbs.getObjectAt(3)).getBytes();
            // 证书 / 签名算法 / 签名值：38540 在外层，0031 在 TBS_Sign 内部
            byte[] certBytes;
            String sigAlgOid;
            byte[] sigValue;
            if (is0031) {
                if (tbs.size() < 7) {
                    return sb.append("[失败] TBS_Sign 字段数不足 7（GM/T 0031 应为 version/eseal/timeInfo/dataHash/propertyInfo/cert/signatureAlgorithm）")
                            .toString();
                }
                certBytes = ASN1OctetString.getInstance(tbs.getObjectAt(5)).getOctets();
                sigAlgOid = ASN1ObjectIdentifier.getInstance(tbs.getObjectAt(6)).getId();
                sigValue = DERBitString.getInstance(sesSig.getObjectAt(1)).getBytes();
            } else {
                certBytes = ASN1OctetString.getInstance(sesSig.getObjectAt(1)).getOctets();
                sigAlgOid = ASN1ObjectIdentifier.getInstance(sesSig.getObjectAt(2)).getId();
                sigValue = DERBitString.getInstance(sesSig.getObjectAt(3)).getBytes();
            }
            java.security.cert.CertificateFactory cf =
                    java.security.cert.CertificateFactory.getInstance("X.509", "BC");
            X509Certificate signerCert = (X509Certificate) cf
                    .generateCertificate(new ByteArrayInputStream(certBytes));
            sb.append("签名者证书: ").append(signerCert.getSubjectX500Principal()).append('\n');
            sb.append("签名算法 OID: ").append(sigAlgOid).append('\n');
            sb.append("签名值长度: ").append(sigValue.length).append(" 字节\n");

            // 原文 SM3 哈希比对
            MessageDigest sm3 = MessageDigest.getInstance("SM3", "BC");
            byte[] calc = sm3.digest(range);
            boolean hashOk = MessageDigest.isEqual(embeddedHash, calc);
            sb.append("原文SM3哈希: ").append(Hex.toHexString(calc)).append('\n');
            sb.append("内嵌dataHash: ").append(Hex.toHexString(embeddedHash)).append('\n');
            sb.append("文档摘要比对: ").append(hashOk ? "通过 ✓" : "失败 ✗").append('\n');

            // 验签（TBS_Sign 完整 DER）
            byte[] tbsDer = tbs.getEncoded("DER");
            boolean sigOk = false;
            try {
                Signature ver = Signature.getInstance("SM3WITHSM2", "BC");
                ver.initVerify(signerCert.getPublicKey());
                ver.update(tbsDer);
                sigOk = ver.verify(sigValue);
            } catch (Exception e) {
                sb.append("  SM3withSM2 验签异常: ").append(e).append('\n');
            }
            sb.append("SM2 签名验证: ").append(sigOk ? "通过 ✓" : "失败 ✗").append('\n');

            // 印章签名自检：GB/T 38540 = 制章者对 eSealInfo（SEQUENCE）的 SM3withSM2 签名；
            // GM/T 0031 = 制章人对 SEQUENCE{ SES_SealInfo, 制章人证书, 签名算法标识 } 的签名。
            boolean sealSigOk = true;
            if (is38540) {
                try {
                    ASN1Sequence eseal = ASN1Sequence.getInstance(tbs.getObjectAt(1));
                    byte[] eSealInfoDer = eseal.getObjectAt(0).toASN1Primitive().getEncoded("DER");
                    byte[] sealCertBytes = ASN1OctetString.getInstance(eseal.getObjectAt(1)).getOctets();
                    byte[] sealSignedValue = DERBitString.getInstance(eseal.getObjectAt(3)).getBytes();
                    X509Certificate sealCert = (X509Certificate) cf
                            .generateCertificate(new ByteArrayInputStream(sealCertBytes));
                    boolean sOk = false;
                    try {
                        Signature ver = Signature.getInstance("SM3WITHSM2", "BC");
                        ver.initVerify(sealCert.getPublicKey());
                        ver.update(eSealInfoDer);
                        sOk = ver.verify(sealSignedValue);
                    } catch (Exception e) {
                        sb.append("  印章验签异常: ").append(e).append('\n');
                    }
                    sb.append("印章签名验证(制章者 ").append(shortDn(sealCert.getSubjectX500Principal().toString()))
                            .append("): ").append(sOk ? "通过 ✓" : "失败 ✗").append('\n');
                    sealSigOk = sOk;
                } catch (Exception e) {
                    sb.append("  印章解析异常: ").append(e).append('\n');
                    sealSigOk = false;
                }
            } else if (is0031) {
                try {
                    ASN1Sequence eseal = ASN1Sequence.getInstance(tbs.getObjectAt(1));
                    byte[] eSealInfoDer = eseal.getObjectAt(0).toASN1Primitive().getEncoded("DER");
                    ASN1Sequence signInfo = ASN1Sequence.getInstance(eseal.getObjectAt(1));
                    byte[] sealCertBytes = ASN1OctetString.getInstance(signInfo.getObjectAt(0)).getOctets();
                    byte[] sealSignedValue = DERBitString.getInstance(signInfo.getObjectAt(2)).getBytes();
                    X509Certificate sealCert = (X509Certificate) cf
                            .generateCertificate(new ByteArrayInputStream(sealCertBytes));
                    boolean sOk = false;
                    try {
                        // GM/T 0031 6.1.1.2：signData = 制章人对 SEQUENCE{ 印章信息, 制章人证书, 签名算法标识 } 的签名
                        ASN1EncodableVector st = new ASN1EncodableVector();
                        st.add(eseal.getObjectAt(0));
                        st.add(signInfo.getObjectAt(0));
                        st.add(signInfo.getObjectAt(1));
                        byte[] signTarget = new DERSequence(st).getEncoded("DER");
                        Signature ver = Signature.getInstance("SM3WITHSM2", "BC");
                        ver.initVerify(sealCert.getPublicKey());
                        ver.update(signTarget);
                        sOk = ver.verify(sealSignedValue);
                    } catch (Exception e) {
                        sb.append("  印章验签异常: ").append(e).append('\n');
                    }
                    sb.append("印章签名验证(制章者 ").append(shortDn(sealCert.getSubjectX500Principal().toString()))
                            .append("): ").append(sOk ? "通过 ✓" : "失败 ✗").append('\n');
                    sealSigOk = sOk;
                } catch (Exception e) {
                    sb.append("  印章解析异常: ").append(e).append('\n');
                    sealSigOk = false;
                }
            }

            // GB/T 38540 7.1.6 时间戳：SES_Signature 可选第 5 字段 timeStamp[0] BIT STRING
            // （对签名值的时间戳，GB/T 20520 = RFC3161，DER 编码；SM2/SM3 场景 messageImprint=SM3）。
            // 兼容解析：EXPLICIT [0]（A0 包 03，标准默认）/ IMPLICIT [0]（80 00…）/ universal BIT STRING（03）/ 旧 OCTET STRING（04）。
            boolean tsOk = true;
            if (is38540 && sesSig.size() >= 5) {
                try {
                    byte[] tok = null;
                    ASN1Encodable tsObj = sesSig.getObjectAt(4);
                    if (tsObj instanceof ASN1TaggedObject) {
                        ASN1TaggedObject tagged = (ASN1TaggedObject) tsObj;
                        // EXPLICIT [0]（A0 包 03/04）或 IMPLICIT [0]（80/81）都兼容
                        ASN1Primitive inner = null;
                        try {
                            inner = tagged.getBaseUniversal(true, org.bouncycastle.asn1.BERTags.BIT_STRING);
                        } catch (Exception e1) {
                            try {
                                inner = tagged.getBaseUniversal(true, org.bouncycastle.asn1.BERTags.OCTET_STRING);
                            } catch (Exception e2) {
                                inner = tagged.getBaseUniversal(false, org.bouncycastle.asn1.BERTags.BIT_STRING);
                            }
                        }
                        if (inner instanceof DERBitString) {
                            tok = DERBitString.getInstance(inner).getBytes();
                        } else if (inner instanceof ASN1OctetString) {
                            tok = ASN1OctetString.getInstance(inner).getOctets();
                        } else {
                            tok = inner.getEncoded("DER");
                        }
                    } else if (tsObj instanceof DERBitString) {
                        tok = DERBitString.getInstance(tsObj).getBytes();
                    } else if (tsObj instanceof ASN1OctetString) {
                        tok = ASN1OctetString.getInstance(tsObj).getOctets();
                    }
                    if (tok == null || tok.length == 0) {
                        sb.append("签名时间戳(timeStamp 字段): 解析失败（未知编码）\n");
                        tsOk = false;
                    } else {
                        TimeStampToken tst = new TimeStampToken(new CMSSignedData(tok));
                        TimeStampTokenInfo info = tst.getTimeStampInfo();
                        sb.append("签名时间戳(timeStamp 字段): TSA=")
                                .append(info.getTsa() == null ? "（未命名）" : info.getTsa().getName())
                                .append("  时间=").append(info.getGenTime())
                                .append("  算法=").append(info.getHashAlgorithm().getAlgorithm().getId())
                                .append('\n');
                        // 绑定校验：messageImprint = SM3(签名值)
                        MessageDigest md = MessageDigest.getInstance("SM3", "BC");
                        boolean bound = Arrays.equals(info.getMessageImprintDigest(), md.digest(sigValue));
                        sb.append("绑定签名值(SM3): ").append(bound ? "通过 ✓" : "失败 ✗").append('\n');
                        // TSA 证书验签
                        boolean tsaOk = false;
                        try {
                            Collection<X509CertificateHolder> tsaCerts =
                                    tst.getCertificates().getMatches(tst.getSID());
                            if (!tsaCerts.isEmpty()) {
                                X509CertificateHolder tsaHolder = tsaCerts.iterator().next();
                                X509Certificate tsaCert = (X509Certificate) cf
                                        .generateCertificate(new ByteArrayInputStream(tsaHolder.getEncoded()));
                                org.bouncycastle.cms.SignerInformationVerifier verifier =
                                        new JcaSimpleSignerInfoVerifierBuilder()
                                                .setProvider("BC").build(tsaCert);
                                tsaOk = tst.isSignatureValid(verifier);
                            }
                        } catch (Exception e) {
                            sb.append("  TSA 验签异常: ").append(e).append('\n');
                        }
                        sb.append("TSA 证书验签: ").append(tsaOk ? "通过 ✓" : "失败 ✗").append('\n');
                        tsOk = bound && tsaOk;
                    }
                } catch (Exception tsE) {
                    sb.append("签名时间戳(timeStamp 字段) 解析异常: ").append(tsE).append('\n');
                    tsOk = false;
                }
            } else if (is0031) {
                // GM/T 0031 timeInfo（TBS_Sign[2] BIT STRING）：
                // 内容可为"时间戳（TimeStampToken DER）"或"UTCTIME 时间（DER）"。
                // 时间戳绑定原文杂凑（messageImprint = dataHash，因 timeInfo 先于签名值存在）。
                try {
                    byte[] tiBytes = DERBitString.getInstance(tbs.getObjectAt(2)).getBytes();
                    boolean parsedTs = false;
                    if (tiBytes != null && tiBytes.length > 0) {
                        try {
                            TimeStampToken tst = new TimeStampToken(new CMSSignedData(tiBytes));
                            TimeStampTokenInfo info = tst.getTimeStampInfo();
                            sb.append("签章时间信息(timeInfo): TSA=")
                                    .append(info.getTsa() == null ? "（未命名）" : info.getTsa().getName())
                                    .append("  时间=").append(info.getGenTime())
                                    .append("  算法=").append(info.getHashAlgorithm().getAlgorithm().getId())
                                    .append('\n');
                            boolean bound = Arrays.equals(info.getMessageImprintDigest(), embeddedHash);
                            sb.append("绑定原文杂凑(SM3): ").append(bound ? "通过 ✓" : "失败 ✗").append('\n');
                            boolean tsaOk = false;
                            try {
                                Collection<X509CertificateHolder> tsaCerts =
                                        tst.getCertificates().getMatches(tst.getSID());
                                if (!tsaCerts.isEmpty()) {
                                    X509CertificateHolder tsaHolder = tsaCerts.iterator().next();
                                    X509Certificate tsaCert = (X509Certificate) cf.generateCertificate(
                                            new ByteArrayInputStream(tsaHolder.getEncoded()));
                                    org.bouncycastle.cms.SignerInformationVerifier verifier =
                                            new JcaSimpleSignerInfoVerifierBuilder()
                                                    .setProvider("BC").build(tsaCert);
                                    tsaOk = tst.isSignatureValid(verifier);
                                }
                            } catch (Exception e) {
                                sb.append("  TSA 验签异常: ").append(e).append('\n');
                            }
                            sb.append("TSA 证书验签: ").append(tsaOk ? "通过 ✓" : "失败 ✗").append('\n');
                            tsOk = bound && tsaOk;
                            parsedTs = true;
                        } catch (Exception te) {
                            // 不是时间戳 → 尝试按 UTCTime 解析
                            try {
                                ASN1UTCTime utc = ASN1UTCTime.getInstance(
                                        ASN1Primitive.fromByteArray(tiBytes));
                                sb.append("签章时间信息(timeInfo): UTCTime ").append(utc.getDate()).append('\n');
                            } catch (Exception ue) {
                                sb.append("签章时间信息(timeInfo): 无法解析（")
                                        .append(Hex.toHexString(tiBytes).substring(0,
                                                Math.min(32, Hex.toHexString(tiBytes).length())))
                                        .append("…）\n");
                            }
                        }
                    } else {
                        sb.append("签章时间信息(timeInfo): 空\n");
                    }
                } catch (Exception e) {
                    sb.append("签章时间信息(timeInfo) 解析异常: ").append(e).append('\n');
                }
            } else {
                sb.append("签名时间戳(timeStamp 字段): 无（未嵌入）\n");
            }

            sb.append("\n========================================\n");
            sb.append("最终结论: ").append((sigOk && hashOk && tsOk && sealSigOk)
                    ? "国密 PDF 电子签章有效 ✓" : "国密 PDF 电子签章无效 ✗").append('\n');
            return sb.toString();
        } catch (Exception e) {
            return sb.append("[失败] SES_Signature 解析异常: ").append(e).append('\n').toString();
        }
    }

    private static String shortDn(String dn) {
        if (dn != null && dn.length() > 120) {
            return dn.substring(0, 120) + "...";
        }
        return dn;
    }

    private static String printable(String s) {
        return s == null || s.isEmpty() ? "(未填写)" : s;
    }

    /** 解析 DER SEQUENCE 对象实际编码总长度（tag + 长度字段 + content），从指定偏移开始。 */
    private static int asn1ObjectTotalLength(byte[] d, int off) {
        int idx = off + 1; // 跳过 tag(0x30)
        int len = d[idx] & 0xFF;
        if ((len & 0x80) != 0) {
            int nb = len & 0x7F;
            len = 0;
            for (int i = 0; i < nb; i++) {
                len = (len << 8) | (d[idx + 1 + i] & 0xFF);
            }
            idx += nb;
        }
        return idx + 1 + len - off;
    }

    private static int readU16(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
    }

    private static long readU32(byte[] b, int off) {
        return (b[off] & 0xFFL) | ((b[off + 1] & 0xFFL) << 8)
                | ((b[off + 2] & 0xFFL) << 16) | ((b[off + 3] & 0xFFL) << 24);
    }

    private static void writeU32(byte[] b, int off, int val) {
        b[off] = (byte) (val & 0xFF);
        b[off + 1] = (byte) ((val >>> 8) & 0xFF);
        b[off + 2] = (byte) ((val >>> 16) & 0xFF);
        b[off + 3] = (byte) ((val >>> 24) & 0xFF);
    }

    private static void writeU32(ByteArrayOutputStream out, int val) {
        out.write(val & 0xFF);
        out.write((val >>> 8) & 0xFF);
        out.write((val >>> 16) & 0xFF);
        out.write((val >>> 24) & 0xFF);
    }

    private static void writeU16(ByteArrayOutputStream out, int val) {
        out.write(val & 0xFF);
        out.write((val >>> 8) & 0xFF);
    }

    private static byte[] readAllBytes(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }

    /** 校验时间戳 messageImprint 是否绑定签名值（按 token 哈希算法自适应 SHA-256/SM3 等）。 */
    private static boolean boundToSignature(TimeStampTokenInfo info, byte[] signature) {
        try {
            String oid = info.getHashAlgorithm().getAlgorithm().getId();
            if ("1.2.156.10197.1.401".equals(oid)) {
                MessageDigest md = MessageDigest.getInstance("SM3", "BC");
                return Arrays.equals(info.getMessageImprintDigest(), md.digest(signature));
            }
            if ("2.16.840.1.101.3.4.2.1".equals(oid)) {
                return Arrays.equals(info.getMessageImprintDigest(),
                        MessageDigest.getInstance("SHA-256").digest(signature));
            }
            if ("2.16.840.1.101.3.4.2.4".equals(oid)) {
                return Arrays.equals(info.getMessageImprintDigest(),
                        MessageDigest.getInstance("SHA-224").digest(signature));
            }
            if ("2.16.840.1.101.3.4.2.2".equals(oid)) {
                return Arrays.equals(info.getMessageImprintDigest(),
                        MessageDigest.getInstance("SHA-384").digest(signature));
            }
            if ("2.16.840.1.101.3.4.2.3".equals(oid)) {
                return Arrays.equals(info.getMessageImprintDigest(),
                        MessageDigest.getInstance("SHA-512").digest(signature));
            }
            return false; // 其他算法无法判定
        } catch (Exception e) {
            return false;
        }
    }
}
