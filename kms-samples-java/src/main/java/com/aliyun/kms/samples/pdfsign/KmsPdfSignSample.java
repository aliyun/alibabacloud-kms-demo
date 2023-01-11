package com.aliyun.kms.samples.pdfsign;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.kms.model.v20160120.GetSecretValueRequest;
import com.aliyuncs.kms.model.v20160120.GetSecretValueResponse;
import com.aliyuncs.kms.model.v20160120.ListKeyVersionsRequest;
import com.aliyuncs.kms.model.v20160120.ListKeyVersionsResponse;
import com.itextpdf.kernel.font.PdfFont;
import com.itextpdf.kernel.font.PdfFontFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import com.itextpdf.test.signutils.Pkcs12FileHelper;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;

public class KmsPdfSignSample {
    public static final String RESOURCES_FOLDER = System.getProperty("user.dir") + "/kmsPdfsign-samples-java/src/main/resources/";
    public static final String FONT = RESOURCES_FOLDER + "/FreeSans.ttf";
    public static final String SOURCE_PDF = RESOURCES_FOLDER + "TEST_PDF.pdf";
    public static final String DEST_PDF = RESOURCES_FOLDER + "sampleSignature.pdf";
    // change with your regionId
    public static final String REGION_ID = "cn-hangzhou";
    // your AccessKeyId
    public static final String ACCESS_KEY_ID = System.getenv("AccessKeyId");
    // your AccessKeySecret
    public static final String ACCESS_KEY_SECRET = System.getenv("AccessKeySecret");

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        // your MasterKeyId
        String keyId = "fa84eabd-6eb3-432b-bad1-**********f3";
        // keyVersionId can be null
        String keyVersionId = "";
        KMSiTextSignature kmsiTextSignature = new KMSiTextSignature();
        DefaultAcsClient kmsClient = kmsiTextSignature.kmsClient(REGION_ID, ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        signPdfWithAliyunKMS(keyId, keyVersionId, kmsClient, "pdfSignCert", false);
    }

    /**
     * 基于kms对pdf签名
     *
     * @param keyId        主密钥（CMK）的全局唯一标识符
     * @param keyVersionId 密钥版本的全局唯一标识符
     * @param secretName   从凭据管家获取证书时需要的凭据名称（使用本地证书时不需要）
     * @param bLocalCert   是否使用本地证书
     * @throws Exception
     */
    public static void signPdfWithAliyunKMS(String keyId, String keyVersionId, DefaultAcsClient kmsClient, String secretName, boolean bLocalCert) throws Exception {
        KMSiTextSignature kmsSignature = getKmsSignature(keyId, keyVersionId, kmsClient);
        HashMap<String, Object> certAndChainMap;
        if (bLocalCert) {
            certAndChainMap = getCertificatesFromLocal();
        } else {
            if (secretName == null) {
                throw new Exception("secretName cannot be null");
            }
            certAndChainMap = getCertificatesFromSecretManager(kmsClient, secretName);
        }
        Certificate certificate = (Certificate) certAndChainMap.get("Certificate");
        Certificate[] certificateChain = (Certificate[]) certAndChainMap.get("CertificateChain");
        pdfSign(certificate, certificateChain, kmsSignature);
    }

    /**
     * 读取本地pfx文件加载证书和私钥对pdf签名
     *
     * @param password pfx文件密码
     * @throws Exception
     */
    public static void signPdfWithPKCS12(char[] password) throws Exception {
        String path = RESOURCES_FOLDER + "signCertRsa01.p12";
        PrivateKey pk = Pkcs12FileHelper.readFirstKey(path, password, password);
        Certificate[] chain = Pkcs12FileHelper.readFirstChain(path, password);
        IExternalSignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, BouncyCastleProvider.PROVIDER_NAME);
        PdfSigner signer = getPdfSigner(false, null, null,
                "signature1", "Test", "TestLocation");
        signer.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CADES);
    }

    /**
     * 从本地获取证书
     *
     * @return HashMap 证书和证书链的map集合
     * @throws Exception
     */
    public static HashMap<String, Object> getCertificatesFromLocal() throws Exception {
        String certStr = FileUtils.readFileToString(new File(RESOURCES_FOLDER + "signcert.pem"), "UTF-8");
        Certificate certLocal = readPemCert(certStr);
        String chainStr = FileUtils.readFileToString(new File(RESOURCES_FOLDER + "certchain.pem"), "UTF-8");
        Certificate[] chainLocal = readPemCertChain(chainStr);
        if (certLocal == null || chainLocal.length == 0) {
            throw new Exception("Cert or chain cannot be null.");
        }
        HashMap<String, Object> certAndChainMap = new HashMap<>();
        certAndChainMap.put("Certificate", certLocal);
        certAndChainMap.put("CertificateChain", chainLocal);
        return certAndChainMap;
    }

    /**
     * 从凭据管家获取证书
     *
     * @param secretName 存储在凭据管家中的凭据名称
     * @return HashMap 证书和证书链的map集合
     * @throws Exception
     */
    public static HashMap<String, Object> getCertificatesFromSecretManager(DefaultAcsClient kmsClient, String secretName) throws Exception {
        String certificateFromSecretManager = getCertFromSecretManager(kmsClient, secretName);
        if (certificateFromSecretManager == null || "".equals(certificateFromSecretManager)) {
            throw new Exception("Cert cannot be null.");
        }
        JSONObject jsonObject = JSON.parseObject(certificateFromSecretManager);
        String cert = jsonObject.getString("Certificate");
        String chain = jsonObject.getString("CertificateChain");
        if (cert == null || "".equals(cert) || chain == null || "".equals(chain)) {
            throw new Exception("cert or chain cannot be null.");
        }
        Certificate[] certificateChain = readPemCertChain(chain);
        Certificate certificate = readPemCert(cert);
        HashMap<String, Object> certAndChainMap = new HashMap<>();
        certAndChainMap.put("Certificate", certificate);
        certAndChainMap.put("CertificateChain", certificateChain);
        return certAndChainMap;
    }


    /**
     * 根据凭据名称从凭据管家获取证书和证书链json字符串
     *
     * @param secretName 凭据名称
     * @return String 证书和证书链json字符串
     * @throws ClientException
     */
    private static String getCertFromSecretManager(DefaultAcsClient kmsClient, String secretName) throws ClientException {
        GetSecretValueRequest request = new GetSecretValueRequest();
        request.setSecretName(secretName);
        GetSecretValueResponse response = kmsClient.getAcsResponse(request);
        return response.getSecretData();
    }

    /**
     * 对pdf进行签名
     *
     * @param certificate  签名证书
     * @param certificates 证书链
     * @param kmsSignature kms签名
     * @throws Exception
     */
    private static void pdfSign(Certificate certificate, Certificate[] certificates, KMSiTextSignature kmsSignature) throws Exception {
        PdfSigner signer = getPdfSigner(false, null, null,
                "signature1", "Test", "TestLocation");

        String algorithm = certificate.getPublicKey().getAlgorithm();
        algorithm = algorithm.startsWith("EC") ? "ECDSA" : algorithm;
        kmsSignature.algorithm = algorithm;
        System.out.println("algorithm: " + algorithm);

        signer.signDetached(new BouncyCastleDigest(), kmsSignature, certificates, null, null, null, 0, PdfSigner.CryptoStandard.CADES);
    }

    /**
     * 获取pdf签名对象
     *
     * @param isAppendMode
     * @param rectangleForNewField 签章样式
     * @param fontSize             签章字体大小
     * @param fieldName            签章名称
     * @param reason               签名原因
     * @param location             签名地点
     * @return PdfSigner pdf签名对象
     * @throws IOException
     */
    private static PdfSigner getPdfSigner(boolean isAppendMode, Rectangle rectangleForNewField, Float fontSize, String fieldName, String reason, String location) throws IOException {
        PdfDocument pdfDocument = new PdfDocument(new PdfReader(SOURCE_PDF));
        PdfReader reader = new PdfReader(SOURCE_PDF);
        System.out.println("pdf pages:" + pdfDocument.getNumberOfPages());

        StampingProperties properties = new StampingProperties();
        if (isAppendMode) {
            properties.useAppendMode();
        }
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(DEST_PDF), properties);
        int certificationLevel = PdfSigner.NOT_CERTIFIED;
        signer.setCertificationLevel(certificationLevel);

        PdfFont font = PdfFontFactory.createFont(FONT, "WinAnsi", true);

        // Creating the appearance
        PdfSignatureAppearance appearance = signer.getSignatureAppearance()
                .setReason(reason)
                .setLocation(location)
                .setLayer2Font(font)
                .setReuseAppearance(false);

        if (rectangleForNewField == null) {
            int x = 400;
            int y = 50;
            int w = 200;
            int h = 100;
            rectangleForNewField = new Rectangle(x, y, w, h);
        }
        appearance.setPageRect(rectangleForNewField);

        if (fontSize == null) {
            fontSize = 12f;
            appearance.setLayer2FontSize(fontSize);
        }

        signer.setFieldName(fieldName);
        return signer;
    }

    /**
     * 获取kms签名
     *
     * @param keyId        主密钥（CMK）的全局唯一标识符
     * @param keyVersionId 密钥版本的全局唯一标识符
     * @return KMSiTextSignature kms签名
     * @throws ClientException
     */
    private static KMSiTextSignature getKmsSignature(String keyId, String keyVersionId, DefaultAcsClient kmsClient) throws ClientException {
        KMSiTextSignature kmsiTextSignature = new KMSiTextSignature();
        kmsiTextSignature.kmsClient = kmsClient;
        kmsiTextSignature.hashAlgorithm = DigestAlgorithms.SHA256;
        kmsiTextSignature.keyId = keyId;
        if ("".equals(keyVersionId) || keyVersionId == null) {
            kmsiTextSignature.keyVersionId = listKeyVersions(keyId, kmsClient).get(0).getKeyVersionId();
        } else {
            kmsiTextSignature.keyVersionId = keyVersionId;
        }
        return kmsiTextSignature;
    }

    /**
     * 获取主密钥版本号集合
     *
     * @param keyId 主密钥（CMK）的全局唯一标识符
     * @return List 主密钥版本号的集合
     * @throws ClientException
     */
    private static List<ListKeyVersionsResponse.KeyVersion> listKeyVersions(String keyId, DefaultAcsClient kmsClient) throws ClientException {
        Integer pageNumber = 1;
        List<ListKeyVersionsResponse.KeyVersion> listKeyVersions = new ArrayList<>();
        for (; ; ) {
            ListKeyVersionsRequest listKeyVersionsReq = new ListKeyVersionsRequest();
            listKeyVersionsReq.setAcceptFormat(FormatType.JSON);
            listKeyVersionsReq.setKeyId(keyId);
            listKeyVersionsReq.setPageNumber(pageNumber);
            listKeyVersionsReq.setPageSize(10);
            ListKeyVersionsResponse listKeyVersionsRes = kmsClient.getAcsResponse(listKeyVersionsReq);
            List<ListKeyVersionsResponse.KeyVersion> keyVersions = listKeyVersionsRes.getKeyVersions();
            Iterator<ListKeyVersionsResponse.KeyVersion> iterator = keyVersions.iterator();

            for (; iterator.hasNext(); ) {
                listKeyVersions.add(iterator.next());
            }
            pageNumber = listKeyVersionsRes.getPageNumber();
            Integer totalCount = listKeyVersionsRes.getTotalCount();
            if (pageNumber * 10 >= totalCount) {
                break;
            }
            pageNumber++;
        }
        return listKeyVersions;
    }

    /**
     * 解析证书
     *
     * @param pemCert 证书字符串
     * @return Certificate 证书
     * @throws Exception
     */
    private static Certificate readPemCert(String pemCert) throws Exception {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(pemCert.getBytes());
        java.security.cert.CertificateFactory factory = java.security.cert.CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
        return factory.generateCertificate(inputStream);
    }

    /**
     * 解析证书链
     *
     * @param chain 证书链字符串
     * @return Certificate[] 证书链
     * @throws CertificateException
     */
    private static Certificate[] readPemCertChain(String chain) throws CertificateException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(chain.getBytes());
        java.security.cert.CertificateFactory factory = java.security.cert.CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
        Collection<? extends Certificate> certificates = factory.generateCertificates(inputStream);
        return certificates.toArray(new Certificate[certificates.size()]);
    }

}
