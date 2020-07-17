package com.aliyun.kms.samples;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.kms.model.v20160120.*;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;


public class GenerateECCSR {

    private static DefaultAcsClient kmsClient;
    private static Map<String, String> digestAlgs = new HashMap<>();
    static {
        digestAlgs.put("RSA_PKCS1_SHA_256", "SHA-256");
        digestAlgs.put("ECDSA_SHA_256", "SHA-256");
    }

    //实现KMS的ContentSigner构建器
    private static class KmsContentSignerBuilder implements ContentSigner {
        private DefaultAcsClient kmsClient;
        private String kmsAlgorithm;
        private String keyId;
        private String keyVersionId;
        private AlgorithmIdentifier sigAlgId;
        private ByteArrayOutputStream stream;

        KmsContentSignerBuilder(DefaultAcsClient kmsClient, String keyId, String keyVersionId, String kmsAlgorithm, String signatureAlgorithm) {
            this.kmsClient = kmsClient;
            this.kmsAlgorithm = kmsAlgorithm;
            this.keyId = keyId;
            this.keyVersionId = keyVersionId;
            this.sigAlgId = (new DefaultSignatureAlgorithmIdentifierFinder()).find(signatureAlgorithm);
            this.stream = new ByteArrayOutputStream();
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return this.sigAlgId;
        }

        @Override
        public OutputStream getOutputStream() {
            return this.stream;
        }

        @Override
        public byte[] getSignature() {
            try {
                return asymmetricSign(this.keyId, this.keyVersionId, this.kmsAlgorithm, stream.toByteArray());
            } catch (Exception e) {
                throw new RuntimeOperatorException("exception obtaining signature: " + e.getMessage(), e);
            }
        }

        private byte[] asymmetricSign(String keyId, String keyVersionId, String algorithm, byte[] message) throws ClientException, NoSuchAlgorithmException {
            final AsymmetricSignRequest req = new AsymmetricSignRequest();
            byte[] digest = MessageDigest.getInstance(digestAlgs.get(algorithm)).digest(message);
            //digest要进行base64编码
            String base64Digest = Base64.getEncoder().encodeToString(digest);
            req.setAcceptFormat(FormatType.JSON);
            req.setKeyId(keyId);
            req.setKeyVersionId(keyVersionId);
            req.setAlgorithm(algorithm);
            req.setDigest(base64Digest);
            AsymmetricSignResponse asymSignRes = this.kmsClient.getAcsResponse(req);
            //签名要进行base64解码
            return Base64.getDecoder().decode(asymSignRes.getValue().getBytes(StandardCharsets.UTF_8));
        }
    }

    private static DefaultAcsClient kmsClient(String regionId, String accessKeyId, String accessKeySecret, String endpoint, String ignoreSSLCerts) {
        if (endpoint != null) {
            DefaultProfile.addEndpoint(regionId, "Kms", endpoint);
        }
        IClientProfile profile = DefaultProfile.getProfile(regionId, accessKeyId, accessKeySecret);
        HttpClientConfig clientConfig = HttpClientConfig.getDefault();
        if (ignoreSSLCerts != null) {
            clientConfig.setIgnoreSSLCerts(Boolean.parseBoolean(ignoreSSLCerts));
        }
        profile.setHttpClientConfig(clientConfig);
        return new DefaultAcsClient(profile);
    }

    private static String createKey(String KeySpec, String keyUsage) throws ClientException {
        final CreateKeyRequest req = new CreateKeyRequest();
        req.setAcceptFormat(FormatType.JSON);
        req.setKeySpec(KeySpec);
        req.setKeyUsage(keyUsage);
        CreateKeyResponse keyRes = kmsClient.getAcsResponse(req);
        return keyRes.getKeyMetadata().getKeyId();
    }

    private static String getPublicKey(String keyId, String keyVersionId) throws ClientException {
        final GetPublicKeyRequest req = new GetPublicKeyRequest();
        req.setAcceptFormat(FormatType.JSON);
        req.setKeyId(keyId);
        req.setKeyVersionId(keyVersionId);
        GetPublicKeyResponse publicKeyRes = kmsClient.getAcsResponse(req);
        return publicKeyRes.getPublicKey();
    }

    private static List<ListKeyVersionsResponse.KeyVersion> listKeyVersions(String keyId) throws ClientException {
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

    private static String generateCSR(String keyId, String keyVersionId, String subjectName, List<String> nameList, String kmsSignAlgorithm, String signatureAlgorithm) throws Exception {
        GeneralName[] gns = new GeneralName[nameList.size()];
        for (int i = 0; i < nameList.size(); i++) {
            gns[i] = new GeneralName(GeneralName.dNSName, nameList.get(i));
        }
        GeneralNames subjectAltName = new GeneralNames(gns);

        //获取KMS ECC公钥
        String publicKeyPem = getPublicKey(keyId, keyVersionId);
        publicKeyPem = publicKeyPem.replaceFirst("-----BEGIN PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceFirst("-----END PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceAll("\\s", "");
        byte[] publicKeyDer = Base64.getDecoder().decode(publicKeyPem);
        //ECC PEM公钥转换为PublicKey结构
        PublicKey pubKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(publicKeyDer));

        //创建CSR构建器
        PKCS10CertificationRequestBuilder p10Builder = new PKCS10CertificationRequestBuilder(new X500Name(subjectName), SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()));

        //添加CSR扩展属性
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, subjectAltName);
        p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());

        //创建KMS签名器
        ContentSigner signer = new KmsContentSignerBuilder(kmsClient, keyId, keyVersionId, kmsSignAlgorithm, signatureAlgorithm);

        //构建CSR
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        try (StringWriter sw = new StringWriter();
             JcaPEMWriter pem = new JcaPEMWriter(sw);) {
            pem.writeObject(csr);
            pem.flush();
            return sw.toString();
        }
    }

    private static void writeTextFile(String outFile, String content) throws IOException {
        File file = new File(outFile);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content.getBytes());
        }
    }

    public static void main(String[] args) {
        String regionId = "cn-hangzhou"; //KMS服务区域，根据实际情况修改
        String accessKeyId = System.getenv("AccessKeyId");
        String accessKeySecret = System.getenv("AccessKeySecret");

        kmsClient = kmsClient(regionId, accessKeyId, accessKeySecret, null, null);

        try {
            String keySpec = "EC_P256";
            String keyUsage = "SIGN/VERIFY";

            //创建KMS ECC非对称密钥（EC_P256，SIGN/VERIFY）
            String keyId = createKey(keySpec, keyUsage);

            //获取非对称密钥密钥版本ID
            List<ListKeyVersionsResponse.KeyVersion> keyVersionList = listKeyVersions(keyId);
            String keyVersionId = keyVersionList.get(0).getKeyVersionId();

            String subjectName = "CN=Test Certificate Request, O=Aliyun KMS, C=CN";
            String kmsAlgorithm = "ECDSA_SHA_256";
            String signatureAlgorithm = "SHA256withECDSA";
            String outFile = "./test.csr";
            List<String> domain = new ArrayList<>() {{
                add("test.com");
            }};

            //获取CSR
            String csr = generateCSR(keyId, keyVersionId, subjectName, domain, kmsAlgorithm, signatureAlgorithm);

            //输出到本地
            writeTextFile(outFile, csr);

        } catch (ClientException e) {
            System.out.println("Failed.");
            System.out.println("Error code: " + e.getErrCode());
            System.out.println("Error message: " + e.getErrMsg());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
