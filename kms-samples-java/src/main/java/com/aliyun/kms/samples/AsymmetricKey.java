package com.aliyun.kms.samples;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.List;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.http.MethodType;
import com.aliyuncs.http.ProtocolType;

import com.aliyuncs.kms.model.v20160120.*;
import com.aliyuncs.kms.model.v20160120.ListKeysResponse.Key;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;


public class AsymmetricKey {
    private static DefaultAcsClient kmsClient;

    private static DefaultAcsClient kmsClient(String regionId, String accessKeyId, String accessKeySecret) {
        IClientProfile profile = DefaultProfile.getProfile(regionId, accessKeyId, accessKeySecret);
        HttpClientConfig clientConfig = HttpClientConfig.getDefault();
        //clientConfig.setIgnoreSSLCerts(true);
        profile.setHttpClientConfig(clientConfig);

        return new DefaultAcsClient(profile);
    }

    private static List<String> ListKeys() throws ClientException {
        Integer pageNumber = 1;
        String keyId;
        List<String> listKeys = new ArrayList<>();
        for (; ; ) {
            ListKeysRequest listKeysReq = new ListKeysRequest();
            listKeysReq.setSysProtocol(ProtocolType.HTTPS);
            listKeysReq.setAcceptFormat(FormatType.JSON);
            listKeysReq.setSysMethod(MethodType.POST);
            listKeysReq.setPageNumber(pageNumber);
            listKeysReq.setPageSize(10);
            ListKeysResponse listKeysRes = kmsClient.getAcsResponse(listKeysReq);
            List<Key> keys = listKeysRes.getKeys();
            Iterator<Key> iterator = keys.iterator();

            for (; iterator.hasNext(); ) {
                keyId = iterator.next().getKeyId();
                listKeys.add(keyId);
            }
            pageNumber = listKeysRes.getPageNumber();
            Integer totalCount = listKeysRes.getTotalCount();
            if (pageNumber * 10 >= totalCount) {
                break;
            }
            pageNumber++;
        }
        return listKeys;
    }

    private static DescribeKeyResponse DescribeKey(String keyId) throws ClientException {
        final DescribeKeyRequest decKeyReq = new DescribeKeyRequest();

        decKeyReq.setSysProtocol(ProtocolType.HTTPS);
        decKeyReq.setAcceptFormat(FormatType.JSON);
        decKeyReq.setSysMethod(MethodType.POST);
        decKeyReq.setKeyId(keyId);

        return kmsClient.getAcsResponse(decKeyReq);
    }

    private static String CreateKey(String keyDesc, String keyUsage) throws ClientException {
        final CreateKeyRequest ckReq = new CreateKeyRequest();

        ckReq.setSysProtocol(ProtocolType.HTTPS);
        ckReq.setAcceptFormat(FormatType.JSON);
        ckReq.setSysMethod(MethodType.POST);
        ckReq.setDescription(keyDesc);
        ckReq.setKeyUsage(keyUsage);
        CreateKeyResponse keyRes = kmsClient.getAcsResponse(ckReq);

        return keyRes.getKeyMetadata().getKeyId();
    }

    private static List<ListKeyVersionsResponse.KeyVersion> ListKeyVersions(String keyId) throws ClientException {
        Integer pageNumber = 1;
        List<ListKeyVersionsResponse.KeyVersion> listKeyVersions = new ArrayList<>();
        for (; ; ) {
            ListKeyVersionsRequest listKeyVersionsReq = new ListKeyVersionsRequest();
            listKeyVersionsReq.setSysProtocol(ProtocolType.HTTPS);
            listKeyVersionsReq.setAcceptFormat(FormatType.JSON);
            listKeyVersionsReq.setSysMethod(MethodType.POST);
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

    private static String DescribeKeyVersion(String keyId, String keyVersionId) throws ClientException {
        final DescribeKeyVersionRequest dkvReq = new DescribeKeyVersionRequest();

        dkvReq.setSysProtocol(ProtocolType.HTTPS);
        dkvReq.setAcceptFormat(FormatType.JSON);
        dkvReq.setSysMethod(MethodType.POST);
        dkvReq.setKeyId(keyId);
        dkvReq.setKeyVersionId(keyVersionId);
        DescribeKeyVersionResponse keyVersion = kmsClient.getAcsResponse(dkvReq);

        return keyVersion.getKeyVersion().getKeyVersionId();
    }

    private static String CreateKeyVersion(String keyId) throws ClientException {
        final CreateKeyVersionRequest ckvReq = new CreateKeyVersionRequest();

        ckvReq.setSysProtocol(ProtocolType.HTTPS);
        ckvReq.setAcceptFormat(FormatType.JSON);
        ckvReq.setSysMethod(MethodType.POST);
        ckvReq.setKeyId(keyId);
        CreateKeyVersionResponse keyVersion = kmsClient.getAcsResponse(ckvReq);

        return keyVersion.getKeyVersion().getKeyVersionId();
    }

    private static String GetPublicKey(String keyId, String keyVersionId) throws ClientException {
        final GetPublicKeyRequest gpkReq = new GetPublicKeyRequest();

        gpkReq.setSysProtocol(ProtocolType.HTTPS);
        gpkReq.setAcceptFormat(FormatType.JSON);
        gpkReq.setSysMethod(MethodType.POST);
        gpkReq.setKeyId(keyId);
        gpkReq.setKeyVersionId(keyVersionId);
        GetPublicKeyResponse publicKeyRes = kmsClient.getAcsResponse(gpkReq);

        return publicKeyRes.getPublicKey();
    }

    private static byte[] AsymmetricEncrypt(String keyId, String keyVersionId, String message, String algorithm) throws ClientException {
        final AsymmetricEncryptRequest aeReq = new AsymmetricEncryptRequest();
        //message要进行base64编码
        String plainText = Base64.getEncoder().encodeToString(message.getBytes(StandardCharsets.UTF_8));
        aeReq.setSysProtocol(ProtocolType.HTTPS);
        aeReq.setAcceptFormat(FormatType.JSON);
        aeReq.setSysMethod(MethodType.POST);
        aeReq.setKeyId(keyId);
        aeReq.setKeyVersionId(keyVersionId);
        aeReq.setPlaintext(plainText);
        aeReq.setAlgorithm(algorithm);
        AsymmetricEncryptResponse asymEncryptRes = kmsClient.getAcsResponse(aeReq);
        String base64CipherBlob = asymEncryptRes.getCiphertextBlob();
        //密文要进行base64解码
        return Base64.getDecoder().decode(base64CipherBlob);
    }

    private static byte[] AsymmetricDecrypt(byte[] cipherBlob, String keyId, String keyVersionId, String algorithm) throws ClientException {
        final AsymmetricDecryptRequest adReq = new AsymmetricDecryptRequest();
        //cipherBlob要进行base64编码
        String cipherText = Base64.getEncoder().encodeToString(cipherBlob);
        adReq.setSysProtocol(ProtocolType.HTTPS);
        adReq.setAcceptFormat(FormatType.JSON);
        adReq.setSysMethod(MethodType.POST);
        adReq.setKeyId(keyId);
        adReq.setKeyVersionId(keyVersionId);
        adReq.setCiphertextBlob(cipherText);
        adReq.setAlgorithm(algorithm);
        AsymmetricDecryptResponse asymDecryptRes = kmsClient.getAcsResponse(adReq);
        String base64Msg = asymDecryptRes.getPlaintext();
        //明文要进行base64解码
        return Base64.getDecoder().decode(base64Msg);
    }

    private static byte[] AsymmetricSign(String keyId, String keyVersionId, String algorithm, String message) throws ClientException, NoSuchAlgorithmException {
        final AsymmetricSignRequest asReq = new AsymmetricSignRequest();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(message.getBytes(StandardCharsets.UTF_8));
        //digest要进行base64编码
        String base64Digest = Base64.getEncoder().encodeToString(digest);
        asReq.setSysProtocol(ProtocolType.HTTPS);
        asReq.setAcceptFormat(FormatType.JSON);
        asReq.setSysMethod(MethodType.POST);
        asReq.setKeyId(keyId);
        asReq.setKeyVersionId(keyVersionId);
        asReq.setAlgorithm(algorithm);
        asReq.setDigest(base64Digest);
        AsymmetricSignResponse asymSignRes = kmsClient.getAcsResponse(asReq);
        //签名要进行base64解码
        return Base64.getDecoder().decode(asymSignRes.getValue().getBytes(StandardCharsets.UTF_8));
    }

    private static boolean AsymmetricVerify(String keyId, String keyVersionId, String algorithm, String message, byte[] signature) throws ClientException, NoSuchAlgorithmException {
        final AsymmetricVerifyRequest avReq = new AsymmetricVerifyRequest();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(message.getBytes(StandardCharsets.UTF_8));
        //digest，signature要进行base64编码
        String base64Digest = Base64.getEncoder().encodeToString(digest);
        String base64Signature = Base64.getEncoder().encodeToString(signature);
        avReq.setSysProtocol(ProtocolType.HTTPS);
        avReq.setAcceptFormat(FormatType.JSON);
        avReq.setSysMethod(MethodType.POST);
        avReq.setKeyId(keyId);
        avReq.setKeyVersionId(keyVersionId);
        avReq.setAlgorithm(algorithm);
        avReq.setDigest(base64Digest);
        avReq.setValue(base64Signature);
        AsymmetricVerifyResponse asymVerifyRes = kmsClient.getAcsResponse(avReq);

        return asymVerifyRes.getValue();
    }

    private static byte[] rsaEncrypt(String keyId, String keyVersionId, String message, String algorithm) throws ClientException, GeneralSecurityException {
        Cipher oaepFromAlgo;
        OAEPParameterSpec oaepParams;

        String publicKeyPem = GetPublicKey(keyId, keyVersionId);
        publicKeyPem = publicKeyPem.replaceFirst("-----BEGIN PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceFirst("-----END PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceAll("\\s", "");
        byte[] publicKeyDer = Base64.getDecoder().decode(publicKeyPem);
        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyDer));

        switch (algorithm) {
            case "RSAES_OAEP_SHA_1":
                oaepFromAlgo = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
                oaepParams = new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
                oaepFromAlgo.init(Cipher.ENCRYPT_MODE, pubKey, oaepParams);
                break;
            case "RSAES_OAEP_SHA_256":
                oaepFromAlgo = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
                oaepFromAlgo.init(Cipher.ENCRYPT_MODE, pubKey, oaepParams);
                break;
            default:
                throw new UnsupportedOperationException(String.format("algorithm '%s' not support.", algorithm));
        }

        return oaepFromAlgo.doFinal(message.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean rsaVerify(String keyId, String keyVersionId, String message, byte[] signature, String algorithm) throws ClientException, GeneralSecurityException {
        Signature rsaSignature;

        String publicKeyPem = GetPublicKey(keyId, keyVersionId);
        publicKeyPem = publicKeyPem.replaceFirst("-----BEGIN PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceFirst("-----END PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceAll("\\s", "");
        byte[] publicKeyDer = Base64.getDecoder().decode(publicKeyPem);
        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyDer));

        switch (algorithm) {
            case "RSA_PSS_SHA_256":
                rsaSignature = Signature.getInstance("RSASSA-PSS");
                rsaSignature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                rsaSignature.initVerify(pubKey);
                rsaSignature.update(message.getBytes(StandardCharsets.UTF_8));
                break;
            case "RSA_PKCS1_SHA_256":
                rsaSignature = Signature.getInstance("SHA256withRSA");
                rsaSignature.initVerify(pubKey);
                rsaSignature.update(message.getBytes(StandardCharsets.UTF_8));
                break;
            default:
                throw new UnsupportedOperationException(String.format("algorithm '%s' not support.", algorithm));
        }
        return rsaSignature.verify(signature);
    }

    private static boolean ecdsaVerify(String keyId, String keyVersionId, String message, byte[] signature) throws GeneralSecurityException, ClientException {
        String publicKeyPem = GetPublicKey(keyId, keyVersionId);
        publicKeyPem = publicKeyPem.replaceFirst("-----BEGIN PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceFirst("-----END PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceAll("\\s", "");
        byte[] publicKeyDer = Base64.getDecoder().decode(publicKeyPem);
        PublicKey pubKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(publicKeyDer));

        Signature ecVerify = Signature.getInstance("SHA256withECDSA");
        ecVerify.initVerify(pubKey);
        ecVerify.update(message.getBytes(StandardCharsets.UTF_8));
        return ecVerify.verify(signature);
    }


    public static void main(String[] args) {
        System.out.println("===========================================");
        System.out.println("Start asymmetric key test");
        System.out.println("===========================================\n");

        String regionId = "cn-hangzhou";
        String accessKeyId = System.getenv("AccessKeyId");
        String accessKeySecret = System.getenv("AccessKeySecret");

        kmsClient = kmsClient(regionId, accessKeyId, accessKeySecret);

        Map<String, List<String>> keySpecs = new HashMap<>();
        keySpecs.put("RSA_2048", new ArrayList<>() {{
            add("ENCRYPT/DECRYPT");
            add("SIGN/VERIFY");
        }});
        keySpecs.put("EC_P256", new ArrayList<>() {{
            add("SIGN/VERIFY");
        }});
        keySpecs.put("EC_P256K", new ArrayList<>() {{
            add("SIGN/VERIFY");
        }});

        try {
            for (String keySpec : keySpecs.keySet()) {
                List<String> keyUsages = keySpecs.get(keySpec);
                for (String keyUsage : keyUsages) {
                    String keyId = null;
                    String keyVersionId = null;

                    System.out.println("KeySpec: " + keySpec);
                    System.out.println("KeyUsage: " + keyUsage);

                    final List<String> listKeys = ListKeys();
                    for (String v : listKeys) {
                        DescribeKeyResponse keyInfo = DescribeKey(v);
                        String spec = keyInfo.getKeyMetadata().getKeySpec();
                        String usage = keyInfo.getKeyMetadata().getKeyUsage();
                        if (spec.equals(keySpec) && usage.equals(keyUsage)) {
                            keyId = keyInfo.getKeyMetadata().getKeyId();
                            break;
                        }
                    }
                    if (keyId == null) {
                        System.out.println("CreateKey...");
                        keyId = CreateKey(keySpec, keyUsage);
                    }
                    System.out.println("KeyId: " + keyId);

                    List<ListKeyVersionsResponse.KeyVersion> keyVersionList = ListKeyVersions(keyId);
                    if (keyVersionList.size() > 0) {
                        String tempVersionId = keyVersionList.get(0).getKeyVersionId();
                        keyVersionId = DescribeKeyVersion(keyId, tempVersionId);
                    }

                    if (keyVersionId == null) {
                        keyVersionId = CreateKeyVersion(keyId);
                    }
                    System.out.println("KeyVersionId: " + keyVersionId);

                    //1.获取公钥信息测试
                    String pemPub = GetPublicKey(keyId, keyVersionId);
                    System.out.println("PublicKey: " + pemPub);

                    switch (keyUsage) {
                        case "ENCRYPT/DECRYPT":
                            //2.非对称加解密测试
                            switch (keySpec) {
                                case "RSA_2048":
                                    String msg = "this is test";
                                    List<String> algorithms = new ArrayList<>() {{
                                        add("RSAES_OAEP_SHA_256");
                                        add("RSAES_OAEP_SHA_1");
                                    }};

                                    for (String algorithm : algorithms) {
                                        //kms加密 kms解密
                                        byte[] cipherBlob = AsymmetricEncrypt(keyId, keyVersionId, msg, algorithm);
                                        byte[] plainText = AsymmetricDecrypt(cipherBlob, keyId, keyVersionId, algorithm);
                                        String message = new String(plainText);
                                        System.out.println("kms encrypt message: " + message);
                                        if (!message.equals(msg)) {
                                            System.out.printf("kms encrypt: decrypt failed, current message:%s, except:%s\n", message, msg);
                                            return;
                                        }
                                        //本地加密 kms解密
                                        cipherBlob = rsaEncrypt(keyId, keyVersionId, msg, algorithm);
                                        plainText = AsymmetricDecrypt(cipherBlob, keyId, keyVersionId, algorithm);
                                        message = new String(plainText);
                                        System.out.println("local encrypt message: " + message);
                                        if (!message.equals(msg)) {
                                            System.out.printf("local encrypt: decrypt failed, current message:%s, except:%s\n", message, msg);
                                            return;
                                        }
                                    }
                                    break;
                                case "EC_P256":
                                case "EC_P256K":
                            }
                            break;
                        case "SIGN/VERIFY":
                            //3.非对称密钥签名验签测试
                            switch (keySpec) {
                                case "RSA_2048":
                                    List<String> algorithms = new ArrayList<>() {{
                                        add("RSA_PSS_SHA_256");
                                        add("RSA_PKCS1_SHA_256");
                                    }};

                                    String msg = "this is test";
                                    for (String algorithm : algorithms) {
                                        //kms签名 kms验签
                                        byte[] signature = AsymmetricSign(keyId, keyVersionId, algorithm, msg);
                                        boolean ok = AsymmetricVerify(keyId, keyVersionId, algorithm, msg, signature);
                                        if (!ok) {
                                            System.out.println("kms verify failed");
                                            return;
                                        }
                                        //kms签名 本地验签
                                        ok = rsaVerify(keyId, keyVersionId, msg, signature, algorithm);
                                        if (!ok) {
                                            System.out.println("local verify failed");
                                            return;
                                        }
                                    }
                                    break;
                                case "EC_P256":
                                case "EC_P256K":
                                    algorithms = new ArrayList<>() {{
                                        add("ECDSA_SHA_256");
                                    }};

                                    msg = "this is test";
                                    for (String algorithm : algorithms) {
                                        //kms签名 kms验签
                                        byte[] signature = AsymmetricSign(keyId, keyVersionId, algorithm, msg);
                                        boolean ok = AsymmetricVerify(keyId, keyVersionId, algorithm, msg, signature);
                                        if (!ok) {
                                            System.out.println("kms verify failed");
                                            return;
                                        }
                                        //kms签名 本地验签
                                        ok = ecdsaVerify(keyId, keyVersionId, msg, signature);
                                        if (!ok) {
                                            System.out.println("local verify failed");
                                            return;
                                        }
                                    }
                                    break;
                            }
                            break;
                    }

                }
            }
            System.out.println("===========================================");
            System.out.println("All test pass");
            System.out.println("===========================================");
        } catch (ClientException e) {
            System.out.println("Failed.");
            System.out.println("Error code: " + e.getErrCode());
            System.out.println("Error message: " + e.getErrMsg());
        } catch (GeneralSecurityException e) {
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        }
    }
}
