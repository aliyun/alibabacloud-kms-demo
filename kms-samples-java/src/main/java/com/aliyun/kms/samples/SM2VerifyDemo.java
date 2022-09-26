package com.aliyun.kms.samples;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.kms.model.v20160120.*;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.util.encoders.Hex;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

/**
 * 本示例展示了使用KMS SM2密钥线上签名，本地通过第三方库验签的用法
 */
public class SM2VerifyDemo {
    private static DefaultAcsClient kmsClient;

    private static DefaultAcsClient kmsClient(String regionId, String accessKeyId, String accessKeySecret) {
        IClientProfile profile = DefaultProfile.getProfile(regionId, accessKeyId, accessKeySecret);
        HttpClientConfig clientConfig = HttpClientConfig.getDefault();
        //clientConfig.setIgnoreSSLCerts(true);
        profile.setHttpClientConfig(clientConfig);
        return new DefaultAcsClient(profile);
    }

    private static PublicKey getPublicKey(String keyId, String keyVersionId) throws Exception {
        final GetPublicKeyRequest request = new GetPublicKeyRequest();
        request.setAcceptFormat(FormatType.JSON);
        request.setKeyId(keyId);
        request.setKeyVersionId(keyVersionId);
        GetPublicKeyResponse response = kmsClient.getAcsResponse(request);

        String pemKey = response.getPublicKey();
        pemKey = pemKey.replaceFirst("-----BEGIN PUBLIC KEY-----", "");
        pemKey = pemKey.replaceFirst("-----END PUBLIC KEY-----", "");
        pemKey = pemKey.replaceAll("\\s", "");
        byte[] derKey = Base64.getDecoder().decode(pemKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derKey);
        return KeyFactory.getInstance("EC", new BouncyCastleProvider()).generatePublic(keySpec);
    }

    private static byte[] AsymmetricSign(String keyId, String keyVersionId, String algorithm, String message) throws ClientException, NoSuchAlgorithmException {
        final AsymmetricSignRequest request = new AsymmetricSignRequest();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(message.getBytes(StandardCharsets.UTF_8));
        //digest要进行base64编码
        String base64Digest = Base64.getEncoder().encodeToString(digest);
        request.setAcceptFormat(FormatType.JSON);
        request.setKeyId(keyId);
        request.setKeyVersionId(keyVersionId);
        request.setAlgorithm(algorithm);
        request.setDigest(base64Digest);
        AsymmetricSignResponse asymSignRes = kmsClient.getAcsResponse(request);
        //签名要进行base64解码
        return Base64.getDecoder().decode(asymSignRes.getValue().getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] AsymmetricSign(String keyId, String keyVersionId, String algorithm, byte[] digest) throws ClientException, NoSuchAlgorithmException {
        final AsymmetricSignRequest request = new AsymmetricSignRequest();
        //digest要进行base64编码
        String base64Digest = Base64.getEncoder().encodeToString(digest);
        request.setAcceptFormat(FormatType.JSON);
        request.setKeyId(keyId);
        request.setKeyVersionId(keyVersionId);
        request.setAlgorithm(algorithm);
        request.setDigest(base64Digest);
        AsymmetricSignResponse response = kmsClient.getAcsResponse(request);
        //签名要进行base64解码
        return Base64.getDecoder().decode(response.getValue().getBytes(StandardCharsets.UTF_8));
    }

    private static boolean AsymmetricVerify(String keyId, String keyVersionId, String algorithm, byte[] digest, byte[] signature) throws ClientException, NoSuchAlgorithmException {
        final AsymmetricVerifyRequest request = new AsymmetricVerifyRequest();
        //digest，signature要进行base64编码
        String base64Digest = Base64.getEncoder().encodeToString(digest);
        String base64Signature = Base64.getEncoder().encodeToString(signature);
        request.setAcceptFormat(FormatType.JSON);
        request.setKeyId(keyId);
        request.setKeyVersionId(keyVersionId);
        request.setAlgorithm(algorithm);
        request.setDigest(base64Digest);
        request.setValue(base64Signature);
        AsymmetricVerifyResponse response = kmsClient.getAcsResponse(request);
        return response.getValue();
    }

    private static boolean sm2Verify(String algorithm, PublicKey publicKey, String message, byte[] signature) throws GeneralSecurityException, ClientException {
        Signature sm2 = Signature.getInstance(algorithm, new BouncyCastleProvider());
        sm2.initVerify(publicKey);
        sm2.update(message.getBytes(StandardCharsets.UTF_8));
        return sm2.verify(signature);
    }

    private static byte[] getZ(Digest digest, ECPublicKeyParameters ecPublicKeyParameters, ECDomainParameters ecDomainParameters) {
        digest.reset();
        String userID = "1234567812345678";
        addUserID(digest, userID.getBytes());

        addFieldElement(digest, ecDomainParameters.getCurve().getA());
        addFieldElement(digest, ecDomainParameters.getCurve().getB());
        addFieldElement(digest, ecDomainParameters.getG().getAffineXCoord());
        addFieldElement(digest, ecDomainParameters.getG().getAffineYCoord());
        addFieldElement(digest, ecPublicKeyParameters.getQ().getAffineXCoord());
        addFieldElement(digest, ecPublicKeyParameters.getQ().getAffineYCoord());

        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }

    private static void addUserID(Digest digest, byte[] userID) {
        int len = userID.length * 8;
        digest.update((byte) (len >> 8 & 0xFF));
        digest.update((byte) (len & 0xFF));
        digest.update(userID, 0, userID.length);
    }

    private static void addFieldElement(Digest digest, ECFieldElement v) {
        byte[] p = v.getEncoded();
        digest.update(p, 0, p.length);
    }

    private static byte[] calcDigest(Digest digest, PublicKey pubKey, byte[] message) {
        X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");
        ECDomainParameters ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());
        BCECPublicKey localECPublicKey = (BCECPublicKey) pubKey;
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(localECPublicKey.getQ(), ecDomainParameters);

        byte[] z = getZ(digest, ecPublicKeyParameters, ecDomainParameters);
        digest.update(z, 0, z.length);
        digest.update(message, 0, message.length);
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }

    public static void main(String[] args) {
        String regionId = "cn-hangzhou";
        String accessKeyId = getAliyunAccessKey("AccessKeyId");
        String accessKeySecret = getAliyunAccessKey("AccessKeySecret");

        // 使用AccessKey创建阿里云KMS Client
        kmsClient = kmsClient(regionId, accessKeyId, accessKeySecret);

        try {
            // 主密钥Id
            String keyId = "<your cmk id>";
            // 主密钥版本Id
            String keyVersionId = "<your cmk version id>";
            // 签名算法
            String algorithm = "<your signature algorithm>";
            // 待签名消息
            String message = "<your message>";

            // 通过KMS服务获取公钥
            PublicKey publicKey = getPublicKey(keyId, keyVersionId);

            // 计算SM3消息摘要
            byte[] digest = calcDigest(new SM3Digest(), publicKey, message.getBytes(StandardCharsets.UTF_8));
            // 计算SHA256消息摘要
            //byte[] digest = calcDigest(new SHA256Digest(), publicKey, message.getBytes(StandardCharsets.UTF_8));

            // 调用KMS服务进行签名
            byte[] signature = AsymmetricSign(keyId, keyVersionId, algorithm, digest);
            System.out.println("KMS签名结果: " + Hex.toHexString(signature));

            boolean value = AsymmetricVerify(keyId, keyVersionId, algorithm, digest, signature);
            System.out.println("KMS验签结果: " + value);

            // 调用第三方库进行验签（SM3摘要）
            value = sm2Verify("SM3WITHSM2", publicKey, message, signature);
            // 调用第三方库进行验签（SHA256摘要）
            //value = sm2Verify("SHA256WITHSM2", publicKey, message, signature);
            System.out.println("本地验签结果: " + value);

        } catch (ClientException e) {
            System.out.println("Code: " + e.getErrCode());
            System.out.println("Message: " + e.getErrMsg());
            System.out.println("RequestId: " + e.getRequestId());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 从文件中读取阿里云AccessKey配置信息
     * 此处为了方便示例，将AccessKey信息配置在resources资源下，实际过程中请不要这样做。
     *
     * @param key AccessKey配置对应的key
     * @return AccessKey配置字符串
     */
    private static String getAliyunAccessKey(String key) {
        InputStream stream = KmsSDKExponentialBackoffDemo.class.getResourceAsStream("/aliyunAccessKey.json");
        Map<String, String> result = new Gson().fromJson(
                new InputStreamReader(stream),
                new TypeToken<Map<String, String>>() {
                }.getType()
        );
        return result.get(key);
    }
}
