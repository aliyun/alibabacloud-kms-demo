package com.aliyun.kms.samples;

import com.aliyun.kms20160120.Client;
import com.aliyun.kms20160120.models.AsymmetricSignRequest;
import com.aliyun.kms20160120.models.AsymmetricSignResponse;
import com.aliyun.kms20160120.models.AsymmetricVerifyRequest;
import com.aliyun.kms20160120.models.AsymmetricVerifyResponse;
import com.aliyun.kms20160120.models.GetPublicKeyRequest;
import com.aliyun.kms20160120.models.GetPublicKeyResponse;
import com.aliyun.teaopenapi.models.Config;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * 本示例展示了使用阿里云SDK V2（kms20160120）调用KMS AsymmetricSign/AsymmetricVerify接口，
 * 使用非对称密钥（RSA或EC）进行签名、验签的用法。
 *
 * 注意事项：
 * 1. 仅支持Usage为SIGN/VERIFY的非对称密钥，支持的算法组合：
 *    RSA_2048/RSA_3072 -> RSA_PSS_SHA_256、RSA_PKCS1_SHA_256
 *    EC_P256/EC_P256K -> ECDSA_SHA_256
 *    EC_SM2 -> SM2DSA（SM2密钥用法请参见SM2SignVerifyV2示例）
 * 2. Digest参数是使用Algorithm对应的哈希算法对原始消息计算的摘要，且必须Base64编码。
 * 3. KMS计算签名、验证数字签名的结果符合对应算法标准，因此除了调用AsymmetricVerify
 *    接口验签，也可以先调用GetPublicKey下载公钥，用其它密码算法库在本地验签。
 */
public class AsymmetricSignVerifyV2 {
    // KMS Client对象
    private static Client client = null;
    // 如果kms实例开启公网访问，endpoint 请参考 https://api.aliyun.com/product/Kms
    // 如果kms实例未开启公网访问，endpoint 请使用实例VPC地址
    private static final String endpoint = "<your kms endpoint>";
    // 填写您在KMS创建的非对称主密钥Id（Usage必须为SIGN/VERIFY）
    private static final String keyId = "<your cmk id>";
    // 填写主密钥版本Id
    private static final String keyVersionId = "<your cmk version id>";
    // 签名算法，本示例以RSA_PKCS1_SHA_256为例，可选值见类注释
    private static final String algorithm = "RSA_PKCS1_SHA_256";

    public static void main(String[] args) {
        // 1.创建 KMS Client 对象并初始化
        try {
            Config config = new Config()
                    // 必填，请确保代码运行环境设置了环境变量 ALIBABA_CLOUD_ACCESS_KEY_ID。
                    .setAccessKeyId(System.getenv("ALIBABA_CLOUD_ACCESS_KEY_ID"))
                    // 必填，请确保代码运行环境设置了环境变量 ALIBABA_CLOUD_ACCESS_KEY_SECRET。
                    .setAccessKeySecret(System.getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"));
            // Endpoint 请参考 https://api.aliyun.com/product/Kms
            config.endpoint = endpoint;
            // 如果使用实例VPC地址并且验证服务端证书，请设置ca证书
            //config.ca = "<your kms ca>";
            client = new Client(config);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        // 待签名消息
        String message = "<your message>";

        try {
            // 2.计算消息摘要，Digest参数使用Algorithm对应的哈希算法计算，并Base64编码
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(message.getBytes(StandardCharsets.UTF_8));
            String base64Digest = Base64.getEncoder().encodeToString(digest);

            // 3.调用AsymmetricSign接口签名
            AsymmetricSignRequest signRequest = new AsymmetricSignRequest()
                    .setKeyId(keyId)
                    .setKeyVersionId(keyVersionId)
                    .setAlgorithm(algorithm)
                    .setDigest(base64Digest);
            AsymmetricSignResponse signResponse = client.asymmetricSign(signRequest);
            // 返回的签名Value为Base64编码
            String base64Signature = signResponse.getBody().getValue();
            System.out.println("================sign================");
            System.out.printf("KeyId: %s%n", signResponse.getBody().getKeyId());
            System.out.printf("KeyVersionId: %s%n", signResponse.getBody().getKeyVersionId());
            System.out.printf("Signature: %s%n", base64Signature);
            System.out.printf("RequestId: %s%n", signResponse.getBody().getRequestId());
            System.out.println("================sign================");

            // 4.调用AsymmetricVerify接口验签
            AsymmetricVerifyRequest verifyRequest = new AsymmetricVerifyRequest()
                    .setKeyId(keyId)
                    .setKeyVersionId(keyVersionId)
                    .setAlgorithm(algorithm)
                    .setDigest(base64Digest)
                    .setValue(base64Signature);
            AsymmetricVerifyResponse verifyResponse = client.asymmetricVerify(verifyRequest);
            System.out.println("================verify================");
            System.out.printf("KeyId: %s%n", verifyResponse.getBody().getKeyId());
            System.out.printf("Value: %s%n", verifyResponse.getBody().getValue());
            System.out.printf("RequestId: %s%n", verifyResponse.getBody().getRequestId());
            System.out.println("================verify================");

            // 5.（可选）下载公钥后在本地验签，适用于需要离线验签或第三方验签的场景
            PublicKey publicKey = getPublicKey(keyId, keyVersionId);
            boolean localVerified = localVerify(publicKey, algorithm, message,
                    Base64.getDecoder().decode(base64Signature));
            System.out.println("本地验签结果: " + localVerified);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 调用GetPublicKey接口获取非对称密钥的公钥（PEM格式）
     */
    private static PublicKey getPublicKey(String keyId, String keyVersionId) throws Exception {
        GetPublicKeyRequest request = new GetPublicKeyRequest()
                .setKeyId(keyId)
                .setKeyVersionId(keyVersionId);
        GetPublicKeyResponse response = client.getPublicKey(request);

        // 解析PEM格式公钥为X509编码
        String pemKey = response.getBody().getPublicKey();
        pemKey = pemKey.replaceFirst("-----BEGIN PUBLIC KEY-----", "");
        pemKey = pemKey.replaceFirst("-----END PUBLIC KEY-----", "");
        pemKey = pemKey.replaceAll("\\s", "");
        byte[] derKey = Base64.getDecoder().decode(pemKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derKey);
        // RSA密钥使用"RSA"，EC密钥请改为"EC"
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    /**
     * 使用公钥在本地验证签名。
     * KMS返回的签名符合标准算法格式（RSA PKCS1/ECDSA均为DER编码），可直接用JCE验签。
     */
    private static boolean localVerify(PublicKey publicKey, String algorithm,
                                       String message, byte[] signature) throws Exception {
        // KMS算法名到JCE算法名的映射
        String jceAlgorithm;
        if ("RSA_PKCS1_SHA_256".equals(algorithm)) {
            jceAlgorithm = "SHA256withRSA";
        } else if ("ECDSA_SHA_256".equals(algorithm)) {
            jceAlgorithm = "SHA256withECDSA";
        } else {
            // RSA_PSS_SHA_256等算法需要额外的算法参数，请根据实际需要选择密码库验签
            throw new IllegalArgumentException("Unsupported algorithm for local verify: " + algorithm);
        }
        Signature verifier = Signature.getInstance(jceAlgorithm);
        verifier.initVerify(publicKey);
        verifier.update(message.getBytes(StandardCharsets.UTF_8));
        return verifier.verify(signature);
    }
}
