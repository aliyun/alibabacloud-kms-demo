package com.aliyun.kms.samples;

import com.aliyun.kms20160120.Client;
import com.aliyun.kms20160120.models.AsymmetricSignRequest;
import com.aliyun.kms20160120.models.AsymmetricSignResponse;
import com.aliyun.kms20160120.models.AsymmetricVerifyRequest;
import com.aliyun.kms20160120.models.AsymmetricVerifyResponse;
import com.aliyun.kms20160120.models.GetPublicKeyRequest;
import com.aliyun.kms20160120.models.GetPublicKeyResponse;
import com.aliyun.teaopenapi.models.Config;
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

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * 本示例展示了使用阿里云SDK V2（kms20160120）调用KMS AsymmetricSign/AsymmetricVerify接口，
 * 使用SM2非对称密钥（KeySpec为EC_SM2，算法为SM2DSA）进行签名、验签的用法，
 * 并演示了通过GetPublicKey获取公钥后在本地使用BouncyCastle验签。
 *
 * 注意事项：
 * 1. 仅支持Usage为SIGN/VERIFY的EC_SM2非对称密钥，签名算法固定为SM2DSA。
 * 2. 按照国家标准GB/T 32918.2《信息安全技术 SM2 椭圆曲线公钥密码算法 第2部分：数字签名算法》，
 *    计算SM2签名值时，Digest参数不是对原始消息直接计算SM3摘要，
 *    而是对Z(A)和M的拼接值计算的摘要：其中M是待签名的原始消息，
 *    Z(A)是GB/T 32918.2中定义的用户A的杂凑值（默认用户ID为1234567812345678）。
 * 3. KMS返回的签名符合SM2DSA标准格式，可直接使用BouncyCastle等密码库在本地验签。
 */
public class SM2SignVerifyV2 {
    // KMS Client对象
    private static Client client = null;
    // 如果kms实例开启公网访问，endpoint 请参考 https://api.aliyun.com/product/Kms
    // 如果kms实例未开启公网访问，endpoint 请使用实例VPC地址
    private static final String endpoint = "<your kms endpoint>";
    // 填写您在KMS创建的SM2非对称主密钥Id（KeySpec为EC_SM2，Usage为SIGN/VERIFY）
    private static final String keyId = "<your cmk id>";
    // 填写主密钥版本Id
    private static final String keyVersionId = "<your cmk version id>";
    // SM2密钥的签名算法固定为SM2DSA
    private static final String algorithm = "SM2DSA";
    // GB/T 32918.2定义的默认用户标识ID
    private static final String SM2_USER_ID = "1234567812345678";

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
            // 2.通过GetPublicKey接口获取SM2公钥
            PublicKey publicKey = getPublicKey(keyId, keyVersionId);

            // 3.计算SM3消息摘要：SM2签名的Digest必须是对 Z(A)||M 计算的SM3摘要，
            // 而不是对原始消息直接计算SM3摘要
            byte[] digest = calcDigest(new SM3Digest(), publicKey,
                    message.getBytes(StandardCharsets.UTF_8));
            String base64Digest = Base64.getEncoder().encodeToString(digest);

            // 4.调用AsymmetricSign接口签名
            AsymmetricSignRequest signRequest = new AsymmetricSignRequest()
                    .setKeyId(keyId)
                    .setKeyVersionId(keyVersionId)
                    .setAlgorithm(algorithm)
                    .setDigest(base64Digest);
            AsymmetricSignResponse signResponse = client.asymmetricSign(signRequest);
            // 返回的签名Value为Base64编码，解码后得到SM2DSA签名值
            byte[] signature = Base64.getDecoder().decode(signResponse.getBody().getValue());
            System.out.println("================sign================");
            System.out.printf("KeyId: %s%n", signResponse.getBody().getKeyId());
            System.out.printf("KeyVersionId: %s%n", signResponse.getBody().getKeyVersionId());
            System.out.printf("Signature: %s%n", Hex.toHexString(signature));
            System.out.printf("RequestId: %s%n", signResponse.getBody().getRequestId());
            System.out.println("================sign================");

            // 5.调用AsymmetricVerify接口验签
            AsymmetricVerifyRequest verifyRequest = new AsymmetricVerifyRequest()
                    .setKeyId(keyId)
                    .setKeyVersionId(keyVersionId)
                    .setAlgorithm(algorithm)
                    .setDigest(base64Digest)
                    .setValue(signResponse.getBody().getValue());
            AsymmetricVerifyResponse verifyResponse = client.asymmetricVerify(verifyRequest);
            System.out.println("================verify================");
            System.out.printf("KeyId: %s%n", verifyResponse.getBody().getKeyId());
            System.out.printf("Value: %s%n", verifyResponse.getBody().getValue());
            System.out.printf("RequestId: %s%n", verifyResponse.getBody().getRequestId());
            System.out.println("================verify================");

            // 6.使用BouncyCastle在本地验签（传入原始消息，SM3WITHSM2内部会计算Z(A)杂凑值）
            boolean localVerified = sm2Verify(publicKey, message, signature);
            System.out.println("本地验签结果: " + localVerified);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 调用GetPublicKey接口获取SM2公钥（PEM格式）
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
        return KeyFactory.getInstance("EC", new BouncyCastleProvider()).generatePublic(keySpec);
    }

    /**
     * 调用AsymmetricSign接口的Digest参数要求：SM3(Z(A)||M)。
     * 其中Z(A)为用户A的杂凑值，计算方法见GB/T 32918.2。
     */
    private static byte[] calcDigest(Digest digest, PublicKey pubKey, byte[] message) {
        X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");
        ECDomainParameters ecDomainParameters = new ECDomainParameters(
                x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());
        BCECPublicKey localECPublicKey = (BCECPublicKey) pubKey;
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(
                localECPublicKey.getQ(), ecDomainParameters);

        byte[] z = getZ(digest, ecPublicKeyParameters, ecDomainParameters);
        digest.update(z, 0, z.length);
        digest.update(message, 0, message.length);
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }

    /**
     * 计算Z(A) = SM3(ENTL||ID||a||b||xG||yG||xA||yA)
     */
    private static byte[] getZ(Digest digest, ECPublicKeyParameters ecPublicKeyParameters,
                               ECDomainParameters ecDomainParameters) {
        digest.reset();
        addUserID(digest, SM2_USER_ID.getBytes(StandardCharsets.UTF_8));

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

    /**
     * 使用BouncyCastle在本地验证SM2签名。
     * SM3WITHSM2验签时传入原始消息即可，BouncyCastle内部会按GB/T 32918.2计算Z(A)。
     */
    private static boolean sm2Verify(PublicKey publicKey, String message,
                                     byte[] signature) throws Exception {
        Signature sm2 = Signature.getInstance("SM3WITHSM2", new BouncyCastleProvider());
        sm2.initVerify(publicKey);
        sm2.update(message.getBytes(StandardCharsets.UTF_8));
        return sm2.verify(signature);
    }
}
