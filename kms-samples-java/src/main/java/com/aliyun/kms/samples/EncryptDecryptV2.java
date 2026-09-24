package com.aliyun.kms.samples;

import com.aliyun.kms20160120.Client;
import com.aliyun.kms20160120.models.DecryptRequest;
import com.aliyun.kms20160120.models.DecryptResponse;
import com.aliyun.kms20160120.models.EncryptRequest;
import com.aliyun.kms20160120.models.EncryptResponse;
import com.aliyun.teaopenapi.models.Config;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * 本示例展示了使用阿里云SDK V2（kms20160120）调用KMS Encrypt/Decrypt接口，
 * 使用对称主密钥（CMK）在线加密、解密数据的用法。
 *
 * 注意事项：
 * 1. Encrypt接口使用指定密钥的主版本加密明文，最多可加密6KB的数据，
 *    例如RSA密钥、数据库密码或其它敏感信息。
 * 2. 请求参数Plaintext必须是经过Base64编码的明文，返回的CiphertextBlob为密文；
 *    Decrypt返回的Plaintext同样为Base64编码，需解码后使用。
 * 3. 如果加密时指定了EncryptionContext，解密时必须提供完全一致的EncryptionContext。
 * 4. 大数据加密请改用信封加密（参见EnvelopeEncryptV2/EnvelopeDecryptV2示例）。
 */
public class EncryptDecryptV2 {
    // KMS Client对象
    private static Client client = null;
    // 如果kms实例开启公网访问，endpoint 请参考 https://api.aliyun.com/product/Kms
    // 如果kms实例未开启公网访问，endpoint 请使用实例VPC地址
    private static final String endpoint = "<your kms endpoint>";
    // 填写您在KMS创建的对称主密钥Id，也可以使用密钥别名（如alias/Example）或密钥ARN
    private static final String keyId = "<your cmk id>";

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

        // 待加密的明文数据（不超过6KB），Plaintext参数要求Base64编码
        String plaintext = "<your plaintext data>";
        String base64Plaintext = Base64.getEncoder().encodeToString(
                plaintext.getBytes(StandardCharsets.UTF_8));

        // 加密上下文（可选）。key/value均为字符串，加密与解密时必须保持一致
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("Example", "Example");

        // 2.调用Encrypt接口加密
        String ciphertextBlob = null;
        try {
            EncryptRequest encryptRequest = new EncryptRequest()
                    .setKeyId(keyId)
                    .setPlaintext(base64Plaintext)
                    .setEncryptionContext(encryptionContext);
            EncryptResponse encryptResponse = client.encrypt(encryptRequest);
            ciphertextBlob = encryptResponse.getBody().getCiphertextBlob();
            System.out.println("================encrypt================");
            System.out.printf("KeyId: %s%n", encryptResponse.getBody().getKeyId());
            System.out.printf("KeyVersionId: %s%n", encryptResponse.getBody().getKeyVersionId());
            System.out.printf("CiphertextBlob: %s%n", ciphertextBlob);
            System.out.printf("RequestId: %s%n", encryptResponse.getBody().getRequestId());
            System.out.println("================encrypt================");
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        // 3.调用Decrypt接口解密，加密时使用的EncryptionContext必须原样传入
        try {
            DecryptRequest decryptRequest = new DecryptRequest()
                    .setCiphertextBlob(ciphertextBlob)
                    .setEncryptionContext(encryptionContext);
            DecryptResponse decryptResponse = client.decrypt(decryptRequest);
            // 返回的Plaintext为Base64编码，解码后得到原始明文
            String decrypted = new String(
                    Base64.getDecoder().decode(decryptResponse.getBody().getPlaintext()),
                    StandardCharsets.UTF_8);
            System.out.println("================decrypt================");
            System.out.printf("KeyId: %s%n", decryptResponse.getBody().getKeyId());
            System.out.printf("Plaintext: %s%n", decrypted);
            System.out.printf("RequestId: %s%n", decryptResponse.getBody().getRequestId());
            System.out.println("================decrypt================");

            // 4.校验解密结果与原始明文一致
            System.out.println("加解密结果一致: " + plaintext.equals(decrypted));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
