package com.aliyun.kms.samples;

import com.aliyun.kms20160120.Client;
import com.aliyun.kms20160120.models.GenerateDataKeyRequest;
import com.aliyun.kms20160120.models.GenerateDataKeyResponse;
import com.aliyun.teaopenapi.models.Config;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class EnvelopeEncryptV2 {
    // KMS Client对象
    private static Client client = null;
    // 如果kms实例开启公网访问，endpoint 请参考 https://api.aliyun.com/product/Kms
    // 如果kms实例未开启公网访问，endpoint 请使用实例VPC地址
    private static final String endpoint = "<your kms endpoint>";
    // 填写您在KMS创建的主密钥Id
    private static final String keyId = "<your cmk id>";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;

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

        // 2.获取数据密钥，下面以Aliyun_AES_256密钥为例进行说明，数据密钥长度32字节
        GenerateDataKeyRequest generateDataKeyRequest = new GenerateDataKeyRequest()
                .setKeyId(keyId) // 生成数据密钥的主密钥Id
                .setNumberOfBytes(32); // 生成的数据密钥的长度
        String plainDataKey = null; // KMS返回的数据密钥明文, 加密本地数据使用
        String encryptedDataKey = null; // KMS返回的数据密钥密文，解密本地数据密文时，先将数据密钥密文解密后使用
        try {
            GenerateDataKeyResponse generateDataKeyResponse = client.generateDataKey(generateDataKeyRequest);
            plainDataKey = generateDataKeyResponse.getBody().getPlaintext();
            encryptedDataKey = generateDataKeyResponse.getBody().getCiphertextBlob();
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        // 3.使用KMS返回的数据密钥明文在本地对数据进行加密，下面以AES-256 GCM模式为例
        byte[] data = "<your plaintext data >".getBytes(StandardCharsets.UTF_8);
        byte[] iv = null; // 加密初始向量，解密时也需要传入
        byte[] cipherText = null; // 密文
        try {
            iv = new byte[GCM_IV_LENGTH];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            byte[] plainDataKeyBytes = Base64.getDecoder().decode(plainDataKey);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(plainDataKeyBytes, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
            cipherText = cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        // 4.输出密文，密文输出或持久化由用户根据需要进行处理，下面示例仅展示将密文输出到一个对象的情况
        // 假如outCipherText是需要输出的密文对象，至少需要包括以下三个内容:
        // (1) encryptedDataKey: KMS返回的数据密钥密文
        // (2) iv: 加密初始向量
        // (3) cipherText: 密文数据
        EnvelopeCipherPersistObject outCipherText = new EnvelopeCipherPersistObject()
                .setEncryptedDataKey(encryptedDataKey)
                .setIv(iv)
                .setCipherText(cipherText);
    }

    public static class EnvelopeCipherPersistObject implements Serializable {
        private String encryptedDataKey;
        private byte[] iv;
        private byte[] cipherText;

        public EnvelopeCipherPersistObject setEncryptedDataKey(String encryptedDataKey) {
            this.encryptedDataKey = encryptedDataKey;
            return this;
        }

        public String getEncryptedDataKey() {
            return encryptedDataKey;
        }

        public EnvelopeCipherPersistObject setIv(byte[] iv) {
            this.iv = iv;
            return this;
        }

        public byte[] getIv() {
            return iv;
        }

        public EnvelopeCipherPersistObject setCipherText(byte[] cipherText) {
            this.cipherText = cipherText;
            return this;
        }

        public byte[] getCipherText() {
            return cipherText;
        }
    }
}
