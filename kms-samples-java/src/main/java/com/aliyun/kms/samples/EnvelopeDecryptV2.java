package com.aliyun.kms.samples;

import com.aliyun.kms20160120.Client;
import com.aliyun.kms20160120.models.DecryptRequest;
import com.aliyun.kms20160120.models.DecryptResponse;
import com.aliyun.teaopenapi.models.Config;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class EnvelopeDecryptV2 {
    // KMS Client对象
    private static Client client = null;
    // 如果kms实例开启公网访问，endpoint 请参考 https://api.aliyun.com/product/Kms
    // 如果kms实例未开启公网访问，endpoint 请使用实例VPC地址
    private static final String endpoint = "<your kms endpoint>";
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

        // 2.存储中读取封信加密持久化对象
        // 获取数据密钥明文，调用KMS解密数据密钥密文
        EnvelopeEncryptV2.EnvelopeCipherPersistObject envelopeCipherPersistObject = getEnvelopeCipherPersistObject();
        String encryptedDataKey = envelopeCipherPersistObject.getEncryptedDataKey(); // 待解密数据密钥密文，由KMS生成
        String plainDataKey = null;
        try {
            DecryptRequest decryptRequest = new DecryptRequest()
                    .setCiphertextBlob(encryptedDataKey);
            DecryptResponse decryptResponse = client.decrypt(decryptRequest);
            plainDataKey = decryptResponse.getBody().getPlaintext();
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        // 3.使用数据密钥明文在本地进行解密, 下面是以AES-256 GCM模式为例
        byte[] iv = envelopeCipherPersistObject.getIv(); // 本地加密时使用的初始向量, 解密数据需要传入
        byte[] cipherText = envelopeCipherPersistObject.getCipherText(); // 待解密密文
        try {
            byte[] plainDataKeyBytes = Base64.getDecoder().decode(plainDataKey);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(plainDataKeyBytes, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
            byte[] decryptedData = cipher.doFinal(cipherText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static EnvelopeEncryptV2.EnvelopeCipherPersistObject getEnvelopeCipherPersistObject() {
        // TODO 用户需要在此处代码进行替换，从存储中读取封信加密持久化对象
        return new EnvelopeEncryptV2.EnvelopeCipherPersistObject();
    }
}
