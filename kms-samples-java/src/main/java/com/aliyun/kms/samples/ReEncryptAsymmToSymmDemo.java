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

import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

public class ReEncryptAsymmToSymmDemo {
    private static DefaultAcsClient kmsClient;

    private static String getAliyunAccessKey(String key) {
        InputStream stream = ReEncryptAsymmToSymmDemo.class.getResourceAsStream("/aliyunAccessKey.json");
        Map<String, String> result = new Gson().fromJson(
                new InputStreamReader(stream), new TypeToken<Map<String, String>>() {
                }.getType()
        );
        return result.get(key);
    }

    private static DefaultAcsClient kmsClient(String regionId, String accessKeyId, String accessKeySecret) {
        IClientProfile profile = DefaultProfile.getProfile(regionId, accessKeyId, accessKeySecret);
        HttpClientConfig clientConfig = HttpClientConfig.getDefault();
        //clientConfig.setIgnoreSSLCerts(true);
        profile.setHttpClientConfig(clientConfig);
        return new DefaultAcsClient(profile);
    }

    private static GenerateDataKeyResponse generateDataKey(String keyId) throws ClientException {
        final GenerateDataKeyRequest request = new GenerateDataKeyRequest();
        request.setAcceptFormat(FormatType.JSON);
        request.setKeyId(keyId);
        return kmsClient.getAcsResponse(request);
    }

    private static GetPublicKeyResponse getPublicKey(String keyId, String keyVersionId) throws ClientException {
        final GetPublicKeyRequest request = new GetPublicKeyRequest();
        request.setAcceptFormat(FormatType.JSON);
        request.setKeyId(keyId);
        request.setKeyVersionId(keyVersionId);
        return kmsClient.getAcsResponse(request);
    }

    private static ExportDataKeyResponse exportDataKey(String cipherTextBlob, String publicKeyBlob, String wrappingKeySpec, String wrappingAlgorithm) throws ClientException {
        final ExportDataKeyRequest request = new ExportDataKeyRequest();
        request.setAcceptFormat(FormatType.JSON);
        request.setCiphertextBlob(cipherTextBlob);
        request.setPublicKeyBlob(publicKeyBlob);
        request.setWrappingKeySpec(wrappingKeySpec);
        request.setWrappingAlgorithm(wrappingAlgorithm);
        return kmsClient.getAcsResponse(request);
    }

    public static ReEncryptResponse reEncrypt(String ciphertextBlob, String destinationKeyId, String sourceKeyId, String sourceKeyVersionId, String sourceEncryptionAlgorithm) throws ClientException {
        final ReEncryptRequest request = new ReEncryptRequest();
        request.setAcceptFormat(FormatType.JSON);
        request.setCiphertextBlob(ciphertextBlob);
        request.setDestinationKeyId(destinationKeyId);
        request.setSourceKeyId(sourceKeyId);
        request.setSourceKeyVersionId(sourceKeyVersionId);
        request.setSourceEncryptionAlgorithm(sourceEncryptionAlgorithm);
        return kmsClient.getAcsResponse(request);
    }

    public static void main(String[] args) {
        String regionId = "cn-hangzhou";
        String accessKeyId = getAliyunAccessKey("AccessKeyId");
        String accessKeySecret = getAliyunAccessKey("AccessKeySecret");

        kmsClient = kmsClient(regionId, accessKeyId, accessKeySecret);

        try {
            String symmCmkId = "2fad5f44-xxxx-xxxx-xxxx-666c52cc9fa9";
            // 对密文解密后再次加密时使用的对称主密钥ID
            String dstSymmCmkId = "09bfadaf-xxxx-xxxx-xxxx-7d43c41a08c6";

            // 解密密文时使用的主密钥ID
            String asymmCmkId = "af5a4579-xxxx-xxxx-xxxx-9ccca3139e68";
            // 用于解密密文的密钥版本标识符
            String asymmCmkVersionId = "0e7d8614-xxxx-xxxx-xxxx-f632c3737e3c";

            // 生成数据密钥
            GenerateDataKeyResponse genDKResponse = generateDataKey(symmCmkId);
            System.out.println("call GenerateDataKey:");
            System.out.println(genDKResponse.getPlaintext());
            System.out.println(genDKResponse.getCiphertextBlob());

            // 获取Base64格式的公钥
            GetPublicKeyResponse getPubKeyResponse = getPublicKey(asymmCmkId, asymmCmkVersionId);
            String pemKey = getPubKeyResponse.getPublicKey();
            String base64Key = pemKey.replaceFirst("-----BEGIN PUBLIC KEY-----", "");
            base64Key = base64Key.replaceFirst("-----END PUBLIC KEY-----", "");
            base64Key = base64Key.replaceAll("\\s", "");

            // 主密钥（CMK）加密数据密钥的密文。
            String ciphertextBlob = genDKResponse.getCiphertextBlob();
            // PublicKeyBlob的密钥类型
            String wrappingKeySpec = "RSA_2048";
            // 使用PublicKeyBlob所指定的公钥，加密（Wrap）数据密钥时的加密算法
            String wrappingAlgorithm = "RSAES_OAEP_SHA_256";
            // 调用ExportDataKey接口使用传入的公钥加密导出数据密钥
            ExportDataKeyResponse exportDKResponse = exportDataKey(ciphertextBlob, base64Key, wrappingKeySpec, wrappingAlgorithm);

            // 待转加密的密文： 非对称类型CMK公钥加密的DataKey
            String exportedDataKey = exportDKResponse.getExportedDataKey();
            // CiphertextBlob是公钥加密结果时，指定公钥加密的算法
            String sourceEncryptionAlgorithm = "RSAES_OAEP_SHA_256";
            // 调用ReEncrypt接口对密文进行转加密。即先解密密文，然后将解密得到的数据或者数据密钥使用新的主密钥再次进行加密，返回加密结果
            ReEncryptResponse ReEncResponse = reEncrypt(exportedDataKey, dstSymmCmkId, asymmCmkId, asymmCmkVersionId, sourceEncryptionAlgorithm);

            System.out.println("call ReEncrypt:");
            System.out.println(ReEncResponse.getCiphertextBlob());
        } catch (ClientException e) {
            System.out.println("Failed.");
            System.out.println("Error code: " + e.getErrCode());
            System.out.println("Error message: " + e.getErrMsg());
        }
    }
}
