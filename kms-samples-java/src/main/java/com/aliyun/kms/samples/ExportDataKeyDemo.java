package com.aliyun.kms.samples;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.http.MethodType;
import com.aliyuncs.http.ProtocolType;
import com.aliyuncs.kms.model.v20160120.*;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

public class ExportDataKeyDemo {
    private static DefaultAcsClient kmsClient;

    private static String getAliyunAccessKey(String key) {
        InputStream stream = ExportDataKeyDemo.class.getResourceAsStream("/aliyunAccessKey.json");
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

    private static GenerateDataKeyWithoutPlaintextResponse generateDataKeyWithoutPlaintext(String keyId) throws ClientException {
        final GenerateDataKeyWithoutPlaintextRequest request = new GenerateDataKeyWithoutPlaintextRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
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

    public static void main(String[] args) {
        String regionId = "cn-hangzhou";
        String accessKeyId = getAliyunAccessKey("AccessKeyId");
        String accessKeySecret = getAliyunAccessKey("AccessKeySecret");

        kmsClient = kmsClient(regionId, accessKeyId, accessKeySecret);

        try{
            String symmCmkId = "2fad5f44-xxxx-xxxx-xxxx-666c52cc9fa9";

            // 调用GenerateDataKeyWithoutPlaintext接口随机生成一个数据密钥，返回CMK加密数据密钥的密文
            GenerateDataKeyWithoutPlaintextResponse genDKResponse = generateDataKeyWithoutPlaintext(symmCmkId);
            System.out.println("call generateDataKeyWithoutPlaintext:");
            System.out.println(genDKResponse.getCiphertextBlob());

            String pemPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvPwSVgmGAaKEs6nFDYnC\n" +
                    "GJESmXeUvIlfHbjGQo02a7lAaOdfZ+TRGwtwkQCXg69wLHOw7QYHtG0/W8M/NMfj\n" +
                    "AVBdH9qB82NpK5TPg6BwFl1Z+otkltfTckQYsGhk8tmimU+w06cJzz6256Gh+Rr/\n" +
                    "T93n12U5QFztk5HHNX/3tz4LWM9gpMKBVaMEHF2JsMQ2b/RtQXwNoZbFOqEtTh/R\n" +
                    "yP1bWPipUcD8PFYhQBHwCEHCVKHPHU/mdd09wtihWud83xipFhabiNOmwXAc5RVF\n" +
                    "o+53I3YpSSsc4uUvnfL22dwVJoyxy0Awl/J8w1r0GMU/yvbXy1AXC4MCcolAydKM\n" +
                    "1QIDAQAB\n" +
                    "-----END PUBLIC KEY-----";
            // Base64编码的公钥
            String base64PublicKey = pemPublicKey.replaceFirst("-----BEGIN PUBLIC KEY-----", "");
            base64PublicKey = base64PublicKey.replaceFirst("-----END PUBLIC KEY-----", "");
            base64PublicKey = base64PublicKey.replaceAll("\\s", "");

            // 主密钥（CMK）加密数据密钥的密文。
            String ciphertextBlob = genDKResponse.getCiphertextBlob();
            // PublicKeyBlob的密钥类型
            String wrappingKeySpec = "RSA_2048";
            // 使用PublicKeyBlob所指定的公钥，加密（Wrap）数据密钥时的加密算法
            String wrappingAlgorithm = "RSAES_OAEP_SHA_256";
            // 调用ExportDataKey接口使用传入的公钥加密导出数据密钥
            ExportDataKeyResponse exportDKResponse = exportDataKey(ciphertextBlob, base64PublicKey, wrappingKeySpec, wrappingAlgorithm);
            System.out.println("call exportDataKey:");
            System.out.println(exportDKResponse.getExportedDataKey());

        }catch (ClientException e){
            System.out.println("Failed.");
            System.out.println("Error code: " + e.getErrCode());
            System.out.println("Error message: " + e.getErrMsg());
        }
    }
}
