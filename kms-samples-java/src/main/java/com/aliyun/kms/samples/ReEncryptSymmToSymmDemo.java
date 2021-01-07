package com.aliyun.kms.samples;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.kms.model.v20160120.GenerateDataKeyRequest;
import com.aliyuncs.kms.model.v20160120.GenerateDataKeyResponse;
import com.aliyuncs.kms.model.v20160120.ReEncryptRequest;
import com.aliyuncs.kms.model.v20160120.ReEncryptResponse;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

public class ReEncryptSymmToSymmDemo {
    private static DefaultAcsClient kmsClient;

    private static String getAliyunAccessKey(String key) {
        InputStream stream = ReEncryptSymmToSymmDemo.class.getResourceAsStream("/aliyunAccessKey.json");
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

    private static ReEncryptResponse reEncrypt(String ciphertextBlob, String destinationKeyId) throws ClientException {
        final ReEncryptRequest request = new ReEncryptRequest();
        request.setAcceptFormat(FormatType.JSON);
        request.setCiphertextBlob(ciphertextBlob);
        request.setDestinationKeyId(destinationKeyId);
        return kmsClient.getAcsResponse(request);
    }

    public static void main(String[] args) {
        String regionId = "cn-hangzhou";
        String accessKeyId = getAliyunAccessKey("AccessKeyId");
        String accessKeySecret = getAliyunAccessKey("AccessKeySecret");

        kmsClient = kmsClient(regionId, accessKeyId, accessKeySecret);

        try {
            // CMK
            String symmCmkId1 = "2fad5f44-xxxx-xxxx-xxxx-666c52cc9fa9";
            // 对密文解密后再次加密时使用的对称主密钥ID
            String destCmkId = "09bfadaf-xxxx-xxxx-xxxx-7d43c41a08c6";

            // 生成数据密钥
            GenerateDataKeyResponse genDKResponse = generateDataKey(symmCmkId1);
            System.out.println("call GenerateDataKey:");
            System.out.println(genDKResponse.getPlaintext());
            System.out.println(genDKResponse.getCiphertextBlob());

            // 待转加密的密文： 对称类型CMK加密的DataKey
            String ciphertextBlob = genDKResponse.getCiphertextBlob();
            // 调用ReEncrypt接口对密文进行转加密。即先解密密文，然后将解密得到的数据或者数据密钥使用新的主密钥再次进行加密，返回加密结果
            ReEncryptResponse ReEncResponse = reEncrypt(ciphertextBlob, destCmkId);
            System.out.println("call ReEncrypt:");
            System.out.println(ReEncResponse.getCiphertextBlob());
        } catch (ClientException e) {
            System.out.println("Failed.");
            System.out.println("Error code: " + e.getErrCode());
            System.out.println("Error message: " + e.getErrMsg());
        }
    }
}
