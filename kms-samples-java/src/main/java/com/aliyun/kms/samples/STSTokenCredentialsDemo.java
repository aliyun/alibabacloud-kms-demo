package com.aliyun.kms.samples;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.auth.AlibabaCloudCredentialsProvider;
import com.aliyuncs.auth.STSAssumeRoleSessionCredentialsProvider;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.kms.model.v20160120.EncryptRequest;
import com.aliyuncs.kms.model.v20160120.EncryptResponse;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

/**
 * 使用STS Token凭据类型示例
 */
public class STSTokenCredentialsDemo {
    private static DefaultAcsClient kmsClient;

    private static String getAliyunAccessKey(String key) {
        InputStream stream = KmsSDKExponentialBackoffDemo.class.getResourceAsStream("/aliyunAccessKey.json");
        Map<String, String> result = new Gson().fromJson(
                new InputStreamReader(stream),
                new TypeToken<Map<String, String>>() {
                }.getType()
        );
        return result.get(key);
    }

    private static DefaultAcsClient kmsClientAccessKey(String regionId, String accessKeyId, String accessKeySecret) {
        IClientProfile profile = DefaultProfile.getProfile(regionId, accessKeyId, accessKeySecret);
        HttpClientConfig clientConfig = HttpClientConfig.getDefault();
        profile.setHttpClientConfig(clientConfig);
        return new DefaultAcsClient(profile);
    }

    private static DefaultAcsClient kmsClientSTSToken(String regionId, String stsAccessKeyId, String stsAccessKeySecret, String stsToken) {
        IClientProfile profile = DefaultProfile.getProfile(regionId, stsAccessKeyId, stsAccessKeySecret, stsToken);
        HttpClientConfig clientConfig = HttpClientConfig.getDefault();
        profile.setHttpClientConfig(clientConfig);
        return new DefaultAcsClient(profile);
    }

    private static DefaultAcsClient kmsClientRamRoleArnOrSts(String regionId, String accessKeyId, String accessKeySecret, String roleSessionName, String roleArn) {
        AlibabaCloudCredentialsProvider provider = new STSAssumeRoleSessionCredentialsProvider(accessKeyId, accessKeySecret, roleSessionName, roleArn, regionId);
        IClientProfile profile = DefaultProfile.getProfile(regionId);
        HttpClientConfig clientConfig = HttpClientConfig.getDefault();
        profile.setHttpClientConfig(clientConfig);
        return new DefaultAcsClient(profile, provider);
    }

    private static EncryptResponse encrypt(String keyAlias, String plaintext) throws ClientException {
        final EncryptRequest request = new EncryptRequest();
        request.setAcceptFormat(FormatType.JSON);
        request.setKeyId(keyAlias);
        request.setPlaintext(plaintext);
        return kmsClient.getAcsResponse(request);
    }

    public static void main(String[] args) {
        String regionId = "cn-hangzhou";
        String keyAlias = "alias/Apollo/WorkKey";
        String plainText = "hello world";

        /**
         * 使用STS token创建阿里云KMS Client (由AliyunSDK维护Token)
         */
        String accessKeyId = getAliyunAccessKey("AccessKeyId");
        String accessKeySecret = getAliyunAccessKey("AccessKeySecret");
        String roleArn = "****";
        String roleSessionName = "****";
        kmsClient = kmsClientRamRoleArnOrSts(regionId, accessKeyId, accessKeySecret, roleArn, roleSessionName);

        /**
         * 使用STS token创建阿里云KMS Client (由用户维护Token)
         */
        //String stsAccessKeyId = "****";
        //String stsAccessKeySecret = "****";
        //String stsToken= "****";
        //kmsClient = kmsClientSTSToken(regionId, stsAccessKeyId, stsAccessKeySecret, stsToken);

        /**
         * 使用AccessKey创建阿里云KMS Client
         */
        //String accessKeyId = getAliyunAccessKey("AccessKeyId");
        //String accessKeySecret = getAliyunAccessKey("AccessKeySecret");
        //kmsClient = kmsClientAccessKey(regionId, accessKeyId, accessKeySecret);

        try {
            EncryptResponse encResponse = encrypt(keyAlias, plainText);
            String cipherBlob = encResponse.getCiphertextBlob();
            System.out.println("CiphertextBlob: " + cipherBlob);
            System.out.println("KeyId: " + encResponse.getKeyId());
        } catch (ClientException e) {
            System.out.println("Failed.");
            System.out.println("Error code: " + e.getErrCode());
            System.out.println("Error message: " + e.getErrMsg());
        }
    }
}
