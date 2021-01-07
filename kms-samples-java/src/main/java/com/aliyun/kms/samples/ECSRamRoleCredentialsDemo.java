package com.aliyun.kms.samples;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.auth.AlibabaCloudCredentialsProvider;
import com.aliyuncs.auth.InstanceProfileCredentialsProvider;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.kms.model.v20160120.EncryptRequest;
import com.aliyuncs.kms.model.v20160120.EncryptResponse;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;

/**
 * 使用ECS RAM Role凭据类型示例
 */
public class ECSRamRoleCredentialsDemo {
    private static DefaultAcsClient kmsClient;

    private static DefaultAcsClient kmsClientECSRamRole(String regionId, String roleName) {
        AlibabaCloudCredentialsProvider provider = new InstanceProfileCredentialsProvider(roleName);
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

        String roleName = "****";
        kmsClient = kmsClientECSRamRole(regionId, roleName);

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
