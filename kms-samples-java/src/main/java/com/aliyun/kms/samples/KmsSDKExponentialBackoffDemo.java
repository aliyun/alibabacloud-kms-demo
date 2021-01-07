package com.aliyun.kms.samples;

import com.aliyuncs.AcsRequest;
import com.aliyuncs.AcsResponse;
import com.aliyuncs.DefaultAcsClient;
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
 * KMS SDK API指数退避重试样例
 */
public class KmsSDKExponentialBackoffDemo {
    private final static String REJECTED_THROTTLING = "Rejected.Throttling";
    private final static String SERVICE_UNAVAILABLE_TEMPORARY = "ServiceUnavailableTemporary";
    private final static String INTERNAL_FAILURE = "InternalFailure";
    private static DefaultAcsClient kmsClient;
    private static long retryInitialIntervalMills = 200L;
    private static long capacity = 10000L;
    private static Integer maxRetries = 5;

    private static String getAliyunAccessKey(String key) {
        InputStream stream = KmsSDKExponentialBackoffDemo.class.getResourceAsStream("/aliyunAccessKey.json");
        Map<String, String> result = new Gson().fromJson(
                new InputStreamReader(stream),
                new TypeToken<Map<String, String>>() {
                }.getType()
        );
        return result.get(key);
    }

    private static DefaultAcsClient kmsClient(String regionId, String accessKeyId, String accessKeySecret) {
        IClientProfile profile = DefaultProfile.getProfile(regionId, accessKeyId, accessKeySecret);
        HttpClientConfig clientConfig = HttpClientConfig.getDefault();
        profile.setHttpClientConfig(clientConfig);
        return new DefaultAcsClient(profile);
    }

    private static EncryptResponse encrypt(String keyAlias, String plaintext) throws ClientException {
        final EncryptRequest request = new EncryptRequest();
        request.setAcceptFormat(FormatType.JSON);
        request.setKeyId(keyAlias);
        request.setPlaintext(plaintext);
        return getAcsResponseWithRetry(EncryptResponse.class, request);
    }

    private static <T extends AcsResponse> T getAcsResponseWithRetry(Class<T> clz, AcsRequest<T> request) throws ClientException {
        if (maxRetries <= 0) {
            maxRetries = 1;
        }
        for (int i = 0; i < maxRetries; i++) {
            try {
                AcsResponse resp = kmsClient.getAcsResponse(request);
                return clz.cast(resp);
            } catch (ClientException e) {
                if (judgeNeedBackoff(e)) {
                    try {
                        Thread.sleep(getWaitTimeExponential(i + 1));
                    } catch (InterruptedException ignore) {
                    }
                } else {
                    throw e;
                }
            }
        }
        throw new ClientException("No results obtained after retrying " + maxRetries + " times");
    }

    private static long getWaitTimeExponential(int retryTimes) {
        return Math.min(capacity, (long) (Math.pow(2, retryTimes) * retryInitialIntervalMills));
    }

    private static boolean judgeNeedBackoff(ClientException e) {
        return REJECTED_THROTTLING.equals(e.getErrCode()) || SERVICE_UNAVAILABLE_TEMPORARY.equals(e.getErrCode()) || INTERNAL_FAILURE.equals(e.getErrCode());
    }

    public static void main(String[] args) {
        String regionId = "cn-hangzhou";
        String accessKeyId = getAliyunAccessKey("AccessKeyId");
        String accessKeySecret = getAliyunAccessKey("AccessKeySecret");
        String keyAlias = "alias/Apollo/WorkKey";
        String plainText = "hello world";

        kmsClient = kmsClient(regionId, accessKeyId, accessKeySecret);

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
