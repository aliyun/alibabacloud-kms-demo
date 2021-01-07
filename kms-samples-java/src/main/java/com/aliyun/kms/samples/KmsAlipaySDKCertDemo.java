package com.aliyun.kms.samples;

import com.alipay.api.kms.aliyun.AliyunKMSAlipayClient;
import com.alipay.api.kms.aliyun.AliyunKMSCertAlipayRequest;
import com.alipay.api.kms.aliyun.AliyunKMSClient;
import com.alipay.api.request.AlipayMobilePublicQrcodeCreateRequest;
import com.alipay.api.response.AlipayMobilePublicQrcodeCreateResponse;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

/**
 * Alipay-sdk使用KMS签名示例，本示例展示了证书模式调用
 */
public class KmsAlipaySDKCertDemo {
    public static void main(String[] args) {
        // KMS主密钥ID，通过KMS控制台或API接口产生，需要改为自己的
        String keyId = "4358f298-8e30-4849-9791-****";
        // KMS密钥版本，通过KMS控制台或API接口获取，需要改为自己的
        String keyVersionId = "e71daa69-c321-4014-b0c4-****";
        // KMS服务地址
        // KMS服务地址列表详情:
        // 请参考：https://help.aliyun.com/document_detail/69006.html?spm=a2c4g.11186623.2.9.783f77cfAoNhY6#concept-69006-zh
        String endpoint = "kms.cn-hangzhou.aliyuncs.com";

        /**
         * 使用AccessKey创建阿里云KMS客户端
         */
        // 通过阿里云官方申请的AccessKey Id，根据实际情况修改
        String accessKeyId = getAliyunAccessKey("AccessKeyId");
        // 通过阿里云官方申请的AccessKey Secret，根据实际情况修改
        String accessKeySecret = getAliyunAccessKey("AccessKeySecret");
        AliyunKMSClient kmsClient = new AliyunKMSClient(endpoint, accessKeyId, accessKeySecret);

        /**
         * 使用STS token创建阿里云KMS客户端 (由用户维护Token)
         */
        //String stsAccessKeyId = "****";
        //String stsAccessKeySecret = "****";
        //String stsToken= "****";
        //AliyunKMSClient kmsClient = new AliyunKMSClient(endpoint, stsAccessKeyId, stsAccessKeySecret, stsToken);

        /**
         * 使用STS token创建阿里云KMS客户端 (由AliyunSDK维护Token)
         */
        //String accessKeyId = "****";
        //String accessKeySecret = "****";
        //String roleArn = "****";
        //String roleSessionName = "****";
        //AliyunKMSClient kmsClient = new AliyunKMSClient(endpoint, accessKeyId, accessKeySecret, roleArn, roleSessionName);

        /**
         * 使用ECS RAM Role创建阿里云KMS客户端
         */
        //String roleName = "****";
        //AliyunKMSClient kmsClient = new AliyunKMSClient(endpoint, roleName);

        try {
            AlipayMobilePublicQrcodeCreateRequest request = new AlipayMobilePublicQrcodeCreateRequest();
            request.setBizContent("{" +
                    "    \"ad_code\":\"CDP_OPEN_MERCHANT\"," +
                    "    \"content_type\":\"URL\"," +
                    "    \"content\":\"http://m.alipay.com/J/fdfd\"," +
                    "    \"action_url\":\"http://m.alipay.com/J/dfdf\"," +
                    "    \"ad_rules\":\"{\"shop_id\":[\"2015090800077000000002549828\"]}\"," +
                    "    \"height\":\"100\"," +
                    "    \"start_time\":\"2020-04-28 12:12:12\"," +
                    "    \"end_time\":\"2021-04-28 12:12:12\"" +
                    "  }");

            AliyunKMSCertAlipayRequest certAlipayRequest = new AliyunKMSCertAlipayRequest();
            certAlipayRequest.setServerUrl("https://openapi.alipay.com/gateway.do");
            certAlipayRequest.setFormat("json");
            certAlipayRequest.setCharset("utf-8");
            certAlipayRequest.setSignType("RSA2");

            // 请更换为您的AppId
            certAlipayRequest.setAppId("2021001185661068");
            // 使用KMS签名不需要设置私钥
            //certAlipayRequest.setPrivateKey(app_privateKey);
            // 请更换为您的应用公钥证书文件路径
            certAlipayRequest.setCertPath("./certs/appCertPublicKey.crt");
            // 请更换为您的支付宝公钥证书文件路径
            certAlipayRequest.setAlipayPublicCertPath("./certs/alipayCertPublicKey.crt");
            // 请更换为您的支付宝根证书文件路径
            certAlipayRequest.setRootCertPath("./certs/alipayRootCert.crt");
            // 设置阿里云KMS客户端对象
            certAlipayRequest.setClient(kmsClient);
            // 设置阿里云KMS主密钥ID
            certAlipayRequest.setKeyId(keyId);
            // 设置阿里云KMS主密钥版本
            certAlipayRequest.setKeyVersionId(keyVersionId);

            // 创建阿里云KMS支付宝客户端
            AliyunKMSAlipayClient alipayClient = new AliyunKMSAlipayClient(certAlipayRequest);
            AlipayMobilePublicQrcodeCreateResponse response = alipayClient.certificateExecute(request);

            System.out.println(response.getBody());
            System.out.println("pass");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 从文件中读取阿里云AccessKey配置信息
     * 此处为了方便示例，将AccessKey信息配置在resources资源下，实际过程中请不要这样做。
     *
     * @param key AccessKey配置对应的key
     * @return AccessKey配置字符串
     */
    private static String getAliyunAccessKey(String key) {
        InputStream stream = KmsAlipaySDKCertDemo.class.getResourceAsStream("/aliyunAccessKey.json");
        Map<String, String> result = new Gson().fromJson(new InputStreamReader(stream), new TypeToken<Map<String, String>>() {
        }.getType());
        return result.get(key);
    }
}
