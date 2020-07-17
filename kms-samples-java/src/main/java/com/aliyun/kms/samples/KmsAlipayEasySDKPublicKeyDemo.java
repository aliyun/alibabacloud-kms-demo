package com.aliyun.kms.samples;

import com.alipay.easysdk.base.qrcode.models.AlipayOpenAppQrcodeCreateResponse;
import com.alipay.easysdk.factory.Factory;
import com.alipay.easysdk.kms.aliyun.AliyunKMSConfig;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

/**
 * Alipay-easysdk使用KMS签名示例，本示例展示了公钥模式调用
 */
public class KmsAlipayEasySDKPublicKeyDemo {
    public static void main(String[] args) {
        Factory.setOptions(getOptions());
        try {
            AlipayOpenAppQrcodeCreateResponse response = Factory.Base.Qrcode().create("page/component/component-pages/view/view", "x=1", "二维码描述");
            if ("10000".equals(response.code)) {
                System.out.println("调用成功");
            } else {
                System.err.println("调用失败，原因：" + response.msg + "，" + response.subMsg);
            }
        } catch (Exception e) {
            System.err.println("调用遭遇异常，原因：" + e.getMessage());
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    private static AliyunKMSConfig getOptions() {
        AliyunKMSConfig config = new AliyunKMSConfig();
        config.protocol = "https";
        config.gatewayHost = "openapi.alipay.com";
        config.signType = "RSA2";

        // 请更换为您的AppId
        config.appId = "202100****";
        // 请修改如下的支付宝公钥字符串为自己的支付宝公钥
        config.alipayPublicKey = "MIIBIjANB...";

        // 如果使用阿里云KMS签名，则需要指定签名提供方名称，阿里云KMS的名称为"AliyunKMS"
        config.signProvider = "AliyunKMS";

        // 如果使用阿里云KMS签名，请更换为您的阿里云AccessKeyId
        config.aliyunAccessKeyId = getAliyunAccessKey("AccessKeyId");
        // 如果使用阿里云KMS签名，请更换为您的阿里云AccessKeySecret
        config.aliyunAccessKeySecret = getAliyunAccessKey("AccessKeySecret");
        // 如果使用阿里云KMS签名，请更换为您的KMS服务密钥ID
        config.kmsKeyId = "4358f298-8e30-4849-9791-****";
        // 如果使用阿里云KMS签名，请更换为您的KMS服务密钥版本ID
        config.kmsKeyVersionId = "e71daa69-c321-4014-b0c4-****";

        // 如果使用阿里云KMS签名，需要更换为您的KMS服务地址
        // KMS服务地址列表详情，请参考：
        // https://help.aliyun.com/document_detail/69006.html?spm=a2c4g.11186623.2.9.783f77cfAoNhY6#concept-69006-zh
        config.kmsEndpoint = "kms.cn-hangzhou.aliyuncs.com";

        return config;
    }

    /**
     * 从文件中读取阿里云AccessKey配置信息
     * 此处为了测试执行的环境普适性，AccessKey信息配置在resources资源下，实际过程中请不要这样做。
     *
     * @param key AccessKey配置对应的key
     * @return AccessKey配置字符串
     */
    private static String getAliyunAccessKey(String key) {
        InputStream stream = KmsAlipayEasySDKPublicKeyDemo.class.getResourceAsStream("/fixture/aliyunAccessKey.json");
        Map<String, String> result = new Gson().fromJson(new InputStreamReader(stream), new TypeToken<Map<String, String>>() {
        }.getType());
        return result.get(key);
    }
}
