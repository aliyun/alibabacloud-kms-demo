# KMS开放API及最佳实践多语言样例

密钥管理服务（Key Management Service，简称KMS）提供密钥的安全托管及密码运算等服务。KMS内置密钥轮转等安全实践，支持其它云产品通过一方集成的方式对其管理的用户数据进行加密保护。借助KMS，您可以专注于数据加解密、电子签名验签等业务功能，无需花费大量成本来保障密钥的保密性、完整性和可用性。

产品官网：[官网](https://www.aliyun.com/product/kms)

KMS控制台：[控制台](https://kms.console.aliyun.com/)

官方文档：[帮助文档](https://help.aliyun.com/product/28933.htm)

在线API调试：[在线调试](https://api.aliyun.com/#/?product=Kms)

KMS SDK下载：[SDK地址](https://help.aliyun.com/document_detail/28956.html)



### 一、KMS开放API及最佳实践多语言样例

使用Java、Go、Python语言实现KMS已开放接口的使用样例以及加解密最佳实践样例。

- Java实现的对应目录：[kms-samples-java](./kms-samples-java)
- Go实现的对应目录：[kms-samples-go](./kms-samples-go)
- Python实现的对应目录：[kms-samples-python](./kms-samples-python)

### 二、样例代码组成

| 样例  | 描述  | [Java](./kms-samples-java) | [Go](./kms-samples-go)  |  [Python](./kms-samples-ptyhon)  |
|:----------|:----------|:----------|:----------|:----------|
| API测试    | 对阿里云KMS接口的测试代码 | [接口测试代码](./kms-samples-java/src/test/java/com/aliyun/kms/samples/OpenApiTest.java)    |[接口测试代码](./kms-samples-go/kms_api_samples) | [接口测试代码](./kms-samples-python/test_openapi.py) |
| 直接加密    | [使用主密钥对数据进行加密解密操作](https://help.aliyun.com/document_detail/131084.html)  | 主密钥[加密](./kms-samples-java/src/main/java/com/aliyun/kms/samples/CmkEncrypt.java), [解密](./kms-samples-java/src/main/java/com/aliyun/kms/samples/CmkDecrypt.java)    |   主密钥[加密](./kms-samples-go/cmk_encrypt_best_practices), [解密](./kms-samples-go/cmk_decrypt_best_practices)| 主密钥[加密](./kms-samples-python/cmk_encrypt.py), [解密](./kms-samples-python/cmk_decrypt.py) |
| 信封加密    | [使用主密钥生成一个数据密钥，再使用数据密钥在本地加解密数据](https://help.aliyun.com/document_detail/131058.html)  | 信封[加密](./kms-samples-java/src/main/java/com/aliyun/kms/samples/EnvelopeEncrypt.java), [解密](./kms-samples-java/src/main/java/com/aliyun/kms/samples/EnvelopeDecrypt.java)   | 信封[加密](./kms-samples-go/envelope_encrypt_best_practices), [解密](./kms-samples-go/envelope_decrypt_best_practices) |  信封[加密](./kms-samples-python/envelope_encrypt.py), [解密](.//kms-samples-python/envelope_decrypt.py)  |
| 数字签名    | [使用非对称CMK生成数字签名以及验证签名的场景](https://help.aliyun.com/document_detail/148146.html)  | [数字签名](./kms-samples-java/src/main/java/com/aliyun/kms/samples/AsymmetricKey.java)  |  [ECC](./kms-samples-go/asymmetric_ecdsa_p256_samples), [RSA](/kms-samples-go/asymmetric_rsassa_samples)  | [数字签名](./kms-samples-python/asymmetric.py) |
| 非对称加密    | [使用非对称CMK进行数据加密和解密的场景](https://help.aliyun.com/document_detail/148145.html)    | [非对称加密](./kms-samples-java/src/main/java/com/aliyun/kms/samples/AsymmetricKey.java)    | [RSA](./kms-samples-go/asymmetric_rsaes_samples)  | [非对称加密](./kms-samples-python/asymmetric.py)  |
| 证书请求    | 基于非对称主密钥生成证书请求    | [RSA证书请求](./kms-samples-java/src/main/java/com/aliyun/kms/samples/GenerateRSACSR.java), [ECC证书请求](./kms-samples-java/src/main/java/com/aliyun/kms/samples/GenerateECCSR.java), [SM2证书请求](./kms-samples-java/src/main/java/com/aliyun/kms/samples/GenerateSM2CSR.java)    | --- | --- |
| 支付宝开放平台    | [通过阿里云KMS产生RSA密钥对，提供支付宝开放平台接口加签功能](https://forum.alipay.com/mini-app/post/8001031)   | [公钥模式](./kms-samples-java/src/main/java/com/aliyun/kms/samples/KmsAlipayEasySDKPublicKeyDemo.java), [证书模式](./kms-samples-java/src/main/java/com/aliyun/kms/samples/KmsAlipayEasySDKCertDemo.java)    | --- | --- |


