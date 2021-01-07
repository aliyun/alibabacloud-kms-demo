# KMS开放API及最佳实践多语言样例-Java实现

密钥管理服务（Key Management Service，简称KMS）提供密钥的安全托管及密码运算等服务。KMS内置密钥轮转等安全实践，支持其它云产品通过一方集成的方式对其管理的用户数据进行加密保护。借助KMS，您可以专注于数据加解密、电子签名验签等业务功能，无需花费大量成本来保障密钥的保密性、完整性和可用性。

本项目使用Java语言实现了KMS以下几个方面的使用样例：

​	1、KMS开放API使用样例

​	2、KMS主密钥在线加解密最佳实践样例

​	3、KMS信封加密本地加解密最佳实践样例

​	4、KMS非对称密钥加解密签名验签使用样例

​	5、KMS使用公钥保护导出数据密钥使用样例

​	6、KMS数据密钥转加密使用样例

​	7、使用STS Token或ECS RamRole访问KMS使用样例

​	8、使用指数退避方法对请求错误进行重试最佳实践样例

​	9、KMS非对称密钥生成CSR最佳实践样例

​	10、Alipay-easysdk/sdk使用KMS签名最佳实践样例

​	11、使用KMS非对称CMK对PDF文件签名最佳实践样例



## 项目源码组织结构

- 将项目代码下载到本地，可看到如下目录结构：

  ```
  ─code-samples
    │  
    ├─kms-samples-java
       │  pom.xml
       │          
       ├─src
         ├─main
         │  ├─java
         │  │  └─com
         │  │      └─kms
         │  │          └─samples
         │  │                  AsymmetricKey.java
         │  │                  CmkDecrypt.java
         │  │                  CmkEncrypt.java
         │  │                  ECSRamRoleCredentialsDemo.java
         │  │                  ExportDataKeyDemo.java
         │  │                  GenerateAndExportDataKeyDemo.java
         │  │                  EnvelopeDecrypt.java
         │  │                  EnvelopeEncrypt.java
         │  │                  GenerateECCSR.java
         │  │                  GenerateRSACSR.java
         │  │                  GenerateSM2CSR.java
         │  │                  KmsAlipayEasySDKCertDemo.java
         │  │                  KmsAlipayEasySDKPublicKeyDemo.java
         │  │                  KmsAlipaySDKCertDemo.java
         │  │                  KmsAlipaySDKPublicKeyDemo.java
         │  │                  KmsSDKExponentialBackoffDemo.java
         │  │                  OpenApi.java
         │  │                  ReEncryptAsymmToSymmDemo.java
         │  │                  ReEncryptSymmToSymmDemo.java
         │  │                  STSTokenCredentialsDemo.java
         │  │                └─pdfsig   
         │  │                      KMSiTextSignature.java
         │  │                      KmsPdfSignSample.java
         │  │                  
         │  └─resources
         │     └─fixture
         │            aliyunAccessKey.json
         └─test
             └─java
                 └─com
                     └─kms
                         └─samples
                                 OpenApiTest.java
                                 TestRunner.java
  
  ```
  

说明：

1、OpenApi.java和OpenApiTest.java包含KMS已开放接口调用样例

2、CmkEncrypt.java和CmkDecrypt.java包含KMS主密钥在线加密和解密最佳实践样例

3、EnvelopeEncrypt.java和EnvelopeDecrypt.java包含KMS信封加密本地加密和解密最佳实践样例

4、AsymmetricKey.java包含了KMS非对称密钥加密、解密、签名和验签使用样例

5、ExportDataKeyDemo.java、GenerateAndExportDataKeyDemo.java包含了KMS使用公钥保护导出数据密钥使用样例

6、ReEncryptSymmToSymmDemo.java 、ReEncryptAsymmToSymmDemo.java包含了KMSKMS数据密钥转加密使用样例

7、ECSRamRoleCredentialsDemo.java、STSTokenCredentialsDemo.java包含了使用STS Token或ECS RamRole访问KMS使用样例

8、KmsSDKExponentialBackoffDemo.java 包含KMS使用指数退避方法对请求错误进行重试最佳实践样例

9、GenerateECCSR.java、GenerateRSACSR.java和GenerateSM2CSR.java包含KMS非对称密钥生成CSR最佳实践样例

10、KmsAlipayEasySDKCertDemo.java和KmsAlipayEasySDKPublicKeyDemo.java包含Alipay-easysdk使用KMS签名最佳实践样例

11、KMSiTextSignature.java KmsPdfSignSample.java 包含KMS非对称密钥对pdf文件进行签名的最佳实践样例


## 使用方法

### 一、KMS开放API使用样例

([什么是Access Key](https://help.aliyun.com/document_detail/53045.html))

([API参考](https://help.aliyun.com/document_detail/69005.html))

- 设置Access Key Id和Access Key Secret

  打开命令行窗口，切换到kms-samples-java目录，执行下面命令：

  ```
  set AccessKeyId="ak"
  set AccessKeySecret="as"
  ```

- 运行测试代码

  - 依赖包准备
  - 下载最新版本的JUnit，这里以junit-4.13.jar示例，将其复制到resources文件夹
    - 下载aliyun-java-sdk-core-4.5.0，将其复制到resources文件夹
    - 下载aliyun-java-sdk-kms-2.11.0，将其复制到resources文件夹
    - 下载gson-2.8.5，将其复制到resources文件夹
  
- 编译，执行下面命令：
  
```
  javac -encoding UTF-8 -cp "src\main\resources\*" -d target src\main\java\com\kms\samples\OpenApi.java src\test\java\com\kms\samples\*.java
```

- 运行，执行下面命令：
  
```
  java -cp "target;src\main\resources\*"  TestRunner
```

注：

- 样例中的配置信息，如ak，as，endpoint，regionid等，要根据真实信息进行修改



### 二、KMS主密钥在线加解密最佳实践样例

#### 1、加密数据

- 设置Access Key Id和Access Key Secret

  打开命令行窗口，切换到kms-samples-java目录，执行下面命令：

  ```
  set AccessKeyId="ak"
  set AccessKeySecret="as"
  ```

- 运行样例

  - 准备工作
  - 需要依赖的包
      - 下载aliyun-java-sdk-core-4.5.0，将其复制到resources文件夹
      - 下载aliyun-java-sdk-kms-2.11.0，将其复制到resources文件夹
      - 下载gson-2.8.5，将其复制到resources文件夹
    - 确保已拥有一个KMS主密钥，本示例使用别名调用加密接口，假定主密钥别名为：alias/Apollo/WorkKey
    - 在kms-samples-java目录下创建certs文件夹
    - 准备一个明文密钥文件，复制到certs文件夹里，本示例假定明文密钥文件名为：key.pem
  
- 编译，执行下面命令：
  
```
  javac -encoding UTF-8 -cp "src\main\resources\*" -d target src\main\java\com\kms\samples\CmkEncrypt.java 
```

- 运行，执行下面命令：
  
```
  java -cp "target;src\main\resources\*"  CmkEncrypt
```

- 执行成功后，会在certs文件夹生成密文文件：key.pem.cipher

注：

- 样例中的配置信息，如ak，as，endpoint，regionid等，要根据真实信息进行修改



#### 2、解密数据

- 设置Access Key Id和Access Key Secret

  打开命令行窗口，切换到kms-samples-java目录，执行下面命令：

  ```
  set AccessKeyId="ak"
  set AccessKeySecret="as"
  ```

- 运行样例

  - 准备工作
  - 需要依赖的包
      - 下载aliyun-java-sdk-core-4.5.0，将其复制到resources文件夹
      - 下载aliyun-java-sdk-kms-2.11.0，将其复制到resources文件夹
    - 下载gson-2.8.5，将其复制到resources文件夹
    - 本示例需要用到加密示例生成的密文文件key.pem.cipher，请先运行加密示例产生此文件
  
- 编译，执行下面命令：
  
  ```
  javac -encoding UTF-8 -cp "src\main\resources\*" -d target src\main\java\com\kms\samples\CmkDecrypt.java 
  ```
  
- 运行，执行下面命令：
  
  ```
  java -cp "target;src\main\resources\*"  CmkDecrypt
  ```
  
  - 执行成功后，会在certs文件夹生成明文文件：decrypted_key.pem.cipher

注：

- 样例中的配置信息，如ak，as，endpoint，regionid等，要根据真实信息进行修改



### 三、KMS信封加密本地加解密最佳实践样例

#### 1、加密数据

- 设置Access Key Id和Access Key Secret

  打开命令行窗口，切换到kms-samples-java目录，执行下面命令：

  ```
  set AccessKeyId="ak"
  set AccessKeySecret="as"
  ```

- 运行样例

  - 准备工作
  - 需要依赖的包
      - 下载aliyun-java-sdk-core-4.5.0，将其复制到resources文件夹
      - 下载aliyun-java-sdk-kms-2.11.0，将其复制到resources文件夹
      - 下载gson-2.8.5，将其复制到resources文件夹
    - 确保已拥有一个KMS主密钥，本示例使用别名调用生成数据密钥接口，假定主密钥别名为：alias/Apollo/WorkKey
    - 在kms-samples-java目录下创建data文件夹
    - 准备一个明文数据文件，复制到data文件夹里，本示例假定明文数据文件名为：sales.csv
  
  - 编译，执行下面命令：
  
  ```
  javac -encoding UTF-8 -cp "src\main\resources\*" -d target src\main\java\com\kms\samples\EnvelopeEncrypt.java 
  ```
  
  - 运行，执行下面命令：
  
  ```
  java -cp "target;src\main\resources\*"  EnvelopeEncrypt
  ```
  
  - 执行成功后，会在data文件夹生成密文文件：sales.csv.cipher

注：

- 样例中的配置信息，如ak，as，endpoint，regionid等，要根据真实信息进行修改



#### 2、解密数据

- 设置Access Key Id和Access Key Secret

  打开命令行窗口，切换到kms-samples-java目录，执行下面命令：

  ```
  set AccessKeyId="ak"
  set AccessKeySecret="as"
  ```

- 运行样例

  - 准备工作
  - 需要依赖的包
      - 下载aliyun-java-sdk-core-4.5.0，将其复制到resources文件夹
      - 下载aliyun-java-sdk-kms-2.11.0，将其复制到resources文件夹
      - 下载gson-2.8.5，将其复制到resources文件夹
    - 本示例需要用到加密示例生成的密文文件sales.csv.cipher，请先运行加密示例产生此文件
  
- 编译，执行下面命令：
  
  ```
  javac -encoding UTF-8 -cp "src\main\resources\*" -d target src\main\java\com\kms\samples\EnvelopeDecrypt.java 
  ```
  
- 运行，执行下面命令：
  
  ```
  java -cp "target;src\main\resources\*"  EnvelopeDecrypt
  ```
  
  - 执行成功后，会在data文件夹生成明文文件：decrypted_sales.csv

注：

- 样例中的配置信息，如ak，as，endpoint，regionid等，要根据真实信息进行修改
