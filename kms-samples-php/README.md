# KMS开放API及最佳实践多语言样例-PHP实现

密钥管理服务（Key Management Service，简称KMS）提供密钥的安全托管及密码运算等服务。KMS内置密钥轮转等安全实践，支持其它云产品通过一方集成的方式对其管理的用户数据进行加密保护。借助KMS，您可以专注于数据加解密、电子签名验签等业务功能，无需花费大量成本来保障密钥的保密性、完整性和可用性。

本项目使用PHP语言实现了KMS以下几个方面的使用样例：

​	1、阿里云SDK V2版本信封加密本地加解密使用样例



## 项目源码组织结构

- 将项目代码下载到本地，可看到如下目录结构：

  ```
  ─code-samples
    │
    └─kms-samples-php
            EnvelopeEncryptV2.php
            EnvelopeDecryptV2.php
  ```



说明：

1、EnvelopeEncryptV2.php和EnvelopeDecryptV2.php包含阿里云SDK V2版本（alibabacloud/kms-20160120）信封加密本地加密和解密最佳实践样例，本地加解密使用OpenSSL密码库



## 使用方法

### 一、阿里云SDK V2版本信封加密本地加解密最佳实践样例

V2版本样例基于阿里云SDK V2（Composer包：alibabacloud/kms-20160120）实现，
数据密钥采用32字节（256位）AES密钥，本地加密采用GCM模式（OpenSSL密码库），流程参考
[使用KMS信封加密在本地环境进行加解密](https://help.aliyun.com/zh/kms/key-management-service/use-cases/use-envelope-encryption)。

#### 1、加密数据

- 安装依赖（在kms-samples-php目录下）：

  ```
  composer require alibabacloud/kms-20160120
  ```

- 设置环境变量AccessKey（样例通过环境变量读取AK，请勿在代码中硬编码）：

  ```
  export ALIBABA_CLOUD_ACCESS_KEY_ID=<your access key id>
  export ALIBABA_CLOUD_ACCESS_KEY_SECRET=<your access key secret>
  ```

- 运行样例

  - 准备工作
    - 确保PHP已安装openssl扩展
    - 确保已拥有一个KMS对称密钥，修改样例中的ENDPOINT与KEY_ID常量
    - 在kms-samples-php目录下创建data文件夹
    - 准备一个明文数据文件，复制到data文件夹里，本示例假定明文数据文件名为：sales.csv

  - 打开命令行窗口，切换到项目下kms-samples-php目录，执行下面命令：

    ```
    php EnvelopeEncryptV2.php
    ```

  - 执行成功后，会在data文件夹生成密文文件：sales.csv.cipher（三行文本：数据密钥密文、IV、数据密文）

#### 2、解密数据

- 运行样例

  - 准备工作
    - 本示例需要用到加密示例生成的密文文件sales.csv.cipher，请先运行加密示例产生此文件

  - 打开命令行窗口，切换到项目下kms-samples-php目录，执行下面命令：

    ```
    php EnvelopeDecryptV2.php
    ```

  - 执行成功后，会在data文件夹生成明文文件：decrypted_sales.csv

注：

- 样例中的配置信息，如endpoint、keyId等，要根据真实信息进行修改
