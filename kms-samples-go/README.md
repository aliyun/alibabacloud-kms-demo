# KMS开放API及最佳实践多语言样例-Go实现

密钥管理服务（Key Management Service，简称KMS）提供密钥的安全托管及密码运算等服务。KMS内置密钥轮转等安全实践，支持其它云产品通过一方集成的方式对其管理的用户数据进行加密保护。借助KMS，您可以专注于数据加解密、电子签名验签等业务功能，无需花费大量成本来保障密钥的保密性、完整性和可用性。

本项目使用Go语言实现了KMS以下几个方面的使用样例：

​	1、KMS开放API使用样例

​	2、KMS主密钥在线加解密最佳实践样例

​	3、KMS信封加密本地加解密最佳实践样例

​	4、KMS非对称密钥加解密签名验签使用样例



## 项目源码组织结构

- 将项目代码下载到本地，可看到如下目录结构：

  ```
  ─code-samples
    ├─kms-samples-go
       ├─asymmetric_ecdsa_p256_samples
       ├─asymmetric_ecdsa_p256k_samples
       ├─asymmetric_rsaes_samples
       ├─asymmetric_rsassa_samples
       ├─cmk_decrypt_best_practices
       ├─cmk_encrypt_best_practices
       ├─envelope_decrypt_best_practices
       ├─envelope_encrypt_best_practices
       └─kms_api_samples
  ```
  

说明：

1、kms_api_samples目录包含KMS已开放接口调用样例

2、cmk_encrypt_best_practices和cmk_decrypt_best_practices目录包含KMS主密钥在线加密和解密最佳实践样例

3、envelope_encrypt_best_practices和envelope_decrypt_best_practices目录包含KMS信封加密本地加密和解密最佳实践样例

4、asymmetric_ecdsa_p256_samples、asymmetric_ecdsa_p256k_samples、asymmetric_rsaes_samples和asymmetric_rsassa_samples包含了KMS非对称密钥加密、解密、签名和验签使用样例



## 使用方法

### 一、KMS开放API使用样例

([什么是Access Key](https://help.aliyun.com/document_detail/53045.html))

([API参考](https://help.aliyun.com/document_detail/69005.html))

- 设置Access Key Id和Access Key Secret

  打开命令行窗口，切换到kms_api_samples目录，执行下面命令：

  ```
  set AccessKeyId="ak"
  set AccessKeySecret="as"
  ```

- 运行测试代码

  ```
  go test .
  ```

注：

- 样例中的配置信息，如ak，as，endpoint，regionid等，要根据真实信息进行修改



### 二、KMS主密钥在线加解密最佳实践样例

#### 1、加密数据

- 设置Access Key Id和Access Key Secret

  打开命令行窗口，切换到cmk_encrypt_best_practices目录，执行下面命令：

  ```
  set AccessKeyId="ak"
  set AccessKeySecret="as"
  ```

- 运行样例

  - 准备工作
    - 确保已拥有一个KMS主密钥，本示例使用别名调用加密接口，假定主密钥别名为：alias/Apollo/WorkKey
    - 在cmk_encrypt_best_practices目录下创建certs文件夹
    - 准备一个明文密钥文件，复制到certs文件夹里，本示例假定明文密钥文件名为：key.pem
  
  - 在打开的命令行窗口执行下面命令进行加密：
  
  ```
  go run cmk_encrypt.go
  ```
  
  - 执行成功后，会在certs文件夹生成密文文件：key.pem.cipher

#### 2、解密数据

- 设置Access Key Id和Access Key Secret

  打开命令行窗口，切换到cmk_decrypt_best_practices目录，执行下面命令：

  ```
  set AccessKeyId="ak"
  set AccessKeySecret="as"
  ```

- 运行样例

  - 准备工作
    - 在cmk_decrypt_best_practices目录下创建certs文件夹
    - 将加密示例生成的密文文件key.pem.cipher复制到certs文件夹
  
  - 在打开的命令行窗口执行下面命令进行解密：
  
  ```
  go run cmk_decrypt.go
  ```
  
  - 执行成功后，会在certs文件夹生成明文文件：decrypted_key.pem.cipher

注：

- 样例中的配置信息，如ak，as，endpoint，regionid等，要根据真实信息进行修改



### 三、KMS信封加密本地加解密最佳实践样例

#### 1、加密数据

- 设置Access Key Id和Access Key Secret

  打开命令行窗口，切换到envelope_encrypt_best_practices目录，执行下面命令：

  ```
  set AccessKeyId="ak"
  set AccessKeySecret="as"
  ```

- 运行样例

  - 准备工作
    - 确保已拥有一个KMS主密钥，本示例使用别名调用生成数据密钥接口，假定主密钥别名为：alias/Apollo/WorkKey
    - 在envelope_encrypt_best_practices目录下创建data文件夹
    - 准备一个明文数据文件，复制到data文件夹里，本示例假定明文数据文件名为：sales.csv
  
  - 在打开的命令行窗口执行下面命令进行加密：
  
  ```
  go run envelope_encrypt.go
  ```
  
  - 执行成功后，会在data文件夹生成密文文件：sales.csv.cipher

#### 2、解密数据

- 设置Access Key Id和Access Key Secret

  打开命令行窗口，切换到envelope_decrypt_best_practices目录，执行下面命令：

  ```
  set AccessKeyId="ak"
  set AccessKeySecret="as"
  ```

- 运行样例

  - 准备工作
    - 在envelope_decrypt_best_practices目录下创建data文件夹
    - 将加密示例生成的密文文件sales.csv.cipher复制到data文件夹
  
  - 在打开的命令行窗口执行下面命令进行解密：
  
  ```
  go run envelope_decrypt.go
  ```
  
  - 执行成功后，会在data文件夹生成明文文件：decrypted_sales.csv

注：

- 样例中的配置信息，如ak，as，endpoint，regionid等，要根据真实信息进行修改

