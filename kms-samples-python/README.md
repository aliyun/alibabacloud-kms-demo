# KMS开放API及最佳实践多语言样例-Python实现

密钥管理服务（Key Management Service，简称KMS）提供密钥的安全托管及密码运算等服务。KMS内置密钥轮转等安全实践，支持其它云产品通过一方集成的方式对其管理的用户数据进行加密保护。借助KMS，您可以专注于数据加解密、电子签名验签等业务功能，无需花费大量成本来保障密钥的保密性、完整性和可用性。

本项目使用Python语言实现了KMS以下几个方面的使用样例：

​	1、KMS开放API使用样例

​	2、KMS主密钥在线加解密最佳实践样例

​	3、KMS信封加密本地加解密最佳实践样例

​	4、KMS非对称密钥加解密签名验签使用样例

​	5、KMS非对称密钥生成证书请求使用样例



## 项目源码组织结构

- 将项目代码下载到本地，可看到如下目录结构：

  ```
  ─code-samples
    │                         
    └─kms-samples-python
            asymmetric.py
            cmk_decrypt.py
            cmk_encrypt.py
            envelope_decrypt.py
            envelope_encrypt.py
            openapi.py
            test_openapi.py
            generate_csr.py
  ```
  

说明：

1、openapi.py和test_openapi.py包含KMS已开放接口调用样例

2、cmk_encrypt.py和cmk_decrypt.py包含KMS主密钥在线加密和解密最佳实践样例

3、envelope_encrypt.py和envelope_decrypt.py包含KMS信封加密本地加密和解密最佳实践样例

4、asymmetric.py包含了KMS非对称密钥加密、解密、签名和验签使用样例

5、generate_csr.py包含了KMS非对称密钥生成证书请求的使用样例，依赖pyOpenSSL，可通过pip3 install pyOpenSSL安装


## 使用方法

### 一、KMS开放API使用样例

([什么是Access Key](https://help.aliyun.com/document_detail/53045.html))

([API参考](https://help.aliyun.com/document_detail/69005.html))

- 运行测试代码

  打开命令行窗口，切换到项目下kms-samples-python目录，执行下面命令：

  ```
  python test_openapi.py --ak "****" --as "****"
  ```

注：

- 样例中的配置信息，如ak，as，endpoint，regionid等，要根据真实信息进行修改



### 二、KMS主密钥在线加解密最佳实践样例

#### 1、加密数据

- 运行样例

  - 准备工作
  - 确保已拥有一个KMS主密钥，本示例使用别名调用加密接口，假定主密钥别名为：alias/Apollo/WorkKey
    - 在kms-samples-python目录下创建certs文件夹
    - 准备一个明文密钥文件，复制到certs文件夹里，本示例假定明文密钥文件名为：key.pem
  
  - 打开命令行窗口，切换到ms-samples-python目录，执行下面命令：
  
  ```
  python cmk_encrypt.py --ak "****" --as "****"
  ```
  
  - 执行成功后，会在certs文件夹生成密文文件：key.pem.cipher

注：

- 样例中的配置信息，如ak，as，endpoint，regionid等，要根据真实信息进行修改



#### 2、解密数据

- 运行样例

  - 准备工作
  - 本示例需要用到加密示例生成的密文文件key.pem.cipher，请先运行加密示例产生此文件
  
- 打开命令行窗口，切换到项目下kms-samples-python目录，执行下面命令：
  
  ```
  python cmk_decrypt.py --ak "****" --as "****"
  ```
  
- 执行成功后，会在certs文件夹生成明文文件：decrypted_key.pem.cipher

注：

- 样例中的配置信息，如ak，as，endpoint，regionid等，要根据真实信息进行修改



### 三、KMS信封加密本地加解密最佳实践样例

#### 1、加密数据

- 运行样例

  - 准备工作
  - 确保已拥有一个KMS主密钥，本示例使用别名调用生成数据密钥接口，假定主密钥别名为：alias/Apollo/WorkKey
    - 在kms-samples-python目录下创建data文件夹
    - 准备一个明文数据文件，复制到data文件夹里，本示例假定明文数据文件名为：sales.csv
  
  - 打开命令行窗口，切换到项目下kms-samples-python目录，执行下面命令：
  
  ```
  python envelope_encrypt.py --ak "****" --as "****"
  ```
  
  - 执行成功后，会在data文件夹生成密文文件：sales.csv.cipher

注：

- 样例中的配置信息，如ak，as，endpoint，regionid等，要根据真实信息进行修改



#### 2、解密数据

- 运行样例

  - 准备工作
  - 本示例需要用到加密示例生成的密文文件sales.csv.cipher，请先运行加密示例产生此文件
  
  - 打开命令行窗口，切换到项目下kms-samples-python目录，执行下面命令：
  
  ```
  python envelope_decrypt.py --ak "****" --as "****"
  ```
  
  - 执行成功后，会在data文件夹生成明文文件：decrypted_sales.csv

注：

- 样例中的配置信息，如ak，as，endpoint，regionid等，要根据真实信息进行修改

