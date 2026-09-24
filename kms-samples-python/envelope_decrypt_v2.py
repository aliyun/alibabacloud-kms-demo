import base64
import os

from alibabacloud_kms20160120 import models as kms_models
from alibabacloud_kms20160120.client import Client as Kms20160120Client
from alibabacloud_tea_openapi import models as open_api_models
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 如果kms实例开启公网访问，endpoint 请参考 https://api.aliyun.com/product/Kms
# 如果kms实例未开启公网访问，endpoint 请使用实例VPC地址
ENDPOINT = '<your kms endpoint>'


def create_kms_client():
    """使用阿里云SDK V2（alibabacloud_kms20160120）创建KMS Client"""
    config = open_api_models.Config(
        # 必填，请确保代码运行环境设置了环境变量 ALIBABA_CLOUD_ACCESS_KEY_ID。
        access_key_id=os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_ID'),
        # 必填，请确保代码运行环境设置了环境变量 ALIBABA_CLOUD_ACCESS_KEY_SECRET。
        access_key_secret=os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_SECRET'))
    # Endpoint 请参考 https://api.aliyun.com/product/Kms
    config.endpoint = ENDPOINT
    # 如果使用实例专属网关并且验证服务端证书，请设置ca证书。
    # 注意：Python SDK 的 config.ca 需传 CA 证书的“文件路径”（底层作为 requests 的 verify 参数使用），不是证书内容。
    # config.ca = '/path/to/kms-ca.pem'
    return Kms20160120Client(config)


def kms_decrypt(client, cipher_text_blob):
    """调用Decrypt接口解密数据密钥密文，返回数据密钥明文（Base64编码）"""
    request = kms_models.DecryptRequest(ciphertext_blob=cipher_text_blob)
    response = client.decrypt(request)
    return response.body.plaintext


def read_text_file(in_file):
    with open(in_file, 'r') as f:
        lines = [line for line in f]
    return lines


def write_text_file(out_file, content):
    with open(out_file, 'w') as f:
        f.write(content)


# 使用数据密钥明文在本地以AES-GCM模式解密数据（示例使用cryptography.hazmat密码库）
def local_decrypt(data_key, nonce, cipher_text, out_file):
    aesgcm = AESGCM(data_key)
    # 密文末尾附加了16字节GCM认证标签，decrypt时会自动校验
    data = aesgcm.decrypt(nonce, cipher_text, None)
    write_text_file(out_file, data.decode('utf-8'))


def main():
    client = create_kms_client()

    in_file = './data/sales.csv.cipher'
    out_file = './data/decrypted_sales.csv'

    # 1.读取信封文件：数据密钥密文、IV、数据密文
    in_lines = read_text_file(in_file)

    # 2.调用Decrypt接口解密数据密钥密文，得到数据密钥明文
    plain_key = kms_decrypt(client, in_lines[0])

    # 3.使用数据密钥明文在本地解密数据密文
    local_decrypt(base64.b64decode(plain_key),
                  base64.b64decode(in_lines[1]),
                  base64.b64decode(in_lines[2]),
                  out_file)


if __name__ == '__main__':
    main()
