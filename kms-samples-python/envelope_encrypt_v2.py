import base64
import os

from alibabacloud_kms20160120 import models as kms_models
from alibabacloud_kms20160120.client import Client as Kms20160120Client
from alibabacloud_tea_openapi import models as open_api_models
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 如果kms实例开启公网访问，endpoint 请参考 https://api.aliyun.com/product/Kms
# 如果kms实例未开启公网访问，endpoint 请使用实例VPC地址
ENDPOINT = '<your kms endpoint>'
# 填写您在KMS创建的对称主密钥Id，也可以使用密钥别名（如alias/Example）
KEY_ID = '<your cmk id>'
# 数据密钥长度，32字节（256位）AES密钥
NUMBER_OF_BYTES = 32
# GCM模式初始向量长度
GCM_NONCE_LENGTH = 12


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


def kms_generate_data_key(client, key_id):
    """调用GenerateDataKey接口生成数据密钥，返回数据密钥明文与密文（均为Base64编码）"""
    request = kms_models.GenerateDataKeyRequest(
        key_id=key_id,
        number_of_bytes=NUMBER_OF_BYTES)
    response = client.generate_data_key(request)
    return response.body.plaintext, response.body.ciphertext_blob


def read_text_file(in_file):
    with open(in_file, 'r') as f:
        content = f.read()
    return content


def write_text_file(out_file, lines):
    with open(out_file, 'w') as f:
        for line in lines:
            f.write(line)
            f.write('\n')


# 使用数据密钥明文在本地以AES-GCM模式加密数据（示例使用cryptography.hazmat密码库）。
# 加密完成后数据密钥明文应立即销毁，仅持久化数据密钥密文（信封）。
#
# Out file format (text)
# Line 1: b64 encoded encrypted data key (envelope)
# Line 2: b64 encoded IV
# Line 3: b64 encoded cipher text (GCM authentication tag appended)
def local_encrypt(plain_key, encrypted_key, in_file, out_file):
    key = base64.b64decode(plain_key)
    aesgcm = AESGCM(key)
    nonce = os.urandom(GCM_NONCE_LENGTH)

    in_content = read_text_file(in_file)
    # encrypt返回的密文已附加16字节GCM认证标签
    cipher_text = aesgcm.encrypt(nonce, in_content.encode('utf-8'), None)

    lines = [encrypted_key,
             base64.b64encode(nonce).decode('utf-8'),
             base64.b64encode(cipher_text).decode('utf-8')]
    write_text_file(out_file, lines)


def main():
    client = create_kms_client()

    in_file = './data/sales.csv'
    out_file = './data/sales.csv.cipher'

    # 1.调用GenerateDataKey接口生成数据密钥
    plain_key, cipher_blob_key = kms_generate_data_key(client, KEY_ID)

    # 2.使用数据密钥明文在本地加密数据，数据密钥密文作为信封与数据密文一起保存
    local_encrypt(plain_key, cipher_blob_key, in_file, out_file)


if __name__ == '__main__':
    main()
