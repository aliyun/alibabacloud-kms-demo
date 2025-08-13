import argparse
import base64

from Crypto.Cipher import AES
from alibabacloud_kms20160120.client import Client
from alibabacloud_kms20160120.models import GenerateDataKeyRequest
from alibabacloud_tea_openapi import models as open_api_models


def kms_generate_data_key(client, key_alias):
    request = GenerateDataKeyRequest()
    request.key_id = key_alias
    request.number_of_bytes = 32
    response = client.generate_data_key(request)
    plaintext = response.body.plaintext
    cipher_text = response.body.ciphertext_blob
    return plaintext, cipher_text


def read_text_file(in_file):
    with open(in_file, 'r') as f:
        content = f.read()
    return content


def write_text_file(out_file, lines):
    with open(out_file, 'w') as f:
        for line in lines:
            f.write(line)
            f.write('\n')


# Out file format (text)
# Line 1: b64 encoded data key
# Line 2: b64 encoded IV
# Line 3: b64 encoded cipher text
# Line 4: b64 encoded authentication tag
def local_encrypt(plain_key, encrypted_key, in_file, out_file):
    key = base64.b64decode(plain_key)
    cipher = AES.new(key, mode=AES.MODE_GCM)

    in_content = read_text_file(in_file)
    cipher_text, tag = cipher.encrypt_and_digest(in_content.encode('utf-8'))

    lines = [encrypted_key, base64.b64encode(cipher.nonce).decode('utf-8'),
             base64.b64encode(cipher_text).decode('utf-8'), base64.b64encode(tag).decode('utf-8')]
    write_text_file(out_file, lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ak', help='the access key id')
    parser.add_argument('--as', help='the access key secret')
    parser.add_argument('--endpoint', default='kms.cn-hangzhou.aliyuncs.com', help='the endpoint')
    args = vars(parser.parse_args())
    config = open_api_models.Config(
        access_key_id=args["ak"],
        access_key_secret=args["as"]
    )
    config.endpoint = args["endpoint"]
    client = Client(config)

    key_alias = 'alias/Apollo/WorkKey'
    in_file = './data/sales.csv'
    out_file = './data/sales.csv.cipher'

    # Generate Data Key
    data_key = kms_generate_data_key(client, key_alias)
    # Locally Encrypt the sales record
    local_encrypt(data_key[0], data_key[1], in_file, out_file)


if __name__ == '__main__':
    main()
