import argparse
import base64

from Crypto.Cipher import AES
from alibabacloud_kms20160120.client import Client
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_kms20160120.models import DecryptRequest


def kms_decrypt(client, cipher_text):
    request = DecryptRequest()
    request.ciphertext_blob = cipher_text
    response = client.decrypt(request)
    return response.body.plaintext


def read_text_file(in_file):
    with open(in_file, 'r') as f:
        lines = []
        for line in f:
            lines.append(line)
    return lines


def write_text_file(out_file, content):
    with open(out_file, 'w') as f:
        f.write(content)


def local_decrypt(data_key, iv, cipher_text, tag, out_file):
    cipher = AES.new(data_key, AES.MODE_GCM, iv)
    data = cipher.decrypt_and_verify(cipher_text, tag)
    write_text_file(out_file, data.decode('utf-8'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ak', help='the access key id')
    parser.add_argument('--as', help='the access key secret')
    parser.add_argument('--endpoint', default='kms.cn-hangzhou.aliyuncs.com', help='the endpoint id')
    args = vars(parser.parse_args())
    config = open_api_models.Config(
        access_key_id=args["ak"],
        access_key_secret=args["as"]
    )
    config.endpoint = args["endpoint"]
    client = Client(config)

    in_file = './data/sales.csv.cipher'
    out_file = './data/decrypted_sales.csv'

    # Read encrypted file
    in_lines = read_text_file(in_file)

    # Decrypt data key
    data_key = kms_decrypt(client, in_lines[0])

    # Locally decrypt the sales record
    local_decrypt(base64.b64decode(data_key),
                  base64.b64decode(in_lines[1]),
                  base64.b64decode(in_lines[2]),
                  base64.b64decode(in_lines[3]),
                  out_file)


if __name__ == '__main__':
    main()
