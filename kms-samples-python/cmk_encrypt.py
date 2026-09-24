import argparse
import base64

from alibabacloud_kms20160120.client import Client
from alibabacloud_kms20160120.models import EncryptRequest
from alibabacloud_tea_openapi.models import Config


def kms_encrypt(client, plaintext, key_alias):
    request = EncryptRequest(key_id=key_alias, plaintext=plaintext)
    response = client.encrypt(request)
    return response.body.ciphertext_blob


def read_text_file(in_file):
    with open(in_file, 'r') as f:
        content = f.read()
    return content


def write_text_file(out_file, content):
    with open(out_file, 'w') as f:
        f.write(content)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ak', help='the access key id')
    parser.add_argument('--as', help='the access key secret')
    parser.add_argument('--region', default='cn-hangzhou', help='the region id')
    args = vars(parser.parse_args())

    config = Config(
        access_key_id=args["ak"],
        access_key_secret=args["as"],
        endpoint=f'kms.{args["region"]}.aliyuncs.com'
    )
    client = Client(config)

    key_alias = 'alias/Apollo/WorkKey'
    in_file = './certs/key.pem'
    out_file = './certs/key.pem.cipher'

    # Read private key file in text mode
    in_content = read_text_file(in_file)

    # Encrypt
    cipher_text = kms_encrypt(client, base64.b64encode(in_content.encode('utf-8')).decode(), key_alias)

    # Write encrypted key file in text mode
    write_text_file(out_file, cipher_text)


if __name__ == '__main__':
    main()
