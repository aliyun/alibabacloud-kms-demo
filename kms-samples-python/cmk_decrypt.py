import argparse
import base64

from alibabacloud_kms20160120.client import Client
from alibabacloud_kms20160120.models import DecryptRequest
from alibabacloud_tea_openapi.models import Config


def kms_decrypt(client, ciphertext_blob):
    request = DecryptRequest(ciphertext_blob=ciphertext_blob)
    response = client.decrypt(request)
    return response.body.plaintext


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

    in_file = './certs/key.pem.cipher'
    out_file = './certs/decrypted_key.pem'

    # Read encrypted key file in text mode
    in_content = read_text_file(in_file)

    # Decrypt
    plaintext_b64 = kms_decrypt(client, in_content)

    # Decode base64 (since encrypt sample base64-encodes before encrypting)
    write_text_file(out_file, base64.b64decode(plaintext_b64).decode('utf-8'))


if __name__ == '__main__':
    main()
