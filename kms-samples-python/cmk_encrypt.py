import argparse
import base64
import json

from aliyunsdkcore.client import AcsClient
from aliyunsdkkms.request.v20160120 import EncryptRequest


def kms_encrypt(client, plaintext, key_alias):
    request = EncryptRequest.EncryptRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_alias)
    request.set_Plaintext(plaintext)
    response = json.loads(client.do_action(request))
    return response.get('CiphertextBlob')


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

    client = AcsClient(args["ak"], args["as"], args["region"])
    # client.set_verify(False)

    key_alias = 'alias/Apollo/WorkKey'
    in_file = './certs/key.pem'
    out_file = './certs/key.pem.cipher'

    # Read private key file in text mode
    in_content = read_text_file(in_file)

    # Encrypt
    cipher_text = kms_encrypt(client, base64.b64encode(in_content.encode('utf-8')), key_alias)

    # Write encrypted key file in text mode
    write_text_file(out_file, cipher_text)


if __name__ == '__main__':
    main()
