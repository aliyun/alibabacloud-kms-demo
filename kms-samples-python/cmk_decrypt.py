import argparse
import base64
import json

from aliyunsdkcore.client import AcsClient
from aliyunsdkkms.request.v20160120 import DecryptRequest


def kms_decrypt(client, cipher_text):
    request = DecryptRequest.DecryptRequest()
    request.set_accept_format('JSON')
    request.set_CiphertextBlob(cipher_text)
    response = json.loads(client.do_action_with_exception(request))
    return response.get('Plaintext')


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

    in_file = './certs/key.pem.cipher'
    out_file = './certs/decrypted_key.pem.cipher'

    # Read encrypted key file in text mode
    in_content = read_text_file(in_file)

    # Decrypt
    cipher_text = kms_decrypt(client, in_content)

    # Write Decrypted key file in text mode
    # 这里使用base64解码是因为加密时明文进行了base64编码
    write_text_file(out_file, base64.b64decode(cipher_text).decode('utf-8'))


if __name__ == '__main__':
    main()
