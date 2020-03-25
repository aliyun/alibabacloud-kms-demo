import argparse
import base64
import json

from Crypto.Cipher import AES
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
    parser.add_argument('--region', default='cn-hangzhou', help='the region id')
    args = vars(parser.parse_args())

    client = AcsClient(args["ak"], args["as"], args["region"])
    # client.set_verify(False)

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
