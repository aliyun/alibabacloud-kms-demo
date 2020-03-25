import argparse
import base64
import json

from Crypto.Cipher import AES
from aliyunsdkcore.client import AcsClient
from aliyunsdkkms.request.v20160120 import GenerateDataKeyRequest


def kms_generate_data_key(client, key_alias):
    request = GenerateDataKeyRequest.GenerateDataKeyRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_alias)
    request.set_NumberOfBytes(32)
    response = json.loads(client.do_action_with_exception(request))
    plaintext = response.get('Plaintext')
    cipher_text = response.get('CiphertextBlob')
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
    parser.add_argument('--region', default='cn-hangzhou', help='the region id')
    args = vars(parser.parse_args())

    client = AcsClient(args["ak"], args["as"], args["region"])
    # client.set_verify(False)

    key_alias = 'alias/Apollo/WorkKey'
    in_file = './data/sales.csv'
    out_file = './data/sales.csv.cipher'

    # Generate Data Key
    data_key = kms_generate_data_key(client, key_alias)

    # Locally Encrypt the sales record
    local_encrypt(data_key[0], data_key[1], in_file, out_file)


if __name__ == '__main__':
    main()
