import argparse
import base64
import hashlib
import json
import ecdsa

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Signature import pkcs1_15
from ecdsa.util import sigdecode_der

from aliyunsdkcore.client import AcsClient
from aliyunsdkkms.request.v20160120 import ListKeysRequest
from aliyunsdkkms.request.v20160120 import DescribeKeyRequest
from aliyunsdkkms.request.v20160120 import CreateKeyRequest
from aliyunsdkkms.request.v20160120 import ListKeyVersionsRequest
from aliyunsdkkms.request.v20160120 import DescribeKeyVersionRequest
from aliyunsdkkms.request.v20160120 import CreateKeyVersionRequest
from aliyunsdkkms.request.v20160120 import GetPublicKeyRequest
from aliyunsdkkms.request.v20160120 import AsymmetricEncryptRequest
from aliyunsdkkms.request.v20160120 import AsymmetricDecryptRequest
from aliyunsdkkms.request.v20160120 import AsymmetricSignRequest
from aliyunsdkkms.request.v20160120 import AsymmetricVerifyRequest


class KeyMetadata(object):
    """密钥信息"""

    def __init__(self, value):
        self.creation_date = "" if "CreationDate" not in value else value.get("CreationDate")
        self.description = "" if "Description" not in value else value.get("Description")
        self.key_id = "" if "KeyId" not in value else value.get("KeyId")
        self.key_state = "" if "KeyState" not in value else value.get("KeyState")
        self.key_usage = "" if "KeyUsage" not in value else value.get("KeyUsage")
        self.key_spec = "" if "KeySpec" not in value else value.get("KeySpec")
        self.primary_key_version = "" if "PrimaryKeyVersion" not in value else value.get("PrimaryKeyVersion")
        self.delete_date = "" if "DeleteDate" not in value else value.get("DeleteDate")
        self.creator = "" if "Creator" not in value else value.get("Creator")
        self.arn = "" if "Arn" not in value else value.get("Arn")
        self.origin = "" if "Origin" not in value else value.get("Origin")
        self.material_expire_time = "" if "MaterialExpireTime" not in value else value.get("MaterialExpireTime")
        self.protection_level = "" if "ProtectionLevel" not in value else value.get("ProtectionLevel")
        self.last_rotation_date = "" if "LastRotationDate" not in value else value.get("LastRotationDate")
        self.automatic_rotation = "" if "AutomaticRotation" not in value else value.get("AutomaticRotation")

    def get_creation_date(self):
        return self.creation_date

    def set_creation_date(self, create_date):
        self.creation_date = create_date

    def get_description(self):
        return self.description

    def set_description(self, description):
        self.description = description

    def get_key_id(self):
        return self.key_id

    def set_key_id(self, key_id):
        self.key_id = key_id

    def get_key_state(self):
        return self.key_state

    def set_key_state(self, key_state):
        self.key_state = key_state

    def get_key_usage(self):
        return self.key_usage

    def set_key_usage(self, key_usage):
        self.key_usage = key_usage

    def get_key_spec(self):
        return self.key_spec

    def set_key_spec(self, key_spec):
        self.key_spec = key_spec

    def get_primary_key_version(self):
        return self.primary_key_version

    def set_primary_key_version(self, primary_key_version):
        self.primary_key_version = primary_key_version

    def get_delete_date(self):
        return self.delete_date

    def set_delete_date(self, delete_date):
        self.delete_date = delete_date

    def get_creator(self):
        return self.creator

    def set_creator(self, creator):
        self.creator = creator

    def get_arn(self):
        return self.arn

    def set_arn(self, arn):
        self.arn = arn

    def get_origin(self):
        return self.origin

    def set_origin(self, origin):
        self.origin = origin

    def get_material_expire_time(self):
        return self.material_expire_time

    def set_material_expire_time(self, material_expire_time):
        self.material_expire_time = material_expire_time

    def get_protection_level(self):
        return self.protection_level

    def set_protection_level(self, protection_level):
        self.protection_level = protection_level

    def get_last_rotation_date(self):
        return self.last_rotation_date

    def set_last_rotation_date(self, last_rotation_date):
        self.last_rotation_date = last_rotation_date

    def get_automatic_rotation(self):
        return self.automatic_rotation

    def set_automatic_rotation(self, automatic_rotation):
        self.automatic_rotation = automatic_rotation


class ListKeysResponse(object):
    """查询密钥返回值"""

    def __init__(self, value):
        self.page_number = 0
        self.total_count = 0
        self.key_ids = []
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if ("Keys" in response) and ("Key" in response["Keys"]):
            for key in response["Keys"]["Key"]:
                if "KeyId" in key:
                    self.key_ids.append(key.get("KeyId"))
        if "PageNumber" in response:
            self.page_number = response["PageNumber"]
        if "TotalCount" in response:
            self.total_count = response["TotalCount"]
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_key_ids(self):
        return self.key_ids[:]

    def get_page_number(self):
        return self.page_number

    def get_total_count(self):
        return self.total_count

    def get_request_id(self):
        return self.request_id


class DescribeKeyResponse(object):
    """获取指定密钥相关信息返回值"""

    def __init__(self, value):
        self.key_metadata = None
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "KeyMetadata" in response:
            self.key_metadata = KeyMetadata(response["KeyMetadata"])
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_key_metadata(self):
        return self.key_metadata

    def get_request_id(self):
        return self.request_id


class CreateKeyResponse(object):
    """创建密钥返回值"""

    def __init__(self, value):
        self.key_metadata = None
        self.key_id = ""
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "KeyMetadata" in response:
            self.key_metadata = KeyMetadata(response["KeyMetadata"])
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_key_metadata(self):
        return self.key_metadata

    def get_key_id(self):
        if self.key_metadata is not None:
            self.key_id = self.key_metadata.get_key_id()
        return self.key_id

    def get_request_id(self):
        return self.request_id


class ListKeyVersionsResponse(object):
    """查询密钥版本返回值"""

    def __init__(self, value):
        self.key_version_ids = []
        self.page_number = 0
        self.total_count = 0
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if ("KeyVersions" in response) and ("KeyVersion" in response["KeyVersions"]):
            for key_version in response["KeyVersions"]["KeyVersion"]:
                if "KeyVersionId" in key_version:
                    self.key_version_ids.append(key_version.get("KeyVersionId"))
        if "TotalCount" in response:
            self.page_number = response["TotalCount"]
        if "PageNumber" in response:
            self.total_count = response["PageNumber"]
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_key_version_ids(self):
        return self.key_version_ids[:]

    def get_page_number(self):
        return self.page_number

    def get_total_count(self):
        return self.total_count

    def get_request_id(self):
        return self.request_id


class DescribeKeyVersionResponse(object):
    """获取密钥版本信息返回值"""

    def __init__(self, value):
        self.request_id = ""
        self.key_id = ""
        self.key_version_id = ""
        self.creation_date = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "KeyVersion" in response:
            if "KeyVersionId" in response["KeyVersion"]:
                self.key_version_id = response["KeyVersion"]["KeyVersionId"]
            if "KeyId" in response["KeyVersion"]:
                self.key_id = response["KeyVersion"]["KeyId"]
            if "CreationDate" in response["KeyVersion"]:
                self.creation_date = response["KeyVersion"]["CreationDate"]
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_key_id(self):
        return self.key_id

    def get_key_version_id(self):
        return self.key_version_id

    def get_creation_date(self):
        return self.creation_date

    def get_request_id(self):
        return self.request_id


class CreateKeyVersionResponse(object):
    """创建密钥版本返回值"""

    def __init__(self, value):
        self.request_id = ""
        self.key_id = ""
        self.key_version_id = ""
        self.creation_date = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]
        if "KeyVersion" in response:
            if "KeyVersionId" in response["KeyVersion"]:
                self.key_version_id = response["KeyVersion"]["KeyVersionId"]
            if "KeyId" in response["KeyVersion"]:
                self.key_id = response["KeyVersion"]["KeyId"]
            if "CreationDate" in response["KeyVersion"]:
                self.creation_date = response["KeyVersion"]["CreationDate"]

    def get_request_id(self):
        return self.request_id

    def get_key_id(self):
        return self.key_id

    def get_key_version_id(self):
        return self.key_version_id

    def get_creation_date(self):
        return self.creation_date


class GetPublicKeyResponse(object):
    """获取公钥信息返回值"""

    def __init__(self, value):
        self.request_id = ""
        self.public_key = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]
        if "PublicKey" in response:
            self.public_key = response["PublicKey"]

    def get_request_id(self):
        return self.request_id

    def get_public_key(self):
        return self.public_key


class AsymmetricEncryptResponse(object):
    """非对称密钥加密返回值"""

    def __init__(self, value):
        self.request_id = ""
        self.key_id = ""
        self.key_version_id = ""
        self.cipher_text_blob = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]
        if "KeyId" in response:
            self.key_id = response["KeyId"]
        if "KeyVersionId" in response:
            self.key_version_id = response["KeyVersionId"]
        if "CiphertextBlob" in response:
            self.cipher_text_blob = response["CiphertextBlob"]

    def get_request_id(self):
        return self.request_id

    def get_key_id(self):
        return self.key_id

    def get_key_version_id(self):
        return self.key_version_id

    def get_cipher_text_blob(self):
        return self.cipher_text_blob


class AsymmetricDecryptResponse(object):
    """非对称密钥解密返回值"""

    def __init__(self, value):
        self.request_id = ""
        self.key_id = ""
        self.key_version_id = ""
        self.plain_text = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]
        if "KeyId" in response:
            self.key_id = response["KeyId"]
        if "KeyVersionId" in response:
            self.key_version_id = response["KeyVersionId"]
        if "Plaintext" in response:
            self.plain_text = response["Plaintext"]

    def get_request_id(self):
        return self.request_id

    def get_key_id(self):
        return self.key_id

    def get_key_version_id(self):
        return self.key_version_id

    def get_plain_text(self):
        return self.plain_text


class AsymmetricSignResponse(object):
    """非对称密钥签名返回值"""

    def __init__(self, value):
        self.request_id = ""
        self.key_id = ""
        self.key_version_id = ""
        self.value = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]
        if "KeyId" in response:
            self.key_id = response["KeyId"]
        if "KeyVersionId" in response:
            self.key_version_id = response["KeyVersionId"]
        if "Value" in response:
            self.value = response["Value"]

    def get_request_id(self):
        return self.request_id

    def get_key_id(self):
        return self.key_id

    def get_key_version_id(self):
        return self.key_version_id

    def get_value(self):
        return self.value


class AsymmetricVerifyResponse(object):
    """非对称密钥验签返回值"""

    def __init__(self, value):
        self.request_id = ""
        self.key_id = ""
        self.key_version_id = ""
        self.value = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]
        if "KeyId" in response:
            self.key_id = response["KeyId"]
        if "KeyVersionId" in response:
            self.key_version_id = response["KeyVersionId"]
        if "Value" in response:
            self.value = response["Value"]

    def get_request_id(self):
        return self.request_id

    def get_key_id(self):
        return self.key_id

    def get_key_version_id(self):
        return self.key_version_id

    def get_value(self):
        return self.value


def list_keys(acs_client):
    key_ids = []
    page_number = "1"
    page_size = "10"
    while True:
        request = ListKeysRequest.ListKeysRequest()
        request.set_accept_format('JSON')
        request.set_PageNumber(page_number)
        request.set_PageSize(page_size)
        response = ListKeysResponse(acs_client.do_action_with_exception(request))
        key_ids[len(key_ids):len(key_ids)] = response.get_key_ids()
        if response.get_page_number() * 10 >= response.get_total_count():
            break
        page_number = str(response.get_page_number() + 1)
    return key_ids


def describe_key(acs_client, key_id):
    request = DescribeKeyRequest.DescribeKeyRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    return DescribeKeyResponse(acs_client.do_action_with_exception(request))


def create_key(acs_client, key_spec, key_usage):
    request = CreateKeyRequest.CreateKeyRequest()
    request.set_accept_format('JSON')
    request.set_KeyUsage(key_usage)
    request.set_KeySpec(key_spec)
    response = CreateKeyResponse(acs_client.do_action_with_exception(request))
    return response.get_key_id()


def list_key_versions(acs_client, key_id):
    key_version_ids = []
    page_number = "1"
    page_size = "10"
    while True:
        request = ListKeyVersionsRequest.ListKeyVersionsRequest()
        request.set_accept_format('JSON')
        request.set_KeyId(key_id)
        request.set_PageNumber(page_number)
        request.set_PageSize(page_size)
        response = ListKeyVersionsResponse(acs_client.do_action_with_exception(request))
        key_version_ids[len(key_version_ids):] = response.get_key_version_ids()
        if response.get_page_number() * 10 >= response.get_total_count():
            break
        page_number = str(response.get_page_number() + 1)
    return key_version_ids


def describe_key_version(acs_client, key_id, key_version_id):
    request = DescribeKeyVersionRequest.DescribeKeyVersionRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    request.set_KeyVersionId(key_version_id)
    return DescribeKeyVersionResponse(acs_client.do_action_with_exception(request))


def create_key_version(acs_client, key_id):
    request = CreateKeyVersionRequest.CreateKeyVersionRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    return CreateKeyVersionResponse(acs_client.do_action_with_exception(request))


def get_public_key(acs_client, key_id, key_version_id):
    request = GetPublicKeyRequest.GetPublicKeyRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    request.set_KeyVersionId(key_version_id)
    response = GetPublicKeyResponse(acs_client.do_action_with_exception(request))
    return response.get_public_key()


def asymmetric_encrypt(acs_client, key_id, key_version_id, message, algorithm):
    request = AsymmetricEncryptRequest.AsymmetricEncryptRequest()
    request.set_accept_format('JSON')
    # message要进行base64编码
    plain_text = base64.b64encode(message.encode('utf-8'))
    request.set_KeyId(key_id)
    request.set_KeyVersionId(key_version_id)
    request.set_Plaintext(plain_text)
    request.set_Algorithm(algorithm)
    response = AsymmetricEncryptResponse(acs_client.do_action_with_exception(request))
    # 密文要进行base64解码
    return base64.b64decode(response.get_cipher_text_blob())


def asymmetric_decrypt(acs_client, key_id, key_version_id, cipher_blob, algorithm):
    request = AsymmetricDecryptRequest.AsymmetricDecryptRequest()
    request.set_accept_format('JSON')
    # cipher_blob要进行base64编码
    cipher_text = base64.b64encode(cipher_blob)
    request.set_KeyId(key_id)
    request.set_KeyVersionId(key_version_id)
    request.set_CiphertextBlob(cipher_text)
    request.set_Algorithm(algorithm)
    response = AsymmetricDecryptResponse(acs_client.do_action_with_exception(request))
    # 明文要进行base64解码
    return base64.b64decode(response.get_plain_text())


def asymmetric_sign(acs_client, key_id, key_version_id, message, algorithm):
    request = AsymmetricSignRequest.AsymmetricSignRequest()
    request.set_accept_format('JSON')
    # 计算消息摘要(SHA-256)
    h = SHA256.new()
    h.update(message.encode('utf-8'))
    digest = base64.b64encode(h.digest())
    request.set_KeyId(key_id)
    request.set_KeyVersionId(key_version_id)
    request.set_Digest(digest)
    request.set_Algorithm(algorithm)
    response = AsymmetricSignResponse(acs_client.do_action_with_exception(request))
    # 签名要进行base64解码
    return base64.b64decode(response.get_value())


def asymmetric_verify(acs_client, key_id, key_version_id, message, signature, algorithm):
    request = AsymmetricVerifyRequest.AsymmetricVerifyRequest()
    request.set_accept_format('JSON')
    # 计算消息摘要(SHA-256)
    h = SHA256.new()
    h.update(message.encode('utf-8'))
    digest = base64.b64encode(h.digest())
    value = base64.b64encode(signature)
    request.set_KeyId(key_id)
    request.set_KeyVersionId(key_version_id)
    request.set_Digest(digest)
    request.set_Value(value)
    request.set_Algorithm(algorithm)
    response = AsymmetricVerifyResponse(acs_client.do_action_with_exception(request))
    return response.get_value()


def rsa_encrypt(acs_client, key_id, key_version_id, message, algorithm):
    pub_key_pem = get_public_key(acs_client, key_id, key_version_id)
    rsa_pub = RSA.importKey(pub_key_pem)

    if algorithm == 'RSAES_OAEP_SHA_1':
        cipher = PKCS1_OAEP.new(rsa_pub)
        return cipher.encrypt(message.encode('utf-8'))
    elif algorithm == 'RSAES_OAEP_SHA_256':
        cipher = PKCS1_OAEP.new(key=rsa_pub, hashAlgo=SHA256)
        return cipher.encrypt(message.encode('utf-8'))
    else:
        return ''


def rsa_verify(acs_client, key_id, key_version_id, message, signature, algorithm):
    pub_key_pem = get_public_key(acs_client, key_id, key_version_id)
    rsa_pub = RSA.importKey(pub_key_pem)

    if algorithm == 'RSA_PSS_SHA_256':
        try:
            verifier = pss.new(rsa_pub)
            verifier.verify(SHA256.new(message.encode('utf-8')), signature)
        except (ValueError, TypeError):
            return False
    elif algorithm == 'RSA_PKCS1_SHA_256':
        try:
            verifier = pkcs1_15.new(rsa_pub)
            verifier.verify(SHA256.new(message.encode('utf-8')), signature)
        except (ValueError, TypeError):
            return False
    else:
        return False
    return True


def ecdsa_verify(acs_client, key_id, key_version_id, message, signature):
    pub_key_pem = get_public_key(acs_client, key_id, key_version_id)
    verifier = ecdsa.VerifyingKey.from_pem(pub_key_pem)
    return verifier.verify(signature, message.encode('utf-8'), hashfunc=hashlib.sha256, sigdecode=sigdecode_der)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ak', help='the access key id')
    parser.add_argument('--as', help='the access key secret')
    parser.add_argument('--region', default='cn-hangzhou', help='the region id')
    args = vars(parser.parse_args())

    client = AcsClient(args["ak"], args["as"], args["region"])

    key_ids = list_keys(client)
    for key_id in key_ids:
        res = describe_key(client, key_id)
        key_metadata = res.get_key_metadata()
        key_id = key_metadata.get_key_id()
        key_version_ids = list_key_versions(client, key_id)
        if not key_metadata.get_key_spec() == 'Aliyun_AES_256':
            public_key = get_public_key(client, key_id, key_version_ids[0])
            print(public_key)

    key_id = 'a8c6eb76-278c-4f88-801b-8fb56e4c3019'
    key_version_id = '6f050e56-9b71-41db-8d48-5275855f1041'

    message = '测试消息'
    cipher_blob = asymmetric_encrypt(client, key_id, key_version_id, message, 'RSAES_OAEP_SHA_256')
    print(cipher_blob)

    plain_text = asymmetric_decrypt(client, key_id, key_version_id, cipher_blob, 'RSAES_OAEP_SHA_256')
    print(plain_text.decode())

    cipher_text = rsa_encrypt(client, key_id, key_version_id, message, 'RSAES_OAEP_SHA_256')
    print(cipher_text)

    plain_text = asymmetric_decrypt(client, key_id, key_version_id, cipher_blob, 'RSAES_OAEP_SHA_256')
    print(plain_text.decode())

    key_id = 'bb974925-d7d2-48c3-b896-cb2a3f3f33bd'
    key_version_id = 'd4229c1f-17ec-40df-bfe0-51667c6c78b6'

    sign = asymmetric_sign(client, key_id, key_version_id, message, 'RSA_PKCS1_SHA_256')
    print(sign)

    value = asymmetric_verify(client, key_id, key_version_id, message, sign, 'RSA_PKCS1_SHA_256')
    if value:
        print('verify success.')
    else:
        print('verify failed.')

    value = rsa_verify(client, key_id, key_version_id, message, sign, 'RSA_PKCS1_SHA_256')
    if value:
        print('verify success.')
    else:
        print('verify failed.')

    key_id = '71032ff8-1803-426f-b5be-c57bdeee1080'
    key_version_id = '529eb3e1-6ef5-4a47-bce4-4c86494ebc1c'

    sign = asymmetric_sign(client, key_id, key_version_id, message, 'ECDSA_SHA_256')
    print(sign)
    value = ecdsa_verify(client, key_id, key_version_id, message, sign)
    if value:
        print('verify success.')
    else:
        print('verify failed.')


if __name__ == '__main__':
    main()
