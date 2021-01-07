import base64
import json

from OpenSSL.crypto import load_publickey, X509Extension
from OpenSSL.crypto import FILETYPE_PEM
from OpenSSL.crypto import X509Req
from OpenSSL.crypto import dump_certificate_request

from OpenSSL._util import (
    ffi as _ffi,
    lib as _lib,
)
from aliyunsdkcore.client import AcsClient
from aliyunsdkkms.request.v20160120.AsymmetricSignRequest import AsymmetricSignRequest
from aliyunsdkkms.request.v20160120.CreateKeyRequest import CreateKeyRequest
from aliyunsdkkms.request.v20160120.GetPublicKeyRequest import GetPublicKeyRequest
from aliyunsdkkms.request.v20160120.ListKeyVersionsRequest import ListKeyVersionsRequest


class KeyMetadata(object):
    """密钥信息类"""

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
        self.rotation_interval = "" if "RotationInterval" not in value else value.get("RotationInterval")

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

    def get_rotation_interval(self):
        return self.rotation_interval

    def set_rotation_interval(self, rotation_interval):
        self.rotation_interval = rotation_interval


class CreateKeyResponse(object):
    """创建密钥返回值类"""

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
    """查询密钥版本返回值类"""

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


class GetPublicKeyResponse(object):
    """获取公钥信息返回值类"""

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


class AsymmetricSignResponse(object):
    """非对称密钥签名返回值类"""

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


def create_key(client, key_spec, key_usage):
    request = CreateKeyRequest()
    request.set_accept_format('JSON')
    request.set_KeyUsage(key_usage)
    request.set_KeySpec(key_spec)
    response = CreateKeyResponse(client.do_action_with_exception(request))
    return response.get_key_id()


def list_key_versions(client, key_id):
    key_version_ids = []
    page_number = "1"
    page_size = "10"
    while True:
        request = ListKeyVersionsRequest()
        request.set_accept_format('json')
        request.set_KeyId(key_id)
        request.set_PageNumber(page_number)
        request.set_PageSize(page_size)
        response = ListKeyVersionsResponse(client.do_action_with_exception(request))
        key_version_ids[len(key_version_ids):] = response.get_key_version_ids()
        if response.get_page_number() * 10 >= response.get_total_count():
            break
        page_number = str(response.get_page_number() + 1)
    return key_version_ids


def get_public_key(client, key_id, key_version_id):
    request = GetPublicKeyRequest()
    request.set_accept_format('JSON')
    request.set_KeyVersionId(key_version_id)
    request.set_KeyId(key_id)

    response = client.do_action_with_exception(request)
    return GetPublicKeyResponse(str(response, encoding='utf-8')).get_public_key()


def get_csr(client, key_id, key_version_id, subject_name, domain, kms_algorithm, signature_algorithm):
    clear_text_public_key_pem = get_public_key(client, key_id, key_version_id)

    # kms get_public_key
    pkey = load_publickey(FILETYPE_PEM, clear_text_public_key_pem)

    req = X509Req()
    req.set_pubkey(pkey)

    req.get_subject().CN = subject_name.get('CN')
    req.get_subject().C = subject_name.get('C')
    req.get_subject().O = subject_name.get('O')
    req.set_version(0)
    # addExtensions
    req.add_extensions([
        X509Extension(b'subjectAltName', False, ','.join(domain).encode('ascii'))
    ])

    result_buffer = _ffi.new('unsigned char**')
    encode_result = _lib.i2d_re_X509_REQ_tbs(req._req, result_buffer)

    md_length = _ffi.new("unsigned int *")
    md = _ffi.new("unsigned char[]", 32)
    evp_md = _lib.EVP_get_digestbyname(b"sha256")

    md_ctx = _lib.Cryptography_EVP_MD_CTX_new()
    md_ctx = _ffi.gc(md_ctx, _lib.Cryptography_EVP_MD_CTX_free)
    _lib.EVP_DigestInit_ex(md_ctx, evp_md, _ffi.NULL)
    _lib.EVP_DigestUpdate(md_ctx, result_buffer[0], encode_result)
    _lib.EVP_DigestFinal_ex(md_ctx, md, md_length)

    psig = _ffi.new("ASN1_BIT_STRING **")
    palg = _ffi.new("X509_ALGOR **")
    _lib.X509_REQ_get0_signature(req._req, psig, palg)

    # kms_sign
    sign_data = kms_sign(client, key_id, key_version_id, kms_algorithm, bytes(md))

    _lib.ASN1_STRING_set(psig[0], sign_data, len(sign_data))
    psig[0].flags &= ~(0x08 | 0x07)
    psig[0].flags |= 0x08

    _lib.OPENSSL_free(result_buffer[0])

    palg[0].algorithm = _lib.OBJ_nid2obj(_lib.OBJ_sn2nid(signature_algorithm))

    csr_pem_str = dump_certificate_request(FILETYPE_PEM, req)
    return csr_pem_str


def write_text_file(out_file, csr):
    with open(out_file, 'wb+') as f:
        f.write(csr)


def kms_sign(client, key_id, key_version_id, kms_algorithm, digest):
    request = AsymmetricSignRequest()
    request.set_accept_format('JSON')
    request.set_Algorithm(kms_algorithm)
    request.set_Digest(base64.b64encode(digest))
    request.set_KeyId(key_id)
    request.set_KeyVersionId(key_version_id)
    response = AsymmetricSignResponse(client.do_action_with_exception(request))
    return base64.b64decode(response.get_value())


def ecc_csr_main(client):
    try:
        key_spec = "EC_P256"
        key_usage = "SIGN/VERIFY"
        # 创建KMS ECC非对称密钥（EC_P256，SIGN/VERIFY）
        key_id = create_key(client, key_spec, key_usage)

        # 获取非对称密钥密钥版本ID
        key_version_list = list_key_versions(client, key_id)
        key_version_id = key_version_list[0]
        subject_name = dict(CN='Test Certificate Request', O='Aliyun KMS', C='CN')
        kms_algorithm = "ECDSA_SHA_256"
        signature_algorithm = b"ecdsa-with-SHA256"  # b"RSA-SHA256" b"RSASSA-PSS"
        out_file = "./test.csr"
        domain = ["DNS:test.com", "DNS:*.test.cn"]

        # getCSR
        csr = get_csr(client, key_id, key_version_id, subject_name, domain, kms_algorithm, signature_algorithm)
        # write
        write_text_file(out_file, csr)
    except IOError:
        print("Create ECC CSR Failed")
    else:
        print("Create ECC CSR SUCCESS")


def rsa_csr_main(client):
    try:
        key_spec = "RSA_2048"
        key_usage = "SIGN/VERIFY"

        # 创建KMS RSA非对称密钥（RSA_2048，SIGN/VERIFY）
        key_id = create_key(client, key_spec, key_usage)

        # 获取非对称密钥密钥版本ID
        key_version_list = list_key_versions(client, key_id)
        key_version_id = key_version_list[0]
        subject_name = dict(CN='Test Certificate Request', O='Aliyun KMS', C='CN')
        kms_algorithm = "RSA_PKCS1_SHA_256"
        signature_algorithm = b"RSA-SHA256"  # b"ecdsa-with-SHA256" b"RSASSA-PSS"
        out_file = "./test.csr"
        domain = ["DNS:test.com", "DNS:*.test.cn"]
        # getCSR
        csr = get_csr(client, key_id, key_version_id, subject_name, domain, kms_algorithm, signature_algorithm)
        # write
        write_text_file(out_file, csr)
    except IOError:
        print("Create RSA CSR Failed")
    else:
        print("Create RSA CSR SUCCESS")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ak', help='the access key id')
    parser.add_argument('--as', help='the access key secret')
    parser.add_argument('--region', default='cn-hangzhou', help='the region id')
    args = vars(parser.parse_args())

    client = AcsClient(args["ak"], args["as"], args["region"])
    # your accessKeyId accessKeySecret regionId
    #client = AcsClient('<AccessKeyId>', '<AccessKeySecret>', 'cn-hangzhou')

    #ecc_csr_main(client)
    rsa_csr_main(client)


if __name__ == '__main__':
    main()
