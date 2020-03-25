import base64
import hashlib
import json
from collections import namedtuple

import ecdsa
from ecdsa.util import sigdecode_der

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Signature import pkcs1_15

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
from aliyunsdkkms.request.v20160120 import CancelKeyDeletionRequest
from aliyunsdkkms.request.v20160120 import CreateAliasRequest
from aliyunsdkkms.request.v20160120 import DeleteAliasRequest
from aliyunsdkkms.request.v20160120 import DeleteKeyMaterialRequest
from aliyunsdkkms.request.v20160120 import DescribeRegionsRequest
from aliyunsdkkms.request.v20160120 import DisableKeyRequest
from aliyunsdkkms.request.v20160120 import EnableKeyRequest
from aliyunsdkkms.request.v20160120 import GenerateDataKeyRequest
from aliyunsdkkms.request.v20160120 import GenerateDataKeyWithoutPlaintextRequest
from aliyunsdkkms.request.v20160120 import GetParametersForImportRequest
from aliyunsdkkms.request.v20160120 import ImportKeyMaterialRequest
from aliyunsdkkms.request.v20160120 import ListAliasesRequest
from aliyunsdkkms.request.v20160120 import ListResourceTagsRequest
from aliyunsdkkms.request.v20160120 import ScheduleKeyDeletionRequest
from aliyunsdkkms.request.v20160120 import TagResourceRequest
from aliyunsdkkms.request.v20160120 import UntagResourceRequest
from aliyunsdkkms.request.v20160120 import UpdateAliasRequest
from aliyunsdkkms.request.v20160120 import UpdateKeyDescriptionRequest
from aliyunsdkkms.request.v20160120 import UpdateRotationPolicyRequest
from aliyunsdkkms.request.v20160120 import EncryptRequest
from aliyunsdkkms.request.v20160120 import DecryptRequest


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


class CancelKeyDeletionResponse(object):
    """撤销密钥删除返回值类"""

    def __init__(self, value):
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_request_id(self):
        return self.request_id


class CreateAliasResponse(object):
    """创建别名返回值类型类"""

    def __init__(self, value):
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_request_id(self):
        return self.request_id


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


class CreateKeyVersionResponse(object):
    """创建密钥版本返回值类"""

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


class DeleteAliasResponse(object):
    """删除别名返回值类型类"""

    def __init__(self, value):
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_request_id(self):
        return self.request_id


class DeleteKeyMaterialResponse(object):
    """删除密钥材料返回值类型类"""

    def __init__(self, value):
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_request_id(self):
        return self.request_id


class DescribeKeyResponse(object):
    """获取指定密钥相关信息返回值类"""

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


class DescribeKeyVersionResponse(object):
    """获取密钥版本信息返回值类"""

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


class DescribeRegionsResponse(object):
    """查询当前账户的可用地域列表返回值类"""

    def __init__(self, value):
        self.request_id = ""
        self.region_ids = []
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]
        if ("Regions" in response) and ("Region" in response["Regions"]):
            for key in response["Regions"]["Region"]:
                if "RegionId" in key:
                    self.region_ids.append(key.get("RegionId"))

    def get_request_id(self):
        return self.request_id

    def get_region_ids(self):
        return self.region_ids[:]


class DisableKeyResponse(object):
    """禁用密钥返回值类"""

    def __init__(self, value):
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_request_id(self):
        return self.request_id


class EnableKeyResponse(object):
    """启用密钥返回值类"""

    def __init__(self, value):
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_request_id(self):
        return self.request_id


class GenerateDataKeyResponse(object):
    """生成数据密钥返回值类"""

    def __init__(self, value):
        self.request_id = ""
        self.plaintext = ""
        self.cipher_text_blob = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]
        if "Plaintext" in response:
            self.plaintext = response["Plaintext"]
        if "CiphertextBlob" in response:
            self.cipher_text_blob = response["CiphertextBlob"]

    def get_request_id(self):
        return self.request_id

    def get_plaintext(self):
        return self.plaintext

    def get_cipher_text_blob(self):
        return self.cipher_text_blob


class GenerateDataKeyWithoutPlaintextResponse(object):
    """生成数据密钥返回值类"""

    def __init__(self, value):
        self.request_id = ""
        self.cipher_text_blob = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]
        if "CiphertextBlob" in response:
            self.cipher_text_blob = response["CiphertextBlob"]

    def get_request_id(self):
        return self.request_id

    def get_cipher_text_blob(self):
        return self.cipher_text_blob


class GetParametersForImportResponse(object):
    """获取导入密钥材料参数返回值类"""

    def __init__(self, value):
        self.request_id = ""
        self.import_token = ""
        self.public_key = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]
        if "ImportToken" in response:
            self.import_token = response["ImportToken"]
        if "PublicKey" in response:
            self.public_key = response["PublicKey"]

    def get_request_id(self):
        return self.request_id

    def get_import_token(self):
        return self.import_token

    def get_public_key(self):
        return self.public_key


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


class ImportKeyMaterialResponse(object):
    """导入密钥材料返回值类"""

    def __init__(self, value):
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_request_id(self):
        return self.request_id


class AsymmetricEncryptResponse(object):
    """非对称密钥加密返回值类"""

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


class EncryptResponse(object):
    """加密数据返回值类"""

    def __init__(self, value):
        self.request_id = ""
        self.key_id = ""
        self.key_version_id = ""
        self.cipher_text_blob = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "KeyVersionId" in response:
            self.key_version_id = response["KeyVersionId"]
        if "KeyId" in response:
            self.key_id = response["KeyId"]
        if "CiphertextBlob" in response:
            self.cipher_text_blob = response["CiphertextBlob"]
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_key_id(self):
        return self.key_id

    def get_key_version_id(self):
        return self.key_version_id

    def get_cipher_text_blob(self):
        return self.cipher_text_blob

    def get_request_id(self):
        return self.request_id


class AsymmetricDecryptResponse(object):
    """非对称密钥解密返回值类"""

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


class DecryptResponse(object):
    """解密数据返回值类"""

    def __init__(self, value):
        self.request_id = ""
        self.key_id = ""
        self.key_version_id = ""
        self.plaintext = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "KeyVersionId" in response:
            self.key_version_id = response["KeyVersionId"]
        if "KeyId" in response:
            self.key_id = response["KeyId"]
        if "Plaintext" in response:
            self.plaintext = response["Plaintext"]
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_key_id(self):
        return self.key_id

    def get_key_version_id(self):
        return self.key_version_id

    def get_plaintext(self):
        return self.plaintext

    def get_request_id(self):
        return self.request_id


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


class AsymmetricVerifyResponse(object):
    """非对称密钥验签返回值类"""

    def __init__(self, value):
        self.request_id = ""
        self.key_id = ""
        self.key_version_id = ""
        self.value = False
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


class ListAliasesResponse(object):
    """查询别名返回值类"""

    def __init__(self, value):
        self.page_number = 0
        self.total_count = 0
        self.aliases = []
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if ("Aliases" in response) and ("Alias" in response["Aliases"]):
            for alias in response["Aliases"]["Alias"]:
                Alias = namedtuple("Alias", ["KeyId", "AliasName", "AliasArn"])
                self.aliases.append(Alias(alias.get("KeyId"), alias.get("AliasName"), alias.get("AliasArn")))
        if "PageNumber" in response:
            self.page_number = response["PageNumber"]
        if "TotalCount" in response:
            self.total_count = response["TotalCount"]
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_aliases(self):
        return self.aliases[:]

    def get_page_number(self):
        return self.page_number

    def get_total_count(self):
        return self.total_count

    def get_request_id(self):
        return self.request_id


class ListKeysResponse(object):
    """查询密钥返回值类"""

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


class ListResourceTagsResponse(object):
    """查询标签返回值类"""

    def __init__(self, value):
        self.tags = []
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if ("Tags" in response) and ("Tag" in response["Tags"]):
            for tag in response["Tags"]["Tag"]:
                Tag = namedtuple("Tag", ["KeyId", "TagKey", "TagValue"])
                self.tags.append(Tag(tag.get("KeyId"), tag.get("TagKey"), tag.get("TagValue")))
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_tags(self):
        return self.tags[:]

    def get_request_id(self):
        return self.request_id


class ScheduleKeyDeletionResponse(object):
    """计划删除密钥返回值类"""

    def __init__(self, value):
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_request_id(self):
        return self.request_id


class TagResourceResponse(object):
    """修改或添加标签返回值类"""

    def __init__(self, value):
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_request_id(self):
        return self.request_id


class UntagResourceResponse(object):
    """删除标签返回值类"""

    def __init__(self, value):
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_request_id(self):
        return self.request_id


class UpdateAliasResponse(object):
    """更新别名所代表的主密钥返回值类"""

    def __init__(self, value):
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_request_id(self):
        return self.request_id


class UpdateKeyDescriptionResponse(object):
    """更新主密钥的描述信息返回值类"""

    def __init__(self, value):
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_request_id(self):
        return self.request_id


class UpdateRotationPolicyResponse(object):
    """更新密钥轮转策略返回值类"""

    def __init__(self, value):
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_request_id(self):
        return self.request_id


def cancel_key_deletion(acs_client, key_id):
    request = CancelKeyDeletionRequest.CancelKeyDeletionRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    return CancelKeyDeletionResponse(acs_client.do_action_with_exception(request))


def create_alias(acs_client, alias_name, key_id):
    request = CreateAliasRequest.CreateAliasRequest()
    request.set_accept_format('JSON')
    request.set_AliasName(alias_name)
    request.set_KeyId(key_id)
    return CreateAliasResponse(acs_client.do_action_with_exception(request))


def create_key(acs_client, key_spec, key_usage, origin):
    request = CreateKeyRequest.CreateKeyRequest()
    request.set_accept_format('JSON')
    request.set_KeyUsage(key_usage)
    request.set_KeySpec(key_spec)
    request.set_Origin(origin)
    response = CreateKeyResponse(acs_client.do_action_with_exception(request))
    return response.get_key_id()


def create_key_version(acs_client, key_id):
    request = CreateKeyVersionRequest.CreateKeyVersionRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    return CreateKeyVersionResponse(acs_client.do_action_with_exception(request))


def delete_alias(acs_client, alias_name):
    request = DeleteAliasRequest.DeleteAliasRequest()
    request.set_accept_format('JSON')
    request.set_AliasName(alias_name)
    return DeleteAliasResponse(acs_client.do_action_with_exception(request))


def delete_key_material(acs_client, key_id):
    request = DeleteKeyMaterialRequest.DeleteKeyMaterialRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    return DeleteKeyMaterialResponse(acs_client.do_action_with_exception(request))


def describe_key(acs_client, key_id):
    request = DescribeKeyRequest.DescribeKeyRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    return DescribeKeyResponse(acs_client.do_action_with_exception(request))


def describe_key_version(acs_client, key_id, key_version_id):
    request = DescribeKeyVersionRequest.DescribeKeyVersionRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    request.set_KeyVersionId(key_version_id)
    return DescribeKeyVersionResponse(acs_client.do_action_with_exception(request))


def describe_regions(acs_client):
    request = DescribeRegionsRequest.DescribeRegionsRequest()
    request.set_accept_format('JSON')
    return DescribeRegionsResponse(acs_client.do_action_with_exception(request)).get_region_ids()


def disable_key(acs_client, key_id):
    request = DisableKeyRequest.DisableKeyRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    return DisableKeyResponse(acs_client.do_action_with_exception(request))


def enable_key(acs_client, key_id):
    request = EnableKeyRequest.EnableKeyRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    return EnableKeyResponse(acs_client.do_action_with_exception(request))


def generate_data_key(acs_client, key_id):
    request = GenerateDataKeyRequest.GenerateDataKeyRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    response = GenerateDataKeyResponse(acs_client.do_action_with_exception(request))
    return response.get_plaintext(), response.get_cipher_text_blob()


def generate_data_key_without_plaintext(acs_client, key_id):
    request = GenerateDataKeyWithoutPlaintextRequest.GenerateDataKeyWithoutPlaintextRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    response = GenerateDataKeyWithoutPlaintextResponse(acs_client.do_action_with_exception(request))
    return response.get_cipher_text_blob()


def get_parameters_for_import(acs_client, key_id, wrapping_key_spec, wrapping_algorithm):
    request = GetParametersForImportRequest.GetParametersForImportRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    request.set_WrappingKeySpec(wrapping_key_spec)
    request.set_WrappingAlgorithm(wrapping_algorithm)
    response = GetParametersForImportResponse(acs_client.do_action_with_exception(request))
    return response.get_public_key(), response.get_import_token()


def get_public_key(acs_client, key_id, key_version_id):
    request = GetPublicKeyRequest.GetPublicKeyRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    request.set_KeyVersionId(key_version_id)
    response = GetPublicKeyResponse(acs_client.do_action_with_exception(request))
    return response.get_public_key()


def import_key_material(acs_client, key_id, import_token, encrypted_key_material):
    request = ImportKeyMaterialRequest.ImportKeyMaterialRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    request.set_ImportToken(import_token)
    request.set_EncryptedKeyMaterial(encrypted_key_material)
    return ImportKeyMaterialResponse(acs_client.do_action_with_exception(request))


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


def encrypt(acs_client, key_id, base64_plaintext):
    request = EncryptRequest.EncryptRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    # plaintext推荐使用base64编码，如果不编码也可以，存在隐患
    # kms在处理plaintext的时候可能没有做解码，是直接对plaintext进行加密
    # 在非对称加密接口中做了解码操作，所以非对称加密必须进行编码
    request.set_Plaintext(base64_plaintext)
    response = EncryptResponse(acs_client.do_action_with_exception(request))
    return response.get_cipher_text_blob()


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


def decrypt(acs_client, cipher_text):
    request = DecryptRequest.DecryptRequest()
    request.set_accept_format('JSON')
    request.set_CiphertextBlob(cipher_text)
    response = DecryptResponse(acs_client.do_action_with_exception(request))
    return response.get_plaintext()


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


def list_aliases(acs_client):
    aliases = []
    page_number = "1"
    page_size = "10"
    while True:
        request = ListAliasesRequest.ListAliasesRequest()
        request.set_accept_format('JSON')
        request.set_PageNumber(page_number)
        request.set_PageSize(page_size)
        response = ListAliasesResponse(acs_client.do_action_with_exception(request))
        aliases[len(aliases):len(aliases)] = response.get_aliases()
        if response.get_page_number() * 10 >= response.get_total_count():
            break
        page_number = str(response.get_page_number() + 1)
    return aliases


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


def list_resource_tags(acs_client, key_id):
    request = ListResourceTagsRequest.ListResourceTagsRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    return ListResourceTagsResponse(acs_client.do_action_with_exception(request)).get_tags()


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


def schedule_key_deletion(acs_client, key_id, pending_window_in_days):
    request = ScheduleKeyDeletionRequest.ScheduleKeyDeletionRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    request.set_PendingWindowInDays(str(pending_window_in_days))
    return ScheduleKeyDeletionResponse(acs_client.do_action_with_exception(request))


def tag_resource(acs_client, key_id, tags):
    request = TagResourceRequest.TagResourceRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    request.set_Tags(tags)
    return TagResourceResponse(acs_client.do_action_with_exception(request))


def untag_resource(acs_client, key_id, tags_keys):
    request = UntagResourceRequest.UntagResourceRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    request.set_TagKeys(tags_keys)
    return UntagResourceResponse(acs_client.do_action_with_exception(request))


# 更新已存在的别名所代表的主密钥
def update_alias(acs_client, alias_name, key_id):
    request = UpdateAliasRequest.UpdateAliasRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    request.set_AliasName(alias_name)
    return UpdateAliasResponse(acs_client.do_action_with_exception(request))


# 更新主密钥的描述信息
def update_key_description(acs_client, key_id, description):
    request = UpdateKeyDescriptionRequest.UpdateKeyDescriptionRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    request.set_Description(description)
    return UpdateKeyDescriptionResponse(acs_client.do_action_with_exception(request))


# enable_automatic_rotation: 'true' or 'false'
def update_rotation_policy(acs_client, key_id, enable_automatic_rotation, rotation_interval):
    request = UpdateRotationPolicyRequest.UpdateRotationPolicyRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    request.set_EnableAutomaticRotation(enable_automatic_rotation)
    request.set_RotationInterval(rotation_interval)
    return UpdateRotationPolicyResponse(acs_client.do_action_with_exception(request))

