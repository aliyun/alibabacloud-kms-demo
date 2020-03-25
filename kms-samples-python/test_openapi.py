import argparse
import base64
import binascii
import sys
import unittest
from collections import namedtuple

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from aliyunsdkcore.client import AcsClient

import openapi


class TestKmsOpenApi(unittest.TestCase):
    AK = ''
    AS = ''
    REGION = ''

    def setUp(self):
        self.client = AcsClient(self.AK, self.AS, self.REGION)
        # self.client.set_verify(False)
        self.symmetric_key_id = '2fad5f44-9573-4f28-8956-666c52cc9fa9'
        self.rsa_key_id = 'a8c6eb76-278c-4f88-801b-8fb56e4c3019'
        self.rsa_key_version_id = '6f050e56-9b71-41db-8d48-5275855f1041'
        self.rsa_key_id_sign = 'bb974925-d7d2-48c3-b896-cb2a3f3f33bd'
        self.rsa_key_version_id_sign = 'd4229c1f-17ec-40df-bfe0-51667c6c78b6'
        self.ec_p256_key_id = '71032ff8-1803-426f-b5be-c57bdeee1080'
        self.ec_p256_key_version_id = '529eb3e1-6ef5-4a47-bce4-4c86494ebc1c'
        self.ec_p256k_key_id = '842a6803-66b0-4849-a040-c09cb0ba1aa3'
        self.ec_p256k_key_version_id = '303cc3ed-ac14-4da7-8d88-7dfd7fe47aed'
        self.external_key_id = '4ffbf0c5-0324-4ccf-8ab7-547a3c148adb'

    def test_cancel_key_deletion(self):
        key_id = self.symmetric_key_id
        key_meta = openapi.describe_key(self.client, key_id).get_key_metadata()
        if key_meta.get_key_state() == 'Enabled':
            openapi.schedule_key_deletion(self.client, key_id, '30')
        openapi.cancel_key_deletion(self.client, key_id)
        key_meta = openapi.describe_key(self.client, key_id).get_key_metadata()
        self.assertEqual('Enabled', key_meta.get_key_state(), 'key state should be Enabled')

    def test_create_alias(self):
        key_id = self.symmetric_key_id
        alias = 'alias/testA'

        aliases = openapi.list_aliases(self.client)
        for v in aliases:
            if v.KeyId == key_id and v.AliasName == alias:
                openapi.delete_alias(self.client, alias)
                self.fail('test_create_alias error: alias/testA already exist')

        openapi.create_alias(self.client, alias, key_id)
        aliases = openapi.list_aliases(self.client)
        ok = False
        for v in aliases:
            if v.KeyId == key_id and v.AliasName == alias:
                ok = True
                break

        self.assertTrue(ok, 'create alias failed')

        openapi.delete_alias(self.client, alias)

    @unittest.skip("Skipping")
    def test_create_key(self):
        key_id = openapi.create_key(self.client, "RSA_2048", "ENCRYPT/DECRYPT", 'Aliyun_KMS')
        self.assertIsNotNone(key_id)

    @unittest.skip("Skipping")
    def test_create_key_version(self):
        key_id = self.rsa_key_id
        key_version = openapi.create_key_version(self.client, key_id)
        key_version_ids = openapi.list_key_versions(self.client, key_id)
        self.assertIn(key_version.get_key_version_id(), key_version_ids)

    def test_delete_alias(self):
        key_id = self.symmetric_key_id
        alias = 'alias/testA'

        openapi.create_alias(self.client, alias, key_id)
        openapi.delete_alias(self.client, alias)

        aliases = openapi.list_aliases(self.client)
        ok = False
        for v in aliases:
            if v.KeyId == key_id and v.AliasName == alias:
                ok = True
                break

        self.assertFalse(ok, 'delete alias failed')

    def test_delete_key_material(self):
        key_id = self.external_key_id

        key_meta = openapi.describe_key(self.client, key_id).get_key_metadata()
        if key_meta.get_key_state() == 'PendingImport':
            pub_key_spec = 'RSA_2048'
            algorithm = 'RSAES_OAEP_SHA_256'
            key_material = binascii.a2b_hex('c03c02695ab6fe914ab6ab209ab3561cab42186eedbfa0d70103ac8d30a88392')

            public_key, import_token = openapi.get_parameters_for_import(self.client, key_id, pub_key_spec, algorithm)
            der_pub = base64.b64decode(public_key)
            rsa_pub = RSA.importKey(der_pub)
            cipher = PKCS1_OAEP.new(key=rsa_pub, hashAlgo=SHA256)
            cipher_blob = cipher.encrypt(key_material)
            encrypted_key_material = base64.b64encode(cipher_blob)
            openapi.import_key_material(self.client, key_id, import_token, encrypted_key_material)

        openapi.delete_key_material(self.client, key_id)
        key_meta = openapi.describe_key(self.client, key_id).get_key_metadata()
        self.assertEqual('PendingImport', key_meta.get_key_state(), 'key state should be PendingImport')

    def test_describe_key(self):
        key_id = self.external_key_id

        key_meta = openapi.describe_key(self.client, key_id).get_key_metadata()
        self.assertEqual('EXTERNAL', key_meta.get_origin(), 'key state should be EXTERNAL')
        self.assertEqual('Aliyun_AES_256', key_meta.get_key_spec(), 'key spec should be Aliyun_AES_256')

    def test_describe_key_version(self):
        key_id = self.rsa_key_id
        key_version_id = self.rsa_key_version_id

        key_version = openapi.describe_key_version(self.client, key_id, key_version_id)
        self.assertEqual(key_id, key_version.get_key_id(), 'keyId should be equal')
        self.assertEqual(key_version_id, key_version.get_key_version_id(), 'keyVersionId should be equal')

    def test_describe_regions(self):
        regions = openapi.describe_regions(self.client)
        self.assertIn(self.REGION, regions)

    def test_disable_key(self):
        key_id = self.symmetric_key_id
        openapi.disable_key(self.client, key_id)
        key_meta = openapi.describe_key(self.client, key_id).get_key_metadata()
        self.assertEqual('Disabled', key_meta.get_key_state(), 'key state should be Disabled')
        openapi.enable_key(self.client, key_id)

    def test_enable_key(self):
        key_id = self.symmetric_key_id
        openapi.disable_key(self.client, key_id)
        openapi.enable_key(self.client, key_id)
        key_meta = openapi.describe_key(self.client, key_id).get_key_metadata()
        self.assertEqual('Enabled', key_meta.get_key_state(), 'key state should be Enabled')

    def test_generate_data_key(self):
        key_id = self.symmetric_key_id
        message = '测试消息'

        plain_key, cipher_blob_key = openapi.generate_data_key(self.client, key_id)
        key = base64.b64decode(plain_key)
        nonce = get_random_bytes(12)
        cipher = AES.new(key=key, nonce=nonce, mode=AES.MODE_GCM, mac_len=16)
        cipher_text, mac = cipher.encrypt_and_digest(message.encode('utf-8'))

        # 解密数据密钥
        plain_key = openapi.decrypt(self.client, cipher_blob_key)
        key = base64.b64decode(plain_key)
        cipher = AES.new(key=key, nonce=nonce, mode=AES.MODE_GCM, mac_len=16)
        plain_text = cipher.decrypt_and_verify(cipher_text, mac)

        self.assertEqual(message, str(plain_text.decode('utf-8')), 'the plaintext should be equal message')

    def test_generate_data_key_without_plaintext(self):
        key_id = self.symmetric_key_id
        message = '测试消息'

        cipher_blob_key = openapi.generate_data_key_without_plaintext(self.client, key_id)
        plain_key = openapi.decrypt(self.client, cipher_blob_key)
        key = base64.b64decode(plain_key)
        nonce = get_random_bytes(12)
        # 加密
        cipher = AES.new(key=key, nonce=nonce, mode=AES.MODE_GCM, mac_len=16)
        cipher_text, mac = cipher.encrypt_and_digest(message.encode('utf-8'))
        # 解密
        cipher = AES.new(key=key, nonce=nonce, mode=AES.MODE_GCM, mac_len=16)
        plain_text = cipher.decrypt_and_verify(cipher_text, mac)

        self.assertEqual(message, str(plain_text.decode('utf-8')), 'the plaintext should be equal message')

    def test_get_parameters_for_import(self):
        key_id = self.external_key_id
        pub_key_spec = 'RSA_2048'
        algorithm = 'RSAES_OAEP_SHA_256'

        pub, token = openapi.get_parameters_for_import(self.client, key_id, pub_key_spec, algorithm)
        self.assertIsNotNone(pub)
        self.assertIsNotNone(token)

    def test_get_public_key(self):
        key_id = self.rsa_key_id
        key_version_id = self.rsa_key_version_id

        public_key = '-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3ZlKsjYOLpag7SN3ozEE\n\
2sKdv1+dBtQcHtAyG6IV5tuFsL0eGYESEJKtkzXE702SUBPTo/c8N3xoIDxh6/qq\n\
xh0up0dc3gxDGzHEOtTOLCeFvO7u8P2kOcbx3Jgd8eIUyJCtpWvRogZhJGe/dPA1\n\
ayFYyonxQBt1r0aRDCdu+KUZ6MzbIMuC9shRMfW6HczT2pcngbpBFp64ksszsNiO\n\
szQxfX0OXFOKNESZRD0vqOMA0pFxzZghwMN9s8FFwURokjZbmImvaj8b4rG0EOkr\n\
sXwk+q6BOzmEa0udiMVBS/QB3B7rYrkn6oST/6LDxLoBfAQp6lonVHhWTIswoQpL\n\
vwIDAQAB\n\
-----END PUBLIC KEY-----\n'

        pub = openapi.get_public_key(self.client, key_id, key_version_id)
        self.assertEqual(public_key, str(pub))

    def test_asymmetric_encrypt(self):
        key_id = self.rsa_key_id
        key_version_id = self.rsa_key_version_id
        algorithm = 'RSAES_OAEP_SHA_256'
        message = '测试消息'

        cipher_blob = openapi.asymmetric_encrypt(self.client, key_id, key_version_id, message, algorithm)
        plaintext = openapi.asymmetric_decrypt(self.client, key_id, key_version_id, cipher_blob, algorithm)

        self.assertEqual(message, str(plaintext.decode('utf-8')), 'plaintext should be hello,中国')

    def test_encrypt(self):
        key_id = self.symmetric_key_id
        message = '测试消息'

        base64_plaintext = base64.b64encode(message.encode('utf-8'))
        cipher_blob = openapi.encrypt(self.client, key_id, base64_plaintext)
        base64_plaintext = openapi.decrypt(self.client, cipher_blob)
        plaintext = base64.b64decode(base64_plaintext)

        self.assertEqual(message, str(plaintext.decode('utf-8')), 'plaintext should be hello,中国')

    def test_asymmetric_decrypt(self):
        cipher_blob = binascii.a2b_hex(
            '933acfe6227de6712bdd56d76518eafa419528fe438c2642f216a2817bbf7ceb6b058f2503f37c3b0e7c226ffd87503a106a65ab73e0dc343d6cf161893d04f889880d4c2870f52f33cccfd8269a763d8730353a010b1c932636556f64b3b9bece7bcea3c919ed9c1f45b5a203a891b4650209b3def42005c3106df1362c4d1b5bd168339acaec77f0e5242436e878edcb5dfd51baed2f5a453768fac5b011ecc06f1c0bfa56bb4edb67ce16ae8ce8715f274e9285dbc1d9988298d8c9bfa2586147eba9e8e46e9f306866fe5994611b5d15dbc6e5fd7dc3d105e5d9ff8438924fee16feedaf1ec8cb446ef2e918fdfb1597a93e82591689bac7d7e1d6fbe1af')
        key_id = self.rsa_key_id
        key_version_id = self.rsa_key_version_id
        algorithm = 'RSAES_OAEP_SHA_256'
        message = '测试消息'

        plaintext = openapi.asymmetric_decrypt(self.client, key_id, key_version_id, cipher_blob, algorithm)
        self.assertEqual(message, plaintext.decode('utf-8'), 'plaintext should be hello,中国')

    def test_decrypt(self):
        cipher_blob = 'MzkyN2FmNmUtNTk3NC00MzZkLWE1YzYtY2UzMTRjOTM2ZTdhXdvyW6fEVxDs0uP1D89aUzsdqGmk3/Rfg9V5lND6oNLX8/tXCRG7sZFocuE='
        message = "测试消息"

        base64_plaintext = openapi.decrypt(self.client, cipher_blob)
        plaintext = base64.b64decode(base64_plaintext)
        self.assertEqual(message, str(plaintext.decode('utf-8')), 'plaintext should be hello,中国')

    def test_asymmetric_sign(self):
        key_id = self.rsa_key_id_sign
        key_version_id = self.rsa_key_version_id_sign
        algorithm = 'RSA_PKCS1_SHA_256'
        message = '测试消息'

        signature = openapi.asymmetric_sign(self.client, key_id, key_version_id, message, algorithm)
        ok = openapi.asymmetric_verify(self.client, key_id, key_version_id, message, signature, algorithm)
        self.assertTrue(ok, 'the result of verify should be True')

    def test_asymmetric_verify(self):
        signature = binascii.a2b_hex(
            '2a52bb2dadc47ee59f68f3bc95c17d0f03d10bc30cc46594cf45aa4760d4b790cf38758348f4860c5514f0934fbbbfc0a0882344fc580e2107193627a1462150e6e5f7230f192b90f10c8fb35b470b02760f907dd55a6de077fc8b23ab28d3711ff05cc5277fe392b3a678633dfb066faaef77325df109f24cc9257be41a5e8b7de824e75cd729502bb6c0ad88259424f49430df71082e36a8f7070ec530dc9bacb733f3ce221c84d4f36f12008a2b0e2fb5f17d68577b81f16ae26de48a3ef643f5dea09b407ea80b450056e6902b6de1b4cc8c4a8a12d857fa45011455f183bd6e05d88175fff9e91d51b7fae396655f0eeb53ed15846fe77929a99e8cf90d')
        key_id = self.rsa_key_id_sign
        key_version_id = self.rsa_key_version_id_sign
        algorithm = 'RSA_PKCS1_SHA_256'
        message = '测试消息'

        ok = openapi.asymmetric_verify(self.client, key_id, key_version_id, message, signature, algorithm)
        self.assertTrue(ok, 'the result of verify should be True')

    def test_list_aliases(self):
        key_id = self.symmetric_key_id
        alias = 'alias/testA'

        openapi.create_alias(self.client, alias, key_id)
        aliases = openapi.list_aliases(self.client)
        self.assertIsNotNone(aliases)
        openapi.delete_alias(self.client, alias)

    def test_list_keys(self):
        key_ids = openapi.list_keys(self.client)
        self.assertIsNotNone(key_ids)

    def test_list_key_versions(self):
        key_id = self.rsa_key_id
        key_versions = openapi.list_key_versions(self.client, key_id)
        self.assertIsNotNone(key_versions)

    def test_list_resource_tags(self):
        key_id = self.symmetric_key_id
        tags = '[{"TagKey": "testA", "TagValue": "123456"}, {"TagKey": "testB", "TagValue": "abcdef"}]'

        openapi.tag_resource(self.client, key_id, tags)
        tag_lists = openapi.list_resource_tags(self.client, key_id)

        self.assertIsNotNone(tag_lists)

        tags_keys = '["testA", "testB"]'
        openapi.untag_resource(self.client, key_id, tags_keys)

    def test_rsa_encrypt(self):
        key_id = self.rsa_key_id
        key_version_id = self.rsa_key_version_id
        algorithm = 'RSAES_OAEP_SHA_256'
        message = '测试消息'

        cipher_blob = openapi.rsa_encrypt(self.client, key_id, key_version_id, message, algorithm)
        if cipher_blob is '':
            self.fail('not supported algorithm')

        plaintext = openapi.asymmetric_decrypt(self.client, key_id, key_version_id, cipher_blob, algorithm)
        self.assertEqual(message, str(plaintext.decode('utf-8')), 'plaintext should be hello,中国')

    def test_rsa_verify(self):
        signature = binascii.a2b_hex('2a52bb2dadc47ee59f68f3bc95c17d0f03d10bc30cc46594cf45aa4760d4b790cf38758348f4860c5514f0934fbbbfc0a0882344fc580e2107193627a1462150e6e5f7230f192b90f10c8fb35b470b02760f907dd55a6de077fc8b23ab28d3711ff05cc5277fe392b3a678633dfb066faaef77325df109f24cc9257be41a5e8b7de824e75cd729502bb6c0ad88259424f49430df71082e36a8f7070ec530dc9bacb733f3ce221c84d4f36f12008a2b0e2fb5f17d68577b81f16ae26de48a3ef643f5dea09b407ea80b450056e6902b6de1b4cc8c4a8a12d857fa45011455f183bd6e05d88175fff9e91d51b7fae396655f0eeb53ed15846fe77929a99e8cf90d')
        key_id = self.rsa_key_id_sign
        key_version_id = self.rsa_key_version_id_sign
        algorithm = 'RSA_PKCS1_SHA_256'
        message = '测试消息'

        ok = openapi.rsa_verify(self.client, key_id, key_version_id, message, signature, algorithm)
        self.assertTrue(ok)

    def test_ecdsa_verify(self):
        # EC_P256
        key_id = self.ec_p256_key_id
        key_version_id = self.ec_p256_key_version_id
        message = '测试消息'

        signature = openapi.asymmetric_sign(self.client, key_id, key_version_id, message, 'ECDSA_SHA_256')
        ok = openapi.ecdsa_verify(self.client, key_id, key_version_id, message, signature)
        self.assertTrue(ok)

        # EC_P256K
        key_id = self.ec_p256k_key_id
        key_version_id = self.ec_p256k_key_version_id

        signature = openapi.asymmetric_sign(self.client, key_id, key_version_id, message, 'ECDSA_SHA_256')
        ok = openapi.ecdsa_verify(self.client, key_id, key_version_id, message, signature)
        self.assertTrue(ok)

    def test_schedule_key_deletion(self):
        key_id = self.symmetric_key_id
        pending_window_in_days = 7

        openapi.schedule_key_deletion(self.client, key_id, pending_window_in_days)
        key_meta = openapi.describe_key(self.client, key_id).get_key_metadata()

        self.assertEqual('PendingDeletion', key_meta.get_key_state(), 'key state should be PendingDeletion')

        openapi.cancel_key_deletion(self.client, key_id)

    def test_tag_resource(self):
        key_id = self.symmetric_key_id
        tags = '[{"TagKey": "testA", "TagValue": "123456"}, {"TagKey": "testB", "TagValue": "abcdef"}]'

        openapi.tag_resource(self.client, key_id, tags)
        tag_lists = openapi.list_resource_tags(self.client, key_id)

        Tag = namedtuple("Tag", ["KeyId", "TagKey", "TagValue"])
        self.assertIn(Tag(key_id, 'testA', '123456'), tag_lists)
        self.assertIn(Tag(key_id, 'testB', 'abcdef'), tag_lists)

        tags_keys = '["testA", "testB"]'
        openapi.untag_resource(self.client, key_id, tags_keys)

    def test_untag_resource(self):
        key_id = self.symmetric_key_id
        tags = '[{"TagKey": "testA", "TagValue": "123456"}, {"TagKey": "testB", "TagValue": "abcdef"}]'

        openapi.tag_resource(self.client, key_id, tags)
        tags_keys = '["testA", "testB"]'
        openapi.untag_resource(self.client, key_id, tags_keys)

        tag_lists = openapi.list_resource_tags(self.client, key_id)
        Tag = namedtuple("Tag", ["KeyId", "TagKey", "TagValue"])
        self.assertNotIn(Tag(key_id, 'testA', '123456'), tag_lists)
        self.assertNotIn(Tag(key_id, 'testB', 'abcdef'), tag_lists)

    def test_update_alias(self):
        key_id = self.symmetric_key_id
        alias = 'alias/testA'

        openapi.create_alias(self.client, alias, key_id)
        key_id = self.rsa_key_id
        openapi.update_alias(self.client, alias, key_id)

        aliases = openapi.list_aliases(self.client)
        ok = False
        for v in aliases:
            if v.KeyId == key_id and v.AliasName == alias:
                ok = True
                break
        self.assertTrue(ok, 'update alias failed')

        openapi.delete_alias(self.client, alias)

    def test_update_key_description(self):
        key_id = self.symmetric_key_id
        new_description = 'update description test'

        key_meta = openapi.describe_key(self.client, key_id).get_key_metadata()
        old_description = key_meta.get_description()
        if len(old_description) <= 0:
            old_description = ' '

        openapi.update_key_description(self.client, key_id, new_description)
        key_meta = openapi.describe_key(self.client, key_id).get_key_metadata()
        self.assertEqual(new_description, key_meta.get_description())

        openapi.update_key_description(self.client, key_id, old_description)

    def test_update_rotation_policy(self):
        key_id = self.symmetric_key_id

        key_meta = openapi.describe_key(self.client, key_id).get_key_metadata()
        old_rotation_interval = key_meta.get_rotation_interval()

        enable_automatic_rotation = True
        if key_meta.get_automatic_rotation() == 'Enabled':
            enable_automatic_rotation = False

        openapi.update_rotation_policy(self.client, key_id, enable_automatic_rotation, '604800s')

        key_meta = openapi.describe_key(self.client, key_id).get_key_metadata()
        if enable_automatic_rotation:
            self.assertEqual('Enabled', key_meta.get_automatic_rotation())
            self.assertEqual('604800s', key_meta.get_rotation_interval())
        else:
            self.assertEqual('Disabled', key_meta.get_automatic_rotation())

        openapi.update_rotation_policy(self.client, key_id, not enable_automatic_rotation, old_rotation_interval)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser()
        parser.add_argument('--ak', help='the access key id')
        parser.add_argument('--as', help='the access key secret')
        parser.add_argument('--region', default='cn-hangzhou', help='the region id')
        args = vars(parser.parse_args())
        TestKmsOpenApi.AK = args["ak"]
        TestKmsOpenApi.AS = args["as"]
        TestKmsOpenApi.REGION = args["region"]
        sys.argv = sys.argv[:1]

    unittest.main()
