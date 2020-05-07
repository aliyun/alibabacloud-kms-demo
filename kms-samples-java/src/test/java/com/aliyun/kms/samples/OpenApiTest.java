package com.aliyun.kms.samples;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.kms.model.v20160120.*;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static org.junit.Assert.*;

public class OpenApiTest {
    private String regionId = "";
    private String accessKeyId = "";
    private String accessKeySecret = "";
    private DefaultAcsClient client = null;
    private String symmetricKeyId = "";
    private String rsaKeyId = "";
    private String rsaKeyVersionId = "";
    private String rsaKeyIdSign = "";
    private String rsaKeyVersionIdSign = "";
    private String ecp256KeyId = "";
    private String ecp256KeyVersionId = "";
    private String ecp256kKeyId = "";
    private String ecp256kKeyVersionId = "";
    private String externalKeyId = "";

    @Before
    public void setUp() {
        this.regionId = "cn-hangzhou";
        this.accessKeyId = System.getenv("AccessKeyId");
        this.accessKeySecret = System.getenv("AccessKeySecret");
        this.client = OpenApi.kmsClient(this.regionId, this.accessKeyId, this.accessKeySecret);
        this.symmetricKeyId = "2fad5f44-9573-4f28-8956-666c52cc9fa9";
        this.rsaKeyId = "a8c6eb76-278c-4f88-801b-8fb56e4c3019";
        this.rsaKeyVersionId = "6f050e56-9b71-41db-8d48-5275855f1041";
        this.rsaKeyIdSign = "bb974925-d7d2-48c3-b896-cb2a3f3f33bd";
        this.rsaKeyVersionIdSign = "d4229c1f-17ec-40df-bfe0-51667c6c78b6";
        this.ecp256KeyId = "71032ff8-1803-426f-b5be-c57bdeee1080";
        this.ecp256KeyVersionId = "529eb3e1-6ef5-4a47-bce4-4c86494ebc1c";
        this.ecp256kKeyId = "842a6803-66b0-4849-a040-c09cb0ba1aa3";
        this.ecp256kKeyVersionId = "303cc3ed-ac14-4da7-8d88-7dfd7fe47aed";
        this.externalKeyId = "4ffbf0c5-0324-4ccf-8ab7-547a3c148adb";
    }

    @After
    public void tearDown() {
        this.client = null;
    }

    @org.junit.Test
    public void kmsClient() {
        DefaultAcsClient client = OpenApi.kmsClient(this.regionId, this.accessKeyId, this.accessKeySecret);
        assertNotNull(client);
    }

    @org.junit.Test
    public void cancelKeyDeletion() throws ClientException {
        String keyId = this.symmetricKeyId;
        String keyState = OpenApi.describeKey(this.client, keyId).getKeyMetadata().getKeyState();
        if (keyState.equals("Enabled")) {
            OpenApi.scheduleKeyDeletion(this.client, keyId, 30);
        }
        OpenApi.cancelKeyDeletion(this.client, keyId);
        keyState = OpenApi.describeKey(this.client, keyId).getKeyMetadata().getKeyState();
        assertEquals("Enabled", keyState);
    }

    @org.junit.Test
    public void createAlias() throws ClientException {
        String keyId = this.symmetricKeyId;
        String alias = "alias/testA";
        List<ListAliasesResponse.Alias> aliases = OpenApi.listAliases(this.client);
        for (ListAliasesResponse.Alias v : aliases) {
            if (v.getKeyId().equals(keyId) && v.getAliasName().equals(alias)) {
                OpenApi.deleteAlias(this.client, alias);
                break;
            }
        }
        OpenApi.createAlias(this.client, alias, keyId);
        aliases = OpenApi.listAliases(this.client);
        boolean ok = false;
        for (ListAliasesResponse.Alias v : aliases) {
            if (v.getKeyId().equals(keyId) && v.getAliasName().equals(alias)) {
                ok = true;
                break;
            }
        }
        assertTrue(ok);
        OpenApi.deleteAlias(this.client, alias);
    }

    @org.junit.Test
    @Ignore
    public void createKey() throws ClientException {
        String keyId = OpenApi.createKey(this.client, "RSA_2048", "ENCRYPT/DECRYPT", "Aliyun_KMS");
        assertNotNull(keyId);
    }

    @org.junit.Test
    @Ignore
    public void createKeyVersion() throws ClientException {
        String keyId = this.rsaKeyId;
        CreateKeyVersionResponse keyVersionRes = OpenApi.createKeyVersion(this.client, keyId);
        assertNotNull(keyVersionRes);
    }

    @org.junit.Test
    public void deleteAlias() throws ClientException {
        String keyId = this.symmetricKeyId;
        String alias = "alias/testA";
        OpenApi.createAlias(this.client, alias, keyId);
        OpenApi.deleteAlias(this.client, alias);
        List<ListAliasesResponse.Alias> aliases = OpenApi.listAliases(this.client);
        boolean ok = false;
        for (ListAliasesResponse.Alias a : aliases) {
            if (a.getKeyId().equals(keyId) && a.getAliasName().equals(alias)) {
                ok = true;
                break;
            }
        }
        assertFalse(ok);
    }

    @org.junit.Test
    public void deleteKeyMaterial() throws ClientException {
        String keyId = externalKeyId;
        OpenApi.deleteKeyMaterial(this.client, keyId);
        DescribeKeyResponse response = OpenApi.describeKey(this.client, keyId);
        assertEquals("PendingImport", response.getKeyMetadata().getKeyState());
    }

    @org.junit.Test
    public void describeKey() throws ClientException {
        String keyId = externalKeyId;
        DescribeKeyResponse response = OpenApi.describeKey(this.client, keyId);
        assertNotNull(response);
    }

    @org.junit.Test
    public void describeKeyVersion() throws ClientException {
        String keyId = rsaKeyId;
        String keyVersionId = rsaKeyVersionId;
        DescribeKeyVersionResponse response = OpenApi.describeKeyVersion(this.client, keyId, keyVersionId);
        assertNotNull(response);
    }

    @org.junit.Test
    public void describeRegions() throws ClientException {
        List<String> regions = OpenApi.describeRegions(this.client);
        assertNotNull(regions);
    }

    @org.junit.Test
    public void disableKey() throws ClientException {
        String keyId = this.symmetricKeyId;
        OpenApi.disableKey(this.client, keyId);
        DescribeKeyResponse response = OpenApi.describeKey(this.client, keyId);
        assertEquals("Disabled", response.getKeyMetadata().getKeyState());
        OpenApi.enableKey(this.client, keyId);
    }

    @org.junit.Test
    public void enableKey() throws ClientException {
        String keyId = this.symmetricKeyId;
        OpenApi.disableKey(this.client, keyId);
        OpenApi.enableKey(this.client, keyId);
        DescribeKeyResponse response = OpenApi.describeKey(this.client, keyId);
        assertEquals("Enabled", response.getKeyMetadata().getKeyState());
    }

    @org.junit.Test
    public void generateDataKey() throws ClientException {
        String keyId = this.symmetricKeyId;
        GenerateDataKeyResponse response = OpenApi.generateDataKey(this.client, keyId);
        assertNotNull(response);
    }

    @org.junit.Test
    public void generateDataKeyWithoutPlaintext() throws ClientException {
        String keyId = this.symmetricKeyId;
        GenerateDataKeyWithoutPlaintextResponse response = OpenApi.generateDataKeyWithoutPlaintext(this.client, keyId);
        assertNotNull(response);
    }

    @org.junit.Test
    public void getParametersForImport() throws ClientException {
        String keyId = externalKeyId;
        String keySpec = "RSA_2048";
        String algorithm = "RSAES_OAEP_SHA_256";
        GetParametersForImportResponse response = OpenApi.getParametersForImport(this.client, keyId, keySpec, algorithm);
        assertNotNull(response);
    }

    @org.junit.Test
    public void getPublicKey() throws ClientException {
        String keyId = this.rsaKeyId;
        String keyVersionId = this.rsaKeyVersionId;
        String publicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3ZlKsjYOLpag7SN3ozEE\n" +
                "2sKdv1+dBtQcHtAyG6IV5tuFsL0eGYESEJKtkzXE702SUBPTo/c8N3xoIDxh6/qq\n" +
                "xh0up0dc3gxDGzHEOtTOLCeFvO7u8P2kOcbx3Jgd8eIUyJCtpWvRogZhJGe/dPA1\n" +
                "ayFYyonxQBt1r0aRDCdu+KUZ6MzbIMuC9shRMfW6HczT2pcngbpBFp64ksszsNiO\n" +
                "szQxfX0OXFOKNESZRD0vqOMA0pFxzZghwMN9s8FFwURokjZbmImvaj8b4rG0EOkr\n" +
                "sXwk+q6BOzmEa0udiMVBS/QB3B7rYrkn6oST/6LDxLoBfAQp6lonVHhWTIswoQpL\n" +
                "vwIDAQAB\n" +
                "-----END PUBLIC KEY-----\n";
                GetPublicKeyResponse response = OpenApi.getPublicKey(this.client, keyId, keyVersionId);
        assertEquals(publicKey, response.getPublicKey());
    }

    @org.junit.Test
    public void asymmetricEncrypt() throws ClientException {
        String keyId = this.rsaKeyId;
        String keyVersionId = this.rsaKeyVersionId;
        String algorithm = "RSAES_OAEP_SHA_256";
        String message = "测试消息";

        byte[] cipherBlob = OpenApi.asymmetricEncrypt(this.client, keyId, keyVersionId, message, algorithm);
        byte[] plaintext = OpenApi.asymmetricDecrypt(this.client, cipherBlob, keyId, keyVersionId, algorithm);
        assertEquals(message, new String(plaintext, StandardCharsets.UTF_8));
    }

    @org.junit.Test
    public void encrypt() throws ClientException {
        String keyId = this.symmetricKeyId;
        String message = "测试消息";
        String cipherBlob = OpenApi.encrypt(this.client, keyId, message);
        String plaintext = OpenApi.decrypt(this.client, cipherBlob);
        assertEquals(message, plaintext);
    }

    @org.junit.Test
    public void asymmetricDecrypt() throws DecoderException, ClientException {
        byte[] cipherBlob = Hex.decodeHex("933acfe6227de6712bdd56d76518eafa419528fe438c2642f216a2817bbf7ceb6b058f2503f37c3b0e7c226ffd87503a106a65ab73e0dc343d6cf161893d04f889880d4c2870f52f33cccfd8269a763d8730353a010b1c932636556f64b3b9bece7bcea3c919ed9c1f45b5a203a891b4650209b3def42005c3106df1362c4d1b5bd168339acaec77f0e5242436e878edcb5dfd51baed2f5a453768fac5b011ecc06f1c0bfa56bb4edb67ce16ae8ce8715f274e9285dbc1d9988298d8c9bfa2586147eba9e8e46e9f306866fe5994611b5d15dbc6e5fd7dc3d105e5d9ff8438924fee16feedaf1ec8cb446ef2e918fdfb1597a93e82591689bac7d7e1d6fbe1af");
        String keyId = this.rsaKeyId;
        String keyVersionId = this.rsaKeyVersionId;
        String algorithm = "RSAES_OAEP_SHA_256";
        String message = "测试消息";
        byte[] plaintext = OpenApi.asymmetricDecrypt(this.client, cipherBlob, keyId, keyVersionId, algorithm);
        assertEquals(message, new String(plaintext, StandardCharsets.UTF_8));
    }

    @org.junit.Test
    public void decrypt() throws ClientException {
        String cipherBlob = "MzkyN2FmNmUtNTk3NC00MzZkLWE1YzYtY2UzMTRjOTM2ZTdhXdvyW6fEVxDs0uP1D89aUzsdqGmk3/Rfg9V5lND6oNLX8/tXCRG7sZFocuE=";
        String message = "测试消息";
        String base64Plaintext = OpenApi.decrypt(this.client, cipherBlob);
        byte[] plaintext = Base64.getDecoder().decode(base64Plaintext);
        assertEquals(message, new String(plaintext, StandardCharsets.UTF_8));
    }

    @org.junit.Test
    public void asymmetricSign() throws ClientException, NoSuchAlgorithmException {
        String keyId = this.rsaKeyIdSign;
        String keyVersionId = this.rsaKeyVersionIdSign;
        String algorithm = "RSA_PKCS1_SHA_256";
        String message = "测试消息";
        byte[] signature = OpenApi.asymmetricSign(this.client, keyId, keyVersionId, algorithm, message);
        boolean ok = OpenApi.asymmetricVerify(this.client, keyId, keyVersionId, algorithm, message, signature);
        assertTrue(ok);
    }

    @org.junit.Test
    public void asymmetricVerify() throws DecoderException, ClientException, NoSuchAlgorithmException {
        byte[] signature = Hex.decodeHex("2a52bb2dadc47ee59f68f3bc95c17d0f03d10bc30cc46594cf45aa4760d4b790cf38758348f4860c5514f0934fbbbfc0a0882344fc580e2107193627a1462150e6e5f7230f192b90f10c8fb35b470b02760f907dd55a6de077fc8b23ab28d3711ff05cc5277fe392b3a678633dfb066faaef77325df109f24cc9257be41a5e8b7de824e75cd729502bb6c0ad88259424f49430df71082e36a8f7070ec530dc9bacb733f3ce221c84d4f36f12008a2b0e2fb5f17d68577b81f16ae26de48a3ef643f5dea09b407ea80b450056e6902b6de1b4cc8c4a8a12d857fa45011455f183bd6e05d88175fff9e91d51b7fae396655f0eeb53ed15846fe77929a99e8cf90d");
        String keyId = this.rsaKeyIdSign;
        String keyVersionId = this.rsaKeyVersionIdSign;
        String algorithm = "RSA_PKCS1_SHA_256";
        String message = "测试消息";
        boolean ok = OpenApi.asymmetricVerify(this.client, keyId, keyVersionId, algorithm, message, signature);
        assertTrue(ok);
    }

    @org.junit.Test
    public void listAliases() throws ClientException {
        String keyId = symmetricKeyId;
        String alias = "alias/testA";
        OpenApi.createAlias(this.client, alias, keyId);
        List<ListAliasesResponse.Alias> aliases = OpenApi.listAliases(this.client);
        OpenApi.deleteAlias(this.client, alias);
        assertNotNull(aliases);
    }

    @org.junit.Test
    public void listAliasesByKeyId() throws ClientException {
        String keyId = this.symmetricKeyId;
        String alias = "alias/testA";
        OpenApi.createAlias(this.client, alias, keyId);
        List<ListAliasesByKeyIdResponse.Alias> aliases = OpenApi.listAliasesByKeyId(this.client, keyId);
        OpenApi.deleteAlias(this.client, alias);
        assertNotNull(aliases);
    }

    @org.junit.Test
    public void listKeyVersions() throws ClientException {
        String keyId = this.rsaKeyId;
        List<ListKeyVersionsResponse.KeyVersion> keyVersions = OpenApi.listKeyVersions(this.client, keyId);
        assertNotNull(keyVersions);
    }

    @org.junit.Test
    public void listKeys() throws ClientException {
        List<String> keyIds = OpenApi.listKeys(this.client);
        assertNotNull(keyIds);
    }

    @org.junit.Test
    public void listResourceTags() throws ClientException {
        String keyId = this.symmetricKeyId;
        String tags = "[{\"TagKey\":\"testA\",\"TagValue\":\"123456\"},{\"TagKey\":\"testB\",\"TagValue\":\"abcdef\"}]";
        OpenApi.tagResource(this.client, keyId, tags);
        List<ListResourceTagsResponse.Tag> listTags = OpenApi.listResourceTags(this.client, keyId);
        String tagsKeys = "[\"testA\", \"testB\"]";
        OpenApi.untagResource(this.client, keyId, tagsKeys);
        assertNotNull(listTags);
    }

    @org.junit.Test
    public void rsaEncrypt() throws GeneralSecurityException, ClientException {
        String keyId = this.rsaKeyId;
        String keyVersionId = this.rsaKeyVersionId;
        String algorithm = "RSAES_OAEP_SHA_256";
        String message = "测试消息";
        byte[] cipherBlob = OpenApi.rsaEncrypt(this.client, keyId, keyVersionId, message, algorithm);
        byte[] plaintext = OpenApi.asymmetricDecrypt(this.client, cipherBlob, keyId, keyVersionId, algorithm);
        assertEquals(message, new String(plaintext, StandardCharsets.UTF_8));
    }

    @org.junit.Test
    public void rsaVerify() throws DecoderException, GeneralSecurityException, ClientException {
        byte[] signature = Hex.decodeHex("2a52bb2dadc47ee59f68f3bc95c17d0f03d10bc30cc46594cf45aa4760d4b790cf38758348f4860c5514f0934fbbbfc0a0882344fc580e2107193627a1462150e6e5f7230f192b90f10c8fb35b470b02760f907dd55a6de077fc8b23ab28d3711ff05cc5277fe392b3a678633dfb066faaef77325df109f24cc9257be41a5e8b7de824e75cd729502bb6c0ad88259424f49430df71082e36a8f7070ec530dc9bacb733f3ce221c84d4f36f12008a2b0e2fb5f17d68577b81f16ae26de48a3ef643f5dea09b407ea80b450056e6902b6de1b4cc8c4a8a12d857fa45011455f183bd6e05d88175fff9e91d51b7fae396655f0eeb53ed15846fe77929a99e8cf90d");
        String keyId = this.rsaKeyIdSign;
        String keyVersionId = this.rsaKeyVersionIdSign;
        String algorithm = "RSA_PKCS1_SHA_256";
        String message = "测试消息";
        boolean ok = OpenApi.rsaVerify(this.client, keyId, keyVersionId, message, signature, algorithm);
        assertTrue(ok);
    }

    @org.junit.Test
    public void ecdsaVerify() throws ClientException, GeneralSecurityException {
        //EC_P256
        String keyId = this.ecp256KeyId;
        String keyVersionId = this.ecp256KeyVersionId;
        String message = "测试消息";
        byte[] signature = OpenApi.asymmetricSign(this.client, keyId, keyVersionId, "ECDSA_SHA_256", message);
        boolean ok = OpenApi.ecdsaVerify(this.client, keyId, keyVersionId, message, signature);
        assertTrue(ok);

        //ECP256K
        keyId = this.ecp256kKeyId;
        keyVersionId = this.ecp256kKeyVersionId;
        signature = OpenApi.asymmetricSign(this.client, keyId, keyVersionId, "ECDSA_SHA_256", message);
        ok = OpenApi.ecdsaVerify(this.client, keyId, keyVersionId, message, signature);
        assertTrue(ok);
    }

    @org.junit.Test
    public void scheduleKeyDeletion() throws ClientException {
        String keyId = this.symmetricKeyId;
        Integer pendingWindowInDays = 7;
        OpenApi.scheduleKeyDeletion(this.client, keyId, pendingWindowInDays);
        DescribeKeyResponse response = OpenApi.describeKey(this.client, keyId);
        assertEquals("PendingDeletion", response.getKeyMetadata().getKeyState());
        OpenApi.cancelKeyDeletion(this.client, keyId);
    }

    @org.junit.Test
    public void tagResource() throws ClientException {
        String keyId = this.symmetricKeyId;
        String tags = "[{\"TagKey\":\"testA\",\"TagValue\":\"123456\"},{\"TagKey\":\"testB\",\"TagValue\":\"abcdef\"}]";

        OpenApi.tagResource(this.client, keyId, tags);
        List<ListResourceTagsResponse.Tag> listTags = OpenApi.listResourceTags(this.client, keyId);

        boolean ok = false;
        for (ListResourceTagsResponse.Tag tag : listTags) {
            if (tag.getKeyId().equals(keyId) && tag.getTagKey().equals("testA") && tag.getTagValue().equals("123456")) {
                ok = true;
                break;
            }
        }
        assertTrue(ok);

        String tagsKeys = "[\"testA\",\"testB\"]";
        OpenApi.untagResource(this.client, keyId, tagsKeys);
    }

    @org.junit.Test
    public void untagResource() throws ClientException {
        String keyId = this.symmetricKeyId;
        String tags = "[{\"TagKey\":\"testA\",\"TagValue\":\"123456\"},{\"TagKey\":\"testB\",\"TagValue\":\"abcdef\"}]";

        OpenApi.tagResource(this.client, keyId, tags);
        String tagsKeys = "[\"testA\",\"testB\"]";
        OpenApi.untagResource(this.client, keyId, tagsKeys);

        List<ListResourceTagsResponse.Tag> listTags = OpenApi.listResourceTags(this.client, keyId);
        boolean ok = false;
        for (ListResourceTagsResponse.Tag tag : listTags) {
            if (tag.getKeyId().equals(keyId) && tag.getTagKey().equals("testA") && tag.getTagValue().equals("123456")) {
                ok = true;
                break;
            }
        }
        assertFalse(ok);
    }

    @org.junit.Test
    public void updateAlias() throws ClientException {
        String keyId = this.symmetricKeyId;
        String alias = "alias/testA";
        OpenApi.createAlias(this.client, alias, keyId);
        keyId = this.rsaKeyId;
        OpenApi.updateAlias(this.client, alias, keyId);
        List<ListAliasesResponse.Alias> aliases = OpenApi.listAliases(this.client);
        boolean ok = false;
        for (ListAliasesResponse.Alias a : aliases) {
            if (a.getKeyId().equals(keyId) && a.getAliasName().equals(alias)) {
                ok = true;
                break;
            }
        }
        assertTrue(ok);
        OpenApi.deleteAlias(this.client, alias);
    }

    @org.junit.Test
    public void updateKeyDescription() throws ClientException {
        String keyId = this.symmetricKeyId;
        String newDescription = "update description test";
        DescribeKeyResponse response = OpenApi.describeKey(this.client, keyId);
        String oldDescription = response.getKeyMetadata().getDescription();
        if (oldDescription.equals("")) {
            oldDescription = " ";
        }
        OpenApi.updateKeyDescription(this.client, keyId, newDescription);
        response = OpenApi.describeKey(this.client, keyId);
        assertEquals(newDescription, response.getKeyMetadata().getDescription());
        OpenApi.updateKeyDescription(this.client, keyId, oldDescription);
    }

    @org.junit.Test
    public void updateRotationPolicy() throws ClientException {
        String keyId = this.symmetricKeyId;
        DescribeKeyResponse response = OpenApi.describeKey(this.client, keyId);
        String oldRotationInterval = response.getKeyMetadata().getRotationInterval();
        boolean enableAutomaticRotation = true;
        if (response.getKeyMetadata().getAutomaticRotation().equals("Enabled")) {
            enableAutomaticRotation = false;
        }
        OpenApi.updateRotationPolicy(this.client, keyId, enableAutomaticRotation, "604800s");
        response = OpenApi.describeKey(this.client, keyId);
        if (enableAutomaticRotation) {
            assertEquals("Enabled", response.getKeyMetadata().getAutomaticRotation());
            assertEquals("604800s", response.getKeyMetadata().getRotationInterval());
        } else {
            assertEquals("Disabled", response.getKeyMetadata().getAutomaticRotation());
        }
        OpenApi.updateRotationPolicy(this.client, keyId, !enableAutomaticRotation, oldRotationInterval);
    }
}
