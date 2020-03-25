package kms_api_samples

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	"github.com/stretchr/testify/assert"
)

const (
	AccessKeyId         = "AccessKeyId"
	AccessKeySecret     = "AccessKeySecret"
	RegionId            = "cn-hangzhou"
	symmetricKeyId      = "2fad5f44-9573-4f28-8956-666c52cc9fa9"
	rsaKeyId            = "a8c6eb76-278c-4f88-801b-8fb56e4c3019"
	rsaKeyVersionId     = "6f050e56-9b71-41db-8d48-5275855f1041"
	rsaKeyIdSign        = "bb974925-d7d2-48c3-b896-cb2a3f3f33bd"
	rsaKeyVersionIdSign = "d4229c1f-17ec-40df-bfe0-51667c6c78b6"
	ecp256KeyId         = "71032ff8-1803-426f-b5be-c57bdeee1080"
	ecp256KeyVersionId  = "529eb3e1-6ef5-4a47-bce4-4c86494ebc1c"
	ecp256kKeyId        = "842a6803-66b0-4849-a040-c09cb0ba1aa3"
	ecp256kKeyVersionId = "303cc3ed-ac14-4da7-8d88-7dfd7fe47aed"
	externalKeyId       = "4ffbf0c5-0324-4ccf-8ab7-547a3c148adb"
)

func createClient() (*kms.Client, error) {
	client, err := CreateKmsClient(RegionId, os.Getenv(AccessKeyId), os.Getenv(AccessKeySecret))
	if err != nil {
		return nil, err
	}
	//client.SetEndpointRules(map[string]string{RegionId: Host}, "openAPI", "public")
	return client, nil
}

func TestCancelKeyDeletion(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := symmetricKeyId

	keyMeta, err := DescribeKey(client, keyId)
	if err != nil {
		t.Errorf("DescribeKey(%s) error:%v", keyId, err)
	}

	if keyMeta.KeyState == "Enabled" {
		err = ScheduleKeyDeletion(client, keyId, 30)
		if err != nil {
			t.Errorf("ScheduleKeyDeletion(%s) error:%v", keyId, err)
		}
	}

	err = CancelKeyDeletion(client, keyId)
	if err != nil {
		t.Errorf("CancelKeyDeletion(%s) error:%v", keyId, err)
	}

	keyMeta, err = DescribeKey(client, keyId)
	if err != nil {
		t.Errorf("DescribeKey(%s) error:%v", keyId, err)
	}

	assert.Equal(t, "Enabled", keyMeta.KeyState, "key state should be Enabled")
}

func TestCreateAlias(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := symmetricKeyId
	alias := "alias/testA"

	err = CreateAlias(client, alias, keyId)
	if err != nil {
		t.Errorf("CreateAlias(%s, %s) error:%v", alias, keyId, err)
	}

	aliases, err := ListAliases(client)
	if err != nil {
		t.Errorf("ListAliases error:%v", err)
	}

	ok := false
	for _, v := range aliases {
		if v.KeyId == keyId && v.AliasName == alias {
			ok = true
			break
		}
	}

	assert.True(t, ok)

	err = DeleteAlias(client, alias)
	if err != nil {
		t.Errorf("DeleteAlias(%s) error:%v", alias, err)
	}
}

func TestCreateKey(t *testing.T) {
	t.Skip("Skipping")
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}
	response, err := CreateKey(client, "RSA_2048", "ENCRYPT/DECRYPT", "Aliyun_KMS")
	if err != nil {
		t.Errorf("CreateKey(%s, %s, %s) error:%v", "RSA_2048", "ENCRYPT/DECRYPT", "Aliyun_KMS", err)
	}
	assert.NotNil(t, response)
}

func TestCreateKeyVersion(t *testing.T) {
	t.Skip("Skipping")
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}
	keyId := rsaKeyId
	keyVersion, err := CreateKeyVersion(client, keyId)
	if err != nil {
		t.Errorf("CreateKeyVersion(%s) error:%v", keyId, err)
	}
	assert.NotNil(t, keyVersion)
}

func TestDeleteAlias(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := symmetricKeyId
	alias := "alias/testA"
	err = CreateAlias(client, alias, keyId)
	if err != nil {
		t.Errorf("CreateAlias(%s, %s) error:%v", alias, keyId, err)
	}

	err = DeleteAlias(client, alias)
	if err != nil {
		t.Errorf("DeleteAlias(%s) error:%v", alias, err)
	}

	aliases, err := ListAliases(client)
	if err != nil {
		t.Errorf("ListAliases error:%v", err)
	}

	ok := false
	for _, v := range aliases {
		if v.KeyId == keyId && v.AliasName == alias {
			ok = true
			break
		}
	}
	assert.False(t, ok)
}

func TestDeleteKeyMaterial(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := externalKeyId

	err = DeleteKeyMaterial(client, keyId)
	if err != nil {
		t.Errorf("DeleteKeyMaterial(%s) error:%v", keyId, err)
	}

	keyMeta, err := DescribeKey(client, keyId)
	if err != nil {
		t.Errorf("DescribeKey(%s) error:%v", keyId, err)
	}

	assert.Equal(t, "PendingImport", keyMeta.KeyState, "key state should be PendingImport")
}

func TestDescribeKey(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := externalKeyId

	keyMeta, err := DescribeKey(client, keyId)
	if err != nil {
		t.Errorf("DescribeKey(%s) error:%v", keyId, err)
	}

	a := assert.New(t)
	a.Equal("EXTERNAL", keyMeta.Origin, "key origin should be EXTERNAL")
	a.Equal("Aliyun_AES_256", keyMeta.KeySpec, "key spec should be Aliyun_AES_256")
}

func TestDescribeKeyVersion(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := rsaKeyId
	keyVersionId := rsaKeyVersionId

	keyVersion, err := DescribeKeyVersion(client, keyId, keyVersionId)
	if err != nil {
		t.Errorf("DescribeKeyVersion(%s, %s) error:%v", keyId, keyVersionId, err)
	}

	a := assert.New(t)
	a.Equal(keyId, keyVersion.KeyId, "keyId should be equal")
	a.Equal(keyVersionId, keyVersion.KeyVersionId, "keyVersionId should be equal")

}

func TestDescribeRegions(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}
	regions, err := DescribeRegions(client)
	if err != nil {
		t.Errorf("DescribeRegions() error:%v", err)
	}
	assert.Contains(t, regions, RegionId)
}

func TestDisableKey(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := symmetricKeyId

	err = DisableKey(client, keyId)
	if err != nil {
		t.Errorf("DisableKey(%s) error:%v", keyId, err)
	}

	keyMeta, err := DescribeKey(client, keyId)
	if err != nil {
		t.Errorf("DescribeKey(%s) error:%v", keyId, err)
	}

	assert.Equal(t, "Disabled", keyMeta.KeyState, "key state should be Disabled")

	err = EnableKey(client, keyId)
	if err != nil {
		t.Errorf("EnableKey(%s) error:%v", keyId, err)
	}

}

func TestEcP256Verify(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := ecp256KeyId
	keyVersionId := ecp256KeyVersionId
	message := "测试消息"

	signature, err := AsymmetricSign(client, keyId, keyVersionId, message, "ECDSA_SHA_256")
	if err != nil {
		t.Errorf("AsymmetricSign(%s,%s,%s,%s) error:%v", keyId, keyVersionId, message, "ECDSA_SHA_256", err)
	}

	err = EcP256Verify(client, keyId, keyVersionId, message, signature)
	if err != nil {
		t.Errorf("EcP256Verify(%s,%s,%s,%s) error:%v", keyId, keyVersionId, message, string(signature), err)
	}
}

func TestEcP256KVerify(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := ecp256kKeyId
	keyVersionId := ecp256kKeyVersionId
	message := "测试消息"

	signature, err := AsymmetricSign(client, keyId, keyVersionId, message, "ECDSA_SHA_256")
	if err != nil {
		t.Errorf("AsymmetricSign(%s,%s,%s,%s) error:%v", keyId, keyVersionId, message, "ECDSA_SHA_256", err)
	}

	err = EcP256KVerify(client, keyId, keyVersionId, message, signature)
	if err != nil {
		t.Errorf("EcP256KVerify(%s,%s,%s,%s) error:%v", keyId, keyVersionId, message, string(signature), err)
	}
}

func TestEnableKey(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := symmetricKeyId
	err = DisableKey(client, keyId)
	if err != nil {
		t.Errorf("DisableKey(%s) error:%v", keyId, err)
	}

	err = EnableKey(client, keyId)
	if err != nil {
		t.Errorf("EnableKey(%s) error:%v", keyId, err)
	}

	keyMeta, err := DescribeKey(client, keyId)
	if err != nil {
		t.Errorf("DescribeKey(%s) error:%v", keyId, err)
	}

	assert.Equal(t, "Enabled", keyMeta.KeyState, "key state should be Enabled")

}

func TestGenerateDataKey(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := symmetricKeyId
	message := []byte("测试消息")

	plainKey, cipherBlobKey, err := GenerateDataKey(client, keyId)
	if err != nil {
		t.Errorf("GenerateDataKey(%s) error:%v", keyId, err)
	}
	key, err := base64.StdEncoding.DecodeString(plainKey)
	if err != nil {
		t.Errorf("base64.StdEncoding.DecodeString(%s) error:%v", plainKey, err)
	}

	//加密明文
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf("aes.NewCipher(%v) error:%v", key, err)
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Errorf("io.ReadFull error:%v", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Errorf("cipher.NewGCM error:%v", err)
	}
	ciphertext := aesgcm.Seal(nil, nonce, message, nil)

	//解密数据密钥
	plainKey2, err := Decrypt(client, cipherBlobKey)
	if err != nil {
		t.Errorf("Decrypt error:%v", err)
	}
	key, err = base64.StdEncoding.DecodeString(plainKey2)
	if err != nil {
		t.Errorf("base64.StdEncoding.DecodeString(%s) error:%v", plainKey, err)
	}

	//解密密文
	block, err = aes.NewCipher(key)
	if err != nil {
		t.Errorf("aes.NewCipher(%v) error:%v", key, err)
	}
	aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		t.Errorf("cipher.NewGCM error:%v", err)
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Errorf("aesgcm.Open error:%v", err)
	}

	assert.Equal(t, message, plaintext, "the plaintext should be equal message")

}

func TestGenerateDataKeyWithoutPlaintext(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := symmetricKeyId
	message := []byte("测试消息")

	cipherBlobKey, err := GenerateDataKeyWithoutPlaintext(client, keyId)
	if err != nil {
		t.Errorf("GenerateDataKeyWithoutPlaintext(%s) error:%v", keyId, err)
	}

	plainKey, err := Decrypt(client, cipherBlobKey)
	if err != nil {
		t.Errorf("Decrypt error:%v", err)
	}
	key, err := base64.StdEncoding.DecodeString(plainKey)
	if err != nil {
		t.Errorf("base64.StdEncoding.DecodeString(%s) error:%v", plainKey, err)
	}

	//加密明文
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf("aes.NewCipher(%v) error:%v", key, err)
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Errorf("io.ReadFull error:%v", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Errorf("cipher.NewGCM error:%v", err)
	}
	ciphertext := aesgcm.Seal(nil, nonce, message, nil)
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Errorf("aesgcm.Open error:%v", err)
	}

	assert.Equal(t, message, plaintext, "the plaintext should be equal message")

}

func TestGetParametersForImport(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := externalKeyId
	pubKeySpec := "RSA_2048"
	algorithm := "RSAES_OAEP_SHA_256"

	publicKey, importToken, err := GetParametersForImport(client, keyId, pubKeySpec, algorithm)
	if err != nil {
		t.Errorf("GetParametersForImport error:%v", err)
	}
	assert.NotNil(t, publicKey)
	assert.NotNil(t, importToken)

}

func TestGetAsymmetricPublicKey(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := rsaKeyId
	keyVersionId := rsaKeyVersionId

	public, err := GetAsymmetricPublicKey(client, keyId, keyVersionId)
	if err != nil {
		t.Errorf("GetAsymmetricPublicKey error:%v", err)
	}

	block, _ := pem.Decode([]byte(public))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatal("failed to decode public key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParsePKIXPublicKey error:%v", err)
	}

	assert.Equal(t, "*rsa.PublicKey", reflect.TypeOf(publicKey).String(), "the type of publicKey should be *rsa.PublicKey")

}

func TestAsymmetricDecrypt(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	cipherBlob, _ := hex.DecodeString("933acfe6227de6712bdd56d76518eafa419528fe438c2642f216a2817bbf7ceb6b058f2503f37c3b0e7c226ffd87503a106a65ab73e0dc343d6cf161893d04f889880d4c2870f52f33cccfd8269a763d8730353a010b1c932636556f64b3b9bece7bcea3c919ed9c1f45b5a203a891b4650209b3def42005c3106df1362c4d1b5bd168339acaec77f0e5242436e878edcb5dfd51baed2f5a453768fac5b011ecc06f1c0bfa56bb4edb67ce16ae8ce8715f274e9285dbc1d9988298d8c9bfa2586147eba9e8e46e9f306866fe5994611b5d15dbc6e5fd7dc3d105e5d9ff8438924fee16feedaf1ec8cb446ef2e918fdfb1597a93e82591689bac7d7e1d6fbe1af")
	keyId := rsaKeyId
	keyVersionId := rsaKeyVersionId
	algorithm := "RSAES_OAEP_SHA_256"
	message := "测试消息"

	plaintext, err := AsymmetricDecrypt(client, keyId, keyVersionId, cipherBlob, algorithm)
	if err != nil {
		t.Errorf("AsymmetricDecrypt(%s,%s,%v,%s) error:%v", keyId, keyVersionId, cipherBlob, algorithm, err)
	}

	assert.Equal(t, message, plaintext)

}

func TestDecrypt(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	cipherBlob := "MzkyN2FmNmUtNTk3NC00MzZkLWE1YzYtY2UzMTRjOTM2ZTdhXdvyW6fEVxDs0uP1D89aUzsdqGmk3/Rfg9V5lND6oNLX8/tXCRG7sZFocuE="
	message := "测试消息"

	base64Plaintext, err := Decrypt(client, cipherBlob)
	if err != nil {
		t.Errorf("Decrypt(%v) error:%v", cipherBlob, err)
	}
	plaintext, err := base64.StdEncoding.DecodeString(base64Plaintext)
	if err != nil {
		t.Errorf("base64.StdEncoding.DecodeString(%s) error:%v", base64Plaintext, err)
	}

	assert.Equal(t, message, string(plaintext))

}

func TestAsymmetricEncrypt(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := rsaKeyId
	keyVersionId := rsaKeyVersionId
	algorithm := "RSAES_OAEP_SHA_256"
	message := "测试消息"

	cipherBlob, err := AsymmetricEncrypt(client, keyId, keyVersionId, message, algorithm)
	if err != nil {
		t.Errorf("AsymmetricEncrypt(%s,%s,%s,%s) error:%v", keyId, keyVersionId, message, algorithm, err)
	}

	plaintext, err := AsymmetricDecrypt(client, keyId, keyVersionId, cipherBlob, algorithm)
	if err != nil {
		t.Errorf("AsymmetricDecrypt(%s,%s,%v,%s) error:%v", keyId, keyVersionId, cipherBlob, algorithm, err)
	}

	assert.Equal(t, message, plaintext)

}

func TestEncrypt(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := symmetricKeyId
	message := "测试消息"

	base64Plaintext := base64.StdEncoding.EncodeToString([]byte(message))
	cipherBlob, err := Encrypt(client, keyId, base64Plaintext)
	if err != nil {
		t.Errorf("Encrypt(%s,%s) error:%v", keyId, message, err)
	}

	base64Plaintext, err = Decrypt(client, cipherBlob)
	if err != nil {
		t.Errorf("Decrypt(%s) error:%v", cipherBlob, err)
	}
	plaintext, err := base64.StdEncoding.DecodeString(base64Plaintext)
	if err != nil {
		t.Errorf("base64.StdEncoding.DecodeString(%s) error:%v", base64Plaintext, err)
	}

	assert.Equal(t, message, string(plaintext))

}

func TestAsymmetricSign(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := rsaKeyIdSign
	keyVersionId := rsaKeyVersionIdSign
	algorithm := "RSA_PKCS1_SHA_256"
	message := "测试消息"

	signature, err := AsymmetricSign(client, keyId, keyVersionId, message, algorithm)
	if err != nil {
		t.Errorf("AsymmetricSign(%s,%s,%s,%s) error:%v", keyId, keyVersionId, message, algorithm, err)
	}
	ok, err := AsymmetricVerify(client, keyId, keyVersionId, message, signature, algorithm)
	if err != nil {
		t.Errorf("AsymmetricVerify(%s,%s,%s,%v,%s) error:%v", keyId, keyVersionId, message, signature, algorithm, err)
	}
	assert.True(t, ok, "the result of verify should be True")

}

func TestAsymmetricVerify(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := hex.DecodeString("2a52bb2dadc47ee59f68f3bc95c17d0f03d10bc30cc46594cf45aa4760d4b790cf38758348f4860c5514f0934fbbbfc0a0882344fc580e2107193627a1462150e6e5f7230f192b90f10c8fb35b470b02760f907dd55a6de077fc8b23ab28d3711ff05cc5277fe392b3a678633dfb066faaef77325df109f24cc9257be41a5e8b7de824e75cd729502bb6c0ad88259424f49430df71082e36a8f7070ec530dc9bacb733f3ce221c84d4f36f12008a2b0e2fb5f17d68577b81f16ae26de48a3ef643f5dea09b407ea80b450056e6902b6de1b4cc8c4a8a12d857fa45011455f183bd6e05d88175fff9e91d51b7fae396655f0eeb53ed15846fe77929a99e8cf90d")
	keyId := rsaKeyIdSign
	keyVersionId := rsaKeyVersionIdSign
	algorithm := "RSA_PKCS1_SHA_256"
	message := "测试消息"

	ok, err := AsymmetricVerify(client, keyId, keyVersionId, message, signature, algorithm)
	if err != nil {
		t.Errorf("AsymmetricVerify(%s,%s,%s,%v,%s) error:%v", keyId, keyVersionId, message, signature, algorithm, err)
	}
	assert.True(t, ok, "the result of verify should be True")
}

func TestListAliases(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := symmetricKeyId
	alias := "alias/testA"

	err = CreateAlias(client, alias, keyId)
	if err != nil {
		t.Errorf("CreateAlias(%s, %s) error:%v", alias, keyId, err)
	}

	aliases, err := ListAliases(client)
	if err != nil {
		t.Errorf("ListAliases() error:%v", err)
	}

	err = DeleteAlias(client, alias)
	if err != nil {
		t.Errorf("DeleteAlias(%s) error:%v", alias, err)
	}

	assert.NotEmpty(t, aliases)
}

func TestListAliasesByKeyId(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := symmetricKeyId
	alias := "alias/testA"
	err = CreateAlias(client, alias, keyId)
	if err != nil {
		t.Errorf("CreateAlias(%s, %s) error:%v", alias, keyId, err)
	}

	aliases, err := ListAliasesByKeyId(client, keyId)
	if err != nil {
		t.Errorf("ListAliases() error:%v", err)
	}

	err = DeleteAlias(client, alias)
	if err != nil {
		t.Errorf("DeleteAlias(%s) error:%v", alias, err)
	}

	assert.NotEmpty(t, aliases)
}

func TestListKeyVersions(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := rsaKeyId

	keyVersions, err := ListKeyVersions(client, keyId)
	if err != nil {
		t.Errorf("ListKeyVersions() error:%v", err)
	}

	assert.NotEmpty(t, keyVersions, "keyVersions should be not empty")

}

func TestListKeys(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyIds, err := ListKeys(client)
	if err != nil {
		t.Errorf("ListKeys() error:%v", err)
	}

	assert.NotEmpty(t, keyIds)
}

func TestListResourceTags(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := symmetricKeyId
	tags := `[{"TagKey":"testA","TagValue":"123456"},{"TagKey":"testB","TagValue":"abcdef"}]`

	err = TagResource(client, keyId, tags)
	if err != nil {
		t.Errorf("TagResource(%s,%s) error:%v", keyId, tags, err)
	}

	tagLists, err := ListResourceTags(client, keyId)
	if err != nil {
		t.Errorf("ListResourceTags(%s) error:%v", keyId, err)
	}

	assert.NotEmpty(t, tagLists, "tags should be not empty")

	tagsKeys := `["testA","testB"]`
	err = UntagResource(client, keyId, tagsKeys)
	if err != nil {
		t.Errorf("UntagResource(%s,%s) error:%v", keyId, tagsKeys, err)
	}

}

func TestRsaEncrypt(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := rsaKeyId
	keyVersionId := rsaKeyVersionId
	algorithm := "RSAES_OAEP_SHA_256"
	message := "测试消息"

	cipherBlob, err := RsaEncrypt(client, keyId, keyVersionId, message, algorithm)
	if err != nil {
		t.Errorf("RsaEncrypt(%s,%s,%s,%s) error:%v", keyId, keyVersionId, message, algorithm, err)
	}

	plaintext, err := AsymmetricDecrypt(client, keyId, keyVersionId, cipherBlob, algorithm)
	if err != nil {
		t.Errorf("AsymmetricDecrypt(%s,%s,%v,%s) error:%v", keyId, keyVersionId, cipherBlob, algorithm, err)
	}

	assert.Equal(t, message, plaintext)

}

func TestRsaVerify(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	signature, _ := hex.DecodeString("2a52bb2dadc47ee59f68f3bc95c17d0f03d10bc30cc46594cf45aa4760d4b790cf38758348f4860c5514f0934fbbbfc0a0882344fc580e2107193627a1462150e6e5f7230f192b90f10c8fb35b470b02760f907dd55a6de077fc8b23ab28d3711ff05cc5277fe392b3a678633dfb066faaef77325df109f24cc9257be41a5e8b7de824e75cd729502bb6c0ad88259424f49430df71082e36a8f7070ec530dc9bacb733f3ce221c84d4f36f12008a2b0e2fb5f17d68577b81f16ae26de48a3ef643f5dea09b407ea80b450056e6902b6de1b4cc8c4a8a12d857fa45011455f183bd6e05d88175fff9e91d51b7fae396655f0eeb53ed15846fe77929a99e8cf90d")
	keyId := rsaKeyIdSign
	keyVersionId := rsaKeyVersionIdSign
	algorithm := "RSA_PKCS1_SHA_256"
	message := "测试消息"

	err = RsaVerify(client, keyId, keyVersionId, message, signature, algorithm)
	if err != nil {
		t.Errorf("RsaVerify(%s,%s,%s,%v,%s) error:%v", keyId, keyVersionId, message, signature, algorithm, err)
	}
}

func TestScheduleKeyDeletion(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := symmetricKeyId
	pendingWindowInDays := 7

	err = ScheduleKeyDeletion(client, keyId, pendingWindowInDays)
	if err != nil {
		t.Errorf("ScheduleKeyDeletion(%s,%d) error:%v", keyId, pendingWindowInDays, err)
	}

	keyMeta, err := DescribeKey(client, keyId)
	if err != nil {
		t.Errorf("DescribeKey(%s) error:%v", keyId, err)
	}

	assert.Equal(t, "PendingDeletion", keyMeta.KeyState, "key state should be PendingDeletion")

	err = CancelKeyDeletion(client, keyId)
	if err != nil {
		t.Errorf("CancelKeyDeletion(%s) error:%v", keyId, err)
	}

}

func TestTagResource(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := symmetricKeyId
	tags := `[{"TagKey":"testA","TagValue":"123456"},{"TagKey":"testB","TagValue":"abcdef"}]`

	err = TagResource(client, keyId, tags)
	if err != nil {
		t.Errorf("TagResource(%s,%v) error:%v", keyId, tags, err)
	}

	tagLists, err := ListResourceTags(client, keyId)
	if err != nil {
		t.Errorf("ListResourceTags(%s) error:%v", keyId, err)
	}

	tag := kms.Tag{KeyId: keyId, TagKey: "testA", TagValue: "123456"}
	assert.Contains(t, tagLists, tag)

	tag = kms.Tag{KeyId: keyId, TagKey: "testB", TagValue: "abcdef"}
	assert.Contains(t, tagLists, tag)

	tagsKeys := `["testA","testB"]`
	err = UntagResource(client, keyId, tagsKeys)
	if err != nil {
		t.Errorf("UntagResource(%s,%s) error:%v", keyId, tagsKeys, err)
	}

}

func TestUntagResource(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := symmetricKeyId
	tags := `[{"TagKey":"testA","TagValue":"123456"},{"TagKey":"testB","TagValue":"abcdef"}]`

	err = TagResource(client, keyId, tags)
	if err != nil {
		t.Errorf("TagResource(%s,%v) error:%v", keyId, tags, err)
	}

	tagsKeys := `["testA","testB"]`
	err = UntagResource(client, keyId, tagsKeys)
	if err != nil {
		t.Errorf("UntagResource(%s,%s) error:%v", keyId, tagsKeys, err)
	}

	tagLists, err := ListResourceTags(client, keyId)
	if err != nil {
		t.Errorf("ListResourceTags(%s) error:%v", keyId, err)
	}

	tag := kms.Tag{KeyId: keyId, TagKey: "testA", TagValue: "123456"}
	assert.NotContains(t, tagLists, tag)

	tag = kms.Tag{KeyId: keyId, TagKey: "testB", TagValue: "abcdef"}
	assert.NotContains(t, tagLists, tag)

}

func TestUpdateAlias(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := symmetricKeyId
	alias := "alias/testA"

	err = CreateAlias(client, alias, keyId)
	if err != nil {
		t.Errorf("CreateAlias(%s, %s) error:%v", alias, keyId, err)
	}

	keyId = rsaKeyId
	err = UpdateAlias(client, alias, keyId) //将别名映射到其他主密钥
	if err != nil {
		t.Errorf("UpdateAlias error:%v", err)
	}

	aliases, err := ListAliases(client)
	if err != nil {
		t.Errorf("ListAliases error:%v", err)
	}

	in := func(l []kms.Alias, keyId, aliasName string) bool {
		for _, v := range l {
			if v.KeyId == keyId && v.AliasName == aliasName {
				return true
			}
		}
		return false
	}
	if ok := in(aliases, keyId, alias); !ok {
		t.Errorf("update alias failed")
	}

	err = DeleteAlias(client, alias)
	if err != nil {
		t.Errorf("DeleteAlias(%s) error:%v", alias, err)
	}

}

func TestUpdateKeyDescription(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := symmetricKeyId
	newDescription := "update description test"

	keyMeta, err := DescribeKey(client, keyId)
	if err != nil {
		t.Errorf("DescribeKey(%s) error:%v", keyId, err)
	}
	oldDescription := keyMeta.Description
	if len(oldDescription) <= 0 {
		oldDescription = " "
	}

	err = UpdateKeyDescription(client, keyId, newDescription)
	if err != nil {
		t.Errorf("UpdateKeyDescription(%s,%s) error:%v", keyId, newDescription, err)
	}

	keyMeta, err = DescribeKey(client, keyId)
	if err != nil {
		t.Errorf("DescribeKey(%s) error:%v", keyId, err)
	}

	assert.Equal(t, newDescription, keyMeta.Description, "key description should be \"update description test\"")

	err = UpdateKeyDescription(client, keyId, oldDescription)
	if err != nil {
		t.Errorf("UpdateKeyDescription(%s,%s) error:%v", keyId, oldDescription, err)
	}

}

func TestUpdateRotationPolicy(t *testing.T) {
	client, err := createClient()
	if err != nil {
		t.Fatal(err)
	}

	keyId := symmetricKeyId

	keyMeta, err := DescribeKey(client, keyId)
	if err != nil {
		t.Errorf("DescribeKey(%s) error:%v", keyId, err)
	}

	enableAutomaticRotation := true
	oldRotationInterval := keyMeta.RotationInterval

	if keyMeta.AutomaticRotation == "Enabled" {
		enableAutomaticRotation = false
	}

	err = UpdateRotationPolicy(client, keyId, enableAutomaticRotation, "604800s")
	if err != nil {
		t.Errorf("UpdateRotationPolicy(%s,%v,%s) error:%v", keyId, enableAutomaticRotation, "7d", err)
	}

	keyMeta, err = DescribeKey(client, keyId)
	if err != nil {
		t.Errorf("DescribeKey(%s) error:%v", keyId, err)
	}
	if enableAutomaticRotation {
		assert.Equal(t, "Enabled", keyMeta.AutomaticRotation, "AutomaticRotation should be Enabled")
		assert.Equal(t, "604800s", keyMeta.RotationInterval, "RotationInterval should be 604800s")
	} else {
		assert.Equal(t, "Disabled", keyMeta.AutomaticRotation, "AutomaticRotation should be Disabled")
	}

	err = UpdateRotationPolicy(client, keyId, !enableAutomaticRotation, oldRotationInterval)
	if err != nil {
		t.Errorf("UpdateRotationPolicy(%s,%v,%s) error:%v", keyId, enableAutomaticRotation, oldRotationInterval, err)
	}

}
