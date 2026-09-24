package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	kms20160120 "github.com/alibabacloud-go/kms-20160120/v3/client"
	"github.com/alibabacloud-go/tea/tea"
)

const (
	// 如果kms实例开启公网访问，endpoint 请参考 https://api.aliyun.com/product/Kms
	// 如果kms实例未开启公网访问，endpoint 请使用实例VPC地址
	Endpoint = "<your kms endpoint>"
	// 填写您在KMS创建的对称主密钥Id，也可以使用密钥别名（如alias/Example）
	KeyId = "<your cmk id>"
	// 数据密钥长度，32字节（256位）AES密钥
	NumberOfBytes = 32
	// GCM模式初始向量长度
	gcmNonceLength = 12
)

// 使用阿里云SDK V2（kms-20160120）创建KMS Client
func createKmsClient() (*kms20160120.Client, error) {
	config := &openapi.Config{
		// 必填，请确保代码运行环境设置了环境变量 ALIBABA_CLOUD_ACCESS_KEY_ID。
		AccessKeyId: tea.String(os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID")),
		// 必填，请确保代码运行环境设置了环境变量 ALIBABA_CLOUD_ACCESS_KEY_SECRET。
		AccessKeySecret: tea.String(os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET")),
	}
	// Endpoint 请参考 https://api.aliyun.com/product/Kms
	config.Endpoint = tea.String(Endpoint)
	// 如果使用实例专属网关并且验证服务端证书，请设置ca证书
	//config.Ca = tea.String("<your kms ca>")
	return kms20160120.NewClient(config)
}

// 调用GenerateDataKey接口生成数据密钥，返回数据密钥明文与数据密钥密文（均为Base64编码）
func kmsGenerateDataKey(client *kms20160120.Client, keyId string) (string, string, error) {
	request := &kms20160120.GenerateDataKeyRequest{
		KeyId:         tea.String(keyId),
		NumberOfBytes: tea.Int32(NumberOfBytes),
	}
	response, err := client.GenerateDataKey(request)
	if err != nil {
		return "", "", fmt.Errorf("GenerateDataKey error:%v", err)
	}
	return tea.StringValue(response.Body.Plaintext), tea.StringValue(response.Body.CiphertextBlob), nil
}

// 使用数据密钥明文在本地以AES-GCM模式加密数据。
// 加密完成后数据密钥明文应立即销毁，仅持久化数据密钥密文（信封）。
//
// Out file format (text)
// Line 1: b64 encoded encrypted data key (envelope)
// Line 2: b64 encoded IV
// Line 3: b64 encoded ciphertext (GCM authentication tag appended)
func localEncrypt(plainKey, encryptedKey, inFile, outFile string) error {
	key, err := base64.StdEncoding.DecodeString(plainKey)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcmNonceLength)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	inContent, err := ioutil.ReadFile(inFile)
	if err != nil {
		return err
	}
	cipherText := aesgcm.Seal(nil, nonce, inContent, nil)
	b64CipherText := base64.StdEncoding.EncodeToString(cipherText)
	b64Nonce := base64.StdEncoding.EncodeToString(nonce)
	lines := encryptedKey + "\n" + b64Nonce + "\n" + b64CipherText

	return ioutil.WriteFile(outFile, []byte(lines), 0644)
}

func main() {
	client, err := createKmsClient()
	if err != nil {
		log.Fatalf("createKmsClient error:%+v\n", err)
	}

	inFile := "./data/sales.csv"
	outFile := "./data/sales.csv.cipher"

	// 1.调用GenerateDataKey接口生成数据密钥
	plainKey, cipherBlobKey, err := kmsGenerateDataKey(client, KeyId)
	if err != nil {
		log.Fatalf("kmsGenerateDataKey error:%+v\n", err)
	}

	// 2.使用数据密钥明文在本地加密数据，数据密钥密文作为信封与数据密文一起保存
	err = localEncrypt(plainKey, cipherBlobKey, inFile, outFile)
	if err != nil {
		log.Fatalf("localEncrypt error:%+v\n", err)
	}
}
