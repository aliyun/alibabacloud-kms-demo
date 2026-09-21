package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	kms20160120 "github.com/alibabacloud-go/kms-20160120/v3/client"
	"github.com/alibabacloud-go/tea/tea"
)

const (
	// 如果kms实例开启公网访问，endpoint 请参考 https://api.aliyun.com/product/Kms
	// 如果kms实例未开启公网访问，endpoint 请使用实例VPC地址
	Endpoint = "<your kms endpoint>"
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

// 调用Decrypt接口解密数据密钥密文，返回数据密钥明文（Base64编码）
func kmsDecrypt(client *kms20160120.Client, cipherTextBlob string) (string, error) {
	request := &kms20160120.DecryptRequest{
		CiphertextBlob: tea.String(cipherTextBlob),
	}
	response, err := client.Decrypt(request)
	if err != nil {
		return "", fmt.Errorf("Decrypt error:%v", err)
	}
	return tea.StringValue(response.Body.Plaintext), nil
}

// 使用数据密钥明文在本地以AES-GCM模式解密数据
func localDecrypt(dataKey, nonce, cipherText []byte, outFile string) error {
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	plaintext, err := aesgcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(outFile, plaintext, 0644)
}

func main() {
	client, err := createKmsClient()
	if err != nil {
		log.Fatalf("createKmsClient error:%+v\n", err)
	}

	inFile := "./data/sales.csv.cipher"
	outFile := "./data/decrypted_sales.csv"

	// 1.读取信封文件：数据密钥密文、IV、数据密文
	inContent, err := ioutil.ReadFile(inFile)
	if err != nil {
		log.Fatalf("ioutil.ReadFile error:%+v\n", err)
	}
	inLines := strings.Split(string(inContent), "\n")

	// 2.调用Decrypt接口解密数据密钥密文，得到数据密钥明文
	plainKey, err := kmsDecrypt(client, inLines[0])
	if err != nil {
		log.Fatalf("kmsDecrypt error:%+v\n", err)
	}
	key, err := base64.StdEncoding.DecodeString(plainKey)
	if err != nil {
		log.Fatalf("base64.StdEncoding.DecodeString(%s) error:%+v\n", plainKey, err)
	}
	nonce, err := base64.StdEncoding.DecodeString(inLines[1])
	if err != nil {
		log.Fatalf("base64.StdEncoding.DecodeString(%s) error:%+v\n", inLines[1], err)
	}
	cipherText, err := base64.StdEncoding.DecodeString(inLines[2])
	if err != nil {
		log.Fatalf("base64.StdEncoding.DecodeString(%s) error:%+v\n", inLines[2], err)
	}

	// 3.使用数据密钥明文在本地解密数据密文
	err = localDecrypt(key, nonce, cipherText, outFile)
	if err != nil {
		log.Fatalf("localDecrypt error:%+v\n", err)
	}
}
