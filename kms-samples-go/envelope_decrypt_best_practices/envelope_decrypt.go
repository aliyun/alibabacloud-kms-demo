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

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

const (
	AccessKeyId     = "AccessKeyId"
	AccessKeySecret = "AccessKeySecret"
	RegionId        = "cn-hangzhou"
)

func kmsDecrypt(client *kms.Client, cipherTextBlob string) (string, error) {
	request := kms.CreateDecryptRequest()
	request.Scheme = "https"
	request.CiphertextBlob = cipherTextBlob
	response, err := client.Decrypt(request)
	if err != nil {
		return "", fmt.Errorf("decrypt error:%v", err)
	}
	return response.Plaintext, nil
}

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
	err = ioutil.WriteFile(outFile, plaintext, 0644)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	client, err := kms.NewClientWithAccessKey(RegionId, os.Getenv(AccessKeyId), os.Getenv(AccessKeySecret))
	if err != nil {
		log.Fatalf("createKmsClient error:%+v\n", err)
	}

	inFile := "./data/sales.csv.cipher"
	outFile := "./data/decrypted_sales.csv"

	//Read encrypted file
	inContent, err := ioutil.ReadFile(inFile)
	if err != nil {
		log.Fatalf("ioutil.ReadFile error:%+v\n", err)
	}
	inLines := strings.Split(string(inContent), "\n")

	//Decrypt data key
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

	err = localDecrypt(key, nonce, cipherText, outFile)
	if err != nil {
		log.Fatalf("localEncrypt error:%+v\n", err)
	}
}
