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

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

const (
	AccessKeyId     = "AccessKeyId"
	AccessKeySecret = "AccessKeySecret"
	RegionId        = "cn-hangzhou"
)

func kmsGenerateDataKey(client *kms.Client, keyAlias string) (string, string, error) {
	request := kms.CreateGenerateDataKeyRequest()
	request.Scheme = "https"
	request.KeyId = keyAlias
	request.NumberOfBytes = "32"
	response, err := client.GenerateDataKey(request)
	if err != nil {
		return "", "", fmt.Errorf("GenerateDataKey error:%v", err)
	}
	return response.Plaintext, response.CiphertextBlob, nil
}

//Out file format (text)
//Line 1: b64 encoded data key
//Line 2: b64 encoded IV
//Line 3: b64 encoded ciphertext
func localEncrypt(plainKey, encryptedKey, inFile, outFile string) error {
	key, err := base64.StdEncoding.DecodeString(plainKey)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, 12)
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

	err = ioutil.WriteFile(outFile, []byte(lines), 0644)
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

	keyAlias := "alias/Apollo/WorkKey"
	inFile := "./data/sales.csv"
	outFile := "./data/sales.csv.cipher"

	//Generate Data Key
	plainKey, cipherBlobKey, err := kmsGenerateDataKey(client, keyAlias)
	if err != nil {
		log.Fatalf("kmsGenerateDataKey error:%+v\n", err)
	}

	err = localEncrypt(plainKey, cipherBlobKey, inFile, outFile)
	if err != nil {
		log.Fatalf("localEncrypt error:%+v\n", err)
	}
}
