package main

import (
	"encoding/base64"
	"fmt"
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

func kmsEncrypt(client *kms.Client, plaintext, keyAlias string) (string, error) {
	request := kms.CreateEncryptRequest()
	request.Scheme = "https"
	request.KeyId = keyAlias
	request.Plaintext = plaintext
	response, err := client.Encrypt(request)
	if err != nil {
		return "", fmt.Errorf("encrypt error:%v", err)
	}
	return response.CiphertextBlob, nil
}

func main() {
	client, err := kms.NewClientWithAccessKey(RegionId, os.Getenv(AccessKeyId), os.Getenv(AccessKeySecret))
	if err != nil {
		log.Fatalf("NewClientWithAccessKey error:%+v\n", err)
	}

	keyAlias := "alias/Apollo/WorkKey"
	inFile := "./certs/key.pem"
	outFile := "./certs/key.pem.cipher"

	//Read private key file in text mode
	inContent, err := ioutil.ReadFile(inFile)
	if err != nil {
		log.Fatalf("ioutil.ReadFile error:%+v\n", err)
	}

	//Encrypt
	base64Content := base64.StdEncoding.EncodeToString(inContent)
	cipherText, err := kmsEncrypt(client, base64Content, keyAlias)
	if err != nil {
		log.Fatalf("kmsEncrypt error:%+v\n", err)
	}

	//Write encrypted key file in text mode
	err = ioutil.WriteFile(outFile, []byte(cipherText), 0644)
	if err != nil {
		log.Fatalf("ioutil.WriteFile error:%+v\n", err)
	}
}
