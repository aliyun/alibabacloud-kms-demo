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

func main() {
	client, err := kms.NewClientWithAccessKey(RegionId, os.Getenv(AccessKeyId), os.Getenv(AccessKeySecret))
	if err != nil {
		log.Fatalf("NewClientWithAccessKey error:%+v\n", err)
	}

	inFile := "./certs/key.pem.cipher"
	outFile := "./certs/decrypted_key.pem.cipher"

	//Read encrypted key file in text mode
	inContent, err := ioutil.ReadFile(inFile)
	if err != nil {
		log.Fatalf("ioutil.ReadFile error:%+v\n", err)
	}

	//Decrypt
	base64Text, err := kmsDecrypt(client, string(inContent))
	if err != nil {
		log.Fatalf("kmsEncrypt error:%+v\n", err)
	}

	//这里使用base64解码是因为加密时明文进行了base64编码
	cipherText, err := base64.StdEncoding.DecodeString(base64Text)
	if err != nil {
		log.Fatalf("base64.StdEncoding.DecodeString error:%+v\n", err)
	}

	//Write Decrypted key file in text mode
	err = ioutil.WriteFile(outFile, []byte(cipherText), 0644)
	if err != nil {
		log.Fatalf("ioutil.WriteFile error:%+v\n", err)
	}
}
