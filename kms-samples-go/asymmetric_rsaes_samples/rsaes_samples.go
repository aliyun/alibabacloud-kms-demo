package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"code-samples/kms-samples-go/kms_api_samples"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

const (
	AccessKeyId     = "AccessKeyId"
	AccessKeySecret = "AccessKeySecret"
	RegionId        = "cn-hangzhou"
)

func main() {
	client, err := kms.NewClientWithAccessKey(RegionId, os.Getenv(AccessKeyId), os.Getenv(AccessKeySecret))
	if err != nil {
		fmt.Println(err)
		return
	}

	//创建RSA_2048非对称密钥，用途为ENCRYPT/DECRYPT
	keyId, err := CreateKey(client, "RSA_2048", "ENCRYPT/DECRYPT")
	if err != nil {
		fmt.Println(err)
		return
	}

	keyVersionList, err := ListKeyVersions(client, keyId)
	if err != nil {
		fmt.Println(err)
		return
	}

	keyVersionId := keyVersionList[0].KeyVersionId

	algorithms := []string{"RSAES_OAEP_SHA_256", "RSAES_OAEP_SHA_1"}
	message := "abcdef123456.,/?_-=+中文\n"

	//非对称密钥加密、解密
	for _, algorithm := range algorithms {
		//KMS加密 KMS解密
		err := asymmetricEncryptDecrypt(client, keyId, keyVersionId, message, algorithm)
		if err != nil {
			fmt.Println(err)
		}
		//本地加密 KMS解密
		err = rsaEncryptDecrypt(client, keyId, keyVersionId, message, algorithm)
		if err != nil {
			fmt.Println(err)
		}
	}
}

//keySpec：RSA_2048、EC_P256、EC_P256K
//keyUsage：ENCRYPT/DECRYPT、SIGN/VERIFY
func CreateKey(client *kms.Client, keySpec, keyUsage string) (string, error) {
	request := kms.CreateCreateKeyRequest()
	request.Scheme = "https"
	request.KeySpec = keySpec
	request.KeyUsage = keyUsage
	response, err := client.CreateKey(request)
	if err != nil {
		return "", err
	}
	return response.KeyMetadata.KeyId, nil
}

func ListKeyVersions(client *kms.Client, keyId string) ([]kms.KeyVersion, error) {
	var keyVersions []kms.KeyVersion
	pageNumber := "1"
	for {
		request := kms.CreateListKeyVersionsRequest()
		request.Scheme = "https"
		request.KeyId = keyId
		request.PageNumber = requests.Integer(pageNumber)
		request.PageSize = "10"
		response, err := client.ListKeyVersions(request)
		if err != nil {
			return nil, err
		}
		for _, keyVersion := range response.KeyVersions.KeyVersion {
			keyVersions = append(keyVersions, keyVersion)
		}
		if response.PageNumber*10 >= response.TotalCount {
			break
		}
		pageNumber = strconv.Itoa(response.PageNumber + 1)
	}
	return keyVersions, nil
}

func asymmetricEncryptDecrypt(client *kms.Client, keyId, keyVersionId, message, algorithm string) error {
	cipherBlob, err := kms_api_samples.AsymmetricEncrypt(client, keyId, keyVersionId, message, algorithm)
	if err != nil {
		return errors.New(fmt.Sprintf("AsymmetricEncrypt error:%+v", err))
	}
	msg, err := kms_api_samples.AsymmetricDecrypt(client, keyId, keyVersionId, cipherBlob, algorithm)
	if err != nil {
		return errors.New(fmt.Sprintf("AsymmetricDecrypt error:%+v", err))
	}
	if message != msg {
		return errors.New(fmt.Sprintf("kms encrypt: decrypt failed, current message:%s, except:%s", msg, message))
	}
	return nil
}

func rsaEncryptDecrypt(client *kms.Client, keyId, keyVersionId, message, algorithm string) error {
	cipherBlob, err := kms_api_samples.RsaEncrypt(client, keyId, keyVersionId, message, algorithm)
	if err != nil {
		return errors.New(fmt.Sprintf("rsaEncrypt error:%+v", err))
	}
	msg, err := kms_api_samples.AsymmetricDecrypt(client, keyId, keyVersionId, cipherBlob, algorithm)
	if err != nil {
		return errors.New(fmt.Sprintf("AsymmetricDecrypt error:%+v", err))
	}
	if message != msg {
		return errors.New(fmt.Sprintf("local encrypt: decrypt failed, current message:%s, except:%s", msg, message))
	}
	return nil
}
