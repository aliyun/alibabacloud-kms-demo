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

	//创建RSA_2048非对称密钥，用途为SIGN/VERIFY
	keyId, err := CreateKey(client, "RSA_2048", "SIGN/VERIFY")
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

	algorithms := []string{"RSA_PSS_SHA_256", "RSA_PKCS1_SHA_256"}
	message := "abcdef123456.,/?_-=+中文\n"

	//非对称密钥签名、验签
	for _, algorithm := range algorithms {
		//KMS签名 KMS验签
		err := asymmetricSignVerify(client, keyId, keyVersionId, message, algorithm)
		if err != nil {
			fmt.Println(err)
		}
		//KMS签名 本地验签
		err = rsaSignVerify(client, keyId, keyVersionId, message, algorithm)
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

func asymmetricSignVerify(client *kms.Client, keyId, keyVersionId, message, algorithm string) error {
	signature, err := kms_api_samples.AsymmetricSign(client, keyId, keyVersionId, message, algorithm)
	if err != nil {
		return errors.New(fmt.Sprintf("AsymmetricSign error:%+v", err))
	}
	ok, err := kms_api_samples.AsymmetricVerify(client, keyId, keyVersionId, message, signature, algorithm)
	if err != nil {
		return errors.New(fmt.Sprintf("AsymmetricVerify error:%+v", err))
	}
	if !ok {
		return errors.New(fmt.Sprintf("signature verify failed"))
	}
	return nil
}

func rsaSignVerify(client *kms.Client, keyId, keyVersionId, message, algorithm string) error {
	signature, err := kms_api_samples.AsymmetricSign(client, keyId, keyVersionId, message, algorithm)
	if err != nil {
		return errors.New(fmt.Sprintf("AsymmetricSign error:%+v", err))
	}
	err = kms_api_samples.RsaVerify(client, keyId, keyVersionId, message, signature, algorithm)
	if err != nil {
		return errors.New(fmt.Sprintf("RsaVerify error:%+v", err))
	}
	return nil
}
