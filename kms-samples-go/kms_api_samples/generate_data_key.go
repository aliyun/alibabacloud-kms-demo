package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func GenerateDataKey(client *kms.Client, keyId string) (string, string, error) {
	request := kms.CreateGenerateDataKeyRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	response, err := client.GenerateDataKey(request)
	if err != nil {
		return "", "", fmt.Errorf("GenerateDataKey error:%v", err)
	}
	return response.Plaintext, response.CiphertextBlob, nil
}

func GenerateDataKeyWithoutPlaintext(client *kms.Client, keyId string) (string, error) {
	request := kms.CreateGenerateDataKeyWithoutPlaintextRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	response, err := client.GenerateDataKeyWithoutPlaintext(request)
	if err != nil {
		return "", fmt.Errorf("GenerateDataKeyWithoutPlaintext error:%v", err)
	}
	return response.CiphertextBlob, nil
}
