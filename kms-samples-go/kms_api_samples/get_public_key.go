package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func GetAsymmetricPublicKey(client *kms.Client, keyId, keyVersionId string) (string, error) {
	request := kms.CreateGetPublicKeyRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	request.KeyVersionId = keyVersionId
	response, err := client.GetPublicKey(request)
	if err != nil {
		return "", fmt.Errorf("GetPublicKey error:%v", err)
	}
	return response.PublicKey, nil

}
