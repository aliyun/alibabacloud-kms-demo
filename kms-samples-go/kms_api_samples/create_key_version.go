package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func CreateKeyVersion(client *kms.Client, keyId string) (*kms.KeyVersion, error) {
	request := kms.CreateCreateKeyVersionRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	response, err := client.CreateKeyVersion(request)
	if err != nil {
		return nil, fmt.Errorf("CreateKeyVersion error:%v", err)
	}
	return &response.KeyVersion, nil
}
