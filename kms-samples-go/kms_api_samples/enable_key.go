package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func EnableKey(client *kms.Client, keyId string) error {
	request := kms.CreateEnableKeyRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	_, err := client.EnableKey(request)
	if err != nil {
		return fmt.Errorf("EnableKey error:%v", err)
	}
	return nil
}
