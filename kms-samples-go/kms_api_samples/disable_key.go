package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func DisableKey(client *kms.Client, keyId string) error {
	request := kms.CreateDisableKeyRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	_, err := client.DisableKey(request)
	if err != nil {
		return fmt.Errorf("DisableKey error:%v", err)
	}
	return nil
}
