package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func UpdateKeyDescription(client *kms.Client, keyId, description string) error {
	request := kms.CreateUpdateKeyDescriptionRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	request.Description = description
	_, err := client.UpdateKeyDescription(request)
	if err != nil {
		return fmt.Errorf("UpdateKeyDescription error:%v", err)
	}
	return nil
}
