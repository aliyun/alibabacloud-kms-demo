package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func CancelKeyDeletion(client *kms.Client, keyId string) error {
	request := kms.CreateCancelKeyDeletionRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	_, err := client.CancelKeyDeletion(request)
	if err != nil {
		return fmt.Errorf("CancelKeyDeletion error:%v", err)
	}
	return nil
}
