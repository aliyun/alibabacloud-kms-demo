package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func DeleteKeyMaterial(client *kms.Client, keyId string) error {
	request := kms.CreateDeleteKeyMaterialRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	_, err := client.DeleteKeyMaterial(request)
	if err != nil {
		return fmt.Errorf("DeleteKeyMaterial error:%v", err)
	}
	return nil
}
