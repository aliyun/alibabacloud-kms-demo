package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func UntagResource(client *kms.Client, keyId, tagsKeys string) error {
	request := kms.CreateUntagResourceRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	request.TagKeys = tagsKeys
	_, err := client.UntagResource(request)
	if err != nil {
		return fmt.Errorf("UntagResource error:%v", err)
	}
	return nil
}
