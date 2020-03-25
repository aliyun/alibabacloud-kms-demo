package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func TagResource(client *kms.Client, keyId, tags string) error {
	request := kms.CreateTagResourceRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	request.Tags = tags
	_, err := client.TagResource(request)
	if err != nil {
		return fmt.Errorf("TagResource error:%v", err)
	}
	return nil
}
