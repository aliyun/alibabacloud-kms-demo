package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func ListResourceTags(client *kms.Client, keyId string) ([]kms.Tag, error) {
	request := kms.CreateListResourceTagsRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	response, err := client.ListResourceTags(request)
	if err != nil {
		return nil, fmt.Errorf("ListResourceTags error:%v", err)
	}
	return response.Tags.Tag, nil
}
