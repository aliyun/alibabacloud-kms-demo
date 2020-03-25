package kms_api_samples

import (
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func DescribeKey(client *kms.Client, keyId string) (*kms.KeyMetadata, error) {
	request := kms.CreateDescribeKeyRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	response, err := client.DescribeKey(request)
	if err != nil {
		return nil, fmt.Errorf("DescribeKey error:%v", err)
	}
	return &response.KeyMetadata, nil
}
