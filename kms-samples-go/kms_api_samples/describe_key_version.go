package kms_api_samples

import (
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func DescribeKeyVersion(client *kms.Client, keyId, keyVersionId string) (*kms.KeyVersion, error) {
	request := kms.CreateDescribeKeyVersionRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	request.KeyVersionId = keyVersionId
	response, err := client.DescribeKeyVersion(request)
	if err != nil {
		return nil, fmt.Errorf("DescribeKeyVersion error:%v", err)
	}
	return &response.KeyVersion, nil
}
