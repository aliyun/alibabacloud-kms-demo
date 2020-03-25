package kms_api_samples

import (
	"errors"
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func CreateKmsClient(regionId, accessKeyId, accessKeySecret string) (*kms.Client, error) {
	client, err := kms.NewClientWithAccessKey(regionId, accessKeyId, accessKeySecret)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("NewClientWithAccessKey error:%+v", err))
	}
	//client.SetHTTPSInsecure(true)
	return client, nil
}
