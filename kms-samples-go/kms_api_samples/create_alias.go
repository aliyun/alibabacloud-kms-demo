package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func CreateAlias(client *kms.Client, aliasName, keyId string) error {
	request := kms.CreateCreateAliasRequest()
	request.Scheme = "https"
	request.AliasName = aliasName
	request.KeyId = keyId
	_, err := client.CreateAlias(request)
	if err != nil {
		return fmt.Errorf("CreateAlias error:%v", err)
	}
	return nil
}
