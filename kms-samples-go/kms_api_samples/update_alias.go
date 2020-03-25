package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func UpdateAlias(client *kms.Client, aliasName, keyId string) error {
	request := kms.CreateUpdateAliasRequest()
	request.Scheme = "https"
	request.AliasName = aliasName
	request.KeyId = keyId
	_, err := client.UpdateAlias(request)
	if err != nil {
		return fmt.Errorf("UpdateAlias error:%v", err)
	}
	return nil
}
