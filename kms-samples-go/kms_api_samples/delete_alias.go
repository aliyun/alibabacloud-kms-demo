package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func DeleteAlias(client *kms.Client, aliasName string) error {
	request := kms.CreateDeleteAliasRequest()
	request.Scheme = "https"
	request.AliasName = aliasName
	_, err := client.DeleteAlias(request)
	if err != nil {
		return fmt.Errorf("DeleteAlias error:%v", err)
	}
	return nil
}
