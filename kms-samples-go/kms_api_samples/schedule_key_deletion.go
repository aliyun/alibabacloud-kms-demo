package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

//pendingWindowInDays：密钥预删除周期，最小值7，最大值30
func ScheduleKeyDeletion(client *kms.Client, keyId string, pendingWindowInDays int) error {
	request := kms.CreateScheduleKeyDeletionRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	request.PendingWindowInDays = requests.NewInteger(pendingWindowInDays)
	_, err := client.ScheduleKeyDeletion(request)
	if err != nil {
		return fmt.Errorf("ScheduleKeyDeletion error:%v", err)
	}
	return nil
}
