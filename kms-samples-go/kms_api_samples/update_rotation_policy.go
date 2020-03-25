package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func UpdateRotationPolicy(client *kms.Client, keyId string, enableAutomaticRotation bool, rotationInterval string) error {
	request := kms.CreateUpdateRotationPolicyRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	request.EnableAutomaticRotation = requests.NewBoolean(enableAutomaticRotation)
	request.RotationInterval = rotationInterval
	_, err := client.UpdateRotationPolicy(request)
	if err != nil {
		return fmt.Errorf("UpdateRotationPolicy error:%v", err)
	}
	return nil
}
