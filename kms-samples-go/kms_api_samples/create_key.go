package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

//keySpec：Aliyun_AES_256、RSA_2048、EC_P256、EC_P256K
//keyUsage：ENCRYPT/DECRYPT、SIGN/VERIFY
func CreateKey(client *kms.Client, keySpec, keyUsage, origin string) (string, error) {
	request := kms.CreateCreateKeyRequest()
	request.Scheme = "https"
	request.KeySpec = keySpec
	request.KeyUsage = keyUsage
	request.Origin = origin
	response, err := client.CreateKey(request)
	if err != nil {
		return "", fmt.Errorf("CreateKey error:%v", err)
	}
	return response.KeyMetadata.KeyId, nil
}
