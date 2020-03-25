package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func GetParametersForImport(client *kms.Client, keyId, wrappingKeySpec, wrappingAlgorithm string) (string, string, error) {
	request := kms.CreateGetParametersForImportRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	request.WrappingKeySpec = wrappingKeySpec
	request.WrappingAlgorithm = wrappingAlgorithm
	response, err := client.GetParametersForImport(request)
	if err != nil {
		return "", "", fmt.Errorf("GetParametersForImport error:%v", err)
	}
	return response.PublicKey, response.ImportToken, nil
}
