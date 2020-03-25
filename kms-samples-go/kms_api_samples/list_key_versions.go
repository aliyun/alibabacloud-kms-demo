package kms_api_samples

import (
	"strconv"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func ListKeyVersions(client *kms.Client, keyId string) ([]kms.KeyVersion, error) {
	var keyVersions []kms.KeyVersion
	pageNumber := requests.Integer("1")
	pageSize := requests.Integer("10")
	for {
		request := kms.CreateListKeyVersionsRequest()
		request.Scheme = "https"
		request.KeyId = keyId
		request.PageNumber = pageNumber
		request.PageSize = pageSize
		response, err := client.ListKeyVersions(request)
		if err != nil {
			return nil, err
		}
		for _, keyVersion := range response.KeyVersions.KeyVersion {
			keyVersions = append(keyVersions, keyVersion)
		}
		if response.PageNumber*10 >= response.TotalCount {
			break
		}
		pageNumber = requests.Integer(strconv.Itoa(response.PageNumber + 1))
	}
	return keyVersions, nil
}
