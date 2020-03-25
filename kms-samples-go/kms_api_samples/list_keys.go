package kms_api_samples

import (
	"fmt"
	"strconv"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func ListKeys(client *kms.Client) ([]string, error) {
	var keyIds []string
	pageNumber := requests.Integer("1")
	pageSize := requests.Integer("10")
	for {
		request := kms.CreateListKeysRequest()
		request.Scheme = "https"
		request.PageNumber = pageNumber
		request.PageSize = pageSize
		response, err := client.ListKeys(request)
		if err != nil {
			return nil, fmt.Errorf("ListKeys error:%v", err)
		}
		for _, key := range response.Keys.Key {
			keyIds = append(keyIds, key.KeyId)
		}
		if response.PageNumber*10 >= response.TotalCount {
			break
		}
		pageNumber = requests.Integer(strconv.Itoa(response.PageNumber + 1))
	}
	return keyIds, nil
}
