package kms_api_samples

import (
	"fmt"
	"strconv"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func ListAliases(client *kms.Client) ([]kms.Alias, error) {
	var aliases []kms.Alias
	pageNumber := requests.Integer("1")
	pageSize := requests.Integer("10")
	for {
		request := kms.CreateListAliasesRequest()
		request.Scheme = "https"
		request.PageNumber = pageNumber
		request.PageSize = pageSize
		response, err := client.ListAliases(request)
		if err != nil {
			return nil, fmt.Errorf("ListAliases error:%v", err)
		}
		for _, alias := range response.Aliases.Alias {
			aliases = append(aliases, alias)
		}
		if response.PageNumber*10 >= response.TotalCount {
			break
		}
		pageNumber = requests.Integer(strconv.Itoa(response.PageNumber + 1))
	}
	return aliases, nil
}

func ListAliasesByKeyId(client *kms.Client, keyId string) ([]string, error) {
	var aliases []string
	pageNumber := requests.Integer("1")
	pageSize := requests.Integer("10")
	for {
		request := kms.CreateListAliasesByKeyIdRequest()
		request.Scheme = "https"
		request.PageNumber = pageNumber
		request.PageSize = pageSize
		request.KeyId = keyId
		response, err := client.ListAliasesByKeyId(request)
		if err != nil {
			return nil, fmt.Errorf("ListAliasesByKeyId error:%v", err)
		}
		for _, alias := range response.Aliases.Alias {
			aliases = append(aliases, alias.AliasName)
		}
		if response.PageNumber*10 >= response.TotalCount {
			break
		}
		pageNumber = requests.Integer(strconv.Itoa(response.PageNumber + 1))
	}
	return aliases, nil
}
