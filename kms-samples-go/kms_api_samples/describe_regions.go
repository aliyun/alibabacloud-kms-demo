package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func DescribeRegions(client *kms.Client) ([]string, error) {
	var regionIds []string
	request := kms.CreateDescribeRegionsRequest()
	request.Scheme = "https"
	response, err := client.DescribeRegions(request)
	if err != nil {
		return nil, fmt.Errorf("DescribeRegions error:%v", err)
	}
	for _, region := range response.Regions.Region {
		regionIds = append(regionIds, region.RegionId)
	}
	return regionIds, nil
}
