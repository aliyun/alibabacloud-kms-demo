package kms_api_samples

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func AsymmetricSign(client *kms.Client, keyId, keyVersionId, message, algorithm string) ([]byte, error) {
	hash := sha256.New()
	hash.Write([]byte(message))
	digest := hash.Sum(nil)

	//digest要进行base64编码
	base64Digest := base64.StdEncoding.EncodeToString(digest)
	request := kms.CreateAsymmetricSignRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	request.KeyVersionId = keyVersionId
	request.Digest = base64Digest
	request.Algorithm = algorithm
	response, err := client.AsymmetricSign(request)
	if err != nil {
		return nil, err
	}
	//签名要进行base64解码
	signature, err := base64.StdEncoding.DecodeString(response.Value)
	if err != nil {
		return nil, fmt.Errorf("base64 decode error:%v", err)
	}
	return signature, nil
}
