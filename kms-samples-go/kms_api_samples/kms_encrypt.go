package kms_api_samples

import (
	"encoding/base64"
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func AsymmetricEncrypt(client *kms.Client, keyId, keyVersionId, message, algorithm string) ([]byte, error) {
	//message要进行base64编码
	plainText := base64.StdEncoding.EncodeToString([]byte(message))
	encReq := kms.CreateAsymmetricEncryptRequest()
	encReq.Scheme = "https"
	encReq.KeyId = keyId
	encReq.KeyVersionId = keyVersionId
	encReq.Plaintext = plainText
	encReq.Algorithm = algorithm
	encResp, err := client.AsymmetricEncrypt(encReq)
	if err != nil {
		return nil, err
	}

	//密文要进行base64解码
	cipherBlob, err := base64.StdEncoding.DecodeString(encResp.CiphertextBlob)
	if err != nil {
		return nil, fmt.Errorf("base64 decode error:%v", err)
	}
	return cipherBlob, nil
}

func Encrypt(client *kms.Client, keyId, base64Plaintext string) (string, error) {
	request := kms.CreateEncryptRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	//plaintext推荐使用base64编码，如果不编码也可以，存在隐患
	//kms在处理plaintext的时候可能没有做解码，是直接对plaintext进行加密
	//在非对称加密接口中做了解码操作，所以非对称加密必须进行编码
	request.Plaintext = base64Plaintext
	response, err := client.Encrypt(request)
	if err != nil {
		return "", fmt.Errorf("encrypt error:%v", err)
	}
	return response.CiphertextBlob, nil
}
