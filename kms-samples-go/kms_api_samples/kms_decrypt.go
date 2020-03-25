package kms_api_samples

import (
	"encoding/base64"
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func AsymmetricDecrypt(client *kms.Client, keyId, keyVersionId string, cipherBlob []byte, algorithm string) (string, error) {
	//cipherBlob要进行base64编码
	cipherText := base64.StdEncoding.EncodeToString(cipherBlob)
	decReq := kms.CreateAsymmetricDecryptRequest()
	decReq.Scheme = "https"
	decReq.KeyId = keyId
	decReq.KeyVersionId = keyVersionId
	decReq.CiphertextBlob = cipherText
	decReq.Algorithm = algorithm
	decResp, err := client.AsymmetricDecrypt(decReq)
	if err != nil {
		return "", fmt.Errorf("AsymmetricDecrypt error:%v", err)
	}

	//明文要进行base64解码
	message, err := base64.StdEncoding.DecodeString(decResp.Plaintext)
	if err != nil {
		return "", fmt.Errorf("base64 decode error:%v", err)
	}
	return string(message), nil
}

func Decrypt(client *kms.Client, cipherTextBlob string) (string, error) {
	request := kms.CreateDecryptRequest()
	request.Scheme = "https"
	request.CiphertextBlob = cipherTextBlob
	response, err := client.Decrypt(request)
	if err != nil {
		return "", fmt.Errorf("decrypt error:%v", err)
	}
	return response.Plaintext, nil
}
