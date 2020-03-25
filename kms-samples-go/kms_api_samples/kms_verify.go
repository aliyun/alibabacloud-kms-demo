package kms_api_samples

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func AsymmetricVerify(client *kms.Client, keyId, keyVersionId, message string, signature []byte, algorithm string) (bool, error) {
	hash := sha256.New()
	hash.Write([]byte(message))
	digest := hash.Sum(nil)

	//digest，signature要进行base64编码
	base64Digest := base64.StdEncoding.EncodeToString(digest)
	base64Signature := base64.StdEncoding.EncodeToString(signature)
	request := kms.CreateAsymmetricVerifyRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	request.KeyVersionId = keyVersionId
	request.Digest = base64Digest
	request.Value = base64Signature
	request.Algorithm = algorithm
	response, err := client.AsymmetricVerify(request)
	if err != nil {
		return false, err
	}
	return response.Value, nil
}
