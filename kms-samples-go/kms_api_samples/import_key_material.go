package kms_api_samples

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func ImportKeyMaterial(client *kms.Client, keyId, importToken, encryptedKeyMaterial string) error {
	request := kms.CreateImportKeyMaterialRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	request.ImportToken = importToken
	request.EncryptedKeyMaterial = encryptedKeyMaterial
	_, err := client.ImportKeyMaterial(request)
	if err != nil {
		return fmt.Errorf("ImportKeyMaterial error:%v", err)
	}
	return nil
}
