package kms_api_samples

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func RsaEncrypt(client *kms.Client, keyId, keyVersionId, message, algorithm string) ([]byte, error) {
	request := kms.CreateGetPublicKeyRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	request.KeyVersionId = keyVersionId
	response, err := client.GetPublicKey(request)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(response.PublicKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode public key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	var cipherBlob []byte
	switch algorithm {
	case "RSAES_OAEP_SHA_1":
		cipherBlob, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey.(*rsa.PublicKey), []byte(message), nil)
		if err != nil {
			return nil, err
		}
	case "RSAES_OAEP_SHA_256":
		cipherBlob, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey.(*rsa.PublicKey), []byte(message), nil)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("not support algorithm")
	}
	return cipherBlob, nil
}
