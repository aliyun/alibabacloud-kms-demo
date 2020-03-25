package kms_api_samples

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func RsaVerify(client *kms.Client, keyId, keyVersionId, message string, signature []byte, algorithm string) error {
	request := kms.CreateGetPublicKeyRequest()
	request.Scheme = "https"
	request.KeyId = keyId
	request.KeyVersionId = keyVersionId
	response, err := client.GetPublicKey(request)
	if err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(response.PublicKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("failed to decode public key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	hash := sha256.New()
	hash.Write([]byte(message))
	digest := hash.Sum(nil)

	switch algorithm {
	case "RSA_PSS_SHA_256":
		pssOptions := rsa.PSSOptions{SaltLength: len(digest), Hash: crypto.SHA256}
		err := rsa.VerifyPSS(publicKey.(*rsa.PublicKey), crypto.SHA256, digest, signature, &pssOptions)
		if err != nil {
			return err
		}
	case "RSA_PKCS1_SHA_256":
		err := rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA256, digest, signature)
		if err != nil {
			return err
		}
	default:
		return errors.New("not support algorithm")
	}
	return nil
}
