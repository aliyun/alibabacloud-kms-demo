package kms_api_samples

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

func EcP256Verify(client *kms.Client, keyId, keyVersionId, message string, signature []byte) error {
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

	var parsedSig struct{ R, S *big.Int }
	_, err = asn1.Unmarshal(signature, &parsedSig)
	if err != nil {
		return err
	}

	ok := ecdsa.Verify(publicKey.(*ecdsa.PublicKey), digest, parsedSig.R, parsedSig.S)
	if !ok {
		return errors.New(fmt.Sprintf("signature verify failed"))
	}
	return nil
}

func EcP256KVerify(client *kms.Client, keyId, keyVersionId, message string, signature []byte) error {
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

	var pki struct {
		Raw       asn1.RawContent
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(block.Bytes, &pki); err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("x509: trailing data after ASN.1 of public-key")
	}

	asn1Data := pki.PublicKey.RightAlign()
	paramsData := pki.Algorithm.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	rest, err := asn1.Unmarshal(paramsData, namedCurveOID)
	if err != nil {
		return errors.New("x509: failed to parse ECDSA parameters as named curve")
	}
	if len(rest) != 0 {
		return errors.New("x509: trailing data after ECDSA parameters")
	}
	namedCurve := secp256k1.S256()
	x, y := elliptic.Unmarshal(namedCurve, asn1Data)
	if x == nil {
		return errors.New("x509: failed to unmarshal elliptic curve point")
	}
	publicKey := &ecdsa.PublicKey{Curve: namedCurve, X: x, Y: y}

	hash := sha256.New()
	hash.Write([]byte(message))
	digest := hash.Sum(nil)

	var parsedSig struct{ R, S *big.Int }
	_, err = asn1.Unmarshal(signature, &parsedSig)
	if err != nil {
		return err
	}

	ok := ecdsa.Verify(publicKey, digest, parsedSig.R, parsedSig.S)
	if !ok {
		return errors.New(fmt.Sprintf("signature verify failed"))
	}
	return nil
}
