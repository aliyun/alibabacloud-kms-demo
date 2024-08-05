package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"os"

	"github.com/alibabacloud-go/tea/tea"
	dedicatedkmsopenapi "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/openapi"
	dedicatedkmssdk "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/sdk"
)

const (
	ClientKeyFile        = "ClientKey_KAAP.f18d20f2-*****.json"
	EnvClientKeyPassword = "ENV_CLIENT_KEY_PASSWORD"
	Endpoint             = "kst-****.cryptoservice.kms.aliyuncs.com"
)

// 实现通过KMS Sign接口签名的Signer
type KmsPrivateKeySigner struct {
	client    *dedicatedkmssdk.Client
	publicKey crypto.PublicKey
	keyId     string
	algorithm string
}

func (ks *KmsPrivateKeySigner) Public() crypto.PublicKey {
	return ks.publicKey
}

func (ks *KmsPrivateKeySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	request := &dedicatedkmssdk.SignRequest{
		KeyId:       tea.String(ks.keyId),
		Message:     digest,
		MessageType: tea.String("DIGEST"),
		Algorithm:   tea.String(ks.algorithm),
	}
	resp, err := ks.client.Sign(request)
	if err != nil {
		return nil, err
	}
	return resp.Signature, nil
}

func main() {
	//在kms实例创建的RSA_2048非对称密钥，用途SIGN/VERIFY
	keyId := "key-*****"
	//调用kms实例Sign接口需要指定的算法名称
	kmsAlg := "RSA_PKCS1_SHA_256"
	//创建证书请求需要指定的签名算法
	sigAlg := x509.SHA256WithRSA
	//保存csr文件名称
	outFile := "./request_pem.csr"

	//创建dkms client
	dkmsClient, err := getDKMSClient(ClientKeyFile, os.Getenv(EnvClientKeyPassword), Endpoint)
	if err != nil {
		log.Fatalf("getDKMSClient error:%+v\n", err)
		return
	}

	//获取非对称密钥公钥
	pub, err := getPublicKey(dkmsClient, keyId)
	if err != nil {
		log.Fatalf("getPublicKey error: %v\n", err)
		return
	}

	//创建证书请求subject
	subject := pkix.Name{
		Country:            []string{"<your-country>"},
		Organization:       []string{"<your-organization>"},
		OrganizationalUnit: []string{"<your-organization-unit>"},
		CommonName:         "<your-domain-name>",
	}

	//创建kms服务签名器对象
	priv := &KmsPrivateKeySigner{
		client:    dkmsClient, //kms实例Client
		keyId:     keyId,      //kms实例非对称密钥Id
		publicKey: pub,        //kms实例非对称密钥公钥
		algorithm: kmsAlg,     //kms实例签名算法名称
	}

	//创建CSR
	csrPem, err := generateCSR(subject, priv, sigAlg)
	if err != nil {
		log.Fatalf("generateCSR error: %v\n", err)
		return
	}

	//保存到本地
	err = os.WriteFile(outFile, csrPem, 0644)
	if err != nil {
		log.Fatalf("os.WriteFile error:%+v\n", err)
	}
}

func getDKMSClient(clientKeyFile, clientKeyPassword, endpoint string) (*dedicatedkmssdk.Client, error) {
	config := &dedicatedkmsopenapi.Config{
		Protocol:      tea.String("https"),
		ClientKeyFile: tea.String(clientKeyFile),
		Password:      tea.String(clientKeyPassword),
		Endpoint:      tea.String(endpoint),
	}
	//验证服务端证书
	//config.CaFilePath = tea.String("/your/path/ca.crt")
	//或，忽略验证服务端证书
	config.IgnoreSSL = tea.Bool(true)
	return dedicatedkmssdk.NewClient(config)
}

func generateCSR(subject pkix.Name, priv *KmsPrivateKeySigner, sigAlg x509.SignatureAlgorithm) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: sigAlg,
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), nil
}

func getPublicKey(client *dedicatedkmssdk.Client, keyId string) (crypto.PublicKey, error) {
	request := &dedicatedkmssdk.GetPublicKeyRequest{
		KeyId: tea.String(keyId),
	}
	response, err := client.GetPublicKey(request)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(*response.PublicKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode public key")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}
