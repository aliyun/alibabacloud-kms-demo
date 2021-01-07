package com.aliyun.kms.samples.pdfsign;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.http.MethodType;
import com.aliyuncs.http.ProtocolType;
import com.aliyuncs.kms.model.v20160120.AsymmetricSignRequest;
import com.aliyuncs.kms.model.v20160120.AsymmetricSignResponse;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;
import com.itextpdf.kernel.PdfException;
import com.itextpdf.signatures.IExternalSignature;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;

public class KMSiTextSignature implements IExternalSignature {
    public DefaultAcsClient kmsClient;
    public String keyId;
    public String algorithm;
    public String keyVersionId;
    public String hashAlgorithm;

    @Override
    public String getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    @Override
    public String getEncryptionAlgorithm() {
        return this.algorithm;
    }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {
        System.out.println("message length: " + message.length);
        final AsymmetricSignRequest asReq = new AsymmetricSignRequest();
        byte[] digest = MessageDigest.getInstance(hashAlgorithm).digest(message);
        //digest要进行base64编码
        String base64Digest = Base64.getEncoder().encodeToString(digest);
        asReq.setSysProtocol(ProtocolType.HTTPS);
        asReq.setAcceptFormat(FormatType.JSON);
        asReq.setSysMethod(MethodType.POST);
        asReq.setKeyId(keyId);
        asReq.setKeyVersionId(keyVersionId);
        asReq.setAlgorithm(getKmsAlgorithm());
        asReq.setDigest(base64Digest);
        AsymmetricSignResponse asySignRes = null;
        try {
            asySignRes = kmsClient.getAcsResponse(asReq);
        } catch (ClientException e) {
            e.printStackTrace();
        }
        //签名要进行base64解码
        return Base64.getDecoder().decode(asySignRes.getValue().getBytes(StandardCharsets.UTF_8));
    }

    private String getKmsAlgorithm() {
        if (this.algorithm.equals("RSA")) {
            return "RSA_PKCS1_SHA_256";
        } else if (this.algorithm.equals("DSA")) {
            return "SM2DSA";
        } else {
            if (!this.algorithm.equals("ECDSA")) {
                throw (new PdfException("Unknown KmsAlgorithm: {0}.")).setMessageParams(algorithm);
            }
            return "ECDSA_SHA_256";
        }
    }

    public DefaultAcsClient kmsClient(String regionId, String accessKeyId, String accessKeySecret) {
        IClientProfile profile = DefaultProfile.getProfile(regionId, accessKeyId, accessKeySecret);
        HttpClientConfig clientConfig = HttpClientConfig.getDefault();
        //clientConfig.setIgnoreSSLCerts(true);
        profile.setHttpClientConfig(clientConfig);

        return new DefaultAcsClient(profile);
    }
}