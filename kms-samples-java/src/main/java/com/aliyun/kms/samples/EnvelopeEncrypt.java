package com.aliyun.kms.samples;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.http.MethodType;
import com.aliyuncs.http.ProtocolType;
import com.aliyuncs.kms.model.v20160120.GenerateDataKeyRequest;
import com.aliyuncs.kms.model.v20160120.GenerateDataKeyResponse;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Base64;

public class EnvelopeEncrypt {
    private static DefaultAcsClient kmsClient;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;

    private static DefaultAcsClient kmsClient(String regionId, String accessKeyId, String accessKeySecret) {
        IClientProfile profile = DefaultProfile.getProfile(regionId, accessKeyId, accessKeySecret);
        HttpClientConfig clientConfig = HttpClientConfig.getDefault();
        //clientConfig.setIgnoreSSLCerts(true);
        profile.setHttpClientConfig(clientConfig);

        return new DefaultAcsClient(profile);
    }

    private static GenerateDataKeyResponse kmsGenerateDataKey(String keyAlias) throws ClientException {
        final GenerateDataKeyRequest request = new GenerateDataKeyRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyAlias);
        return kmsClient.getAcsResponse(request);
    }

    private static byte[] readTextFile(String inFile) throws IOException {
        File file = new File(inFile);
        try (InputStream in = new FileInputStream(file)) {
            long len = file.length();
            byte[] data = new byte[(int) len];
            in.read(data);
            return data;
        }
    }

    private static void writeTextFile(String outFile, String content) throws IOException {
        File file = new File(outFile);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content.getBytes());
        }
    }

    //Out file format (text)
    //Line 1: b64 encoded data key
    //Line 2: b64 encoded IV
    //Line 3: b64 encoded cipherText
    private static void localEncrypt(String plainKey, String encryptedKey, String inFile, String outFile) throws Exception  {
        byte[] key = Base64.getDecoder().decode(plainKey);

        byte[] inContent = readTextFile(inFile);

        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
        byte[] cipherText = cipher.doFinal(inContent);

        String b64CipherText = Base64.getEncoder().encodeToString(cipherText);
        String b64IV = Base64.getEncoder().encodeToString(iv);
        String outContent = encryptedKey + "\n" + b64IV + "\n" + b64CipherText;

        writeTextFile(outFile, outContent);
    }

    public static void main(String[] args) {
        String regionId = "cn-hangzhou";
        String accessKeyId = System.getenv("AccessKeyId");
        String accessKeySecret = System.getenv("AccessKeySecret");

        kmsClient = kmsClient(regionId, accessKeyId, accessKeySecret);

        String keyAlias = "alias/Apollo/WorkKey";
        String inFile = "./data/sales.csv";
        String outFile = "./data/sales.csv.cipher";

        try{
            //Generate Data Key
            GenerateDataKeyResponse response = kmsGenerateDataKey(keyAlias);

            //Locally Encrypt the sales record
            localEncrypt(response.getPlaintext(), response.getCiphertextBlob(), inFile, outFile);

        } catch (ClientException e) {
            System.out.println("Failed.");
            System.out.println("Error code: " + e.getErrCode());
            System.out.println("Error message: " + e.getErrMsg());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
