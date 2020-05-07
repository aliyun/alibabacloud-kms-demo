package com.aliyun.kms.samples;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.http.MethodType;
import com.aliyuncs.http.ProtocolType;
import com.aliyuncs.kms.model.v20160120.DecryptRequest;
import com.aliyuncs.kms.model.v20160120.DecryptResponse;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;

public class EnvelopeDecrypt {
    private static DefaultAcsClient kmsClient;
    private static final int GCM_TAG_LENGTH = 16;

    private static DefaultAcsClient kmsClient(String regionId, String accessKeyId, String accessKeySecret) {
        IClientProfile profile = DefaultProfile.getProfile(regionId, accessKeyId, accessKeySecret);
        HttpClientConfig clientConfig = HttpClientConfig.getDefault();
        //clientConfig.setIgnoreSSLCerts(true);
        profile.setHttpClientConfig(clientConfig);

        return new DefaultAcsClient(profile);
    }

    private static String kmsDecrypt(String cipherTextBlob) throws ClientException {
        final DecryptRequest request = new DecryptRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setCiphertextBlob(cipherTextBlob);
        DecryptResponse response = kmsClient.getAcsResponse(request);
        return response.getPlaintext();
    }

    private static List<String> readTextFile(String inFile) throws IOException {
        return Files.readAllLines(Paths.get(inFile));
    }

    private static void writeTextFile(String outFile, byte[] content) throws IOException {
        File file = new File(outFile);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content);
        }
    }

    private static void localDecrypt(byte[] dataKey, byte[] iv, byte[] cipherText, String outFile) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(dataKey, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        byte[] decryptedText = cipher.doFinal(cipherText);
        writeTextFile(outFile, decryptedText);
    }

    public static void main(String[] args) {
        String regionId = "cn-hangzhou";
        String accessKeyId = System.getenv("AccessKeyId");
        String accessKeySecret = System.getenv("AccessKeySecret");

        kmsClient = kmsClient(regionId, accessKeyId, accessKeySecret);

        String inFile = "./data/sales.csv.cipher";
        String outFile = "./data/decrypted_sales.csv";

        try{
            //Read encrypted file
            List<String> inLines = readTextFile(inFile);

            //Decrypt data key
            String dataKey = kmsDecrypt(inLines.get(0));

            //Locally decrypt the sales record
            localDecrypt(Base64.getDecoder().decode(dataKey),
                    Base64.getDecoder().decode(inLines.get(1)),
                    Base64.getDecoder().decode(inLines.get(2)),
                    outFile);

        } catch (ClientException e) {
            System.out.println("Failed.");
            System.out.println("Error code: " + e.getErrCode());
            System.out.println("Error message: " + e.getErrMsg());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
