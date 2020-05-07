package com.aliyun.kms.samples;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.http.MethodType;
import com.aliyuncs.http.ProtocolType;

import com.aliyuncs.kms.model.v20160120.*;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;

public class OpenApi {
    public static DefaultAcsClient kmsClient(String regionId, String accessKeyId, String accessKeySecret) {
        IClientProfile profile = DefaultProfile.getProfile(regionId, accessKeyId, accessKeySecret);
        HttpClientConfig clientConfig = HttpClientConfig.getDefault();
        //clientConfig.setIgnoreSSLCerts(true);
        profile.setHttpClientConfig(clientConfig);

        return new DefaultAcsClient(profile);
    }

    public static CancelKeyDeletionResponse cancelKeyDeletion(DefaultAcsClient kmsClient, String keyId) throws ClientException {
        final CancelKeyDeletionRequest request = new CancelKeyDeletionRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        return kmsClient.getAcsResponse(request);
    }

    public static CreateAliasResponse createAlias(DefaultAcsClient kmsClient, String aliasName, String keyId) throws ClientException {
        final CreateAliasRequest request = new CreateAliasRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        request.setAliasName(aliasName);
        return kmsClient.getAcsResponse(request);
    }

    public static String createKey(DefaultAcsClient kmsClient, String keySpec, String keyUsage, String origin) throws ClientException {
        final CreateKeyRequest request = new CreateKeyRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeySpec(keySpec);
        request.setKeyUsage(keyUsage);
        request.setOrigin(origin);
        return kmsClient.getAcsResponse(request).getKeyMetadata().getKeyId();
    }

    public static CreateKeyVersionResponse createKeyVersion(DefaultAcsClient kmsClient, String keyId) throws ClientException {
        final CreateKeyVersionRequest request = new CreateKeyVersionRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        return kmsClient.getAcsResponse(request);

    }

    public static DeleteAliasResponse deleteAlias(DefaultAcsClient kmsClient, String aliasName) throws ClientException {
        final DeleteAliasRequest request = new DeleteAliasRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setAliasName(aliasName);
        return kmsClient.getAcsResponse(request);
    }

    public static DeleteKeyMaterialResponse deleteKeyMaterial(DefaultAcsClient kmsClient, String keyId) throws ClientException {
        final DeleteKeyMaterialRequest request = new DeleteKeyMaterialRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        return kmsClient.getAcsResponse(request);
    }

    public static DescribeKeyResponse describeKey(DefaultAcsClient kmsClient, String keyId) throws ClientException {
        final DescribeKeyRequest request = new DescribeKeyRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        return kmsClient.getAcsResponse(request);
    }

    public static DescribeKeyVersionResponse describeKeyVersion(DefaultAcsClient kmsClient, String keyId, String keyVersionId) throws ClientException {
        final DescribeKeyVersionRequest request = new DescribeKeyVersionRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        request.setKeyVersionId(keyVersionId);
        return kmsClient.getAcsResponse(request);
    }

    public static List<String> describeRegions(DefaultAcsClient kmsClient) throws ClientException {
        final DescribeRegionsRequest request = new DescribeRegionsRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        DescribeRegionsResponse response = kmsClient.getAcsResponse(request);

        List<String> regionIds = new ArrayList<>();
        for (DescribeRegionsResponse.Region region : response.getRegions()) {
            regionIds.add(region.getRegionId());
        }

        return regionIds;
    }

    public static DisableKeyResponse disableKey(DefaultAcsClient kmsClient, String keyId) throws ClientException {
        final DisableKeyRequest request = new DisableKeyRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        return kmsClient.getAcsResponse(request);
    }

    public static EnableKeyResponse enableKey(DefaultAcsClient kmsClient, String keyId) throws ClientException {
        final EnableKeyRequest request = new EnableKeyRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        return kmsClient.getAcsResponse(request);
    }

    public static GenerateDataKeyResponse generateDataKey(DefaultAcsClient kmsClient, String keyId) throws ClientException {
        final GenerateDataKeyRequest request = new GenerateDataKeyRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        return kmsClient.getAcsResponse(request);
    }

    public static GenerateDataKeyWithoutPlaintextResponse generateDataKeyWithoutPlaintext(DefaultAcsClient kmsClient, String keyId) throws ClientException {
        final GenerateDataKeyWithoutPlaintextRequest request = new GenerateDataKeyWithoutPlaintextRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        return kmsClient.getAcsResponse(request);
    }

    public static GetParametersForImportResponse getParametersForImport(DefaultAcsClient kmsClient, String keyId, String wrappingKeySpec, String wrappingAlgorithm) throws ClientException {
        final GetParametersForImportRequest request = new GetParametersForImportRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        request.setWrappingKeySpec(wrappingKeySpec);
        request.setWrappingAlgorithm(wrappingAlgorithm);
        return kmsClient.getAcsResponse(request);
    }

    public static GetPublicKeyResponse getPublicKey(DefaultAcsClient kmsClient, String keyId, String keyVersionId) throws ClientException {
        final GetPublicKeyRequest request = new GetPublicKeyRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        request.setKeyVersionId(keyVersionId);
        return kmsClient.getAcsResponse(request);
    }

    public static ImportKeyMaterialResponse importKeyMaterial(DefaultAcsClient kmsClient, String keyId, String importToken, String encryptedKeyMaterial) throws ClientException {
        final ImportKeyMaterialRequest request = new ImportKeyMaterialRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        request.setImportToken(importToken);
        request.setEncryptedKeyMaterial(encryptedKeyMaterial);
        return kmsClient.getAcsResponse(request);
    }

    public static byte[] asymmetricEncrypt(DefaultAcsClient kmsClient, String keyId, String keyVersionId, String message, String algorithm) throws ClientException {
        final AsymmetricEncryptRequest request = new AsymmetricEncryptRequest();
        //message要进行base64编码
        String plainText = Base64.getEncoder().encodeToString(message.getBytes(StandardCharsets.UTF_8));
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        request.setKeyVersionId(keyVersionId);
        request.setPlaintext(plainText);
        request.setAlgorithm(algorithm);
        AsymmetricEncryptResponse asymEncryptRes = kmsClient.getAcsResponse(request);
        String base64CipherBlob = asymEncryptRes.getCiphertextBlob();
        //密文要进行base64解码
        return Base64.getDecoder().decode(base64CipherBlob);
    }

    public static String encrypt(DefaultAcsClient kmsClient, String keyId, String base64Plaintext) throws ClientException {
        final EncryptRequest request = new EncryptRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        request.setPlaintext(base64Plaintext);
        EncryptResponse response = kmsClient.getAcsResponse(request);
        return response.getCiphertextBlob();
    }

    public static byte[] asymmetricDecrypt(DefaultAcsClient kmsClient, byte[] cipherBlob, String keyId, String keyVersionId, String algorithm) throws ClientException {
        final AsymmetricDecryptRequest request = new AsymmetricDecryptRequest();
        //cipherBlob要进行base64编码
        String cipherText = Base64.getEncoder().encodeToString(cipherBlob);
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        request.setKeyVersionId(keyVersionId);
        request.setCiphertextBlob(cipherText);
        request.setAlgorithm(algorithm);
        AsymmetricDecryptResponse asymDecryptRes = kmsClient.getAcsResponse(request);
        String base64Msg = asymDecryptRes.getPlaintext();
        //明文要进行base64解码
        return Base64.getDecoder().decode(base64Msg);
    }

    public static String decrypt(DefaultAcsClient kmsClient, String cipherTextBlob) throws ClientException {
        final DecryptRequest request = new DecryptRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setCiphertextBlob(cipherTextBlob);
        DecryptResponse response = kmsClient.getAcsResponse(request);
        return response.getPlaintext();
    }

    public static byte[] asymmetricSign(DefaultAcsClient kmsClient, String keyId, String keyVersionId, String algorithm, String message) throws ClientException, NoSuchAlgorithmException {
        final AsymmetricSignRequest request = new AsymmetricSignRequest();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(message.getBytes(StandardCharsets.UTF_8));
        //digest要进行base64编码
        String base64Digest = Base64.getEncoder().encodeToString(digest);
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        request.setKeyVersionId(keyVersionId);
        request.setAlgorithm(algorithm);
        request.setDigest(base64Digest);
        AsymmetricSignResponse asymSignRes = kmsClient.getAcsResponse(request);
        //签名要进行base64解码
        return Base64.getDecoder().decode(asymSignRes.getValue().getBytes(StandardCharsets.UTF_8));
    }

    public static boolean asymmetricVerify(DefaultAcsClient kmsClient, String keyId, String keyVersionId, String algorithm, String message, byte[] signature) throws ClientException, NoSuchAlgorithmException {
        final AsymmetricVerifyRequest request = new AsymmetricVerifyRequest();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(message.getBytes(StandardCharsets.UTF_8));
        //digest，signature要进行base64编码
        String base64Digest = Base64.getEncoder().encodeToString(digest);
        String base64Signature = Base64.getEncoder().encodeToString(signature);
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        request.setKeyVersionId(keyVersionId);
        request.setAlgorithm(algorithm);
        request.setDigest(base64Digest);
        request.setValue(base64Signature);
        AsymmetricVerifyResponse asymVerifyRes = kmsClient.getAcsResponse(request);

        return asymVerifyRes.getValue();
    }

    public static List<ListAliasesResponse.Alias> listAliases(DefaultAcsClient kmsClient) throws ClientException {
        Integer pageNumber = 1;
        Integer pageSize = 10;
        List<ListAliasesResponse.Alias> listAliases = new ArrayList<>();
        for (; ; ) {
            final ListAliasesRequest request = new ListAliasesRequest();
            request.setSysProtocol(ProtocolType.HTTPS);
            request.setAcceptFormat(FormatType.JSON);
            request.setSysMethod(MethodType.POST);
            request.setPageNumber(pageNumber);
            request.setPageSize(pageSize);
            ListAliasesResponse listAliasesRes = kmsClient.getAcsResponse(request);

            List<ListAliasesResponse.Alias> aliases = listAliasesRes.getAliases();
            Iterator<ListAliasesResponse.Alias> iterator = aliases.iterator();

            for (; iterator.hasNext(); ) {
                listAliases.add(iterator.next());
            }

            pageNumber = listAliasesRes.getPageNumber();
            Integer totalCount = listAliasesRes.getTotalCount();
            if (pageNumber * pageSize >= totalCount) {
                break;
            }
            pageNumber++;
        }
        return listAliases;
    }

    public static List<ListAliasesByKeyIdResponse.Alias> listAliasesByKeyId(DefaultAcsClient kmsClient, String keyId) throws ClientException {
        Integer pageNumber = 1;
        Integer pageSize = 10;
        List<ListAliasesByKeyIdResponse.Alias> listAliases = new ArrayList<>();
        for (; ; ) {
            final ListAliasesByKeyIdRequest request = new ListAliasesByKeyIdRequest();
            request.setSysProtocol(ProtocolType.HTTPS);
            request.setAcceptFormat(FormatType.JSON);
            request.setSysMethod(MethodType.POST);
            request.setKeyId(keyId);
            request.setPageNumber(pageNumber);
            request.setPageSize(pageSize);
            ListAliasesByKeyIdResponse listAliasesRes = kmsClient.getAcsResponse(request);

            List<ListAliasesByKeyIdResponse.Alias> aliases = listAliasesRes.getAliases();
            Iterator<ListAliasesByKeyIdResponse.Alias> iterator = aliases.iterator();

            for (; iterator.hasNext(); ) {
                listAliases.add(iterator.next());
            }

            pageNumber = listAliasesRes.getPageNumber();
            Integer totalCount = listAliasesRes.getTotalCount();
            if (pageNumber * pageSize >= totalCount) {
                break;
            }
            pageNumber++;
        }
        return listAliases;
    }

    public static List<ListKeyVersionsResponse.KeyVersion> listKeyVersions(DefaultAcsClient kmsClient, String keyId) throws ClientException {
        Integer pageNumber = 1;
        Integer pageSize = 10;
        List<ListKeyVersionsResponse.KeyVersion> listKeyVersions = new ArrayList<>();
        for (; ; ) {
            ListKeyVersionsRequest request = new ListKeyVersionsRequest();
            request.setSysProtocol(ProtocolType.HTTPS);
            request.setAcceptFormat(FormatType.JSON);
            request.setSysMethod(MethodType.POST);
            request.setKeyId(keyId);
            request.setPageNumber(pageNumber);
            request.setPageSize(pageSize);
            ListKeyVersionsResponse listKeyVersionsRes = kmsClient.getAcsResponse(request);
            List<ListKeyVersionsResponse.KeyVersion> keyVersions = listKeyVersionsRes.getKeyVersions();
            Iterator<ListKeyVersionsResponse.KeyVersion> iterator = keyVersions.iterator();

            for (; iterator.hasNext(); ) {
                listKeyVersions.add(iterator.next());
            }
            pageNumber = listKeyVersionsRes.getPageNumber();
            Integer totalCount = listKeyVersionsRes.getTotalCount();
            if (pageNumber * pageSize >= totalCount) {
                break;
            }
            pageNumber++;
        }
        return listKeyVersions;
    }

    public static List<String> listKeys(DefaultAcsClient kmsClient) throws ClientException {
        Integer pageNumber = 1;
        Integer pageSize = 10;
        List<String> listKeys = new ArrayList<>();
        for (; ; ) {
            ListKeysRequest request = new ListKeysRequest();
            request.setSysProtocol(ProtocolType.HTTPS);
            request.setAcceptFormat(FormatType.JSON);
            request.setSysMethod(MethodType.POST);
            request.setPageNumber(pageNumber);
            request.setPageSize(pageSize);
            ListKeysResponse listKeysRes = kmsClient.getAcsResponse(request);
            List<ListKeysResponse.Key> keys = listKeysRes.getKeys();
            Iterator<ListKeysResponse.Key> iterator = keys.iterator();

            for (; iterator.hasNext(); ) {
                String keyId = iterator.next().getKeyId();
                listKeys.add(keyId);
            }
            pageNumber = listKeysRes.getPageNumber();
            Integer totalCount = listKeysRes.getTotalCount();
            if (pageNumber * pageSize >= totalCount) {
                break;
            }
            pageNumber++;
        }
        return listKeys;
    }

    public static List<ListResourceTagsResponse.Tag> listResourceTags(DefaultAcsClient kmsClient, String keyId) throws ClientException {
        final ListResourceTagsRequest request = new ListResourceTagsRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        return kmsClient.getAcsResponse(request).getTags();
    }

    public static byte[] rsaEncrypt(DefaultAcsClient kmsClient, String keyId, String keyVersionId, String message, String algorithm) throws ClientException, GeneralSecurityException {
        Cipher oaepFromAlgo;
        OAEPParameterSpec oaepParams;

        GetPublicKeyResponse publicKeyRes = getPublicKey(kmsClient, keyId, keyVersionId);
        String publicKeyPem = publicKeyRes.getPublicKey();
        publicKeyPem = publicKeyPem.replaceFirst("-----BEGIN PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceFirst("-----END PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceAll("\\s", "");
        byte[] publicKeyDer = Base64.getDecoder().decode(publicKeyPem);
        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyDer));

        switch (algorithm) {
            case "RSAES_OAEP_SHA_1":
                oaepFromAlgo = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
                oaepParams = new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
                oaepFromAlgo.init(Cipher.ENCRYPT_MODE, pubKey, oaepParams);
                break;
            case "RSAES_OAEP_SHA_256":
                oaepFromAlgo = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
                oaepFromAlgo.init(Cipher.ENCRYPT_MODE, pubKey, oaepParams);
                break;
            default:
                throw new UnsupportedOperationException(String.format("algorithm '%s' not support.", algorithm));
        }
        return oaepFromAlgo.doFinal(message.getBytes(StandardCharsets.UTF_8));
    }

    public static boolean rsaVerify(DefaultAcsClient kmsClient, String keyId, String keyVersionId, String message, byte[] signature, String algorithm) throws ClientException, GeneralSecurityException {
        Signature rsaSignature;

        GetPublicKeyResponse publicKeyRes = getPublicKey(kmsClient, keyId, keyVersionId);
        String publicKeyPem = publicKeyRes.getPublicKey();
        publicKeyPem = publicKeyPem.replaceFirst("-----BEGIN PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceFirst("-----END PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceAll("\\s", "");
        byte[] publicKeyDer = Base64.getDecoder().decode(publicKeyPem);
        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyDer));

        switch (algorithm) {
            case "RSA_PSS_SHA_256":
                rsaSignature = Signature.getInstance("RSASSA-PSS");
                rsaSignature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                rsaSignature.initVerify(pubKey);
                rsaSignature.update(message.getBytes(StandardCharsets.UTF_8));
                break;
            case "RSA_PKCS1_SHA_256":
                rsaSignature = Signature.getInstance("SHA256withRSA");
                rsaSignature.initVerify(pubKey);
                rsaSignature.update(message.getBytes(StandardCharsets.UTF_8));
                break;
            default:
                throw new UnsupportedOperationException(String.format("algorithm '%s' not support.", algorithm));
        }
        return rsaSignature.verify(signature);
    }

    public static boolean ecdsaVerify(DefaultAcsClient kmsClient, String keyId, String keyVersionId, String message, byte[] signature) throws GeneralSecurityException, ClientException {
        GetPublicKeyResponse publicKeyRes = getPublicKey(kmsClient, keyId, keyVersionId);
        String publicKeyPem = publicKeyRes.getPublicKey();
        publicKeyPem = publicKeyPem.replaceFirst("-----BEGIN PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceFirst("-----END PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceAll("\\s", "");
        byte[] publicKeyDer = Base64.getDecoder().decode(publicKeyPem);
        PublicKey pubKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(publicKeyDer));

        Signature ecVerify = Signature.getInstance("SHA256withECDSA");
        ecVerify.initVerify(pubKey);
        ecVerify.update(message.getBytes(StandardCharsets.UTF_8));
        return ecVerify.verify(signature);
    }

    public static void scheduleKeyDeletion(DefaultAcsClient kmsClient, String keyId, Integer pendingWindowInDays) throws ClientException {
        final ScheduleKeyDeletionRequest request = new ScheduleKeyDeletionRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        request.setPendingWindowInDays(pendingWindowInDays);
        kmsClient.getAcsResponse(request);
    }

    public static TagResourceResponse tagResource(DefaultAcsClient kmsClient, String keyId, String tags) throws ClientException {
        final TagResourceRequest request = new TagResourceRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        request.setTags(tags);
        return kmsClient.getAcsResponse(request);
    }

    public static UntagResourceResponse untagResource(DefaultAcsClient kmsClient, String keyId, String tagsKeys) throws ClientException {
        final UntagResourceRequest request = new UntagResourceRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        request.setTagKeys(tagsKeys);
        return kmsClient.getAcsResponse(request);
    }

    public static UpdateAliasResponse updateAlias(DefaultAcsClient kmsClient, String aliasName, String keyId) throws ClientException {
        final UpdateAliasRequest request = new UpdateAliasRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setAliasName(aliasName);
        request.setKeyId(keyId);
        return kmsClient.getAcsResponse(request);
    }

    public static UpdateKeyDescriptionResponse updateKeyDescription(DefaultAcsClient kmsClient, String keyId, String description) throws ClientException {
        final UpdateKeyDescriptionRequest request = new UpdateKeyDescriptionRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        request.setDescription(description);
        return kmsClient.getAcsResponse(request);
    }

    public static UpdateRotationPolicyResponse updateRotationPolicy(DefaultAcsClient kmsClient, String keyId, Boolean enableAutomaticRotation, String rotationInterval) throws ClientException {
        final UpdateRotationPolicyRequest request = new UpdateRotationPolicyRequest();
        request.setSysProtocol(ProtocolType.HTTPS);
        request.setAcceptFormat(FormatType.JSON);
        request.setSysMethod(MethodType.POST);
        request.setKeyId(keyId);
        request.setEnableAutomaticRotation(enableAutomaticRotation);
        request.setRotationInterval(rotationInterval);
        return kmsClient.getAcsResponse(request);
    }
}
