<?php

/**
 * 本示例展示了使用阿里云SDK V2（alibabacloud/kms-20160120）调用KMS GenerateDataKey接口，
 * 在本地以AES-256-GCM模式对数据进行信封加密的用法（示例使用OpenSSL密码库）。
 * 流程参考：https://help.aliyun.com/zh/kms/key-management-service/use-cases/use-envelope-encryption
 *
 * 依赖安装：composer require alibabacloud/kms-20160120
 */

require_once __DIR__ . '/vendor/autoload.php';

use AlibabaCloud\SDK\Kms\V20160120\Kms;
use AlibabaCloud\SDK\Kms\V20160120\Models\GenerateDataKeyRequest;
use Darabonba\OpenApi\Models\Config;

// 如果kms实例开启公网访问，endpoint 请参考 https://api.aliyun.com/product/Kms
// 如果kms实例未开启公网访问，endpoint 请使用实例VPC地址或专属网关地址
const ENDPOINT = '<your kms endpoint>';
// 填写您在KMS创建的对称主密钥Id，也可以使用密钥别名（如alias/Example）
const KEY_ID = '<your cmk id>';
// 数据密钥长度，32字节（256位）AES密钥
const NUMBER_OF_BYTES = 32;
// GCM模式初始向量长度
const GCM_IV_LENGTH = 12;
// GCM认证标签长度
const GCM_TAG_LENGTH = 16;

/**
 * 使用阿里云SDK V2（alibabacloud/kms-20160120）创建KMS Client
 */
function createKmsClient(): Kms
{
    $config = new Config([
        // 必填，请确保代码运行环境设置了环境变量 ALIBABA_CLOUD_ACCESS_KEY_ID。
        'accessKeyId' => getenv('ALIBABA_CLOUD_ACCESS_KEY_ID'),
        // 必填，请确保代码运行环境设置了环境变量 ALIBABA_CLOUD_ACCESS_KEY_SECRET。
        'accessKeySecret' => getenv('ALIBABA_CLOUD_ACCESS_KEY_SECRET'),
    ]);
    // Endpoint 请参考 https://api.aliyun.com/product/Kms
    $config->endpoint = ENDPOINT;
    // 如果使用实例专属网关并且验证服务端证书，请设置ca证书。
    // 注意：本 SDK 的 $config->ca 不会被底层传输层使用（不生效），请改用 Dara 全局配置注入
    // CA 证书的“文件路径”（不是证书内容），且不要设置 ignoreSSL（否则会覆盖此处证书校验）。
    // 需 use AlibabaCloud\Dara\Dara; 或直接使用全限定名，在创建 Client 前调用一次即可：
    // \AlibabaCloud\Dara\Dara::config(['verify' => '/path/to/kms-ca.pem']);
    return new Kms($config);
}

/**
 * 调用GenerateDataKey接口生成数据密钥，返回数据密钥明文与密文（均为Base64编码）
 */
function kmsGenerateDataKey(Kms $client, string $keyId): array
{
    $request = new GenerateDataKeyRequest([
        'keyId' => $keyId,
        'numberOfBytes' => NUMBER_OF_BYTES,
    ]);
    $response = $client->generateDataKey($request);
    return [$response->body->plaintext, $response->body->ciphertextBlob];
}

/**
 * 使用数据密钥明文在本地以AES-256-GCM模式加密数据（示例使用OpenSSL密码库）。
 * 加密完成后数据密钥明文应立即销毁，仅持久化数据密钥密文（信封）。
 *
 * 密文文件格式（文本，三行）
 * 第1行: Base64编码的数据密钥密文（信封）
 * 第2行: Base64编码的IV
 * 第3行: Base64编码的数据密文（末尾附加GCM认证标签）
 */
function localEncrypt(string $plainKey, string $encryptedKey, string $inFile, string $outFile): void
{
    $key = base64_decode($plainKey);
    $iv = random_bytes(GCM_IV_LENGTH);
    $tag = '';

    $inContent = file_get_contents($inFile);
    // openssl_encrypt 的 tag 通过引用参数返回，密文本身不含tag
    $cipherText = openssl_encrypt($inContent, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', GCM_TAG_LENGTH);
    if (false === $cipherText) {
        throw new RuntimeException('openssl_encrypt error');
    }

    $lines = $encryptedKey . "\n" . base64_encode($iv) . "\n" . base64_encode($cipherText . $tag);
    file_put_contents($outFile, $lines);
}

// 1.创建 KMS Client 对象并初始化
$client = createKmsClient();

$inFile = './data/sales.csv';
$outFile = './data/sales.csv.cipher';

// 2.调用GenerateDataKey接口生成数据密钥
list($plainKey, $cipherBlobKey) = kmsGenerateDataKey($client, KEY_ID);

// 3.使用数据密钥明文在本地加密数据，数据密钥密文作为信封与数据密文一起保存
localEncrypt($plainKey, $cipherBlobKey, $inFile, $outFile);
echo "envelope encrypt done: {$outFile}\n";
