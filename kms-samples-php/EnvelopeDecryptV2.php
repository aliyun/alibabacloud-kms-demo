<?php

/**
 * 本示例展示了使用阿里云SDK V2（alibabacloud/kms-20160120）调用KMS Decrypt接口解密数据密钥密文，
 * 然后在本地以AES-256-GCM模式对数据密文解密的用法（示例使用OpenSSL密码库）。
 * 流程参考：https://help.aliyun.com/zh/kms/key-management-service/use-cases/use-envelope-encryption
 *
 * 依赖安装：composer require alibabacloud/kms-20160120
 */

require_once __DIR__ . '/vendor/autoload.php';

use AlibabaCloud\SDK\Kms\V20160120\Kms;
use AlibabaCloud\SDK\Kms\V20160120\Models\DecryptRequest;
use Darabonba\OpenApi\Models\Config;

// 如果kms实例开启公网访问，endpoint 请参考 https://api.aliyun.com/product/Kms
// 如果kms实例未开启公网访问，endpoint 请使用实例VPC地址或专属网关地址
const ENDPOINT = '<your kms endpoint>';
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
 * 调用Decrypt接口解密数据密钥密文，返回数据密钥明文（Base64编码）
 */
function kmsDecrypt(Kms $client, string $cipherTextBlob): string
{
    $request = new DecryptRequest([
        'ciphertextBlob' => $cipherTextBlob,
    ]);
    $response = $client->decrypt($request);
    return $response->body->plaintext;
}

/**
 * 使用数据密钥明文在本地以AES-256-GCM模式解密数据（示例使用OpenSSL密码库）。
 * 数据密文末尾附加了16字节GCM认证标签，解密时需拆分后单独传入，OpenSSL会自动校验。
 */
function localDecrypt(string $dataKey, string $iv, string $cipherTextWithTag, string $outFile): void
{
    $tag = substr($cipherTextWithTag, -GCM_TAG_LENGTH);
    $cipherText = substr($cipherTextWithTag, 0, strlen($cipherTextWithTag) - GCM_TAG_LENGTH);

    $plaintext = openssl_decrypt($cipherText, 'aes-256-gcm', $dataKey, OPENSSL_RAW_DATA, $iv, $tag);
    if (false === $plaintext) {
        throw new RuntimeException('openssl_decrypt error, GCM tag verify failed');
    }
    file_put_contents($outFile, $plaintext);
}

// 1.创建 KMS Client 对象并初始化
$client = createKmsClient();

$inFile = './data/sales.csv.cipher';
$outFile = './data/decrypted_sales.csv';

// 2.读取信封文件：数据密钥密文、IV、数据密文（含GCM标签）
$inLines = explode("\n", trim(file_get_contents($inFile)));

// 3.调用Decrypt接口解密数据密钥密文，得到数据密钥明文
$plainKey = kmsDecrypt($client, $inLines[0]);

// 4.使用数据密钥明文在本地解密数据密文
localDecrypt(base64_decode($plainKey), base64_decode($inLines[1]), base64_decode($inLines[2]), $outFile);
echo "envelope decrypt done: {$outFile}\n";
