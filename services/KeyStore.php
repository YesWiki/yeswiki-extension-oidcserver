<?php

namespace YesWiki\Oidcserver\Service;

use Defuse\Crypto\Key;
use League\OAuth2\Server\CryptKey;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

/**
 * The provider's signing key pair and encryption key, generated on first use under `oidc_keys_path`.
 */
class KeyStore
{
    private const PRIVATE_KEY = 'private.key';
    private const ENCRYPTION_KEY = 'encryption.key';

    public function __construct(private readonly ParameterBagInterface $params)
    {
    }

    public function privateKey(): CryptKey
    {
        return new CryptKey($this->privateKeyPem());
    }

    public function publicKey(): CryptKey
    {
        return new CryptKey($this->publicKeyPem());
    }

    public function encryptionKey(): Key
    {
        $path = $this->path(self::ENCRYPTION_KEY);
        if (!is_file($path)) {
            $this->write($path, Key::createNewRandomKey()->saveToAsciiSafeString());
        }

        return Key::loadFromAsciiSafeString(trim((string)file_get_contents($path)));
    }

    /** Key identifier advertised in the JWKS and in every signed token header. */
    public function keyId(): string
    {
        return substr($this->base64Url(hash('sha256', $this->rsaDetails()['n'], true)), 0, 16);
    }

    /**
     * @return array<string,string>
     */
    public function publicJwk(): array
    {
        $rsa = $this->rsaDetails();

        return [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => $this->keyId(),
            'n' => $this->base64Url($rsa['n']),
            'e' => $this->base64Url($rsa['e']),
        ];
    }

    private function privateKeyPem(): string
    {
        $path = $this->path(self::PRIVATE_KEY);
        if (!is_file($path)) {
            $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            if ($key === false || !openssl_pkey_export($key, $pem)) {
                throw new \RuntimeException('Unable to generate the OpenID Connect signing key');
            }
            $this->write($path, $pem);
        }

        return (string)file_get_contents($path);
    }

    private function publicKeyPem(): string
    {
        return $this->details()['key'];
    }

    /**
     * @return array{n:string,e:string}
     */
    private function rsaDetails(): array
    {
        return $this->details()['rsa'];
    }

    private function details(): array
    {
        $key = openssl_pkey_get_private($this->privateKeyPem());
        $details = $key === false ? false : openssl_pkey_get_details($key);
        if ($details === false) {
            throw new \RuntimeException('The OpenID Connect signing key cannot be read');
        }

        return $details;
    }

    private function path(string $file): string
    {
        return rtrim((string)$this->params->get('oidc_keys_path'), '/') . '/' . $file;
    }

    private function write(string $path, string $contents): void
    {
        $dir = dirname($path);
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException("Unable to create {$dir}");
        }
        $tmp = tempnam($dir, 'key');
        if ($tmp === false || file_put_contents($tmp, $contents) === false || !chmod($tmp, 0600) || !rename($tmp, $path)) {
            throw new \RuntimeException("Unable to write {$path}");
        }
    }

    private function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
