<?php

namespace YesWiki\Test\Oidcserver\Service;

require_once 'includes/autoload.inc.php';
require_once 'tools/oidcserver/vendor/autoload.php';

use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBag;
use YesWiki\Oidcserver\Service\KeyStore;

class KeyStoreTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/oidcserver-keystore-' . bin2hex(random_bytes(6)) . '/oidc';
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            unlink($file);
        }
        if (is_dir($this->dir)) {
            rmdir($this->dir);
            rmdir(dirname($this->dir));
        }
    }

    public function testKeysAreCreatedPrivateOnFirstUse(): void
    {
        $this->store()->privateKey();
        $this->store()->encryptionKey();

        $this->assertSame(0700, fileperms($this->dir) & 0777);
        $this->assertSame(0600, fileperms($this->dir . '/private.key') & 0777);
        $this->assertSame(0600, fileperms($this->dir . '/encryption.key') & 0777);
    }

    public function testKeysAreReusedAcrossInstances(): void
    {
        $first = $this->store();
        $kid = $first->keyId();
        $encryptionKey = $first->encryptionKey()->saveToAsciiSafeString();

        $second = $this->store();
        $this->assertSame($kid, $second->keyId());
        $this->assertSame($first->privateKey()->getKeyContents(), $second->privateKey()->getKeyContents());
        $this->assertSame($encryptionKey, $second->encryptionKey()->saveToAsciiSafeString());
    }

    public function testThePublishedJwkVerifiesWhatThePrivateKeySigns(): void
    {
        $store = $this->store();
        $jwk = $store->publicJwk();
        openssl_sign('payload', $signature, $store->privateKey()->getKeyContents(), OPENSSL_ALGO_SHA256);

        $this->assertSame(['kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256', 'kid' => $store->keyId()], array_intersect_key($jwk, array_flip(['kty', 'use', 'alg', 'kid'])));
        $this->assertSame(1, openssl_verify('payload', $signature, self::pemFromJwk($jwk), OPENSSL_ALGO_SHA256));
        $this->assertSame(1, openssl_verify('payload', $signature, $store->publicKey()->getKeyContents(), OPENSSL_ALGO_SHA256));
    }

    private function store(): KeyStore
    {
        return new KeyStore(new ParameterBag(['oidc_keys_path' => $this->dir]));
    }

    /** Rebuilds a PEM public key from the modulus and exponent of a JWK, as a relying party does. */
    private static function pemFromJwk(array $jwk): string
    {
        $decode = fn (string $value) => base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4));
        $length = fn (string $bytes) => strlen($bytes) < 128 ? chr(strlen($bytes)) : (strlen($bytes) < 256 ? "\x81" . chr(strlen($bytes)) : "\x82" . pack('n', strlen($bytes)));
        $der = fn (int $tag, string $bytes) => chr($tag) . $length($bytes) . $bytes;
        $integer = fn (string $bytes) => $der(0x02, (ord($bytes[0]) > 0x7F ? "\0" : '') . $bytes);
        $rsaKey = $der(0x30, $integer($decode($jwk['n'])) . $integer($decode($jwk['e'])));
        $spki = $der(0x30, $der(0x30, "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00") . $der(0x03, "\0" . $rsaKey));

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }
}
