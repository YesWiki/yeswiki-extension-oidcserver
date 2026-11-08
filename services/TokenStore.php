<?php

namespace YesWiki\Oidcserver\Service;

use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use YesWiki\Core\Service\DbService;

/**
 * Persists issued codes and tokens in `oidcserver_tokens` so they can be revoked and checked.
 */
class TokenStore
{
    public const AUTH_CODE = 'auth_code';
    public const ACCESS_TOKEN = 'access_token';
    public const REFRESH_TOKEN = 'refresh_token';

    public function __construct(private readonly DbService $dbService)
    {
    }

    public function table(): string
    {
        return $this->dbService->prefixTable('oidcserver_tokens');
    }

    public function add(string $kind, string $identifier, string $clientId, ?string $userId, \DateTimeImmutable $expiresAt): void
    {
        if ($this->find($identifier) !== null) {
            throw UniqueTokenIdentifierConstraintViolationException::create();
        }
        $this->dbService->query(sprintf(
            "INSERT INTO %s (identifier, kind, client_id, user_id, expires_at, revoked) VALUES ('%s', '%s', '%s', %s, '%s', 0)",
            $this->table(),
            $this->dbService->escape($identifier),
            $this->dbService->escape($kind),
            $this->dbService->escape($clientId),
            $userId === null ? 'NULL' : "'" . $this->dbService->escape($userId) . "'",
            $expiresAt->format('Y-m-d H:i:s')
        ));
        $this->purgeExpired();
    }

    public function revoke(string $identifier): void
    {
        $this->dbService->query(sprintf(
            "UPDATE %s SET revoked = 1 WHERE identifier = '%s'",
            $this->table(),
            $this->dbService->escape($identifier)
        ));
    }

    public function isRevoked(string $identifier): bool
    {
        $row = $this->find($identifier);

        return $row === null || (int)$row['revoked'] === 1;
    }

    /** Records the nonce an authorization code carries over to its ID token. */
    public function bindNonce(string $authCodeId, string $nonce): void
    {
        $this->dbService->query(sprintf(
            "UPDATE %s SET nonce = '%s' WHERE identifier = '%s' AND kind = '%s'",
            $this->table(),
            $this->dbService->escape($nonce),
            $this->dbService->escape($authCodeId),
            self::AUTH_CODE
        ));
    }

    public function nonce(string $authCodeId): ?string
    {
        $row = $this->find($authCodeId);

        return isset($row['nonce']) && $row['nonce'] !== '' ? (string)$row['nonce'] : null;
    }

    private function find(string $identifier): ?array
    {
        return $this->dbService->loadSingle(sprintf(
            "SELECT * FROM %s WHERE identifier = '%s'",
            $this->table(),
            $this->dbService->escape($identifier)
        ));
    }

    private function purgeExpired(): void
    {
        $this->dbService->query(sprintf(
            "DELETE FROM %s WHERE expires_at < '%s'",
            $this->table(),
            (new \DateTimeImmutable('-1 day'))->format('Y-m-d H:i:s')
        ));
    }
}
