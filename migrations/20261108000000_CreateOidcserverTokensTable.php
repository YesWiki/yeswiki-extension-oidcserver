<?php

use YesWiki\Core\YesWikiMigration;

/**
 * Creates the table holding the authorization codes, access tokens and refresh tokens the provider issues.
 */
class CreateOidcserverTokensTable extends YesWikiMigration
{
    public function run()
    {
        $this->dbService->query(sprintf(
            'CREATE TABLE IF NOT EXISTS %s (
                identifier VARCHAR(128) NOT NULL,
                kind VARCHAR(16) NOT NULL,
                client_id VARCHAR(190) NOT NULL,
                user_id VARCHAR(190) DEFAULT NULL,
                nonce VARCHAR(255) DEFAULT NULL,
                expires_at DATETIME NOT NULL,
                revoked TINYINT(1) NOT NULL DEFAULT 0,
                PRIMARY KEY (identifier),
                KEY idx_expires_at (expires_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci',
            $this->dbService->prefixTable('oidcserver_tokens')
        ));
    }
}
