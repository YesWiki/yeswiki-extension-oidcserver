<?php

namespace YesWiki\Test\Oidcserver;

require_once 'tests/YesWikiTestCase.php';
require_once 'tools/oidcserver/vendor/autoload.php';

use YesWiki\Core\Service\DbService;
use YesWiki\Test\Core\YesWikiTestCase;
use YesWiki\Wiki;

/**
 * Boots the wiki and makes sure the extension's token table exists, as `./yeswicli migrate` would.
 */
abstract class OidcserverTestCase extends YesWikiTestCase
{
    protected static Wiki $wiki;

    public static function setUpBeforeClass(): void
    {
        self::$wiki = self::getWiki();
        require_once 'tools/oidcserver/migrations/20261108000000_CreateOidcserverTokensTable.php';
        $migration = new \CreateOidcserverTokensTable();
        $migration->setWiki(self::$wiki);
        $migration->setDbService(self::$wiki->services->get(DbService::class));
        $migration->run();
    }

    /** Deletes every code and token issued to the given clients. */
    protected static function deleteTokensOf(array $clientIds): void
    {
        if ($clientIds === []) {
            return;
        }
        $db = self::$wiki->services->get(DbService::class);
        $db->query(sprintf(
            'DELETE FROM %s WHERE client_id IN (%s)',
            $db->prefixTable('oidcserver_tokens'),
            implode(',', array_map(fn ($id) => "'" . $db->escape($id) . "'", $clientIds))
        ));
    }

    protected static function removeDirectory(string $dir): void
    {
        foreach (glob($dir . '/*') ?: [] as $file) {
            unlink($file);
        }
        if (is_dir($dir)) {
            rmdir($dir);
        }
    }
}
