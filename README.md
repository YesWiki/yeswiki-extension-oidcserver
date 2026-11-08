# YesWiki OpenID Connect server

Cette extension fait de YesWiki un fournisseur OpenID Connect. Une application déclarée (Nextcloud, Mattermost, Discourse, etc.) peut alors proposer « Se connecter avec le wiki ». La personne se connecte sur le wiki, accepte de partager son identité, et revient dans l'application connectée.

Le socle OAuth2 est [league/oauth2-server](https://oauth2.thephpleague.com/) 9.4. L'extension y ajoute la couche OpenID Connect : `id_token` signé en RS256, `nonce`, `/userinfo`, JWKS et document de découverte.

## Installation

```sh
cd tools/oidcserver
composer install --no-dev
cd ../..
./yeswicli migrate
```

La migration crée la table `<préfixe>oidcserver_tokens`. Au premier appel, l'extension génère la clé de signature RSA et la clé de chiffrement dans `private/oidc/`, avec les droits 0600. Supprimer ce dossier invalide tous les jetons émis.

## Déclarer une application

Les applications se déclarent dans `wakka.config.php`. Il n'y a pas encore d'interface d'administration.

```php
'oidc_clients' => [
    'nextcloud' => [
        'name' => 'Nextcloud de l\'association',
        'secret_hash' => '$2y$12$…',
        'redirect_uris' => ['https://cloud.example.org/apps/user_oidc/code'],
        'skip_consent' => false,
    ],
],
```

La clé du tableau (`nextcloud`) est le `client_id`. Le wiki ne garde que le hash du secret. Pour le produire :

```sh
php -r 'echo password_hash("le-secret-donné-à-l-application", PASSWORD_DEFAULT), "\n";'
```

Sans `secret_hash`, le client est public : il ne s'authentifie pas, et PKCE devient obligatoire. Avec `skip_consent` à `true`, une personne déjà connectée ne voit pas l'écran de consentement. Réservez-le aux applications de la même structure.

Durées de vie, en durées ISO 8601 : `oidc_auth_code_ttl` (`PT10M`), `oidc_access_token_ttl` (`PT1H`), `oidc_refresh_token_ttl` (`P1M`).

## Points de terminaison

L'issuer est l'URL de base du wiki, sans `?` ni barre finale, par exemple `https://wiki.example.org`.

| Rôle | URL |
| --- | --- |
| Découverte | `?api/oidc/openid-configuration` |
| Autorisation | `?api/oidc/authorize` |
| Jeton | `?api/oidc/token` |
| Userinfo | `?api/oidc/userinfo` |
| JWKS | `?api/oidc/jwks` |

Une application qui découvre le fournisseur toute seule cherche `<issuer>/.well-known/openid-configuration`. Avec Apache, ajoutez dans le `.htaccess` du wiki, à côté de la règle WebFinger :

```apache
RewriteRule ^\.well-known/openid-configuration$ index.php?wiki=api/oidc/openid-configuration [QSA,L]
```

Sans cette règle, il faut donner à l'application les URL une par une.

## Scopes et claims

| Scope | Claims |
| --- | --- |
| `openid` | `sub` (le nom d'utilisateur du wiki) |
| `profile` | `name`, `preferred_username` |
| `email` | `email` |
| `offline_access` | aucun, accepté pour les clients qui le demandent |

## Limites connues

- Seul le flux par code d'autorisation est géré. Pas de flux implicite ni hybride, pas de `client_credentials`.
- Le RequestGuard du core refuse les POST venant d'un autre site. Un client qui appelle `?api/oidc/token` depuis le navigateur (application JavaScript sur un autre domaine) reçoit donc un 403. Les clients côté serveur ne sont pas concernés.
- Pas de `auth_time` dans l'`id_token` : le wiki ne garde pas l'heure de connexion. `max_age` et `prompt=login` sont ignorés.
- Pas de déconnexion initiée par l'application (`end_session_endpoint`), pas d'enregistrement dynamique de clients, pas de rotation de clé.
- `sub` est le nom d'utilisateur. Si un compte change de nom, les applications le voient comme une nouvelle personne.
