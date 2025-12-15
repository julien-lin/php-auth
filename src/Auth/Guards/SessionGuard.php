<?php

declare(strict_types=1);

namespace JulienLinard\Auth\Guards;

use JulienLinard\Auth\Models\UserInterface;
use JulienLinard\Auth\Providers\UserProviderInterface;
use JulienLinard\Auth\Hashers\HasherInterface;
use JulienLinard\Auth\RememberToken\RememberTokenManagerInterface;
use JulienLinard\Core\Session\Session;

/**
 * Guard d'authentification par session
 */
class SessionGuard implements GuardInterface
{
    private UserProviderInterface $userProvider;
    private HasherInterface $hasher;
    private string $sessionKey;
    private ?UserInterface $user = null;
    private ?RememberTokenManagerInterface $rememberTokenManager = null;
    private string $rememberCookieName;
    private int $rememberLifetime;
    
    /**
     * Cache mémoire pour les utilisateurs (durée d'une requête)
     * Clé : user_id, Valeur : UserInterface
     */
    private static array $userCache = [];

    /**
     * Constructeur
     *
     * @param UserProviderInterface $userProvider Provider d'utilisateurs
     * @param HasherInterface $hasher Hasher de mots de passe
     * @param string $sessionKey Clé de session pour stocker l'utilisateur
     * @param RememberTokenManagerInterface|null $rememberTokenManager Gestionnaire de tokens "Remember Me" (optionnel)
     * @param string $rememberCookieName Nom du cookie "Remember Me" (par défaut: 'remember_token')
     * @param int $rememberLifetime Durée de vie du token en secondes (par défaut: 30 jours)
     */
    public function __construct(
        UserProviderInterface $userProvider,
        HasherInterface $hasher,
        string $sessionKey = 'auth_user',
        ?RememberTokenManagerInterface $rememberTokenManager = null,
        string $rememberCookieName = 'remember_token',
        int $rememberLifetime = 2592000
    ) {
        $this->userProvider = $userProvider;
        $this->hasher = $hasher;
        $this->sessionKey = $sessionKey;
        $this->rememberTokenManager = $rememberTokenManager;
        $this->rememberCookieName = $rememberCookieName;
        $this->rememberLifetime = $rememberLifetime;
    }

    /**
     * Tente d'authentifier un utilisateur avec des credentials
     */
    public function attempt(array $credentials, bool $remember = false): bool
    {
        $user = $this->userProvider->findByCredentials($credentials);
        
        if ($user === null) {
            return false;
        }

        // Vérifier le mot de passe
        if (!isset($credentials['password'])) {
            return false;
        }

        $password = $credentials['password'];
        $hashedPassword = $user->getAuthPassword();

        if (!$this->hasher->verify($password, $hashedPassword)) {
            return false;
        }

        // Rehash si nécessaire et sauvegarder le nouveau hash
        if ($this->hasher->needsRehash($hashedPassword)) {
            $newHash = $this->hasher->hash($password);
            $this->userProvider->updatePassword($user, $newHash);
        }

        // Authentifier l'utilisateur
        $this->login($user, $remember);
        
        return true;
    }

    /**
     * Authentifie un utilisateur directement
     */
    public function login(UserInterface $user, bool $remember = false): void
    {
        // Stocker l'ID de l'utilisateur en session
        Session::set($this->sessionKey, $user->getAuthIdentifier());
        
        // Régénérer l'ID de session pour sécurité
        Session::regenerate(true);
        
        $this->user = $user;
        
        // Créer un token "Remember Me" si demandé
        if ($remember && $this->rememberTokenManager !== null) {
            $token = $this->rememberTokenManager->createToken($user, $this->rememberLifetime);
            $this->setRememberCookie($token->getToken());
        } elseif ($remember && $this->rememberTokenManager === null) {
            // Logger un avertissement si "remember me" est demandé mais non configuré
            error_log(
                'RememberTokenManager non configuré. "Remember Me" ne peut pas être utilisé.'
            );
        }
    }

    /**
     * Déconnecte l'utilisateur actuel
     */
    public function logout(): void
    {
        $user = $this->user;
        
        Session::remove($this->sessionKey);
        Session::regenerate(true);
        
        // Nettoyer le cache de l'utilisateur
        if ($user !== null) {
            self::clearUserCacheFor($user->getAuthIdentifier());
        }
        
        $this->user = null;
        
        // Supprimer le token "Remember Me" si présent
        if ($this->rememberTokenManager !== null) {
            $token = $this->getRememberCookie();
            if ($token !== null) {
                $this->rememberTokenManager->deleteToken($token);
                $this->clearRememberCookie();
            }
            
            // Supprimer tous les tokens de l'utilisateur (optionnel, pour sécurité)
            if ($user !== null) {
                $this->rememberTokenManager->deleteAllTokensForUser($user);
            }
        }
    }

    /**
     * Vérifie si un utilisateur est authentifié
     */
    public function check(): bool
    {
        return $this->user() !== null;
    }

    /**
     * Vérifie si aucun utilisateur n'est authentifié
     */
    public function guest(): bool
    {
        return !$this->check();
    }

    /**
     * Retourne l'utilisateur actuellement authentifié
     */
    public function user(): ?UserInterface
    {
        if ($this->user !== null) {
            return $this->user;
        }

        // Essayer d'abord la session
        $userId = Session::get($this->sessionKey);
        
        if ($userId !== null) {
            // Vérifier le cache mémoire d'abord
            $cacheKey = (string)$userId;
            if (isset(self::$userCache[$cacheKey])) {
                $this->user = self::$userCache[$cacheKey];
                return $this->user;
            }
            
            $user = $this->userProvider->findById($userId);
            if ($user !== null) {
                // Mettre en cache
                self::$userCache[$cacheKey] = $user;
            }
            $this->user = $user;
            return $user;
        }

        // Si pas de session, essayer le token "Remember Me"
        if ($this->rememberTokenManager !== null) {
            $token = $this->getRememberCookie();
            if ($token !== null) {
                $user = $this->rememberTokenManager->getUserByToken($token);
                if ($user !== null) {
                    // Réauthentifier l'utilisateur en session
                    Session::set($this->sessionKey, $user->getAuthIdentifier());
                    Session::regenerate(true);
                    
                    // Mettre en cache
                    $cacheKey = (string)$user->getAuthIdentifier();
                    self::$userCache[$cacheKey] = $user;
                    
                    $this->user = $user;
                    return $user;
                } else {
                    // Token invalide ou expiré, supprimer le cookie
                    $this->clearRememberCookie();
                }
            }
        }
        
        return null;
    }

    /**
     * Nettoie le cache mémoire des utilisateurs
     * 
     * Utile pour forcer le rechargement d'un utilisateur depuis la base de données
     * (par exemple après une mise à jour)
     */
    public static function clearUserCache(): void
    {
        self::$userCache = [];
    }

    /**
     * Nettoie le cache d'un utilisateur spécifique
     * 
     * @param int|string $userId ID de l'utilisateur
     */
    public static function clearUserCacheFor(int|string $userId): void
    {
        $cacheKey = (string)$userId;
        unset(self::$userCache[$cacheKey]);
    }

    /**
     * Définit le cookie "Remember Me"
     */
    private function setRememberCookie(string $token): void
    {
        $expires = time() + $this->rememberLifetime;
        $isHttps = $this->isHttps();
        
        setcookie(
            $this->rememberCookieName,
            $token,
            [
                'expires' => $expires,
                'path' => '/',
                'domain' => '',
                'secure' => $isHttps,
                'httponly' => true,
                'samesite' => 'Strict'
            ]
        );
    }

    /**
     * Récupère le token depuis le cookie "Remember Me"
     */
    private function getRememberCookie(): ?string
    {
        return $_COOKIE[$this->rememberCookieName] ?? null;
    }

    /**
     * Supprime le cookie "Remember Me"
     */
    private function clearRememberCookie(): void
    {
        if (isset($_COOKIE[$this->rememberCookieName])) {
            setcookie(
                $this->rememberCookieName,
                '',
                [
                    'expires' => time() - 3600,
                    'path' => '/',
                    'domain' => '',
                    'secure' => $this->isHttps(),
                    'httponly' => true,
                    'samesite' => 'Strict'
                ]
            );
            unset($_COOKIE[$this->rememberCookieName]);
        }
    }

    /**
     * Vérifie si la requête est en HTTPS
     */
    private function isHttps(): bool
    {
        return (
            (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
            (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') ||
            (!empty($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443)
        );
    }

    /**
     * Retourne l'ID de l'utilisateur actuellement authentifié
     */
    public function id(): int|string|null
    {
        $user = $this->user();
        return $user?->getAuthIdentifier();
    }
}

