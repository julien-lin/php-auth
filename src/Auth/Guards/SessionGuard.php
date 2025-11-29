<?php

declare(strict_types=1);

namespace JulienLinard\Auth\Guards;

use JulienLinard\Auth\Models\UserInterface;
use JulienLinard\Auth\Providers\UserProviderInterface;
use JulienLinard\Auth\Hashers\HasherInterface;
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

    /**
     * Constructeur
     *
     * @param UserProviderInterface $userProvider Provider d'utilisateurs
     * @param HasherInterface $hasher Hasher de mots de passe
     * @param string $sessionKey Clé de session pour stocker l'utilisateur
     */
    public function __construct(
        UserProviderInterface $userProvider,
        HasherInterface $hasher,
        string $sessionKey = 'auth_user'
    ) {
        $this->userProvider = $userProvider;
        $this->hasher = $hasher;
        $this->sessionKey = $sessionKey;
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

        // Rehash si nécessaire
        if ($this->hasher->needsRehash($hashedPassword)) {
            $newHash = $this->hasher->hash($password);
            // Note: Il faudrait sauvegarder le nouveau hash dans la base
            // Cela nécessiterait une méthode updatePassword() sur l'entité
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
        
        // TODO: Implémenter "remember me" avec tokens persistants
        if ($remember) {
            // Créer un token et le stocker en cookie
        }
    }

    /**
     * Déconnecte l'utilisateur actuel
     */
    public function logout(): void
    {
        Session::remove($this->sessionKey);
        Session::regenerate(true);
        $this->user = null;
        
        // TODO: Supprimer le token "remember me" si présent
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

        $userId = Session::get($this->sessionKey);
        
        if ($userId === null) {
            return null;
        }

        $user = $this->userProvider->findById($userId);
        $this->user = $user;
        
        return $user;
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

