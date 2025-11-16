<?php

namespace JulienLinard\Auth;

use JulienLinard\Auth\Guards\GuardInterface;
use JulienLinard\Auth\Guards\SessionGuard;
use JulienLinard\Auth\Providers\UserProviderInterface;
use JulienLinard\Auth\Providers\DatabaseUserProvider;
use JulienLinard\Auth\Hashers\HasherInterface;
use JulienLinard\Auth\Hashers\PasswordHasher;
use JulienLinard\Doctrine\EntityManager;
use JulienLinard\Auth\Models\UserInterface;

/**
 * Gestionnaire principal d'authentification
 */
class AuthManager
{
    private GuardInterface $guard;
    private array $config;

    /**
     * Constructeur
     *
     * @param array $config Configuration
     */
    public function __construct(array $config)
    {
        $this->config = $this->normalizeConfig($config);
        $this->guard = $this->createGuard();
    }

    /**
     * Normalise la configuration
     */
    private function normalizeConfig(array $config): array
    {
        return [
            'user_class' => $config['user_class'] ?? null,
            'entity_manager' => $config['entity_manager'] ?? null,
            'session_key' => $config['session_key'] ?? 'auth_user',
            'remember_me' => $config['remember_me'] ?? true,
            'identifier_field' => $config['identifier_field'] ?? 'id',
            'credential_field' => $config['credential_field'] ?? 'email',
            'hasher' => $config['hasher'] ?? null,
            'hasher_algorithm' => $config['hasher_algorithm'] ?? null,
            'hasher_options' => $config['hasher_options'] ?? null,
            'provider' => $config['provider'] ?? null,
        ];
    }

    /**
     * Crée le guard par défaut
     */
    private function createGuard(): GuardInterface
    {
        $userProvider = $this->createUserProvider();
        $hasher = $this->createHasher();
        
        return new SessionGuard(
            $userProvider,
            $hasher,
            $this->config['session_key']
        );
    }

    /**
     * Crée le provider d'utilisateurs
     */
    private function createUserProvider(): UserProviderInterface
    {
        if ($this->config['provider'] !== null) {
            return $this->config['provider'];
        }

        $em = $this->config['entity_manager'];
        if (!$em instanceof EntityManager) {
            throw new \RuntimeException('EntityManager requis pour DatabaseUserProvider.');
        }

        $userClass = $this->config['user_class'];
        if ($userClass === null) {
            throw new \RuntimeException('user_class requis dans la configuration.');
        }

        return new DatabaseUserProvider(
            $em,
            $userClass,
            $this->config['identifier_field'],
            $this->config['credential_field']
        );
    }

    /**
     * Crée le hasher de mots de passe
     */
    private function createHasher(): HasherInterface
    {
        if ($this->config['hasher'] !== null) {
            return $this->config['hasher'];
        }

        // Si un algorithme est spécifié dans la config, l'utiliser
        $algorithm = $this->config['hasher_algorithm'] ?? PASSWORD_BCRYPT;
        $options = $this->config['hasher_options'] ?? [];

        // Convertir string en constante si nécessaire
        if (is_string($algorithm)) {
            $algorithm = match(strtoupper($algorithm)) {
                'BCRYPT', 'PASSWORD_BCRYPT' => PASSWORD_BCRYPT,
                'ARGON2ID', 'PASSWORD_ARGON2ID' => defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT,
                'ARGON2I', 'PASSWORD_ARGON2I' => defined('PASSWORD_ARGON2I') ? PASSWORD_ARGON2I : PASSWORD_BCRYPT,
                default => PASSWORD_BCRYPT,
            };
        }

        return new PasswordHasher($algorithm, $options);
    }

    /**
     * Tente d'authentifier un utilisateur avec des credentials
     */
    public function attempt(array $credentials, bool $remember = false): bool
    {
        return $this->guard->attempt($credentials, $remember);
    }

    /**
     * Authentifie un utilisateur directement
     */
    public function login(UserInterface $user, bool $remember = false): void
    {
        $this->guard->login($user, $remember);
    }

    /**
     * Déconnecte l'utilisateur actuel
     */
    public function logout(): void
    {
        $this->guard->logout();
    }

    /**
     * Vérifie si un utilisateur est authentifié
     */
    public function check(): bool
    {
        return $this->guard->check();
    }

    /**
     * Vérifie si aucun utilisateur n'est authentifié
     */
    public function guest(): bool
    {
        return $this->guard->guest();
    }

    /**
     * Retourne l'utilisateur actuellement authentifié
     */
    public function user(): ?UserInterface
    {
        return $this->guard->user();
    }

    /**
     * Retourne l'ID de l'utilisateur actuellement authentifié
     */
    public function id(): int|string|null
    {
        return $this->guard->id();
    }

    /**
     * Vérifie si l'utilisateur a un rôle spécifique
     */
    public function hasRole(string $role): bool
    {
        $user = $this->user();
        return $user !== null && $user->hasRole($role);
    }

    /**
     * Vérifie si l'utilisateur a une permission spécifique
     */
    public function can(string $permission): bool
    {
        $user = $this->user();
        return $user !== null && $user->hasPermission($permission);
    }

    /**
     * Retourne le guard actuel
     */
    public function guard(): GuardInterface
    {
        return $this->guard;
    }
}

