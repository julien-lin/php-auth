<?php

namespace JulienLinard\Auth\Guards;

use JulienLinard\Auth\Models\UserInterface;

/**
 * Interface pour les guards d'authentification
 */
interface GuardInterface
{
    /**
     * Tente d'authentifier un utilisateur avec des credentials
     *
     * @param array $credentials Credentials (ex: ['email' => '...', 'password' => '...'])
     * @param bool $remember Si true, crée un token "remember me"
     * @return bool True si l'authentification a réussi
     */
    public function attempt(array $credentials, bool $remember = false): bool;

    /**
     * Authentifie un utilisateur directement (sans vérification de mot de passe)
     *
     * @param UserInterface $user Utilisateur à authentifier
     * @param bool $remember Si true, crée un token "remember me"
     * @return void
     */
    public function login(UserInterface $user, bool $remember = false): void;

    /**
     * Déconnecte l'utilisateur actuel
     *
     * @return void
     */
    public function logout(): void;

    /**
     * Vérifie si un utilisateur est authentifié
     *
     * @return bool True si authentifié
     */
    public function check(): bool;

    /**
     * Vérifie si aucun utilisateur n'est authentifié
     *
     * @return bool True si non authentifié
     */
    public function guest(): bool;

    /**
     * Retourne l'utilisateur actuellement authentifié
     *
     * @return UserInterface|null Utilisateur ou null
     */
    public function user(): ?UserInterface;

    /**
     * Retourne l'ID de l'utilisateur actuellement authentifié
     *
     * @return int|string|null ID ou null
     */
    public function id(): int|string|null;
}

