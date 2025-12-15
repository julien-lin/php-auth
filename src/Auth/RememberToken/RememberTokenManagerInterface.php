<?php

declare(strict_types=1);

namespace JulienLinard\Auth\RememberToken;

use JulienLinard\Auth\Models\UserInterface;

/**
 * Interface pour le gestionnaire de tokens "Remember Me"
 */
interface RememberTokenManagerInterface
{
    /**
     * Crée un nouveau token "Remember Me" pour un utilisateur
     *
     * @param UserInterface $user Utilisateur
     * @param int $lifetime Durée de vie en secondes (par défaut: 30 jours)
     * @return RememberToken Token créé
     */
    public function createToken(UserInterface $user, int $lifetime = 2592000): RememberToken;

    /**
     * Récupère un utilisateur par son token "Remember Me"
     *
     * @param string $token Token
     * @return UserInterface|null Utilisateur ou null si token invalide/expiré
     */
    public function getUserByToken(string $token): ?UserInterface;

    /**
     * Supprime un token "Remember Me"
     *
     * @param string $token Token à supprimer
     * @return void
     */
    public function deleteToken(string $token): void;

    /**
     * Supprime tous les tokens d'un utilisateur
     *
     * @param UserInterface $user Utilisateur
     * @return void
     */
    public function deleteAllTokensForUser(UserInterface $user): void;

    /**
     * Nettoie les tokens expirés
     *
     * @return int Nombre de tokens supprimés
     */
    public function cleanExpiredTokens(): int;
}

