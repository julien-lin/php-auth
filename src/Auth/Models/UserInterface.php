<?php

namespace JulienLinard\Auth\Models;

/**
 * Interface pour les modèles utilisateur
 */
interface UserInterface
{
    /**
     * Retourne l'identifiant unique de l'utilisateur
     */
    public function getAuthIdentifier(): int|string;

    /**
     * Retourne le mot de passe hashé de l'utilisateur
     */
    public function getAuthPassword(): string;

    /**
     * Retourne les rôles de l'utilisateur
     *
     * @return array|string Tableau de rôles ou string
     */
    public function getAuthRoles(): array|string;

    /**
     * Retourne les permissions de l'utilisateur
     *
     * @return array Tableau de permissions
     */
    public function getAuthPermissions(): array;
}

