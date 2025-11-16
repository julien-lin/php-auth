<?php

namespace JulienLinard\Auth\Providers;

use JulienLinard\Auth\Models\UserInterface;

/**
 * Interface pour les providers d'utilisateurs
 */
interface UserProviderInterface
{
    /**
     * Retourne un utilisateur par son identifiant
     *
     * @param int|string $identifier Identifiant de l'utilisateur
     * @return UserInterface|null Utilisateur ou null
     */
    public function findById(int|string $identifier): ?UserInterface;

    /**
     * Retourne un utilisateur par ses credentials
     *
     * @param array $credentials Credentials (ex: ['email' => '...', 'password' => '...'])
     * @return UserInterface|null Utilisateur ou null
     */
    public function findByCredentials(array $credentials): ?UserInterface;

    /**
     * Retourne un utilisateur par un champ spécifique
     *
     * @param string $field Nom du champ
     * @param mixed $value Valeur
     * @return UserInterface|null Utilisateur ou null
     */
    public function findByField(string $field, mixed $value): ?UserInterface;
}

