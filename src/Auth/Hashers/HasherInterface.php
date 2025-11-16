<?php

namespace JulienLinard\Auth\Hashers;

/**
 * Interface pour les hash de mots de passe
 */
interface HasherInterface
{
    /**
     * Hash un mot de passe
     *
     * @param string $password Mot de passe en clair
     * @return string Mot de passe hashé
     */
    public function hash(string $password): string;

    /**
     * Vérifie qu'un mot de passe correspond à un hash
     *
     * @param string $password Mot de passe en clair
     * @param string $hash Hash à vérifier
     * @return bool True si le mot de passe correspond
     */
    public function verify(string $password, string $hash): bool;

    /**
     * Vérifie si un hash doit être rehashé
     *
     * @param string $hash Hash à vérifier
     * @return bool True si le hash doit être rehashé
     */
    public function needsRehash(string $hash): bool;
}

