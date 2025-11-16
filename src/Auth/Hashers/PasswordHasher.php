<?php

namespace JulienLinard\Auth\Hashers;

/**
 * Hasher de mots de passe utilisant password_hash() PHP
 */
class PasswordHasher implements HasherInterface
{
    /**
     * Algorithme de hash (PASSWORD_BCRYPT ou PASSWORD_ARGON2ID)
     */
    private int $algorithm;

    /**
     * Options pour password_hash()
     */
    private array $options;

    /**
     * Constructeur
     *
     * @param int $algorithm Algorithme (PASSWORD_BCRYPT par défaut)
     * @param array $options Options pour password_hash()
     */
    public function __construct(int $algorithm = PASSWORD_BCRYPT, array $options = [])
    {
        $this->algorithm = $algorithm;
        
        // Options par défaut selon l'algorithme
        if (empty($options)) {
            if ($algorithm === PASSWORD_BCRYPT) {
                $this->options = ['cost' => 12];
            } elseif ($algorithm === PASSWORD_ARGON2ID) {
                $this->options = [
                    'memory_cost' => 65536, // 64 MB
                    'time_cost' => 4,
                    'threads' => 3,
                ];
            } else {
                $this->options = [];
            }
        } else {
            $this->options = $options;
        }
    }

    /**
     * Hash un mot de passe
     */
    public function hash(string $password): string
    {
        $hash = password_hash($password, $this->algorithm, $this->options);
        
        if ($hash === false) {
            throw new \RuntimeException('Impossible de hasher le mot de passe.');
        }
        
        return $hash;
    }

    /**
     * Vérifie qu'un mot de passe correspond à un hash
     */
    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Vérifie si un hash doit être rehashé
     */
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, $this->algorithm, $this->options);
    }
}

