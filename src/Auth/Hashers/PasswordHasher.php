<?php

declare(strict_types=1);

namespace JulienLinard\Auth\Hashers;

/**
 * Hasher de mots de passe utilisant password_hash() PHP
 */
class PasswordHasher implements HasherInterface
{
    /**
     * Algorithme de hash (PASSWORD_BCRYPT ou PASSWORD_ARGON2ID)
     * Stocké comme int (2 pour BCRYPT, 3 pour ARGON2ID)
     */
    private int $algorithm;

    /**
     * Options pour password_hash()
     */
    private array $options;

    /**
     * Constructeur
     *
     * @param int|string $algorithm Algorithme (PASSWORD_BCRYPT par défaut)
     * @param array $options Options pour password_hash()
     */
    public function __construct(int|string $algorithm = PASSWORD_BCRYPT, array $options = [])
    {
        // Normaliser l'algorithme (convertir string en int si nécessaire)
        $this->algorithm = $this->normalizeAlgorithm($algorithm);
        
        // Options par défaut selon l'algorithme
        if (empty($options)) {
            if ($this->algorithm === 2) {
                $this->options = ['cost' => 12];
            } elseif (defined('PASSWORD_ARGON2ID') && is_int(PASSWORD_ARGON2ID) && $this->algorithm === PASSWORD_ARGON2ID) {
                $this->options = [
                    'memory_cost' => 65536, // 64 MB
                    'time_cost' => 4,
                    'threads' => 3,
                ];
            } elseif ($this->algorithm === 3) {
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
     * Normalise l'algorithme (convertit string en int si nécessaire)
     * 
     * @param int|string $algorithm Algorithme
     * @return int Algorithme normalisé
     */
    private function normalizeAlgorithm(int|string $algorithm): int
    {
        if (is_int($algorithm)) {
            return $algorithm;
        }
        
        // Convertir les strings en constantes entières
        return match(strtoupper($algorithm)) {
            'BCRYPT', 'PASSWORD_BCRYPT', '2Y', '2A' => 2,
            'ARGON2ID', 'PASSWORD_ARGON2ID' => defined('PASSWORD_ARGON2ID') && is_int(PASSWORD_ARGON2ID) ? PASSWORD_ARGON2ID : 2,
            'ARGON2I', 'PASSWORD_ARGON2I' => defined('PASSWORD_ARGON2I') && is_int(PASSWORD_ARGON2I) ? PASSWORD_ARGON2I : 2,
            default => 2,
        };
    }

    /**
     * Hash un mot de passe
     */
    public function hash(string $password): string
    {
        // Utiliser la constante directement (password_hash accepte string ou int)
        // En PHP 8.5+, PASSWORD_BCRYPT peut être une string "2y", mais password_hash() l'accepte
        $algorithm = $this->algorithm === 2 && defined('PASSWORD_BCRYPT') 
            ? PASSWORD_BCRYPT 
            : ($this->algorithm === 3 && defined('PASSWORD_ARGON2ID') 
                ? PASSWORD_ARGON2ID 
                : $this->algorithm);
        
        $hash = password_hash($password, $algorithm, $this->options);
        
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
        // Utiliser la constante directement (password_needs_rehash accepte string ou int)
        // En PHP 8.5+, PASSWORD_BCRYPT peut être une string "2y", mais password_needs_rehash() l'accepte
        $algorithm = $this->algorithm === 2 && defined('PASSWORD_BCRYPT') 
            ? PASSWORD_BCRYPT 
            : ($this->algorithm === 3 && defined('PASSWORD_ARGON2ID') 
                ? PASSWORD_ARGON2ID 
                : $this->algorithm);
        
        return password_needs_rehash($hash, $algorithm, $this->options);
    }
}

