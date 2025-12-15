<?php

declare(strict_types=1);

namespace JulienLinard\Auth\RememberToken;

/**
 * Modèle pour les tokens "Remember Me"
 * 
 * Cette classe représente un token de session persistante.
 * 
 * NOTE: Cette classe est un modèle simple. Pour l'utiliser avec Doctrine,
 * vous devez créer une entité correspondante dans votre application.
 * 
 * Structure de table recommandée:
 * ```sql
 * CREATE TABLE remember_tokens (
 *     id INT AUTO_INCREMENT PRIMARY KEY,
 *     user_id INT NOT NULL,
 *     token VARCHAR(255) NOT NULL UNIQUE,
 *     expires_at DATETIME NOT NULL,
 *     created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 *     INDEX idx_user_id (user_id),
 *     INDEX idx_token (token),
 *     INDEX idx_expires_at (expires_at)
 * );
 * ```
 */
class RememberToken
{
    private ?int $id = null;
    private int|string $userId;
    private string $token;
    private \DateTime $expiresAt;
    private \DateTime $createdAt;

    public function __construct(
        int|string $userId,
        string $token,
        \DateTime $expiresAt,
        ?\DateTime $createdAt = null
    ) {
        $this->userId = $userId;
        $this->token = $token;
        $this->expiresAt = $expiresAt;
        $this->createdAt = $createdAt ?? new \DateTime();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function setId(?int $id): void
    {
        $this->id = $id;
    }

    public function getUserId(): int|string
    {
        return $this->userId;
    }

    public function setUserId(int|string $userId): void
    {
        $this->userId = $userId;
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function setToken(string $token): void
    {
        $this->token = $token;
    }

    public function getExpiresAt(): \DateTime
    {
        return $this->expiresAt;
    }

    public function setExpiresAt(\DateTime $expiresAt): void
    {
        $this->expiresAt = $expiresAt;
    }

    public function getCreatedAt(): \DateTime
    {
        return $this->createdAt;
    }

    public function setCreatedAt(\DateTime $createdAt): void
    {
        $this->createdAt = $createdAt;
    }

    /**
     * Vérifie si le token est expiré
     */
    public function isExpired(): bool
    {
        return $this->expiresAt < new \DateTime();
    }
}

