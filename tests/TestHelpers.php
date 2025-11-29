<?php

declare(strict_types=1);

namespace Tests;

use JulienLinard\Auth\Models\UserInterface;

/**
 * Classes helper pour les tests
 */
class TestUser implements UserInterface
{
    public ?int $id = 1;
    public string $email = 'test@example.com';
    public string $password;
    public string $role = 'user';
    public array $permissions = [];

    public function __construct()
    {
        $this->password = password_hash('password123', PASSWORD_BCRYPT);
    }

    public function getAuthIdentifier(): int|string
    {
        return $this->id ?? 0;
    }

    public function getAuthPassword(): string
    {
        return $this->password ?? '';
    }

    public function getAuthRoles(): array|string
    {
        return $this->role ?? [];
    }

    public function getAuthPermissions(): array
    {
        return $this->permissions ?? [];
    }
}
