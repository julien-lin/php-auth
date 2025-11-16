<?php

namespace JulienLinard\Auth\Models;

/**
 * Trait pour les modèles authentifiables
 */
trait Authenticatable
{
    /**
     * Retourne l'identifiant unique de l'utilisateur
     */
    public function getAuthIdentifier(): int|string
    {
        return $this->id ?? 0;
    }

    /**
     * Retourne le mot de passe hashé de l'utilisateur
     */
    public function getAuthPassword(): string
    {
        return $this->password ?? '';
    }

    /**
     * Retourne les rôles de l'utilisateur
     */
    public function getAuthRoles(): array|string
    {
        return $this->roles ?? [];
    }

    /**
     * Retourne les permissions de l'utilisateur
     */
    public function getAuthPermissions(): array
    {
        return $this->permissions ?? [];
    }

    /**
     * Vérifie si l'utilisateur a un rôle spécifique
     */
    public function hasRole(string $role): bool
    {
        $roles = $this->getAuthRoles();
        
        if (is_string($roles)) {
            return $roles === $role;
        }
        
        return in_array($role, $roles, true);
    }

    /**
     * Vérifie si l'utilisateur a une permission spécifique
     */
    public function hasPermission(string $permission): bool
    {
        $permissions = $this->getAuthPermissions();
        return in_array($permission, $permissions, true);
    }
}

