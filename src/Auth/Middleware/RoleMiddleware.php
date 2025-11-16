<?php

namespace JulienLinard\Auth\Middleware;

use JulienLinard\Router\Middleware;
use JulienLinard\Router\Request;
use JulienLinard\Router\Response;
use JulienLinard\Auth\AuthManager;

/**
 * Middleware pour vérifier les rôles
 */
class RoleMiddleware implements Middleware
{
    private AuthManager $auth;
    private string|array $roles;

    /**
     * Constructeur
     *
     * @param string|array $roles Rôle(s) requis
     * @param AuthManager|null $auth Instance d'AuthManager (optionnel)
     */
    public function __construct(string|array $roles, ?AuthManager $auth = null)
    {
        $this->roles = is_array($roles) ? $roles : [$roles];
        // TODO: Récupérer depuis le container si disponible
        $this->auth = $auth ?? $this->createAuthManager();
    }

    /**
     * Crée une instance d'AuthManager (méthode temporaire)
     */
    private function createAuthManager(): AuthManager
    {
        throw new \RuntimeException(
            'AuthManager doit être fourni au constructeur ou disponible dans le container.'
        );
    }

    /**
     * Traite la requête
     */
    public function handle(Request $request): void
    {
        if (!$this->auth->check()) {
            Response::json(['error' => 'Unauthorized', 'message' => 'Vous devez être authentifié.'], 401)->send();
            exit;
        }

        $hasRole = false;
        foreach ($this->roles as $role) {
            if ($this->auth->hasRole($role)) {
                $hasRole = true;
                break;
            }
        }

        if (!$hasRole) {
            Response::json([
                'error' => 'Forbidden',
                'message' => 'Vous n\'avez pas les permissions nécessaires.'
            ], 403)->send();
            exit;
        }
    }
}

