<?php

namespace JulienLinard\Auth\Middleware;

use JulienLinard\Router\Middleware;
use JulienLinard\Router\Request;
use JulienLinard\Router\Response;
use JulienLinard\Auth\AuthManager;

/**
 * Middleware pour vérifier les permissions
 */
class PermissionMiddleware implements Middleware
{
    private AuthManager $auth;
    private string|array $permissions;

    /**
     * Constructeur
     *
     * @param string|array $permissions Permission(s) requise(s)
     * @param AuthManager|null $auth Instance d'AuthManager (optionnel)
     */
    public function __construct(string|array $permissions, ?AuthManager $auth = null)
    {
        $this->permissions = is_array($permissions) ? $permissions : [$permissions];
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

        $hasPermission = false;
        foreach ($this->permissions as $permission) {
            if ($this->auth->can($permission)) {
                $hasPermission = true;
                break;
            }
        }

        if (!$hasPermission) {
            Response::json([
                'error' => 'Forbidden',
                'message' => 'Vous n\'avez pas les permissions nécessaires.'
            ], 403)->send();
            exit;
        }
    }
}

