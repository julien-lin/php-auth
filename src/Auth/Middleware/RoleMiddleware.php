<?php

declare(strict_types=1);

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
        $this->auth = $auth ?? $this->createAuthManager();
    }

    /**
     * Crée une instance d'AuthManager depuis le container
     */
    private function createAuthManager(): AuthManager
    {
        try {
            $app = \JulienLinard\Core\Application::getInstanceOrFail();
            $container = $app->getContainer();
            return $container->make(AuthManager::class);
        } catch (\Exception $e) {
            throw new \RuntimeException(
                'AuthManager doit être fourni au constructeur ou disponible dans le container. ' . $e->getMessage()
            );
        }
    }

    /**
     * Traite la requête
     */
    public function handle(Request $request): ?Response
    {
        if (!$this->auth->check()) {
            return Response::json(['error' => 'Unauthorized', 'message' => 'Vous devez être authentifié.'], 401);
        }

        $hasRole = false;
        foreach ($this->roles as $role) {
            if ($this->auth->hasRole($role)) {
                $hasRole = true;
                break;
            }
        }

        if (!$hasRole) {
            return Response::json([
                'error' => 'Forbidden',
                'message' => 'Vous n\'avez pas les permissions nécessaires.'
            ], 403);
        }
        
        return null; // Continuer l'exécution
    }
}

