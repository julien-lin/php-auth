<?php

declare(strict_types=1);

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

        $hasPermission = false;
        foreach ($this->permissions as $permission) {
            if ($this->auth->can($permission)) {
                $hasPermission = true;
                break;
            }
        }

        if (!$hasPermission) {
            return Response::json([
                'error' => 'Forbidden',
                'message' => 'Vous n\'avez pas les permissions nécessaires.'
            ], 403);
        }
        
        return null; // Continuer l'exécution
    }
}

