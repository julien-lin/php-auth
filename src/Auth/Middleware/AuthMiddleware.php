<?php

declare(strict_types=1);

namespace JulienLinard\Auth\Middleware;

use JulienLinard\Router\Middleware;
use JulienLinard\Router\Request;
use JulienLinard\Router\Response;
use JulienLinard\Auth\AuthManager;
use JulienLinard\Core\Application;

/**
 * Middleware pour vérifier l'authentification
 */
class AuthMiddleware implements Middleware
{
    private AuthManager $auth;

    /**
     * Constructeur
     *
     * @param AuthManager|null $auth Instance d'AuthManager (optionnel, sera récupérée depuis le container si null)
     */
    public function __construct(?AuthManager $auth = null)
    {
        $this->auth = $auth ?? $this->getAuthManagerFromContainer();
    }

    /**
     * Récupère AuthManager depuis le container
     */
    private function getAuthManagerFromContainer(): AuthManager
    {
        try {
            $app = Application::getInstanceOrFail();
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
            // Pour les requêtes GET (pages web) → rediriger vers la page de connexion
            if ($request->getMethod() === 'GET') {
                $response = new Response(302);
                $response->setHeader('Location', '/login');
                return $response;
            }
            
            // Pour les requêtes POST/AJAX → retourner une erreur JSON
            return Response::json([
                'error' => 'Unauthorized',
                'message' => 'Vous devez être authentifié.'
            ], 401);
        }
        
        return null; // Continuer l'exécution
    }
}

