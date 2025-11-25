<?php

namespace JulienLinard\Auth\Middleware;

use JulienLinard\Router\Middleware;
use JulienLinard\Router\Request;
use JulienLinard\Router\Response;
use JulienLinard\Auth\AuthManager;

/**
 * Middleware pour vérifier l'authentification
 */
class AuthMiddleware implements Middleware
{
    private AuthManager $auth;

    /**
     * Constructeur
     *
     * @param AuthManager|null $auth Instance d'AuthManager (optionnel, sera créée si null)
     */
    public function __construct(?AuthManager $auth = null)
    {
        // TODO: Récupérer depuis le container si disponible
        $this->auth = $auth ?? $this->createAuthManager();
    }

    /**
     * Crée une instance d'AuthManager (méthode temporaire)
     */
    private function createAuthManager(): AuthManager
    {
        // Cette méthode devrait récupérer la config depuis le container
        // Pour l'instant, on lève une exception
        throw new \RuntimeException(
            'AuthManager doit être fourni au constructeur ou disponible dans le container.'
        );
    }

    /**
     * Traite la requête
     */
    public function handle(Request $request): ?Response
    {
        if (!$this->auth->check()) {
            return Response::json(['error' => 'Unauthorized', 'message' => 'Vous devez être authentifié.'], 401);
        }
        
        return null; // Continuer l'exécution
    }
}

