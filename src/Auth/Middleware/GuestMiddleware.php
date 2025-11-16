<?php

namespace JulienLinard\Auth\Middleware;

use JulienLinard\Router\Middleware;
use JulienLinard\Router\Request;
use JulienLinard\Router\Response;
use JulienLinard\Auth\AuthManager;

/**
 * Middleware pour vérifier que l'utilisateur n'est PAS authentifié (guest)
 */
class GuestMiddleware implements Middleware
{
    private AuthManager $auth;

    /**
     * Constructeur
     *
     * @param AuthManager|null $auth Instance d'AuthManager (optionnel)
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
        throw new \RuntimeException(
            'AuthManager doit être fourni au constructeur ou disponible dans le container.'
        );
    }

    /**
     * Traite la requête
     */
    public function handle(Request $request): void
    {
        if ($this->auth->check()) {
            Response::json([
                'error' => 'Forbidden',
                'message' => 'Cette route est réservée aux utilisateurs non authentifiés.'
            ], 403)->send();
            exit;
        }
    }
}

