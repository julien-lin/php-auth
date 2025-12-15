<?php

declare(strict_types=1);

namespace JulienLinard\Auth\RememberToken;

use JulienLinard\Doctrine\EntityManager;
use JulienLinard\Auth\Models\UserInterface;
use JulienLinard\Auth\Providers\UserProviderInterface;

/**
 * Gestionnaire de tokens "Remember Me" utilisant Doctrine EntityManager
 * 
 * NOTE: Cette implémentation nécessite une table `remember_tokens` dans votre base de données.
 * La structure de table est documentée dans migrations/remember_tokens.sql
 */
class DatabaseRememberTokenManager implements RememberTokenManagerInterface
{
    private EntityManager $em;
    private UserProviderInterface $userProvider;
    private string $tokenClass;
    private string $tokenTableName;

    /**
     * Constructeur
     *
     * @param EntityManager $em Entity Manager
     * @param UserProviderInterface $userProvider Provider d'utilisateurs
     * @param string $tokenClass Classe de l'entité token (ex: 'App\Entity\RememberToken')
     * @param string $tokenTableName Nom de la table (par défaut: 'remember_tokens')
     */
    public function __construct(
        EntityManager $em,
        UserProviderInterface $userProvider,
        string $tokenClass,
        string $tokenTableName = 'remember_tokens'
    ) {
        $this->em = $em;
        $this->userProvider = $userProvider;
        $this->tokenClass = $tokenClass;
        $this->tokenTableName = $tokenTableName;
    }

    /**
     * Crée un nouveau token "Remember Me" pour un utilisateur
     */
    public function createToken(UserInterface $user, int $lifetime = 2592000): RememberToken
    {
        // Générer un token sécurisé (64 caractères hex)
        $token = bin2hex(random_bytes(32));
        
        // Calculer la date d'expiration
        $expiresAt = new \DateTime();
        $expiresAt->modify("+{$lifetime} seconds");
        
        // Créer l'entité token
        $rememberToken = new RememberToken(
            $user->getAuthIdentifier(),
            $token,
            $expiresAt
        );
        
        // Persister via EntityManager
        // NOTE: L'entité doit être mappée correctement dans votre application
        $this->persistToken($rememberToken);
        
        return $rememberToken;
    }

    /**
     * Récupère un utilisateur par son token "Remember Me"
     */
    public function getUserByToken(string $token): ?UserInterface
    {
        // Rechercher le token dans la base
        $tokenEntity = $this->findTokenByValue($token);
        
        if ($tokenEntity === null) {
            return null;
        }
        
        // Vérifier si le token est expiré
        if ($tokenEntity->isExpired()) {
            $this->deleteToken($token);
            return null;
        }
        
        // Récupérer l'utilisateur
        return $this->userProvider->findById($tokenEntity->getUserId());
    }

    /**
     * Supprime un token "Remember Me"
     */
    public function deleteToken(string $token): void
    {
        $tokenEntity = $this->findTokenByValue($token);
        
        if ($tokenEntity !== null) {
            $this->deleteTokenEntity($tokenEntity);
        }
    }

    /**
     * Supprime tous les tokens d'un utilisateur
     */
    public function deleteAllTokensForUser(UserInterface $user): void
    {
        $tokens = $this->findTokensByUserId($user->getAuthIdentifier());
        
        foreach ($tokens as $token) {
            $this->deleteTokenEntity($token);
        }
    }

    /**
     * Nettoie les tokens expirés
     */
    public function cleanExpiredTokens(): int
    {
        $connection = $this->em->getConnection();
        $sql = "DELETE FROM `{$this->tokenTableName}` WHERE expires_at < NOW()";
        
        $stmt = $connection->execute($sql);
        
        return $stmt->rowCount();
    }

    /**
     * Trouve un token par sa valeur
     * 
     * Utilise une requête SQL directe car nous n'avons pas d'entité Doctrine mappée
     */
    private function findTokenByValue(string $token): ?RememberToken
    {
        $connection = $this->em->getConnection();
        $sql = "SELECT id, user_id, token, expires_at, created_at 
                FROM `{$this->tokenTableName}` 
                WHERE token = :token 
                LIMIT 1";
        
        $result = $connection->fetchOne($sql, ['token' => $token]);
        
        if ($result === null) {
            return null;
        }
        
        return $this->hydrateToken($result);
    }

    /**
     * Trouve tous les tokens d'un utilisateur
     */
    private function findTokensByUserId(int|string $userId): array
    {
        $connection = $this->em->getConnection();
        $sql = "SELECT id, user_id, token, expires_at, created_at 
                FROM `{$this->tokenTableName}` 
                WHERE user_id = :user_id";
        
        $results = $connection->fetchAll($sql, ['user_id' => $userId]);
        
        $tokens = [];
        foreach ($results as $row) {
            $tokens[] = $this->hydrateToken($row);
        }
        
        return $tokens;
    }

    /**
     * Hydrate un RememberToken depuis un tableau de données
     */
    private function hydrateToken(array $data): RememberToken
    {
        $token = new RememberToken(
            $data['user_id'],
            $data['token'],
            new \DateTime($data['expires_at']),
            new \DateTime($data['created_at'])
        );
        
        if (isset($data['id'])) {
            $token->setId((int)$data['id']);
        }
        
        return $token;
    }

    /**
     * Persiste un token dans la base de données
     */
    private function persistToken(RememberToken $token): void
    {
        $connection = $this->em->getConnection();
        $sql = "INSERT INTO `{$this->tokenTableName}` (user_id, token, expires_at, created_at) 
                VALUES (:user_id, :token, :expires_at, :created_at)";
        
        $connection->execute($sql, [
            'user_id' => $token->getUserId(),
            'token' => $token->getToken(),
            'expires_at' => $token->getExpiresAt()->format('Y-m-d H:i:s'),
            'created_at' => $token->getCreatedAt()->format('Y-m-d H:i:s'),
        ]);
        
        // Récupérer l'ID généré
        $lastId = $connection->lastInsertId();
        if ($lastId) {
            $token->setId((int)$lastId);
        }
    }

    /**
     * Supprime une entité token de la base de données
     */
    private function deleteTokenEntity(RememberToken $token): void
    {
        if ($token->getId() === null) {
            return;
        }
        
        $connection = $this->em->getConnection();
        $sql = "DELETE FROM `{$this->tokenTableName}` WHERE id = :id";
        
        $connection->execute($sql, ['id' => $token->getId()]);
    }
}

