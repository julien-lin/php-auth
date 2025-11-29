<?php

declare(strict_types=1);

namespace JulienLinard\Auth\Providers;

use JulienLinard\Doctrine\EntityManager;
use JulienLinard\Auth\Models\UserInterface;

/**
 * Provider d'utilisateurs utilisant Doctrine EntityManager
 */
class DatabaseUserProvider implements UserProviderInterface
{
    private EntityManager $em;
    private string $userClass;
    private string $identifierField;
    private string $credentialField;

    /**
     * Constructeur
     *
     * @param EntityManager $em Entity Manager
     * @param string $userClass Classe de l'utilisateur
     * @param string $identifierField Champ pour l'identifiant (par défaut: 'id')
     * @param string $credentialField Champ pour les credentials (par défaut: 'email')
     */
    public function __construct(
        EntityManager $em,
        string $userClass,
        string $identifierField = 'id',
        string $credentialField = 'email'
    ) {
        $this->em = $em;
        $this->userClass = $userClass;
        $this->identifierField = $identifierField;
        $this->credentialField = $credentialField;
    }

    /**
     * Retourne un utilisateur par son identifiant
     */
    public function findById(int|string $identifier): ?UserInterface
    {
        $user = $this->em->find($this->userClass, $identifier);
        
        if ($user instanceof UserInterface) {
            return $user;
        }
        
        return null;
    }

    /**
     * Retourne un utilisateur par ses credentials
     */
    public function findByCredentials(array $credentials): ?UserInterface
    {
        if (!isset($credentials[$this->credentialField])) {
            return null;
        }

        $value = $credentials[$this->credentialField];
        return $this->findByField($this->credentialField, $value);
    }

    /**
     * Retourne un utilisateur par un champ spécifique
     * 
     * @param string $field Nom du champ
     * @param mixed $value Valeur
     * @return UserInterface|null Utilisateur ou null
     */
    public function findByField(string $field, mixed $value): ?UserInterface
    {
        $repository = $this->em->getRepository($this->userClass);
        $user = $repository->findOneBy([$field => $value]);
        
        if ($user instanceof UserInterface) {
            return $user;
        }
        
        return null;
    }
}

