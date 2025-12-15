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

    /**
     * Met à jour le mot de passe hashé d'un utilisateur
     * 
     * Utilise la réflexion pour trouver et mettre à jour le champ password
     * de l'entité utilisateur, puis persiste les changements via EntityManager.
     *
     * @param UserInterface $user Utilisateur
     * @param string $hashedPassword Nouveau mot de passe hashé
     * @return void
     * @throws \RuntimeException Si le champ password n'est pas trouvé ou n'est pas modifiable
     */
    public function updatePassword(UserInterface $user, string $hashedPassword): void
    {
        // Vérifier que l'utilisateur est une instance de la classe attendue
        if (!($user instanceof $this->userClass)) {
            throw new \RuntimeException(
                "L'utilisateur doit être une instance de {$this->userClass}"
            );
        }

        // Utiliser la réflexion pour trouver le champ password
        $reflection = new \ReflectionClass($user);
        
        // Chercher un champ nommé 'password' ou 'hashedPassword'
        $passwordFields = ['password', 'hashedPassword', 'passwordHash'];
        $passwordProperty = null;
        
        foreach ($passwordFields as $fieldName) {
            if ($reflection->hasProperty($fieldName)) {
                $passwordProperty = $reflection->getProperty($fieldName);
                break;
            }
        }
        
        if ($passwordProperty === null) {
            throw new \RuntimeException(
                "Impossible de trouver le champ password dans {$this->userClass}. " .
                "Champs recherchés: " . implode(', ', $passwordFields)
            );
        }
        
        // Rendre la propriété accessible et mettre à jour la valeur
        $passwordProperty->setAccessible(true);
        $passwordProperty->setValue($user, $hashedPassword);
        
        // Persister les changements via EntityManager
        $this->em->persist($user);
        $this->em->flush();
    }
}

