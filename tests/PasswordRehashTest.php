<?php

declare(strict_types=1);

namespace Tests;

use PHPUnit\Framework\TestCase;
use JulienLinard\Auth\Guards\SessionGuard;
use JulienLinard\Auth\Providers\UserProviderInterface;
use JulienLinard\Auth\Hashers\HasherInterface;
use JulienLinard\Auth\Hashers\PasswordHasher;
use JulienLinard\Auth\Models\UserInterface;
use JulienLinard\Core\Session\Session;

/**
 * Tests pour le rehash automatique des mots de passe
 */
class PasswordRehashTest extends TestCase
{
    private UserProviderInterface $userProvider;
    private HasherInterface $hasher;
    private string $sessionKey = 'test_auth_user';

    protected function setUp(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
        $_SESSION = [];
        
        $this->hasher = new PasswordHasher(PASSWORD_BCRYPT);
        $this->userProvider = $this->createMock(UserProviderInterface::class);
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
    }

    public function testRehashWhenNeeded()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $password = 'password123';
        
        // Créer un hash avec un coût faible (nécessitera un rehash)
        $oldHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 4]);
        
        $user = $this->createMock(UserInterface::class);
        $user->method('getAuthIdentifier')->willReturn(1);
        $user->method('getAuthPassword')->willReturn($oldHash);
        $user->method('getAuthRoles')->willReturn('user');
        $user->method('getAuthPermissions')->willReturn([]);
        
        $this->userProvider
            ->method('findByCredentials')
            ->willReturn($user);
        
        // Vérifier que updatePassword est appelé avec un nouveau hash
        $this->userProvider
            ->expects($this->once())
            ->method('updatePassword')
            ->with($user, $this->callback(function ($newHash) use ($password) {
                // Vérifier que le nouveau hash est différent de l'ancien
                return password_verify($password, $newHash);
            }));
        
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        $result = $guard->attempt([
            'email' => 'test@example.com',
            'password' => $password
        ]);
        
        $this->assertTrue($result);
    }

    public function testNoRehashWhenNotNeeded()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $password = 'password123';
        
        // Créer un hash avec coût normal (ne nécessitera pas de rehash)
        $currentHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        
        $user = $this->createMock(UserInterface::class);
        $user->method('getAuthIdentifier')->willReturn(1);
        $user->method('getAuthPassword')->willReturn($currentHash);
        $user->method('getAuthRoles')->willReturn('user');
        $user->method('getAuthPermissions')->willReturn([]);
        
        $this->userProvider
            ->method('findByCredentials')
            ->willReturn($user);
        
        // Vérifier que updatePassword n'est PAS appelé
        $this->userProvider
            ->expects($this->never())
            ->method('updatePassword');
        
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        $result = $guard->attempt([
            'email' => 'test@example.com',
            'password' => $password
        ]);
        
        $this->assertTrue($result);
    }
}

