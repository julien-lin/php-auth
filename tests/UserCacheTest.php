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
 * Tests pour le cache mémoire des utilisateurs
 */
class UserCacheTest extends TestCase
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
        
        // Nettoyer le cache avant chaque test
        SessionGuard::clearUserCache();
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
        
        // Nettoyer le cache après chaque test
        SessionGuard::clearUserCache();
    }

    private function createMockUser(int $id = 1): UserInterface
    {
        $user = $this->createMock(UserInterface::class);
        $user->method('getAuthIdentifier')->willReturn($id);
        $user->method('getAuthPassword')->willReturn('hashed-password');
        $user->method('getAuthRoles')->willReturn('user');
        $user->method('getAuthPermissions')->willReturn([]);
        return $user;
    }

    public function testUserIsCached()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $user = $this->createMockUser();
        
        // Le provider ne devrait être appelé qu'une seule fois
        $this->userProvider
            ->expects($this->once())
            ->method('findById')
            ->with(1)
            ->willReturn($user);
        
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        // Login pour créer la session
        $guard->login($user);
        
        // Créer un nouveau guard (simule une nouvelle requête)
        $guard2 = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        // Appeler user() plusieurs fois - le cache devrait être utilisé
        $user1 = $guard2->user();
        $user2 = $guard2->user();
        $user3 = $guard2->user();
        
        $this->assertSame($user1, $user2);
        $this->assertSame($user2, $user3);
    }

    public function testClearUserCache()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $user = $this->createMockUser();
        
        $this->userProvider
            ->method('findById')
            ->with(1)
            ->willReturn($user);
        
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        $guard->login($user);
        
        // Nettoyer le cache
        SessionGuard::clearUserCache();
        
        // Créer un nouveau guard - le provider devrait être appelé à nouveau
        $this->userProvider
            ->expects($this->atLeastOnce())
            ->method('findById')
            ->with(1)
            ->willReturn($user);
        
        $guard2 = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        $guard2->user();
    }

    public function testClearUserCacheForSpecificUser()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $user1 = $this->createMockUser(1);
        $user2 = $this->createMockUser(2);
        
        $this->userProvider
            ->method('findById')
            ->willReturnCallback(function ($id) use ($user1, $user2) {
                return $id === 1 ? $user1 : $user2;
            });
        
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        $guard->login($user1);
        
        // Nettoyer le cache pour user1 uniquement
        SessionGuard::clearUserCacheFor(1);
        
        // Créer un nouveau guard - le provider devrait être appelé pour user1
        $this->userProvider
            ->expects($this->once())
            ->method('findById')
            ->with(1)
            ->willReturn($user1);
        
        $guard2 = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        $guard2->user();
    }

    public function testCacheIsClearedOnLogout()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $user = $this->createMockUser();
        
        $this->userProvider
            ->method('findById')
            ->with(1)
            ->willReturn($user);
        
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        $guard->login($user);
        
        // Logout devrait nettoyer le cache
        $guard->logout();
        
        // Vérifier que le cache est vide
        $this->assertNull($guard->user());
    }
}

