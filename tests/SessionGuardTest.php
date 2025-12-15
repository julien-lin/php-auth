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

class SessionGuardTest extends TestCase
{
    private UserProviderInterface $userProvider;
    private HasherInterface $hasher;
    private string $sessionKey = 'test_auth_user';

    protected function setUp(): void
    {
        // Nettoyer la session avant chaque test
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
        $_SESSION = [];
        
        $this->hasher = new PasswordHasher(PASSWORD_BCRYPT);
        
        // Créer un mock UserProvider
        $this->userProvider = $this->createMock(UserProviderInterface::class);
    }

    protected function tearDown(): void
    {
        // Nettoyer la session après chaque test
        $_SESSION = [];
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
    }

    private function createMockUser(int $id = 1, string $password = 'password123'): UserInterface
    {
        $user = $this->createMock(UserInterface::class);
        $user->method('getAuthIdentifier')->willReturn($id);
        $user->method('getAuthPassword')->willReturn($this->hasher->hash($password));
        $user->method('getAuthRoles')->willReturn('user');
        $user->method('getAuthPermissions')->willReturn([]);
        return $user;
    }

    public function testCheckWhenNotAuthenticated()
    {
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        $this->assertFalse($guard->check());
    }

    public function testGuestWhenNotAuthenticated()
    {
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        $this->assertTrue($guard->guest());
    }

    public function testUserWhenNotAuthenticated()
    {
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        $this->assertNull($guard->user());
    }

    public function testIdWhenNotAuthenticated()
    {
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        $this->assertNull($guard->id());
    }

    public function testAttemptWithValidCredentials()
    {
        // Démarrer une session pour le test
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $user = $this->createMockUser();
        
        $this->userProvider
            ->method('findByCredentials')
            ->willReturn($user);
        
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        $result = $guard->attempt([
            'email' => 'test@example.com',
            'password' => 'password123'
        ]);
        
        $this->assertTrue($result);
        $this->assertTrue($guard->check());
    }

    public function testAttemptWithInvalidCredentials()
    {
        // Démarrer une session pour le test
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $this->userProvider
            ->method('findByCredentials')
            ->willReturn(null);
        
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        $result = $guard->attempt([
            'email' => 'test@example.com',
            'password' => 'wrong-password'
        ]);
        
        $this->assertFalse($result);
        $this->assertFalse($guard->check());
    }

    public function testAttemptWithWrongPassword()
    {
        // Démarrer une session pour le test
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $user = $this->createMockUser();
        
        $this->userProvider
            ->method('findByCredentials')
            ->willReturn($user);
        
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        $result = $guard->attempt([
            'email' => 'test@example.com',
            'password' => 'wrong-password'
        ]);
        
        $this->assertFalse($result);
        $this->assertFalse($guard->check());
    }

    public function testAttemptWithoutPassword()
    {
        // Démarrer une session pour le test
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $user = $this->createMockUser();
        
        $this->userProvider
            ->method('findByCredentials')
            ->willReturn($user);
        
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        $result = $guard->attempt([
            'email' => 'test@example.com'
        ]);
        
        $this->assertFalse($result);
    }

    public function testLogin()
    {
        $user = $this->createMockUser();
        
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        $guard->login($user);
        
        $this->assertTrue($guard->check());
        $this->assertEquals($user, $guard->user());
        $this->assertEquals(1, $guard->id());
    }

    public function testLogout()
    {
        // Démarrer une session pour le test
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $user = $this->createMockUser();
        
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        $guard->login($user);
        $this->assertTrue($guard->check());
        
        $guard->logout();
        
        $this->assertFalse($guard->check());
        $this->assertTrue($guard->guest());
        $this->assertNull($guard->user());
        $this->assertNull($guard->id());
    }

    public function testUserRetrievalFromSession()
    {
        // Démarrer une session pour le test
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $user = $this->createMockUser();
        
        $this->userProvider
            ->method('findById')
            ->with(1)
            ->willReturn($user);
        
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        // Login pour créer la session
        $guard->login($user);
        
        // Vérifier que l'utilisateur est bien stocké
        $this->assertTrue($guard->check());
        $this->assertNotNull($guard->user());
        $this->assertEquals(1, $guard->id());
        
        // Créer un nouveau guard pour simuler une nouvelle requête
        $guard2 = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        $this->assertTrue($guard2->check());
        $this->assertNotNull($guard2->user());
        $this->assertEquals(1, $guard2->id());
    }

    public function testUserRetrievalWhenUserNotFound()
    {
        // Démarrer une session pour le test
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $user = $this->createMockUser();
        
        $guard = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        // Login pour créer la session
        $guard->login($user);
        
        // Nettoyer le cache pour forcer le rechargement depuis le provider
        SessionGuard::clearUserCache();
        
        // Créer un nouveau guard avec provider qui ne trouve pas l'utilisateur
        $this->userProvider
            ->method('findById')
            ->with(1)
            ->willReturn(null);
        
        $guard2 = new SessionGuard($this->userProvider, $this->hasher, $this->sessionKey);
        
        // L'utilisateur ne devrait pas être trouvé
        $this->assertNull($guard2->user());
        $this->assertFalse($guard2->check());
    }
}
