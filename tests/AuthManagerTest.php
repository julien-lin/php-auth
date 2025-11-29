<?php

declare(strict_types=1);

namespace Tests;

use PHPUnit\Framework\TestCase;
use JulienLinard\Auth\AuthManager;
use JulienLinard\Auth\Models\UserInterface;
use JulienLinard\Auth\Guards\GuardInterface;
use JulienLinard\Doctrine\EntityManager;
use Tests\TestUser;

class AuthManagerTest extends TestCase
{
    private function createMockEntityManager(): EntityManager
    {
        return $this->createMock(EntityManager::class);
    }

    private function createMockUser(): UserInterface
    {
        $user = $this->createMock(UserInterface::class);
        $user->method('getAuthIdentifier')->willReturn(1);
        $user->method('getAuthPassword')->willReturn(password_hash('password123', PASSWORD_BCRYPT));
        $user->method('getAuthRoles')->willReturn('user');
        $user->method('getAuthPermissions')->willReturn([]);
        $user->method('hasRole')->willReturnCallback(function($role) {
            return $role === 'user';
        });
        $user->method('hasPermission')->willReturn(false);
        return $user;
    }

    public function testAuthManagerCreation()
    {
        $em = $this->createMockEntityManager();
        
        $config = [
            'user_class' => TestUser::class,
            'entity_manager' => $em
        ];

        $auth = new AuthManager($config);
        
        $this->assertInstanceOf(AuthManager::class, $auth);
        $this->assertInstanceOf(GuardInterface::class, $auth->guard());
    }

    public function testAuthManagerCreationWithoutUserClass()
    {
        $em = $this->createMockEntityManager();
        
        $config = [
            'entity_manager' => $em
        ];

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('user_class requis dans la configuration.');
        
        new AuthManager($config);
    }

    public function testAuthManagerCreationWithoutEntityManager()
    {
        $config = [
            'user_class' => TestUser::class
        ];

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('EntityManager requis pour DatabaseUserProvider.');
        
        new AuthManager($config);
    }

    public function testCheckWhenNotAuthenticated()
    {
        $em = $this->createMockEntityManager();
        
        $config = [
            'user_class' => TestUser::class,
            'entity_manager' => $em
        ];

        $auth = new AuthManager($config);
        
        $this->assertFalse($auth->check());
    }

    public function testGuestWhenNotAuthenticated()
    {
        $em = $this->createMockEntityManager();
        
        $config = [
            'user_class' => TestUser::class,
            'entity_manager' => $em
        ];

        $auth = new AuthManager($config);
        
        $this->assertTrue($auth->guest());
    }

    public function testUserWhenNotAuthenticated()
    {
        $em = $this->createMockEntityManager();
        
        $config = [
            'user_class' => TestUser::class,
            'entity_manager' => $em
        ];

        $auth = new AuthManager($config);
        
        $this->assertNull($auth->user());
    }

    public function testIdWhenNotAuthenticated()
    {
        $em = $this->createMockEntityManager();
        
        $config = [
            'user_class' => TestUser::class,
            'entity_manager' => $em
        ];

        $auth = new AuthManager($config);
        
        $this->assertNull($auth->id());
    }

    public function testHasRoleWhenNotAuthenticated()
    {
        $em = $this->createMockEntityManager();
        
        $config = [
            'user_class' => TestUser::class,
            'entity_manager' => $em
        ];

        $auth = new AuthManager($config);
        
        $this->assertFalse($auth->hasRole('admin'));
    }

    public function testCanWhenNotAuthenticated()
    {
        $em = $this->createMockEntityManager();
        
        $config = [
            'user_class' => TestUser::class,
            'entity_manager' => $em
        ];

        $auth = new AuthManager($config);
        
        $this->assertFalse($auth->can('edit-posts'));
    }
}

// Utiliser TestUser depuis TestHelpers.php
