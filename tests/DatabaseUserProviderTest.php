<?php

declare(strict_types=1);

namespace Tests;

use PHPUnit\Framework\TestCase;
use JulienLinard\Auth\Providers\DatabaseUserProvider;
use JulienLinard\Auth\Models\UserInterface;
use JulienLinard\Doctrine\EntityManager;
use JulienLinard\Doctrine\Repository\EntityRepository;
use Tests\TestUser;

class DatabaseUserProviderTest extends TestCase
{
    private function createMockEntityManager(): EntityManager
    {
        return $this->createMock(EntityManager::class);
    }

    private function createMockRepository(): EntityRepository
    {
        return $this->createMock(EntityRepository::class);
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

    public function testFindByIdWithExistingUser()
    {
        $em = $this->createMockEntityManager();
        $user = $this->createMockUser();
        
        $em->method('find')
            ->with(TestUser::class, 1)
            ->willReturn($user);
        
        $provider = new DatabaseUserProvider($em, TestUser::class);
        
        $result = $provider->findById(1);
        
        $this->assertInstanceOf(UserInterface::class, $result);
        $this->assertEquals($user, $result);
    }

    public function testFindByIdWithNonExistingUser()
    {
        $em = $this->createMockEntityManager();
        
        $em->method('find')
            ->with(TestUser::class, 999)
            ->willReturn(null);
        
        $provider = new DatabaseUserProvider($em, TestUser::class);
        
        $result = $provider->findById(999);
        
        $this->assertNull($result);
    }

    public function testFindByCredentialsWithValidCredentials()
    {
        $em = $this->createMockEntityManager();
        $repository = $this->createMockRepository();
        $user = $this->createMockUser();
        
        $em->method('getRepository')
            ->with(TestUser::class)
            ->willReturn($repository);
        
        $repository->method('findOneBy')
            ->with(['email' => 'test@example.com'])
            ->willReturn($user);
        
        $provider = new DatabaseUserProvider($em, TestUser::class, 'id', 'email');
        
        $result = $provider->findByCredentials(['email' => 'test@example.com', 'password' => 'password123']);
        
        $this->assertInstanceOf(UserInterface::class, $result);
        $this->assertEquals($user, $result);
    }

    public function testFindByCredentialsWithInvalidCredentials()
    {
        $em = $this->createMockEntityManager();
        $repository = $this->createMockRepository();
        
        $em->method('getRepository')
            ->with(TestUser::class)
            ->willReturn($repository);
        
        $repository->method('findOneBy')
            ->with(['email' => 'nonexistent@example.com'])
            ->willReturn(null);
        
        $provider = new DatabaseUserProvider($em, TestUser::class, 'id', 'email');
        
        $result = $provider->findByCredentials(['email' => 'nonexistent@example.com', 'password' => 'password123']);
        
        $this->assertNull($result);
    }

    public function testFindByCredentialsWithoutCredentialField()
    {
        $em = $this->createMockEntityManager();
        
        $provider = new DatabaseUserProvider($em, MockUser::class, 'id', 'email');
        
        $result = $provider->findByCredentials(['password' => 'password123']);
        
        $this->assertNull($result);
    }

    public function testFindByFieldWithValidField()
    {
        $em = $this->createMockEntityManager();
        $repository = $this->createMockRepository();
        $user = $this->createMockUser();
        
        $em->method('getRepository')
            ->with(TestUser::class)
            ->willReturn($repository);
        
        $repository->method('findOneBy')
            ->with(['username' => 'testuser'])
            ->willReturn($user);
        
        $provider = new DatabaseUserProvider($em, TestUser::class);
        
        $result = $provider->findByField('username', 'testuser');
        
        $this->assertInstanceOf(UserInterface::class, $result);
        $this->assertEquals($user, $result);
    }

    public function testFindByFieldWithNonExistingValue()
    {
        $em = $this->createMockEntityManager();
        $repository = $this->createMockRepository();
        
        $em->method('getRepository')
            ->with(TestUser::class)
            ->willReturn($repository);
        
        $repository->method('findOneBy')
            ->with(['username' => 'nonexistent'])
            ->willReturn(null);
        
        $provider = new DatabaseUserProvider($em, TestUser::class);
        
        $result = $provider->findByField('username', 'nonexistent');
        
        $this->assertNull($result);
    }

    public function testCustomIdentifierAndCredentialFields()
    {
        $em = $this->createMockEntityManager();
        $repository = $this->createMockRepository();
        $user = $this->createMockUser();
        
        $em->method('getRepository')
            ->with(TestUser::class)
            ->willReturn($repository);
        
        $repository->method('findOneBy')
            ->with(['username' => 'testuser'])
            ->willReturn($user);
        
        $provider = new DatabaseUserProvider($em, TestUser::class, 'user_id', 'username');
        
        $result = $provider->findByCredentials(['username' => 'testuser', 'password' => 'password123']);
        
        $this->assertInstanceOf(UserInterface::class, $result);
    }
}

// Mock User class for testing (déjà défini dans AuthManagerTest.php)
