<?php

declare(strict_types=1);

namespace Tests;

use PHPUnit\Framework\TestCase;
use JulienLinard\Auth\Models\Authenticatable;
use JulienLinard\Auth\Models\UserInterface;

class RolesAndPermissionsTest extends TestCase
{
    public function testHasRoleWithStringRole()
    {
        $user = new TestUser();
        $user->role = 'admin';
        
        $this->assertTrue($user->hasRole('admin'));
        $this->assertFalse($user->hasRole('user'));
    }

    public function testHasRoleWithArrayRoles()
    {
        $user = new TestUser();
        $user->roles = ['admin', 'moderator'];
        
        $this->assertTrue($user->hasRole('admin'));
        $this->assertTrue($user->hasRole('moderator'));
        $this->assertFalse($user->hasRole('user'));
    }

    public function testHasPermission()
    {
        $user = new TestUser();
        $user->permissions = ['edit-posts', 'delete-posts'];
        
        $this->assertTrue($user->hasPermission('edit-posts'));
        $this->assertTrue($user->hasPermission('delete-posts'));
        $this->assertFalse($user->hasPermission('manage-users'));
    }

    public function testGetAuthRolesReturnsString()
    {
        $user = new TestUser();
        $user->role = 'admin';
        
        $roles = $user->getAuthRoles();
        $this->assertEquals('admin', $roles);
    }

    public function testGetAuthRolesReturnsArray()
    {
        $user = new TestUser();
        $user->roles = ['admin', 'moderator'];
        
        $roles = $user->getAuthRoles();
        $this->assertIsArray($roles);
        $this->assertEquals(['admin', 'moderator'], $roles);
    }

    public function testGetAuthPermissionsReturnsArray()
    {
        $user = new TestUser();
        $user->permissions = ['edit-posts', 'delete-posts'];
        
        $permissions = $user->getAuthPermissions();
        $this->assertIsArray($permissions);
        $this->assertEquals(['edit-posts', 'delete-posts'], $permissions);
    }

    public function testGetAuthIdentifier()
    {
        $user = new TestUser();
        $user->id = 123;
        
        $this->assertEquals(123, $user->getAuthIdentifier());
    }

    public function testGetAuthPassword()
    {
        $user = new TestUser();
        $user->password = 'hashed-password';
        
        $this->assertEquals('hashed-password', $user->getAuthPassword());
    }

    public function testGetAuthRolesWithNull()
    {
        $user = new TestUser();
        $user->role = null;
        $user->roles = null;
        
        $roles = $user->getAuthRoles();
        $this->assertEquals([], $roles);
    }

    public function testGetAuthPermissionsWithNull()
    {
        $user = new TestUser();
        $user->permissions = null;
        
        $permissions = $user->getAuthPermissions();
        $this->assertEquals([], $permissions);
    }
}

// Test User class using Authenticatable trait
class TestUser implements UserInterface
{
    use Authenticatable;

    public ?int $id = null;
    public ?string $password = null;
    public ?string $role = null;
    public ?array $roles = null;
    public ?array $permissions = null;
}
