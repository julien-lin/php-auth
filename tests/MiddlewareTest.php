<?php

declare(strict_types=1);

namespace Tests;

use PHPUnit\Framework\TestCase;
use JulienLinard\Auth\Middleware\AuthMiddleware;
use JulienLinard\Auth\Middleware\GuestMiddleware;
use JulienLinard\Auth\Middleware\RoleMiddleware;
use JulienLinard\Auth\Middleware\PermissionMiddleware;
use JulienLinard\Auth\AuthManager;
use JulienLinard\Router\Request;
use JulienLinard\Router\Response;
use JulienLinard\Doctrine\EntityManager;

class MiddlewareTest extends TestCase
{
    private function createMockAuthManager(bool $authenticated = false, bool $hasRole = false, bool $hasPermission = false): AuthManager
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('check')->willReturn($authenticated);
        $auth->method('hasRole')->willReturn($hasRole);
        $auth->method('can')->willReturn($hasPermission);
        return $auth;
    }

    public function testAuthMiddlewareWithAuthenticatedUser()
    {
        $auth = $this->createMockAuthManager(true);
        $middleware = new AuthMiddleware($auth);
        $request = new Request('/test', 'GET');
        
        $response = $middleware->handle($request);
        
        $this->assertNull($response); // Continue l'exécution
    }

    public function testAuthMiddlewareWithUnauthenticatedUserGet()
    {
        $auth = $this->createMockAuthManager(false);
        $middleware = new AuthMiddleware($auth);
        $request = new Request('/test', 'GET');
        
        $response = $middleware->handle($request);
        
        $this->assertInstanceOf(Response::class, $response);
        $this->assertEquals(302, $response->getStatusCode());
        $headers = $response->getHeaders();
        $this->assertArrayHasKey('location', $headers);
        $this->assertEquals('/login', $headers['location']);
    }

    public function testAuthMiddlewareWithUnauthenticatedUserPost()
    {
        $auth = $this->createMockAuthManager(false);
        $middleware = new AuthMiddleware($auth);
        $request = new Request('/api/test', 'POST');
        
        $response = $middleware->handle($request);
        
        $this->assertInstanceOf(Response::class, $response);
        $this->assertEquals(401, $response->getStatusCode());
        $content = json_decode($response->getContent(), true);
        $this->assertArrayHasKey('error', $content);
        $this->assertEquals('Unauthorized', $content['error']);
    }

    public function testGuestMiddlewareWithAuthenticatedUser()
    {
        $auth = $this->createMockAuthManager(true);
        $middleware = new GuestMiddleware($auth);
        $request = new Request('/login', 'GET');
        
        $response = $middleware->handle($request);
        
        $this->assertInstanceOf(Response::class, $response);
        $this->assertEquals(403, $response->getStatusCode());
        $content = json_decode($response->getContent(), true);
        $this->assertArrayHasKey('error', $content);
        $this->assertEquals('Forbidden', $content['error']);
    }

    public function testGuestMiddlewareWithGuest()
    {
        $auth = $this->createMockAuthManager(false);
        $middleware = new GuestMiddleware($auth);
        $request = new Request('/login', 'GET');
        
        $response = $middleware->handle($request);
        
        $this->assertNull($response); // Continue l'exécution
    }

    public function testRoleMiddlewareWithCorrectRole()
    {
        $auth = $this->createMockAuthManager(true, true);
        $middleware = new RoleMiddleware('admin', $auth);
        $request = new Request('/admin', 'GET');
        
        $response = $middleware->handle($request);
        
        $this->assertNull($response); // Continue l'exécution
    }

    public function testRoleMiddlewareWithWrongRole()
    {
        $auth = $this->createMockAuthManager(true, false);
        $middleware = new RoleMiddleware('admin', $auth);
        $request = new Request('/admin', 'GET');
        
        $response = $middleware->handle($request);
        
        $this->assertInstanceOf(Response::class, $response);
        $this->assertEquals(403, $response->getStatusCode());
        $content = json_decode($response->getContent(), true);
        $this->assertArrayHasKey('error', $content);
        $this->assertEquals('Forbidden', $content['error']);
    }

    public function testRoleMiddlewareWithUnauthenticatedUser()
    {
        $auth = $this->createMockAuthManager(false);
        $middleware = new RoleMiddleware('admin', $auth);
        $request = new Request('/admin', 'GET');
        
        $response = $middleware->handle($request);
        
        $this->assertInstanceOf(Response::class, $response);
        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testRoleMiddlewareWithMultipleRoles()
    {
        $auth = $this->createMockAuthManager(true, true);
        $middleware = new RoleMiddleware(['admin', 'moderator'], $auth);
        $request = new Request('/admin', 'GET');
        
        $response = $middleware->handle($request);
        
        $this->assertNull($response); // Continue l'exécution
    }

    public function testPermissionMiddlewareWithCorrectPermission()
    {
        $auth = $this->createMockAuthManager(true, false, true);
        $middleware = new PermissionMiddleware('edit-posts', $auth);
        $request = new Request('/posts/edit', 'GET');
        
        $response = $middleware->handle($request);
        
        $this->assertNull($response); // Continue l'exécution
    }

    public function testPermissionMiddlewareWithWrongPermission()
    {
        $auth = $this->createMockAuthManager(true, false, false);
        $middleware = new PermissionMiddleware('edit-posts', $auth);
        $request = new Request('/posts/edit', 'GET');
        
        $response = $middleware->handle($request);
        
        $this->assertInstanceOf(Response::class, $response);
        $this->assertEquals(403, $response->getStatusCode());
        $content = json_decode($response->getContent(), true);
        $this->assertArrayHasKey('error', $content);
        $this->assertEquals('Forbidden', $content['error']);
    }

    public function testPermissionMiddlewareWithUnauthenticatedUser()
    {
        $auth = $this->createMockAuthManager(false);
        $middleware = new PermissionMiddleware('edit-posts', $auth);
        $request = new Request('/posts/edit', 'GET');
        
        $response = $middleware->handle($request);
        
        $this->assertInstanceOf(Response::class, $response);
        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testPermissionMiddlewareWithMultiplePermissions()
    {
        $auth = $this->createMockAuthManager(true, false, true);
        $middleware = new PermissionMiddleware(['edit-posts', 'delete-posts'], $auth);
        $request = new Request('/posts', 'GET');
        
        $response = $middleware->handle($request);
        
        $this->assertNull($response); // Continue l'exécution
    }
}
