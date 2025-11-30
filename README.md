# Auth PHP - Complete Authentication System

[🇫🇷 Read in French](README.fr.md) | [🇬🇧 Read in English](README.md)

## 💝 Support the project

If this bundle is useful to you, consider [becoming a sponsor](https://github.com/sponsors/julien-lin) to support the development and maintenance of this open source project.

---

A complete and modern authentication system for PHP 8+ with user management, roles, permissions, customizable guards and integration with JulienLinard packages.

**Current Version**: 1.1.0 | **Tests**: 64 tests, 133 assertions (100% passing) | **Strict Types**: ✅ Enabled

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Authentication](#authentication)
- [Roles and Permissions](#roles-and-permissions)
- [Middlewares](#middlewares)
- [User Providers](#user-providers)
- [Guards](#guards)
- [Hashers](#hashers)
- [Integration with Other Packages](#integration-with-other-packages)
- [API Reference](#api-reference)
- [Complete Examples](#complete-examples)
- [Tests](#-tests)

## 🚀 Installation

```bash
composer require julienlinard/auth-php
```

**Requirements**:
- PHP 8.0 or higher
- `julienlinard/core-php` (for Session)
- `julienlinard/doctrine-php` (for DatabaseUserProvider)

## ⚡ Quick Start

### Minimal Example

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use JulienLinard\Auth\AuthManager;
use JulienLinard\Doctrine\EntityManager;

// Database configuration
$dbConfig = [
    'host' => 'localhost',
    'dbname' => 'mydatabase',
    'user' => 'root',
    'password' => 'password'
];

$em = new EntityManager($dbConfig);

// Authentication configuration
$authConfig = [
    'user_class' => User::class,
    'entity_manager' => $em
];

$auth = new AuthManager($authConfig);

// Login attempt
$credentials = [
    'email' => 'user@example.com',
    'password' => 'password123'
];

if ($auth->attempt($credentials)) {
    $user = $auth->user();
    echo "Welcome " . $user->firstname;
} else {
    echo "Invalid credentials";
}
```

## 📖 Configuration

### Complete Configuration

```php
use JulienLinard\Auth\AuthManager;
use JulienLinard\Doctrine\EntityManager;

$em = new EntityManager($dbConfig);

$authConfig = [
    // User entity class (required)
    'user_class' => User::class,
    
    // Entity Manager (required for DatabaseUserProvider)
    'entity_manager' => $em,
    
    // Session key to store user (optional, default: 'auth_user')
    'session_key' => 'auth_user',
    
    // Enable "remember me" (optional, default: true)
    'remember_me' => true,
    
    // Identifier field (optional, default: 'id')
    'identifier_field' => 'id',
    
    // Credential field (optional, default: 'email')
    'credential_field' => 'email',
    
    // Custom hasher (optional)
    'hasher' => new CustomHasher(),
    
    // Hash algorithm (optional, default: PASSWORD_BCRYPT)
    // Supports: 'BCRYPT', 'ARGON2ID', 'ARGON2I', or PHP constants
    'hasher_algorithm' => 'ARGON2ID',
    
    // Hasher options (optional)
    'hasher_options' => [
        'memory_cost' => 65536,
        'time_cost' => 4,
        'threads' => 3
    ],
    
    // Custom provider (optional)
    'provider' => new CustomUserProvider()
];

$auth = new AuthManager($authConfig);
```

### Minimal Configuration

```php
$authConfig = [
    'user_class' => User::class,
    'entity_manager' => $em
];

$auth = new AuthManager($authConfig);
```

## 🔐 Authentication

### Login with Credentials

```php
// Login attempt
$credentials = [
    'email' => 'user@example.com',
    'password' => 'password123'
];

if ($auth->attempt($credentials)) {
    // Login successful
    $user = $auth->user();
    echo "Welcome " . $user->firstname;
} else {
    // Invalid credentials
    echo "Email or password incorrect";
}
```

### Login with "Remember Me"

```php
// Login with "remember me" enabled
$auth->attempt($credentials, true);
```

### Direct Login (without password verification)

```php
use JulienLinard\Auth\Models\UserInterface;

$user = $em->getRepository(User::class)->find(1);

// Authenticate user directly
$auth->login($user);

// With "remember me"
$auth->login($user, true);
```

### Logout

```php
// Logout
$auth->logout();
```

### Checks

```php
// Check if a user is authenticated
if ($auth->check()) {
    $user = $auth->user();
    echo "Logged in user: " . $user->email;
}

// Check if no user is authenticated
if ($auth->guest()) {
    echo "No user logged in";
}

// Get current user
$user = $auth->user(); // Returns UserInterface|null

// Get current user ID
$userId = $auth->id(); // Returns int|string|null
```

## 👥 Roles and Permissions

### Check a Role

```php
// Check if user has a specific role
if ($auth->hasRole('admin')) {
    echo "User is administrator";
}

// Check multiple roles (OR)
if ($auth->hasRole('admin') || $auth->hasRole('moderator')) {
    echo "User is admin or moderator";
}
```

### Check a Permission

```php
// Check if user has a permission
if ($auth->can('edit-posts')) {
    echo "User can edit posts";
}

// Check multiple permissions (OR)
if ($auth->can('edit-posts') || $auth->can('delete-posts')) {
    echo "User can edit or delete posts";
}
```

### Implementation in User Entity

```php
<?php

use JulienLinard\Doctrine\Mapping\Entity;
use JulienLinard\Doctrine\Mapping\Column;
use JulienLinard\Doctrine\Mapping\Id;
use JulienLinard\Auth\Models\UserInterface;
use JulienLinard\Auth\Models\Authenticatable;

#[Entity(table: 'users')]
class User implements UserInterface
{
    use Authenticatable;
    
    #[Id]
    #[Column(type: 'integer', autoIncrement: true)]
    public ?int $id = null;
    
    #[Column(type: 'string', length: 255)]
    public string $email;
    
    #[Column(type: 'string', length: 255)]
    public string $password;
    
    #[Column(type: 'string', length: 255, nullable: true)]
    public ?string $firstname = null;
    
    #[Column(type: 'string', length: 50, nullable: true)]
    public ?string $role = null; // 'admin', 'user', 'moderator', etc.
    
    // Roles (can be a string or an array)
    public function getAuthRoles(): array|string
    {
        return $this->role ?? 'user';
    }
    
    // Permissions (returns an array)
    public function getAuthPermissions(): array
    {
        // Example: permissions based on role
        return match($this->role) {
            'admin' => ['edit-posts', 'delete-posts', 'manage-users'],
            'moderator' => ['edit-posts', 'delete-posts'],
            'user' => ['view-posts'],
            default => []
        };
    }
}
```

## 🛡️ Middlewares

### AuthMiddleware

Protects a route by requiring authentication.

```php
use JulienLinard\Auth\Middleware\AuthMiddleware;
use JulienLinard\Router\Router;

$router = new Router();
$auth = new AuthManager($authConfig);

// Protected route with AuthMiddleware (default redirect to '/login')
class DashboardController
{
    #[Route(
        path: '/dashboard',
        methods: ['GET'],
        name: 'dashboard',
        middleware: [new AuthMiddleware()]
    )]
    public function index(): Response
    {
        return new Response(200, '<h1>Dashboard</h1>');
    }
}

// With custom redirect route
#[Route(
    path: '/dashboard',
    methods: ['GET'],
    middleware: [new AuthMiddleware('/connexion')]
)]

// AuthManager is automatically retrieved from container if not provided
// You can also pass it explicitly:
#[Route(
    path: '/dashboard',
    methods: ['GET'],
    middleware: [new AuthMiddleware('/login', $auth)]
)]
```

**Parameters:**
- `$redirectTo` (optional, default: `'/login'`): Route to redirect to if user is not authenticated (for GET requests)
- `$auth` (optional): AuthManager instance (automatically retrieved from container if not provided)

### RoleMiddleware

Protects a route by requiring a specific role.

```php
use JulienLinard\Auth\Middleware\RoleMiddleware;

// Route protected by role (default: returns JSON error for unauthorized)
class AdminController
{
    #[Route(
        path: '/admin/users',
        methods: ['GET'],
        name: 'admin.users',
        middleware: [
            new AuthMiddleware(),
            new RoleMiddleware('admin')
        ]
    )]
    public function users(): Response
    {
        return Response::json(['users' => []]);
    }
}

// With multiple accepted roles
#[Route(
    path: '/moderate',
    methods: ['GET'],
    middleware: [
        new AuthMiddleware(),
        new RoleMiddleware(['admin', 'moderator'])
    ]
)]

// With custom redirect route (for GET requests)
#[Route(
    path: '/admin',
    methods: ['GET'],
    middleware: [
        new AuthMiddleware(),
        new RoleMiddleware('admin', '/unauthorized')
    ]
)]
```

**Parameters:**
- `$roles` (required): Role(s) required (string or array)
- `$redirectTo` (optional, default: `null`): Route to redirect to if user doesn't have the role (for GET requests). If `null`, returns JSON error
- `$auth` (optional): AuthManager instance (automatically retrieved from container if not provided)

### PermissionMiddleware

Protects a route by requiring a specific permission.

```php
use JulienLinard\Auth\Middleware\PermissionMiddleware;

// Route protected by permission (default: returns JSON error for unauthorized)
class PostController
{
    #[Route(
        path: '/posts/{id}/edit',
        methods: ['POST'],
        middleware: [
            new AuthMiddleware(),
            new PermissionMiddleware('edit-posts')
        ]
    )]
    public function update(Request $request): Response
    {
        // User has 'edit-posts' permission
        return Response::json(['message' => 'Post updated']);
    }
}

// With multiple accepted permissions
#[Route(
    path: '/posts/{id}/delete',
    methods: ['DELETE'],
    middleware: [
        new AuthMiddleware(),
        new PermissionMiddleware(['delete-posts', 'manage-posts'])
    ]
)]

// With custom redirect route (for GET requests)
#[Route(
    path: '/posts/{id}/edit',
    methods: ['GET'],
    middleware: [
        new AuthMiddleware(),
        new PermissionMiddleware('edit-posts', '/forbidden')
    ]
)]
```

**Parameters:**
- `$permissions` (required): Permission(s) required (string or array)
- `$redirectTo` (optional, default: `null`): Route to redirect to if user doesn't have the permission (for GET requests). If `null`, returns JSON error
- `$auth` (optional): AuthManager instance (automatically retrieved from container if not provided)

### GuestMiddleware

Protects a route by requiring that no user is authenticated (for login/registration pages).

```php
use JulienLinard\Auth\Middleware\GuestMiddleware;

class AuthController
{
    // Default redirect to '/' if user is already authenticated
    #[Route(
        path: '/login',
        methods: ['GET'],
        middleware: [new GuestMiddleware()]
    )]
    public function loginForm(): Response
    {
        // Only unauthenticated users can access
        return new Response(200, '<form>...</form>');
    }
    
    // With custom redirect route
    #[Route(
        path: '/register',
        methods: ['GET'],
        middleware: [new GuestMiddleware('/dashboard')]
    )]
    public function registerForm(): Response
    {
        // If user is authenticated, redirect to '/dashboard'
        return new Response(200, '<form>...</form>');
    }
}
```

**Parameters:**
- `$redirectTo` (optional, default: `'/'`): Route to redirect to if user is already authenticated (for GET requests)
- `$auth` (optional): AuthManager instance (automatically retrieved from container if not provided)

### Usage with Route Groups

```php
use JulienLinard\Router\Router;

$router = new Router();
$auth = new AuthManager($authConfig);

// Route group protected by authentication
$router->group('/dashboard', [new AuthMiddleware()], function($router) {
    $router->registerRoutes(DashboardController::class);
});

// Route group protected by admin role with custom redirect
$router->group('/admin', [
    new AuthMiddleware(),
    new RoleMiddleware('admin', '/unauthorized')
], function($router) {
    $router->registerRoutes(AdminController::class);
});

// Route group protected by permission with custom redirect
$router->group('/posts', [
    new AuthMiddleware(),
    new PermissionMiddleware('edit-posts', '/forbidden')
], function($router) {
    $router->registerRoutes(PostController::class);
});
```

## 🔌 User Providers

### DatabaseUserProvider (default)

Uses `doctrine-php` to retrieve users from the database.

```php
use JulienLinard\Auth\Providers\DatabaseUserProvider;
use JulienLinard\Doctrine\EntityManager;

$em = new EntityManager($dbConfig);

// Manual creation (optional, created automatically by default)
$provider = new DatabaseUserProvider(
    $em,
    User::class,
    'id',        // Identifier field
    'email'      // Credential field
);

$authConfig = [
    'user_class' => User::class,
    'entity_manager' => $em,
    'provider' => $provider
];
```

### Custom User Provider

Create your own provider by implementing `UserProviderInterface`.

```php
<?php

use JulienLinard\Auth\Providers\UserProviderInterface;
use JulienLinard\Auth\Models\UserInterface;

class ApiUserProvider implements UserProviderInterface
{
    public function findById(int|string $identifier): ?UserInterface
    {
        // Retrieve from external API
        $response = file_get_contents("https://api.example.com/users/{$identifier}");
        $data = json_decode($response, true);
        
        if ($data) {
            return new User($data);
        }
        
        return null;
    }
    
    public function findByCredentials(array $credentials): ?UserInterface
    {
        // Retrieve from external API with credentials
        $email = $credentials['email'] ?? null;
        if (!$email) {
            return null;
        }
        
        $response = file_get_contents("https://api.example.com/users?email={$email}");
        $data = json_decode($response, true);
        
        if ($data && isset($data[0])) {
            return new User($data[0]);
        }
        
        return null;
    }
}

// Usage
$authConfig = [
    'user_class' => User::class,
    'provider' => new ApiUserProvider()
];
```

## 🛡️ Guards

### SessionGuard (default)

Uses PHP sessions to store authentication state.

```php
use JulienLinard\Auth\Guards\SessionGuard;
use JulienLinard\Auth\Providers\DatabaseUserProvider;
use JulienLinard\Auth\Hashers\PasswordHasher;

$provider = new DatabaseUserProvider($em, User::class);
$hasher = new PasswordHasher(PASSWORD_BCRYPT);

$guard = new SessionGuard($provider, $hasher, 'auth_user');

// The guard is created automatically by AuthManager
// But you can customize it if needed
```

### Custom Guard

Create your own guard by implementing `GuardInterface`.

```php
<?php

use JulienLinard\Auth\Guards\GuardInterface;
use JulienLinard\Auth\Models\UserInterface;
use JulienLinard\Auth\Providers\UserProviderInterface;
use JulienLinard\Auth\Hashers\HasherInterface;

class JwtGuard implements GuardInterface
{
    public function __construct(
        private UserProviderInterface $userProvider,
        private HasherInterface $hasher
    ) {}
    
    public function attempt(array $credentials, bool $remember = false): bool
    {
        $user = $this->userProvider->findByCredentials($credentials);
        
        if ($user === null) {
            return false;
        }
        
        if (!isset($credentials['password'])) {
            return false;
        }
        
        if (!$this->hasher->verify($credentials['password'], $user->getAuthPassword())) {
            return false;
        }
        
        // Create a JWT token instead of using session
        $token = $this->createJwtToken($user);
        setcookie('auth_token', $token, time() + 3600);
        
        return true;
    }
    
    public function check(): bool
    {
        $token = $_COOKIE['auth_token'] ?? null;
        if (!$token) {
            return false;
        }
        
        $userId = $this->decodeJwtToken($token);
        return $userId !== null;
    }
    
    public function user(): ?UserInterface
    {
        $token = $_COOKIE['auth_token'] ?? null;
        if (!$token) {
            return null;
        }
        
        $userId = $this->decodeJwtToken($token);
        if (!$userId) {
            return null;
        }
        
        return $this->userProvider->findById($userId);
    }
    
    // ... other methods required by GuardInterface
}
```

## 🔒 Hashers

### PasswordHasher (default)

Uses native PHP hash functions.

```php
use JulienLinard\Auth\Hashers\PasswordHasher;

// With default algorithm (BCRYPT)
$hasher = new PasswordHasher();

// With specific algorithm
$hasher = new PasswordHasher(PASSWORD_ARGON2ID);

// With custom options
$hasher = new PasswordHasher(PASSWORD_ARGON2ID, [
    'memory_cost' => 65536,
    'time_cost' => 4,
    'threads' => 3
]);

// Usage
$password = 'password123';
$hash = $hasher->hash($password);
$isValid = $hasher->verify($password, $hash);
$needsRehash = $hasher->needsRehash($hash);
```

### Custom Hasher

Create your own hasher by implementing `HasherInterface`.

```php
<?php

use JulienLinard\Auth\Hashers\HasherInterface;

class CustomHasher implements HasherInterface
{
    public function hash(string $password): string
    {
        // Your custom hash logic
        return hash('sha256', $password . 'salt');
    }
    
    public function verify(string $password, string $hash): bool
    {
        return hash('sha256', $password . 'salt') === $hash;
    }
    
    public function needsRehash(string $hash): bool
    {
        // Your logic to determine if rehash is needed
        return false;
    }
}

// Usage
$authConfig = [
    'user_class' => User::class,
    'entity_manager' => $em,
    'hasher' => new CustomHasher()
];
```

## 🔗 Integration with Other Packages

### Integration with core-php

```php
<?php

use JulienLinard\Core\Application;
use JulienLinard\Doctrine\EntityManager;
use JulienLinard\Auth\AuthManager;

// Initialize the application
$app = Application::create(__DIR__);
$app->loadEnv();

// Configure database
$em = new EntityManager([
    'host' => $_ENV['DB_HOST'],
    'dbname' => $_ENV['DB_NAME'],
    'user' => $_ENV['DB_USER'],
    'password' => $_ENV['DB_PASS']
]);

// Configure authentication
$auth = new AuthManager([
    'user_class' => User::class,
    'entity_manager' => $em
]);

// Use in a controller
class HomeController extends \JulienLinard\Core\Controller\Controller
{
    public function index(AuthManager $auth)
    {
        if ($auth->check()) {
            $user = $auth->user();
            return $this->view('dashboard', ['user' => $user]);
        }
        
        return $this->redirect('/login');
    }
}
```

### Integration with doctrine-php

```php
<?php

use JulienLinard\Doctrine\EntityManager;
use JulienLinard\Doctrine\Mapping\Entity;
use JulienLinard\Doctrine\Mapping\Column;
use JulienLinard\Doctrine\Mapping\Id;
use JulienLinard\Auth\Models\UserInterface;
use JulienLinard\Auth\Models\Authenticatable;

// Define the User entity
#[Entity(table: 'users')]
class User implements UserInterface
{
    use Authenticatable;
    
    #[Id]
    #[Column(type: 'integer', autoIncrement: true)]
    public ?int $id = null;
    
    #[Column(type: 'string', length: 255)]
    public string $email;
    
    #[Column(type: 'string', length: 255)]
    public string $password;
    
    // ... other properties
}

// Use with AuthManager
$em = new EntityManager($dbConfig);
$auth = new AuthManager([
    'user_class' => User::class,
    'entity_manager' => $em
]);
```

### Integration with php-router

```php
<?php

use JulienLinard\Router\Router;
use JulienLinard\Router\Attributes\Route;
use JulienLinard\Auth\AuthManager;
use JulienLinard\Auth\Middleware\AuthMiddleware;
use JulienLinard\Auth\Middleware\RoleMiddleware;

$router = new Router();
$auth = new AuthManager($authConfig);

// Public routes
class HomeController
{
    #[Route(path: '/', methods: ['GET'], name: 'home')]
    public function index(): Response
    {
        return new Response(200, '<h1>Home</h1>');
    }
}

// Protected routes
class DashboardController
{
    #[Route(
        path: '/dashboard',
        methods: ['GET'],
        name: 'dashboard',
        middleware: [new AuthMiddleware($auth)]
    )]
    public function index(): Response
    {
        return new Response(200, '<h1>Dashboard</h1>');
    }
}

// Routes with roles
class AdminController
{
    #[Route(
        path: '/admin',
        methods: ['GET'],
        name: 'admin',
        middleware: [
            new AuthMiddleware($auth),
            new RoleMiddleware('admin', $auth)
        ]
    )]
    public function index(): Response
    {
        return new Response(200, '<h1>Admin</h1>');
    }
}

// Register routes
$router->registerRoutes(HomeController::class);
$router->registerRoutes(DashboardController::class);
$router->registerRoutes(AdminController::class);
```

## 📚 API Reference

### AuthManager

#### `__construct(array $config)`

Creates a new AuthManager instance.

```php
$auth = new AuthManager([
    'user_class' => User::class,
    'entity_manager' => $em
]);
```

#### `attempt(array $credentials, bool $remember = false): bool`

Attempts to authenticate a user with credentials.

```php
$success = $auth->attempt([
    'email' => 'user@example.com',
    'password' => 'password123'
], true);
```

#### `login(UserInterface $user, bool $remember = false): void`

Authenticates a user directly without password verification.

```php
$user = $em->getRepository(User::class)->find(1);
$auth->login($user, true);
```

#### `logout(): void`

Logs out the current user.

```php
$auth->logout();
```

#### `check(): bool`

Checks if a user is authenticated.

```php
if ($auth->check()) {
    // User authenticated
}
```

#### `guest(): bool`

Checks if no user is authenticated.

```php
if ($auth->guest()) {
    // No user authenticated
}
```

#### `user(): ?UserInterface`

Returns the currently authenticated user.

```php
$user = $auth->user();
if ($user) {
    echo $user->email;
}
```

#### `id(): int|string|null`

Returns the ID of the currently authenticated user.

```php
$userId = $auth->id();
```

#### `hasRole(string $role): bool`

Checks if the user has a specific role.

```php
if ($auth->hasRole('admin')) {
    // User is admin
}
```

#### `can(string $permission): bool`

Checks if the user has a specific permission.

```php
if ($auth->can('edit-posts')) {
    // User can edit posts
}
```

#### `guard(): GuardInterface`

Returns the current guard.

```php
$guard = $auth->guard();
```

## 💡 Complete Examples

### Example 1: Complete Application with Authentication

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use JulienLinard\Core\Application;
use JulienLinard\Doctrine\EntityManager;
use JulienLinard\Auth\AuthManager;
use JulienLinard\Auth\Middleware\AuthMiddleware;
use JulienLinard\Auth\Middleware\RoleMiddleware;
use JulienLinard\Router\Router;
use JulienLinard\Router\Attributes\Route;
use JulienLinard\Router\Request;
use JulienLinard\Router\Response;

// Initialize the application
$app = Application::create(__DIR__);
$app->loadEnv();

// Configure database
$em = new EntityManager([
    'host' => $_ENV['DB_HOST'],
    'dbname' => $_ENV['DB_NAME'],
    'user' => $_ENV['DB_USER'],
    'password' => $_ENV['DB_PASS']
]);

// Configure authentication
$auth = new AuthManager([
    'user_class' => User::class,
    'entity_manager' => $em
]);

// Authentication controller
class AuthController
{
    public function __construct(
        private AuthManager $auth,
        private EntityManager $em
    ) {}
    
    #[Route(path: '/login', methods: ['GET'], name: 'login')]
    public function loginForm(): Response
    {
        return new Response(200, '<form method="POST" action="/login">...</form>');
    }
    
    #[Route(path: '/login', methods: ['POST'], name: 'login.post')]
    public function login(Request $request): Response
    {
        $credentials = [
            'email' => $request->getBodyParam('email'),
            'password' => $request->getBodyParam('password')
        ];
        
        if ($this->auth->attempt($credentials)) {
            return new Response(302, '', ['Location' => '/dashboard']);
        }
        
        return new Response(200, 'Invalid credentials');
    }
    
    #[Route(path: '/logout', methods: ['POST'], name: 'logout')]
    public function logout(): Response
    {
        $this->auth->logout();
        return new Response(302, '', ['Location' => '/']);
    }
}

// Dashboard controller
class DashboardController
{
    public function __construct(private AuthManager $auth) {}
    
    #[Route(
        path: '/dashboard',
        methods: ['GET'],
        name: 'dashboard',
        middleware: [new AuthMiddleware($auth)]
    )]
    public function index(): Response
    {
        $user = $this->auth->user();
        return new Response(200, "<h1>Welcome {$user->firstname}</h1>");
    }
}

// Admin controller
class AdminController
{
    public function __construct(private AuthManager $auth) {}
    
    #[Route(
        path: '/admin',
        methods: ['GET'],
        name: 'admin',
        middleware: [
            new AuthMiddleware($auth),
            new RoleMiddleware('admin', $auth)
        ]
    )]
    public function index(): Response
    {
        return new Response(200, '<h1>Admin Panel</h1>');
    }
}

// Register routes
$router = $app->getRouter();
$router->registerRoutes(AuthController::class);
$router->registerRoutes(DashboardController::class);
$router->registerRoutes(AdminController::class);

// Start the application
$app->start();
```

## 🧪 Tests

The library includes a comprehensive test suite with **64 tests** and **133 assertions**, ensuring reliability and quality.

```bash
composer test
```

### Test Coverage

- ✅ **AuthManager**: 9 tests (creation, verification, roles, permissions)
- ✅ **PasswordHasher**: 12 tests (hash, verify, rehash, different algorithms)
- ✅ **SessionGuard**: 11 tests (attempt, login, logout, check, user, session)
- ✅ **DatabaseUserProvider**: 8 tests (findById, findByCredentials, findByField)
- ✅ **Middlewares**: 13 tests (AuthMiddleware, GuestMiddleware, RoleMiddleware, PermissionMiddleware)
- ✅ **Roles and Permissions**: 10 tests (Authenticatable trait)

**Test Results**: 100% passing (64/64 tests)

### Code Quality

- ✅ **Strict Types**: All 16 source files use `declare(strict_types=1)`
- ✅ **Type Safety**: Enhanced type hints with PHP 8 union types and `mixed`
- ✅ **PHP 8.5+ Compatible**: Full support for PHP 8.5+ features

## 📝 License

MIT License - See the LICENSE file for more details.

## 🤝 Contributing

Contributions are welcome! Feel free to open an issue or a pull request.

## 📧 Support

For any questions or issues, please open an issue on GitHub.

## 💝 Support the project

If this bundle is useful to you, consider [becoming a sponsor](https://github.com/sponsors/julien-lin) to support the development and maintenance of this open source project.

---

**Developed with ❤️ by Julien Linard**
