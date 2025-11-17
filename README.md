# Auth PHP - Système d'Authentification Complet

Un système d'authentification complet et moderne pour PHP 8+ avec gestion des utilisateurs, rôles, permissions, guards personnalisables et intégration avec les packages JulienLinard.

## 📋 Table des matières

- [Installation](#installation)
- [Démarrage rapide](#démarrage-rapide)
- [Configuration](#configuration)
- [Authentification](#authentification)
- [Rôles et Permissions](#rôles-et-permissions)
- [Middlewares](#middlewares)
- [User Providers](#user-providers)
- [Guards](#guards)
- [Hashers](#hashers)
- [Intégration avec les autres packages](#intégration-avec-les-autres-packages)
- [API Reference](#api-reference)
- [Exemples complets](#exemples-complets)

## 🚀 Installation

```bash
composer require julienlinard/auth-php
```

**Requirements** :
- PHP 8.0 ou supérieur
- `julienlinard/core-php` (pour Session)
- `julienlinard/doctrine-php` (pour DatabaseUserProvider)

## ⚡ Démarrage rapide

### Exemple minimal

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use JulienLinard\Auth\AuthManager;
use JulienLinard\Doctrine\EntityManager;

// Configuration de la base de données
$dbConfig = [
    'host' => 'localhost',
    'dbname' => 'mydatabase',
    'user' => 'root',
    'password' => 'password'
];

$em = new EntityManager($dbConfig);

// Configuration d'authentification
$authConfig = [
    'user_class' => User::class,
    'entity_manager' => $em
];

$auth = new AuthManager($authConfig);

// Tentative de connexion
$credentials = [
    'email' => 'user@example.com',
    'password' => 'password123'
];

if ($auth->attempt($credentials)) {
    $user = $auth->user();
    echo "Bienvenue " . $user->firstname;
} else {
    echo "Identifiants incorrects";
}
```

## 📖 Configuration

### Configuration complète

```php
use JulienLinard\Auth\AuthManager;
use JulienLinard\Doctrine\EntityManager;

$em = new EntityManager($dbConfig);

$authConfig = [
    // Classe de l'entité utilisateur (requis)
    'user_class' => User::class,
    
    // Entity Manager (requis pour DatabaseUserProvider)
    'entity_manager' => $em,
    
    // Clé de session pour stocker l'utilisateur (optionnel, défaut: 'auth_user')
    'session_key' => 'auth_user',
    
    // Activer "remember me" (optionnel, défaut: true)
    'remember_me' => true,
    
    // Champ pour l'identifiant (optionnel, défaut: 'id')
    'identifier_field' => 'id',
    
    // Champ pour les credentials (optionnel, défaut: 'email')
    'credential_field' => 'email',
    
    // Hasher personnalisé (optionnel)
    'hasher' => new CustomHasher(),
    
    // Algorithme de hash (optionnel, défaut: PASSWORD_BCRYPT)
    // Supporte: 'BCRYPT', 'ARGON2ID', 'ARGON2I', ou constantes PHP
    'hasher_algorithm' => 'ARGON2ID',
    
    // Options du hasher (optionnel)
    'hasher_options' => [
        'memory_cost' => 65536,
        'time_cost' => 4,
        'threads' => 3
    ],
    
    // Provider personnalisé (optionnel)
    'provider' => new CustomUserProvider()
];

$auth = new AuthManager($authConfig);
```

### Configuration minimale

```php
$authConfig = [
    'user_class' => User::class,
    'entity_manager' => $em
];

$auth = new AuthManager($authConfig);
```

## 🔐 Authentification

### Login avec credentials

```php
// Tentative de connexion
$credentials = [
    'email' => 'user@example.com',
    'password' => 'password123'
];

if ($auth->attempt($credentials)) {
    // Connexion réussie
    $user = $auth->user();
    echo "Bienvenue " . $user->firstname;
} else {
    // Identifiants incorrects
    echo "Email ou mot de passe incorrect";
}
```

### Login avec "Remember Me"

```php
// Connexion avec "remember me" activé
$auth->attempt($credentials, true);
```

### Login direct (sans vérification de mot de passe)

```php
use JulienLinard\Auth\Models\UserInterface;

$user = $em->getRepository(User::class)->find(1);

// Authentifier directement l'utilisateur
$auth->login($user);

// Avec "remember me"
$auth->login($user, true);
```

### Logout

```php
// Déconnexion
$auth->logout();
```

### Vérifications

```php
// Vérifier si un utilisateur est authentifié
if ($auth->check()) {
    $user = $auth->user();
    echo "Utilisateur connecté : " . $user->email;
}

// Vérifier si aucun utilisateur n'est authentifié
if ($auth->guest()) {
    echo "Aucun utilisateur connecté";
}

// Récupérer l'utilisateur actuel
$user = $auth->user(); // Retourne UserInterface|null

// Récupérer l'ID de l'utilisateur actuel
$userId = $auth->id(); // Retourne int|string|null
```

## 👥 Rôles et Permissions

### Vérifier un rôle

```php
// Vérifier si l'utilisateur a un rôle spécifique
if ($auth->hasRole('admin')) {
    echo "L'utilisateur est administrateur";
}

// Vérifier plusieurs rôles (OR)
if ($auth->hasRole('admin') || $auth->hasRole('moderator')) {
    echo "L'utilisateur est admin ou modérateur";
}
```

### Vérifier une permission

```php
// Vérifier si l'utilisateur a une permission
if ($auth->can('edit-posts')) {
    echo "L'utilisateur peut éditer des posts";
}

// Vérifier plusieurs permissions (OR)
if ($auth->can('edit-posts') || $auth->can('delete-posts')) {
    echo "L'utilisateur peut éditer ou supprimer des posts";
}
```

### Implémentation dans l'entité User

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
    
    // Rôles (peut être un string ou un array)
    public function getAuthRoles(): array|string
    {
        return $this->role ?? 'user';
    }
    
    // Permissions (retourne un array)
    public function getAuthPermissions(): array
    {
        // Exemple : permissions basées sur le rôle
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

Protège une route en exigeant une authentification.

```php
use JulienLinard\Auth\Middleware\AuthMiddleware;
use JulienLinard\Router\Router;

$router = new Router();
$auth = new AuthManager($authConfig);

// Route protégée avec AuthMiddleware
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
```

### RoleMiddleware

Protège une route en exigeant un rôle spécifique.

```php
use JulienLinard\Auth\Middleware\RoleMiddleware;

// Route protégée par rôle
class AdminController
{
    #[Route(
        path: '/admin/users',
        methods: ['GET'],
        name: 'admin.users',
        middleware: [
            new AuthMiddleware($auth),
            new RoleMiddleware('admin', $auth)
        ]
    )]
    public function users(): Response
    {
        return Response::json(['users' => []]);
    }
}

// Avec plusieurs rôles acceptés
#[Route(
    path: '/moderate',
    methods: ['GET'],
    middleware: [
        new AuthMiddleware($auth),
        new RoleMiddleware(['admin', 'moderator'], $auth)
    ]
)]
```

### PermissionMiddleware

Protège une route en exigeant une permission spécifique.

```php
use JulienLinard\Auth\Middleware\PermissionMiddleware;

// Route protégée par permission
class PostController
{
    #[Route(
        path: '/posts/{id}/edit',
        methods: ['POST'],
        middleware: [
            new AuthMiddleware($auth),
            new PermissionMiddleware('edit-posts', $auth)
        ]
    )]
    public function update(Request $request): Response
    {
        // L'utilisateur a la permission 'edit-posts'
        return Response::json(['message' => 'Post mis à jour']);
    }
}

// Avec plusieurs permissions acceptées
#[Route(
    path: '/posts/{id}/delete',
    methods: ['DELETE'],
    middleware: [
        new AuthMiddleware($auth),
        new PermissionMiddleware(['delete-posts', 'manage-posts'], $auth)
    ]
)]
```

### GuestMiddleware

Protège une route en exigeant qu'aucun utilisateur ne soit authentifié (pour les pages de connexion/inscription).

```php
use JulienLinard\Auth\Middleware\GuestMiddleware;

class AuthController
{
    #[Route(
        path: '/login',
        methods: ['GET'],
        middleware: [new GuestMiddleware($auth)]
    )]
    public function loginForm(): Response
    {
        // Seuls les utilisateurs non authentifiés peuvent accéder
        return new Response(200, '<form>...</form>');
    }
}
```

### Utilisation avec des groupes de routes

```php
use JulienLinard\Router\Router;

$router = new Router();
$auth = new AuthManager($authConfig);

// Groupe de routes protégées par authentification
$router->group('/dashboard', [new AuthMiddleware($auth)], function($router) {
    $router->registerRoutes(DashboardController::class);
});

// Groupe de routes protégées par rôle admin
$router->group('/admin', [
    new AuthMiddleware($auth),
    new RoleMiddleware('admin', $auth)
], function($router) {
    $router->registerRoutes(AdminController::class);
});

// Groupe de routes protégées par permission
$router->group('/posts', [
    new AuthMiddleware($auth),
    new PermissionMiddleware('edit-posts', $auth)
], function($router) {
    $router->registerRoutes(PostController::class);
});
```

## 🔌 User Providers

### DatabaseUserProvider (par défaut)

Utilise `doctrine-php` pour récupérer les utilisateurs depuis la base de données.

```php
use JulienLinard\Auth\Providers\DatabaseUserProvider;
use JulienLinard\Doctrine\EntityManager;

$em = new EntityManager($dbConfig);

// Création manuelle (optionnel, créé automatiquement par défaut)
$provider = new DatabaseUserProvider(
    $em,
    User::class,
    'id',        // Champ identifiant
    'email'      // Champ credential
);

$authConfig = [
    'user_class' => User::class,
    'entity_manager' => $em,
    'provider' => $provider
];
```

### User Provider personnalisé

Créez votre propre provider en implémentant `UserProviderInterface`.

```php
<?php

use JulienLinard\Auth\Providers\UserProviderInterface;
use JulienLinard\Auth\Models\UserInterface;

class ApiUserProvider implements UserProviderInterface
{
    public function findById(int|string $identifier): ?UserInterface
    {
        // Récupérer depuis une API externe
        $response = file_get_contents("https://api.example.com/users/{$identifier}");
        $data = json_decode($response, true);
        
        if ($data) {
            return new User($data);
        }
        
        return null;
    }
    
    public function findByCredentials(array $credentials): ?UserInterface
    {
        // Récupérer depuis une API externe avec credentials
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

// Utilisation
$authConfig = [
    'user_class' => User::class,
    'provider' => new ApiUserProvider()
];
```

## 🛡️ Guards

### SessionGuard (par défaut)

Utilise les sessions PHP pour stocker l'état d'authentification.

```php
use JulienLinard\Auth\Guards\SessionGuard;
use JulienLinard\Auth\Providers\DatabaseUserProvider;
use JulienLinard\Auth\Hashers\PasswordHasher;

$provider = new DatabaseUserProvider($em, User::class);
$hasher = new PasswordHasher(PASSWORD_BCRYPT);

$guard = new SessionGuard($provider, $hasher, 'auth_user');

// Le guard est créé automatiquement par AuthManager
// Mais vous pouvez le personnaliser si nécessaire
```

### Guard personnalisé

Créez votre propre guard en implémentant `GuardInterface`.

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
        
        // Créer un token JWT au lieu d'utiliser la session
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
    
    // ... autres méthodes requises par GuardInterface
}
```

## 🔒 Hashers

### PasswordHasher (par défaut)

Utilise les fonctions de hash PHP natives.

```php
use JulienLinard\Auth\Hashers\PasswordHasher;

// Avec algorithme par défaut (BCRYPT)
$hasher = new PasswordHasher();

// Avec algorithme spécifique
$hasher = new PasswordHasher(PASSWORD_ARGON2ID);

// Avec options personnalisées
$hasher = new PasswordHasher(PASSWORD_ARGON2ID, [
    'memory_cost' => 65536,
    'time_cost' => 4,
    'threads' => 3
]);

// Utilisation
$password = 'password123';
$hash = $hasher->hash($password);
$isValid = $hasher->verify($password, $hash);
$needsRehash = $hasher->needsRehash($hash);
```

### Hasher personnalisé

Créez votre propre hasher en implémentant `HasherInterface`.

```php
<?php

use JulienLinard\Auth\Hashers\HasherInterface;

class CustomHasher implements HasherInterface
{
    public function hash(string $password): string
    {
        // Votre logique de hash personnalisée
        return hash('sha256', $password . 'salt');
    }
    
    public function verify(string $password, string $hash): bool
    {
        return hash('sha256', $password . 'salt') === $hash;
    }
    
    public function needsRehash(string $hash): bool
    {
        // Votre logique pour déterminer si un rehash est nécessaire
        return false;
    }
}

// Utilisation
$authConfig = [
    'user_class' => User::class,
    'entity_manager' => $em,
    'hasher' => new CustomHasher()
];
```

## 🔗 Intégration avec les autres packages

### Intégration avec core-php

```php
<?php

use JulienLinard\Core\Application;
use JulienLinard\Doctrine\EntityManager;
use JulienLinard\Auth\AuthManager;

// Initialiser l'application
$app = Application::create(__DIR__);
$app->loadEnv();

// Configurer la base de données
$em = new EntityManager([
    'host' => $_ENV['DB_HOST'],
    'dbname' => $_ENV['DB_NAME'],
    'user' => $_ENV['DB_USER'],
    'password' => $_ENV['DB_PASS']
]);

// Configurer l'authentification
$auth = new AuthManager([
    'user_class' => User::class,
    'entity_manager' => $em
]);

// Utiliser dans un contrôleur
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

### Intégration avec doctrine-php

```php
<?php

use JulienLinard\Doctrine\EntityManager;
use JulienLinard\Doctrine\Mapping\Entity;
use JulienLinard\Doctrine\Mapping\Column;
use JulienLinard\Doctrine\Mapping\Id;
use JulienLinard\Auth\Models\UserInterface;
use JulienLinard\Auth\Models\Authenticatable;

// Définir l'entité User
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
    
    // ... autres propriétés
}

// Utiliser avec AuthManager
$em = new EntityManager($dbConfig);
$auth = new AuthManager([
    'user_class' => User::class,
    'entity_manager' => $em
]);
```

### Intégration avec php-router

```php
<?php

use JulienLinard\Router\Router;
use JulienLinard\Router\Attributes\Route;
use JulienLinard\Auth\AuthManager;
use JulienLinard\Auth\Middleware\AuthMiddleware;
use JulienLinard\Auth\Middleware\RoleMiddleware;

$router = new Router();
$auth = new AuthManager($authConfig);

// Routes publiques
class HomeController
{
    #[Route(path: '/', methods: ['GET'], name: 'home')]
    public function index(): Response
    {
        return new Response(200, '<h1>Accueil</h1>');
    }
}

// Routes protégées
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

// Routes avec rôles
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

// Enregistrer les routes
$router->registerRoutes(HomeController::class);
$router->registerRoutes(DashboardController::class);
$router->registerRoutes(AdminController::class);
```

## 📚 API Reference

### AuthManager

#### `__construct(array $config)`

Crée une nouvelle instance d'AuthManager.

```php
$auth = new AuthManager([
    'user_class' => User::class,
    'entity_manager' => $em
]);
```

#### `attempt(array $credentials, bool $remember = false): bool`

Tente d'authentifier un utilisateur avec des credentials.

```php
$success = $auth->attempt([
    'email' => 'user@example.com',
    'password' => 'password123'
], true);
```

#### `login(UserInterface $user, bool $remember = false): void`

Authentifie un utilisateur directement sans vérification de mot de passe.

```php
$user = $em->getRepository(User::class)->find(1);
$auth->login($user, true);
```

#### `logout(): void`

Déconnecte l'utilisateur actuel.

```php
$auth->logout();
```

#### `check(): bool`

Vérifie si un utilisateur est authentifié.

```php
if ($auth->check()) {
    // Utilisateur authentifié
}
```

#### `guest(): bool`

Vérifie si aucun utilisateur n'est authentifié.

```php
if ($auth->guest()) {
    // Aucun utilisateur authentifié
}
```

#### `user(): ?UserInterface`

Retourne l'utilisateur actuellement authentifié.

```php
$user = $auth->user();
if ($user) {
    echo $user->email;
}
```

#### `id(): int|string|null`

Retourne l'ID de l'utilisateur actuellement authentifié.

```php
$userId = $auth->id();
```

#### `hasRole(string $role): bool`

Vérifie si l'utilisateur a un rôle spécifique.

```php
if ($auth->hasRole('admin')) {
    // L'utilisateur est admin
}
```

#### `can(string $permission): bool`

Vérifie si l'utilisateur a une permission spécifique.

```php
if ($auth->can('edit-posts')) {
    // L'utilisateur peut éditer des posts
}
```

#### `guard(): GuardInterface`

Retourne le guard actuel.

```php
$guard = $auth->guard();
```

## 💡 Exemples complets

### Exemple 1 : Application complète avec authentification

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

// Initialiser l'application
$app = Application::create(__DIR__);
$app->loadEnv();

// Configurer la base de données
$em = new EntityManager([
    'host' => $_ENV['DB_HOST'],
    'dbname' => $_ENV['DB_NAME'],
    'user' => $_ENV['DB_USER'],
    'password' => $_ENV['DB_PASS']
]);

// Configurer l'authentification
$auth = new AuthManager([
    'user_class' => User::class,
    'entity_manager' => $em
]);

// Contrôleur d'authentification
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
        
        return new Response(200, 'Identifiants incorrects');
    }
    
    #[Route(path: '/logout', methods: ['POST'], name: 'logout')]
    public function logout(): Response
    {
        $this->auth->logout();
        return new Response(302, '', ['Location' => '/']);
    }
}

// Contrôleur dashboard
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
        return new Response(200, "<h1>Bienvenue {$user->firstname}</h1>");
    }
}

// Contrôleur admin
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
        return new Response(200, '<h1>Panel Admin</h1>');
    }
}

// Enregistrer les routes
$router = $app->getRouter();
$router->registerRoutes(AuthController::class);
$router->registerRoutes(DashboardController::class);
$router->registerRoutes(AdminController::class);

// Démarrer l'application
$app->start();
```

## 🧪 Tests

```bash
composer test
```

## 📝 License

MIT License - Voir le fichier LICENSE pour plus de détails.

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une issue ou une pull request.

## 📧 Support

Pour toute question ou problème, veuillez ouvrir une issue sur GitHub.

---

**Développé avec ❤️ par Julien Linard**
