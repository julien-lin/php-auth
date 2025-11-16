# Auth PHP - Système d'Authentification

Un système d'authentification complet pour PHP 8+ avec gestion des utilisateurs, rôles, permissions, et sécurité.

## 🚀 Installation

```bash
composer require julienlinard/auth-php
```

**Requirements** : PHP 8.0 ou supérieur, core-php, doctrine-php

## ⚡ Démarrage rapide

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use JulienLinard\Auth\AuthManager;
use JulienLinard\Auth\Middleware\AuthMiddleware;

// Configuration
$auth = new AuthManager($config);

// Login
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

// Vérification d'authentification
if ($auth->check()) {
    $user = $auth->user();
}

// Logout
$auth->logout();
```

## 📋 Fonctionnalités

- ✅ **Authentication** - Login/Logout avec hash sécurisé
- ✅ **Authorization** - Système de rôles et permissions
- ✅ **User Management** - Création, validation, reset password
- ✅ **Security** - Protection CSRF, XSS, brute force
- ✅ **Middlewares** - AuthMiddleware, RoleMiddleware, PermissionMiddleware
- ✅ **Session Management** - Gestion sécurisée des sessions

## 📖 Documentation

### Configuration

```php
use JulienLinard\Auth\AuthManager;

$config = [
    'user_class' => User::class,
    'session_key' => 'auth_user',
    'remember_me' => true,
    'password_reset_expiry' => 3600, // 1 heure
];

$auth = new AuthManager($config);
```

### Login/Logout

```php
// Login avec credentials
if ($auth->attempt(['email' => 'test@example.com', 'password' => 'password'])) {
    // Succès
}

// Login avec remember me
$auth->attempt(['email' => 'test@example.com', 'password' => 'password'], true);

// Logout
$auth->logout();
```

### Vérifications

```php
// Vérifier si authentifié
if ($auth->check()) {
    $user = $auth->user();
}

// Vérifier un rôle
if ($auth->hasRole('admin')) {
    // Accès admin
}

// Vérifier une permission
if ($auth->can('edit-posts')) {
    // Permission accordée
}
```

### Middlewares

```php
use JulienLinard\Auth\Middleware\AuthMiddleware;
use JulienLinard\Auth\Middleware\RoleMiddleware;

// Route protégée par authentification
$router->group('/dashboard', [AuthMiddleware::class], function($router) {
    $router->registerRoutes(DashboardController::class);
});

// Route protégée par rôle
$router->group('/admin', [
    AuthMiddleware::class,
    new RoleMiddleware('admin')
], function($router) {
    $router->registerRoutes(AdminController::class);
});
```

## 📝 License

MIT License - Voir le fichier LICENSE pour plus de détails.

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une issue ou une pull request.

---

**Développé avec ❤️ par Julien Linard**

