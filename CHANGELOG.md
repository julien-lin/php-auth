# Changelog

Tous les changements notables de ce projet seront documentés dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

## [1.2.0] - 2025-01-XX

### ✨ Ajouté

- **Redirections configurables dans les middlewares** : Ajout de paramètres de redirection personnalisables
  - `AuthMiddleware` : Paramètre `$redirectTo` (défaut: `'/login'`) pour personnaliser la redirection si l'utilisateur n'est pas authentifié
  - `GuestMiddleware` : Paramètre `$redirectTo` (défaut: `'/'`) pour personnaliser la redirection si l'utilisateur est déjà authentifié
  - `RoleMiddleware` : Paramètre `$redirectTo` (défaut: `null`) pour rediriger les utilisateurs sans le rôle requis (pour les requêtes GET)
  - `PermissionMiddleware` : Paramètre `$redirectTo` (défaut: `null`) pour rediriger les utilisateurs sans la permission requise (pour les requêtes GET)

### 🔧 Amélioré

- **Middlewares** : Amélioration du comportement des redirections
  - Redirection automatique pour les requêtes GET vers la route configurée
  - Retour d'erreur JSON pour les requêtes POST/AJAX (comportement inchangé)
  - Support de `null` pour désactiver les redirections et retourner uniquement des erreurs JSON

- **Documentation** : Mise à jour complète des README (anglais et français)
  - Documentation des nouveaux paramètres de redirection
  - Exemples d'utilisation avec redirections personnalisées
  - Exemples mis à jour pour les groupes de routes

### 📝 Documentation

- Ajout d'exemples détaillés pour chaque middleware avec les nouveaux paramètres
- Documentation des valeurs par défaut et du comportement selon le type de requête

## [1.1.0] - 2025-11-29

### ✨ Ajouté

- **Tests complets** : Ajout d'une suite de tests complète (40+ tests)
  - Tests pour `AuthManager` (création, vérification, rôles, permissions)
  - Tests pour `PasswordHasher` (hash, verify, rehash, différents algorithmes)
  - Tests pour `SessionGuard` (attempt, login, logout, check, user, session)
  - Tests pour `DatabaseUserProvider` (findById, findByCredentials, findByField)
  - Tests pour les middlewares (AuthMiddleware, GuestMiddleware, RoleMiddleware, PermissionMiddleware)
  - Tests pour les rôles et permissions (Authenticatable trait)

### 🔧 Amélioré

- **Strict Types** : Ajout de `declare(strict_types=1)` dans tous les fichiers source (16/16)
  - Améliore la type safety et la détection d'erreurs
  - Appliqué à tous les fichiers (AuthManager, Guards, Hashers, Providers, Middlewares, Models, Exceptions)

- **Type Hints** : Amélioration des type hints avec PHP 8
  - Utilisation du type `mixed` pour les paramètres flexibles
  - Types union pour les rôles (`array|string`)
  - Types améliorés pour `findByField()`

- **Intégration Container** : Amélioration de l'intégration avec le container dans les middlewares
  - Implémentation complète de `createAuthManager()` dans RoleMiddleware, PermissionMiddleware, GuestMiddleware
  - Suppression des TODO et méthodes temporaires
  - Récupération automatique depuis le container si disponible

- **Documentation PHPDoc** : Amélioration de la documentation pour `findByField()`

- **PasswordHasher** : Support amélioré pour PHP 8.5+ (PASSWORD_BCRYPT peut être string)
  - Normalisation automatique des algorithmes (string → int)
  - Compatibilité avec toutes les versions PHP 8.0+
  - Gestion correcte des constantes PASSWORD_* (string ou int selon version PHP)

- **Authenticatable** : Amélioration de `getAuthRoles()` pour gérer correctement role (string) et roles (array)
  - Priorité aux roles (array) si défini
  - Fallback sur role (string) si roles n'est pas défini
  - Retourne [] par défaut

### 🐛 Corrigé

- **Middlewares** : Correction de l'intégration avec le container
  - Implémentation complète de la récupération depuis le container
  - Messages d'erreur améliorés

### 📊 Statistiques

- **Tests** : 64 tests (0 → 64, +64 nouveaux tests)
- **Assertions** : 133 assertions
- **Taux de réussite** : 100% (tous les tests passent)
- **Strict types** : 16/16 fichiers (100%)
- **Couverture** : Tests complets pour toutes les fonctionnalités principales

## [1.0.8] - 2025-11-XX

### ✨ Ajouté

- Système d'authentification complet
- Gestion des utilisateurs, rôles et permissions
- Guards personnalisables
- Intégration avec Doctrine PHP
- Middlewares pour le routage
