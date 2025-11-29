<?php

declare(strict_types=1);

namespace JulienLinard\Auth\Exceptions;

/**
 * Exception levée lorsqu'un utilisateur non authentifié tente d'accéder à une ressource protégée
 */
class UnauthorizedException extends AuthenticationException
{
}

