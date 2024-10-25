<?php

namespace Jauntin\TwoFactorAuth\Providers;

use Closure;
use Illuminate\Foundation\Auth\User;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorUserContract;

interface TwoFactorProviderInterface
{
    public function sendVerificationCode(User&TwoFactorUserContract $user, ?Closure $callback = null): void;

    public function validateVerificationCode(User&TwoFactorUserContract $user, string $verificationCode): bool;
}
