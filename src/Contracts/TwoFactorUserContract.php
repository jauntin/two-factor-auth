<?php

namespace Jauntin\TwoFactorAuth\Contracts;

use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Jauntin\TwoFactorAuth\Enums\TwoFactorType;
use Jauntin\TwoFactorAuth\Models\TwoFactorUserProvider;

interface TwoFactorUserContract
{
    public function hasTwoFactor(?TwoFactorType $provider = null): bool;

    /**
     * @param  TwoFactorType[]  $providers
     */
    public function addTwoFactor(array $providers): void;

    /**
     * @return EloquentCollection<int,TwoFactorUserProvider>
     */
    public function getTwoFactorProviders(): EloquentCollection;

    public function getDefaultTwoFactorProvider(): ?TwoFactorType;

    /**
     * @return HasMany<TwoFactorUserProvider>
     */
    public function twoFactorProviders(): HasMany;
}
