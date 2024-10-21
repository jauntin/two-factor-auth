<?php

namespace Jauntin\TwoFactorAuth\Models\Traits;

use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User;
use Jauntin\TwoFactorAuth\Enums\TwoFactorType;
use Jauntin\TwoFactorAuth\Models\TwoFactorUserProvider;

/**
 * @mixin User
 *
 * @property EloquentCollection<int,TwoFactorUserProvider> $twoFactorProviders
 */
trait HasTwoFactor
{
    public function hasTwoFactor(?TwoFactorType $provider = null): bool
    {
        if (is_null($provider)) {
            return $this->twoFactorProviders->isNotEmpty();
        }

        return $this->twoFactorProviders->some(fn (TwoFactorUserProvider $userProvider) => $userProvider->provider === $provider);
    }

    /**
     * @param  TwoFactorType[]  $providers
     */
    public function addTwoFactor(array $providers): void
    {
        foreach ($providers as $provider) {
            $this->twoFactorProviders()->create([
                'user_id' => $this->getAuthIdentifier(),
                'provider' => $provider,
            ]);
        }
    }

    /**
     * @return EloquentCollection<int,TwoFactorUserProvider>
     */
    public function getTwoFactorProviders(): EloquentCollection
    {
        return $this->twoFactorProviders;
    }

    public function getDefaultProviderType(): ?TwoFactorType
    {
        $defaultProvider = config('two-factor-auth.defaults.provider');

        return $this->twoFactorProviders->where('provider', TwoFactorType::tryFrom($defaultProvider))->first()?->provider;
    }

    /**
     * @return HasMany<TwoFactorUserProvider>
     */
    public function twoFactorProviders(): HasMany
    {
        return $this->hasMany(TwoFactorUserProvider::class);
    }
}
