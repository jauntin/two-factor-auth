<?php

namespace Jauntin\TwoFactorAuth;

use Illuminate\Auth\CreatesUserProviders;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\ServiceProvider;

/**
 * @codeCoverageIgnore
 */
final class TwoFactorAuthServiceProvider extends ServiceProvider
{
    use CreatesUserProviders;

    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        $this->publishes([
            __DIR__.'/../config/config.php' => config_path('two-factor-auth.php'),
        ]);
    }

    /**
     * Register the application services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/config.php', 'two-factor-auth');
        $this->registerVerificationCodeRepository();
        $this->registerTwoFactorBroker();
    }

    private function registerVerificationCodeRepository(): void
    {
        $this->app->singleton(VerificationCodeRepository::class, function () {
            $key = config('app.key');
            if (str_starts_with($key, 'base64:')) {
                $key = base64_decode(substr($key, 7));
            }

            return new VerificationCodeRepository(
                $key,
                config('two-factor-auth.pattern'),
                config('two-factor-auth.expire'),
                config('two-factor-auth.throttle'),
            );
        });
    }

    private function registerTwoFactorBroker(): void
    {
        $this->app->singleton(TwoFactorBroker::class, function () {
            $users = $this->createUserProvider('users');
            if (! $users) {
                throw new \InvalidArgumentException(
                    'Authentication user provider is not defined'
                );
            }
            /** @var UserProvider $users */
            $mailableClass = config('two-factor-auth.providers.email.mailable');

            if (! $mailableClass || ! class_exists($mailableClass)) {
                throw new \InvalidArgumentException(
                    'Mailable for email provider is not defined'
                );
            }

            return new TwoFactorBroker($this->app->make(VerificationCodeRepository::class), $users, $this->app->make($mailableClass));
        });
    }
}
