<?php

namespace Jauntin\TwoFactorAuth;

use Illuminate\Auth\CreatesUserProviders;
use Illuminate\Container\Container;
use Illuminate\Support\ServiceProvider;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorMailable;
use Jauntin\TwoFactorAuth\Providers\TwoFactorProviderContext;

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
        $this->registerTwoFactorProviderContext();
        $this->registerTwoFactorBroker();
    }

    private function registerVerificationCodeRepository(): void
    {
        $this->app->singleton(VerificationCodeRepository::class, function (Container $container) {
            $key = $container['config']['app.key'];
            if (str_starts_with($key, 'base64:')) {
                $key = base64_decode(substr($key, 7));
            }

            return new VerificationCodeRepository(
                $key,
                $container['config']['two-factor-auth.pattern'],
                $container['config']['two-factor-auth.expire'],
                $container['config']['two-factor-auth.throttle'],
            );
        });
    }

    private function registerTwoFactorProviderContext(): void
    {
        $this->app->bind(TwoFactorMailable::class, config('two-factor-auth.providers.email.mailable'));
        $this->app->singleton(TwoFactorProviderContext::class, function (Container $container) {
            return new TwoFactorProviderContext(
                $container->make(VerificationCodeRepository::class),
                $container->make(TwoFactorMailable::class),
            );
        });
    }

    private function registerTwoFactorBroker(): void
    {
        $this->app->singleton(TwoFactorBroker::class, function (Container $container) {
            $users = $this->createUserProvider('users');
            if (! $users) {
                throw new \InvalidArgumentException(
                    'Authentication user provider is not defined'
                );
            }

            return new TwoFactorBroker(
                $container->make(VerificationCodeRepository::class),
                $users,
                $container->make(TwoFactorProviderContext::class),
            );
        });
    }
}
