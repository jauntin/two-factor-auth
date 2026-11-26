<?php

namespace Tests\Unit;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Schema;
use Jauntin\TwoFactorAuth\Enums\TwoFactorType;
use Jauntin\TwoFactorAuth\Notification\TwoFactorVerification;
use Jauntin\TwoFactorAuth\TwoFactorBroker;
use Tests\DatabaseTestCase;
use Tests\Fixtures\User;

/**
 * The login flow the consumer apps run, on the real framework: the broker comes from the
 * container (service provider, CreatesUserProviders, Eloquent user provider) and the user
 * is an Eloquent model using HasTwoFactor. Keep it free of mocks, so each Laravel and PHP
 * version in the CI matrix runs the package's framework integration.
 */
class LoginFlowTest extends DatabaseTestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);
        $app['config']->set('auth.providers.users', ['driver' => 'eloquent', 'model' => User::class]);
    }

    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('email');
        });
    }

    public function test_container_broker_sends_and_verifies_a_code_for_an_eloquent_user(): void
    {
        Mail::fake();
        $user = User::create(['email' => 'admin@example.com']);
        $user->addTwoFactor([TwoFactorType::EMAIL]);
        $broker = $this->app->make(TwoFactorBroker::class);

        $this->assertTrue($user->hasTwoFactor());
        $broker->sendVerificationCode($user);

        $code = '';
        Mail::assertQueued(TwoFactorVerification::class, function (TwoFactorVerification $mail) use (&$code) {
            preg_match('/\d{6}/', $mail->render(), $matches);
            $code = $matches[0] ?? '';

            return $mail->hasTo('admin@example.com');
        });
        $this->assertTrue($broker->existsNotExpired($user));

        $request = Request::create('/verify', 'POST', [
            'credentials' => ['email' => 'admin@example.com'],
            'verificationCode' => $code,
        ]);
        $this->assertTrue($broker->validateVerificationRequest($request)->is($user));

        $broker->deleteVerificationCode($user);
        $this->assertFalse($broker->existsNotExpired($user));
    }
}
