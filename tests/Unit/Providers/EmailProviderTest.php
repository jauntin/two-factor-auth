<?php

namespace Tests\Unit\Providers;

use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Mail;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorMailable;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorUserContract;
use Jauntin\TwoFactorAuth\Exception\ThrottledException;
use Jauntin\TwoFactorAuth\Notification\TwoFactorVerification;
use Jauntin\TwoFactorAuth\Providers\EmailProvider;
use Jauntin\TwoFactorAuth\VerificationCodeRepository;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;

class EmailProviderTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected function setUp(): void
    {
        parent::setUp();

        Mail::fake();
        $this->codes = Mockery::mock(VerificationCodeRepository::class);
        $this->provider = new EmailProvider($this->codes, new TwoFactorVerification);

        $this->user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $this->user->shouldReceive('getAuthIdentifier')->andReturn(1);
        $this->user->shouldReceive('getEmailForVerification')->andReturn('test@example.com');
    }

    public function test_send_verification_code_successfully()
    {
        $this->codes->expects('recentlyCreatedCode')->with($this->user)->andReturnFalse()->once();
        $this->codes->shouldReceive('create')->with($this->user)->andReturn('123456');

        $this->provider->sendVerificationCode($this->user);

        Mail::assertQueued(function (TwoFactorMailable $mailable) {
            return $mailable->to[0]['address'] === 'test@example.com';
        });
    }

    public function test_send_verification_code_with_throttle_exception()
    {
        $this->expectException(ThrottledException::class);
        $this->expectExceptionMessage('Too many verification code requests');

        $this->codes->shouldReceive('recentlyCreatedCode')->with($this->user)->andReturn(true);

        $this->provider->sendVerificationCode($this->user);
    }

    public function test_send_verification_code_with_callback()
    {
        $this->codes->shouldReceive('recentlyCreatedCode')->with($this->user)->andReturn(false);
        $this->codes->shouldReceive('create')->with($this->user)->andReturn('123456');

        $callback = function (User $user, string $verificationCode) {
            $this->assertSame($this->user, $user);
            $this->assertEquals('123456', $verificationCode);
        };
        $callback->bindTo($this);
        $this->provider->sendVerificationCode($this->user, $callback);

        Mail::assertNotQueued(TwoFactorMailable::class);
    }

    public function test_validate_verification_code_successfully()
    {
        $this->codes->shouldReceive('exists')->with($this->user, '123456')->andReturn(true);

        $isValid = $this->provider->validateVerificationCode($this->user, '123456');

        $this->assertTrue($isValid);
    }

    public function test_validate_verification_code_fails()
    {
        $this->codes->shouldReceive('exists')->with($this->user, 'wrong_code')->andReturn(false);

        $isValid = $this->provider->validateVerificationCode($this->user, 'wrong_code');

        $this->assertFalse($isValid);
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        Mockery::close();
    }
}
