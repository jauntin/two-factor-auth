<?php

namespace Tests\Unit\Providers;

use Jauntin\TwoFactorAuth\Contracts\TwoFactorMailable;
use Jauntin\TwoFactorAuth\Enums\TwoFactorType;
use Jauntin\TwoFactorAuth\Exception\InvalidProviderException;
use Jauntin\TwoFactorAuth\Providers\EmailProvider;
use Jauntin\TwoFactorAuth\Providers\TwoFactorProviderContext;
use Jauntin\TwoFactorAuth\VerificationCodeRepository;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;

class TwoFactorProviderContextTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected function setUp(): void
    {
        parent::setUp();

        $this->codes = Mockery::mock(VerificationCodeRepository::class);
        $this->mailable = Mockery::mock(TwoFactorMailable::class);

        $this->context = new TwoFactorProviderContext($this->codes, $this->mailable);
    }

    public function testProviderReturnsEmailProvider()
    {
        $provider = $this->context->provider(TwoFactorType::EMAIL);

        $this->assertInstanceOf(EmailProvider::class, $provider);
    }

    public function testProviderThrowsInvalidProviderException()
    {
        $this->expectException(InvalidProviderException::class);
        $this->expectExceptionMessage('Two-factor provider "sms" is not supported.');

        $this->context->provider(TwoFactorType::SMS);
    }
}
