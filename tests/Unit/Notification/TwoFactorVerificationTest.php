<?php

namespace Tests\Unit\Notification;

use Jauntin\TwoFactorAuth\Notification\TwoFactorVerification;
use Orchestra\Testbench\TestCase;

class TwoFactorVerificationTest extends TestCase
{
    public function test_default_mailable_renders_the_verification_code_without_a_view(): void
    {
        $mailable = (new TwoFactorVerification)->setVerificationCode('<123456>');

        $mailable->assertSeeInHtml('Your verification code: &lt;123456&gt;', false);
    }
}
