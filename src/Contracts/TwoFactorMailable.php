<?php

namespace Jauntin\TwoFactorAuth\Contracts;

use Illuminate\Contracts\Mail\Mailable;

interface TwoFactorMailable extends Mailable
{
    public function setVerificationCode(string $verificationCode): self;
}
