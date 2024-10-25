<?php

namespace Jauntin\TwoFactorAuth\Providers;

use Jauntin\TwoFactorAuth\Contracts\TwoFactorMailable;
use Jauntin\TwoFactorAuth\Enums\TwoFactorType;
use Jauntin\TwoFactorAuth\Exception\InvalidProviderException;
use Jauntin\TwoFactorAuth\VerificationCodeRepository;

class TwoFactorProviderContext
{
    public function __construct(private readonly VerificationCodeRepository $codes, private readonly TwoFactorMailable $mailable) {}

    public function provider(TwoFactorType $type): TwoFactorProviderInterface
    {
        return match ($type) {
            TwoFactorType::EMAIL => new EmailProvider($this->codes, $this->mailable),
            default => throw new InvalidProviderException(sprintf('Two-factor provider "%s" is not supported.', $type->value)),
        };
    }
}
