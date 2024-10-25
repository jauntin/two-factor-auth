<?php

namespace Jauntin\TwoFactorAuth\Providers;

use Closure;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Mail;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorMailable;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorUserContract;
use Jauntin\TwoFactorAuth\Exception\ThrottledException;
use Jauntin\TwoFactorAuth\VerificationCodeRepository;

class EmailProvider implements TwoFactorProviderInterface
{
    public function __construct(
        private readonly VerificationCodeRepository $codes,
        private readonly TwoFactorMailable $mailable,
    ) {}

    /**
     * @throws ThrottledException
     */
    public function sendVerificationCode(TwoFactorUserContract&User $user, ?Closure $callback = null): void
    {
        if ($this->codes->recentlyCreatedCode($user)) {
            throw new ThrottledException('Too many verification code requests');
        }

        $verificationCode = $this->codes->create($user);

        if ($callback) {
            $callback($user, $verificationCode);
        } else {
            $this->sendEmail($user, $verificationCode);
        }
    }

    public function validateVerificationCode(TwoFactorUserContract&User $user, string $verificationCode): bool
    {
        return $this->codes->exists($user, $verificationCode);
    }

    private function sendEmail(User&TwoFactorUserContract $user, string $verificationCode): void
    {
        Mail::to($user->getEmailForVerification())->queue($this->mailable->setVerificationCode($verificationCode));
    }
}
