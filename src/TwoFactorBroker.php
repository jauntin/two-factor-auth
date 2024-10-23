<?php

namespace Jauntin\TwoFactorAuth;

use Closure;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorMailable;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorUserContract;
use Jauntin\TwoFactorAuth\Enums\TwoFactorType;
use Jauntin\TwoFactorAuth\Exception\InvalidCredentialsException;
use Jauntin\TwoFactorAuth\Exception\InvalidProviderException;
use Jauntin\TwoFactorAuth\Exception\InvalidVerificationCodeException;
use Jauntin\TwoFactorAuth\Exception\ThrottledException;
use UnexpectedValueException;

class TwoFactorBroker
{
    public function __construct(
        private readonly VerificationCodeRepository $codes,
        private readonly UserProvider $users,
        private readonly TwoFactorMailable $mailable,
    ) {}

    /**
     * @param  (User&TwoFactorUserContract)|array<string,string>  $user
     *
     * @throws InvalidCredentialsException|ThrottledException|InvalidProviderException
     */
    public function sendVerificationCode(
        (User&TwoFactorUserContract)|array $user,
        ?TwoFactorType $provider = null,
        ?Closure $callback = null,
    ): void {
        // If array was passed instead we will check to see if we found a user for given credentials array
        // and if we did not we will throw an exception
        if (! $user instanceof TwoFactorUserContract) {
            $user = $this->getUser($user);

            if (is_null($user)) {
                throw new InvalidCredentialsException('Invalid user credentials');
            }
        }

        if ($provider && ! $user->hasTwoFactor($provider)) {
            throw new InvalidProviderException('User has no two factor provider');
        }

        if ($this->codes->recentlyCreatedCode($user)) {
            throw new ThrottledException('Too many verification code requests');
        }

        $verificationCode = $this->codes->create($user);

        if ($callback) {
            $callback($user, $verificationCode);
        } else {
            $this->notifyUser($user, $verificationCode, $provider);
        }
    }

    /**
     * Get the user for the given credentials.
     *
     * @param  array<string,string>  $credentials
     */
    public function getUser(array $credentials): (User&TwoFactorUserContract)|null
    {
        $user = $this->users->retrieveByCredentials($credentials);

        if ($user && ! $user instanceof User && ! $user instanceof TwoFactorUserContract) {
            throw new UnexpectedValueException('User must implement TwoFactorUserContract interface.');
        }

        /** @var User&TwoFactorUserContract $user */
        return $user;
    }

    /**
     * Create a new verification code for the given user.
     */
    public function createVerificationCode(User&TwoFactorUserContract $user): string
    {
        return $this->codes->create($user);
    }

    /**
     * Delete verification codes for the given user.
     */
    public function deleteVerificationCode(User&TwoFactorUserContract $user): void
    {
        $this->codes->delete($user);
    }

    /**
     * Validate the given verification code
     */
    public function verificationCodeExists(User&TwoFactorUserContract $user, string $verificationCode): bool
    {
        return $this->codes->exists($user, $verificationCode);
    }

    /**
     * Validate a password reset for the given credentials.
     *
     * @throws InvalidCredentialsException|InvalidVerificationCodeException
     */
    public function validateVerificationRequest(Request $request): User&TwoFactorUserContract
    {
        $params = $request->validate([
            'credentials' => ['required', 'array'],
            'verificationCode' => ['required', 'string'],
        ]);
        if (is_null($user = $this->getUser($params['credentials']))) {
            throw new InvalidCredentialsException('Invalid user credentials');
        }

        if (! $this->codes->exists($user, $params['verificationCode'])) {
            throw new InvalidVerificationCodeException('Verification code invalid');
        }

        return $user;
    }

    /**
     * @throws InvalidProviderException
     */
    private function notifyUser(
        User&TwoFactorUserContract $user,
        string $verificationCode,
        TwoFactorType|string|null $provider = null,
    ): void {
        $provider = $provider ?? $user->getDefaultProviderType();
        if (is_string($provider)) {
            $provider = TwoFactorType::tryFrom($provider);
        }

        match ($provider) {
            TwoFactorType::EMAIL => Mail::to($user->getEmailForVerification())->queue($this->mailable->setVerificationCode($verificationCode)),
            default => throw new InvalidProviderException('Invalid two factor provider'),
        };
    }
}
