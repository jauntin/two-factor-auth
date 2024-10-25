<?php

namespace Jauntin\TwoFactorAuth;

use Closure;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorUserContract;
use Jauntin\TwoFactorAuth\Enums\TwoFactorType;
use Jauntin\TwoFactorAuth\Exception\InvalidCredentialsException;
use Jauntin\TwoFactorAuth\Exception\InvalidProviderException;
use Jauntin\TwoFactorAuth\Exception\InvalidVerificationCodeException;
use Jauntin\TwoFactorAuth\Exception\ThrottledException;
use Jauntin\TwoFactorAuth\Providers\TwoFactorProviderContext;
use UnexpectedValueException;

class TwoFactorBroker
{
    public function __construct(
        private readonly VerificationCodeRepository $codes,
        private readonly UserProvider $users,
        private readonly TwoFactorProviderContext $providers,
    ) {}

    /**
     * @param  (User&TwoFactorUserContract)|array<string,string>  $user
     *
     * @throws InvalidCredentialsException|ThrottledException|InvalidProviderException
     */
    public function sendVerificationCode(
        (User&TwoFactorUserContract)|array $user,
        ?TwoFactorType $twoFactorType = null,
        ?Closure $callback = null,
    ): void {
        // If array was passed instead we will check to see if we found a user for given credentials array
        // and if we did not we will throw an exception
        if (is_array($user)) {
            $user = $this->getUser($user);

            if (is_null($user)) {
                throw new InvalidCredentialsException('Invalid user credentials');
            }
        }

        if ($twoFactorType && ! $user->hasTwoFactor($twoFactorType)) {
            throw new InvalidProviderException(sprintf('User has no "%s" two factor provider', $twoFactorType->value));
        }
        $twoFactorType = $twoFactorType ?? $user->getDefaultTwoFactorProvider();
        if (! $twoFactorType) {
            throw new InvalidProviderException('User has no two factor provider');
        }

        $this->providers->provider($twoFactorType)->sendVerificationCode($user, $callback);
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
     * Delete expired verification codes.
     */
    public function deleteExpiredVerificationCodes(): void
    {
        $this->codes->deleteExpired();
    }

    /**
     * Validate the given verification code
     *
     * @throws InvalidProviderException
     */
    public function validateVerificationCode(User&TwoFactorUserContract $user, string $verificationCode, ?TwoFactorType $twoFactorType = null): bool
    {
        $twoFactorType = $twoFactorType ?? $user->getDefaultTwoFactorProvider();

        if (! $twoFactorType) {
            throw new InvalidProviderException('User has no two factor provider');
        }

        return $this->providers->provider($twoFactorType)->validateVerificationCode($user, $verificationCode);
    }

    /**
     * Determine if the given user recently created a two factor verification code.
     */
    public function hasRecentlyCreatedCode(User&TwoFactorUserContract $user): bool
    {
        return $this->codes->recentlyCreatedCode($user);
    }

    /**
     * Determine if a verification code record exists for user and is not expired.
     */
    public function existsNotExpired(User&TwoFactorUserContract $user): bool
    {
        return $this->codes->existsNotExpired($user);
    }

    /**
     * Validate a password reset for the given credentials.
     *
     * @throws InvalidCredentialsException|InvalidVerificationCodeException|InvalidProviderException
     */
    public function validateVerificationRequest(Request $request): User&TwoFactorUserContract
    {
        $params = $request->validate([
            'credentials' => ['required', 'array'],
            'verificationCode' => ['required', 'string'],
            'provider' => ['nullable', Rule::enum(TwoFactorType::class)],
        ]);

        if (is_null($user = $this->getUser($params['credentials']))) {
            throw new InvalidCredentialsException('Invalid user credentials');
        }

        $twoFactorType = isset($params['provider']) ? TwoFactorType::from($params['provider']) : null;

        if (! $this->validateVerificationCode($user, $params['verificationCode'], $twoFactorType)) {
            throw new InvalidVerificationCodeException('Verification code invalid');
        }

        return $user;
    }
}
