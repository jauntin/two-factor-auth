<?php

namespace Jauntin\TwoFactorAuth;

use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Carbon;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorUserContract;
use Jauntin\TwoFactorAuth\Models\TwoFactorVerificationCode;

class VerificationCodeRepository
{
    public function __construct(
        private readonly Hasher $hasher,
        private readonly string $pattern,
        private readonly int $expire = 5,
        private readonly int $throttle = 30,
        private readonly int $maxAttempts = 10,
    ) {}

    /**
     * Create a new two factor verification code record.
     */
    public function create(User&TwoFactorUserContract $user): string
    {
        $this->delete($user);

        $verificationCode = $this->generateVerificationCode();

        $twoFactorCode = new TwoFactorVerificationCode;
        $twoFactorCode->user_id = $user->getAuthIdentifier();
        $twoFactorCode->code = $this->hasher->make($verificationCode);
        $twoFactorCode->created_at = new Carbon;
        $twoFactorCode->save();

        return $verificationCode;
    }

    /**
     * Determine if a verification code record exists and is valid.
     *
     * A wrong code counts as an attempt; the attempt that reaches the limit deletes the record.
     */
    public function exists(User&TwoFactorUserContract $user, string $code): bool
    {
        $userId = $user->getAuthIdentifier();
        $record = TwoFactorVerificationCode::where('user_id', $userId)->first();

        if (! $record || $this->codeExpired($record->created_at)) {
            return false;
        }

        // Race guard: a record left at the limit by concurrent wrong attempts is dead.
        // ponytail: wrong guesses that all read the record before the first delete are still each checked; fine at this scale
        if ($record->attempts >= $this->attemptLimit()) {
            $this->delete($user);

            return false;
        }

        if ($this->hasher->check($code, $record->code)) {
            return true;
        }

        TwoFactorVerificationCode::where('user_id', $userId)->increment('attempts');
        TwoFactorVerificationCode::where('user_id', $userId)
            ->where('attempts', '>=', $this->attemptLimit())
            ->delete();

        return false;
    }

    /**
     * Determine if a verification code record exists for user and is not expired.
     */
    public function existsNotExpired(User&TwoFactorUserContract $user): bool
    {
        $expiredAt = Carbon::now()->subMinutes($this->expire);

        return TwoFactorVerificationCode::where('user_id', $user->getAuthIdentifier())
            ->where('created_at', '>=', $expiredAt)
            ->where('attempts', '<', $this->attemptLimit())
            ->exists();
    }

    /**
     * Wrong attempts allowed per code. Values below 1 act as 1.
     */
    private function attemptLimit(): int
    {
        return max(1, $this->maxAttempts);
    }

    /**
     * Determine if the verification code has expired.
     */
    protected function codeExpired(Carbon $createdAt): bool
    {
        return $createdAt->addMinutes($this->expire)->isPast();
    }

    /**
     * Determine if the given user recently created a two factor verification code.
     */
    public function recentlyCreatedCode(User&TwoFactorUserContract $user): bool
    {
        $record = TwoFactorVerificationCode::where('user_id', $user->getAuthIdentifier())->first();

        return $record && $this->verificationCodeRecentlyCreated($record->created_at);
    }

    /**
     * Determine if the verification code record was recently created.
     */
    protected function verificationCodeRecentlyCreated(Carbon $createdAt): bool
    {
        if ($this->throttle <= 0) {
            return false;
        }

        return $createdAt->addSeconds($this->throttle)->isFuture();
    }

    /**
     * Delete a verification code record by user.
     */
    public function delete(User&TwoFactorUserContract $user): bool
    {
        return TwoFactorVerificationCode::where('user_id', $user->getAuthIdentifier())->delete();
    }

    /**
     * Delete expired verification codes.
     */
    public function deleteExpired(): void
    {
        $expiredAt = Carbon::now()->subMinutes($this->expire);

        TwoFactorVerificationCode::where('created_at', '<', $expiredAt)->delete();
    }

    /**
     * Generate a new verification code
     */
    public function generateVerificationCode(): string
    {
        return Regexifier::regexify($this->pattern);
    }
}
