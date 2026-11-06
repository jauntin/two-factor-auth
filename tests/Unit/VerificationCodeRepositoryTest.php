<?php

namespace Tests\Unit;

use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Hash;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorUserContract;
use Jauntin\TwoFactorAuth\Models\TwoFactorVerificationCode;
use Jauntin\TwoFactorAuth\VerificationCodeRepository;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Tests\DatabaseTestCase;

class VerificationCodeRepositoryTest extends DatabaseTestCase
{
    use MockeryPHPUnitIntegration;

    private function user(int $id = 1): User&TwoFactorUserContract
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('getAuthIdentifier')->andReturn($id);

        return $user;
    }

    private function codes(): VerificationCodeRepository
    {
        return $this->app->make(VerificationCodeRepository::class);
    }

    private function row(int $userId = 1): ?TwoFactorVerificationCode
    {
        return TwoFactorVerificationCode::where('user_id', $userId)->first();
    }

    private function guessWrong(User&TwoFactorUserContract $user, int $times): void
    {
        for ($i = 0; $i < $times; $i++) {
            $this->assertFalse($this->codes()->exists($user, 'wrong'));
        }
    }

    public function test_create_stores_only_a_hash_of_a_code_matching_the_pattern(): void
    {
        $code = $this->codes()->create($this->user());

        $this->assertMatchesRegularExpression('/^[0-9]{6}$/', $code);
        $this->assertNotSame($code, $this->row()->code);
        $this->assertTrue(Hash::check($code, $this->row()->code));
    }

    public function test_verification_code_exists(): void
    {
        $user = $this->user();
        $code = $this->codes()->create($user);

        $this->assertTrue($this->codes()->exists($user, $code));
    }

    public function test_verification_code_does_not_exist(): void
    {
        $this->assertFalse($this->codes()->exists($this->user(), '123456'));
    }

    public function test_recently_created_code(): void
    {
        $user = $this->user();
        $this->codes()->create($user);

        $this->assertTrue($this->codes()->recentlyCreatedCode($user));
        $this->travel(31)->seconds();
        $this->assertFalse($this->codes()->recentlyCreatedCode($user));
    }

    public function test_exists_not_expired(): void
    {
        $user = $this->user();
        $this->codes()->create($user);

        $this->assertTrue($this->codes()->existsNotExpired($user));
        $this->travel(6)->minutes();
        $this->assertFalse($this->codes()->existsNotExpired($user));
    }

    public function test_delete_expired_verification_codes(): void
    {
        $this->codes()->create($this->user(1));
        $this->travel(6)->minutes();
        $this->codes()->create($this->user(2));

        $this->codes()->deleteExpired();

        $this->assertNull($this->row(1));
        $this->assertNotNull($this->row(2));
    }

    public function test_delete(): void
    {
        $user = $this->user();
        $this->codes()->create($user);

        $this->codes()->delete($user);

        $this->assertNull($this->row());
    }

    public function test_generate_verification_code(): void
    {
        $this->assertMatchesRegularExpression('/^[0-9]{6}$/', $this->codes()->generateVerificationCode());
    }

    public function test_create_starts_at_zero_attempts(): void
    {
        $user = $this->user();
        $this->codes()->create($user);
        $this->assertSame(0, $this->row()->attempts);

        $this->guessWrong($user, 3);
        $this->codes()->create($user);

        $this->assertSame(0, $this->row()->attempts);
    }

    public function test_right_code_is_accepted_after_nine_wrong_attempts(): void
    {
        $user = $this->user();
        $code = $this->codes()->create($user);

        $this->guessWrong($user, 9);

        $this->assertTrue($this->codes()->exists($user, $code));
        $this->assertSame(9, $this->row()->attempts);
    }

    public function test_tenth_wrong_attempt_deletes_the_code(): void
    {
        $user = $this->user();
        $code = $this->codes()->create($user);

        $this->guessWrong($user, 10);

        $this->assertNull($this->row());
        $this->assertFalse($this->codes()->exists($user, $code));
        $this->assertFalse($this->codes()->existsNotExpired($user));
    }

    public function test_expired_code_does_not_count_attempts(): void
    {
        $user = $this->user();
        $this->codes()->create($user);
        $this->travel(6)->minutes();

        $this->guessWrong($user, 1);

        $this->assertSame(0, $this->row()->attempts);
    }

    public function test_code_left_at_the_limit_is_rejected_and_deleted(): void
    {
        $user = $this->user();
        $code = $this->codes()->create($user);
        TwoFactorVerificationCode::where('user_id', 1)->update(['attempts' => 10]);

        $this->assertFalse($this->codes()->existsNotExpired($user));
        $this->assertFalse($this->codes()->exists($user, $code));
        $this->assertNull($this->row());
    }

    public function test_wrong_attempts_do_not_touch_another_users_code(): void
    {
        $this->codes()->create($this->user(1));
        $code2 = $this->codes()->create($this->user(2));

        $this->guessWrong($this->user(1), 10);

        $this->assertNull($this->row(1));
        $this->assertSame(0, $this->row(2)->attempts);
        $this->assertTrue($this->codes()->exists($this->user(2), $code2));
    }

    public function test_max_attempts_below_one_acts_as_one(): void
    {
        $codes = new VerificationCodeRepository($this->app->make(Hasher::class), '[0-9]{6}', maxAttempts: 0);
        $user = $this->user();
        $code = $codes->create($user);

        $this->assertTrue($codes->exists($user, $code));
        $this->assertFalse($codes->exists($user, 'wrong'));
        $this->assertNull($this->row());
    }
}
