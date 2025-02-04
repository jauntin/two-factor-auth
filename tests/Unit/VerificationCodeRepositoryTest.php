<?php

namespace Tests\Unit;

use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorUserContract;
use Jauntin\TwoFactorAuth\Models\TwoFactorVerificationCode;
use Jauntin\TwoFactorAuth\VerificationCodeRepository;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;

class VerificationCodeRepositoryTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    public function test_create_verification_code_success()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('getAuthIdentifier')->andReturn(1);

        // Mock the TwoFactorVerificationCode model to avoid database calls
        $twoFactorCode = Mockery::mock('overload:'.TwoFactorVerificationCode::class);
        $twoFactorCode->shouldReceive('save')->once();
        $hasher = Mockery::mock(Hasher::class);
        $hasher->shouldReceive('make')->with('123456')->andReturn(Str::random());

        // Mock deleteExisting to ensure it's called
        $repository = Mockery::mock(VerificationCodeRepository::class, [$hasher, '^[0-9]{6}$', 5, 30])->makePartial();
        $repository->shouldAllowMockingProtectedMethods();
        $repository->shouldReceive('delete')->with($user)->once();

        // Mock generateVerificationCode
        $repository->shouldReceive('generateVerificationCode')->andReturn('123456');

        $verificationCode = $repository->create($user);

        $this->assertEquals('123456', $verificationCode);
    }

    public function test_verification_code_exists_success()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('getAuthIdentifier')->andReturn(1);

        $twoFactorCode = Mockery::mock('alias:Jauntin\TwoFactorAuth\Models\TwoFactorVerificationCode');
        $twoFactorCode->created_at = Carbon::now()->subMinute();
        $twoFactorCode->code = $code = Str::random();
        $twoFactorCode->shouldReceive('where')
            ->with('user_id', 1)
            ->andReturnSelf();
        $twoFactorCode->shouldReceive('first')
            ->once()
            ->andReturnSelf();
        $hasher = Mockery::mock(Hasher::class);
        $hasher->shouldReceive('check')->with('123456', $code)->andReturnTrue();

        $repository = new VerificationCodeRepository($hasher, '^[0-9]{6}$');

        $exists = $repository->exists($user, '123456');

        $this->assertTrue($exists);
    }

    public function test_verification_code_does_not_exist()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('getAuthIdentifier')->andReturn(1);

        $twoFactorCode = Mockery::mock('alias:Jauntin\TwoFactorAuth\Models\TwoFactorVerificationCode');
        $twoFactorCode->shouldReceive('where')
            ->with('user_id', 1)
            ->andReturnSelf();
        $twoFactorCode->shouldReceive('first')
            ->once()
            ->andReturnNull();
        $hasher = Mockery::mock(Hasher::class);
        $hasher->shouldNotReceive('check');

        $repository = new VerificationCodeRepository($hasher, '^[0-9]{6}$');

        $exists = $repository->exists($user, '123456');

        $this->assertFalse($exists);
    }

    public function test_recently_created_code_success()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('getAuthIdentifier')->andReturn(1);

        $twoFactorCode = Mockery::mock('alias:Jauntin\TwoFactorAuth\Models\TwoFactorVerificationCode');
        $twoFactorCode->created_at = Carbon::now()->subSeconds(10);
        $twoFactorCode->code = hash_hmac('sha256', '123456', 'test_hash_key');
        $twoFactorCode->shouldReceive('where')
            ->with('user_id', 1)
            ->andReturnSelf();
        $twoFactorCode->shouldReceive('first')
            ->once()
            ->andReturnSelf();
        $hasher = Mockery::mock(Hasher::class);
        $hasher->shouldNotReceive('check');

        $repository = new VerificationCodeRepository($hasher, '^[0-9]{6}$', 5, 30);

        $recentlyCreated = $repository->recentlyCreatedCode($user);

        $this->assertTrue($recentlyCreated);
    }

    public function test_exists_not_expired()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('getAuthIdentifier')->andReturn(1);

        $twoFactorCode = Mockery::mock('alias:Jauntin\TwoFactorAuth\Models\TwoFactorVerificationCode');
        $twoFactorCode->created_at = Carbon::now()->subSeconds(10);
        $twoFactorCode->code = hash_hmac('sha256', '123456', 'test_hash_key');
        $twoFactorCode->shouldReceive('where')
            ->with('user_id', 1)
            ->andReturnSelf();
        $twoFactorCode->shouldReceive('where')
            ->with('created_at', '>=', Mockery::type(Carbon::class))
            ->andReturnSelf();
        $twoFactorCode->shouldReceive('exists')
            ->once()
            ->andReturnTrue();
        $hasher = Mockery::mock(Hasher::class);
        $hasher->shouldNotReceive('check');

        $repository = new VerificationCodeRepository($hasher, '^[0-9]{6}$', 5, 30);

        $existsNotExpired = $repository->existsNotExpired($user);

        $this->assertTrue($existsNotExpired);
    }

    public function test_delete_expired_verification_codes_success()
    {
        $twoFactorCode = Mockery::mock('alias:Jauntin\TwoFactorAuth\Models\TwoFactorVerificationCode');
        $twoFactorCode->shouldReceive('where')
            ->with('created_at', '<', Mockery::type(Carbon::class))
            ->andReturnSelf();
        $twoFactorCode->shouldReceive('delete')
            ->once()
            ->andReturnTrue();
        $hasher = Mockery::mock(Hasher::class);
        $hasher->shouldNotReceive('check');

        $repository = new VerificationCodeRepository($hasher, '^[0-9]{6}$', 5, 30);

        $repository->deleteExpired();

        $this->assertTrue(true);  // If no exceptions occur, the test is successful
    }

    public function test_delete_success()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('getAuthIdentifier')->andReturn(1);

        $twoFactorCode = Mockery::mock('alias:Jauntin\TwoFactorAuth\Models\TwoFactorVerificationCode');
        $twoFactorCode->shouldReceive('where')
            ->with('user_id', 1)
            ->andReturnSelf();
        $twoFactorCode->shouldReceive('delete')
            ->once()
            ->andReturnTrue();
        $hasher = Mockery::mock(Hasher::class);
        $hasher->shouldNotReceive('check');

        $repository = new VerificationCodeRepository($hasher, '^[0-9]{6}$');
        $deleted = $repository->delete($user);

        $this->assertEquals(1, $deleted);
    }

    public function test_generate_verification_code()
    {
        $hasher = Mockery::mock(Hasher::class);
        $hasher->shouldNotReceive('check');
        $repository = new VerificationCodeRepository($hasher, '^[0-9]{6}$');

        $verificationCode = $repository->generateVerificationCode();

        $this->assertMatchesRegularExpression('/^[0-9]{6}$/', $verificationCode);
    }
}
