<?php

namespace Tests\Unit;

use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Carbon;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorUserContract;
use Jauntin\TwoFactorAuth\Models\TwoFactorVerificationCode;
use Jauntin\TwoFactorAuth\VerificationCodeRepository;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;

class VerificationCodeRepositoryTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    public function testCreateVerificationCodeSuccess()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('getAuthIdentifier')->andReturn(1);

        // Mock the TwoFactorVerificationCode model to avoid database calls
        $twoFactorCode = Mockery::mock('overload:'.TwoFactorVerificationCode::class);
        $twoFactorCode->shouldReceive('save')->once();

        // Mock deleteExisting to ensure it's called
        $repository = Mockery::mock(VerificationCodeRepository::class, ['test_hash_key', '^[0-9]{6}$', 5, 30])->makePartial();
        $repository->shouldAllowMockingProtectedMethods();
        $repository->shouldReceive('delete')->with($user)->once();

        // Mock generateVerificationCode
        $repository->shouldReceive('generateVerificationCode')->andReturn('123456');

        $verificationCode = $repository->create($user);

        $this->assertEquals('123456', $verificationCode);
    }

    public function testVerificationCodeExistsSuccess()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('getAuthIdentifier')->andReturn(1);

        $twoFactorCode = Mockery::mock('alias:Jauntin\TwoFactorAuth\Models\TwoFactorVerificationCode');
        $twoFactorCode->created_at = Carbon::now()->subMinute();
        $twoFactorCode->code = hash_hmac('sha256', '123456', 'test_hash_key');
        $twoFactorCode->shouldReceive('where')
            ->with('user_id', 1)
            ->andReturnSelf();
        $twoFactorCode->shouldReceive('first')
            ->once()
            ->andReturnSelf();

        $repository = new VerificationCodeRepository('test_hash_key', '^[0-9]{6}$');

        $exists = $repository->exists($user, '123456');

        $this->assertTrue($exists);
    }

    public function testVerificationCodeDoesNotExist()
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

        $repository = new VerificationCodeRepository('test_hash_key', '^[0-9]{6}$');

        $exists = $repository->exists($user, '123456');

        $this->assertFalse($exists);
    }

    public function testRecentlyCreatedCodeSuccess()
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

        $repository = new VerificationCodeRepository('test_hash_key', '^[0-9]{6}$', 5, 30);

        $recentlyCreated = $repository->recentlyCreatedCode($user);

        $this->assertTrue($recentlyCreated);
    }

    public function testDeleteExpiredVerificationCodesSuccess()
    {
        $twoFactorCode = Mockery::mock('alias:Jauntin\TwoFactorAuth\Models\TwoFactorVerificationCode');
        $twoFactorCode->shouldReceive('where')
            ->with('created_at', '<', Mockery::type(Carbon::class))
            ->andReturnSelf();
        $twoFactorCode->shouldReceive('delete')
            ->once()
            ->andReturnTrue();

        $repository = new VerificationCodeRepository('test_hash_key', '^[0-9]{6}$', 5, 30);

        $repository->deleteExpired();

        $this->assertTrue(true);  // If no exceptions occur, the test is successful
    }

    public function testDeleteSuccess()
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

        $repository = new VerificationCodeRepository('test_hash_key', '^[0-9]{6}$');
        $deleted = $repository->delete($user);

        $this->assertEquals(1, $deleted);
    }

    public function testGenerateVerificationCode()
    {
        $repository = new VerificationCodeRepository('test_hash_key', '^[0-9]{6}$');

        $verificationCode = $repository->generateVerificationCode();

        $this->assertMatchesRegularExpression('/^[0-9]{6}$/', $verificationCode);
    }
}
