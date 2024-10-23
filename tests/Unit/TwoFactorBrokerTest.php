<?php

namespace Tests\Unit;

use Exception;
use Illuminate\Contracts\Auth\Authenticatable;
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
use Jauntin\TwoFactorAuth\TwoFactorBroker;
use Jauntin\TwoFactorAuth\VerificationCodeRepository;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use UnexpectedValueException;

class TwoFactorBrokerTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    public function testSendVerificationCodeSuccess()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('hasTwoFactor')->with(TwoFactorType::EMAIL)->andReturn(true);
        $user->shouldReceive('getDefaultProviderType')->andReturn(TwoFactorType::EMAIL);
        $user->shouldReceive('getEmailForVerification')->andReturn('user@example.com');

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('recentlyCreatedCode')->with($user)->andReturn(false);
        $codes->shouldReceive('create')->with($user)->andReturn('123456');

        $mailable = Mockery::mock(TwoFactorMailable::class);
        $mailable->shouldReceive('setVerificationCode')->with('123456')->andReturn($mailable);

        Mail::shouldReceive('to')->with('user@example.com')->andReturnSelf();
        Mail::shouldReceive('queue')->with($mailable)->once();

        $userProvider = Mockery::mock(UserProvider::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $mailable);

        $broker->sendVerificationCode($user, TwoFactorType::EMAIL);
    }

    public function testSendVerificationCodeSuccessWithCallback()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('hasTwoFactor')->with(TwoFactorType::EMAIL)->andReturn(true);
        $user->shouldReceive('getDefaultProviderType')->andReturn(TwoFactorType::EMAIL);
        $user->shouldReceive('getEmailForVerification')->andReturn('user@example.com');

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('recentlyCreatedCode')->with($user)->andReturn(false);
        $codes->shouldReceive('create')->with($user)->andReturn('123456');

        $mailable = Mockery::mock(TwoFactorMailable::class);
        $mailable->shouldReceive('setVerificationCode')->with('123456')->andReturn($mailable);

        $userProvider = Mockery::mock(UserProvider::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $mailable);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage(sprintf('Sending code %s for use %s', '123456', 'user@example.com'));

        $broker->sendVerificationCode($user, TwoFactorType::EMAIL, function ($user, $verificationCode) {
            throw new Exception(sprintf('Sending code %s for use %s', $verificationCode, $user->getEmailForVerification()));
        });
    }

    public function testSendVerificationCodeThrottledException()
    {
        $this->expectException(ThrottledException::class);

        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('hasTwoFactor')->with(TwoFactorType::EMAIL)->andReturn(true);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('recentlyCreatedCode')->with($user)->andReturn(true);

        $mailable = Mockery::mock(TwoFactorMailable::class);

        $userProvider = Mockery::mock(UserProvider::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $mailable);

        Mail::shouldReceive('to')->never();

        $broker->sendVerificationCode($user, TwoFactorType::EMAIL);
    }

    public function testSendVerificationCodeInvalidCredentialsException()
    {
        $this->expectException(InvalidCredentialsException::class);

        $credentials = ['email' => 'user@example.com'];

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturnNull();

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $mailable = Mockery::mock(TwoFactorMailable::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $mailable);

        Mail::shouldReceive('to')->never();

        $broker->sendVerificationCode($credentials, TwoFactorType::EMAIL);
    }

    public function testSendVerificationCodeInvalidProviderException()
    {
        $this->expectException(InvalidProviderException::class);

        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('hasTwoFactor')->with(TwoFactorType::SMS)->andReturn(false);

        $codes = Mockery::mock(VerificationCodeRepository::class);

        $mailable = Mockery::mock(TwoFactorMailable::class);

        $userProvider = Mockery::mock(UserProvider::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $mailable);

        Mail::shouldReceive('to')->never();

        $broker->sendVerificationCode($user, TwoFactorType::SMS);
    }

    public function testValidateVerificationRequestSuccess()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $credentials = ['email' => 'user@example.com'];
        $request = Request::create('/verify', 'POST', [
            'credentials' => $credentials,
            'verificationCode' => '123456',
        ]);
        $request::macro('validate', fn (array $rules, array $params = []) => array_merge($request->all(), $params));

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('exists')->with($user, '123456')->andReturn(true);

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn($user);

        $mailable = Mockery::mock(TwoFactorMailable::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $mailable);

        $result = $broker->validateVerificationRequest($request);

        $this->assertSame($user, $result);
    }

    public function testValidateVerificationRequestInvalidCredentialsException()
    {
        $this->expectException(InvalidCredentialsException::class);

        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $credentials = ['email' => 'user@example.com'];
        $request = Request::create('/verify', 'POST', [
            'credentials' => $credentials,
            'verificationCode' => '123456',
        ]);
        $request::macro('validate', fn (array $rules, array $params = []) => array_merge($request->all(), $params));

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn(null);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldNotReceive('exists');

        $mailable = Mockery::mock(TwoFactorMailable::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $mailable);

        $broker->validateVerificationRequest($request);
    }

    public function testValidateVerificationRequestInvalidVerificationCodeException()
    {
        $this->expectException(InvalidVerificationCodeException::class);

        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $credentials = ['email' => 'user@example.com'];
        $request = Request::create('/verify', 'POST', [
            'credentials' => $credentials,
            'verificationCode' => 'wrong_code',
        ]);
        $request::macro('validate', fn (array $rules, array $params = []) => array_merge($request->all(), $params));

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn($user);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('exists')->with($user, 'wrong_code')->andReturn(false);

        $mailable = Mockery::mock(TwoFactorMailable::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $mailable);

        $broker->validateVerificationRequest($request);
    }

    public function testCreateVerificationCodeSuccess()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('create')->with($user)->andReturn('123456');

        $mailable = Mockery::mock(TwoFactorMailable::class);
        $userProvider = Mockery::mock(UserProvider::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $mailable);

        $verificationCode = $broker->createVerificationCode($user);

        $this->assertEquals('123456', $verificationCode);
    }

    public function testCreateVerificationCodeFailure()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('create')->with($user)->andThrow(new Exception('Failed to create code'));

        $mailable = Mockery::mock(TwoFactorMailable::class);
        $userProvider = Mockery::mock(UserProvider::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $mailable);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Failed to create code');

        $broker->createVerificationCode($user);
    }

    public function testDeleteVerificationCodeSuccess()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('delete')->with($user)->once();

        $mailable = Mockery::mock(TwoFactorMailable::class);
        $userProvider = Mockery::mock(UserProvider::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $mailable);

        $broker->deleteVerificationCode($user);

        $this->assertTrue(true);  // Since no exception is expected, success implies it worked
    }

    public function testDeleteVerificationCodeFailure()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('delete')->with($user)->andThrow(new Exception('Failed to delete code'));

        $mailable = Mockery::mock(TwoFactorMailable::class);
        $userProvider = Mockery::mock(UserProvider::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $mailable);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Failed to delete code');

        $broker->deleteVerificationCode($user);
    }

    public function testVerificationCodeExistsSuccess()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('exists')->with($user, '123456')->andReturn(true);

        $mailable = Mockery::mock(TwoFactorMailable::class);
        $userProvider = Mockery::mock(UserProvider::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $mailable);

        $exists = $broker->verificationCodeExists($user, '123456');

        $this->assertTrue($exists);
    }

    public function testVerificationCodeDoesNotExist()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('exists')->with($user, 'wrong_code')->andReturn(false);

        $mailable = Mockery::mock(TwoFactorMailable::class);
        $userProvider = Mockery::mock(UserProvider::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $mailable);

        $exists = $broker->verificationCodeExists($user, 'wrong_code');

        $this->assertFalse($exists);
    }

    public function testGetUserThrowsExceptionForInvalidUser()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('User must implement TwoFactorUserContract interface.');

        $credentials = ['email' => 'user@example.com'];

        // Mock a user that implements only Authenticatable but not User or TwoFactorUserContract
        $invalidUser = Mockery::mock(Authenticatable::class);

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn($invalidUser);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $mailable = Mockery::mock(TwoFactorMailable::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $mailable);

        // Call the method that should throw the exception
        $broker->getUser($credentials);
    }

    public function testDeleteExpiredVerificationCodesSuccess()
    {
        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('deleteExpired')->once();

        $mailable = Mockery::mock(TwoFactorMailable::class);
        $userProvider = Mockery::mock(UserProvider::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $mailable);

        $broker->deleteExpiredVerificationCodes();

        $this->assertTrue(true);  // Ensure the method completes without throwing any exception
    }
}
