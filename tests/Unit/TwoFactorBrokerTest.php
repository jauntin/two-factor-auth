<?php

namespace Tests\Unit;

use Exception;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorUserContract;
use Jauntin\TwoFactorAuth\Enums\TwoFactorType;
use Jauntin\TwoFactorAuth\Exception\InvalidCredentialsException;
use Jauntin\TwoFactorAuth\Exception\InvalidProviderException;
use Jauntin\TwoFactorAuth\Exception\InvalidVerificationCodeException;
use Jauntin\TwoFactorAuth\Exception\ThrottledException;
use Jauntin\TwoFactorAuth\Providers\TwoFactorProviderContext;
use Jauntin\TwoFactorAuth\Providers\TwoFactorProviderInterface;
use Jauntin\TwoFactorAuth\TwoFactorBroker;
use Jauntin\TwoFactorAuth\VerificationCodeRepository;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;
use UnexpectedValueException;

class TwoFactorBrokerTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    public function test_send_verification_code_success()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('hasTwoFactor')->with(TwoFactorType::EMAIL)->andReturn(true);
        $user->shouldReceive('getDefaultTwoFactorProvider')->andReturn(TwoFactorType::EMAIL);
        $user->shouldReceive('getEmailForVerification')->andReturn('user@example.com');

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('recentlyCreatedCode')->with($user)->andReturn(false);
        $codes->shouldReceive('create')->with($user)->andReturn('123456');

        $context = Mockery::mock(TwoFactorProviderContext::class, function (TwoFactorProviderContext&MockInterface $context) {
            $twoFactorProvider = Mockery::mock(TwoFactorProviderInterface::class);
            $twoFactorProvider->expects('sendVerificationCode')->with(Mockery::type(TwoFactorUserContract::class), null);
            $context->expects('provider')->andReturn($twoFactorProvider);
        });

        $userProvider = Mockery::mock(UserProvider::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        $broker->sendVerificationCode($user, TwoFactorType::EMAIL);
    }

    public function test_send_verification_code_success_with_callback()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('hasTwoFactor')->with(TwoFactorType::EMAIL)->andReturn(true);
        $user->shouldReceive('getDefaultTwoFactorProvider')->andReturn(TwoFactorType::EMAIL);
        $user->shouldReceive('getEmailForVerification')->andReturn('user@example.com');

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('recentlyCreatedCode')->with($user)->andReturn(false);
        $codes->shouldReceive('create')->with($user)->andReturn('123456');

        $context = Mockery::mock(TwoFactorProviderContext::class, function (TwoFactorProviderContext&MockInterface $context) {
            $twoFactorProvider = Mockery::mock(TwoFactorProviderInterface::class);
            $twoFactorProvider->expects('sendVerificationCode')->with(Mockery::type(TwoFactorUserContract::class), Mockery::type(\Closure::class));
            $context->expects('provider')->andReturn($twoFactorProvider);
        });

        $userProvider = Mockery::mock(UserProvider::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        $broker->sendVerificationCode($user, TwoFactorType::EMAIL, fn ($user) => $user);
    }

    public function test_send_verification_code_throttled_exception()
    {
        $this->expectException(ThrottledException::class);

        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('hasTwoFactor')->with(TwoFactorType::EMAIL)->andReturn(true);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('recentlyCreatedCode')->with($user)->andReturn(true);

        $context = Mockery::mock(TwoFactorProviderContext::class, function (TwoFactorProviderContext&MockInterface $context) {
            $twoFactorProvider = Mockery::mock(TwoFactorProviderInterface::class);
            $twoFactorProvider->shouldReceive('sendVerificationCode')
                ->with(Mockery::type(TwoFactorUserContract::class), null)
                ->andThrow(ThrottledException::class);
            $context->shouldReceive('provider')->andReturn($twoFactorProvider);
        });

        $userProvider = Mockery::mock(UserProvider::class);

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        $broker->sendVerificationCode($user, TwoFactorType::EMAIL);
    }

    public function test_send_verification_code_invalid_credentials_exception()
    {
        $this->expectException(InvalidCredentialsException::class);

        $credentials = ['email' => 'user@example.com'];

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturnNull();

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldNotReceive('recentlyCreatedCode');

        $context = Mockery::mock(TwoFactorProviderContext::class);
        $context->shouldNotReceive('provider');

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        $broker->sendVerificationCode($credentials, TwoFactorType::EMAIL);
    }

    public function test_send_verification_code_invalid_provider_exception()
    {
        $this->expectException(InvalidProviderException::class);

        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('hasTwoFactor')->with(TwoFactorType::SMS)->andReturn(false);

        $codes = Mockery::mock(VerificationCodeRepository::class);

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldNotReceive('retrieveByCredentials');

        $context = Mockery::mock(TwoFactorProviderContext::class);
        $context->shouldNotReceive('provider');

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        Mail::shouldReceive('to')->never();

        $broker->sendVerificationCode($user, TwoFactorType::SMS);
    }

    public function test_validate_verification_request_success()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->shouldReceive('getDefaultTwoFactorProvider')->andReturn(TwoFactorType::EMAIL);
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

        $context = Mockery::mock(TwoFactorProviderContext::class, function (TwoFactorProviderContext&MockInterface $context) {
            $twoFactorProvider = Mockery::mock(TwoFactorProviderInterface::class);
            $twoFactorProvider->expects('validateVerificationCode')
                ->with(Mockery::type(TwoFactorUserContract::class), '123456')
                ->andReturnTrue();
            $context->expects('provider')->andReturn($twoFactorProvider);
        });

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        $result = $broker->validateVerificationRequest($request);

        $this->assertSame($user, $result);
    }

    public function test_validate_verification_request_invalid_credentials_exception()
    {
        $this->expectException(InvalidCredentialsException::class);

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

        $context = Mockery::mock(TwoFactorProviderContext::class);
        $context->shouldNotReceive('provider');

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        $broker->validateVerificationRequest($request);
    }

    public function test_validate_verification_request_invalid_provider_exception()
    {
        $this->expectException(InvalidProviderException::class);
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->expects('getDefaultTwoFactorProvider')->andReturnNull();

        $credentials = ['email' => 'user@example.com'];
        $request = Request::create('/verify', 'POST', [
            'credentials' => $credentials,
            'verificationCode' => '123456',
        ]);
        $request::macro('validate', fn (array $rules, array $params = []) => array_merge($request->all(), $params));

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn($user);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldNotReceive('exists');

        $context = Mockery::mock(TwoFactorProviderContext::class);
        $context->shouldNotReceive('provider');

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        $broker->validateVerificationRequest($request);
    }

    public function test_validate_verification_request_invalid_verification_code_exception()
    {
        $this->expectException(InvalidVerificationCodeException::class);

        $user = Mockery::mock(User::class, TwoFactorUserContract::class);
        $user->expects('getDefaultTwoFactorProvider')->andReturn(TwoFactorType::EMAIL);
        $credentials = ['email' => 'user@example.com'];
        $request = Request::create('/verify', 'POST', [
            'credentials' => $credentials,
            'verificationCode' => 'wrong_code',
        ]);
        $request::macro('validate', fn (array $rules, array $params = []) => array_merge($request->all(), $params));

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn($user);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldNotReceive('exists');

        $context = Mockery::mock(TwoFactorProviderContext::class, function (TwoFactorProviderContext&MockInterface $context) {
            $twoFactorProvider = Mockery::mock(TwoFactorProviderInterface::class);
            $twoFactorProvider->expects('validateVerificationCode')
                ->with(Mockery::type(TwoFactorUserContract::class), 'wrong_code')
                ->andReturnFalse();
            $context->expects('provider')->andReturn($twoFactorProvider);
        });

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        $broker->validateVerificationRequest($request);
    }

    public function test_create_verification_code_success()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('create')->with($user)->andReturn('123456');

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldNotReceive('retrieveByCredentials');

        $context = Mockery::mock(TwoFactorProviderContext::class);
        $context->shouldNotReceive('provider');

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        $verificationCode = $broker->createVerificationCode($user);

        $this->assertEquals('123456', $verificationCode);
    }

    public function test_create_verification_code_failure()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('create')->with($user)->andThrow(new Exception('Failed to create code'));

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldNotReceive('retrieveByCredentials');

        $context = Mockery::mock(TwoFactorProviderContext::class);
        $context->shouldNotReceive('provider');

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Failed to create code');

        $broker->createVerificationCode($user);
    }

    public function test_delete_verification_code_success()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('delete')->with($user)->once();

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldNotReceive('retrieveByCredentials');

        $context = Mockery::mock(TwoFactorProviderContext::class);
        $context->shouldNotReceive('provider');

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        $broker->deleteVerificationCode($user);

        $this->assertTrue(true);  // Since no exception is expected, success implies it worked
    }

    public function test_delete_verification_code_failure()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('delete')->with($user)->andThrow(new Exception('Failed to delete code'));

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldNotReceive('retrieveByCredentials');

        $context = Mockery::mock(TwoFactorProviderContext::class);
        $context->shouldNotReceive('provider');

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Failed to delete code');

        $broker->deleteVerificationCode($user);
    }

    public function test_validate_verification_code_success()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('exists')->with($user, '123456')->andReturn(true);

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldNotReceive('retrieveByCredentials');

        $context = Mockery::mock(TwoFactorProviderContext::class);
        $context->expects('provider')->with(TwoFactorType::EMAIL)->andReturnUsing(function () use ($user) {
            $twoFactorProvider = Mockery::mock(TwoFactorProviderInterface::class);
            $twoFactorProvider->expects('validateVerificationCode')
                ->with($user, '123456')
                ->andReturnTrue();

            return $twoFactorProvider;
        });

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        $exists = $broker->validateVerificationCode($user, '123456', TwoFactorType::EMAIL);

        $this->assertTrue($exists);
    }

    public function test_validate_verification_code_failure()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldReceive('exists')->with($user, 'wrong_code')->andReturn(false);

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldNotReceive('retrieveByCredentials');

        $context = Mockery::mock(TwoFactorProviderContext::class);
        $context->expects('provider')->with(TwoFactorType::EMAIL)->andReturnUsing(function () use ($user) {
            $twoFactorProvider = Mockery::mock(TwoFactorProviderInterface::class);
            $twoFactorProvider->expects('validateVerificationCode')
                ->with($user, 'wrong_code')
                ->andReturnFalse();

            return $twoFactorProvider;
        });

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        $exists = $broker->validateVerificationCode($user, 'wrong_code', TwoFactorType::EMAIL);

        $this->assertFalse($exists);
    }

    public function test_get_user_throws_exception_for_invalid_user()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('User must implement TwoFactorUserContract interface.');

        $credentials = ['email' => 'user@example.com'];

        // Mock a user that implements only Authenticatable but not User or TwoFactorUserContract
        $invalidUser = Mockery::mock(Authenticatable::class);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->shouldNotReceive();

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn($invalidUser);

        $context = Mockery::mock(TwoFactorProviderContext::class);
        $context->shouldNotReceive('provider');

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        // Call the method that should throw the exception
        $broker->getUser($credentials);
    }

    public function test_delete_expired_verification_codes_success()
    {
        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->expects('deleteExpired')->once();

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldNotReceive('retrieveByCredentials');

        $context = Mockery::mock(TwoFactorProviderContext::class);
        $context->shouldNotReceive('provider');

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        $broker->deleteExpiredVerificationCodes();

        $this->assertTrue(true);  // Ensure the method completes without throwing any exception
    }

    public function test_has_recently_created_code()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->expects('recentlyCreatedCode')->with($user)->once()->andReturnTrue();

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldNotReceive('retrieveByCredentials');

        $context = Mockery::mock(TwoFactorProviderContext::class);
        $context->shouldNotReceive('provider');

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        $this->assertTrue($broker->hasRecentlyCreatedCode($user));
    }

    public function test_exists_not_expired()
    {
        $user = Mockery::mock(User::class, TwoFactorUserContract::class);

        $codes = Mockery::mock(VerificationCodeRepository::class);
        $codes->expects('existsNotExpired')->with($user)->once()->andReturnTrue();

        $userProvider = Mockery::mock(UserProvider::class);
        $userProvider->shouldNotReceive('retrieveByCredentials');

        $context = Mockery::mock(TwoFactorProviderContext::class);
        $context->shouldNotReceive('provider');

        $broker = new TwoFactorBroker($codes, $userProvider, $context);

        $this->assertTrue($broker->existsNotExpired($user));
    }
}
