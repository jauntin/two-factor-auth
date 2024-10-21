# Saving quote package

Send two factor verification codes for Jauntin projects

## Installation

Install using composer
    - Add this repository as a [vcs source](https://getcomposer.org/doc/05-repositories.md#vcs) using `"url": "https://github.com/jauntin/two-factor-auth"`
    - `composer require jauntin/two-factor-auth`

## Usage

To add two factor providers for users, send verification codes and verify them
the `User` model must implement `Jauntin\TwoFactorAuth\Contracts\TwoFactorUserContract` interface.
For convenience`Jauntin\TwoFactorAuth\Models\Traits\HasTwoFactor` trait is available for developers.

```php
<?php

namespace App;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorUserContract;
use Jauntin\TwoFactorAuth\Models\Traits\HasTwoFactor;

class User extends Authenticatable implements TwoFactorUserContract
{
  use HasTwoFactor;
}
```

### Available providers

All available providers should be added to `Jauntin\TwoFactorAuth\Enums\TwoFactorType` enum 
as well as their configurations to the`two-factor-auth.providers.{provider}`

For now only `Email` provider is available

### Updating configuration

Default package configuration is

```php
<?php

return [
    'defaults' => [
        'provider' => 'email', // default provider to use
    ],
    'expire' => 5, // code expiration time in minutes
    'throttle' => 30, // time in seconds before user can request another code
    'pattern' => '[0-9]{6}', // regex pattern of generated verification code
    'providers' => [
        'email' => [
            'mailable' => \Jauntin\TwoFactorAuth\Notification\TwoFactorVerification::class, // Class name of the mailable to send for verification
        ],
    ],
];
```

To update configuration you can run `php artisan vendor:publish` command and publish `Jauntin\TwoFactorAuth\TwoFactorAuthServiceProvider`


### Email provider

To send verification code via email you need to create `Mailable` class that implements `Jauntin\TwoFactorAuth\Contracts\TwoFactorMailable`
and update published config `two-factor-auth.php` for email provider

```php

namespace App\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Address;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorMailable as TwoFactorMailableContract;

class TwoFactorVerification extends Mailable implements TwoFactorMailableContract
{
    use Queueable;

    private string $verificationCode;

    public function envelope(): Envelope
    {
        return new Envelope(
            from: new Address(config('mail.from.address'), config('mail.from.name')),
            subject: 'Verification code',
        );
    }

    public function content(): Content
    {
        return new Content(
            view: 'emails.two-factor-verification',
            with: [
                'code' => $this->verificationCode,
            ]
        );
    }

    public function setVerificationCode(string $verificationCode): self
    {
        $this->verificationCode = $verificationCode;

        return $this;
    }
}
```

```php
<?php

return [
    'defaults' => [
        'provider' => 'email',
    ],
    'expire' => 5, // code expiration time in minutes
    'throttle' => 30, // time in seconds before user can request another code
    'pattern' => '[0-9]{6}', // regex pattern of generated verification code
    'providers' => [
        'email' => [
            'mailable' => \App\Notifications\TwoFactorVerification::class, // Class name of the mailable to send for verification
        ],
    ],
];
```

### Adding two factor provider to existing user

To assign new two factor provider you can insert a new record inside `two_factro_user_providers` table, where
- `user_id` is foreign key for `users.id` column
- `provider` is a string that represents `Jauntin\TwoFactorAuth\Enums\TwoFactorType`

```php
DB::table('two_factor_user_providers')->insert([
    'user_id' => $user->id,
    'provider' => TwoFactorType::EMAIL->value,
]);
```

Or you can use existing `User` model and `addTwoFactor(array $providers)` method
```php
$user = \Illuminate\Foundation\Auth\User::find(1);
$user->addTwoFactor([TwoFactorType::EMAIL]);
```

### Sending verification

Almost all operations with two-factor auth is done with `Jauntin\TwoFactorAuth\TwoFactorBroker`
To send verification code you should check whether the user has assigned two factor provider first:
```php
$user = \Illuminate\Foundation\Auth\User::find(1);
$broker = app(\Jauntin\TwoFactorAuth\TwoFactorBroker::class);

if ($user->hasTwoFactor($provider ?? null)) {
    $broker->sendVerificationCode($user, $provider ?? null);
}
```

### Verifying code

Almost all operations with two-factor auth is done with `Jauntin\TwoFactorAuth\TwoFactorBroker`
To verify two-factor code you can use `$twoFactorBroker->verificationCodeExists()` method
```php
$user = \Illuminate\Foundation\Auth\User::find(1);
$broker = app(\Jauntin\TwoFactorAuth\TwoFactorBroker::class);

$broker->verificationCodeExists($user, '123456');
```
Or you can use `$twoFactorBroker->validateVerificationRequest()` method to validate the request itself if its body is in given format
```json
{
  "credentials": {
    "email": "sysadmin@jauntin.com"
  },
  "verificationCode": "123456"
}
```

```php
class AuthController extends BaseController
{
    public function verifyCode($request) {
        $broker = app(\Jauntin\TwoFactorAuth\TwoFactorBroker::class);
        $user = $broker->validateVerificationRequest($request);
    }
}
```

Both methods will ensure that verification code is valid and not expired

### Deleting used code

After you verified the user by two-factor code you can delete the verification code code record from database

```php
$user = \Illuminate\Foundation\Auth\User::find(1);
$broker = app(\Jauntin\TwoFactorAuth\TwoFactorBroker::class);

$this->twoFactorBroker->deleteVerificationCode($user);
```
