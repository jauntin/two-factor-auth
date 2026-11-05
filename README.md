# Two-factor auth package

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
    'max_attempts' => 10, // wrong attempts allowed per code; the last one deletes it (values below 1 act as 1)
    'credential_keys' => ['email'], // credentials keys allowed to look up the user
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

To assign new two factor provider you can insert a new record inside `two_factor_user_providers` table, where
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
To verify two-factor code you can use `$twoFactorBroker->validateVerificationCode()` method
```php
$user = \Illuminate\Foundation\Auth\User::find(1);
$broker = app(\Jauntin\TwoFactorAuth\TwoFactorBroker::class);

$broker->validateVerificationCode($user, '123456');
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

Both methods will ensure that verification code is valid and not expired.

`credentials` accepts only the keys listed in `credential_keys`, with string values. Any other
key or value fails validation (HTTP 422). `getUser()` ignores keys outside the list.

Each wrong code counts as an attempt. The attempt that reaches `max_attempts` (default 10)
deletes the code; values below 1 act as 1. The right code doesn't reset the count, and the
caller still deletes the code after a successful check (see below). Once the code is deleted,
`existsNotExpired()` returns `false`, so the user has to start the login again.

### Deleting used code

After you verified the user by two-factor code you can delete the verification code code record from database

```php
$user = \Illuminate\Foundation\Auth\User::find(1);
$broker = app(\Jauntin\TwoFactorAuth\TwoFactorBroker::class);

$this->twoFactorBroker->deleteVerificationCode($user);
```

## Upgrading to 1.4.0

- A new package migration adds `attempts` to `two_factor_verification_codes`. It runs with the
  normal `php artisan migrate`.
- The new `max_attempts` and `credential_keys` settings take their package defaults; a published
  `two-factor-auth.php` doesn't need to change.
- After 10 wrong codes the code is deleted. A resend that requires `existsNotExpired()` then
  fails, and the user restarts the login.
- A verification request with a credential key other than `email` (or a non-string value) now
  gets HTTP 422, and `getUser()` ignores such keys.

## Development

Constraints a change has to respect. Consumers (gatherguard, gbli-events,
basicare-plus) require `^1.x`, so every minor release reaches them on their next
`composer update`.

### Compatibility

- Supported ranges: PHP `>=8.3 <8.4`, Laravel `^10 || ^11 || ^12`. CI also runs
  with `--prefer-lowest`, so code must work on the lowest allowed versions.
- Consumers publish `two-factor-auth.php`, and `mergeConfigFrom` merges only the
  top level. A new top-level key reaches them through the package default; a new
  key nested under `defaults` or `providers` is hidden by their published copy.
  Add new settings as top-level keys with defaults.
- New constructor parameters get defaults, so the service provider stays the only
  place that needs to know about them.

### Migrations

Package migrations load through `loadMigrationsFrom` and run in each consumer's
normal `migrate`, against live tables (in gatherguard, the Helm migration job).
Ship schema changes as a new additive migration, such as a new column with a
default. Released migrations never change.

### Verification codes

- Every random choice in code generation uses `random_int()` (CSPRNG).
- Codes are stored only as `Hasher` hashes. The plain code leaves the package only
  through the mailable or the caller's `$callback`.
- `two_factor_verification_codes` has no primary key. There is one row per
  `user_id`, because `create()` deletes the old row before inserting. Queries
  target rows by `user_id`.
- Wrong guesses are counted only in `VerificationCodeRepository::exists()`. A hash
  match never touches `attempts`. A row at the limit counts as absent for
  `exists()` and `existsNotExpired()`.
- Only `credential_keys`, with string values, reach
  `UserProvider::retrieveByCredentials()`.

### Tests

- Repository tests extend `Tests\DatabaseTestCase`: Orchestra Testbench with
  in-memory SQLite, `TwoFactorAuthServiceProvider` registered, package migrations
  run (same setup as `jauntin/saving-quote`'s `tests/SavingQuoteTestCase.php`).
- Don't mock Eloquent models with Mockery `alias:`/`overload:`. Those mocks
  replace the class for the whole PHP process and break every real-model test in
  the same run.
