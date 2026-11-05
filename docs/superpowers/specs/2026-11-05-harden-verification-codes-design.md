# Harden verification codes — design

Issue: jauntin/two-factor-auth#7. Release: `1.4.0`.
Origin: jauntin/gatherguard#1729 (subtask 4) and jauntin/gatherguard#1724 (finding F2).
Consumers: gatherguard (upgrades in the #1729 PR), gbli-events (jauntin/gbli-events#1180) and
basicare-plus (jauntin/basicare-plus#1185). All three require `^1.3.0`, so their next `composer update`
installs 1.4.0.

## Why

The package sends a Verification Code by email as the second factor of an admin login. Three defects
make it weaker than it has to be:

1. **Predictable codes.** `src/Regexifier.php` makes every random choice with `mt_rand()` and
   `array_rand()`. PHP documents both as unsuitable for cryptographic use. OWASP ASVS 5.0 6.5.3 (L2)
   requires a CSPRNG for authentication secrets.
2. **Unlimited guesses per code.** A wrong code leaves the code valid
   (`VerificationCodeRepository::exists()`). Only success or expiry (5 min) removes it. The only limit
   is whatever route throttle the consumer applies, and that limit is per IP.
3. **Every credential key reaches the user query.** `TwoFactorBroker::getUser()` passes the whole
   `credentials` array to `UserProvider::retrieveByCredentials()` (`src/TwoFactorBroker.php:65`,
   `:144`). An unknown key gives HTTP 500 (`QueryException`). A real column such as `id` becomes the
   lookup key. gatherguard works around it in its controller. gbli-events passes the raw request
   `credentials` (`gbli-events/backend/app/Http/Controllers/API/AuthController.php:159,175`).

## Goals

- Every random choice in code generation comes from `random_int()`.
- A code accepts at most 10 wrong attempts. The 10th wrong attempt deletes the code.
- Only allow-listed credential keys, with string values, reach the user query. Unknown keys in a
  verification request fail validation (HTTP 422), not with HTTP 500.
- gatherguard, gbli-events and basicare-plus upgrade from `^1.3.0` to `1.4.0` with no code change.

## Non-goals

- Binding verification to a login session, or a per-user failure limit across codes. Those are app
  concerns; gatherguard does both in #1729.
- Changing the code length, pattern, expiry (5 min), resend throttle (30 s), or email content.
- TOTP or any other provider.
- Removing the gatherguard controller workaround. That happens in the gatherguard #1729 PR.

## Anti-goals

- A consumer has to change code, config, or a published file to keep working after the upgrade.
- The user-visible flow changes for someone who types the right code within 10 tries.

## Constraints

- PHP `>=8.3 <8.4`; Laravel `^10 || ^11 || ^12` (`composer.json`). Keep both ranges.
- The service provider loads migrations straight from the package (`loadMigrationsFrom`,
  `TwoFactorAuthServiceProvider.php:21`). A new package migration runs in each consumer's normal
  `migrate`. In gatherguard that is the Helm migration job. The migration must be safe on a live
  table: add a column with a default, nothing else.
- `two_factor_verification_codes` has no primary key. Rows are keyed by `user_id`, and `create()`
  deletes the old row before it inserts a new one (`VerificationCodeRepository::create()`).
- Minor version bump: public method signatures stay compatible. New constructor parameters get
  defaults.

## Decisions

### 1. CSPRNG in `Regexifier`

Replace every `mt_rand()` and `array_rand()` in `src/Regexifier.php` with `random_int()`.
`randomElement` picks the key with `random_int(0, count - 1)` over `array_keys`. The others are
`randomLetter`, `randomDigit`, `randomDigitNotNull`, `randomCharacter`, and the `*` replacement at
line 111. Keep `Regexifier`'s pattern support, because the pattern is configurable. When done, no
`mt_rand` or `array_rand` remains in `src/`.

### 2. Failed-attempt limit per code

- New package migration: add `attempts` (unsigned small integer, default 0) to
  `two_factor_verification_codes`.
- New config key `max_attempts`, default `10`, in `config/config.php`. The service provider passes it
  to `VerificationCodeRepository` as a new constructor parameter, defaulting to 10.
- Counting lives in `VerificationCodeRepository::exists()`. Both `validateVerificationRequest()` and
  `validateVerificationCode()` reach it through `EmailProvider::validateVerificationCode()`, so both
  count.
  - No record or expired record: return `false`. Nothing is counted.
  - Record with `attempts >= max_attempts`: delete it, return `false`. This is the race guard.
  - Hash matches: return `true`. Don't touch `attempts`. The consumer deletes the code on success, as
    today.
  - Hash doesn't match: increment `attempts` atomically (query-builder `increment`). The table holds
    one row per user, because `create()` deletes first, so target the row by `user_id`. If the new value
    is `>= max_attempts`, delete the record. Return `false`.
- `existsNotExpired()` also ignores a row left at the limit, so a race can't leave a resendable dead
  code (my call).
- After deletion, `existsNotExpired()` returns `false`. A consumer that requires an unexpired code
  before resend (gatherguard does) sends the user back to the password step. gatherguard wants exactly
  this (#1729).

### 3. Credential key allow-list (#1724 F2)

- New config key `credential_keys`, default `['email']`.
- `validateVerificationRequest()` validates `credentials` as `array:<allowed keys>` with each value a
  required string. An unknown key or a non-string value gives a `ValidationException` (HTTP 422).
- `getUser(array $credentials)` keeps only the allowed keys with string values. If none remain, it
  returns `null`, and callers already turn `null` into `InvalidCredentialsException`. The same filter
  protects `sendVerificationCode()` when it gets an array.

### 4. Release

- Document `max_attempts` and `credential_keys` in `README.md`. Add an upgrade note for consumers:
  the migration runs on `migrate`, and after 10 wrong tries resend fails, so the user restarts login.
- Tag `1.4.0` after merge, the same way as the earlier tags.

## Tests

Extend the existing unit suites in `tests/Unit`:

- `RegexifierTest`: generated codes still match `[0-9]{6}` and the other patterns already tested.
- `VerificationCodeRepositoryTest`:
  - 9 wrong attempts and then the right code: accepted.
  - 10 wrong attempts: the record is gone, and the right code is rejected.
  - A new `create()` starts at 0 attempts.
  - An expired code doesn't count attempts.
- `TwoFactorBrokerTest`:
  - `validateVerificationRequest` with an unknown credential key, or an array value, throws
    `ValidationException`.
  - `getUser(['id' => 1])` returns `null`.
  - `getUser(['email' => …])` works as before.
- Migration: the `attempts` default is 0.
- Today no package test touches a database. `VerificationCodeRepositoryTest` mocks the model with
  Mockery `alias:`/`overload:`, and nothing registers the service provider. The new behavior needs a
  DB-backed testbench test case that registers the provider and runs the package migrations.
  - **Decided:** in-memory SQLite, as the sibling package `saving-quote` does
    (`tests/SavingQuoteTestCase.php`, same CI image). No MySQL service in package CI.
  - The real-MySQL rule applies to the consuming apps, and gatherguard's MySQL suite runs this
    migration on upgrade.
  - The alias mocks replace the model class for the whole PHP process, so they can't share a run with
    real-model tests. Rewrite them, or run them in a separate process or suite (builder's choice).
- `composer` checks the package already runs: phpstan, pint, tests.

## Left to the builder

- Migration file name and timestamp.
- Whether `TwoFactorBroker` gets the allowed keys through its constructor or reads config.
- How to cover the "delete at limit" step against concurrent wrong attempts beyond the race guard
  above (my call: the guard is enough at this scale).
- What a `max_attempts` below 1 means. Document the choice in the README.
