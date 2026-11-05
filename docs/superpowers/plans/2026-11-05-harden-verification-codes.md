# Harden Verification Codes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Release `1.4.0` of `jauntin/two-factor-auth` with CSPRNG codes, a 10-wrong-attempt limit per code, and a credential-key allow-list, with no consumer change.

**Architecture:** `Regexifier` swaps every RNG call for `random_int()`. `VerificationCodeRepository::exists()` counts wrong guesses in a new `attempts` column and deletes the row at the limit. `TwoFactorBroker` gets an allow-list of credential keys, enforced in request validation and in `getUser()`. New settings are top-level config keys with defaults, passed in through constructor parameters with defaults.

**Tech Stack:** PHP 8.3, Laravel 10–12, Orchestra Testbench (in-memory SQLite), PHPUnit, Mockery, Pint, Larastan.

**Spec:** `docs/superpowers/specs/2026-11-05-harden-verification-codes-design.md`

## Global Constraints

- PHP `>=8.3 <8.4`; Laravel `^10 || ^11 || ^12`. Keep both ranges in `composer.json`. Local vendor is Laravel 10 / Testbench 8; CI runs Laravel 12 at `prefer-lowest` and `prefer-stable`.
- Minor release: public method signatures stay compatible; new constructor parameters get defaults.
- New settings are top-level config keys with defaults (`mergeConfigFrom` merges only the top level; all three consumers have a published `two-factor-auth.php` without the new keys).
- Migration: add a column with a default, nothing else. Released migrations never change.
- `two_factor_verification_codes` has no primary key; target rows by `user_id`.
- Unchanged: code length, pattern, `expire` (5 min), `throttle` (30 s), email content.
- Run every PHP command in the devcontainer. Below, `dx '<cmd>'` means
  `docker exec -w /workspace/two-factor-auth jauntin-devcontainer_devcontainer-app-1 sh -c '<cmd>'`.
- Done per task = `dx 'vendor/bin/pint && vendor/bin/phpstan && vendor/bin/phpunit'` green. No `@phpstan-ignore` or baseline additions.
- Commit subjects start with `[7] `. Don't push, open the PR, or tag `1.4.0` unless the user asks.

## Review Focus

1. **Wrong guesses against one user's code** must leave every other user's code and count alone (the increment and delete target `user_id`). → Task 2, `test_wrong_attempts_do_not_touch_another_users_code`.
2. **`max_attempts` below 1** (0 or negative in a consumer's config) must not reject the right code on the first try. Decision: values below 1 act as 1. → Task 2, `test_max_attempts_below_one_acts_as_one`.
3. **Non-string credential values passed straight to `getUser()`** (gbli-events' resend passes raw `credentials` input, so `email` can be an array) return `null` without a query, never HTTP 500. → Task 3, `test_get_user_drops_non_string_values`.
4. **List-shaped or integer credentials in a verify request** (`credentials: ["a@b.c"]`, `email: 1`) give `ValidationException` (422), not 500. → Task 3, data-provider rows in `test_validate_verification_request_rejects_bad_credentials`.
5. **Custom code patterns** (README lets consumers set any `pattern`) still generate matching codes after the RNG swap. Only `\W{6}` is tested today. The 11 commented-out cases are re-enabled in Task 1; 10 of them were checked and pass.

---

### Task 1: CSPRNG in `Regexifier`

**Files:**
- Modify: `src/Regexifier.php` (helpers at lines 69–113, `*` replacement inside `asciify`)
- Test: `tests/Unit/RegexifierTest.php`

**Interfaces:**
- Consumes: nothing.
- Produces: `Regexifier::regexify(string $regex = ''): string`, unchanged.

- [ ] **Step 1: Write the failing tests**

In `RegexifierTest`:
- Uncomment every case in `regularExpressions()`, including `'6 digits' => '/[0-9]{6}/'`. The 10 non-backslash cases were checked to pass 2000/2000 on today's code. `'regexify backslash'` was not checked: if it also fails on `main` before your change, re-comment it and say so in the commit body.
- Add the invariant test:

```php
public function test_code_generation_uses_only_random_int(): void
{
    $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(__DIR__.'/../../src', \FilesystemIterator::SKIP_DOTS));
    foreach ($files as $file) {
        $this->assertDoesNotMatchRegularExpression(
            '/\b(mt_rand|array_rand|rand|shuffle|str_shuffle|lcg_value|uniqid)\s*\(/',
            file_get_contents($file->getPathname()),
            $file->getPathname(),
        );
    }
}
```

- [ ] **Step 2: Run to verify the invariant fails and the patterns pass**

Run: `dx 'vendor/bin/phpunit --filter RegexifierTest'`
Expected: `test_code_generation_uses_only_random_int` FAILS on `src/Regexifier.php`; every active `test_regexify` case passes.

- [ ] **Step 3: Replace every RNG call in `src/Regexifier.php` with `random_int()`**

- `randomElement(array $elements): mixed` — `$keys = array_keys($elements); return $elements[$keys[random_int(0, count($keys) - 1)]];`
- `randomLetter`, `randomDigit`, `randomDigitNotNull`, `asciify`: `mt_rand(a, b)` → `random_int(a, b)`, same bounds.
- `randomCharacter`: `random_int` for the four ranges, and pick from `$arr` through `self::randomElement($arr)`.

- [ ] **Step 4: Run the gate**

Run: `dx 'vendor/bin/pint && vendor/bin/phpstan && vendor/bin/phpunit'`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add src/Regexifier.php tests/Unit/RegexifierTest.php
git commit -m "[7] Generate verification codes with random_int"
```

---

### Task 2: Failed-attempt limit per code

**Files:**
- Create: `database/migrations/2026_11_05_000000_add_attempts_to_two_factor_verification_codes.php`
- Create: `tests/DatabaseTestCase.php`
- Modify: `config/config.php`, `src/Models/TwoFactorVerificationCode.php`, `src/VerificationCodeRepository.php`, `src/TwoFactorAuthServiceProvider.php:38-46`
- Rewrite: `tests/Unit/VerificationCodeRepositoryTest.php` (DB-backed; drops all `alias:`/`overload:` mocks)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces:
  - `VerificationCodeRepository::__construct(Hasher $hasher, string $pattern, int $expire = 5, int $throttle = 30, int $maxAttempts = 10)` — consumers' tests call it positionally with two args (`gbli-events/backend/tests/Feature/Http/Controllers/API/AuthControllerTest.php:280`, `basicare-plus/…/AuthControllerTest.php:362`), so the default is required.
  - `abstract class Tests\DatabaseTestCase extends Orchestra\Testbench\TestCase` — Task 3 doesn't need it, but any later DB test does.
  - Config key `two-factor-auth.max_attempts` (int, default `10`).

- [ ] **Step 1: Add the DB test case**

`tests/DatabaseTestCase.php`, modelled on `../saving-quote/tests/SavingQuoteTestCase.php`:
- `use RefreshDatabase;` (runs the package migrations, which the provider registers via `loadMigrationsFrom`).
- `getPackageProviders()` → `[TwoFactorAuthServiceProvider::class]`.
- `getEnvironmentSetUp($app)`: `database.default` = `testbench`; `database.connections.testbench` = `['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']`; `hashing.bcrypt.rounds` = `4` (10-guess tests run bcrypt `check` 10×).
- Omit `foreign_key_constraints` from the connection: SQLite then doesn't enforce the `users` FK, and tests need no `users` table.

- [ ] **Step 2: Rewrite `VerificationCodeRepositoryTest` as DB-backed, with the new tests**

Extends `Tests\DatabaseTestCase`. Helpers: `user(int $id = 1)` returns `Mockery::mock(User::class, TwoFactorUserContract::class)` with `getAuthIdentifier` → `$id`; `codes()` returns `$this->app->make(VerificationCodeRepository::class)` (covers the provider wiring); `row(int $userId = 1): ?TwoFactorVerificationCode`. Wrong guess = `'wrong'`.

Port the existing behaviour (no mocks of the model):
- `test_create_stores_only_a_hash_of_a_code_matching_the_pattern` — code matches `/^[0-9]{6}$/`; `row()->code !== $code`; `Hash::check($code, row()->code)`.
- `test_recently_created_code` — true right after `create()`; false after `$this->travel(31)->seconds()`.
- `test_exists_not_expired` — true after `create()`; false after `$this->travel(6)->minutes()`.
- `test_delete_expired_verification_codes` — user 1 created, travel 6 min, user 2 created, `deleteExpired()`: `row(1)` null, `row(2)` not null.
- `test_delete` — `row()` null after `delete()`.
- `test_generate_verification_code` — matches `/^[0-9]{6}$/`.

New (spec + Review Focus 1, 2):

```php
public function test_create_starts_at_zero_attempts(): void
{
    $user = $this->user();
    $this->codes()->create($user);
    $this->assertSame(0, $this->row()->attempts);            // migration default
    for ($i = 0; $i < 3; $i++) { $this->codes()->exists($user, 'wrong'); }
    $this->codes()->create($user);
    $this->assertSame(0, $this->row()->attempts);
}

public function test_right_code_is_accepted_after_nine_wrong_attempts(): void
{
    // 9 × assertFalse(exists($user, 'wrong')); then assertTrue(exists($user, $code)); row()->attempts === 9
}

public function test_tenth_wrong_attempt_deletes_the_code(): void
{
    // 10 × assertFalse(exists($user, 'wrong')); row() === null;
    // assertFalse(exists($user, $code)); assertFalse(existsNotExpired($user))
}

public function test_expired_code_does_not_count_attempts(): void
{
    // create; travel(6)->minutes(); assertFalse(exists($user, 'wrong')); row()->attempts === 0
}

public function test_code_left_at_the_limit_is_rejected_and_deleted(): void
{
    // create; TwoFactorVerificationCode::where('user_id', 1)->update(['attempts' => 10]);
    // assertFalse(existsNotExpired($user)); assertFalse(exists($user, $code)); row() === null
}

public function test_wrong_attempts_do_not_touch_another_users_code(): void
{
    // create for user 1 and user 2; 10 wrong on user 1;
    // row(1) === null; row(2)->attempts === 0; assertTrue(exists(user(2), $code2))
}

public function test_max_attempts_below_one_acts_as_one(): void
{
    $codes = new VerificationCodeRepository($this->app->make(Hasher::class), '[0-9]{6}', maxAttempts: 0);
    // $code = $codes->create($user); assertTrue($codes->exists($user, $code));
    // assertFalse($codes->exists($user, 'wrong')); row() === null
}
```

- [ ] **Step 3: Run to verify the new tests fail**

Run: `dx 'vendor/bin/phpunit --filter VerificationCodeRepositoryTest'`
Expected: ported tests PASS; new tests FAIL (no `attempts` column / no limit).

- [ ] **Step 4: Implement**

- Migration: `Schema::table('two_factor_verification_codes', …)` → `$table->unsignedSmallInteger('attempts')->default(0);` `down()` drops the column.
- Model: `@property int $attempts`; add `'attempts' => 'integer'` to `$casts`.
- `config/config.php`: top-level `'max_attempts' => 10, // wrong attempts allowed per code; the last one deletes it (values below 1 act as 1)`.
- Service provider: pass `$container['config']['two-factor-auth.max_attempts']` as the 5th argument.
- Repository: new constructor param `int $maxAttempts = 10`; the effective limit is `max(1, $maxAttempts)`.
  - `exists()`, in this order: no record or expired → `false` (no count). `attempts >= limit` → `delete($user)`, `false`. Hash matches → `true`, `attempts` untouched. Otherwise `TwoFactorVerificationCode::where('user_id', $id)->increment('attempts')`, then `->where('user_id', $id)->where('attempts', '>=', $limit)->delete()`, return `false`. (Delete-by-condition after the atomic increment, so no re-read is needed.)
  - `existsNotExpired()`: add `->where('attempts', '<', $limit)`.
  - Comment at the guard: concurrent wrong guesses that all read before the first delete can each still be checked; accepted at this scale (spec, "Left to the builder").

- [ ] **Step 5: Run the gate**

Run: `dx 'vendor/bin/pint && vendor/bin/phpstan && vendor/bin/phpunit'`
Expected: all green. `grep -rn "alias:\|overload:" tests` prints nothing.

- [ ] **Step 6: Commit**

```bash
git add database/migrations config/config.php src tests
git commit -m "[7] Delete a verification code after 10 wrong attempts"
```

---

### Task 3: Credential key allow-list

**Files:**
- Modify: `src/TwoFactorBroker.php` (constructor; `getUser()` at :65; `validateVerificationRequest()` at :140), `src/TwoFactorAuthServiceProvider.php:59-73`, `config/config.php`
- Test: `tests/Unit/TwoFactorBrokerTest.php`

**Interfaces:**
- Consumes: nothing from Tasks 1–2.
- Produces:
  - `TwoFactorBroker::__construct(VerificationCodeRepository $codes, UserProvider $users, TwoFactorProviderContext $providers, array $credentialKeys = ['email'])`, `$credentialKeys` typed `list<string>`. Constructor, not a config read, so tests build it without config.
  - `getUser(array $credentials): (User&TwoFactorUserContract)|null` — signature unchanged; docblock widens to `array<array-key,mixed>`.
  - Config key `two-factor-auth.credential_keys` (default `['email']`).

- [ ] **Step 1: Write the failing tests**

Existing tests keep passing unchanged (they use `['email' => …]`). Add:

```php
#[DataProvider('badCredentials')]
public function test_validate_verification_request_rejects_bad_credentials(array $credentials): void
{
    $this->expectException(ValidationException::class);
    $request = Request::create('/verify', 'POST', ['credentials' => $credentials, 'verificationCode' => '123456']);
    // no validate macro: real validation
    $users = Mockery::mock(UserProvider::class);
    $users->shouldNotReceive('retrieveByCredentials');
    (new TwoFactorBroker(Mockery::mock(VerificationCodeRepository::class), $users, Mockery::mock(TwoFactorProviderContext::class)))
        ->validateVerificationRequest($request);
}

public static function badCredentials(): array
{
    return [
        'unknown key' => [['email' => 'user@example.com', 'id' => '1']],
        'only an unknown key' => [['id' => '1']],
        'array value' => [['email' => ['user@example.com']]],
        'integer value' => [['email' => 1]],
        'list' => [['user@example.com']],
    ];
}
```

- `test_get_user_ignores_keys_outside_the_allow_list` — `getUser(['id' => 1])` is `null`; `retrieveByCredentials` never called.
- `test_get_user_passes_only_allowed_string_credentials` — `getUser(['email' => 'user@example.com', 'id' => '1'])` calls `retrieveByCredentials` `->with(['email' => 'user@example.com'])` once and returns that user.
- `test_get_user_drops_non_string_values` — `getUser(['email' => ['user@example.com']])` is `null`; `retrieveByCredentials` never called.
- `test_send_verification_code_with_disallowed_credentials_throws_invalid_credentials` — `sendVerificationCode(['id' => 1])` throws `InvalidCredentialsException`; no `retrieveByCredentials`.
- `test_credential_keys_are_configurable` — broker built with `credentialKeys: ['username']`: `getUser(['username' => 'bob', 'email' => 'x'])` calls `retrieveByCredentials` with `['username' => 'bob']`.

- [ ] **Step 2: Run to verify they fail**

Run: `dx 'vendor/bin/phpunit --filter TwoFactorBrokerTest'`
Expected: new tests FAIL (no `ValidationException`; `retrieveByCredentials` receives extra keys).

- [ ] **Step 3: Implement**

- `config/config.php`: top-level `'credential_keys' => ['email'], // credentials keys allowed to look up the user`.
- Service provider: pass `$container['config']['two-factor-auth.credential_keys']` as the 4th argument.
- `validateVerificationRequest()` rules: `'credentials' => ['required', 'array:'.implode(',', $this->credentialKeys)]`, `'credentials.*' => ['required', 'string']`.
- `getUser()`: keep `Arr::only($credentials, $this->credentialKeys)` entries that are strings; empty → return `null` before calling the provider.

- [ ] **Step 4: Run the gate**

Run: `dx 'vendor/bin/pint && vendor/bin/phpstan && vendor/bin/phpunit'`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add config/config.php src tests
git commit -m "[7] Look users up only by allow-listed credential keys"
```

---

### Task 4: Docs, upgrade note, spec removal

**Files:**
- Modify: `README.md` (`### Updating configuration` :39-59, `### Verifying code` :163-193, `## Development` :206+)
- Delete: `docs/superpowers/specs/2026-11-05-harden-verification-codes-design.md`, this plan

**Interfaces:**
- Consumes: config keys `max_attempts`, `credential_keys` (Tasks 2, 3); limit semantics from Task 2 Step 4.
- Produces: nothing.

- [ ] **Step 1: Update `README.md`**

- Config block: add `max_attempts` and `credential_keys`, same comments as `config/config.php`.
- `### Verifying code`: replace the nonexistent `verificationCodeExists()` with `validateVerificationCode($user, $code)`. State: each wrong code counts; the 10th (`max_attempts`) deletes the code; values below 1 act as 1; the right code doesn't reset the count, and the caller still deletes the code on success; a deleted code makes `existsNotExpired()` false. `credentials` accepts only `credential_keys`, string values; anything else is a 422.
- New `### Upgrading to 1.4.0` (before `## Development`): the `attempts` migration runs on the normal `migrate`; the new keys need no publish (package defaults); after 10 wrong tries resend gated on `existsNotExpired()` fails and the user restarts login; requests with credential keys other than `email` now get 422, and `getUser()` ignores them.
- `## Development` → `### Verification codes`: add "Wrong guesses are counted only in `VerificationCodeRepository::exists()`; a hash match never touches `attempts`; a row at the limit counts as absent for `exists()` and `existsNotExpired()`." and "Only `credential_keys`, string values, reach `UserProvider::retrieveByCredentials()`."
- `## Development` → `### Tests`: replace the `overload:`/`alias:` bullet with: repository tests use `Tests\DatabaseTestCase` (real model, in-memory SQLite); don't mock Eloquent models with `alias:`/`overload:`, since those replace the class for the whole PHP process.

- [ ] **Step 2: Remove the spec and plan**

```bash
git rm docs/superpowers/specs/2026-11-05-harden-verification-codes-design.md docs/superpowers/plans/2026-11-05-harden-verification-codes.md
```

(Check first that every spec constraint still in force sits in README or a code comment.)

- [ ] **Step 3: Full gate from clean install**

Run: `dx 'composer install && vendor/bin/pint && vendor/bin/phpstan && vendor/bin/phpunit'`
Expected: all green; `grep -rnE "mt_rand|array_rand" src` prints nothing.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "[7] Document 1.4.0 hardening and drop the spec"
```

- [ ] **Step 5: `/security-review`** (AGENTS.md: code generation, storage, validation changed). Fix findings in new commits, rerun Step 3.

- [ ] **Step 6: Draft the PR body** (don't open it unless asked). Name the call sites: gatherguard `backend/app/Http/Controllers/API/AuthController.php:140-167` (keeps working; its email-only workaround becomes redundant, removed in gatherguard #1729); gbli-events `…/AuthController.php:159,175` (passes raw `credentials`: unknown keys now 422 on verify, ignored on resend); basicare-plus `…/AuthController.php:160-187` (unchanged behaviour). Consumer tests constructing `VerificationCodeRepository` with two args (gbli-events `AuthControllerTest.php:280`, basicare-plus `AuthControllerTest.php:362`) are unaffected by the defaulted 5th param.
