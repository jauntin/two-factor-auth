<?php

namespace Tests\Fixtures;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorUserContract;
use Jauntin\TwoFactorAuth\Models\Traits\HasTwoFactor;

/**
 * A consumer app's user model, set up as README "Usage" describes.
 */
class User extends Authenticatable implements TwoFactorUserContract
{
    use HasTwoFactor;

    public $timestamps = false;

    protected $fillable = ['email'];
}
