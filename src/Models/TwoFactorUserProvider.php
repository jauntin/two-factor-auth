<?php

/**
 * @file
 * Model of two_factor_verification_codes table
 */

namespace Jauntin\TwoFactorAuth\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Jauntin\TwoFactorAuth\Enums\TwoFactorType;

/**
 * App\TwoFactorUserProvider
 *
 * @property int $user_id
 * @property TwoFactorType $provider
 *
 * @method static Builder|TwoFactorVerificationCode factory()
 * @method static Builder|TwoFactorVerificationCode first()
 * @method static Builder|TwoFactorVerificationCode newModelQuery()
 * @method static Builder|TwoFactorVerificationCode newQuery()
 * @method static Builder|TwoFactorVerificationCode query()
 * @method static Builder|TwoFactorVerificationCode where($field, $value)
 */
class TwoFactorUserProvider extends Model
{
    public $incrementing = false;

    public $timestamps = false;

    protected $table = 'two_factor_user_providers';

    protected $fillable = ['user_id', 'provider'];

    protected $casts = [
        'provider' => TwoFactorType::class,
    ];
}
