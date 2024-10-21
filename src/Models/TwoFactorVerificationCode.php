<?php

/**
 * @file
 * Model of two_factor_verification_codes table
 */

namespace Jauntin\TwoFactorAuth\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Carbon;

/**
 * App\TwoFactorVerificationCode
 *
 * @property int $user_id
 * @property string $provider
 * @property string $code
 * @property Carbon $created_at
 * @property-read User|null $user
 *
 * @method static Builder|TwoFactorVerificationCode factory()
 * @method static Builder|TwoFactorVerificationCode first()
 * @method static Builder|TwoFactorVerificationCode newModelQuery()
 * @method static Builder|TwoFactorVerificationCode newQuery()
 * @method static Builder|TwoFactorVerificationCode query()
 * @method static Builder|TwoFactorVerificationCode whereUserId($value)
 * @method static Builder|TwoFactorVerificationCode whereProvider($value)
 * @method static Builder|TwoFactorVerificationCode whereCode($value)
 */
class TwoFactorVerificationCode extends Model
{
    public $incrementing = false;

    public $timestamps = false;

    protected $table = 'two_factor_verification_codes';

    /** @var array<string, string> */
    protected $casts = [
        'created_at' => 'datetime',
    ];

    /**
     * @return BelongsTo<User,self>
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class, 'user_id', 'id');
    }
}
