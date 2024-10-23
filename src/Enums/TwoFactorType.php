<?php

namespace Jauntin\TwoFactorAuth\Enums;

enum TwoFactorType: string
{
    case EMAIL = 'email';
    case SMS = 'sms';
}
