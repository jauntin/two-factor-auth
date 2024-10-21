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
