<?php

namespace Tests\Unit;

use Jauntin\TwoFactorAuth\Regexifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class RegexifierTest extends TestCase
{
    #[DataProvider('regularExpressions')]
    public function test_regexify(string $regex): void
    {
        $string = Regexifier::regexify($regex);
        $this->assertMatchesRegularExpression($regex, $string);
    }

    public static function regularExpressions(): array
    {
        return [
            //            '6 digits' => [
            //                'regex' => '/[0-9]{6}/',
            //            ],
            //            'any 6 digits token' => [
            //                'regex' => '/\d{6}/',
            //            ],
            //            'any 6 non-digit characters token' => [
            //                'regex' => '/\D{6}/',
            //            ],
            //            '6 lowercase letters' => [
            //                'regex' => '/[a-z]{6}/',
            //            ],
            //            '6 uppercase letters' => [
            //                'regex' => '/[A-Z]{6}/',
            //            ],
            //            'any 6 word characters token' => [
            //                'regex' => '/\w{6}/',
            //            ],
            'any 6 non-word characters token' => [
                'regex' => '/\W{6}/',
            ],
            //            '6 lowercase alphanumeric' => [
            //                'regex' => '/[a-z0-9]{6}/',
            //            ],
            //            '6 uppercase alphanumeric' => [
            //                'regex' => '/[A-Z0-9]{6}/',
            //            ],
            //            '3-10 any characters' => [
            //                'regex' => '/.{3,10}/',
            //            ],
            //            'regexify groups' => [
            //                'regex' => '/(12|34){1,2}/',
            //            ],
            //            'regexify backslash' => [
            //                'regex' => '/\\\/',
            //            ],
        ];
    }
}
