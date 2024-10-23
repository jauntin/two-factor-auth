<?php

namespace Jauntin\TwoFactorAuth;

class Regexifier
{
    public static function regexify(string $regex = ''): string
    {
        // ditch the anchors
        $regex = preg_replace('/^\/?\^?/', '', $regex);
        $regex = preg_replace('/\$?\/?$/', '', (string) $regex);
        // All {2} become {2,2}
        $regex = preg_replace('/\{(\d+)\}/', '{\1,\1}', (string) $regex);
        // Single-letter quantifiers (?, *, +) become bracket quantifiers ({0,1}, {0,rand}, {1, rand})
        $regex = preg_replace('/(?<!\\\)\?/', '{0,1}', (string) $regex);
        $regex = preg_replace('/(?<!\\\)\*/', '{0,'.self::randomDigitNotNull().'}', (string) $regex);
        $regex = preg_replace('/(?<!\\\)\+/', '{1,'.self::randomDigitNotNull().'}', (string) $regex);
        // [12]{1,2} becomes [12] or [12][12]
        $regex = preg_replace_callback('/(\[[^\]]+\])\{(\d+),(\d+)\}/', static function ($matches) {
            return str_repeat($matches[1], self::randomElement(range($matches[2], $matches[3])));
        }, (string) $regex);
        // (12|34){1,2} becomes (12|34) or (12|34)(12|34)
        $regex = preg_replace_callback('/(\([^\)]+\))\{(\d+),(\d+)\}/', static function ($matches) {
            return str_repeat($matches[1], self::randomElement(range($matches[2], $matches[3])));
        }, (string) $regex);
        // A{1,2} becomes A or AA or \d{3} becomes \d\d\d
        $regex = preg_replace_callback('/(\\\?.)\{(\d+),(\d+)\}/', static function ($matches) {
            return str_repeat($matches[1], self::randomElement(range($matches[2], $matches[3])));
        }, (string) $regex);
        // (this|that) becomes 'this' or 'that'
        $regex = preg_replace_callback('/\((.*?)\)/', static function ($matches) {
            return self::randomElement(explode('|', str_replace(['(', ')'], '', $matches[1])));
        }, (string) $regex);
        // All A-F inside [] become ABCDEF
        $regex = preg_replace_callback('/\[([^\]]+)\]/', static function ($matches) {
            return '['.preg_replace_callback('/(\w|\d)\-(\w|\d)/', static function ($range) {
                return implode('', range($range[1], $range[2]));
            }, $matches[1]).']';
        }, (string) $regex);
        // All [ABC] become B (or A or C)
        $regex = preg_replace_callback('/\[([^\]]+)\]/', static function ($matches) {
            // remove backslashes (that are not followed by another backslash) because they are escape characters
            $match = (string) preg_replace('/\\\(?!\\\)/', '', $matches[1]);
            $randomElement = self::randomElement(str_split($match));

            //[.] should not be a random character, but a literal .
            return str_replace('.', '\.', $randomElement);
        }, (string) $regex);
        // replace \d with number, \w and \D with letter, \W with special character and . with ascii
        $regex = preg_replace_callback('/\\\w/', [self::class, 'randomLetter'], (string) $regex);
        $regex = preg_replace_callback('/\\\W/', [self::class, 'randomCharacter'], (string) $regex);
        $regex = preg_replace_callback('/\\\d/', [self::class, 'randomDigit'], (string) $regex);
        $regex = preg_replace_callback('/\\\D/', [self::class, 'randomLetter'], (string) $regex);
        //replace . with ascii except backslash
        $regex = preg_replace_callback('/(?<!\\\)\./', static function () {
            $chr = self::asciify('*');

            if ($chr === '\\') {
                $chr .= '\\';
            }

            return $chr;
        }, (string) $regex);
        // remove remaining single backslashes and escaped dots
        $regex = str_replace('\\\\', '[:escaped_backslash:]', (string) $regex);
        $regex = str_replace('\\', '', $regex);
        $regex = str_replace('[:escaped_backslash:]', '\\', $regex);

        return str_replace('[:escaped_dot:]', '.', (string) $regex);
    }

    /**
     * @param  mixed[]  $elements
     */
    private static function randomElement(array $elements): mixed
    {
        return $elements[array_rand($elements)];
    }

    private static function randomLetter(): string
    {
        return chr(mt_rand(97, 122));
    }

    private static function randomDigit(): int
    {
        return mt_rand(0, 9);
    }

    private static function randomCharacter(): string
    {
        $arr = [mt_rand(33, 47), mt_rand(58, 64), mt_rand(91, 94), 96, mt_rand(123, 126)];
        $chr = chr($arr[array_rand($arr)]);
        if ($chr === '\\') {
            return '[:escaped_backslash:]';
        }
        if ($chr === '.') {
            return '[:escaped_dot:]';
        }

        return $chr;
    }

    private static function randomDigitNotNull(): int
    {
        return mt_rand(1, 9);
    }

    private static function asciify(string $string = '****'): string
    {
        return (string) preg_replace('/\*/u', chr(mt_rand(33, 126)), $string);
    }
}
