<?php

namespace Tests;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Jauntin\TwoFactorAuth\TwoFactorAuthServiceProvider;
use Orchestra\Testbench\TestCase;

abstract class DatabaseTestCase extends TestCase
{
    use RefreshDatabase;

    protected function getPackageProviders($app): array
    {
        return [TwoFactorAuthServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('database.default', 'testbench');
        // No foreign_key_constraints key: SQLite leaves the users FK unenforced, so no users table is needed
        $app['config']->set('database.connections.testbench', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        $app['config']->set('hashing.bcrypt.rounds', 4);
    }
}
