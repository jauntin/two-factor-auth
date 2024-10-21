<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('two_factor_user_providers', function (Blueprint $table) {
            $table->foreignId('user_id');
            $table->string('provider');
            $table->primary(['user_id', 'provider']);
            $table->foreign('user_id')->references('id')->on('users');
        });

        Schema::create('two_factor_verification_codes', function (Blueprint $table) {
            $table->foreignId('user_id');
            $table->string('code')->unique();
            $table->timestamp('created_at');
            $table->foreign('user_id')->references('id')->on('users');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('two_factor_verification_codes');
        Schema::dropIfExists('two_factor_user_providers');
    }
};
