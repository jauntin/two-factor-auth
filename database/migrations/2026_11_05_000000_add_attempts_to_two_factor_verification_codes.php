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
        Schema::table('two_factor_verification_codes', function (Blueprint $table) {
            $table->unsignedSmallInteger('attempts')->default(0);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('two_factor_verification_codes', function (Blueprint $table) {
            $table->dropColumn('attempts');
        });
    }
};
