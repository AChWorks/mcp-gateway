<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->string('role', 32)->default('viewer');
            $table->string('site_scope_mode', 16)->default('selected');
            $table->boolean('access_enabled')->default(true);
        });

        Schema::create('user_permission_denials', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->string('permission', 96);
            $table->timestamps();

            $table->unique(['user_id', 'permission']);
        });

        Schema::create('user_site_access', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->foreignUlid('site_record_id')->constrained('sites')->cascadeOnDelete();
            $table->boolean('allowed')->default(true);
            $table->timestamps();

            $table->unique(['user_id', 'site_record_id']);
            $table->index(['user_id', 'allowed']);
        });

        Schema::create('user_site_permission_denials', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->foreignUlid('site_record_id')->constrained('sites')->cascadeOnDelete();
            $table->string('permission', 96);
            $table->timestamps();

            $table->unique(['user_id', 'site_record_id', 'permission'], 'user_site_permission_denials_unique');
            $table->index(['user_id', 'permission']);
        });

        DB::table('users')->update([
            'role' => 'administrator',
            'site_scope_mode' => 'all',
            'access_enabled' => true,
        ]);

        $firstUserId = DB::table('users')->orderBy('id')->value('id');
        if ($firstUserId !== null) {
            DB::table('users')
                ->where('id', $firstUserId)
                ->update([
                    'role' => 'owner',
                    'site_scope_mode' => 'all',
                    'access_enabled' => true,
                ]);
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('user_site_permission_denials');
        Schema::dropIfExists('user_site_access');
        Schema::dropIfExists('user_permission_denials');

        Schema::table('users', function (Blueprint $table): void {
            $table->dropColumn(['role', 'site_scope_mode', 'access_enabled']);
        });
    }
};
