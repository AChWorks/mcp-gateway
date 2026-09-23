<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('site_groups', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('name', 160)->unique();
            $table->timestamps();
        });

        Schema::create('site_group_sites', function (Blueprint $table): void {
            $table->id();
            $table->foreignUlid('site_group_id')->constrained('site_groups')->cascadeOnDelete();
            $table->foreignUlid('site_record_id')->constrained('sites')->cascadeOnDelete();
            $table->timestamps();

            $table->unique(['site_group_id', 'site_record_id']);
            $table->index(['site_record_id', 'site_group_id']);
        });

        Schema::create('site_group_users', function (Blueprint $table): void {
            $table->id();
            $table->foreignUlid('site_group_id')->constrained('site_groups')->cascadeOnDelete();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->timestamps();

            $table->unique(['site_group_id', 'user_id']);
            $table->index(['user_id', 'site_group_id']);
        });

        Schema::create('site_group_permission_denials', function (Blueprint $table): void {
            $table->id();
            $table->foreignUlid('site_group_id')->constrained('site_groups')->cascadeOnDelete();
            $table->string('permission', 96);
            $table->timestamps();

            $table->unique(['site_group_id', 'permission']);
            $table->index(['permission', 'site_group_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('site_group_permission_denials');
        Schema::dropIfExists('site_group_users');
        Schema::dropIfExists('site_group_sites');
        Schema::dropIfExists('site_groups');
    }
};
