<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // New semantic authority is always an explicit Owner-created grant.
        // It applies equally to human and permitted AI channels; OAuth client
        // authorization is independently enforced at the AI connection edge.
        Schema::create('wordpress_publish_group_grants', static function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->foreignUlid('target_group_id')->constrained('target_groups')->cascadeOnDelete();
            $table->timestamps();
            $table->unique(['user_id', 'target_group_id'], 'wp_publish_group_grant_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('wordpress_publish_group_grants');
    }
};
