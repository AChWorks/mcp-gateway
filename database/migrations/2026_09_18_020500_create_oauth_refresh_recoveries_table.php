<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oauth_refresh_recoveries', function (Blueprint $table): void {
            $table->char('old_token_hash', 64)->primary();
            $table->string('old_refresh_token_id', 128);
            $table->string('successor_access_token_id', 128);
            $table->string('successor_refresh_token_id', 128);
            $table->ulid('authorization_id');
            $table->string('client_id', 255);
            $table->foreignId('user_id');
            $table->string('resource', 1024);
            $table->json('requested_scopes')->nullable();
            $table->longText('response_ciphertext');
            $table->unsignedBigInteger('rotation_staged_at_us');
            $table->timestamp('recovery_expires_at');
            $table->unsignedTinyInteger('uses_remaining')->default(1);
            $table->timestamps();

            $table->foreign('old_refresh_token_id', 'oauth_recovery_old_refresh_fk')
                ->references('id')->on('oauth_refresh_tokens')->cascadeOnDelete();
            $table->foreign('successor_access_token_id', 'oauth_recovery_access_fk')
                ->references('id')->on('oauth_access_tokens')->cascadeOnDelete();
            $table->foreign('successor_refresh_token_id', 'oauth_recovery_refresh_fk')
                ->references('id')->on('oauth_refresh_tokens')->cascadeOnDelete();
            $table->foreign('authorization_id', 'oauth_recovery_authorization_fk')
                ->references('id')->on('oauth_authorizations')->cascadeOnDelete();
            $table->foreign('user_id', 'oauth_recovery_user_fk')
                ->references('id')->on('users')->cascadeOnDelete();

            $table->index('recovery_expires_at', 'oauth_recovery_expiry_idx');
            $table->index(['authorization_id', 'created_at'], 'oauth_recovery_authorization_idx');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_refresh_recoveries');
    }
};
