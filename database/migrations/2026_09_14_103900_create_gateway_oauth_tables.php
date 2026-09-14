<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oauth_authorizations', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('client_id', 255);
            $table->string('resource', 1024);
            $table->char('resource_hash', 64);
            $table->json('scopes');
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();

            $table->index(['client_id', 'user_id', 'resource_hash'], 'oauth_authorizations_lookup');
            $table->index('revoked_at');
        });

        Schema::create('oauth_auth_codes', function (Blueprint $table): void {
            $table->string('id', 128)->primary();
            $table->ulid('authorization_id');
            $table->string('client_id', 255);
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('resource', 1024);
            $table->json('scopes');
            $table->timestamp('expires_at');
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();

            $table->foreign('authorization_id')->references('id')->on('oauth_authorizations')->cascadeOnDelete();
            $table->index(['authorization_id', 'revoked_at']);
        });

        Schema::create('oauth_access_tokens', function (Blueprint $table): void {
            $table->string('id', 128)->primary();
            $table->ulid('authorization_id');
            $table->string('client_id', 255);
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('resource', 1024);
            $table->json('scopes');
            $table->timestamp('expires_at');
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();

            $table->foreign('authorization_id')->references('id')->on('oauth_authorizations')->cascadeOnDelete();
            $table->index(['authorization_id', 'revoked_at']);
        });

        Schema::create('oauth_refresh_tokens', function (Blueprint $table): void {
            $table->string('id', 128)->primary();
            $table->string('access_token_id', 128);
            $table->ulid('authorization_id');
            $table->string('client_id', 255);
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('resource', 1024);
            $table->timestamp('expires_at');
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();

            $table->foreign('access_token_id')->references('id')->on('oauth_access_tokens')->cascadeOnDelete();
            $table->foreign('authorization_id')->references('id')->on('oauth_authorizations')->cascadeOnDelete();
            $table->index(['authorization_id', 'revoked_at']);
        });

        Schema::create('oauth_client_assertions', function (Blueprint $table): void {
            $table->id();
            $table->string('client_id', 255);
            $table->char('jti_hash', 64);
            $table->timestamp('expires_at');
            $table->timestamps();

            $table->unique(['client_id', 'jti_hash'], 'oauth_client_assertions_unique');
            $table->index('expires_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_client_assertions');
        Schema::dropIfExists('oauth_refresh_tokens');
        Schema::dropIfExists('oauth_access_tokens');
        Schema::dropIfExists('oauth_auth_codes');
        Schema::dropIfExists('oauth_authorizations');
    }
};
