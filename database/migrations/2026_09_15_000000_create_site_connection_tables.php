<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('sites', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('site_id', 64)->unique();
            $table->string('display_name', 160);
            $table->string('base_url', 1024);
            $table->char('base_url_hash', 64)->unique();
            $table->string('connector_type', 64)->default('wp_ai_bridge');
            $table->string('mcp_resource_url', 1024);
            $table->string('oauth_issuer_url', 1024);
            $table->string('oauth_authorization_url', 1024);
            $table->string('oauth_token_url', 1024);
            $table->string('oauth_revocation_url', 1024);
            $table->string('connection_state', 32)->default('disconnected');
            $table->string('last_error_code', 64)->nullable();
            $table->timestamp('last_tested_at')->nullable();
            $table->timestamp('connected_at')->nullable();
            $table->timestamps();

            $table->index(['connector_type', 'connection_state']);
        });

        Schema::create('site_credentials', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignUlid('site_record_id')->unique()->constrained('sites')->cascadeOnDelete();
            $table->string('client_id', 255);
            $table->string('resource_url', 1024);
            $table->char('binding_hash', 64);
            $table->longText('encrypted_payload');
            $table->timestamp('access_expires_at')->nullable();
            $table->timestamps();

            $table->index(['client_id', 'binding_hash']);
        });

        Schema::create('site_oauth_flows', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignUlid('site_record_id')->unique()->constrained('sites')->cascadeOnDelete();
            $table->char('state_hash', 64)->unique();
            $table->longText('encrypted_context');
            $table->timestamp('expires_at');
            $table->timestamp('consumed_at')->nullable();
            $table->timestamps();

            $table->index('expires_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('site_oauth_flows');
        Schema::dropIfExists('site_credentials');
        Schema::dropIfExists('sites');
    }
};
