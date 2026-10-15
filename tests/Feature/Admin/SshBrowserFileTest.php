<?php

namespace Tests\Feature\Admin;

use App\Application\Mcp\SshCommandMcpToolHandlers;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class SshBrowserFileTest extends TestCase
{
    use RefreshDatabase;

    public function test_both_browser_file_routes_fail_closed_when_opt_in_is_disabled(): void
    {
        $target = $this->target();
        $this->actingAs($this->user('owner'));
        config()->set('ssh.file_transfer.enabled', false);

        $this->get(route('admin.targets.show', $target))
            ->assertOk()
            ->assertDontSee('Choose a local file')
            ->assertDontSee('Download verified file');
        $this->post(route('admin.targets.ssh-files.upload', $target), [
            'local_file' => UploadedFile::fake()->createWithContent('private.bin', "secret\x00bytes"),
            'destination' => '/home/example/private.bin',
            'private_staging_dir' => '/home/example/.stage',
        ])->assertNotFound();
        $this->post(route('admin.targets.ssh-files.download', $target), [
            'path' => '/etc/passwd',
        ])->assertNotFound();
    }

    public function test_enabled_browser_picker_enforces_live_target_authorization_and_csrf(): void
    {
        $target = $this->target();
        config()->set('ssh.file_transfer.enabled', true);
        $this->actingAs($this->user('owner'));
        $this->get(route('admin.targets.show', $target))->assertOk()
            ->assertSee('Choose a local file')
            ->assertSee('Download verified file')
            ->assertSee('enctype="multipart/form-data"', false)
            ->assertSee('name="_token"', false);

        // No Target permission => no picker and no file read/write endpoint.
        $viewer = $this->user('viewer');
        $this->actingAs($viewer);
        $this->get(route('admin.targets.show', $target))->assertForbidden();
        $this->post(route('admin.targets.ssh-files.upload', $target), [
            'local_file' => UploadedFile::fake()->createWithContent('secret.txt', 'test'),
            'destination' => '/home/example/secret.txt',
            'private_staging_dir' => '/home/example/.stage',
        ])->assertForbidden();
        $this->post(route('admin.targets.ssh-files.download', $target), [
            'path' => '/etc/passwd',
        ])->assertForbidden();
    }

    public function test_valid_file_picker_upload_does_not_allow_unsafe_remote_path_or_leak_bytes(): void
    {
        $target = $this->target();
        config()->set('ssh.file_transfer.enabled', true);
        $this->actingAs($this->user('owner'));
        $secret = 'private-file-content-'.bin2hex(random_bytes(8));
        $this->post(route('admin.targets.ssh-files.upload', $target), [
            'local_file' => UploadedFile::fake()->createWithContent('private.txt', $secret),
            'destination' => 'relative/not/allowed',
            'private_staging_dir' => '/tmp/.gateway-secure',
        ])->assertRedirect()->assertSessionHasErrors('file_exchange');

        $this->post(route('admin.targets.ssh-files.download', $target), [
            'path' => 'relative/not/allowed',
        ])->assertRedirect()->assertSessionHasErrors('file_exchange');

        $this->assertDatabaseMissing('activity_events', [
            'operation' => $secret,
        ]);
        self::assertStringNotContainsString($secret, (string) json_encode(
            DB::table('activity_events')->get(), JSON_THROW_ON_ERROR,
        ));
    }

    public function test_disposable_ssh_fixture_browser_file_picker_upload_download_sha256(): void
    {
        if (getenv('SSH_FIXTURE_ENABLED') !== '1') {
            $this->markTestSkipped('The disposable OpenSSH fixture is not configured.');
        }

        $this->app->bind(SshDialAddressPolicy::class,
            static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
            {
                public function approvedDialAddresses(
                    SshRegisteredEndpoint $endpoint,
                    ?int $deadlineNs = null,
                ): array {
                    return ['127.0.0.1'];
                }
            });
        $owner = $this->user('owner');
        $target = app(SshTargetRegistration::class)->register(
            'browser-real', 'Browser real fixture', 'fixture.example.test',
            (int) getenv('SSH_FIXTURE_PORT_MODERN'), (string) getenv('SSH_FIXTURE_USER'),
            trim((string) file_get_contents((string) getenv('SSH_FIXTURE_ED25519_HOST_PUB'))),
            'private_key', (string) file_get_contents((string) getenv('SSH_FIXTURE_RSA_LOGIN_KEY')),
            (string) getenv('SSH_FIXTURE_KEY_PASSPHRASE'),
        );
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        config()->set('ssh.file_transfer.enabled', true);
        $this->actingAs($owner);
        $path = dirname((string) getenv('SSH_FIXTURE_PRIVATE_STAGING')).'/browser-'.bin2hex(random_bytes(8)).'.bin';
        $content = random_bytes(180127);
        $hash = hash('sha256', $content);

        $this->post(route('admin.targets.ssh-files.upload', $target), [
            'local_file' => UploadedFile::fake()->createWithContent('content.bin', $content),
            'destination' => $path,
            'private_staging_dir' => (string) getenv('SSH_FIXTURE_PRIVATE_STAGING'),
        ])->assertRedirect(route('admin.targets.show', $target))->assertSessionHasNoErrors();

        $download = $this->post(route('admin.targets.ssh-files.download', $target), [
            'path' => $path,
        ])->assertOk();
        self::assertSame('application/octet-stream', $download->headers->get('Content-Type'));
        self::assertSame($hash, $download->headers->get('X-Gateway-File-SHA256'));
        self::assertSame((string) strlen($content), $download->headers->get('Content-Length'));
        ob_start();
        $download->baseResponse->sendContent();
        $result = (string) ob_get_clean();
        self::assertSame($content, $result);

        $duplicate = $this->post(route('admin.targets.ssh-files.upload', $target), [
            'local_file' => UploadedFile::fake()->createWithContent('content.bin', $content),
            'destination' => $path,
            'private_staging_dir' => (string) getenv('SSH_FIXTURE_PRIVATE_STAGING'),
        ])->assertSessionHasErrors('file_exchange');
        $this->post(route('admin.targets.ssh-files.upload', $target), [
            'local_file' => UploadedFile::fake()->createWithContent('content.bin', $content),
            'destination' => $path,
            'private_staging_dir' => (string) getenv('SSH_FIXTURE_PRIVATE_STAGING'),
            'overwrite' => '1',
        ])->assertSessionHasNoErrors();

        // The fixture file is the only remote path modified by this test.
        $removed = app(SshCommandMcpToolHandlers::class)->run(
            $owner, $target->target_id, 'rm -f -- '.escapeshellarg($path),
        );
        self::assertTrue($removed['ok'], json_encode($removed));
    }

    private function user(string $role): User
    {
        return User::query()->create([
            'name' => $role,
            'email' => $role.'-ssh-file-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => $role,
            'target_scope_mode' => $role === 'owner' ? 'all' : 'selected',
            'access_enabled' => true,
        ]);
    }

    private function target(): Target
    {
        $hostKey = 'ssh-ed25519 '.base64_encode(
            pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x41", 32),
        );
        $target = app(SshTargetRegistration::class)->register(
            'browser-file', 'Browser File Target', 'example.test', 22,
            'browser-user', $hostKey, 'password', 'test-fixture-only', null,
        );
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();

        return $target;
    }
}
