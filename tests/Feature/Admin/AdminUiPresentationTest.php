<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Domain\Targets\TargetGroup;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\ViewErrorBag;
use Tests\TestCase;

final class AdminUiPresentationTest extends TestCase
{
    use RefreshDatabase;

    public function test_target_wordpress_operation_uses_shared_admin_markup(): void
    {
        $source = file_get_contents(resource_path('views/admin/targets/connectors/wordpress/operations.blade.php'));
        $result = file_get_contents(resource_path('views/admin/targets/wordpress-bridge-info.blade.php'));
        self::assertIsString($source);
        self::assertIsString($result);
        self::assertStringContainsString('@can(\'wordpress.abilities.execute.readonly\', $target)', $source);
        self::assertStringContainsString('@csrf', $source);
        self::assertStringContainsString('class="panel panel-wide"', $source);
        self::assertStringContainsString('class="page-heading"', $result);
        self::assertStringContainsString('role="alert"', $result);
        self::assertStringContainsString('{{ $response }}', $result);
        self::assertStringContainsString('operation-result-preview', $result);
        $css = file_get_contents(public_path('css/admin.css'));
        self::assertIsString($css);
        self::assertStringContainsString('.operation-result-preview {', $css);
        self::assertStringContainsString('overflow-wrap: anywhere;', $css);
    }

    public function test_endpoint_preflight_is_in_shared_enrollment_actions_for_both_connectors(): void
    {
        $this->actingAs($this->owner());

        foreach (['wp_ai_bridge', 'ssh_direct'] as $type) {
            $html = $this->get('/admin/targets/create?connector_type='.$type)
                ->assertOk()->getContent();

            $dom = new \DOMDocument;
            $previous = libxml_use_internal_errors(true);
            $dom->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
            $xpath = new \DOMXPath($dom);

            self::assertSame(1, (int) $xpath->evaluate(
                'count(//form[@id="target-create-form"]/div[@data-target-actions]'
                .'//button[@type="submit"][@formnovalidate][@formaction])',
            ));
            self::assertSame(0, (int) $xpath->evaluate(
                'count(//fieldset[@data-connector-panel]//button[@formnovalidate][@formaction])',
            ));
            self::assertStringContainsString('Preflight is optional and read-only.', $html);
            self::assertStringContainsString('Register Target', $html);
        }

        session()->flash('target_endpoint_preflight', [
            'ok' => false,
            'message' => 'Unsafe <script>untrusted</script> result',
            'next_step' => 'Inspect Gateway DNS',
            'reference' => 'test-reference',
        ]);
        $this->get('/admin/targets/create?connector_type=ssh_direct')
            ->assertOk()
            ->assertSee('role="alert"', false)
            ->assertSee('Unsafe &lt;script&gt;untrusted&lt;/script&gt; result', false)
            ->assertDontSee('Unsafe <script>untrusted</script> result', false)
            ->assertSee('Inspect Gateway DNS');
    }

    public function test_successful_preflight_is_explicitly_bound_to_checked_fields_and_can_be_invalidated(): void
    {
        $this->actingAs($this->owner());
        foreach ([
            ['wp_ai_bridge', 'https://wordpress.example.test/path', ['base_url' => 'https://wordpress.example.test/path']],
            ['ssh_direct', '[2606:4700:4700::1111]:2222', ['ssh_host' => '[2606:4700:4700::1111]', 'ssh_port' => '2222']],
        ] as [$type, $subject, $fields]) {
            session()->flash('target_endpoint_preflight', [
                'ok' => true,
                'message' => 'Public destination observed.',
                'limitation' => 'This does not authorize a connection.',
                'checked_subject' => $subject,
                'checked_connector' => $type,
                'checked_fields' => $fields,
            ]);
            session()->flashInput(['connector_type' => $type, ...$fields]);
            $html = $this->get('/admin/targets/create?connector_type='.$type)
                ->assertOk()
                ->assertSee('Checked endpoint')
                ->assertSee('target-preflight-stale')
                ->getContent();
            self::assertStringContainsString('js/admin-forms.js?v=', $html);
            $behavior = (string) file_get_contents(public_path('js/admin-forms.js'));
            self::assertStringContainsString('const syncPreflight =', $behavior);
            self::assertStringContainsString('preflightInvalidated = true', $behavior);
            self::assertStringContainsString('Object.keys(checkedFields || {})', $behavior);

            $dom = new \DOMDocument;
            $previous = libxml_use_internal_errors(true);
            $dom->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
            $xpath = new \DOMXPath($dom);
            self::assertSame(1, (int) $xpath->evaluate('count(//*[@id="target-endpoint-preflight"][@data-checked-connector])'));
            self::assertSame($type,
                $xpath->evaluate('string(//*[@id="target-endpoint-preflight"]/@data-checked-connector)'));
            $parsed = json_decode($xpath->evaluate(
                'string(//*[@id="target-endpoint-preflight"]/@data-checked-fields)',
            ), true, 512, JSON_THROW_ON_ERROR);
            self::assertSame($fields, $parsed);
            self::assertSame($subject,
                trim($xpath->evaluate('string(//*[@id="target-endpoint-preflight"]//code)')));
            self::assertSame(1, (int) $xpath->evaluate('count(//*[@id="target-preflight-stale"][@hidden][@role="status"])'));
        }
    }

    public function test_external_authorization_handoff_reuses_admin_layout_and_has_accessible_fallback(): void
    {
        $this->actingAs($this->owner());
        $target = new Target([
            'target_id' => 'generic-provider',
            'connector_type' => 'ssh_direct',
            'display_name' => 'Other connector',
        ]);
        $html = view('admin.targets.external-authorization', [
            'target' => $target,
            'destination' => 'https://consent.example.test/authorize?state=nonsecret&scope=read',
            'providerHost' => 'consent.example.test',
            'errors' => new ViewErrorBag,
        ])->render();

        $dom = new \DOMDocument;
        $previous = libxml_use_internal_errors(true);
        $dom->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);
        $xpath = new \DOMXPath($dom);

        self::assertSame(1, (int) $xpath->evaluate(
            'count(//head/meta[@http-equiv="refresh"][starts-with(@content,"0;url=https://consent.example.test/")])',
        ));
        self::assertSame(1, (int) $xpath->evaluate(
            'count(//main//section[contains(@class,"panel")]/h1[@id="external-authorization-title"])',
        ));
        self::assertSame(1, (int) $xpath->evaluate(
            'count(//main//a[@rel="noreferrer noopener"][contains(@class,"button-primary")])',
        ));
        self::assertStringContainsString('Do not resubmit the connection form.', $html);
        self::assertStringContainsString('css/admin.css?v=', $html);
    }

    public function test_admin_stylesheet_is_versioned_from_release_identity(): void
    {
        $this->actingAs($this->owner())
            ->get('/admin/users/create')
            ->assertOk()
            ->assertSee(
                'css/admin.css?v='.trim((string) file_get_contents(base_path('VERSION'))).'-'
                .substr((string) hash_file('sha256', public_path('css/admin.css')), 0, 12), false,
            );
    }

    public function test_ai_connection_checkbox_is_a_separate_accessible_user_account_control(): void
    {
        $owner = $this->owner();
        $this->actingAs($owner);

        foreach (['/admin/users/create', '/admin/users/'.$owner->id.'/edit'] as $route) {
            $html = $this->get($route)->assertOk()->getContent();
            $dom = new \DOMDocument;
            $previous = libxml_use_internal_errors(true);
            $dom->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
            $xpath = new \DOMXPath($dom);

            self::assertSame(1, (int) $xpath->evaluate(
                'count(//fieldset[legend[normalize-space(.)="AI / MCP connection"]]'
                .'//label[@for="ai_access_enabled"])',
            ));
            self::assertSame(1, (int) $xpath->evaluate(
                'count(//fieldset[legend[normalize-space(.)="AI / MCP connection"]]'
                .'//input[@type="checkbox"][@id="ai_access_enabled"]'
                .'[@name="ai_access_enabled"][@value="1"])',
            ));
            self::assertStringContainsString('independent of the account role', $html);
            self::assertStringContainsString('It never adds a Target or action permission.', $html);
        }
    }

    public function test_ssh_job_script_budget_uses_existing_accessible_owner_setting_fields(): void
    {
        $html = $this->actingAs($this->owner())
            ->get('/admin/operations')
            ->assertOk()
            ->assertSee('Maximum SSH Job script input (KiB)')
            ->getContent();

        $dom = new \DOMDocument;
        $previous = libxml_use_internal_errors(true);
        $dom->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);
        $xpath = new \DOMXPath($dom);

        self::assertSame(1, (int) $xpath->evaluate(
            'count(//fieldset[legend[normalize-space(.)="Detached SSH Jobs"]]'
            .'//label[@for="setting_ssh_job_max_script_kib"])',
        ));
        self::assertSame(1, (int) $xpath->evaluate(
            'count(//fieldset[legend[normalize-space(.)="Detached SSH Jobs"]]'
            .'//input[@id="setting_ssh_job_max_script_kib"]'
            .'[@name="values[ssh_job_max_script_kib]"][@min="16"][@max="512"]'
            .'[@aria-describedby="setting_ssh_job_max_script_kib_info"])',
        ));
        self::assertSame(1, (int) $xpath->evaluate(
            'count(//fieldset[legend[normalize-space(.)="SSH commands"]]'
            .'//input[@id="setting_ssh_command_max_kib"])',
        ));

        $css = file_get_contents(public_path('css/admin.css'));
        self::assertIsString($css);
        self::assertStringContainsString(
            ".operations-field-grid {\n        grid-template-columns: minmax(0, 1fr);",
            $css,
        );
    }

    public function test_extended_sync_ssh_limits_remain_owner_only_accessible_numeric_controls(): void
    {
        $html = $this->actingAs($this->owner())
            ->get('/admin/operations')->assertOk()->getContent();
        $dom = new \DOMDocument;
        $previous = libxml_use_internal_errors(true);
        $dom->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);
        $xpath = new \DOMXPath($dom);
        foreach ([
            'ssh_transfer_max_seconds' => ['min' => '5', 'max' => '3600'],
            'ssh_command_timeout_seconds' => ['min' => '15', 'max' => '600'],
        ] as $key => $range) {
            self::assertSame(1, (int) $xpath->evaluate(
                'count(//input[@type="number"][@id="setting_'.$key.'"]'
                .'[@name="values['.$key.']"][@min="'.$range['min'].'"][@max="'.$range['max'].'"]'
                .'[@aria-describedby="setting_'.$key.'_info"])',
            ));
        }
        self::assertStringContainsString('extended timeout requires suitable PHP', $html);
        self::assertStringContainsString('up to 600 seconds', $html);
    }

    public function test_target_ai_guidance_forms_reuse_accessible_shared_responsive_controls(): void
    {
        $owner = $this->owner();
        $target = Target::query()->create([
            'target_id' => 'note-ui',
            'display_name' => 'Production note editor',
            'connector_type' => 'ssh_direct',
            'ai_guidance' => "Production server\nExplain every change.",
        ]);
        $this->actingAs($owner);

        foreach ([
            '/admin/targets/create?connector_type=ssh_direct',
            '/admin/targets/create?connector_type=wp_ai_bridge',
            '/admin/targets/note-ui/edit',
        ] as $url) {
            $html = $this->get($url)->assertOk()->getContent();
            $dom = new \DOMDocument;
            $previous = libxml_use_internal_errors(true);
            $dom->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
            $xpath = new \DOMXPath($dom);

            self::assertSame(1, (int) $xpath->evaluate(
                'count(//label[@for="ai_guidance"])',
            ));
            self::assertSame(1, (int) $xpath->evaluate(
                'count(//textarea[@id="ai_guidance"][@name="ai_guidance"][@rows="3"]'
                .'[@maxlength="800"][@aria-describedby="ai_guidance_help"])',
            ));
            self::assertSame(1, (int) $xpath->evaluate(
                'count(//p[@id="ai_guidance_help"][contains(@class,"field-help")])',
            ));
            self::assertStringContainsString('This is advice, not enforced approval.', $html);
            self::assertStringNotContainsString('name="approval_policy"', $html);
        }

        $edit = $this->get('/admin/targets/note-ui/edit')->assertOk()->getContent();
        self::assertStringContainsString("Production server\nExplain every change.", $edit);

        $css = file_get_contents(public_path('css/admin.css'));
        self::assertIsString($css);
        self::assertStringContainsString('.field textarea {', $css);
        self::assertStringContainsString('grid-template-columns: minmax(0, 1fr);', $css);
        self::assertStringContainsString('.target-ai-guidance-text {', $css);
        self::assertStringContainsString('white-space: pre-wrap;', $css);
        self::assertStringContainsString('overflow-wrap: anywhere;', $css);
    }

    public function test_adjacent_admin_panels_use_shared_spacing_without_page_specific_card_fixes(): void
    {
        $this->actingAs($this->owner())
            ->get('/admin/oauth-clients')
            ->assertOk()
            ->assertSee('class="panel panel-wide ai-client-authorizations"', false);

        $css = file_get_contents(public_path('css/admin.css'));
        self::assertIsString($css);
        self::assertStringContainsString('--ui-panel-stack-gap: 1.25rem;', $css);
        self::assertMatchesRegularExpression(
            '/\.main-content\s*>\s*\.panel\s*\+\s*\.panel\s*\{\s*margin-block-start:\s*var\(--ui-panel-stack-gap\);\s*\}/',
            $css,
        );
        self::assertStringNotContainsString('.ai-client-authorizations {', $css);
        self::assertStringContainsString('.client-grant-revoke-form {', $css);

        $targetEditor = file_get_contents(resource_path('views/admin/targets/edit.blade.php'));
        self::assertIsString($targetEditor);
        self::assertSame(2, substr_count($targetEditor, '<section class="panel panel-wide target-enrollment"'));
    }

    public function test_shared_admin_headings_wrap_valid_long_target_names_and_tables_follow_direction(): void
    {
        $name = str_repeat('L', 160);
        Target::query()->create([
            'target_id' => 'long-heading',
            'display_name' => $name,
            'connector_type' => 'wp_ai_bridge',
        ]);
        $owner = $this->owner();
        $this->actingAs($owner)
            ->get('/admin/targets/long-heading')
            ->assertOk()
            ->assertSee('<h1>'.$name.'</h1>', false);
        $this->actingAs($owner)
            ->get('/admin/targets')
            ->assertOk()
            ->assertSee($name)
            ->assertSee('<th scope="col">Actions</th>', false)
            ->assertSee('class="table-wrap targets-table-wrap"', false);

        $css = file_get_contents(public_path('css/admin.css'));
        self::assertIsString($css);
        self::assertMatchesRegularExpression(
            '/\.page-heading\s*>\s*:first-child,\s*\.section-heading\s*>\s*:first-child\s*\{\s*min-width:\s*0;\s*\}/',
            $css,
        );
        self::assertMatchesRegularExpression(
            '/h1,\s*h2\s*\{[^}]*overflow-wrap:\s*anywhere;/s',
            $css,
        );
        self::assertMatchesRegularExpression(
            '/\.table-wrap\s*\{[^}]*position:\s*relative;[^}]*overflow-x:\s*auto;/s',
            $css,
        );
        self::assertMatchesRegularExpression('/th,\s*td\s*\{[^}]*text-align:\s*start;/s', $css);
        self::assertMatchesRegularExpression('/\.table-action\s*\{\s*text-align:\s*end;/s', $css);
    }

    public function test_dense_operational_tables_preserve_headers_and_opt_in_to_readable_identity_columns(): void
    {
        $target = Target::query()->create([
            'target_id' => 'ui-wordpress-reassigning',
            'display_name' => 'UI WordPress reassigning',
            'connector_type' => 'wp_ai_bridge',
            'connection_state' => 'reassigning',
        ]);
        $this->actingAs($this->owner());
        app(ActivityRecorder::class)->recordRequired(
            '00000000-0000-4000-8000-000000000001',
            'fixture-readability',
            'unknown',
            $target,
            'fixture_unknown',
        );

        foreach (['/admin' => [2, 2], '/admin/activity' => [1, 3]] as $url => [$tableCount, $identityCount]) {
            $html = $this->get($url)->assertOk()->getContent();
            $document = new \DOMDocument;
            $previous = libxml_use_internal_errors(true);
            $document->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
            $xpath = new \DOMXPath($document);
            $readable = '//table[contains(concat(" ", normalize-space(@class), " "), " table-readable ")]';

            self::assertSame($tableCount, (int) $xpath->evaluate('count('.$readable.')'));
            self::assertSame($identityCount, (int) $xpath->evaluate(
                'count('.$readable.'/thead/tr/th[@scope="col"][@class="table-identity"])',
            ));
            self::assertSame($tableCount, (int) $xpath->evaluate(
                'count(//div[@class="table-wrap"]/table[@class="table-readable"]/tbody)',
            ));
            self::assertStringContainsString('ui-wordpress-reassigning', $html);
            self::assertSame(0, (int) $xpath->evaluate('count('.$readable.'[@role="presentation"])'));
        }

        $this->get('/admin/targets')->assertOk()->assertDontSee('table-readable', false);
        $this->get('/admin/users')->assertOk()->assertDontSee('table-readable', false);

        $css = file_get_contents(public_path('css/admin.css'));
        self::assertIsString($css);
        self::assertMatchesRegularExpression('/table\.table-readable\s*\{\s*min-inline-size:\s*48rem;\s*\}/', $css);
        self::assertMatchesRegularExpression('/\.table-readable\s+\.table-identity\s*\{\s*min-inline-size:\s*12rem;\s*\}/', $css);
    }

    public function test_permission_controls_explain_title_scope_and_effective_behavior(): void
    {
        $response = $this->actingAs($this->owner())
            ->get('/admin/users/create');

        $response
            ->assertOk()
            ->assertSee('Remove Targets')
            ->assertSee('targets.remove')
            ->assertSee('Target-scoped')
            ->assertSee('effective Target scope')
            ->assertSee('not limited to Targets the user created');
    }

    public function test_target_inventory_separates_connection_oauth_and_pause_without_false_required_label(): void
    {
        $withStoredOauth = Target::query()->create([
            'target_id' => 'wp-stored',
            'display_name' => 'Stored OAuth WordPress',
            'connector_type' => 'wp_ai_bridge',
        ]);
        $withStoredOauth->forceFill(['connection_state' => 'connected'])->save();
        TargetCredential::query()->create([
            'target_record_id' => $withStoredOauth->getKey(),
            'connector_type' => 'wp_ai_bridge',
            'purpose' => 'wordpress_oauth',
            'encrypted_payload' => 'opaque-test-fixture',
        ]);
        $withoutOauth = Target::query()->create([
            'target_id' => 'wp-no-credential',
            'display_name' => 'No OAuth WordPress',
            'connector_type' => 'wp_ai_bridge',
        ]);
        $withoutOauth->forceFill(['connection_state' => 'connected'])->save();
        $pausedSsh = Target::query()->create([
            'target_id' => 'ssh-paused-list',
            'display_name' => 'Paused SSH',
            'connector_type' => 'ssh_direct',
        ]);
        $pausedSsh->forceFill([
            'connection_state' => 'connected',
            'operations_paused' => true,
        ])->save();

        $html = $this->actingAs($this->owner())->get('/admin/targets')
            ->assertOk()
            ->assertSee('<th scope="col">Connection</th>', false)
            ->assertSee('<th scope="col">Gateway operations</th>', false)
            ->assertSee('<th scope="col">Actions</th>', false)
            ->assertSee('class="targets-table"', false)
            ->assertSee('class="target-action-confirm"', false)
            ->assertSee('Confirm Pause')
            ->assertSee('Confirm Resume')
            ->getContent();

        preg_match_all('/<tbody>.*?<\/tbody>/s', $html, $tables);
        self::assertCount(1, $tables[0]);
        preg_match_all('/<tr>.*?<\/tr>/s', $tables[0][0], $rows);
        $rowFor = static function (string $id) use ($rows): string {
            foreach ($rows[0] as $row) {
                if (str_contains($row, '>'.$id.'</code>')) {
                    return $row;
                }
            }

            return '';
        };
        $storedRow = $rowFor('wp-stored');
        self::assertNotSame('', $storedRow);
        self::assertStringContainsString('WordPress authorization stored', $storedRow);
        self::assertStringNotContainsString('WordPress authorization required', $storedRow);
        self::assertStringContainsString('Connected', $storedRow);
        self::assertStringContainsString('Enabled', $storedRow);

        $missingRow = $rowFor('wp-no-credential');
        self::assertNotSame('', $missingRow);
        self::assertStringContainsString('WordPress authorization required', $missingRow);

        $pausedRow = $rowFor('ssh-paused-list');
        self::assertNotSame('', $pausedRow);
        self::assertStringContainsString('Connected', $pausedRow);
        self::assertStringContainsString('Paused', $pausedRow);
        self::assertStringContainsString('Confirm Resume', $pausedRow);
        self::assertStringNotContainsString('Confirm Pause', $pausedRow);

        $css = file_get_contents(public_path('css/admin.css'));
        self::assertIsString($css);
        self::assertStringContainsString('.targets-table', $css);
        self::assertStringContainsString('.targets-mobile-label', $css);
        self::assertStringContainsString('@media (max-width: 30rem)', $css);
        self::assertStringContainsString('.target-action-confirm > summary:focus-visible', $css);

        $operator = User::query()->create([
            'name' => 'Read-only inventory operator',
            'email' => 'targets-list-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::All->value,
            'access_enabled' => true,
        ]);
        $this->actingAs($operator)->get('/admin/targets')
            ->assertOk()
            ->assertSee('Inspect')
            ->assertDontSee('Confirm Pause')
            ->assertDontSee('Confirm Resume')
            ->assertDontSee('class="target-action-confirm"', false);
    }

    public function test_target_inventory_labels_unsupported_historical_connectors_without_reclassifying_them(): void
    {
        $legacy = Target::query()->create([
            'target_id' => 'legacy-unsupported',
            'display_name' => 'Historical connector',
            'connector_type' => 'ssh_direct',
        ]);
        // The immutable model disallows new unsupported connector types; only
        // previously persisted historical records may still have one.
        DB::table('targets')->where('id', $legacy->getKey())
            ->update(['connector_type' => 'unrecognized_connector']);

        Target::query()->create([
            'target_id' => 'supported-ssh',
            'display_name' => 'Supported SSH',
            'connector_type' => 'ssh_direct',
        ]);
        Target::query()->create([
            'target_id' => 'supported-wordpress',
            'display_name' => 'Supported WordPress',
            'connector_type' => 'wp_ai_bridge',
        ]);

        $html = $this->actingAs($this->owner())
            ->get('/admin/targets')
            ->assertOk()
            ->getContent();
        $document = new \DOMDocument;
        $previous = libxml_use_internal_errors(true);
        $document->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);
        $xpath = new \DOMXPath($document);

        $connectorLabelFor = static function (string $targetId) use ($xpath): array {
            $cell = $xpath->query(
                '//table[contains(concat(" ", normalize-space(@class), " "), " targets-table ")]'
                .'/tbody/tr[td[1]//code[text()="'.$targetId.'"]]/td[2]',
            )->item(0);
            self::assertInstanceOf(\DOMElement::class, $cell);

            return [
                trim($xpath->evaluate('string(.//strong)', $cell)),
                trim($xpath->evaluate('string(.//code)', $cell)),
            ];
        };

        self::assertSame(['Unsupported connector', 'unrecognized_connector'], $connectorLabelFor('legacy-unsupported'));
        self::assertSame(['Direct SSH', 'ssh_direct'], $connectorLabelFor('supported-ssh'));
        self::assertSame(['WordPress (WP AI Bridge)', 'wp_ai_bridge'], $connectorLabelFor('supported-wordpress'));
        self::assertSame('unrecognized_connector', DB::table('targets')->where('id', $legacy->getKey())->value('connector_type'));
    }

    public function test_target_entry_remains_neutral_and_available_connectors_have_registration_flows(): void
    {
        $owner = $this->owner();

        $this->actingAs($owner)
            ->get('/admin/targets')
            ->assertOk()
            ->assertSee('Add Target')
            ->assertDontSee('Add WordPress Target');

        $this->actingAs($owner)
            ->get('/admin/targets/create')
            ->assertOk()
            ->assertSee('WordPress (WP AI Bridge)')
            ->assertSee('Direct SSH')
            ->assertSee('value="wp_ai_bridge"', false)
            ->assertSee('value="ssh_direct"', false)
            ->assertDontSee('value="ai_server_agent"', false)
            ->assertSee('WordPress public HTTPS URL')
            ->assertSee('Trusted OpenSSH server public host key')
            ->assertSee('separate trusted channel')
            ->assertSee('Password only')
            ->assertSee('Private key only')
            ->assertDontSee('Password + private key')
            ->assertSee('name="connector_type"', false)
            ->assertSee('data-connector-panel="wp_ai_bridge"', false)
            ->assertSee('data-connector-panel="ssh_direct"', false);
    }

    public function test_user_and_group_denials_are_grouped_without_exposing_future_connectors_as_active(): void
    {
        $owner = $this->owner();

        foreach (['/admin/users/create', '/admin/target-groups/create'] as $url) {
            $this->actingAs($owner)->get($url)
                ->assertOk()
                ->assertSee('Shared Target management')
                ->assertSee('WordPress (WP AI Bridge)')
                ->assertSee('Direct SSH')
                ->assertSee('Checked = DENY')
                ->assertSee('Active')
                ->assertDontSee('AI Server Agent')
                ->assertDontSee('View paused Agent permission identifiers (read-only)')
                ->assertDontSee('SSH settings require an authorized Owner editor');
        }

        $createUser = $this->actingAs($owner)->get('/admin/users/create')->assertOk()
            ->assertSee('Gateway administration')
            ->assertSee('Active · Owner-confirmed')
            ->assertSee('ssh_permissions_reviewed')
            ->assertSee('Owner bypasses every permission and Target restriction for recovery')
            ->assertSee('confirm_ssh_permission_changes')
            ->assertSee('value="ssh.command.run"', false)
            ->assertSee('value="ssh.file.read"', false)
            ->assertSee('value="ssh.file.write"', false);
        foreach (GatewayPermission::sshCapabilities() as $permission) {
            self::assertMatchesRegularExpression(
                '/<input[^>]*name="denied_permissions\[\]"[^>]*value="'.preg_quote($permission->value, '/').'"[^>]*checked/s',
                $createUser->getContent(),
            );
        }
        $this->actingAs($owner)->get('/admin/target-groups/create')
            ->assertSee('Active · deny-only')
            ->assertSee('confirm_ssh_group_changes')
            ->assertSee('value="ssh.command.run"', false);
        self::assertSame('gateway', GatewayPermission::SecurityManage->adminGroup());
        self::assertSame('targets', GatewayPermission::TargetsView->adminGroup());
        self::assertSame('wordpress', GatewayPermission::WordpressAbilitiesInspect->adminGroup());
        self::assertSame('ssh', GatewayPermission::SshCommandRun->adminGroup());
        self::assertNull(GatewayPermission::tryFrom('agent.command.run'));
        self::assertTrue(collect(GatewayPermission::cases())->every(
            static fn (GatewayPermission $permission): bool => ! str_starts_with($permission->value, 'agent.')));
    }

    public function test_specific_wordpress_target_hides_other_connector_permissions_but_preserves_old_denials(): void
    {
        $owner = $this->owner();
        $operator = User::query()->create([
            'name' => 'Operator',
            'email' => 'operator-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
            'access_enabled' => true,
        ]);
        $target = Target::query()->create([
            'target_id' => 'wp-demo',
            'display_name' => 'WP Demo',
            'connector_type' => 'wp_ai_bridge',
        ]);
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $target->getKey(),
            'permission' => GatewayPermission::SshCommandRun->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->actingAs($owner)
            ->get('/admin/users/'.$operator->getKey().'/targets/'.$target->target_id.'/edit')
            ->assertOk()
            ->assertSee('Shared Target management')
            ->assertSee('WordPress (WP AI Bridge)')
            ->assertDontSee('Review reserved permission definitions')
            ->assertDontSee('Run SSH remote commands')
            ->assertDontSee('AI Server Agent')
            ->assertSee('name="denied_permissions[]" value="ssh.command.run"', false)
            ->assertSee('Existing restrictions for other connector types are preserved');
    }

    public function test_direct_ssh_target_user_scope_edits_show_live_deny_only_controls_not_reserved_definitions(): void
    {
        $owner = $this->owner();
        $operator = User::query()->create([
            'name' => 'SSH operator',
            'email' => 'ssh-ui-'.uniqid().'@example.test',
            'password' => 'DifferentHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
            'access_enabled' => true,
        ]);
        $target = Target::query()->create([
            'target_id' => 'ssh-ui-target', 'display_name' => 'SSH Target',
            'connector_type' => 'ssh_direct',
        ]);
        $this->actingAs($owner)->get('/admin/users/'.$operator->getKey().'/targets/'.$target->target_id.'/edit')
            ->assertOk()
            ->assertSee('Direct SSH')
            ->assertSee('Active · Target-specific denies')
            ->assertSee('value="ssh.command.run"', false)
            ->assertSee('value="ssh.file.read"', false)
            ->assertSee('value="ssh.file.write"', false)
            ->assertSee('confirm_ssh_target_changes')
            ->assertDontSee('View paused Agent permission identifiers');
    }

    public function test_group_and_user_edit_preserve_stored_future_denials_as_hidden_values(): void
    {
        $owner = $this->owner();
        $group = TargetGroup::query()->create(['name' => 'Mixed connector group']);
        DB::table('target_group_permission_denials')->insert([
            'target_group_id' => $group->getKey(),
            'permission' => GatewayPermission::SshCommandRun->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        $operator = User::query()->create([
            'name' => 'Operator',
            'email' => 'operator-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
            'access_enabled' => true,
        ]);
        DB::table('user_permission_denials')->insert([
            'user_id' => $operator->getKey(),
            'permission' => GatewayPermission::SshCommandRun->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->actingAs($owner)->get('/admin/target-groups/'.$group->getKey().'/edit')
            ->assertOk()
            ->assertSee('value="ssh.command.run"', false)
            ->assertSee('confirm_ssh_group_changes')
            ->assertDontSee('Existing denial retained');
        $this->actingAs($owner)->get('/admin/users/'.$operator->getKey().'/edit')
            ->assertOk()
            ->assertSee('ssh.command.run')
            ->assertSee('confirm_ssh_permission_changes')
            ->assertDontSee('Existing denial retained');
    }

    public function test_ai_client_registry_paginates_durable_history_and_supports_exact_profile_lookup(): void
    {
        $profiles = [];
        $clients = [];
        for ($i = 0; $i < 53; $i++) {
            $profile = 'dcr_'.str_pad(dechex($i), 32, '0', STR_PAD_LEFT);
            $client = 'dcr_'.str_pad(dechex($i), 48, '0', STR_PAD_LEFT);
            $profiles[] = [
                'profile_key' => $profile, 'client_id' => $client,
                'auth_strategy' => 'dcr_client_secret_post',
                'generation' => 1, 'disabled_at' => null,
                'created_at' => now()->addSeconds($i), 'updated_at' => now(),
            ];
            $clients[] = [
                'profile_key' => $profile, 'client_id' => $client,
                'display_name' => 'ChatGPT (DCR)', 'secret_hash' => hash('sha256', $client),
                'redirect_uris' => json_encode(['https://chatgpt.com/connector_platform_oauth_redirect'], JSON_THROW_ON_ERROR),
                'retired_at' => $i === 0 ? now() : null,
                'created_at' => now()->addSeconds($i), 'updated_at' => now(),
            ];
        }
        foreach (array_chunk($profiles, 40) as $rows) {
            DB::table('oauth_client_profiles')->insert($rows);
        }
        foreach (array_chunk($clients, 40) as $rows) {
            DB::table('oauth_dcr_clients')->insert($rows);
        }

        $this->actingAs($this->owner());
        $first = $this->get('/admin/oauth-clients')->assertOk()->assertSee('DCR client profile pages');
        self::assertSame(50, substr_count($first->getContent(), '<code>dcr_client_secret_post</code>'));
        $first->assertDontSee('<code>dcr_'.str_pad('0', 32, '0', STR_PAD_LEFT).'</code>', false)
            ->assertSee('clients_page=2');

        $second = $this->get('/admin/oauth-clients?clients_page=2')->assertOk();
        self::assertSame(3, substr_count($second->getContent(), '<code>dcr_client_secret_post</code>'));
        $second->assertSee('<code>dcr_'.str_pad('0', 32, '0', STR_PAD_LEFT).'</code>', false)
            ->assertSee('Retired (permanent)');

        $filtered = $this->get('/admin/oauth-clients?profile=dcr_'.str_pad('0', 32, '0', STR_PAD_LEFT))
            ->assertOk();
        self::assertSame(1, substr_count($filtered->getContent(), '<code>dcr_client_secret_post</code>'));
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Gateway Owner',
            'email' => 'owner-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner->value,
            'target_scope_mode' => TargetScopeMode::All->value,
            'access_enabled' => true,
        ]);
    }
}
