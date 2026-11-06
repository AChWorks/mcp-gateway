@extends('admin.layout')

@section('title', __('Connection Relays'))
@section('form-page', '1')

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('System') }}</div>
        <h1>{{ __('Connection Relays') }}</h1>
        <p class="muted reading-width">{{ __('Register one intermediary for several SSH/SFTP or WordPress Targets. Direct stays the default; existing Reverse SSH routes remain separate.') }}</p>
    </div>
    <div class="action-row">
        <a href="#relay-add-heading" class="button button-primary">{{ __('Add Relay') }}</a>
        <a href="{{ route('admin.targets.create') }}">{{ __('Add Target') }}</a>
    </div>
</div>

<section class="panel panel-wide" aria-labelledby="relay-setup-heading">
    <h2 id="relay-setup-heading">{{ __('Before enabling a Relay') }}</h2>
    <p class="muted reading-width">{{ __('Registration only saves an inactive route. A privileged host operator must complete these separate steps; the Gateway cannot install or attest its own transport.') }}</p>
    <ol class="reverse-setup-list">
        <li><strong>{{ __('Isolate the Gateway') }}</strong>
            <p class="field-help">{{ __('Use a dedicated PHP-FPM and worker UID, with exclusive access to the selected local SOCKS5 listener.') }}</p>
        </li>
        <li><strong>{{ __('Restrict the Iran intermediary') }}</strong>
            <p class="field-help">{{ __('Pin its SSH host key and limit a dedicated forwarding-only account to approved public destinations.') }}</p>
        </li>
        <li><strong>{{ __('Verify and attest the host') }}</strong>
            <p class="field-help">{{ __('Test the effective access rules, then issue fresh, boot- and policy-bound root-owned evidence. Recheck after every disable or host-policy change.') }}</p>
        </li>
    </ol>
    <details class="target-help-details">
        <summary>{{ __('Security details and operator runbook') }}</summary>
        <p class="field-help">{{ __('Loopback alone is not isolation when other websites share a PHP Unix user. The privileged verifier must refresh short-lived evidence and rotate its policy generation before changing relevant host rules. Never expose SOCKS5 publicly or use an ambient proxy.') }}</p>
        <p class="field-help">{{ __('Operator procedure:') }} <code>docs/CONNECTION-RELAYS.md</code></p>
        <p class="field-help">{{ __('A verified local SOCKS greeting is not proof of destination reachability or identity. Test the selected Target’s SSH key/login or HTTPS certificate separately.') }}</p>
    </details>
</section>

<section class="panel panel-wide" aria-labelledby="relay-list-heading">
    <h2 id="relay-list-heading">{{ __('Registered Relays') }} ({{ $relays->count() }})</h2>
    <p class="field-help">{{ __('Relays are managed independently. Renaming only changes the displayed name; editing a connection requires renewed host verification.') }}</p>
    @forelse ($relays as $relay)
        <article class="target-subsection" aria-labelledby="relay-title-{{ $relay->id }}">
            <div class="section-heading">
                <div>
                    <h3 id="relay-title-{{ $relay->id }}">{{ $relay->display_name }}</h3>
                    <p class="field-help">{{ $relay->enabled ? __('Enabled for selected Targets') : __('Disabled — no Target can use this Relay') }}</p>
                </div>
            </div>
            <dl class="summary-list summary-grid">
                <div><dt>{{ __('Relay ID') }}</dt><dd><code>{{ $relay->relay_id }}</code></dd></div>
                <div><dt>{{ __('Control SSH') }}</dt><dd><code>{{ $relay->control_user.'@'.$relay->control_host.':'.$relay->control_port }}</code></dd></div>
                <div><dt>{{ __('Local SOCKS5') }}</dt><dd><code>127.0.0.1:{{ $relay->local_socks_port }}</code></dd></div>
                <div><dt>{{ __('Targets using Relay') }}</dt><dd>{{ $counts[$relay->id] ?? 0 }}</dd></div>
                <div><dt>{{ __('Operational status') }}</dt><dd>{{ $operationalStates[$relay->id]->label() }}</dd></div>
                <div><dt>{{ __('Host evidence') }}</dt><dd>{{ $hostStates[$relay->id] ? __('Current for this PHP UID') : __('Not ready — missing, expired or mismatched') }}</dd></div>
            </dl>
            <p class="field-help">{{ $operationalStates[$relay->id]->nextAction() }}</p>
            @if ($hostCommands[$relay->id] ?? null)
                <details class="target-help-details">
                    <summary>{{ __('Audit installed Gateway-local policy (read-only)') }}</summary>
                    <p class="field-help">{{ __('Run only on the authorized Gateway host after privileged Setup. Checks root-owned host identity, effective systemd service, nftables loopback UID restrictions on IPv4/IPv6, and the actual listening process without changing host state. A PASS does not issue readiness evidence or prove the Iran egress policy, dedicated PHP-FPM ownership, or Target authentication.') }}</p>
                    <div class="field">
                        <label for="relay-audit-command-{{ $relay->id }}">{{ __('Verified, Relay-specific local audit command') }}</label>
                        <textarea id="relay-audit-command-{{ $relay->id }}" rows="4" readonly spellcheck="false" autocomplete="off">{{ $hostCommands[$relay->id]['audit_gateway'] }}</textarea>
                        <p class="field-help">{{ __('If the helper is not yet installed, use the separately verified installation action under Retire and remove Relay. Do not run it as part of routine browsing. The UID in this command is the present web-process UID; verify that dedicated FPM and CLI identities match before future host attestation.') }}</p>
                    </div>
                </details>
            @endif
            @if ($rotationStates[$relay->id] ?? false)
                <p class="field-help">{{ __('Old revision retirement is sealed. Save the pending connection change before requesting setup for the new revision.') }}</p>
            @endif
            <details class="target-help-details">
                <summary>{{ __('Rename Relay') }}</summary>
                <p class="field-help">{{ __('Change the name displayed in Gateway without interrupting the connection or bound Targets.') }}</p>
                @php $renameDraft = old('name_relay_id') === (string) $relay->getKey(); @endphp
                <form method="post" class="form-stack" action="{{ route('admin.connection-relays.rename', ['relay' => $relay->id]) }}" autocomplete="off">
                    @csrf
                    @method('PUT')
                    <input type="hidden" name="relay_revision" value="{{ $relay->lifecycle_revision }}">
                    <input type="hidden" name="name_relay_id" value="{{ $relay->getKey() }}">
                    <div class="field">
                        <label for="relay-name-{{ $relay->id }}">{{ __('Display name') }}</label>
                        <input id="relay-name-{{ $relay->id }}" type="text" name="display_name" maxlength="160" required
                            autocomplete="off" data-admin-manual-entry
                            data-admin-server-value="{{ $renameDraft ? old('display_name', $relay->display_name) : $relay->display_name }}"
                            value="{{ $renameDraft ? old('display_name', $relay->display_name) : $relay->display_name }}"
                            @if($renameDraft && $errors->has('display_name')) aria-invalid="true" aria-describedby="relay-name-error-{{ $relay->id }}" @endif>
                        @if($renameDraft) @error('display_name')<p class="field-error" role="alert" id="relay-name-error-{{ $relay->id }}">{{ $message }}</p>@enderror @endif
                    </div>
                    <div class="field">
                        <label for="relay-rename-password-{{ $relay->id }}">{{ __('Current Owner password') }}</label>
                        <input id="relay-rename-password-{{ $relay->id }}" type="password" name="current_password" data-admin-requires-intent autocomplete="current-password" maxlength="255" required>
                    </div>
                    <button class="button button-secondary" type="submit">{{ __('Save display name') }}</button>
                </form>
            </details>
            @if ($relay->enabled)
                <form method="post" class="form-stack" action="{{ route('admin.connection-relays.test', ['relay' => $relay->id]) }}">
                    @csrf
                    <button class="button button-secondary" type="submit">{{ __('Check local SOCKS5 greeting') }}</button>
                    <p class="field-help">{{ __('Control-only check; no Target authentication or remote operation.') }}</p>
                </form>
            @endif
            <form method="post" class="form-stack" action="{{ route('admin.connection-relays.toggle', ['relay' => $relay->id]) }}">
                @csrf
                <input type="hidden" name="relay_revision" value="{{ $relay->lifecycle_revision }}">
                <input type="hidden" name="enable" value="{{ $relay->enabled ? '0' : '1' }}">
                <div class="field">
                    <label for="relay-toggle-password-{{ $relay->id }}">{{ __('Current Owner password') }}</label>
                    <input id="relay-toggle-password-{{ $relay->id }}" type="password" name="current_password" data-admin-requires-intent autocomplete="current-password" maxlength="255" required>
                </div>
                <button class="button {{ $relay->enabled ? 'button-secondary' : 'button-primary' }}" type="submit">{{ $relay->enabled ? __('Disable Relay and fence bound Targets') : __('Enable with current host evidence') }}</button>
                @if (! $relay->enabled)
                    <p class="field-help">{{ __('Enabling requires renewed host evidence after any prior disable. Existing Targets must reconnect and verify their identity.') }}</p>
                @endif
            </form>
            @if (! $relay->enabled && (int) ($counts[$relay->id] ?? 0) === 0)
                <details class="target-help-details">
                    <summary>{{ __('Edit connection settings') }}</summary>
                    <p class="field-help">{{ __('The Relay ID is permanent. Changing host, port, user, pinned key or SOCKS5 port requires a root-owned rotation fence BEFORE saving; a cleanup receipt alone cannot prevent a concurrent Setup. After saving, provision and attest the next configuration revision separately. Display-only rename needs no host command.') }}</p>
                    @if($deletionFencedStates[$relay->id] ?? false)
                        <p class="field-error" role="alert">{{ __('This registration has a permanent deletion fence. Connection settings cannot be edited; renew the retirement proof if needed, then complete the confirmed Delete action.') }}</p>
                    @else
                        @if (! ($rotationStates[$relay->id] ?? false))
                            @if ($hostCommands[$relay->id] ?? null)
                                <div class="field">
                                    <label for="relay-rotate-command-{{ $relay->id }}">{{ __('One Gateway-host cleanup and revision-fence command — run before saving connection changes') }}</label>
                                    <textarea id="relay-rotate-command-{{ $relay->id }}" rows="7" readonly spellcheck="false" autocomplete="off">{{ $hostCommands[$relay->id]['cleanup_for_rotation'] }}</textarea>
                                    <p class="field-help">{{ __('Expected on first run: RETIREMENT VERIFIED then LIFECYCLE FENCE VERIFIED (rotate); on retry, only LIFECYCLE FENCE VERIFIED. This permanently blocks old configuration commands; if DB save fails, retry the same update. Never run this command for display-only rename.') }}</p>
                                </div>
                            @else
                                <p class="field-error" role="alert">{{ __('The host helper does not match this release; restore a verified version before privileged rotation.') }}</p>
                            @endif
                        @else
                            <p class="field-help">{{ __('Rotation fence verified for this configuration. Save the new identity or retry the previously interrupted save.') }}</p>
                        @endif
                        <form class="form-stack" method="post" action="{{ route('admin.connection-relays.update', ['relay' => $relay->id]) }}" autocomplete="off">
                        @csrf
                        @method('PUT')
                        <input type="hidden" name="relay_revision" value="{{ $relay->lifecycle_revision }}">
                        <input type="hidden" name="edit_relay_id" value="{{ $relay->getKey() }}">
                        @include('admin.connection-relays.partials.fields', ['prefix' => 'edit-'.$relay->id, 'editing' => true])
                        <div class="field">
                            <label for="relay-edit-password-{{ $relay->id }}">{{ __('Current Owner password') }}</label>
                            <input id="relay-edit-password-{{ $relay->id }}" type="password" name="current_password" data-admin-requires-intent autocomplete="current-password" maxlength="255" required>
                        </div>
                        <button class="button button-primary" type="submit">{{ __('Save Relay identity') }}</button>
                        </form>
                    @endif
                </details>
            @elseif (! $relay->enabled)
                <p class="field-help">{{ __('Reassign or detach the :count Target(s) under Targets before editing the connection. No Target will switch to Direct automatically.', ['count' => $counts[$relay->id] ?? 0]) }}</p>
                <a href="{{ route('admin.targets.index') }}">{{ __('Manage assigned Targets') }}</a>
            @endif
            @if (! $relay->enabled && (int) ($counts[$relay->id] ?? 0) === 0)
                <details class="target-help-details" id="relay-retire-{{ $relay->id }}">
                    <summary>{{ __('Retire and remove Relay') }}</summary>
                    @if (! ($retiredStates[$relay->id] ?? false))
                        <p class="field-help">{{ __('Next: run the Gateway-host cleanup-and-seal-for-delete command with authorized sudo. It retires only the selected Relay local resources and permanently fences old setup commands BEFORE any DB Delete. A disconnected Iran host NEVER blocks this action. Refresh afterward.') }}</p>
                        @if ($hostCommands[$relay->id] ?? null)
                            <div class="field">
                                <label for="relay-retire-command-{{ $relay->id }}">{{ __('One cleanup-and-seal-for-delete command — Gateway host only') }}</label>
                                <textarea id="relay-retire-command-{{ $relay->id }}" rows="7" readonly spellcheck="false" autocomplete="off">{{ $hostCommands[$relay->id]['cleanup'] }}</textarea>
                                <p class="field-help">{{ __('Expected final output: LIFECYCLE FENCE VERIFIED (delete); the first run also prints RETIREMENT VERIFIED. Re-running can renew expired evidence without lifting the fence. Delete remains blocked unless the root-owned fence matches this record. A deletion fence is permanent, so never use it when you intend to edit this registration.') }}</p>
                            </div>
                            <details class="target-help-details">
                                <summary>{{ __('Verified host helper installation, upgrade and preflight') }}</summary>
                                <p class="field-help">{{ __('The Cleanup command installs a missing helper or validates the exact current version; it NEVER replaces an existing helper. The optional upgrade command below explicitly replaces only the one known previous release after verification. Confirm trusted release SHA256 and the application path before any privileged action.') }}</p>
                                <div class="field">
                                    <label for="relay-retire-bootstrap-{{ $relay->id }}">{{ __('One-time verified helper installation') }}</label>
                                    <textarea id="relay-retire-bootstrap-{{ $relay->id }}" rows="3" readonly spellcheck="false" autocomplete="off">{{ $hostCommands[$relay->id]['bootstrap'] }}</textarea>
                                </div>
                                <p class="field-help">{{ __('Helper release SHA256') }}: <code>{{ $hostCommands[$relay->id]['sha256'] }}</code></p>
                                <div class="field">
                                    <label for="relay-retire-upgrade-{{ $relay->id }}">{{ __('Explicit verified helper upgrade — Gateway host only') }}</label>
                                    <textarea id="relay-retire-upgrade-{{ $relay->id }}" rows="5" readonly spellcheck="false" autocomplete="off">{{ $hostCommands[$relay->id]['upgrade'] }}</textarea>
                                    <p class="field-help">{{ __('This is a separate authorized host-wide action, not part of ordinary Cleanup. Run only if the installed tool has the known previous SHA256 :previous. An unknown or modified binary is never replaced. Before upgrading a legacy helper, stop issuing old commands and let all historical operator sessions finish; they do not hold the new shared lock. After upgrading, refresh this page and use only newly generated commands. Compare the destination SHA256 with the trusted release before retrying Cleanup.', ['previous' => $hostCommands[$relay->id]['upgrade_from_sha256']]) }}</p>
                                </div>
                                <div class="field">
                                    <label for="relay-retire-preflight-{{ $relay->id }}">{{ __('Optional read-only local preflight') }}</label>
                                    <textarea id="relay-retire-preflight-{{ $relay->id }}" rows="3" readonly spellcheck="false" autocomplete="off">{{ $hostCommands[$relay->id]['preflight'] }}</textarea>
                                </div>
                                <p class="field-help">{{ __('The helper never performs a remote SSH connection or reaches the Iran server. It refuses unknown systemd, firewall and key namespaces, instead of deleting unrelated resources. It does not provision a new Relay.') }}</p>
                            </details>
                        @else
                            <p class="field-error" role="alert">{{ __('Cannot generate the host cleanup command: the installed helper does not match the release-pinned SHA256 or Relay identity. Restore a verified Gateway release before privileged operations.') }}</p>
                        @endif
                    @else
                        <p class="field-help">{{ __('Gateway-host cleanup and irreversible deletion fence have been verified for this record. Setup commands for this record can no longer run; Iran cleanup is not required. Confirm the final deletion.') }}</p>
                        <form method="post" class="form-stack" action="{{ route('admin.connection-relays.destroy', ['relay' => $relay->id]) }}" autocomplete="off">
                        @csrf
                        @method('DELETE')
                        <input type="hidden" name="relay_revision" value="{{ $relay->lifecycle_revision }}">
                        <div class="field">
                            <label for="relay-confirm-delete-{{ $relay->id }}">{{ __('Type the exact Relay ID to confirm deletion: :id', ['id' => $relay->relay_id]) }}</label>
                            <input id="relay-confirm-delete-{{ $relay->id }}" type="text" name="confirm_relay_id" required maxlength="64" autocomplete="off" spellcheck="false">
                        </div>
                        <label class="checkbox-option">
                            <input type="checkbox" name="confirm_gateway_cleanup" value="1" required>
                            <span>{{ __('I confirm Gateway-host cleanup and irreversible deletion fencing were completed. Iran-side cleanup is optional and does not block deleting this Gateway record.') }}</span>
                        </label>
                        <div class="field">
                            <label for="relay-delete-password-{{ $relay->id }}">{{ __('Current Owner password') }}</label>
                            <input id="relay-delete-password-{{ $relay->id }}" type="password" name="current_password" data-admin-requires-intent autocomplete="current-password" maxlength="255" required>
                        </div>
                        <button class="button button-danger" type="submit">{{ __('Delete verified retired Relay') }}</button>
                        </form>
                    @endif
                </details>
            @elseif ($relay->enabled)
                <p class="field-help">{{ __('Disable this Relay before deleting it. Assigned Targets must also be explicitly detached or reassigned.') }}</p>
            @endif
        </article>
    @empty
        <p class="muted">{{ __('No Relays registered yet. Add one below; it starts disabled and cannot route traffic until the host is verified.') }}</p>
    @endforelse
</section>

<section class="panel panel-wide" aria-labelledby="relay-add-heading">
    <h2 id="relay-add-heading">{{ __('Add Connection Relay') }}</h2>
    <p class="field-help">{{ __('Give this reusable route a stable name, control endpoint and independently verified public SSH host key.') }}</p>
    <form class="form-stack" method="post" action="{{ route('admin.connection-relays.store') }}" autocomplete="off">
        @csrf
        @include('admin.connection-relays.partials.fields', ['prefix' => 'add', 'editing' => false, 'relay' => null])
        <div class="field">
            <label for="relay-add-password">{{ __('Current Owner password') }}</label>
            <input id="relay-add-password" type="password" name="current_password" data-admin-requires-intent autocomplete="current-password" maxlength="255" required>
        </div>
        <button class="button button-primary" type="submit">{{ __('Register disabled Relay') }}</button>
        <p class="field-help">{{ __('No tunnel, firewall rule or Target authorization is created by this action.') }}</p>
    </form>
</section>
@endsection
