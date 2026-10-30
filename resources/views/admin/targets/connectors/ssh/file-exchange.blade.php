@if ($sshHasCredential)
    @canany(['ssh.file.read', 'ssh.file.write'], $target)
        <section class="panel panel-wide" aria-labelledby="ssh-browser-file-title">
            <div class="section-heading">
                <div>
                    <div class="eyebrow">{{ __('Authenticated browser file handoff') }}</div>
                    <h2 id="ssh-browser-file-title">{{ __('SSH file upload and download') }}</h2>
                </div>
            </div>
            @if ($target->operations_paused)
                <p class="muted">{{ __('SSH browser upload and download are unavailable while this Target is paused.') }}</p>
            @elseif (config('ssh.file_transfer.enabled', false) === true)
                <p class="muted">{{ __('Select an actual local file in this browser for an SSH Target. ChatGPT message attachments do not automatically reach MCP tools. Remote file limits and SSH OS-account permissions still apply.') }}</p>
                @if ($errors->has('file_exchange'))
                    <p class="target-recovery-warning" role="alert">{{ $errors->first('file_exchange') }}</p>
                @endif
                @can('ssh.file.write', $target)
                    <form method="post" enctype="multipart/form-data" class="form-stack" action="{{ route('admin.targets.ssh-files.upload', ['target' => $target->target_id]) }}">
                        @csrf
                        <h3>{{ __('Upload local file to SSH Target') }}</h3>
                        <label>{{ __('Choose a local file') }}
                            <input type="file" name="local_file" required>
                        </label>
                        <label>{{ __('Absolute remote destination path') }}
                            <input name="destination" type="text" required maxlength="1024" autocomplete="off" placeholder="/home/account/uploads/document.bin">
                        </label>
                        <label>{{ __('Pre-created private remote staging directory (0700)') }}
                            <input name="private_staging_dir" type="text" required maxlength="1024" autocomplete="off" placeholder="/home/account/.gateway-private-transfer">
                        </label>
                        <p class="field-help">{{ __('Create this private directory in advance under the authenticated remote SSH account and verify mode 0700. No file data is sent if staging is missing or unsafe. Large uploads require sufficient PHP and proxy body limits.') }}</p>
                        <label><input type="checkbox" name="overwrite" value="1"> {{ __('Allow atomic replacement if destination already exists (last writer wins)') }}</label>
                        <button type="submit" class="button button-primary">{{ __('Upload and verify SHA-256') }}</button>
                    </form>
                @endcan
                @can('ssh.file.read', $target)
                    <form method="post" class="form-stack" action="{{ route('admin.targets.ssh-files.download', ['target' => $target->target_id]) }}">
                        @csrf
                        <h3>{{ __('Download SSH file to this browser') }}</h3>
                        <label>{{ __('Absolute remote source path') }}
                            <input type="text" name="path" required maxlength="1024" autocomplete="off" placeholder="/home/account/reports/report.zip">
                        </label>
                        <button type="submit" class="button button-secondary">{{ __('Download verified file') }}</button>
                    </form>
                @endcan
                <p class="field-help">{{ __('Downloads are forced as attachments with content sniffing disabled; verify reported size and SHA-256. Interrupted transfers are not resumable. Failed writes must be inspected before retry.') }}</p>
            @else
                <p class="muted">{{ __('Whole-file browser exchange is disabled on this Gateway. It requires an explicitly approved SSH_FILE_TRANSFER_ENABLED deployment change; bounded SFTP tools remain independent.') }}</p>
            @endif
        </section>
    @endcanany
@endif
