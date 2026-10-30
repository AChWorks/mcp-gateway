@can('wordpress.abilities.execute.readonly', $target)
    <section class="panel panel-wide" aria-labelledby="wordpress-bridge-info-title">
        <h2 id="wordpress-bridge-info-title">{{ __('WordPress operations') }}</h2>
        <p class="field-help">{{ __('First shared Admin/AI operation: inspect the selected WordPress Bridge without granting mutating, destructive or unclassified ability execution.') }}</p>
        <form method="post" action="{{ route('admin.targets.wordpress.bridge-info', ['target' => $target->target_id]) }}">
            @csrf
            <button class="button button-secondary" type="submit">{{ __('Inspect Bridge information (read-only)') }}</button>
        </form>
    </section>
@endcan
