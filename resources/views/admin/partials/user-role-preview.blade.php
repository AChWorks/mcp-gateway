{{-- Native, read-only Role preview for browsers without JavaScript.
     GET never changes the account; the subsequent normal CSRF-protected
     User create/update form remains the only mutation. --}}
<noscript>
    <div class="panel-note">
        <p>{{ __('JavaScript is disabled. First preview the Role whose restrictions you want to edit, then complete and save the form below. Opening another preview discards unsaved form changes.') }}</p>
        <div class="action-row">
            @foreach ($roles as $previewRole)
                <a class="button button-secondary"
                    href="{{ route($previewRoute, [...$previewRouteParameters, 'preview_role' => $previewRole->value]) }}"
                    @if ($selectedUserRole === $previewRole) aria-current="page" @endif>
                    {{ \Illuminate\Support\Str::headline($previewRole->value) }}
                </a>
            @endforeach
        </div>
    </div>
</noscript>
