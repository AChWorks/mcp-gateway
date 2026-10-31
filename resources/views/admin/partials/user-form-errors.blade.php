@if ($hasSubmittedRestrictions ?? session()->hasOldInput())
    <div class="alert alert-error" role="alert" data-user-save-failed>
        <strong>{{ ($editingUser ?? false) ? __('User changes were not saved.') : __('User was not created.') }}</strong>
        <p>{{ __('The checked restriction boxes below are an unsaved draft, not the saved account permissions. Correct the failed submission and save again.') }}</p>
        @if ($errors->any())
            <ul>
                @foreach ($errors->all() as $message)
                    <li>{{ $message }}</li>
                @endforeach
            </ul>
        @endif
    </div>
@endif
