@php($hasRejectedDraft = $hasSubmittedRestrictions ?? session()->hasOldInput())
@if ($hasRejectedDraft || $errors->any())
    <div class="alert alert-error" role="alert" data-user-save-failed data-admin-feedback tabindex="-1" autofocus>
        <strong>{{ ($editingUser ?? false) ? __('User changes were not saved.') : __('User was not created.') }}</strong>
        @if ($hasRejectedDraft)
            <p>{{ __('The checked restriction boxes below are an unsaved draft, not the saved account permissions. Correct the failed submission and save again.') }}</p>
        @else
            <p>{{ __('Review the validation errors below. No account changes were saved.') }}</p>
        @endif
        @if ($errors->any())
            <ul>
                @foreach ($errors->all() as $message)
                    <li>{{ $message }}</li>
                @endforeach
            </ul>
        @endif
    </div>
@endif
