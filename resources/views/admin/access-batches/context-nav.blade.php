@php($isGroupContext = str_starts_with($context, 'group-'))
<nav class="section-nav" aria-label="{{ $isGroupContext ? __('Group sections') : __('User access sections') }}">
    @if ($isGroupContext)
        <a href="{{ route('admin.target-groups.targets.index', ['targetGroup' => $subject['id']]) }}" @if ($context === 'group-targets') aria-current="page" @endif>{{ __('Targets') }}</a>
        <a href="{{ route('admin.target-groups.users.index', ['targetGroup' => $subject['id']]) }}" @if ($context === 'group-users') aria-current="page" @endif>{{ __('Users') }}</a>
        <a href="{{ route('admin.target-groups.edit', ['targetGroup' => $subject['id']]) }}" @if ($context === 'group-restrictions') aria-current="page" @endif>{{ __('Restrictions and settings') }}</a>
    @else
        <a href="{{ route('admin.users.targets.index', ['user' => $subject['id']]) }}" @if ($context === 'user-targets') aria-current="page" @endif>{{ __('Targets') }}</a>
        <a href="{{ route('admin.users.groups.index', ['user' => $subject['id']]) }}" @if ($context === 'user-groups') aria-current="page" @endif>{{ __('Groups') }}</a>
        <a href="{{ route('admin.users.edit', ['user' => $subject['id']]) }}" @if ($context === 'user-account') aria-current="page" @endif>{{ __('Account and restrictions') }}</a>
    @endif
</nav>
