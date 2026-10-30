<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AccessBatchWorkflow;
use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Admin\TargetConnectorAdmin;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\TargetGroup;
use App\Http\Controllers\Controller;
use App\Models\User;
use DomainException;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;

/** Native draft selection and review transport; the workflow owns access decisions. */
final class AccessBatchController extends Controller
{
    private const SESSION_KEY = 'admin_access_batches';

    private const REVIEW_KEY = 'admin_access_batch_review';

    /** @var array<string, array{route:string, parameter:string, noun:string, add:string}> */
    private const CONTEXTS = [
        'group-targets' => ['route' => 'admin.target-groups.targets.index', 'parameter' => 'targetGroup', 'noun' => 'Targets', 'add' => 'Add Targets'],
        'group-users' => ['route' => 'admin.target-groups.users.index', 'parameter' => 'targetGroup', 'noun' => 'Users', 'add' => 'Add users'],
        'user-groups' => ['route' => 'admin.users.groups.index', 'parameter' => 'user', 'noun' => 'Groups', 'add' => 'Assign groups'],
        'user-targets' => ['route' => 'admin.users.targets.index', 'parameter' => 'user', 'noun' => 'Targets', 'add' => 'Add Targets'],
    ];

    public function groupTargets(Request $request, TargetGroup $targetGroup, AccessBatchWorkflow $workflow, TargetConnectorAdmin $connectors): View
    {
        return $this->collection($request, $workflow, $connectors, 'group-targets', (string) $targetGroup->getKey());
    }

    public function groupUsers(Request $request, TargetGroup $targetGroup, AccessBatchWorkflow $workflow, TargetConnectorAdmin $connectors): View
    {
        return $this->collection($request, $workflow, $connectors, 'group-users', (string) $targetGroup->getKey());
    }

    public function userGroups(Request $request, User $user, AccessBatchWorkflow $workflow, TargetConnectorAdmin $connectors): View
    {
        return $this->collection($request, $workflow, $connectors, 'user-groups', (string) $user->getKey());
    }

    public function userTargets(Request $request, User $user, AccessBatchWorkflow $workflow, TargetConnectorAdmin $connectors): View
    {
        return $this->collection($request, $workflow, $connectors, 'user-targets', (string) $user->getKey());
    }

    public function selection(Request $request, string $context, string $subject, AccessBatchWorkflow $workflow): RedirectResponse
    {
        $actor = $this->actor($request);
        $this->context($context);
        $filters = $this->filters($request);
        $intent = $this->intent($request, $context, $filters['membership']);
        $fields = $request->validate([
            'page_ids' => ['nullable', 'array', 'max:50'],
            'page_ids.*' => ['string', 'max:64', 'regex:/\\A[a-zA-Z0-9]+\\z/D'],
            'selected_ids' => ['nullable', 'array', 'max:100'],
            'selectable_ids' => ['nullable', 'array', 'max:50'],
            'selectable_ids.*' => ['string', 'max:64', 'regex:/\\A[a-zA-Z0-9]+\\z/D'],
            'unavailable_ids' => ['nullable', 'array', 'max:100'],
            'unavailable_ids.*' => ['string', 'max:64', 'regex:/\\A[a-zA-Z0-9]+\\z/D'],
            'selected_ids.*' => ['string', 'max:64', 'regex:/\\A[a-zA-Z0-9]+\\z/D'],
            'shown_intent' => ['nullable', 'string', 'max:16'],
            'shown_membership' => ['nullable', Rule::in(['members', 'available', 'all', 'selected'])],
            'action' => ['required', Rule::in(['save', 'filter', 'previous', 'next', 'selected', 'members', 'clear', 'select-page', 'review'])],
        ]);
        $pageIds = array_values(array_unique($fields['page_ids'] ?? []));
        $checked = array_values(array_unique($fields['selected_ids'] ?? []));
        $unavailable = array_values(array_unique($fields['unavailable_ids'] ?? []));
        $selectable = array_values(array_unique($fields['selectable_ids'] ?? []));
        if (array_diff($checked, [...$pageIds, ...$unavailable]) !== [] || array_diff($selectable, $pageIds) !== []) {
            throw ValidationException::withMessages(['selection' => __('Select only the rows displayed on this page.')]);
        }

        $action = (string) $fields['action'];
        $shownMembership = (string) ($fields['shown_membership'] ?? $filters['membership']);
        $existing = ($fields['shown_intent'] ?? $intent) === $intent
            ? $this->selectionIds($request, $actor, $context, $subject, $intent) : [];
        $ids = $action === 'clear' ? [] : array_values(array_unique([
            ...array_diff($existing, [...$pageIds, ...$unavailable]),
            ...($action === 'select-page' ? [...$selectable, ...array_diff($checked, $selectable)] : $checked),
        ]));
        if (count($ids) > 100) {
            throw ValidationException::withMessages([
                'selection' => __('Select at most 100 items for one change. Your previous saved selection is unchanged.'),
            ]);
        }

        // Authorize the context and validate the subject before writing even a draft.
        $workflow->page($actor, $context, $subject, ['page' => 1, 'membership' => 'all'], []);
        $request->session()->forget(self::REVIEW_KEY);
        $this->saveSelection($request, $actor, $context, $subject, $intent, $ids);

        if ($action === 'review') {
            if ($ids === []) {
                return redirect($this->collectionUrl($context, $subject, [...$filters, 'intent' => $intent]))
                    ->withErrors(['selection' => __('Select at least one item to review.')]);
            }
            try {
                $preview = $workflow->review($actor, $context, $subject, $intent, $ids);
            } catch (DomainException $exception) {
                return $this->selectionError($exception, $context, $subject, [...$filters, 'intent' => $intent]);
            }
            $nonce = (string) Str::uuid();
            // Store exactly the reviewed snapshot. Rendering or password errors never restamp it.
            $request->session()->put(self::REVIEW_KEY, [
                'id' => $nonce,
                'actor' => (string) $actor->getKey(),
                'context' => $context,
                'subject' => $subject,
                'preview' => $preview,
            ]);

            return redirect()->route('admin.access-batches.review', [
                'context' => $context, 'subject' => $subject, 'review' => $nonce,
            ]);
        }

        $filters['page'] = match ($action) {
            'filter', 'selected', 'members' => 1,
            'previous' => max(1, $filters['page'] - 1),
            'next' => $filters['page'] + 1,
            default => $filters['page'],
        };
        if ($action === 'selected') {
            $filters['membership'] = 'selected';
        } elseif ($action === 'members') {
            $filters['membership'] = 'members';
        }

        // Opening the basket reveals all saved identities, regardless of the
        // search/connector fields that happened to be on the previous page.
        if ($action === 'selected' || ($action === 'filter'
            && $filters['membership'] === 'selected' && $shownMembership !== 'selected')) {
            $filters['search'] = '';
            $filters['connector_type'] = '';
        }

        $nextIntent = $intent;
        if ($context !== 'user-targets' && ($action === 'members'
            || ($action === 'filter' && $filters['membership'] !== $shownMembership
                && in_array($filters['membership'], ['members', 'available'], true)))) {
            $nextIntent = $filters['membership'] === 'available' ? 'add' : 'remove';
        }

        return redirect($this->collectionUrl($context, $subject, [...$filters, 'intent' => $nextIntent]));
    }

    public function review(Request $request, string $context, string $subject, string $review): View
    {
        $actor = $this->actor($request);
        $saved = $this->storedReview($request, $actor, $context, $subject, $review);
        $this->navigationContext($request, $context);

        return view('admin.access-batches.review', [
            'context' => $context,
            'subjectId' => $subject,
            'preview' => $saved['preview'],
            'reviewId' => $review,
            'collectionUrl' => $this->collectionUrl($context, $subject, [
                'membership' => 'selected', 'intent' => $saved['preview']['intent'],
            ]),
        ]);
    }

    public function apply(Request $request, string $context, string $subject, AccessBatchWorkflow $workflow, AdministratorPasswordConfirmation $confirmation): RedirectResponse
    {
        $actor = $this->actor($request);
        $fields = $request->validate([
            'review_id' => ['required', 'uuid'],
            'confirm_ssh_changes' => ['nullable', 'boolean'],
        ]);
        $saved = $this->storedReview($request, $actor, $context, $subject, (string) $fields['review_id']);
        $preview = $saved['preview'];
        $confirmation->confirm($request);

        try {
            $result = $workflow->apply($actor, $context, $subject, (string) $preview['token'], $request->boolean('confirm_ssh_changes'));
        } catch (DomainException $exception) {
            if ($exception->getMessage() === 'ssh_confirmation_required') {
                return redirect()->route('admin.access-batches.review', [
                    'context' => $context, 'subject' => $subject, 'review' => $saved['id'],
                ])->withErrors(['confirm_ssh_changes' => __('Review the SSH impact and explicitly confirm it before applying these changes.')]);
            }
            $request->session()->forget(self::REVIEW_KEY);

            return $this->selectionError($exception, $context, $subject, [
                'membership' => 'selected', 'intent' => $preview['intent'],
            ]);
        }

        $this->saveSelection($request, $actor, $context, $subject, (string) $preview['intent'], []);
        $request->session()->forget(self::REVIEW_KEY);

        return redirect($this->collectionUrl($context, $subject))
            ->with('status', __('Changes saved: :changed changed, :unchanged already in the requested state.', [
                'changed' => $result['changed_count'], 'unchanged' => $result['unchanged_count'],
            ]));
    }

    private function collection(Request $request, AccessBatchWorkflow $workflow, TargetConnectorAdmin $connectors, string $context, string $subject): View
    {
        $actor = $this->actor($request);
        $this->navigationContext($request, $context);
        $filters = $this->filters($request);
        $intent = $this->intent($request, $context, $filters['membership']);
        $ids = $this->selectionIds($request, $actor, $context, $subject, $intent);
        $data = $workflow->page($actor, $context, $subject, $filters, $ids);
        $onPage = array_intersect($ids, [...array_column($data['items'], 'id'), ...($data['unavailable_ids'] ?? [])]);

        return view('admin.access-batches.index', [
            'context' => $context,
            'subjectId' => $subject,
            'data' => $data,
            'filters' => $filters,
            'intent' => $intent,
            'selectedIds' => $ids,
            'offPageCount' => count($ids) - count($onPage),
            'collectionUrl' => $this->collectionUrl($context, $subject),
            'addUrl' => $this->collectionUrl($context, $subject, [
                'membership' => 'available', 'intent' => $context === 'user-targets' ? 'allow' : 'add',
            ]),
            'membersUrl' => $this->collectionUrl($context, $subject),
            'labels' => $this->context($context),
            'connectorOptions' => str_ends_with($context, '-targets') ? $connectors->options() : [],
        ]);
    }

    private function navigationContext(Request $request, string $context): void
    {
        $this->context($context);
        $request->attributes->set('admin.navigation.route', str_starts_with($context, 'group-')
            ? 'admin.target-groups.targets.index' : 'admin.users.targets.index');
    }

    private function actor(Request $request): User
    {
        Gate::authorize(GatewayPermission::UsersManage->value);
        $actor = $request->user();
        abort_unless($actor instanceof User, 401);

        return $actor;
    }

    /** @return array{page:int,search:string,membership:string,connector_type:string} */
    private function filters(Request $request): array
    {
        $fields = $request->validate([
            'page' => ['nullable', 'integer', 'min:1', 'max:1000000'],
            'search' => ['nullable', 'string', 'max:160'],
            'membership' => ['nullable', Rule::in(['members', 'available', 'all', 'selected'])],
            'connector_type' => ['nullable', 'string', 'max:64'],
        ]);

        return [
            'page' => (int) ($fields['page'] ?? 1),
            'search' => trim((string) ($fields['search'] ?? '')),
            'membership' => (string) ($fields['membership'] ?? 'members'),
            'connector_type' => (string) ($fields['connector_type'] ?? ''),
        ];
    }

    private function intent(Request $request, string $context, string $membership): string
    {
        $allowed = $context === 'user-targets' ? ['allow', 'deny', 'inherit'] : ['add', 'remove'];
        $default = $context === 'user-targets'
            ? ($membership === 'available' ? 'allow' : 'deny')
            : ($membership === 'available' ? 'add' : 'remove');
        $fields = $request->validate(['intent' => ['nullable', Rule::in($allowed)]]);

        return (string) ($fields['intent'] ?? $default);
    }

    /** @return array{route:string,parameter:string,noun:string,add:string} */
    private function context(string $context): array
    {
        abort_unless(isset(self::CONTEXTS[$context]), 404);

        return self::CONTEXTS[$context];
    }

    /** @param array<string, mixed> $query */
    private function collectionUrl(string $context, string $subject, array $query = []): string
    {
        $metadata = $this->context($context);

        return route($metadata['route'], [$metadata['parameter'] => $subject, ...$query]);
    }

    private function basketKey(User $actor, string $context, string $subject, string $intent): string
    {
        return hash('sha256', $actor->getKey().'|'.$context.'|'.$subject.'|'.$intent);
    }

    /** @return list<string> */
    private function selectionIds(Request $request, User $actor, string $context, string $subject, string $intent): array
    {
        $baskets = $request->session()->get(self::SESSION_KEY, []);
        $basket = is_array($baskets) ? ($baskets[$this->basketKey($actor, $context, $subject, $intent)] ?? []) : [];
        if (! is_array($basket) || (int) ($basket['updated_at'] ?? 0) < now()->subHour()->timestamp) {
            return [];
        }
        $ids = $basket['ids'] ?? [];

        return is_array($ids) ? array_values(array_filter($ids, 'is_string')) : [];
    }

    /** @param list<string> $ids */
    private function saveSelection(Request $request, User $actor, string $context, string $subject, string $intent, array $ids): void
    {
        $baskets = $request->session()->get(self::SESSION_KEY, []);
        $baskets = is_array($baskets) ? $baskets : [];
        $baskets = array_filter($baskets, static fn (mixed $basket): bool => is_array($basket)
            && (int) ($basket['updated_at'] ?? 0) >= now()->subHour()->timestamp);
        uasort($baskets, static fn (array $a, array $b): int => ($a['updated_at'] ?? 0) <=> ($b['updated_at'] ?? 0));
        $key = $this->basketKey($actor, $context, $subject, $intent);
        unset($baskets[$key]);
        $baskets[$key] = ['ids' => $ids, 'updated_at' => now()->timestamp];
        $request->session()->put(self::SESSION_KEY, array_slice($baskets, -8, null, true));
    }

    /** @return array<string,mixed> */
    private function storedReview(Request $request, User $actor, string $context, string $subject, string $nonce): array
    {
        $this->context($context);
        $saved = $request->session()->get(self::REVIEW_KEY);
        $current = is_array($saved)
            && ($saved['actor'] ?? null) === (string) $actor->getKey()
            && ($saved['context'] ?? null) === $context
            && ($saved['subject'] ?? null) === $subject
            && is_string($saved['id'] ?? null)
            && hash_equals($saved['id'], $nonce)
            && is_array($saved['preview'] ?? null);
        if (! $current) {
            throw new HttpResponseException(redirect($this->collectionUrl($context, $subject))
                ->withErrors(['selection' => __('This review is no longer current. Review the selection again; no change was applied by this request.')]));
        }

        return $saved;
    }

    /** @param array<string,mixed> $query */
    private function selectionError(DomainException $exception, string $context, string $subject, array $query): RedirectResponse
    {
        $message = match ($exception->getMessage()) {
            'batch_invalid_context' => __('This access operation is unavailable. Return to the relevant group or user.'),
            'batch_invalid_selection' => __('Select between 1 and 100 valid items, then review the change again.'),
            'batch_selection_unavailable' => __('A selected item is no longer available. Review the selected list and remove unavailable items. Nothing was changed.'),
            'batch_review_invalid', 'batch_review_expired' => __('This review has expired or is no longer valid. Your selection is kept; review it again before saving.'),
            'batch_review_stale' => __('Membership or access settings changed after your review. Nothing was changed. Review the current state before confirming again.'),
            'batch_blocked' => __('This selection contains a blocked change. Review the listed restrictions or use the individual advanced editor. Nothing was changed.'),
            'owner_unrestricted' => __('Owners retain unrestricted recovery access and cannot receive narrowing assignments.'),
            default => null,
        };
        if ($message === null) {
            throw $exception;
        }

        return redirect($this->collectionUrl($context, $subject, $query))->withErrors(['selection' => $message]);
    }
}
