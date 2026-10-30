<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

final class AccessBatchAdminTest extends TestCase
{
    use RefreshDatabase;

    public function test_group_names_open_current_members_and_creation_leads_to_the_member_list(): void
    {
        $this->actingAs($this->owner());
        $group = TargetGroup::query()->create(['name' => 'Production']);
        $member = $this->target('member');
        $other = $this->target('other');
        $group->targets()->attach($member);
        $this->get('/admin/target-groups?search=Production')->assertOk()
            ->assertSee(route('admin.target-groups.targets.index', ['targetGroup' => $group->id]), false);
        $this->get('/admin/target-groups?search=Missing')->assertOk()->assertSee('No groups match this search.');

        $this->get($this->collection('group-targets', $group->id))->assertOk()
            ->assertSee($member->display_name)->assertDontSee($other->display_name)
            ->assertSee('Group sections')->assertSee('Restrictions and settings')->assertSee('Add Targets');
        $this->get($this->collection('group-targets', $group->id, ['membership' => 'available']))->assertOk()
            ->assertSee($other->display_name)->assertDontSee($member->display_name);

        $response = $this->post('/admin/target-groups', ['name' => 'New group', 'current_password' => 'CorrectHorse!234']);
        $created = TargetGroup::query()->where('name', 'New group')->firstOrFail();
        $response->assertRedirect(route('admin.target-groups.targets.index', ['targetGroup' => $created->id]));
    }

    public function test_native_paging_preserves_explicit_choices_and_applies_only_the_three_reviewed_targets(): void
    {
        Http::preventStrayRequests();
        $this->actingAs($this->owner());
        $group = TargetGroup::query()->create(['name' => 'Native batch']);
        for ($i = 0; $i < 55; $i++) {
            $this->target(sprintf('fleet-%03d', $i));
        }
        $first = $this->page('group-targets', $group->id, ['membership' => 'available', 'intent' => 'add']);
        self::assertCount(50, $first['items']);
        $firstIds = array_column($first['items'], 'id');
        $selected = array_slice($firstIds, 0, 2);
        $next = $this->post($this->selection('group-targets', $group->id), [
            'page_ids' => $firstIds, 'selectable_ids' => $firstIds, 'selected_ids' => $selected,
            'intent' => 'add', 'shown_intent' => 'add', 'membership' => 'available', 'page' => 1, 'action' => 'next',
        ])->assertRedirect();
        $second = $this->get($next->headers->get('Location'))->assertOk()->viewData('data');
        self::assertCount(5, $second['items']);
        self::assertSame(2, $second['selected_count']);
        $lastId = $second['items'][0]['id'];
        $saved = $this->review('group-targets', $group->id, [$lastId], [
            'page' => 2, 'page_ids' => array_column($second['items'], 'id'),
        ]);
        self::assertEqualsCanonicalizing([...$selected, $lastId], $saved['preview']['ids']);
        $this->get($this->reviewUrl($saved))->assertOk()->assertSee('3 changes');
        self::assertSame(0, $group->targets()->count());

        $this->post($this->applyUrl('group-targets', $group->id), [
            'review_id' => $saved['id'], 'current_password' => 'CorrectHorse!234',
        ])->assertRedirect($this->collection('group-targets', $group->id))->assertSessionHasNoErrors();
        self::assertEqualsCanonicalizing([...$selected, $lastId], $group->targets()->pluck('targets.id')->all());
        Http::assertNothingSent();
    }

    public function test_search_and_selected_view_keep_the_saved_basket_without_selecting_search_matches(): void
    {
        $this->actingAs($this->owner());
        $group = TargetGroup::query()->create(['name' => 'Search context']);
        $first = $this->target('chosen');
        $other = $this->target('unchosen');
        $response = $this->post($this->selection('group-targets', $group->id), [
            'page_ids' => [$first->id, $other->id], 'selected_ids' => [$first->id],
            'membership' => 'available', 'intent' => 'add', 'shown_intent' => 'add',
            'search' => 'no-matching-name', 'action' => 'filter',
        ])->assertRedirect();
        $filtered = $this->get($response->headers->get('Location'))->assertOk();
        self::assertSame([], $filtered->viewData('data')['items']);
        $filtered->assertSee('Your saved selection is kept.')->assertSee('Saved selection: 1');
        $selected = $this->page('group-targets', $group->id, ['membership' => 'selected', 'intent' => 'add']);
        self::assertSame([$first->id], array_column($selected['items'], 'id'));
        self::assertSame(0, $group->targets()->count());
    }

    public function test_native_select_page_is_bounded_and_an_over_limit_draft_does_not_replace_the_saved_selection(): void
    {
        $this->actingAs($this->owner());
        $group = TargetGroup::query()->create(['name' => 'Bounded selection']);
        for ($i = 0; $i < 105; $i++) {
            $this->target(sprintf('bound-%03d', $i));
        }
        $ids = [];
        for ($page = 1; $page <= 2; $page++) {
            $data = $this->page('group-targets', $group->id, ['membership' => 'available', 'intent' => 'add', 'page' => $page]);
            $pageIds = array_column($data['items'], 'id');
            $this->post($this->selection('group-targets', $group->id), [
                'page_ids' => $pageIds, 'selectable_ids' => $pageIds, 'selected_ids' => [],
                'membership' => 'available', 'intent' => 'add', 'page' => $page, 'action' => 'select-page',
            ])->assertRedirect()->assertSessionHasNoErrors();
            $ids = [...$ids, ...$pageIds];
        }
        self::assertCount(100, $ids);
        $third = $this->page('group-targets', $group->id, ['membership' => 'available', 'intent' => 'add', 'page' => 3]);
        $thirdIds = array_column($third['items'], 'id');
        $this->post($this->selection('group-targets', $group->id), [
            'page_ids' => $thirdIds, 'selectable_ids' => $thirdIds,
            'membership' => 'available', 'intent' => 'add', 'page' => 3, 'action' => 'select-page',
        ])->assertSessionHasErrors('selection');
        $selected = $this->page('group-targets', $group->id, ['membership' => 'selected', 'intent' => 'add']);
        self::assertSame(100, $selected['selected_count']);
        self::assertSame(0, $group->targets()->count());
    }

    public function test_password_errors_keep_the_exact_review_and_changed_state_requires_an_explicit_new_review(): void
    {
        $this->actingAs($this->owner());
        $group = TargetGroup::query()->create(['name' => 'Review snapshot']);
        $target = $this->target('reviewed');
        $saved = $this->review('group-targets', $group->id, [$target->id]);
        $token = $saved['preview']['token'];
        $this->from($this->reviewUrl($saved))->post($this->applyUrl('group-targets', $group->id), [
            'review_id' => $saved['id'], 'current_password' => 'WrongPassword!234',
        ])->assertSessionHasErrors('current_password');
        self::assertSame($token, session('admin_access_batch_review')['preview']['token']);
        self::assertFalse(session()->hasOldInput('current_password'));

        DB::table('target_group_permission_denials')->insert([
            'target_group_id' => $group->id, 'permission' => GatewayPermission::WordpressAbilitiesExecuteMutating->value,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $this->get($this->reviewUrl($saved))->assertOk();
        self::assertSame($token, session('admin_access_batch_review')['preview']['token']);
        $this->post($this->applyUrl('group-targets', $group->id), [
            'review_id' => $saved['id'], 'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('selection');
        self::assertNull(session('admin_access_batch_review'));
        self::assertSame(0, $group->targets()->count());
        self::assertSame(1, $this->page('group-targets', $group->id, ['membership' => 'selected', 'intent' => 'add'])['selected_count']);
    }

    public function test_an_older_review_from_another_tab_cannot_apply_or_replace_the_newer_review(): void
    {
        $this->actingAs($this->owner());
        $first = TargetGroup::query()->create(['name' => 'First tab']);
        $second = TargetGroup::query()->create(['name' => 'Second tab']);
        $target = $this->target('tabs');
        $old = $this->review('group-targets', $first->id, [$target->id]);
        $new = $this->review('group-targets', $second->id, [$target->id]);
        $this->post($this->applyUrl('group-targets', $first->id), [
            'review_id' => $old['id'], 'current_password' => 'CorrectHorse!234',
        ])->assertRedirect($this->collection('group-targets', $first->id))->assertSessionHasErrors('selection');
        self::assertSame($new['id'], session('admin_access_batch_review')['id']);
        self::assertSame(0, $first->targets()->count());
        self::assertSame(0, $second->targets()->count());
    }

    public function test_a_deleted_saved_identity_can_be_removed_from_the_draft_without_clearing_other_choices(): void
    {
        $this->actingAs($this->owner());
        $group = TargetGroup::query()->create(['name' => 'Unavailable selection']);
        $missing = $this->target('gone');
        $kept = $this->target('kept');
        $this->post($this->selection('group-targets', $group->id), [
            'page_ids' => [$missing->id, $kept->id], 'selected_ids' => [$missing->id, $kept->id],
            'membership' => 'available', 'intent' => 'add', 'action' => 'save',
        ])->assertRedirect();
        $missingId = $missing->id;
        $missing->delete();
        $selected = $this->page('group-targets', $group->id, ['membership' => 'selected', 'intent' => 'add']);
        self::assertContains($missingId, $selected['unavailable_ids']);
        $this->post($this->selection('group-targets', $group->id), [
            'page_ids' => [$kept->id], 'unavailable_ids' => [$missingId], 'selected_ids' => [$kept->id],
            'membership' => 'selected', 'intent' => 'add', 'action' => 'save',
        ])->assertRedirect()->assertSessionHasNoErrors();
        self::assertSame(1, $this->page('group-targets', $group->id, ['membership' => 'selected', 'intent' => 'add'])['selected_count']);
    }

    public function test_user_centric_group_assignment_uses_one_review_and_preserves_the_user_scope(): void
    {
        $this->actingAs($this->owner());
        $user = $this->person();
        $first = TargetGroup::query()->create(['name' => 'User first']);
        $second = TargetGroup::query()->create(['name' => 'User second']);
        $this->get($this->collection('user-groups', (string) $user->id))->assertOk()
            ->assertSee('User access sections')->assertSee('Assign groups');
        $saved = $this->review('user-groups', (string) $user->id, [$first->id, $second->id]);
        $this->post($this->applyUrl('user-groups', (string) $user->id), [
            'review_id' => $saved['id'], 'current_password' => 'CorrectHorse!234',
        ])->assertRedirect()->assertSessionHasNoErrors();
        self::assertSame(2, DB::table('target_group_users')->where('user_id', $user->id)->count());
        self::assertSame(TargetScopeMode::Selected, $user->refresh()->target_scope_mode);
        self::assertFalse($user->ai_access_enabled);
    }

    public function test_normal_bulk_allow_shows_an_explicit_deny_as_blocked_and_keeps_advanced_rules_reachable(): void
    {
        $this->actingAs($this->owner());
        $user = $this->person();
        $target = $this->target('explicit-deny');
        DB::table('user_target_access')->insert([
            'user_id' => $user->id, 'target_record_id' => $target->id, 'allowed' => false,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $saved = $this->review('user-targets', (string) $user->id, [$target->id], ['intent' => 'allow', 'shown_intent' => 'allow']);
        self::assertFalse($saved['preview']['can_apply']);
        $this->get($this->reviewUrl($saved))->assertOk()->assertSee('blocked change')
            ->assertSee('Open individual Target rules')->assertSee('disabled', false)
            ->assertSee(route('admin.users.targets.edit', ['user' => $user->id, 'target' => $target->target_id]), false);
        $this->get(route('admin.users.targets.edit', ['user' => $user->id, 'target' => $target->target_id]))
            ->assertOk()->assertSee($target->display_name)->assertSee($target->target_id)->assertSee('Explicit scope rule');
        $this->post($this->applyUrl('user-targets', (string) $user->id), [
            'review_id' => $saved['id'], 'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('selection');
        self::assertFalse((bool) DB::table('user_target_access')->where('user_id', $user->id)->value('allowed'));
    }

    public function test_ssh_review_is_only_shown_when_required_and_missing_confirmation_keeps_the_review(): void
    {
        $this->actingAs($this->owner());
        $group = TargetGroup::query()->create(['name' => 'SSH review']);
        $target = $this->target('ssh-reviewed', 'ssh_direct');
        $saved = $this->review('group-targets', $group->id, [$target->id]);
        self::assertTrue($saved['preview']['requires_ssh_confirmation']);
        $this->get($this->reviewUrl($saved))->assertOk()->assertSee('confirm_ssh_changes', false)
            ->assertSee('Adding or removing memberships can change SSH reachability')
            ->assertDontSee('direct Target scope changes');
        $this->post($this->applyUrl('group-targets', $group->id), [
            'review_id' => $saved['id'], 'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('confirm_ssh_changes');
        self::assertSame($saved['preview']['token'], session('admin_access_batch_review')['preview']['token']);
        $this->post($this->applyUrl('group-targets', $group->id), [
            'review_id' => $saved['id'], 'current_password' => 'CorrectHorse!234', 'confirm_ssh_changes' => '1',
        ])->assertRedirect()->assertSessionHasNoErrors();
        self::assertSame(1, $group->targets()->count());
    }

    public function test_non_owner_cannot_read_or_store_an_access_selection(): void
    {
        $group = TargetGroup::query()->create(['name' => 'Owner only']);
        $this->actingAs($this->person());
        $this->get($this->collection('group-targets', $group->id))->assertForbidden();
        $this->post($this->selection('group-targets', $group->id), [
            'action' => 'save', 'membership' => 'members', 'intent' => 'remove',
        ])->assertForbidden();
        self::assertNull(session('admin_access_batches'));
    }

    public function test_switching_direct_action_starts_from_this_page_without_inheriting_hidden_selections(): void
    {
        $this->actingAs($this->owner());
        $user = $this->person();
        $first = $this->target('intent-first');
        $hidden = $this->target('intent-hidden');
        foreach ([['allow', $first], ['deny', $hidden]] as [$intent, $target]) {
            $this->post($this->selection('user-targets', (string) $user->id), [
                'page_ids' => [$target->id], 'selected_ids' => [$target->id],
                'membership' => 'all', 'intent' => $intent, 'shown_intent' => $intent, 'action' => 'save',
            ])->assertRedirect()->assertSessionHasNoErrors();
        }
        $saved = $this->review('user-targets', (string) $user->id, [$first->id], [
            'membership' => 'all', 'intent' => 'deny', 'shown_intent' => 'allow',
        ]);
        self::assertSame([$first->id], $saved['preview']['ids']);
        self::assertSame('deny', $saved['preview']['intent']);
    }

    public function test_saved_drafts_and_reviews_cannot_be_reused_by_another_acting_account(): void
    {
        $firstOwner = $this->owner();
        $secondOwner = User::query()->create([
            'name' => 'Second Owner', 'email' => 'second-owner@example.test', 'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner, 'target_scope_mode' => TargetScopeMode::All, 'access_enabled' => true,
        ]);
        $group = TargetGroup::query()->create(['name' => 'Actor binding']);
        $target = $this->target('actor-bound');
        $this->actingAs($firstOwner);
        $saved = $this->review('group-targets', $group->id, [$target->id]);
        $this->actingAs($secondOwner);
        self::assertSame(0, $this->page('group-targets', $group->id, ['membership' => 'selected', 'intent' => 'add'])['selected_count']);
        $this->post($this->applyUrl('group-targets', $group->id), [
            'review_id' => $saved['id'], 'current_password' => 'CorrectHorse!234',
        ])->assertRedirect()->assertSessionHasErrors('selection');
        self::assertSame(0, $group->targets()->count());
    }

    public function test_view_selected_clears_search_connector_and_page_after_saving_current_page_choices(): void
    {
        $this->actingAs($this->owner());
        $group = TargetGroup::query()->create(['name' => 'Visible saved basket']);
        $this->target('a-ssh-selected', 'ssh_direct');
        for ($i = 0; $i < 54; $i++) {
            $this->target(sprintf('basket-%03d', $i));
        }
        $firstPage = $this->get($this->collection('group-targets', $group->id, ['membership' => 'available', 'intent' => 'add']))->assertOk();
        $firstPage->assertSee('name="shown_membership" value="available"', false);
        $first = $firstPage->viewData('data');
        $firstIds = array_column($first['items'], 'id');
        $savedIds = array_slice($firstIds, 0, 2);
        $next = $this->post($this->selection('group-targets', $group->id), [
            'page_ids' => $firstIds, 'selected_ids' => $savedIds,
            'intent' => 'add', 'shown_intent' => 'add', 'shown_membership' => 'available',
            'membership' => 'available', 'page' => 1, 'action' => 'next',
        ])->assertRedirect();
        $second = $this->get($next->headers->get('Location'))->assertOk()->viewData('data');
        $newlyChecked = $second['items'][0]['id'];
        $response = $this->post($this->selection('group-targets', $group->id), [
            'page_ids' => array_column($second['items'], 'id'), 'selected_ids' => [$newlyChecked],
            'intent' => 'add', 'shown_intent' => 'add', 'shown_membership' => 'available',
            'membership' => 'available', 'page' => 2, 'search' => 'no-matching-name',
            'connector_type' => 'wp_ai_bridge', 'action' => 'selected',
        ])->assertRedirect();
        $selected = $this->get($response->headers->get('Location'))->assertOk();
        self::assertSame('', $selected->viewData('filters')['search']);
        self::assertSame('', $selected->viewData('filters')['connector_type']);
        self::assertSame(1, $selected->viewData('data')['page']);
        self::assertSame('add', $selected->viewData('intent'));
        self::assertEqualsCanonicalizing([...$savedIds, $newlyChecked], array_column($selected->viewData('data')['items'], 'id'));
        self::assertSame(3, $selected->viewData('data')['selected_count']);
        self::assertSame(0, $group->targets()->count());
    }

    public function test_membership_filters_keep_the_explicit_basket_and_only_deliberate_members_or_available_transitions_change_intent(): void
    {
        $this->actingAs($this->owner());
        $group = TargetGroup::query()->create(['name' => 'Intent-preserving views']);
        $target = $this->target('saved-add-choice');
        $this->target('other-choice');
        $this->post($this->selection('group-targets', $group->id), [
            'page_ids' => [$target->id], 'selected_ids' => [$target->id],
            'membership' => 'available', 'shown_membership' => 'available',
            'intent' => 'add', 'shown_intent' => 'add', 'action' => 'save',
        ])->assertRedirect()->assertSessionHasNoErrors();
        $toSelected = $this->post($this->selection('group-targets', $group->id), [
            'membership' => 'selected', 'shown_membership' => 'available',
            'intent' => 'add', 'shown_intent' => 'add', 'search' => 'no-matching-name',
            'connector_type' => 'ssh_direct', 'action' => 'filter',
        ])->assertRedirect();
        $selected = $this->get($toSelected->headers->get('Location'))->assertOk();
        self::assertSame('add', $selected->viewData('intent'));
        self::assertSame([$target->id], array_column($selected->viewData('data')['items'], 'id'));
        self::assertSame('', $selected->viewData('filters')['search']);
        self::assertSame('', $selected->viewData('filters')['connector_type']);

        $withinSelected = $this->post($this->selection('group-targets', $group->id), [
            'page_ids' => [$target->id], 'selected_ids' => [$target->id],
            'membership' => 'selected', 'shown_membership' => 'selected',
            'intent' => 'add', 'shown_intent' => 'add', 'search' => 'intentional-no-match', 'action' => 'filter',
        ])->assertRedirect();
        $filtered = $this->get($withinSelected->headers->get('Location'))->assertOk();
        self::assertSame('add', $filtered->viewData('intent'));
        self::assertSame('intentional-no-match', $filtered->viewData('filters')['search']);
        self::assertSame([], $filtered->viewData('data')['items']);
        self::assertSame(1, $filtered->viewData('data')['selected_count']);

        foreach ([['all', 'selected', 'add', 1], ['members', 'all', 'remove', 0], ['available', 'members', 'add', 1]] as [$view, $shown, $nextIntent, $count]) {
            $currentIntent = $shown === 'members' ? 'remove' : 'add';
            $response = $this->post($this->selection('group-targets', $group->id), [
                'membership' => $view, 'shown_membership' => $shown,
                'intent' => $currentIntent, 'shown_intent' => $currentIntent, 'action' => 'filter',
            ])->assertRedirect();
            $page = $this->get($response->headers->get('Location'))->assertOk();
            self::assertSame($nextIntent, $page->viewData('intent'));
            self::assertSame($count, $page->viewData('data')['selected_count']);
        }
        self::assertSame(0, $group->targets()->count());
    }

    public function test_direct_ssh_scope_review_explains_inheritance_without_membership_wording_or_new_acknowledgement_defaults(): void
    {
        $this->actingAs($this->owner());
        $user = $this->person();
        $target = $this->target('ssh-direct-scope-copy', 'ssh_direct');
        DB::table('user_target_access')->insert([
            'user_id' => $user->id, 'target_record_id' => $target->id, 'allowed' => true,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $saved = $this->review('user-targets', (string) $user->id, [$target->id], [
            'membership' => 'members', 'intent' => 'inherit', 'shown_intent' => 'inherit',
        ]);
        self::assertTrue($saved['preview']['requires_ssh_confirmation']);
        $response = $this->get($this->reviewUrl($saved))->assertOk()
            ->assertSee('direct Target scope changes')
            ->assertSee('Inherit may restore another already-approved access path.')
            ->assertDontSee('Adding or removing memberships can change SSH reachability');
        self::assertSame($saved['preview']['token'], session('admin_access_batch_review')['preview']['token']);
        self::assertSame(1, preg_match('/<input[^>]+id="confirm_ssh_changes"[^>]*>/', $response->getContent(), $input));
        self::assertStringNotContainsString('checked', $input[0]);
        $this->post($this->applyUrl('user-targets', (string) $user->id), [
            'review_id' => $saved['id'], 'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('confirm_ssh_changes');
        self::assertTrue((bool) DB::table('user_target_access')->where('user_id', $user->id)->value('allowed'));
        self::assertSame($saved['preview']['token'], session('admin_access_batch_review')['preview']['token']);
    }

    /** @param array<string,mixed> $query */
    private function collection(string $context, string $subject, array $query = []): string
    {
        [$name, $parameter] = match ($context) {
            'group-targets' => ['admin.target-groups.targets.index', 'targetGroup'],
            'group-users' => ['admin.target-groups.users.index', 'targetGroup'],
            'user-groups' => ['admin.users.groups.index', 'user'],
            'user-targets' => ['admin.users.targets.index', 'user'],
        };

        return route($name, [$parameter => $subject, ...$query]);
    }

    private function selection(string $context, string $subject): string
    {
        return route('admin.access-batches.selection', ['context' => $context, 'subject' => $subject]);
    }

    private function applyUrl(string $context, string $subject): string
    {
        return route('admin.access-batches.apply', ['context' => $context, 'subject' => $subject]);
    }

    /** @param array<string,mixed> $saved */
    private function reviewUrl(array $saved): string
    {
        return route('admin.access-batches.review', [
            'context' => $saved['context'], 'subject' => $saved['subject'], 'review' => $saved['id'],
        ]);
    }

    /** @param array<string,mixed> $query
     * @return array<string,mixed>
     */
    private function page(string $context, string $subject, array $query = []): array
    {
        return $this->get($this->collection($context, $subject, $query))->assertOk()->viewData('data');
    }

    /** @param list<string> $ids
     * @param  array<string,mixed>  $overrides
     * @return array<string,mixed>
     */
    private function review(string $context, string $subject, array $ids, array $overrides = []): array
    {
        $intent = $context === 'user-targets' ? 'allow' : 'add';
        $this->post($this->selection($context, $subject), [
            'page_ids' => $ids, 'selected_ids' => $ids, 'selectable_ids' => $ids,
            'membership' => 'available', 'intent' => $intent, 'shown_intent' => $intent,
            'action' => 'review', ...$overrides,
        ])->assertRedirect()->assertSessionHasNoErrors();

        return session('admin_access_batch_review');
    }

    public function test_review_keeps_exactly_one_current_global_group_or_user_destination(): void
    {
        $this->actingAs($this->owner());
        $group = TargetGroup::query()->create(['name' => 'Navigation context']);
        $target = $this->target('navigation-context');
        $user = $this->person();
        foreach ([
            ['group-targets', (string) $group->id, (string) $target->id, route('admin.target-groups.index')],
            ['user-groups', (string) $user->id, (string) $group->id, route('admin.users.index')],
        ] as [$context, $subject, $item, $destination]) {
            $saved = $this->review($context, $subject, [$item]);
            $html = $this->get($this->reviewUrl($saved))->assertOk()->getContent();
            $document = new \DOMDocument;
            $previous = libxml_use_internal_errors(true);
            $document->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
            $links = (new \DOMXPath($document))->query('//nav[@class="admin-nav"]//a[@aria-current="page"]');
            self::assertCount(1, $links);
            self::assertSame($destination, $links->item(0)->getAttribute('href'));
        }
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Access Owner', 'email' => 'batch-owner@example.test', 'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner, 'target_scope_mode' => TargetScopeMode::All,
            'access_enabled' => true,
        ]);
    }

    private function person(): User
    {
        return User::query()->create([
            'name' => 'Scoped user', 'email' => 'batch-user@example.test', 'password' => 'DifferentHorse!234',
            'role' => GatewayRole::Viewer, 'target_scope_mode' => TargetScopeMode::Selected,
            'access_enabled' => true,
        ]);
    }

    private function target(string $id, string $type = 'wp_ai_bridge'): Target
    {
        return Target::query()->create([
            'target_id' => $id, 'display_name' => 'Target '.$id, 'connector_type' => $type,
        ]);
    }
}
