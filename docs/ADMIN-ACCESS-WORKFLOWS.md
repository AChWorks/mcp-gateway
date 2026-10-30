# Admin group and Target assignment workflows

The Owner-only access workspace uses the existing role, global-denial, group and direct-Target rules. The interface does not introduce another permission model or a public MCP access-management API.

## Find the correct context

- **Target groups:** click a group name to open its current member Targets. The group's **Targets**, **Users** and **Restrictions and settings** destinations share the same context.
- **Users:** open a user's **Targets** or **Groups** directly. Account and global restrictions remain separately reachable.
- **Create a group:** enter its name and confirm the current password. Advanced capability restrictions are optional. Continue to its member list to select Targets and users.

A member list starts with assigned items. **Add Targets**, **Add users** or **Assign groups** opens the available list. Search, connector filtering and 50-row pages avoid loading a full fleet into the browser.

## Select explicit items

Use native row checkboxes. **Select this page** covers eligible rows on that page, never all matching or future items. One operation accepts at most 100 explicit identities; this bounds a transaction, not the size of a fleet.

The server keeps a temporary selection per acting account, subject, operation and intent. Search, paging, **View selected** and **Review selected changes** submit the current page's checkboxes before continuing and retain choices on other pages. Native navigation without JavaScript follows the same path. The small progressive initializer updates the visible count and page-selection convenience only; it does not authorize or apply a change.

Changing a direct-Target action starts a new selection from the current page. Drafts expire after one hour, retain at most eight contexts, and contain no password. Selection is not a permission grant. Deleted or otherwise unavailable saved identifiers can be removed individually from the draft.

## Review and apply once

The review names the exact selected items, current and requested states, changed/unchanged counts, and relevant SSH or publishing consequences. The encrypted review expires after ten minutes and is bound to the actor, context, intent, immutable identities and reviewed state.

Enter the current password once to apply the reviewed batch. Relevant SSH changes also require explicit acknowledgement. All selected changes apply together or none do. Missing, stale, blocked or unavailable selections are not silently omitted.

A password error retains the exact existing review and never retains the password. A changed or expired review returns to the saved selection for an explicit new review. Opening a newer review invalidates an older review in another tab; the old tab cannot apply a different selection.

If the browser cannot confirm completion, reopen the member list and inspect saved state before creating another review. The interface never automatically replays an uncertain mutation.

## Interpret access correctly

- Group membership can supply reachability for **Selected targets** users. It does not grant a capability missing from the role or global ceiling.
- Group denials accumulate, and a direct Target deny still wins. Removing one group membership does not promise loss of access through another group or All targets scope.
- **Allow direct reachability**, **Deny direct reachability** and **Use inherited reachability** preserve each Target's existing capability denials. Normal bulk Allow does not silently replace an existing direct Deny; use its individual advanced editor to review that exception.
- A scope source is not a complete effective-capability simulation. Disabled accounts remain disabled; All/Selected scope, AI access and global SSH denials are not changed by membership selection. Owners retain unrestricted recovery access.
- Restriction checkboxes visibly say **Deny**. Checked means blocked, not granted.
- Existing group publishing grants may include a Target added to their named dynamic group. Removing a user from a group also removes that membership's publishing grants; reassignment does not restore them automatically.

The application services own fresh authorization, lock ordering, review-state comparison and required transactional Activity for each changed relationship. Controller/session selection and browser controls cannot waive those checks.
