# MCP Gateway Admin UI Quality Standard

**Scope:** Every current and future Gateway Administration page (Targets, Users, Target Groups, AI clients, Operations, Activity, Connection and authentication). This is the durable review checklist for new UI, modifications and regression fixes; it does not authorize production deployment. The source of implementation truth is [admin.css](../public/css/admin.css) and existing [Blade views](../resources/views/admin). Keep changes consistent with [Development](DEVELOPMENT.md#admin-ui-foundation).

## Shared visual and spacing rules

- Use the shared `--ui-*` tokens for color, text, surfaces, borders, radii, controls and focus. Add a new token only for a genuinely reused rule; no duplicate page-specific palettes or local components that conflict with shared CSS.
- **No touching independent cards:** adjacent top-level `.panel` surfaces inside `.main-content` must have at least `--ui-panel-stack-gap` (currently **1.25rem**) of block-axis breathing room. This includes both "Display and identity" / "Connection settings" in Edit Target **and** unrelated stacked pages such as AI clients. Maintain one shared selector `.main-content > .panel + .panel`, not view-specific margins for each occurrence.
- Distinguish major sections (separate panels), subordinate groups (e.g. `.target-subsection` within a panel) and fields (`.field`). A border between internal fields is not a substitute for spacing between cards. Use shared `.form-stack` or `.form-grid`, not manual `<br>` gaps or arbitrary inline styles.
- A page title and its action/navigation row must remain separate from cards. Respect established page-heading, table, alert and pagination spacing without doubling their margins. Use logical properties such as `margin-block-start` and `padding-inline` so direction changes do not break the layout.
- Buttons are visually and functionally grouped near their action; primary actions are distinguishable, secondary navigation is consistent, destructive actions have deliberate confirmation. Do not stack an unbroken wide control set across narrow screens.

## Responsive, legible and accessible states

- Inspect at a narrow phone width (360–390px), tablet (768px), and wide desktop (at least 1280px) when rendering is available. Two-column fields become a single column before labels/inputs collide. Inputs, long URLs, host keys and identifiers must not overflow or create horizontal scrolling outside explicitly scrollable tables/navigation.
- Use semantic heading order, visible labels, clear field help, effective error messages and keyboard-operable form controls. Keep visible `:focus-visible`, full-label checkbox targets and sufficient text/background contrast. Never rely only on color to convey connected/error/danger/disabled states.
- Show actionable failures, status and recovery guidance with safe correlation IDs. No raw secrets, access tokens, passwords, private keys or remote HTTP bodies in UI/log diagnostics. Error, pending, empty, loading and saved states should not shift controls into unreadable or overlapping positions.
- Keep the optional Add Target endpoint preflight control and status in the shared enrollment action area, available for each explicitly supported connector; it must not be hidden inside one connector panel or imply a successful network preflight verifies authentication or the remote system identity. A successful check must identify its exact checked subject, and changing the selected connector or any checked endpoint field must invalidate that result with an accessible status announcement.
- Verify both light and dark media preference, reduced-motion setting, longest realistic localized text, and RTL-compatible layout when relevant. Keep text wrapping, sufficient touch targets and readable monospace/code snippets.
- Preserve server-rendered Blade, escaped output, CSRF, per-user/Target permissions, redaction, Owner password reauthentication and the current security/transport boundaries. UI polish must not silently relax behavior.

## Acceptance and durable regression discipline

1. Identify which shared layout class/token owns a visible problem. **Fix that one shared rule**; review every view using it for side effects. Do not bury a repeated issue with a special class on the latest page.
2. Include the specific reproduced state (e.g. two adjacent top-level panels, long SSH host, inline error, restricted Owner permissions) in the smallest applicable PHPUnit/feature regression. `tests/Feature/Admin/AdminUiPresentationTest.php` protects shared stylesheet and markup contracts.
3. Validate CSS syntax/changed-source assertions and relevant Admin feature tests. For visual changes, inspect actual browser geometry at desktop and mobile when a safe test session is available; check independent card gaps, focus, overflow, contrast and both theme variants. Mark visual browser testing **NOT TESTED** if it cannot be run; CSS grep is not a screenshot test.
4. In review, explicitly compare the touched screen **and at least one sibling surface** reusing the same component. Record deviations that are required vs future polish; do not create a heavy CI/browser requirement solely for cosmetic changes, but never label untested visuals as verified.
5. Do not change public release tags or deployed operator installations as part of a stylesheet/documentation fix. Follow the repository's exact-source validation, review, integration and release approval gates.
