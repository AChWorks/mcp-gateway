# Repository instructions for development agents

GitHub source, Issues, approved releases and current CI own facts about what is merged, published or actually deployed. This file is a **repository-wide development rule**, not permission to merge, publish, modify operator hosts or access secrets.

## Any Admin UI or stylesheet change

1. Read [Admin UI Quality Standard](docs/ADMIN-UI-QUALITY.md) and the Admin UI foundation in [Development](docs/DEVELOPMENT.md#admin-ui-foundation).
2. Reuse `public/css/admin.css` tokens and existing Blade/HTML components. Repair shared spacing and layout rules at the shared level. **Never solve repeated adjacent-panel collisions by adding one-off per-page margin hacks.**
3. Keep light/dark, keyboard focus, semantic headings/labels, compact/mobile layout, input validation, destructive-action confirmations, and readable error/empty/loading states. Follow the existing access and CSRF boundaries.
4. Review the affected page **and sibling pages reusing the component**. Check 360–390px mobile, 768px tablet and wide desktop layouts when rendering tools are available; test narrow/long content and state variations as appropriate.
5. Add or update the smallest meaningful regression in `tests/Feature/Admin/AdminUiPresentationTest.php` (plus relevant functional tests). CSS source assertions alone are **not** proof of a visual browser pass; report any unperformed visual acceptance explicitly.
6. Update the quality standard only when the shared rule changes. Do not add unrelated refactors, duplicate CSS systems, unsupported automated screenshot claims, or unreviewed auth/OAuth/permission behavior.

For all other changes, follow the authoritative project docs and required GitHub review/release gates. No source commit or Release changes an installed production host automatically.
