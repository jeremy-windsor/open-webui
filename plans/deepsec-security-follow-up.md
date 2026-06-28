# DeepSec Security Follow-up Plan

Date: 2026-06-28

## #1 Decide whether this fork is maintained

This is a public fork and DeepSec produced a large matcher surface: 116 candidate files / 729 candidate hits. These are **not AI-confirmed findings yet**; they are the fast scan queue. Do not start patching random warnings until we decide whether this fork is meant to be maintained or should simply be synced/archived/deleted.

If the fork is maintained, run a full DeepSec AI process pass and triage before code changes.

Initial candidate clusters:

1. `secret-in-log` — 420 hits. Review logging paths for accidental token/API-key/user-data logging.
2. `py-fastapi-route` — 94 hits. Review auth boundaries on backend routes.
3. `ssrf` — 44 hits. Review URL fetch/proxy/import paths.
4. `insecure-crypto` — 29 hits. Separate real crypto from harmless hashing/random UI use.
5. `dangerous-html` / `xss` — review frontend HTML injection sinks.
6. `untrusted-redirect-following` — review fetch/redirect behavior around user-controlled URLs.

Working rule: if this fork is not actively deployed or maintained, the repair plan is to reduce exposure by syncing with upstream or removing the fork, not to carry a private security patch queue forever. That road ends in a swamp with invoices.
