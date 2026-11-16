# Console v3 results (branch console-new, based on integration-7)

Console UX for four backend features that had no UI. Screenshots (light and dark) are in `docs/screenshots/console-v3/`.

## What was built
| Feature | Where | Data source |
|---|---|---|
| Releases: channels, versions, test evidence, Promote flow | Operations > Releases (`/releases`) | new read-only `GET /releases` (repo tree + signer records); promote creates a `release.promote` plan |
| Release diff in Approvals | Approvals > plan detail | plan params compared with the target channel; approver count from the plan list |
| Controller role banner | every page when `/readyz` says standby or fenced | `/readyz` (role, epoch, replication lag) |
| Controller card | System | `GET /system` `controller` block (role, epoch, replication, last promotion) |
| Scope-change approver count | Proxmox endpoint > change scope | `GET /approvals/policy` before submit; the plan's own `approvals_required` after submit. Risk is the backend preview risk. Nothing is computed in the browser |
| Bootstrap health | Deployment detail, "Guest start-up" | new `GET /deployments/{slug}/bootstrap` (pending, reported, enrolled, sealed, expired, revoked, failed; replay alarm from the audit trail; rate-limited from the callback limiter) |

New backend settings (optional, unset = the Releases page says it is not connected): `ICS_RELEASE_REPO_DIR` (served signed repo tree), `ICS_RELEASE_RECORDS_DIR` (signer `records/`, read access for the ics user). Promotion itself still requires `ICS_RELEASE_PROMOTE_CMD`.

## Gates
- Frontend: `vue-tsc` clean, vitest 143 passed (16 new in `consolev3.test.ts`), `vite build` ok.
- Backend full suite: 873 passed, 2 failed. The two failures are `test_golden_image.py::test_the_ubuntu_profile_refuses_a_wrong_pin...` and `test_review5.py::test_l7_upstream_must_be_pinned_fresh...`; both are image-recipe pin/freshness checks unrelated to this change and not touched by it (no files of theirs were modified). New tests: `tests/test_console_api.py` (5 tests, all pass).
- e2e (`ics/e2e/run.sh`): 437 passed + 27 passed (flows), 0 failed, 84 skipped (desktop-only / viewport skips by design). New spec `09b-console-v3.spec.ts`; `releases` added to the route list and IA (Operations > Releases replaces the Planned "Updates" item). Axe findings found in the first run (contrast, scrollable regions, unexplained disabled button) were fixed; one moderate landmark-name finding remained after the second run and is fixed by naming the table region per channel.

## Honest limits
- A standby serves its own static page for browser requests, so the full console cannot load on a standby (sign-in needs writes). The banner therefore mainly appears on a fenced primary, or if the standby guard is ever relaxed. In e2e the standby and fenced cases are produced by answering `/readyz` in the browser with the real response shape; the banner logic is unit-tested.
- The e2e does not drive the scope-change drawer (needs a Proxmox endpoint); the approver-count logic is unit-tested and `/approvals/policy` is checked live.
- Replay-alarm and rate-limited bootstrap states are covered by the backend test and vitest, not by e2e (the alarm needs a replayed valid proof).
- The Releases page needs the two settings above; the e2e launcher sets them to a fixture repo tree in the same layout as the signer's output.
