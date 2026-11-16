# `docs/progress.json` — public roadmap & progress feed

Stable URL for the website: `https://raw.githubusercontent.com/agit8or1/office-unbound/main/docs/progress.json`
Human view: [`ROADMAP.md`](../ROADMAP.md) (generated — run `python3 scripts/render_roadmap.py`; CI fails if it is stale).

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `office-unbound-progress/1` — bump on breaking changes |
| `updated` | ISO date | last edit of the feed |
| `stage` | string | overall project stage |
| `current_version` | string | product version (SemVer); must equal the repo-root `VERSION` file (validated in CI) |
| `releases[]` | object | newest first: `version` (SemVer, unique), `date`, `status` (`prepared` \| `released` \| `yanked`), `highlights[]`, `notes_url` (https), optional `channel`, `changelog`. Bundled into `BUILD_INFO.json` at install time so ICS can show "pending updates" offline (ADR-0011) |
| `summary` | string | one-paragraph public summary |
| `status_values` | object | machine status key → display label (ADR-0000 values + `blocked` + `deferred` — owner-deferred work that must not start before its stated condition) |
| `principles` | string[] | product principles |
| `phases[]` | object | `id`, `name`, `status`, `items[]` |
| `phases[].items[]` | object | `id` (unique), `title`, `status`, `evidence[]` (repo paths, validated to exist), optional `note` |
| `acceptance[]` | object | first-demo acceptance tests: `id`, `title`, `status`, optional `note`, optional `evidence[]` |
| `known_limitations` | string[] | limitations we state publicly |

Rules: a status may only move forward with evidence in the repo (ADR-0000). `integrated_lab` = demonstrated in the isolated lab; nothing is `alpha` or later until there is a release.
