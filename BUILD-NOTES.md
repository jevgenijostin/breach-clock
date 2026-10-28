# Night 1 — 2026-10-28/29

## Scope shipped

Invoice, ten hosts, three released seeds, Standard and Fast Operator, three attack stages, one conditional RDP fallback, two causal business workflows, DSL/back-scan/alerts, AP/Trust containment, four outcomes, grades, side-by-side after-action and raw replay, demo licensing, custom setup sharing, and rule/after-action JSON exports. No backend or runtime external service.

No cuts. Rule-set import loads validated drafts; each deployment still costs 1 AP. Hard and JSON exports retained because their checks pass.

## Interpretation decisions

- The T2-isolation/T3-dump winning trace requires local activity to finish on an isolated host. Networking is blocked immediately; pending T3 credential work remains local. Eviction is assessed at turn end, no earlier than T3.
- Standard fallback takes six ticks from block through completion. A block later than T8 cannot complete by T14. The game preserves the specified delays and shift horizon, allowing Survived. Branch-only containment at T6 still breaches by T12 on every free seed (Hard: T4 block, T9 breach).
- Resets block new logons, not established remote sessions. After fallback RDP, the late winning policy isolates APP-01 as well as the root. Cutting root + credentials before RDP prevents the remote session entirely. This is stricter than the brief's abbreviated late-policy wording, consistent with the no-live-controlled-host eviction criterion.
- Current-tick feed is free; historical queries cost AP. A query does not itself advance the attacker. Only End turn does, following the hard tick-order invariant.
- Live UI contains no truth tags. Internal workflow/session names were replaced with opaque session IDs during review. Trust deltas still convey information because the requested penalty rule depends on truth.
- Rule review reports final active definitions against all collected telemetry. It does not claim historical precision at deployment time.

## Local verification

- TypeScript typecheck and ESLint.
- 112 Vitest tests: DSL acceptance/rejection and positions; numeric/string semantics; absent fields; back-scan and rule alternatives; AP/rule cap/Trust; deterministic event/outcome equality; parent/source causality and ordering; isolation/reset boundaries; fallback conditions; overlap and clue query visibility; separate streams; all four policy outcomes over 3 seeds × 2 profiles.
- Full winning and losing trace snapshots supplement semantic assertions. Snapshots are not the correctness oracle.
- Playwright production-build smoke: early win and subsequent breach, DSL errors without AP loss, Pro gate, HMAC activation/reload/deactivation, Hard custom setup, download, mobile width, no external requests, validated rule import with normal AP charging, unavailable browser storage, and replay clue links.
- Three manual, agent-operated UI walkthroughs used a persistent Chromium instance, chosen actions, raw-row inspection and screenshots. These were separate from the automated smoke suite. No independent human participated.

## Manual-play observations

1. **EMBER-1, early response:** the broad PowerShell rule showed both WS-05 refresh and WS-03 hidden encoded execution. Refining it to winword left one match; isolated WS-03 at T2, inspected the local dump at T3, reset both credentials, then Evicted / A / Trust 100. The distinction was readable, but preloading the exact winning rule would have given away the task; the starter was changed to the broad rule. Alerts originally fell below the fold at desktop size, so matched alerts now move above the rule editor.
2. **EMBER-2, delayed response:** deployed an encoded-command rule at T6, queried FS-01 logons, identified WS-01, isolated FS-01, reset svc-backup at T7. APP-01 RDP appeared at T8. Querying it plus isolating root and resetting dana used all three AP; APP-01 still staged at T9. Isolating APP-01 then produced Evicted / B / Trust 100. The one-tick benign backup jitter meant the backup lookalike had not arrived at T6, and containment prevented it. Allowed by the authored ±1 window, but this seed makes that ambiguity less visible. Existing-session persistence could surprise new players; it is called out in the briefing and action help.
3. **EMBER-3, wrong end-game response:** at T9, `bytes > 50000000` showed both offsite-backup.example (90 MB) and cdn-sync.example (60 MB). Deliberately isolated BKP-01 and queried DC-01; attacker transfers rose to 95 MB and 130 MB. Ended Breached / D / Trust 70 at T11. The destination distinction was clear, but a broad rule retains historical backup alerts after containment; tick labels are essential. The after-action explicitly says the Finance archive left the company.

## What is not verified

Fairness for unfamiliar real players; realism or ATT&CK fidelity; comprehensive accessibility; Safari/Firefox behavior; exhaustive custom-seed coverage; secure licensing (intentionally absent). No claims that tests measure player comprehension. No game-session persistence across reloads.

## Deployment

Target: https://jevgenijostin.github.io/breach-clock/

CI and live-site verification are recorded after the deployment run completes.
