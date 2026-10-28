# Breach Clock

A turn-based SOC defense game that runs entirely in your browser. You are the on-call analyst investigating an invoice phishing incident. Read causal telemetry, write small detection rules, and contain the attacker without shutting down the company.

**[Play Breach Clock](https://jevgenijostin.github.io/breach-clock/)** · [Build notes](BUILD-NOTES.md)

## How to play

1. Read the briefing and known business workflows. Advance the quiet first tick.
2. Inspect current-tick telemetry for free. Spend **1 AP** to query historical events, deploy a rule, isolate a host, or reset an account. You receive **3 AP per tick**; unused AP does not carry over.
3. A broad detection is a lead, not a verdict. Compare **parent_process** and **command_line** for Office-spawned PowerShell; compare **source_host** for network logons; compare destinations for large transfers.
4. Contain the root and any established remote sessions. Isolation immediately blocks communication. Resets prevent future logons but do not terminate an already-established session. Local processes can still emit records on an isolated host.
5. **End turn** resolves the current transfer attempt, checks outcomes, and advances five game-minutes. There is no real-time timer. Even during the last transfer tick, containment can stop completion before you end the turn.

The query result is capped at 40 rows, newest first. Narrow the host and tick range to find context. Rules back-scan **all collected telemetry**, not just the query result, and continue matching future events. Eight rules can be active. Editing/removing a rule is free; invalid rules or actions cost no AP. Refreshing the page starts a new shift; there is no save/resume feature.

### Outcomes and Trust

- **Evicted:** no live attacker foothold remains after the pending T3 local credential activity. Isolated credentials cannot move without a reachable live source.
- **Survived:** tick 14 ends without completed exfiltration, but the attacker retains a legal action. A lower-grade win.
- **Breached:** the Finance archive finishes transferring to `cdn-sync.example`.
- **Fired:** Business Trust reaches zero or below. This takes precedence if both loss conditions occur in the same turn.

Trust starts at 100 and never increases. Clean host isolation costs: ordinary workstation −10, finance workstation −25, WS-05 −25, FS-01 −25, BKP-01 −30, APP-01 −35, ADM-01 −20, DC-01 −50. Resetting a clean workflow credential (`dana` or `svc-backup`) costs 10. Compromised hosts and stolen credentials cost zero, as required by the scenario; this means the Trust change itself supplies some information. The UI never labels a live host compromised or gives live TP/FP scores.

Grades: **A** for eviction by T4 with Trust ≥90 and no false isolations; **B** for other eviction with Trust ≥60 and at most two false isolations; **C** for other eviction or survival; **D** for either loss. After-action shows the true path, visible clue IDs linked to raw events, your queries/actions, final active rules' TP/FP counts, and the complete telemetry sequence.

## Detection DSL

Hand-written tokenizer → validated AST → pure evaluator. No JavaScript evaluation.

```text
process_name = "powershell.exe"
process_name = "powershell.exe" AND parent_process = "winword.exe"
event_type = "logon" AND host = "FS-01"
command_line contains "-enc"
bytes > 50000000 AND dest_domain != "offsite-backup.example"
```

| Fields                                                                                                  | Type    | Operators                       |
| ------------------------------------------------------------------------------------------------------- | ------- | ------------------------------- |
| event_type, host, user, process_name, parent_process, command_line, source_host, dest_host, dest_domain | String  | `=`, `!=`, `contains`           |
| logon_type, bytes, tick                                                                                 | Integer | `=`, `!=`, `>`, `<`, `>=`, `<=` |

Strings must use double quotes; all string matches and field names ignore case. Strings have no escape syntax. Join clauses with `AND`; multiple rules provide alternatives. Missing fields never match, including `!=`. Integers must be safe integers. Unknown fields, wrong types and invalid syntax return an error with a one-based character position and do not spend AP.

No regex, OR/NOT within a rule, parentheses, temporal correlation, aggregation, YAML/Sigma import, or arbitrary code. PIDs, logon IDs, opaque session IDs and timestamps are inspectable raw context but are not DSL fields. Event types are `process`, `logon`, and `network`; DNS/domain activity is represented within `network`.

## Invoice scenario and seeds

Exactly ten hosts: WS-01 through WS-05, FS-01, APP-01, DC-01, ADM-01 and BKP-01. Users: chen, eli, bo, dana, svc-backup and t.nowak. The attack moves through phishing foothold, credential access/lateral movement, and staging/exfiltration. Two business workflows create lookalikes: finance refresh and nightly backup/offsite upload.

Three free seeds retain the same chain and clue guarantees:

| Seed    | Patient zero (spoiler) | Finance workstation |
| ------- | ---------------------- | ------------------- |
| EMBER-1 | WS-03                  | WS-05               |
| EMBER-2 | WS-01                  | WS-04               |
| EMBER-3 | WS-02                  | WS-05               |

Standard: foothold T2, credentials T3, dwell T4–5, lateral T6, staging T7–8, transfer T9–11. The backup logon is within ±1 tick of lateral movement; its upload overlaps the primary transfer. Attacker and benign streams are separately seeded; changing noise cannot change the attack sequence. Opaque IDs may change with event volume.

One alternate route is available when the file-server route is blocked and the root remains live with usable dana credentials: RDP to APP-01 two ticks after the block, staging one tick later, then three transfer ticks. A remote foothold already created must also be isolated. Resetting svc-backup prevents new authentication; it does not revoke an established FS-01 foothold.

**Timing interpretations:** isolation allows the already-started local credential dump at T3, matching the authored early winning trace. A fallback triggered after T8 cannot finish its specified six-tick sequence inside a 14-tick Standard shift. This build preserves both the fallback delays and the hard horizon, producing Survived when applicable. Blocking at the primary lateral window permits fallback Breached losses for every released seed. These choices resolve contradictory portions of the brief rather than silently accelerating the route.

## Free / Analyst Pack

**Free:** all actions, full DSL, complete after-action replay, three fixed seeds, Standard profile.

**Analyst Pack (demo Pro):** Fast Operator profile, custom seed entry and shareable setup URLs, rule-set JSON export, after-action JSON export. Fast Operator uses the same scenario, removes dwell, moves laterally at T4, stages at T5, transfers at T6–7, and emits denser benign activity. Its fallback uses a two-tick transfer. All three released seeds pass early/late win and both loss policies in both profiles. Arbitrary custom seeds use the same structural schedule but are not an exhaustively validated seed catalog.

Generate a key, open **Analyst Pack**, and paste the signed output:

```sh
npm run gen-key
```

Demo licensing: not secure. No payment integration or real license enforcement.

`src/license.ts` mirrors the CoverBoard/PlayBoard WebCrypto HMAC-SHA-256 pattern. The deliberately inspectable `DEMO_SECRET` signs `{version, tier:"paid", issuedAt, licenseId}`. The key is stored in `breachclock.license.v1` in localStorage and reverified on load. Activation is asynchronous; deactivation removes it. This is a product demonstration, not access control. No accounts, backend, external API calls or analytics. Asset requests stay on the site's origin; external documentation links open only when followed.

Rule-set JSON import is free: open the import control, load a version-1 rules file, choose a validated definition, then deploy it for the usual 1 AP. Import accepts at most eight rules and never bypasses the AP or active-rule limits. Shared URLs encode the setup, not a replay of player actions.

## Run and verify

Use Node 24 LTS or newer and npm:

```sh
npm ci
npm run dev
npm run typecheck
npm run lint
npm test
npx playwright install chromium
npm run test:e2e
npm run build
```

Vite serves under `/breach-clock/`. The UI uses TypeScript and CSS with no UI framework. Engine and DSL modules have no DOM dependency. Vitest covers parsing, action semantics, containment, causal ordering, separate streams, deterministic replay, clue access, overlap, and policy traces. Two full event/outcome snapshots are regression checks, not correctness proofs. Playwright runs production-build browser smoke flows, licensing/export checks and mobile/no-external-request checks.

GitHub Actions checks Ubuntu and Windows, then deploys the main branch to GitHub Pages. This night-project intentionally commits directly to main. See [BUILD-NOTES.md](BUILD-NOTES.md) for verification evidence and manual walkthrough observations.

## Honest limitations

One authored scenario; tiny DSL; telemetry is stylized, not a faithful ATT&CK emulation. Difficulty has not been validated with real players. Hard profile is parameters on the same scenario. No backend/accounts/leaderboards yet. No scenario editor, additional techniques or richer telemetry families. Game truth is withheld by the UI, but a pure client-side game cannot keep its source or memory secret.

Tests establish mechanical solvability, not fairness for real players or realism of telemetry. The recorded manual plays were agent-operated browser walkthroughs, not independent human playtesting. The briefing and affordances still need evaluation by unfamiliar players. No cross-browser, assistive-technology or exhaustive custom-seed certification is claimed.

MIT licensed.
