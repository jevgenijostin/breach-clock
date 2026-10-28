import "./style.css";
import { Game } from "../engine/game";
import {
  hosts,
  users,
  type Event,
  type Host,
  type Profile,
  type User,
} from "../engine/model";
import { seedCodes } from "../engine/scenario";
import {
  loadLicense,
  saveLicense,
  verifyLicense,
  type LicenseState,
} from "../license";

const app = document.querySelector<HTMLDivElement>("#app")!;
let game = new Game();
let license: LicenseState = null;
let queryRows: Event[] | null = null;
let message = "";
let draft = 'process_name = "powershell.exe"';
let editing: number | undefined;
let licenseBusy = false;
let showPack = false;
const queryFilter = { host: "", user: "", event_type: "", from: "1", to: "14" };
const esc = (value: unknown) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
const options = (values: readonly string[], selected = "") =>
  values
    .map(
      (v) => `<option ${v === selected ? "selected" : ""}>${esc(v)}</option>`,
    )
    .join("");
const clock = (tick: number) =>
  `${String(2 + Math.floor(((tick - 1) * 5) / 60)).padStart(2, "0")}:${String(((tick - 1) * 5) % 60).padStart(2, "0")}`;
const disabled = () => (game.outcome || game.ap <= 0 ? "disabled" : "");
function eventTable(rows: Event[], truth?: Set<string>) {
  if (!rows.length)
    return '<p class="empty">No matching telemetry. Try a different context or advance the shift.</p>';
  return `<div class="table-scroll"><table><thead><tr><th>Tick / ID</th><th>Host · user</th><th>Type</th><th>Raw event / context</th></tr></thead><tbody>${rows.map((e) => `<tr ${truth ? `class="${truth.has(e.id) ? "malicious" : "benign"}"` : ""}><td>T${e.tick}<small>${e.id}</small></td><td>${esc(e.host)}<small>${esc(e.user)}</small></td><td>${esc(e.event_type)}${truth ? `<small>${truth.has(e.id) ? "Attacker" : "Benign"}</small>` : ""}</td><td><span class="event-main">${esc(e.event_type === "process" ? `${e.parent_process ? e.parent_process + " → " : ""}${e.process_name}` : e.event_type === "logon" ? `${e.source_host} → ${e.dest_host} · logon ${e.logon_type}` : `${e.host} → ${e.dest_domain ?? e.dest_host}`)}</span><small>${esc(e.command_line ?? (e.bytes !== undefined ? `${Number(e.bytes).toLocaleString()} bytes` : `logon_id=${e.logon_id}`))}</small><details><summary>Raw fields</summary><pre>${esc(JSON.stringify(e, null, 2))}</pre></details></td></tr>`).join("")}</tbody></table></div>`;
}
function pack() {
  return `<section class="pack panel"><div class="panel-heading"><h2>Analyst Pack <span class="badge">${license ? "ACTIVE" : "DEMO PRO"}</span></h2><button id="close-pack" class="quiet">Close</button></div><p>Fast Operator profile, custom seed codes, rule-set and after-action JSON export. The full Standard game, DSL and replay are always free.</p><p class="muted">Demo licensing: not secure. No payments. Generate a key locally with <code>npm run gen-key</code>.</p><label>Demo license key<textarea id="license-key" rows="2" placeholder="Paste a signed demo key" ${licenseBusy ? "disabled" : ""}></textarea></label><div class="button-row"><button id="activate" ${licenseBusy ? "disabled" : ""}>${licenseBusy ? "Verifying…" : "Activate key"}</button>${license ? '<button id="deactivate">Deactivate</button>' : ""}</div></section>`;
}
function render() {
  const v = game.view();
  const report = game.report();
  app.innerHTML = `<header><a class="brand" href="./"><span class="brand-mark">◷</span> BREACH<span>CLOCK</span></a><div class="header-meta">NIGHT 01 <span>/</span> INVOICE <span>/</span> ${esc(v.seed)}</div><button id="pack" class="quiet">${license ? "Analyst Pack · Active" : "Analyst Pack ↗"}</button></header>
  <main><section class="shift-strip"><div><p class="eyebrow">${report ? "SHIFT CLOSED / AFTER-ACTION" : "LIVE SHIFT / ON-CALL ANALYST"}</p><h1>${report ? esc(report.outcome) : "Keep the company online."}</h1><p class="muted">${report ? "The evidence is in. Reconstruct the night." : "Find the intrusion. Contain it before the data leaves."}</p></div><div class="metrics"><div><span class="metric-label">SHIFT CLOCK</span><strong>${clock(v.tick)}</strong><small>TICK ${v.tick} / 14</small></div><div><span class="metric-label">ACTION POINTS</span><strong class="pips" aria-label="${v.ap} action points">${"●".repeat(v.ap)}${"○".repeat(3 - v.ap)}</strong><small>3 PER TURN</small></div><div><span class="metric-label">BUSINESS TRUST</span><strong class="${v.trust <= 35 ? "danger" : ""}">${v.trust}<em>/100</em></strong><meter min="0" max="100" value="${Math.max(0, v.trust)}" aria-label="Business trust"></meter></div></div></section>
  <div id="message" role="status" aria-live="polite" class="notice ${message ? "" : "hidden"}">${esc(message)}</div>
  ${showPack ? pack() : ""}
  ${report ? renderReport(report) : renderPlay(v)}
  <footer><span>BREACH CLOCK / A SIMULATED INCIDENT</span><span>Local-only · No accounts · No analytics</span><a href="https://github.com/jevgenijostin/breach-clock" target="_blank" rel="noreferrer">Source & field guide ↗</a></footer></main>`;
  wire();
}
function renderPlay(v: ReturnType<Game["view"]>) {
  return `<section class="brief panel"><span class="badge">INCIDENT 001</span><p><b>Mail gateway:</b> invoice.docm was delivered to three employees. Unknown opener. Investigate Office-spawned processes and follow their context.</p><details><summary>Shift briefing & controls</summary><p>Each tick is five minutes. Telemetry arrives first; spend up to 3 AP, then end the turn. Query, deploy, isolate and reset each cost 1 AP. Rule edits/removal are free. Invalid actions cost nothing. New rules back-scan all collected telemetry. Rules alert; they never contain automatically.</p><p><b>Known business activity:</b> finance refresh on ${v.finance}, using dana; nightly backup from BKP-01 to FS-01 using svc-backup, then offsite-backup.example. Legacy export tasks may leave credentials cached on workstations.</p><p>Isolation blocks all host communication, but local process records may continue. Resets prevent new logons; existing sessions need isolation. Unnecessary containment damages Trust. Loss: exfiltration completes or Trust reaches zero. Stop all attacker activity to be Evicted; reach tick 14 without a breach to be Survived. Outcomes are evaluated when you end your turn.</p><p>Business costs for clean hosts: WS −10; finance workstation −25; FS −25; BKP −30; APP −35; ADM −20; DC −50. Clean workflow credentials −10. Containing compromised hosts or stolen credentials costs zero. Actions cannot be undone.</p></details></section>
  <div class="console-grid"><aside><section class="panel"><div class="panel-heading"><h2>01 / Fleet</h2><span class="muted">10 HOSTS</span></div><div class="host-grid">${v.hosts.map((h) => `<div class="host ${h.isolated ? "isolated" : ""}"><div><span class="host-dot"></span><b>${h.host}</b></div><small>${h.host === v.finance ? "Finance workstation" : h.host.startsWith("WS") ? "Workstation" : ({ "FS-01": "File server", "APP-01": "Finance app", "DC-01": "Domain controller", "ADM-01": "Admin jump host", "BKP-01": "Backup server" } as Record<string, string>)[h.host]}</small><button data-isolate="${h.host}" ${h.isolated ? "disabled" : disabled()}>${h.isolated ? "Isolated" : "Isolate · 1 AP"}</button></div>`).join("")}</div><p class="muted fine">Dots show connectivity only. No host health verdicts.</p></section><section class="panel"><h2>Credential control</h2><label>Account<select id="credential">${options(users)}</select></label><button id="reset" ${disabled()}>Reset credential · 1 AP</button><p class="muted fine">${v.reset.length ? `Reset: ${v.reset.join(", ")}` : "Reset stops new logons. Isolate established sessions."}</p></section></aside>
  <div class="investigation"><section class="panel"><div class="panel-heading"><h2>02 / Telemetry</h2><span class="badge">${v.eventCount} EVENTS</span></div><form id="query-form"><div class="filters"><label>Host<select id="q-host"><option value="">All hosts</option>${options(hosts, queryFilter.host)}</select></label><label>User<select id="q-user"><option value="">All users</option>${options(users, queryFilter.user)}</select></label><label>Event type<select id="q-type"><option value="">All types</option>${options(["process", "logon", "network"], queryFilter.event_type)}</select></label><label>From tick<input id="q-from" type="number" min="1" max="14" value="${queryFilter.from}"></label><label>To tick<input id="q-to" type="number" min="1" max="14" value="${queryFilter.to}"></label><button ${disabled()}>Query · 1 AP</button></div></form><div class="subheading"><span>${queryRows ? "QUERY RESULTS · NEWEST FIRST · MAX 40" : `CURRENT TICK FEED · T${v.tick}`}</span>${queryRows ? '<button id="live-feed" class="text-button">Return to current tick</button>' : "<span>Query history for context</span>"}</div>${eventTable(queryRows ?? [...v.recent].reverse())}</section></div>
  <aside class="detections"><section class="panel"><div class="panel-heading"><h2>03 / Detections</h2><span class="muted">${v.rules.length} / 8</span></div><label for="rule">${editing ? `Edit rule ${editing} · free` : "New detection rule"}</label><textarea id="rule" rows="5" spellcheck="false">${esc(draft)}</textarea><div class="button-row"><button id="deploy" ${editing ? "" : disabled()}>${editing ? "Save edit · free" : "Deploy rule · 1 AP"}</button>${editing ? '<button id="cancel-edit" class="quiet">Cancel</button>' : ""}</div><details class="dsl-help"><summary>DSL reference</summary><p>Comparisons: <code>= != contains</code>. Integers also support <code>&gt; &lt; &gt;= &lt;=</code>. Join with <code>AND</code>. Strings use double quotes; matches ignore case. Multiple rules act as alternatives.</p><p>Fields: event_type, host, user, process_name, parent_process, command_line, source_host, dest_host, dest_domain, logon_type, bytes, tick.</p><p>No OR, NOT, regex, parentheses, aggregation or JavaScript. Missing fields never match. All detections back-scan existing telemetry.</p></details><div class="rules">${v.rules.map((r) => `<article><code>${esc(r.text)}</code><div><button data-edit="${r.id}" class="text-button">Edit #${r.id}</button><button data-remove="${r.id}" class="text-button">Remove</button></div></article>`).join("")}</div><button id="export-rules" class="quiet export">Export rules ${license ? "↓" : "· Pro 🔒"}</button></section><section class="panel alerts"><div class="panel-heading"><h2>Alerts</h2><span class="badge amber">${v.alerts.length} MATCHES</span></div><p class="muted fine">Matches are leads, not verdicts. Check source host and parent process.</p>${v.alerts.length ? v.alerts.map((a) => `<article class="alert"><div><b>${esc(a.event.host)}</b><span>T${a.event.tick} · ${a.event.id} · R${a.rules.join(", R")}</span></div><code>${esc(a.event.command_line ?? `${a.event.dest_domain ?? a.event.source_host} · ${a.event.bytes ?? a.event.logon_type}`)}</code><details><summary>Matching raw event</summary><pre>${esc(JSON.stringify(a.event, null, 2))}</pre></details></article>`).join("") : '<div class="empty"><span class="radar">◎</span>No rules have matched.<br>Deploy a detection to start watching.</div>'}</section></aside></div>
  <section class="turn-bar"><div><b>${v.ap ? `${v.ap} AP remaining` : "Actions spent"}</b><span>Ending the turn resolves transfers and advances five minutes. Unspent AP is lost.</span></div><button id="end-turn" class="primary">End turn <span>→</span></button></section>
  <section class="setup panel"><label>Next shift seed<select id="seed">${options(seedCodes, v.seed)}</select></label><label>Profile<select id="profile"><option>Standard</option><option ${v.profile === "Fast Operator" ? "selected" : ""}>Fast Operator</option></select></label><label>Custom seed ${license ? "" : "· Pro 🔒"}<input id="custom-seed" maxlength="64" placeholder="e.g. NIGHT-SHIFT"></label><button id="restart" class="quiet">Start new shift</button><button id="share" class="quiet">Share seed ${license ? "↗" : "· Pro 🔒"}</button></section>`;
}
function renderReport(r: NonNullable<ReturnType<Game["report"]>>) {
  const seen = new Set(r.actions.flatMap((a) => a.eventIds ?? []));
  const text = {
    Evicted: "Attacker evicted. No live foothold remains.",
    Survived:
      "The shift ended before the transfer completed. The attacker still has a live foothold.",
    Breached:
      "DATA EXFILTRATED. The Finance archive left the company for cdn-sync.example.",
    Fired:
      "ACCESS REVOKED. Business Trust reached zero. Your containment shut down too much of the company.",
  }[r.outcome];
  return `<section class="outcome panel ${r.grade === "D" ? "loss" : ""}"><div class="grade">${r.grade}</div><div><p class="eyebrow">${r.outcome === "Breached" ? "CONFIRMED DATA LOSS" : "FINAL ASSESSMENT"}</p><h2>${esc(text)}</h2><p>Tick ${r.tick} · Trust ${r.trust} · ${r.falseIsolations} unnecessary host isolations · ${esc(r.profile)}</p><p class="muted fine">A: eviction by T4, Trust ≥90, zero false isolations. B: eviction with Trust ≥60 and ≤2 false isolations. C: other eviction or survival. D: breach or fired.</p></div></section><div class="replay-grid"><section class="panel"><h2>What happened / attacker truth</h2><ol class="timeline">${r.path.map((p) => `<li><span>T${p.tick} / ${clock(p.tick)}</span><b>${esc(p.host)} · ${esc(p.action)}</b><small>${p.clueIds.length ? `VISIBLE CLUES: ${p.clueIds.join(", ")}${p.clueIds.some((id) => seen.has(id)) ? " · queried" : ""}` : "State transition · no direct telemetry"}</small></li>`).join("")}</ol></section><section class="panel"><h2>What you saw / decisions</h2><p class="muted fine">Current-tick telemetry was available in the live feed; query rows below record explicit investigations. Rule matches can include historical events.</p><ol class="timeline">${r.actions.map((a) => `<li><span>T${a.tick}</span><b>${esc(a.action)}</b><code>${esc(a.detail)}</code>${a.eventIds ? `<small>Returned: ${a.eventIds.join(", ") || "no rows"}</small>` : ""}</li>`).join("") || "<li>No actions taken.</li>"}</ol></section></div><section class="panel"><h2>Detection review / truth now revealed</h2><p class="muted">Final active rule definitions evaluated against all collected telemetry. TP / FP count matching raw rows, including process parents.</p>${r.rules.length ? `<table><thead><tr><th>Rule</th><th>Attacker matches (TP)</th><th>Benign matches (FP)</th></tr></thead><tbody>${r.rules.map((rule) => `<tr><td><code>${esc(rule.text)}</code></td><td>${rule.tp}</td><td>${rule.fp}</td></tr>`).join("")}</tbody></table>` : "<p>No active rules to evaluate.</p>"}</section><section class="panel"><h2>Full telemetry replay</h2><p class="muted">Coral rows belong to the attacker. Clue IDs above link the path to these raw records.</p>${eventTable(r.events, new Set(r.maliciousIds))}</section><div class="button-row report-actions"><button id="another" class="primary">Play another seed →</button><button id="export-report">Export after-action JSON ${license ? "↓" : "· Pro 🔒"}</button><button id="export-rules">Export rules ${license ? "↓" : "· Pro 🔒"}</button></div>`;
}
function click(id: string, action: () => void) {
  document.getElementById(id)?.addEventListener("click", action);
}
function value(id: string) {
  return (document.getElementById(id) as HTMLInputElement | HTMLSelectElement)
    .value;
}
function result(error: string | null, success: string) {
  message = error ?? success;
  render();
}
function start(seed: string, profile: Profile) {
  game = new Game(seed, profile);
  queryRows = null;
  editing = undefined;
  message = "";
  render();
}
function exportJson(name: string, data: unknown) {
  if (!license) {
    showPack = true;
    message = "Activate a demo Analyst Pack key to export JSON.";
    render();
    return;
  }
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function wire() {
  click("pack", () => {
    showPack = !showPack;
    render();
  });
  click("close-pack", () => {
    showPack = false;
    render();
  });
  click("activate", () => {
    void activate(value("license-key"));
  });
  click("deactivate", () => {
    const saved = saveLicense(null, localStorage);
    license = null;
    message = saved
      ? "Demo license deactivated."
      : "Deactivated for this session; browser storage could not be updated.";
    render();
  });
  document.getElementById("rule")?.addEventListener("input", () => {
    draft = value("rule");
  });
  click("deploy", () => {
    const error = game.deploy(draft, editing);
    if (!error) editing = undefined;
    result(error, "Rule active. All collected events have been scanned.");
  });
  click("cancel-edit", () => {
    editing = undefined;
    render();
  });
  document
    .querySelectorAll<HTMLButtonElement>("[data-isolate]")
    .forEach((b) =>
      b.addEventListener("click", () =>
        result(
          game.isolate(b.dataset.isolate as Host),
          `${b.dataset.isolate} isolated. Communication blocked.`,
        ),
      ),
    );
  document.querySelectorAll<HTMLButtonElement>("[data-edit]").forEach((b) =>
    b.addEventListener("click", () => {
      editing = Number(b.dataset.edit);
      draft = game.rules.find((r) => r.id === editing)!.text;
      render();
    }),
  );
  document.querySelectorAll<HTMLButtonElement>("[data-remove]").forEach((b) =>
    b.addEventListener("click", () => {
      const id = Number(b.dataset.remove);
      game.removeRule(id);
      if (editing === id) editing = undefined;
      render();
    }),
  );
  click("reset", () => {
    const user = value("credential") as User;
    result(
      game.resetCredential(user),
      `${user} credential reset. New logons blocked.`,
    );
  });
  for (const [id, key] of [
    ["q-host", "host"],
    ["q-user", "user"],
    ["q-type", "event_type"],
    ["q-from", "from"],
    ["q-to", "to"],
  ] as const)
    document.getElementById(id)?.addEventListener("change", () => {
      queryFilter[key] = value(id);
    });
  document.getElementById("query-form")?.addEventListener("submit", (e) => {
    e.preventDefault();
    const q = game.query({
      host: queryFilter.host,
      user: queryFilter.user,
      event_type: queryFilter.event_type,
      from: Number(queryFilter.from),
      to: Number(queryFilter.to),
    });
    if (!q.error) queryRows = q.rows;
    result(
      q.error ?? null,
      `${q.rows.length} rows returned. Newest first; maximum 40.`,
    );
  });
  click("live-feed", () => {
    queryRows = null;
    render();
  });
  click("end-turn", () => {
    game.endTurn();
    queryRows = null;
    message = "";
    render();
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
  click("restart", () => {
    const profile = value("profile") as Profile;
    const custom = value("custom-seed").trim().toUpperCase();
    if (!license && (profile !== "Standard" || custom)) {
      showPack = true;
      message =
        "Fast Operator and custom seeds require a demo Analyst Pack key.";
      render();
      return;
    }
    start(custom || value("seed"), profile);
  });
  click("another", () =>
    start(
      seedCodes[
        (seedCodes.indexOf(game.config.seed as (typeof seedCodes)[number]) +
          1) %
          3
      ],
      license ? game.config.profile : "Standard",
    ),
  );
  click("export-rules", () =>
    exportJson("breach-clock-rules.json", {
      version: 1,
      rules: game.rules.map((r) => r.text),
    }),
  );
  click("export-report", () =>
    exportJson("breach-clock-after-action.json", game.report()),
  );
  click("share", () => {
    if (!license) {
      showPack = true;
      message = "Activate Analyst Pack to share custom seed codes.";
      render();
      return;
    }
    const url = new URL(location.href);
    url.search = new URLSearchParams({
      seed: game.config.seed,
      profile: game.config.profile,
    }).toString();
    message = `Share this deterministic setup (actions are not included): ${url.href}`;
    render();
  });
}
async function activate(key: string) {
  if (licenseBusy) return;
  licenseBusy = true;
  render();
  const verified = await verifyLicense(key);
  if (verified) {
    license = verified;
    message = saveLicense(verified, localStorage)
      ? "Analyst Pack activated."
      : "Activated for this session. Browser storage is unavailable.";
  } else
    message = "Invalid demo key. Check the complete signed key and try again.";
  licenseBusy = false;
  render();
}
async function init() {
  try {
    license = await loadLicense(localStorage);
  } catch {
    license = null;
  }
  const params = new URLSearchParams(location.search);
  const seed = params.get("seed")?.trim().toUpperCase().slice(0, 64);
  const profile =
    params.get("profile") === "Fast Operator" ? "Fast Operator" : "Standard";
  if (
    seed &&
    (license || seedCodes.includes(seed as (typeof seedCodes)[number])) &&
    (license || profile === "Standard")
  )
    game = new Game(seed, profile);
  else if (seed) {
    message =
      "This shared setup requires Analyst Pack. Activate a key, then reopen the link.";
    showPack = true;
  }
  render();
}
void init();
