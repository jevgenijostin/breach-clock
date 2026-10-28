import { parse, type Clause } from "../dsl/parser";
import { evaluate } from "../dsl/evaluate";
import { Attacker } from "./attacker";
import { Benign } from "./benign";
import {
  hosts,
  users,
  type Host,
  type User,
  type Profile,
  type Outcome,
  type Query,
  type ActionRecord,
  type Event,
} from "./model";
import { scenario } from "./scenario";
import { Telemetry } from "./telemetry";
export type Rule = { id: number; text: string; ast: Clause[] };
export class Game {
  tick = 1;
  ap = 3;
  trust = 100;
  outcome: Outcome | null = null;
  falseIsolations = 0;
  isolated = new Set<Host>();
  reset = new Set<User>();
  rules: Rule[] = [];
  actions: ActionRecord[] = [];
  private nextRule = 1;
  private telemetry = new Telemetry(this.isolated);
  private attacker: Attacker;
  private benign: Benign;
  readonly config;
  constructor(seed = "EMBER-1", profile: Profile = "Standard", noise?: number) {
    this.config = scenario(seed, profile);
    this.attacker = new Attacker(
      this.config,
      this.telemetry,
      this.isolated,
      this.reset,
    );
    this.benign = new Benign(
      this.config,
      this.telemetry,
      this.isolated,
      this.reset,
      noise ?? this.config.noise,
    );
    this.advance();
  }
  private advance() {
    this.attacker.advance(this.tick);
    this.benign.advance(this.tick);
  }
  private available() {
    return this.outcome
      ? "This shift has ended."
      : this.ap <= 0
        ? "No AP remaining. End the turn to advance."
        : null;
  }
  private spend(action: string, detail: string, eventIds?: string[]) {
    this.ap--;
    this.actions.push({ tick: this.tick, action, detail, eventIds });
  }
  query(filter: Query): { error?: string; rows: Event[] } {
    const error = this.available();
    if (error) return { error, rows: [] };
    if (
      (filter.from !== undefined &&
        (!Number.isInteger(filter.from) ||
          filter.from < 1 ||
          filter.from > 14)) ||
      (filter.to !== undefined &&
        (!Number.isInteger(filter.to) || filter.to < 1 || filter.to > 14)) ||
      (filter.from ?? 1) > (filter.to ?? 14)
    )
      return {
        error: "Tick range must be ordered integers from 1 to 14.",
        rows: [],
      };
    const rows = this.telemetry.events
      .filter(
        (e) =>
          (!filter.host || e.host === filter.host) &&
          (!filter.user ||
            e.user.toLowerCase() === filter.user.toLowerCase()) &&
          (!filter.event_type || e.event_type === filter.event_type) &&
          e.tick >= (filter.from ?? 1) &&
          e.tick <= (filter.to ?? this.tick),
      )
      .slice(-40)
      .reverse();
    this.spend(
      "Query",
      JSON.stringify(filter),
      rows.map((e) => e.id),
    );
    return { rows: structuredClone(rows) };
  }
  isolate(host: Host): string | null {
    const error = this.available();
    if (error) return error;
    if (!hosts.includes(host)) return "Unknown host.";
    if (this.isolated.has(host)) return "Host is already isolated.";
    if (!this.attacker.controlled.has(host)) {
      const costs: Record<Host, number> = {
        "WS-01": 10,
        "WS-02": 10,
        "WS-03": 10,
        "WS-04": 10,
        "WS-05": 25,
        "FS-01": 25,
        "APP-01": 35,
        "DC-01": 50,
        "ADM-01": 20,
        "BKP-01": 30,
      };
      this.trust -= host === this.config.finance ? 25 : costs[host];
      this.falseIsolations++;
    }
    this.isolated.add(host);
    this.spend("Isolate", host);
    this.attacker.considerFallback(this.tick);
    return null;
  }
  resetCredential(user: User): string | null {
    const error = this.available();
    if (error) return error;
    if (!users.includes(user)) return "Unknown account.";
    if (this.reset.has(user)) return "Credential is already reset.";
    if (
      !this.attacker.stolen.has(user) &&
      ["svc-backup", "dana"].includes(user)
    )
      this.trust -= 10;
    this.reset.add(user);
    this.spend("Reset", user);
    this.attacker.considerFallback(this.tick);
    return null;
  }
  deploy(text: string, editId?: number): string | null {
    const parsed = parse(text);
    if (!parsed.ok) return parsed.error;
    if (this.outcome) return "This shift has ended.";
    if (editId !== undefined) {
      const rule = this.rules.find((r) => r.id === editId);
      if (!rule) return "Rule no longer exists.";
      rule.text = text;
      rule.ast = parsed.ast;
      this.actions.push({ tick: this.tick, action: "Edit rule", detail: text });
      return null;
    }
    const error = this.available();
    if (error) return error;
    if (this.rules.length >= 8)
      return "Maximum 8 active rules. Edit or remove a rule first.";
    this.rules.push({ id: this.nextRule++, text, ast: parsed.ast });
    this.spend("Deploy rule", text);
    return null;
  }
  removeRule(id: number) {
    if (!this.outcome) {
      this.rules = this.rules.filter((r) => r.id !== id);
      this.actions.push({
        tick: this.tick,
        action: "Remove rule",
        detail: String(id),
      });
    }
  }
  alerts() {
    return this.telemetry.events
      .filter((e) => this.rules.some((r) => evaluate(r.ast, e)))
      .map((e) => ({
        event: structuredClone(e),
        rules: this.rules.filter((r) => evaluate(r.ast, e)).map((r) => r.id),
      }))
      .reverse();
  }
  endTurn() {
    if (this.outcome) return;
    const breached = this.attacker.finishTurn();
    if (this.trust <= 0) this.outcome = "Fired";
    else if (breached) this.outcome = "Breached";
    else if (!this.attacker.hasLegalAction(this.tick)) this.outcome = "Evicted";
    else if (this.tick === 14) this.outcome = "Survived";
    if (!this.outcome) {
      this.tick++;
      this.ap = 3;
      this.advance();
    }
  }
  view() {
    return {
      tick: this.tick,
      ap: this.ap,
      trust: this.trust,
      outcome: this.outcome,
      seed: this.config.seed,
      profile: this.config.profile,
      finance: this.config.finance,
      hosts: hosts.map((host) => ({ host, isolated: this.isolated.has(host) })),
      reset: [...this.reset],
      rules: this.rules.map(({ id, text }) => ({ id, text })),
      alerts: this.alerts(),
      eventCount: this.telemetry.events.length,
      recent: structuredClone(
        this.telemetry.events.filter((e) => e.tick === this.tick),
      ),
      actions: structuredClone(this.actions),
    };
  }
  report() {
    if (!this.outcome) return null;
    const grade =
      this.outcome === "Breached" || this.outcome === "Fired"
        ? "D"
        : this.outcome === "Survived"
          ? "C"
          : this.tick <= 4 && this.trust >= 90 && this.falseIsolations === 0
            ? "A"
            : this.trust >= 60 && this.falseIsolations <= 2
              ? "B"
              : "C";
    return {
      seed: this.config.seed,
      profile: this.config.profile,
      outcome: this.outcome,
      tick: this.tick,
      trust: this.trust,
      grade,
      falseIsolations: this.falseIsolations,
      path: structuredClone(this.attacker.path),
      events: structuredClone(this.telemetry.events),
      maliciousIds: [...this.telemetry.malicious],
      actions: structuredClone(this.actions),
      rules: this.rules.map((r) => {
        const hits = this.telemetry.events.filter((e) => evaluate(r.ast, e));
        return {
          id: r.id,
          text: r.text,
          tp: hits.filter((e) => this.telemetry.malicious.has(e.id)).length,
          fp: hits.filter((e) => !this.telemetry.malicious.has(e.id)).length,
        };
      }),
    };
  }
}
