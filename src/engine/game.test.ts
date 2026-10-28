import { describe, expect, it } from "vitest";
import { Game } from "./game";
import { seedCodes } from "./scenario";
import { hosts, type Host, type Profile } from "./model";
const profiles: Profile[] = ["Standard", "Fast Operator"];
const finish = (game: Game) => {
  while (!game.outcome) game.endTurn();
  return game.report()!;
};
const until = (g: Game, tick: number) => {
  while (g.tick < tick && !g.outcome) g.endTurn();
};
const win = (g: Game) => {
  until(g, 2);
  expect(
    g.deploy(
      'process_name = "powershell.exe" AND parent_process = "winword.exe"',
    ),
  ).toBeNull();
  const hits = g.alerts();
  expect(hits).toHaveLength(1);
  expect(g.isolate(hits[0].event.host)).toBeNull();
  g.endTurn();
  expect(g.tick).toBe(3);
  expect(
    g.view().recent.some((e) => e.command_line?.toString().includes("lsass")),
  ).toBe(true);
  g.resetCredential("svc-backup");
  g.resetCredential("dana");
  g.endTurn();
  return g.report()!;
};
const lateWin = (g: Game) => {
  until(g, g.config.lateralTick);
  const q = g.query({ host: "FS-01", event_type: "logon" });
  const source = q.rows.find((e) => e.source_host !== "BKP-01")!
    .source_host as Host;
  g.isolate("FS-01");
  g.resetCredential("svc-backup");
  g.endTurn();
  g.endTurn();
  expect(
    g.view().recent.some((e) => e.logon_type === 10 && e.host === "APP-01"),
  ).toBe(true);
  g.isolate(source);
  g.resetCredential("dana");
  g.isolate("APP-01");
  g.endTurn();
  return g.report()!;
};
describe.each(seedCodes)("%s policy and fairness", (seed) => {
  describe.each(profiles)("%s", (profile) => {
    it("early winning trace evicts at T3 with Trust 100", () => {
      const r = win(new Game(seed, profile));
      expect([r.outcome, r.tick, r.trust, r.grade]).toEqual([
        "Evicted",
        3,
        100,
        "A",
      ]);
    });
    it("late winning trace investigates the lateral source and contains the fallback", () => {
      const r = lateWin(new Game(seed, profile));
      expect(r.outcome).toBe("Evicted");
      expect(r.trust).toBe(100);
      expect(r.path.some((p) => p.action.includes("Alternate route"))).toBe(
        true,
      );
    });
    it("harmless queries lose to exfil", () => {
      const g = new Game(seed, profile);
      while (!g.outcome) {
        g.query({ host: "DC-01" });
        g.endTurn();
      }
      expect(g.outcome).toBe("Breached");
      expect(g.tick).toBe(profile === "Standard" ? 11 : 7);
    });
    it("panic isolation loses to business impact", () => {
      const g = new Game(seed, profile);
      g.isolate("BKP-01");
      g.isolate(g.config.finance);
      g.isolate("APP-01");
      g.endTurn();
      g.isolate("FS-01");
      g.endTurn();
      expect(g.outcome).toBe("Fired");
      expect(g.trust).toBe(-15);
    });
    it("branch-only containment adapts and still breaches within the shift", () => {
      const g = new Game(seed, profile);
      until(g, g.config.lateralTick);
      g.isolate("FS-01");
      const r = finish(g);
      expect(r.outcome).toBe("Breached");
      expect(r.tick).toBeLessThanOrEqual(14);
      const alternate = r.path.find((p) =>
        p.action.includes("Alternate route"),
      )!;
      expect(alternate.tick).toBe(g.config.lateralTick + 2);
    });
    it("has ordered causal telemetry, ambiguity overlap, lead time, bounded noise", () => {
      const g = new Game(seed, profile);
      const r = finish(g);
      const events = r.events;
      expect(events.length).toBeLessThan(300);
      events.forEach((e, i) => {
        if (i) expect(e.timestamp).toBeGreaterThan(events[i - 1].timestamp);
        if (e.parent_pid)
          expect(
            events
              .slice(0, i)
              .some(
                (p) =>
                  p.pid === e.parent_pid &&
                  p.host === e.host &&
                  p.timestamp <= e.timestamp,
              ),
          ).toBe(true);
        if (e.event_type === "logon")
          expect(
            events
              .slice(0, i)
              .some(
                (p) =>
                  p.host === e.source_host && p.session_id === e.session_id,
              ),
          ).toBe(true);
      });
      const malicious = new Set(r.maliciousIds);
      const lateral = events.find(
        (e) => e.event_type === "logon" && malicious.has(e.id),
      )!;
      const backup = events.find(
        (e) => e.event_type === "logon" && e.source_host === "BKP-01",
      )!;
      expect(Math.abs(lateral.tick - backup.tick)).toBeLessThanOrEqual(1);
      expect(
        events.some((e) => e.tick === 2 && e.parent_process === "excel.exe"),
      ).toBe(true);
      expect(
        events.some((e) => e.tick === 2 && e.parent_process === "winword.exe"),
      ).toBe(true);
      const exfil = events.filter(
        (e) =>
          e.dest_domain === "cdn-sync.example" && Number(e.bytes) > 50000000,
      );
      expect(
        events.some(
          (e) =>
            e.dest_domain === "offsite-backup.example" &&
            exfil.some((x) => x.tick === e.tick),
        ),
      ).toBe(true);
      const stage = events.find((e) => e.process_name === "7z.exe")!;
      expect(exfil[0].tick - stage.tick).toBeGreaterThanOrEqual(1);
      expect(exfil.at(-1)!.tick - stage.tick).toBeGreaterThanOrEqual(1);
      for (const p of r.path.filter(
        (p) => p.clueIds.length && !p.action.startsWith("Exfiltration"),
      )) {
        const clue = events.find((e) => e.id === p.clueIds.at(-1))!;
        const q = new Game(seed, profile);
        until(q, clue.tick);
        const rows = q.query({
          host: clue.host,
          from: clue.tick,
          to: clue.tick,
        }).rows;
        expect(rows.some((e) => e.id === clue.id)).toBe(true);
        expect(q.ap).toBe(2);
        expect(r.tick - clue.tick).toBeGreaterThanOrEqual(1);
      }
    });
    it("keeps attacker choices independent of benign noise", () => {
      const r1 = finish(new Game(seed, profile, 0)),
        r2 = finish(new Game(seed, profile, 4));
      const path = (r: typeof r1) =>
        r.path.map(({ tick, action, host }) => ({ tick, action, host }));
      expect(path(r1)).toEqual(path(r2));
      const attack = (r: typeof r1) =>
        r.events
          .filter((e) => r.maliciousIds.includes(e.id))
          .map((e) => [
            e.tick,
            e.host,
            e.user,
            e.event_type,
            e.process_name,
            e.source_host,
            e.dest_domain,
            e.command_line,
            e.bytes,
          ]);
      expect(attack(r1)).toEqual(attack(r2));
    });
    it("replays the same actions deterministically", () =>
      expect(lateWin(new Game(seed, profile))).toEqual(
        lateWin(new Game(seed, profile)),
      ));
    it("keeps Trust nonincreasing and truth out of gameplay projections", () => {
      const g = new Game(seed, profile);
      let previous = 100;
      while (!g.outcome) {
        const view = g.view();
        expect(view.trust).toBeLessThanOrEqual(previous);
        previous = view.trust;
        expect(JSON.stringify(view)).not.toMatch(
          /"(controlled|compromised|stolen|malicious|tp|fp|path|patient)"/,
        );
        expect(g.report()).toBeNull();
        if (g.tick === 4) g.isolate("ADM-01");
        g.endTurn();
      }
    });
  });
});
describe("action semantics", () => {
  it("charges only valid actions; caps AP, permits free edits, retroactively scans", () => {
    const g = new Game();
    until(g, 3);
    expect(g.deploy('unknown = "x"')).toMatch(/Unknown field/);
    expect(g.ap).toBe(3);
    g.deploy('parent_process = "winword.exe"');
    expect(g.alerts()[0].event.tick).toBe(2);
    g.query({ host: "WS-03" });
    g.query({ host: "FS-01" });
    expect(g.ap).toBe(0);
    expect(g.isolate("WS-03")).toMatch(/No AP/);
    expect(g.resetCredential("dana")).toMatch(/No AP/);
    expect(g.deploy('host = "WS-03"')).toMatch(/No AP/);
    expect(g.deploy('process_name = "7z.exe"', 1)).toBeNull();
    expect(g.ap).toBe(0);
    expect(g.alerts()).toHaveLength(0);
    g.removeRule(1);
    expect(g.rules).toHaveLength(0);
    expect(g.ap).toBe(0);
    g.endTurn();
    expect(g.ap).toBe(3);
  });
  it("caps active rules at eight and does not duplicate overlapping alerts", () => {
    const g = new Game();
    for (let i = 0; i < 8; i++) {
      if (!g.ap) g.endTurn();
      expect(g.deploy("tick >= 1")).toBeNull();
    }
    expect(g.deploy("tick >= 1")).toMatch(/8/);
    expect(g.ap).toBe(1);
    const ids = g.alerts().map((a) => a.event.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
  it.each([
    ["WS-01", 10],
    ["WS-05", 25],
    ["FS-01", 25],
    ["BKP-01", 30],
    ["APP-01", 35],
    ["ADM-01", 20],
    ["DC-01", 50],
  ] as const)("penalizes clean %s by %i", (host, cost) => {
    const g = new Game();
    g.isolate(host);
    expect(g.trust).toBe(100 - cost);
    expect(g.isolate(host)).toMatch(/already/);
    expect(g.ap).toBe(2);
  });
  it("charges clean workflow credentials but not stolen credentials or compromised hosts", () => {
    const clean = new Game();
    clean.resetCredential("svc-backup");
    expect(clean.trust).toBe(90);
    clean.resetCredential("dana");
    expect(clean.trust).toBe(80);
    const g = new Game();
    until(g, 6);
    g.isolate("FS-01");
    g.resetCredential("svc-backup");
    g.resetCredential("dana");
    expect(g.trust).toBe(100);
  });
  it("isolation permits local activity but blocks all later cross-host traffic", () => {
    const g = new Game();
    until(g, 2);
    g.isolate("WS-03");
    g.endTurn();
    expect(
      g.view().recent.some((e) => e.command_line?.toString().includes("lsass")),
    ).toBe(true);
    const r = finish(g);
    expect(
      r.events.filter(
        (e) =>
          e.tick > 2 &&
          e.event_type !== "process" &&
          [e.host, e.source_host, e.dest_host].includes("WS-03"),
      ),
    ).toHaveLength(0);
    expect(
      r.events.some((e) => e.host === "FS-01" && r.maliciousIds.includes(e.id)),
    ).toBe(false);
  });
  it("reset prevents later use and breaks the associated workflow", () => {
    const g = new Game();
    until(g, 3);
    g.resetCredential("svc-backup");
    g.resetCredential("dana");
    const r = finish(g);
    expect(
      r.events.filter(
        (e) =>
          e.tick > 3 &&
          e.event_type === "logon" &&
          ["svc-backup", "dana"].includes(e.user),
      ),
    ).toHaveLength(0);
    expect(
      r.events.filter(
        (e) =>
          e.tick > 3 &&
          ["svc-backup", "dana"].includes(e.user) &&
          !r.maliciousIds.includes(e.id),
      ),
    ).toHaveLength(0);
    expect(r.path.some((p) => p.action.includes("Alternate route"))).toBe(
      false,
    );
    expect(r.outcome).toBe("Survived");
  });
  it("does not reuse dana or trigger a fallback without a live root", () => {
    const g = new Game();
    until(g, 6);
    g.isolate("WS-03");
    g.isolate("FS-01");
    const r = finish(g);
    expect(r.outcome).toBe("Evicted");
    expect(r.path.some((p) => p.action.includes("Alternate route"))).toBe(
      false,
    );
  });
  it("cancels fallback if dana resets before RDP, without evicting an existing remote session", () => {
    const g = new Game();
    until(g, 6);
    g.isolate("FS-01");
    g.resetCredential("dana");
    const r = finish(g);
    expect(r.path.some((p) => p.action.includes("Alternate route"))).toBe(
      false,
    );
    expect(r.outcome).toBe("Survived");
    const active = new Game();
    until(active, 6);
    active.resetCredential("svc-backup");
    active.resetCredential("dana");
    expect(finish(active).outcome).toBe("Breached");
  });
  it("lets containment stop the final exfil tick before completion", () => {
    const g = new Game();
    until(g, 11);
    g.isolate("FS-01");
    g.isolate("WS-03");
    g.endTurn();
    expect(g.outcome).toBe("Evicted");
  });
  it("late fallback preserves the 14-tick horizon and yields Survived", () => {
    const g = new Game();
    until(g, 10);
    g.isolate("FS-01");
    const r = finish(g);
    expect(r.outcome).toBe("Survived");
    expect(r.tick).toBe(14);
    expect(r.path.find((p) => p.action.includes("Alternate route"))?.tick).toBe(
      12,
    );
  });
  it("pre-isolated targets cannot receive logons; all hosts obey crossing invariant", () => {
    for (const host of hosts) {
      const g = new Game();
      g.isolate(host);
      const r = finish(g);
      expect(
        r.events.filter(
          (e) =>
            e.tick > 1 &&
            e.event_type !== "process" &&
            [e.host, e.source_host, e.dest_host].includes(host),
        ),
      ).toHaveLength(0);
    }
  });
  it("queries cap at 40 and reject invalid ranges without charging", () => {
    const g = new Game("EMBER-1", "Standard", 4);
    until(g, 8);
    const rows = g.query({}).rows;
    expect(rows).toHaveLength(40);
    expect(rows[0].timestamp).toBeGreaterThan(rows[39].timestamp);
    expect(g.query({ from: 9, to: 2 }).error).toBeTruthy();
    expect(g.ap).toBe(2);
  });
  it("records complete winning and losing event/outcome sequences as regression snapshots", () => {
    expect(win(new Game())).toMatchSnapshot("entire early win");
    expect(finish(new Game())).toMatchSnapshot("entire untouched breach");
  });
});
