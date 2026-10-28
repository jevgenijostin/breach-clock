import type { Host, User } from "./model";
import type { Scenario } from "./scenario";
import { randomStream } from "./rng";
import { Telemetry } from "./telemetry";
export class Benign {
  private random: () => number;
  private backupTick: number;
  constructor(
    private config: Scenario,
    private telemetry: Telemetry,
    private isolated: Set<Host>,
    private reset: Set<User>,
    private noise: number,
  ) {
    this.random = randomStream(config.seed, "benign");
    this.backupTick =
      config.lateralTick +
      (config.seed === "EMBER-1" ? 0 : Math.floor(this.random() * 3) - 1);
  }
  advance(tick: number) {
    const c = this.config,
      t = this.telemetry;
    if (tick === 2 && !this.reset.has("dana"))
      t.process(
        tick,
        c.finance,
        "dana",
        "excel.exe",
        "powershell.exe",
        "-File refresh.ps1",
        "finance-refresh",
      );
    if (tick >= 2 && tick <= 8 && !this.reset.has("dana"))
      t.emit(tick, {
        event_type: "network",
        host: c.finance,
        user: "dana",
        dest_host: "APP-01",
        dest_domain: "finance.internal",
        bytes: 12000,
        session_id: "finance-refresh",
      });
    if (
      tick === this.backupTick &&
      !this.reset.has("svc-backup") &&
      !this.isolated.has("BKP-01") &&
      !this.isolated.has("FS-01")
    ) {
      t.logon(tick, "BKP-01", "FS-01", "svc-backup", 3, "nightly-backup");
      t.process(
        tick,
        "FS-01",
        "svc-backup",
        "backupagent.exe",
        "powershell.exe",
        "-EncodedCommand QgBBAEMASwBVAFAB",
        "nightly-backup",
      );
    }
    if (
      tick >= c.exfilTick &&
      tick <= c.exfilTick + 2 &&
      !this.reset.has("svc-backup") &&
      !this.isolated.has("FS-01")
    )
      t.emit(tick, {
        event_type: "network",
        host: "BKP-01",
        user: "svc-backup",
        dest_domain: "offsite-backup.example",
        bytes: 90000000,
        session_id: "nightly-backup",
      });
    // Bounded, causal desktop sessions; changing noise cannot consume attacker randomness.
    for (let i = 0; i < Math.min(4, this.noise); i++) {
      const host = (["WS-01", "WS-02", "WS-04"] as Host[])[
        Math.floor(this.random() * 3)
      ];
      t.process(
        tick,
        host,
        ["eli", "bo"][i % 2],
        "explorer.exe",
        "outlook.exe",
        "--sync inbox",
        `desktop-${tick}-${i}`,
      );
    }
  }
}
