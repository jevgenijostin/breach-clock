import type { Host, PathEntry, User } from "./model";
import type { Scenario } from "./scenario";
import { Telemetry } from "./telemetry";
export class Attacker {
  controlled = new Set<Host>();
  stolen = new Set<User>();
  path: PathEntry[] = [];
  fallbackAt: number | null = null;
  fallbackUsed = false;
  target: Host | null = null;
  exfilProgress = 0;
  exfilThisTurn = false;
  constructor(
    public config: Scenario,
    private telemetry: Telemetry,
    private isolated: Set<Host>,
    private reset: Set<User>,
  ) {}
  private live(host: Host) {
    return this.controlled.has(host) && !this.isolated.has(host);
  }
  private credential(user: User) {
    return this.stolen.has(user) && !this.reset.has(user);
  }
  private record(tick: number, action: string, host: Host, ids: string[] = []) {
    this.path.push({ tick, action, host, clueIds: ids });
  }
  considerFallback(tick: number) {
    if (
      this.fallbackAt !== null ||
      this.fallbackUsed ||
      !this.live(this.config.patient) ||
      !this.credential("dana")
    )
      return;
    if (!this.isolated.has("FS-01") && !this.reset.has("svc-backup")) return;
    if (this.isolated.has("APP-01") || tick < 3) return;
    this.fallbackAt = tick + 2;
    this.record(
      tick,
      "Primary route blocked; alternate RDP route scheduled",
      this.config.patient,
    );
  }
  advance(tick: number) {
    const c = this.config,
      t = this.telemetry;
    this.exfilThisTurn = false;
    if (tick === 2) {
      this.controlled.add(c.patient);
      const rows = t.process(
        tick,
        c.patient,
        "chen",
        "winword.exe",
        "powershell.exe",
        "-nop -w hidden -enc SQBOAFYATwBJAEMARQA=",
        "invoice-open",
        true,
      );
      this.record(
        tick,
        "Foothold: invoice.docm opens an encoded PowerShell",
        c.patient,
        rows.map((e) => e.id),
      );
    }
    if (tick === 3 && this.controlled.has(c.patient)) {
      const rows = t.process(
        tick,
        c.patient,
        "chen",
        "powershell.exe",
        "svchost_update.exe",
        "--read lsass --cache legacy-export",
        "credential-dump",
        true,
      );
      for (const user of ["svc-backup", "dana"] as const)
        if (!this.reset.has(user)) this.stolen.add(user);
      this.record(
        tick,
        "Local credential access: svc-backup and dana cached credentials",
        c.patient,
        rows.map((e) => e.id),
      );
    }
    if (tick >= 3 && this.live(c.patient)) {
      t.emit(
        tick,
        {
          event_type: "network",
          host: c.patient,
          user: "chen",
          dest_domain: "cdn-sync.example",
          bytes: 840,
          session_id: "beacon",
        },
        true,
      );
    }
    this.considerFallback(tick);
    if (
      tick === c.lateralTick &&
      this.fallbackAt === null &&
      this.live(c.patient) &&
      this.credential("svc-backup") &&
      !this.isolated.has("FS-01")
    ) {
      const rows = t.logon(
        tick,
        c.patient,
        "FS-01",
        "svc-backup",
        3,
        "lateral-wmi",
        true,
      );
      rows.push(
        ...t.process(
          tick,
          "FS-01",
          "svc-backup",
          "wmiprvse.exe",
          "powershell.exe",
          "-enc SQBOAFYATwBJAEMARQA=",
          "lateral-wmi",
          true,
        ),
      );
      this.controlled.add("FS-01");
      this.target = "FS-01";
      this.record(
        tick,
        "Lateral movement with stolen svc-backup",
        "FS-01",
        rows.map((e) => e.id),
      );
    }
    if (
      this.fallbackAt === tick &&
      this.live(c.patient) &&
      this.credential("dana") &&
      !this.isolated.has("APP-01")
    ) {
      const rows = t.logon(
        tick,
        c.patient,
        "APP-01",
        "dana",
        10,
        "fallback-rdp",
        true,
      );
      this.controlled.add("APP-01");
      this.target = "APP-01";
      this.fallbackUsed = true;
      this.exfilProgress = 0;
      this.record(
        tick,
        "Alternate route: dana RDP session",
        "APP-01",
        rows.map((e) => e.id),
      );
    }
    const target = this.target;
    if (!target || !this.live(target)) return;
    const stageTick =
      target === "APP-01" ? this.fallbackAt! + 1 : c.stagingTick;
    const transferTick =
      target === "APP-01" ? this.fallbackAt! + 2 : c.exfilTick;
    if (tick >= stageTick && tick < transferTick) {
      const rows = t.process(
        tick,
        target,
        target === "APP-01" ? "dana" : "svc-backup",
        "cmd.exe",
        "7z.exe",
        "7z a cache.7z Finance/",
        "staging",
        true,
      );
      this.record(
        tick,
        "Staging: Finance archive prepared",
        target,
        rows.map((e) => e.id),
      );
    }
    if (tick >= transferTick) {
      const row = t.emit(
        tick,
        {
          event_type: "network",
          host: target,
          user: target === "APP-01" ? "dana" : "svc-backup",
          dest_domain: "cdn-sync.example",
          bytes: 60000000 + this.exfilProgress * 35000000,
          session_id: "exfil",
        },
        true,
      );
      this.exfilThisTurn = !!row;
      this.record(
        tick,
        "Exfiltration attempt: Finance archive to cdn-sync.example",
        target,
        row ? [row.id] : [],
      );
    }
  }
  finishTurn() {
    if (this.exfilThisTurn && this.target && this.live(this.target))
      this.exfilProgress++;
    return this.exfilProgress >= this.config.exfilDuration;
  }
  hasLegalAction(tick: number): boolean {
    if (tick < 3) return true; // Already-started local credential activity completes at T3.
    return [...this.controlled].some((host) => !this.isolated.has(host));
  }
}
