import type { Event, EventInput, Host } from "./model";
export class Telemetry {
  events: Event[] = [];
  malicious = new Set<string>();
  private pid = 1000;
  private sessions = new Map<string, string>();
  constructor(private isolated: Set<Host>) {}
  emit(tick: number, input: EventInput, malicious = false): Event | undefined {
    if (input.event_type === "network" || input.event_type === "logon") {
      if (
        [input.host, input.source_host, input.dest_host].some(
          (h) => h && this.isolated.has(h as Host),
        )
      )
        return;
    }
    const id = `E${String(this.events.length + 1).padStart(4, "0")}`;
    if (!this.sessions.has(input.session_id)) {
      this.sessions.set(input.session_id, `S${String(this.sessions.size + 1).padStart(4, "0")}`);
    }
    const event: Event = {
      ...input,
      session_id: this.sessions.get(input.session_id)!,
      ...(input.logon_id ? { logon_id: this.sessions.get(input.logon_id)! } : {}),
      id,
      tick,
      timestamp:
        Date.UTC(2026, 9, 29, 2) +
        (tick - 1) * 300000 +
        this.events.length * 100,
    };
    this.events.push(event);
    if (malicious) this.malicious.add(id);
    return event;
  }
  process(
    tick: number,
    host: Host,
    user: string,
    parent: string,
    name: string,
    command: string,
    session: string,
    malicious = false,
  ): Event[] {
    const parentPid = ++this.pid;
    const root = this.emit(
      tick,
      {
        event_type: "process",
        host,
        user,
        process_name: parent,
        command_line: parent,
        pid: parentPid,
        session_id: session,
      },
      malicious,
    )!;
    const child = this.emit(
      tick,
      {
        event_type: "process",
        host,
        user,
        process_name: name,
        parent_process: parent,
        command_line: command,
        pid: ++this.pid,
        parent_pid: parentPid,
        session_id: session,
      },
      malicious,
    )!;
    return [root, child];
  }
  logon(
    tick: number,
    source: Host,
    target: Host,
    user: string,
    type: number,
    session: string,
    malicious = false,
  ): Event[] {
    if (this.isolated.has(source) || this.isolated.has(target)) return [];
    const sourceEvents = this.process(
      tick,
      source,
      user,
      "services.exe",
      type === 10 ? "mstsc.exe" : "net.exe",
      `connect ${target}`,
      session,
      malicious,
    );
    const logon = this.emit(
      tick,
      {
        event_type: "logon",
        host: target,
        user,
        source_host: source,
        dest_host: target,
        logon_type: type,
        logon_id: session,
        session_id: session,
      },
      malicious,
    )!;
    return [...sourceEvents, logon];
  }
}
