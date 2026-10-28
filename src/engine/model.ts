import type { RuleEvent } from "../dsl/schema";
export const hosts = [
  "WS-01",
  "WS-02",
  "WS-03",
  "WS-04",
  "WS-05",
  "FS-01",
  "APP-01",
  "DC-01",
  "ADM-01",
  "BKP-01",
] as const;
export type Host = (typeof hosts)[number];
export const users = [
  "chen",
  "eli",
  "bo",
  "dana",
  "svc-backup",
  "t.nowak",
] as const;
export type User = (typeof users)[number];
export type Profile = "Standard" | "Fast Operator";
export type Outcome = "Evicted" | "Survived" | "Breached" | "Fired";
export type Event = RuleEvent & {
  id: string;
  tick: number;
  timestamp: number;
  event_type: "process" | "logon" | "network";
  host: Host;
  user: string;
  session_id: string;
  pid?: number;
  parent_pid?: number;
  logon_id?: string;
};
export type EventInput = Omit<Event, "id" | "timestamp" | "tick">;
export type PathEntry = {
  tick: number;
  action: string;
  host: Host;
  clueIds: string[];
};
export type Query = {
  host?: string;
  user?: string;
  event_type?: string;
  from?: number;
  to?: number;
};
export type ActionRecord = {
  tick: number;
  action: string;
  detail: string;
  eventIds?: string[];
};
