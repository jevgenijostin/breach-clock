export const schema = {
  event_type: "string",
  host: "string",
  user: "string",
  process_name: "string",
  parent_process: "string",
  command_line: "string",
  source_host: "string",
  dest_host: "string",
  dest_domain: "string",
  logon_type: "number",
  bytes: "number",
  tick: "number",
} as const;
export type Field = keyof typeof schema;
export type RuleEvent = Partial<Record<Field, string | number>>;
