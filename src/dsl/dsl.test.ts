import { describe, expect, it } from "vitest";
import { parse } from "./parser";
import { evaluate, matchesAny } from "./evaluate";
import type { RuleEvent } from "./schema";
const ast = (text: string) => {
  const p = parse(text);
  if (!p.ok) throw new Error(p.error);
  return p.ast;
};
describe("tiny DSL", () => {
  it.each(["=", "!=", ">", "<", ">=", "<="])("accepts numeric %s", (op) =>
    expect(parse(`bytes ${op} 50000000`).ok).toBe(true),
  );
  it("matches case-insensitively, with conjunction and OR across rules", () => {
    const event = {
      process_name: "PowerShell.EXE",
      parent_process: "WINWORD.exe",
      bytes: 60000000,
    };
    expect(
      evaluate(
        ast(
          'process_name = "powershell.exe" AND parent_process contains "word"',
        ),
        event,
      ),
    ).toBe(true);
    expect(
      evaluate(ast('process_name = "powershell.exe" AND bytes < 5'), event),
    ).toBe(false);
    expect(
      matchesAny([ast("bytes < 5"), ast("bytes >= 60000000")], event),
    ).toBe(true);
    expect(matchesAny([], event)).toBe(false);
  });
  it.each([
    'host = "x" OR host = "y"',
    'NOT host = "x"',
    '(host = "x")',
    'host matches "x.*"',
    'host =~ "x"',
    "count(host) > 2",
    'host = "x" THEN host = "y"',
    "title: sigma",
    'eval("1")',
    "host = /x/",
    'unknown = "x"',
    'bytes contains "5"',
    'bytes = "5"',
    "host > 1",
    "host = 5",
    "bytes > 1.5",
    'host = "unterminated',
    'host = "x" AND',
    "",
    "bytes > 999999999999999999999999",
    'host "=" "x"',
  ])("rejects %s with position", (input) => {
    const p = parse(input);
    expect(p.ok).toBe(false);
    if (!p.ok) {
      expect(p.error).toMatch(/position \d+/);
      expect(p.position).toBeGreaterThan(0);
    }
  });
  it("does not match absent fields, including inequality", () =>
    expect(evaluate(ast('dest_domain != "offsite-backup.example"'), {})).toBe(
      false,
    ));
  it("handles AND inside literals and empty strings", () => {
    expect(
      evaluate(ast('command_line contains "x AND y"'), {
        command_line: "x and y",
      }),
    ).toBe(true);
    expect(evaluate(ast('host = ""'), { host: "" })).toBe(true);
  });
  it("implements comparison boundaries", () => {
    const e: RuleEvent = { bytes: 5 };
    for (const [rule, expected] of [
      ["bytes = 5", true],
      ["bytes != 5", false],
      ["bytes > 5", false],
      ["bytes < 5", false],
      ["bytes >= 5", true],
      ["bytes <= 5", true],
    ] as const)
      expect(evaluate(ast(rule), e)).toBe(expected);
  });
});
