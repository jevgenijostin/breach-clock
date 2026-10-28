import { expect, it } from "vitest";
import { readRuleSet } from "./rule-set";
it("loads a versioned rule export", () => {
  expect(
    readRuleSet(JSON.stringify({ version: 1, rules: ['host = "FS-01"'] })),
  ).toEqual({ rules: ['host = "FS-01"'] });
});
it.each([
  "not json",
  '{"version":2,"rules":[]}',
  '{"version":1,"rules":[5]}',
  '{"version":1,"rules":["host = 5"]}',
  " ".repeat(65537),
])("rejects invalid or oversized imports without exceptions", (input) => {
  expect(readRuleSet(input).error).toBeTruthy();
});
