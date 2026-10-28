import type { Clause } from "./parser";
import type { RuleEvent } from "./schema";
export function evaluate(ast: Clause[], event: RuleEvent): boolean {
  return ast.every(({ field, operator, value }) => {
    const raw = event[field];
    // Missing fields never match, including !=.
    if (raw === undefined) return false;
    const actual = typeof raw === "string" ? raw.toLowerCase() : raw;
    switch (operator) {
      case "=":
        return actual === value;
      case "!=":
        return actual !== value;
      case "contains":
        return (
          typeof actual === "string" &&
          typeof value === "string" &&
          actual.includes(value)
        );
      case ">":
        return (
          typeof actual === "number" &&
          typeof value === "number" &&
          actual > value
        );
      case "<":
        return (
          typeof actual === "number" &&
          typeof value === "number" &&
          actual < value
        );
      case ">=":
        return (
          typeof actual === "number" &&
          typeof value === "number" &&
          actual >= value
        );
      case "<=":
        return (
          typeof actual === "number" &&
          typeof value === "number" &&
          actual <= value
        );
    }
  });
}
export const matchesAny = (rules: Clause[][], event: RuleEvent) =>
  rules.some((rule) => evaluate(rule, event));
