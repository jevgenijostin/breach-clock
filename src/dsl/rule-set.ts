import { parse } from "./parser";
export function readRuleSet(
  input: string,
): { rules: string[]; error?: never } | { rules?: never; error: string } {
  try {
    if (input.length > 65536)
      return { error: "Rule-set files must be at most 64 KB." };
    const data: unknown = JSON.parse(input);
    if (
      !data ||
      typeof data !== "object" ||
      !("version" in data) ||
      data.version !== 1 ||
      !("rules" in data) ||
      !Array.isArray(data.rules) ||
      data.rules.length < 1 ||
      data.rules.length > 8
    )
      return { error: "Expected version 1 and an array of 1–8 rule strings." };
    for (const [index, text] of data.rules.entries()) {
      if (typeof text !== "string")
        return { error: `Rule ${index + 1} must be a string.` };
      const result = parse(text);
      if (!result.ok) return { error: `Rule ${index + 1}: ${result.error}` };
    }
    return { rules: data.rules as string[] };
  } catch {
    return { error: 'Invalid JSON. Expected {"version":1,"rules":["..."]}.' };
  }
}
