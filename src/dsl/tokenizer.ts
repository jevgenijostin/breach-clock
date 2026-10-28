export type Token = {
  text: string;
  pos: number;
  kind: "word" | "string" | "integer" | "operator";
};
export class SyntaxIssue extends Error {
  constructor(
    message: string,
    public position: number,
  ) {
    super(`${message} at position ${position + 1}.`);
  }
}
export function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < input.length) {
    if (/\s/.test(input[i])) {
      i++;
      continue;
    }
    const pos = i;
    if (input[i] === '"') {
      i++;
      let value = "";
      while (i < input.length && input[i] !== '"') value += input[i++];
      if (i === input.length)
        throw new SyntaxIssue("Unclosed double-quoted string", pos);
      i++;
      tokens.push({ text: value, pos, kind: "string" });
      continue;
    }
    const rest = input.slice(i);
    const match = /^(>=|<=|!=|=|>|<)|^(-?\d+)|^([A-Za-z_][A-Za-z_0-9]*)/.exec(
      rest,
    );
    if (!match)
      throw new SyntaxIssue(
        `Unexpected character ${JSON.stringify(input[i])}; only comparisons joined by AND are supported`,
        pos,
      );
    tokens.push({
      text: match[0],
      pos,
      kind: match[1] ? "operator" : match[2] ? "integer" : "word",
    });
    i += match[0].length;
  }
  return tokens;
}
