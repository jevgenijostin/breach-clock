import { schema, type Field } from "./schema";
import { SyntaxIssue, tokenize } from "./tokenizer";
export type Operator = "=" | "!=" | ">" | "<" | ">=" | "<=" | "contains";
export type Clause = {
  field: Field;
  operator: Operator;
  value: string | number;
};
export type ParseResult =
  { ok: true; ast: Clause[] } | { ok: false; error: string; position: number };
export function parse(input: string): ParseResult {
  try {
    const tokens = tokenize(input);
    let index = 0;
    const ast: Clause[] = [];
    const take = (expected: string) => {
      const token = tokens[index++];
      if (!token) throw new SyntaxIssue(`Expected ${expected}`, input.length);
      return token;
    };
    for (;;) {
      const fieldToken = take("field name");
      const name = fieldToken.text.toLowerCase();
      if (fieldToken.kind !== "word" || !Object.hasOwn(schema, name))
        throw new SyntaxIssue(
          `Unknown field ${JSON.stringify(fieldToken.text)}`,
          fieldToken.pos,
        );
      const field = name as Field;
      const op = take("comparison operator");
      const operator = op.text.toLowerCase() as Operator;
      if (
        !["=", "!=", ">", "<", ">=", "<=", "contains"].includes(operator) ||
        (op.kind !== "operator" && op.kind !== "word")
      )
        throw new SyntaxIssue(
          "Expected =, !=, contains, >, <, >= or <=",
          op.pos,
        );
      const literal = take(
        schema[field] === "number" ? "integer literal" : "double-quoted string",
      );
      if (schema[field] === "number") {
        if (
          literal.kind !== "integer" ||
          operator === "contains" ||
          !Number.isSafeInteger(Number(literal.text))
        )
          throw new SyntaxIssue(
            `${field} requires an integer comparison (contains is for strings)`,
            literal.pos,
          );
      } else if (
        literal.kind !== "string" ||
        !["=", "!=", "contains"].includes(operator)
      ) {
        throw new SyntaxIssue(
          `${field} requires =, != or contains and a double-quoted string`,
          literal.pos,
        );
      }
      ast.push({
        field,
        operator,
        value:
          schema[field] === "number"
            ? Number(literal.text)
            : literal.text.toLowerCase(),
      });
      if (index === tokens.length) break;
      const join = take("AND");
      if (join.kind !== "word" || join.text.toUpperCase() !== "AND")
        throw new SyntaxIssue(
          "Only AND may join clauses; OR, NOT, regex, nesting and aggregation are not supported",
          join.pos,
        );
    }
    return { ok: true, ast };
  } catch (error) {
    if (error instanceof SyntaxIssue)
      return { ok: false, error: error.message, position: error.position + 1 };
    return { ok: false, error: "Invalid rule at position 1.", position: 1 };
  }
}
