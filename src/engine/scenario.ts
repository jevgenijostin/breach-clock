import { randomStream } from "./rng";
import type { Host, Profile } from "./model";
export const seedCodes = ["EMBER-1", "EMBER-2", "EMBER-3"] as const;
export function scenario(seed: string, profile: Profile = "Standard") {
  const attacker = randomStream(seed, "attacker");
  const index = seedCodes.indexOf(seed as (typeof seedCodes)[number]);
  const patient = (
    index >= 0
      ? ["WS-03", "WS-01", "WS-02"][index]
      : ["WS-01", "WS-02", "WS-03"][Math.floor(attacker() * 3)]
  ) as Host;
  const hard = profile === "Fast Operator";
  return {
    seed,
    profile,
    patient,
    finance: (index === 1 ? "WS-04" : "WS-05") as Host,
    lateralTick: hard ? 4 : 6,
    stagingTick: hard ? 5 : 7,
    exfilTick: hard ? 6 : 9,
    exfilDuration: hard ? 2 : 3,
    noise: hard ? 3 : 1,
  };
}
export type Scenario = ReturnType<typeof scenario>;
