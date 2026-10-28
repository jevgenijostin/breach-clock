import { createHmac, randomUUID } from "node:crypto";
import { Buffer } from "node:buffer";
const payload = {
  version: 1,
  tier: "paid",
  issuedAt: Date.now(),
  licenseId: randomUUID(),
};
const body = Buffer.from(JSON.stringify(payload)).toString("base64");
console.log(
  `${body}.${createHmac("sha256", "breachclock-demo-v1-client-inspectable-secret").update(body).digest("hex")}`,
);
