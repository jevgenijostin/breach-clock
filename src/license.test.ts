import { expect, it } from "vitest";
import {
  demoPayload,
  signLicense,
  verifyLicense,
  loadLicense,
  saveLicense,
  LICENSE_STORAGE_KEY,
} from "./license";
it("verifies signatures and rejects tampering, malformed data and future payloads", async () => {
  const p = demoPayload(1, "test");
  const key = await signLicense(p);
  expect((await verifyLicense(key))?.payload).toEqual(p);
  expect(await verifyLicense(key + "x")).toBeNull();
  expect(await verifyLicense("invalid")).toBeNull();
  expect(
    await verifyLicense(
      await signLicense(demoPayload(Date.now() + 100000, "future")),
    ),
  ).toBeNull();
});
it("activates, reloads with verification, and deactivates", async () => {
  const data = new Map<string, string>();
  const storage = {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => {
      data.set(k, v);
    },
    removeItem: (k: string) => {
      data.delete(k);
    },
  };
  const state = await verifyLicense(await signLicense(demoPayload(1, "test")));
  expect(saveLicense(state, storage)).toBe(true);
  expect(await loadLicense(storage)).toEqual(state);
  data.set(
    LICENSE_STORAGE_KEY,
    '{"key":"fake","entitlements":{"tier":"paid"}}',
  );
  expect(await loadLicense(storage)).toBeNull();
  saveLicense(null, storage);
  expect(await loadLicense(storage)).toBeNull();
});
