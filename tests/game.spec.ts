import { expect, test } from "@playwright/test";
import { createHmac } from "node:crypto";
test("early containment wins through the browser; next seed can lose to breach", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("./");
  await expect(
    page.getByRole("heading", { name: "Keep the company online." }),
  ).toBeVisible();
  await page.getByRole("button", { name: "End turn" }).click();
  await page.locator('#rule').fill('process_name = "powershell.exe" AND parent_process = "winword.exe"');
  await page.getByRole("button", { name: "Deploy rule · 1 AP" }).click();
  await expect(page.locator(".alert")).toHaveCount(1);
  await expect(page.locator(".alert")).toContainText("WS-03");
  await page.locator('[data-isolate="WS-03"]').click();
  await page.getByRole("button", { name: "End turn" }).click();
  await page.locator("#credential").selectOption("svc-backup");
  await page.locator("#reset").click();
  await page.locator("#credential").selectOption("dana");
  await page.locator("#reset").click();
  await page.getByRole("button", { name: "End turn" }).click();
  await expect(
    page.getByRole("heading", { name: "Evicted", exact: true }),
  ).toBeVisible();
  await expect(page.locator(".grade")).toHaveText("A");
  await expect(page.getByText("What happened / attacker truth")).toBeVisible();
  await page.getByRole("button", { name: "Play another seed" }).click();
  for (let i = 0; i < 11; i++)
    await page.getByRole("button", { name: "End turn" }).click();
  await expect(
    page.getByRole("heading", { name: "Breached", exact: true }),
  ).toBeVisible();
  await expect(page.getByText(/DATA EXFILTRATED/)).toBeVisible();
  expect(errors).toEqual([]);
});
test("validation, locked Pro, license activation, hard profile, export and deactivation", async ({
  page,
}) => {
  await page.goto("./");
  await page.locator("#rule").fill('host = "FS-01" OR bytes > 5');
  await page.locator("#deploy").click();
  await expect(page.locator("#message")).toContainText("position");
  await expect(page.locator(".pips")).toHaveAttribute(
    "aria-label",
    "3 action points",
  );
  await page.locator("#export-rules").click();
  await expect(page.locator(".pack")).toBeVisible();
  const body = Buffer.from(
    JSON.stringify({
      version: 1,
      tier: "paid",
      issuedAt: 1,
      licenseId: "browser-test",
    }),
  ).toString("base64");
  const key = `${body}.${createHmac("sha256", "breachclock-demo-v1-client-inspectable-secret").update(body).digest("hex")}`;
  await page.locator("#license-key").fill(key);
  await page.locator("#activate").click();
  await expect(page.locator("#message")).toContainText("activated");
  await page.reload();
  await expect(page.locator("#pack")).toContainText("Active");
  await page.locator("#profile").selectOption("Fast Operator");
  await page.locator("#custom-seed").fill("TEST-NIGHT");
  await page.locator("#restart").click();
  await expect(page.locator(".header-meta")).toContainText("TEST-NIGHT");
  const download = page.waitForEvent("download");
  await page.locator("#export-rules").click();
  expect((await download).suggestedFilename()).toBe("breach-clock-rules.json");
  for (let i = 0; i < 7; i++) await page.locator("#end-turn").click();
  await expect(
    page.getByRole("heading", { name: "Breached", exact: true }),
  ).toBeVisible();
  await page.locator("#pack").click();
  await page.locator("#deactivate").click();
  await expect(page.locator("#pack")).not.toContainText("Active");
});
test("small screen remains usable and makes no external requests", async ({
  page,
}) => {
  const external: string[] = [];
  page.on("request", (req) => {
    if (!req.url().startsWith("http://127.0.0.1:4173/"))
      external.push(req.url());
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("./");
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.locator("#end-turn").click();
  await page.locator("#deploy").click();
  await expect(page.locator(".alert")).toHaveCount(2);
  expect(external).toEqual([]);
});
