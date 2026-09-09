import { test, expect } from "@playwright/test";
const password = process.env.DEMO_PASSWORD;
test.beforeEach(async ({ page }) => {
  if (!password)
    throw new Error(
      "Set DEMO_PASSWORD to the locally configured seed password.",
    );
  await page.goto("/login");
  await page.getByLabel("Email address").fill("analyst@sentinel.example");
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible();
});
test("investigate a real alert, persist a note, and filter alerts", async ({
  page,
}) => {
  await page.getByRole("button", { name: /^Alerts/ }).click();
  await page.getByLabel("Severity filter").selectOption("critical");
  await expect(page.locator("tbody tr").first()).toContainText("critical");
  await page.locator("tbody .row-title").first().click();
  await expect(
    page.getByRole("heading", { name: "Why this matched" }),
  ).toBeVisible();
  await page
    .getByRole("combobox", { name: "Status", exact: true })
    .selectOption("investigating");
  await page.getByRole("button", { name: "Save decision" }).click();
  await expect(page.getByRole("status")).toContainText("Investigation updated");
  const note = `Synthetic analyst review ${Date.now()}`;
  await page.getByLabel("Analyst note").fill(note);
  await page.getByRole("button", { name: "Add note", exact: true }).click();
  await expect(page.locator(".note")).toContainText([note]);
  await page.reload();
  await page.getByRole("button", { name: /^Alerts/ }).click();
  await page.getByLabel("Search records").fill("does-not-exist-synthetic");
  await expect(
    page.getByRole("heading", { name: "No matching alerts" }),
  ).toBeVisible();
});
test("ingest a sample event and observe accepted feedback", async ({
  page,
}) => {
  await page.getByRole("button", { name: "Events", exact: true }).click();
  await page.getByRole("button", { name: "Ingest events" }).click();
  await page.getByRole("button", { name: "Submit data" }).click();
  await expect(page.getByRole("status")).toContainText("events accepted");
  await expect(page.locator("tbody")).toContainText("dns_query");
});
test("create asset, find it, and show real API failure with retry", async ({
  page,
}) => {
  await page.getByRole("button", { name: "Assets", exact: true }).click();
  await page.getByRole("button", { name: "Add asset" }).click();
  const hostname = `e2e-${Date.now()}`;
  await page.getByLabel("hostname", { exact: true }).fill(hostname);
  await page.getByLabel("ip address", { exact: true }).fill("192.0.2.240");
  await page.getByLabel("operating system", { exact: true }).fill("Linux");
  await page.getByLabel("owner", { exact: true }).fill("Demo Owner");
  await page.getByLabel("department", { exact: true }).fill("Security");
  await page.getByRole("button", { name: "Create asset" }).click();
  await page.getByLabel("Search records").fill(hostname);
  await expect(page.locator("tbody")).toContainText(hostname);
  await page.route("**/api/v1/events?**", (route) =>
    route.fulfill({
      status: 503,
      json: { detail: "Synthetic service interruption" },
    }),
  );
  await page.getByRole("button", { name: "Events", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Unable to load data" }),
  ).toBeVisible();
  await page.unroute("**/api/v1/events?**");
  await page.getByRole("button", { name: "Try again" }).click();
  await expect(page.locator("tbody tr").first()).toBeVisible();
});
test("capture dashboard and tablet layout; logout protects workspace", async ({
  page,
}) => {
  await expect(page.locator(".chart svg").first()).toBeVisible();
  await page.screenshot({
    path: "../../docs/screenshots/overview.png",
    fullPage: true,
  });
  await page.setViewportSize({ width: 820, height: 1180 });
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/login/);
  await page.goto("/");
  await expect(page).toHaveURL(/login/);
});
