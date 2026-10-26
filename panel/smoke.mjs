import { chromium } from "playwright";
import fs from "node:fs/promises";
import path from "node:path";
import assert from "node:assert/strict";

const root = path.resolve("..");
const output = path.join(root, ".validation");
await fs.mkdir(output, {recursive:true});
const browser = await chromium.launch({channel:"msedge",headless:true});
const context = await browser.newContext({viewport:{width:1440,height:1000}});
const page = await context.newPage();
const errors = [];
page.on("pageerror", (error) => errors.push(error.message));
page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()); });
await page.goto("http://127.0.0.1:9017/", {waitUntil:"networkidle"});
await page.locator("#login-password").fill("demo-password-2026");
await page.getByRole("button", {name:/进入控制台/}).click();
await page.locator("#console").waitFor({state:"visible"});

async function add(name, address) {
  await page.locator("#add-exit").click();
  await page.locator("#exit-name").fill(name);
  await page.locator("#exit-address").fill(address);
  await page.locator("#exit-user").fill("test-only-user");
  await page.locator("#exit-password").fill("test-only-browser-password");
  await page.locator("#save-exit").click();
  await page.locator("#exit-dialog").waitFor({state:"hidden"});
  await page.locator(".exit-name").filter({hasText:name}).waitFor();
  await page.locator(".path-route.is-selected").filter({hasText:name}).waitFor();
}

async function apply(name) {
  await page.locator(".exit-card").filter({has:page.getByRole("heading", {name,exact:true})})
    .locator('[data-action="apply"]').click();
  await page.waitForFunction((value) => document.querySelector("#metric-active").textContent === value, name);
  await page.locator("#add-exit").waitFor({state:"visible"});
  await page.locator(".path-route.is-current").filter({hasText:name}).waitFor();
}

if (await page.locator(".exit-card").count() === 0) {
  await add("美国主出口", "us.proxy.example.com");
  await add("德国备用出口", "de.proxy.example.com");
  assert.equal(await page.locator(".path-route").count(), 2);
  assert.equal(await page.locator(".path-route.is-current").count(), 0);
  assert.equal(await page.locator("#metric-active").textContent(), "尚未配置");
  await page.locator("#path-test").click();
  await page.locator('.path-route[data-phase="checking"]').waitFor();
  await page.locator('.path-route.is-selected[data-phase="ready"]').waitFor();
}
await apply("美国主出口");
await apply("德国备用出口");
await page.getByRole("button", {name:"预览出口：美国主出口",exact:true}).click();
assert.equal(await page.locator("#metric-active").textContent(), "德国备用出口");
assert.equal(await page.locator(".path-route.is-current .route-name").textContent(), "德国备用出口");
await add("检测失败示例", "fail.proxy.example.com");
await page.locator("#path-test").click();
await page.locator('.path-route.is-selected[data-phase="error"]').waitFor();
assert.equal(await page.locator("#metric-active").textContent(), "德国备用出口");
await page.screenshot({path:path.join(output,"panel-path-failed.png"),fullPage:true,animations:"disabled"});

async function remove(name) {
  await page.locator(".exit-card").filter({has:page.getByRole("heading", {name,exact:true})})
    .locator('[data-action="delete"]').click();
  await page.locator("#confirm-ok").click();
  await page.locator(".exit-name").filter({hasText:name}).waitFor({state:"hidden"});
}
await remove("检测失败示例");
assert.equal(await page.locator(".path-route").count(), 2);
await remove("德国备用出口");
assert.equal(await page.locator(".path-route.is-current .route-name").textContent(), "德国备用出口");
assert.match(await page.locator(".path-route.is-current .route-status").textContent(), /已从草稿移除/);
await apply("美国主出口");
assert.equal(await page.locator(".path-route").count(), 1);
await page.locator("#rollback").click();
await page.locator("#confirm-ok").click();
await page.waitForFunction(() => document.querySelector("#metric-active").textContent === "德国备用出口");
assert.equal(await page.locator(".path-route").count(), 2);
await page.locator(".exit-card").first().locator('[data-action="edit"]').click();
assert.equal(await page.locator("#exit-user").inputValue(), "");
assert.equal(await page.locator("#exit-password").inputValue(), "");
await page.locator("#cancel-dialog").click();

const downloadEvent = page.waitForEvent("download");
await page.locator("#download-top").click();
const download = await downloadEvent;
assert.equal(download.suggestedFilename(), "clash-node-console.yaml");
const profile = await fs.readFile(await download.path(), "utf8");
assert(profile.includes("AUTO"));
assert(!profile.includes("test-only-browser-password"));
assert(!profile.includes("test-only-user"));

await page.locator('[data-view="routing"]').first().click();
await page.locator("#routing-mode").selectOption("services");
await page.locator("#routing-service-summary").waitFor({state:"visible"});
await page.locator("#domains").fill("github.com\nexample.com");
await page.getByRole("button", {name:"保存分流规则"}).click();
await page.waitForFunction(() => document.querySelector("#toast").textContent.includes("分流规则已保存"));
const serviceDownloadEvent = page.waitForEvent("download");
await page.locator('.nav-button[data-view="access"]').click();
await page.locator('#view-access .download-button').click();
const serviceDownload = await serviceDownloadEvent;
const serviceProfile = await fs.readFile(await serviceDownload.path(), "utf8");
assert(serviceProfile.includes("rule-providers:"));
assert(serviceProfile.includes("MATCH, Others"));
assert(serviceProfile.includes("AND,((RULE-SET,Domestic),(RULE-SET,Domestic IPs)),Domestic"));
await page.locator('.nav-button[data-view="routing"]').click();
await page.screenshot({path:path.join(output,"panel-routing-desktop.png"),fullPage:true,animations:"disabled"});
await page.setViewportSize({width:390,height:844});
assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
await page.screenshot({path:path.join(output,"panel-routing-mobile.png"),fullPage:true,animations:"disabled"});
await page.setViewportSize({width:1440,height:1000});
await page.locator('[data-view="overview"]').first().click();
await page.waitForFunction(() => document.getAnimations().every((animation) => animation.effect.getTiming().iterations === Infinity || animation.playState !== "running"));
await page.locator("#toast").waitFor({state:"hidden"});
await page.screenshot({path:path.join(output,"panel-desktop.png"),fullPage:true,animations:"disabled"});
await page.setViewportSize({width:390,height:844});
await page.screenshot({path:path.join(output,"panel-mobile.png"),fullPage:true,animations:"disabled"});
const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth);
assert.equal(overflow, false, "Mobile layout should fit the viewport");
await page.setViewportSize({width:320,height:740});
assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
await page.emulateMedia({reducedMotion:"reduce"});
assert.equal(await page.locator(".route-line").first().evaluate((element) => getComputedStyle(element).animationName), "none");
await page.locator("#logout-mobile").click();
await page.locator("#login-screen").waitFor({state:"visible"});
assert.equal(errors.length, 0, "Browser should not log errors: " + errors.join("; "));
console.log("UI smoke passed: service routing selection and download, dynamic branches, probe, rollback, mobile layout, reduced motion and logout.");
await browser.close();
