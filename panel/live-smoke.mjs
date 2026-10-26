import { chromium } from "playwright";
import fs from "node:fs/promises";
import path from "node:path";
import assert from "node:assert/strict";

const root = path.resolve("..");
const login = JSON.parse(await fs.readFile(path.join(root, "panel-login.private.json"), "utf8"));
const browser = await chromium.launch({channel:"msedge", headless:true});
try {
  const context = await browser.newContext({viewport:{width:1440,height:1000}});
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const base = login.url;
  assert.equal((await context.request.get(base + "api/state")).status(), 401);
  const initial = await context.request.get(base + "api/session");
  assert.equal(initial.status(), 200);
  assert.equal((await initial.json()).authenticated, false);

  const response = await page.goto(base, {waitUntil:"networkidle"});
  assert.equal(response.status(), 200);
  await page.locator("#login-user").fill(login.username);
  await page.locator("#login-password").fill(login.password);
  await page.getByRole("button", {name:/进入控制台/}).click();
  await page.locator("#console").waitFor({state:"visible"});
  await page.waitForFunction(() => document.querySelector("#server-pill").textContent.includes("节点服务运行中"));
  const cookie = (await context.cookies(base)).find((item) => item.name === "vps_panel_session");
  assert(cookie && cookie.secure && cookie.httpOnly && cookie.sameSite === "Strict");
  assert.equal(cookie.path, "/node-console/");
  const state = await (await context.request.get(base + "api/state")).json();
  assert.equal(state.demo, false);
  assert.equal(state.service_active, true);
  assert.equal(await page.locator(".path-route").count(), state.exits.length + (state.active && !state.exits.some((exit) => exit.id === state.active.id) ? 1 : 0));
  if (state.active) assert.equal(await page.locator(".path-route.is-current .route-name").textContent(), state.active.name);
  assert.equal((await context.request.get(base + "api/profile")).status(), state.download_ready ? 200 : 409);

  const session = await (await context.request.get(base + "api/session")).json();
  const denied = await context.request.post(base + "api/domains", {
    headers:{Origin:new URL(base).origin}, data:{domains:state.domains},
  });
  assert.equal(denied.status(), 403);
  const originDenied = await context.request.post(base + "api/domains", {
    headers:{Origin:"https://unrelated.invalid", "X-CSRF-Token":session.csrf},
    data:{domains:state.domains},
  });
  assert.equal(originDenied.status(), 403);

  await page.locator('.nav-button[data-view="routing"]').click();
  assert.equal(await page.locator("#domains").inputValue(), state.domains.join("\n"));
  assert.equal(await page.locator("#routing-mode").inputValue(), state.routing_mode || "manual");
  await page.getByRole("button", {name:"保存分流规则"}).click();
  await page.waitForFunction(() => document.querySelector("#toast").textContent.includes("分流规则已保存"));
  const saved = await (await context.request.get(base + "api/state")).json();
  assert.deepEqual(saved.domains, state.domains);
  assert.equal(saved.routing_mode, state.routing_mode);
  await page.locator('.nav-button[data-view="overview"]').click();
  await page.locator("#toast").waitFor({state:"hidden"});
  await page.waitForFunction(() => document.getAnimations().every((animation) => animation.effect.getTiming().iterations === Infinity || animation.playState !== "running"));
  await page.screenshot({path:path.join(root,".validation","panel-live-desktop.png"),fullPage:true,animations:"disabled"});
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  await page.screenshot({path:path.join(root,".validation","panel-live-mobile.png"),fullPage:true,animations:"disabled"});
  await page.locator("#logout-mobile").click();
  await page.locator("#login-screen").waitFor({state:"visible"});
  assert.equal((await context.request.get(base + "api/state")).status(), 401);
  assert.deepEqual(errors, []);
  console.log("Live HTTPS checks passed: login, secure session, protected API, current exit branches, same-value rule persistence, assets, desktop/mobile layout and logout. Existing exits were preserved; no production proxy was added or switched.");
} finally {
  await browser.close();
}
