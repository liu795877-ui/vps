import { chromium } from "playwright";
import fs from "node:fs/promises";
import path from "node:path";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const panel = path.dirname(fileURLToPath(import.meta.url));
const output = path.join(panel, "..", ".validation");
await fs.mkdir(output, {recursive:true});
const demoDirectory = await fs.mkdtemp(path.join(output, "smart-ui-demo-"));
const port = Number(process.env.SMART_SMOKE_PORT || 9019);
const origin = "http://127.0.0.1:" + port;
const demo = spawn(process.env.PYTHON || "python", [path.join(panel, "server.py"),
  "--demo", "--directory", demoDirectory, "--config", path.join(demoDirectory, "demo-xray.json"),
  "--public-ip", "198.51.100.63", "--origin", origin, "--base-path", "/", "--port", String(port)],
  {cwd:panel, windowsHide:true, stdio:["ignore", "pipe", "pipe"]});
let browser;
try {
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Demo did not start.")), 15000);
    demo.stdout.on("data", (data) => { if (data.toString().includes("listening")) { clearTimeout(timer); resolve(); } });
    demo.on("error", (error) => { clearTimeout(timer); reject(error); });
    demo.on("exit", (code) => { clearTimeout(timer); reject(new Error("Demo exited with code " + code)); });
    demo.stderr.on("data", (data) => { clearTimeout(timer); reject(new Error(data.toString())); });
  });
  browser = await chromium.launch({channel:"msedge", headless:true});
  const context = await browser.newContext({viewport:{width:1440,height:1000}});
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(origin + "/", {waitUntil:"networkidle"});
  await page.locator("#login-password").fill("demo-password-2026");
  await page.getByRole("button", {name:/进入控制台/}).click();
  await page.locator("#console").waitFor({state:"visible"});
  await page.locator("#path-server-button").click();
  await page.waitForFunction(() => document.querySelector("#metric-ip").textContent === "198.51.100.63");
  await page.locator('.nav-button[data-view="routing"]').click();
  assert.equal(await page.locator("#routing-mode").inputValue(), "manual");
  assert.match(await page.locator("#routing-mode-hint").textContent(), /其他网站使用本机网络/);
  await page.locator("#routing-mode").selectOption("smart");
  await page.locator("#routing-smart-summary").waitFor({state:"visible"});
  assert.equal(await page.locator("#routing-service-summary").isVisible(), false);
  await page.locator("#direct-domains").fill("example.cn\nbilibili.com");
  await page.locator("#domains").fill("example.com\ngithub.com");
  async function save() {
    const response = page.waitForResponse((value) => value.url().endsWith("/api/routing") && value.request().method() === "POST");
    await page.getByRole("button", {name:"保存分流规则"}).click();
    const saved = await response;
    assert.equal(saved.status(), 200);
    await page.waitForFunction(() => !document.querySelector("#routing-form button[type='submit']").disabled);
    return saved.request().postDataJSON();
  }
  assert.deepEqual(await save(), {domains:["example.com","github.com"], direct_domains:["example.cn","bilibili.com"], mode:"smart"});
  assert.match(await page.locator("#toast").textContent(), /导入配置一次/);
  const first = await (await context.request.get(origin + "/api/state")).json();
  assert.equal(first.routing_mode, "smart");
  assert.deepEqual(first.direct_domains, ["example.cn","bilibili.com"]);
  assert.equal(first.routing_subscription.enabled, true);

  await page.locator("#direct-domains").fill("example.cn\nbilibili.com\nnew.example.cn");
  await save();
  assert.match(await page.locator("#toast").textContent(), /5 分钟自动同步/);
  assert.match(await page.locator("#toast").textContent(), /刷新客户端规则集/);
  assert.doesNotMatch(await page.locator("#toast").textContent(), /重新下载|导入配置一次/);
  await page.locator('.nav-button[data-view="overview"]').click();
  assert.match(await page.locator("#path-routing-caption").textContent(), /国内走本机/);
  assert.equal(await page.locator("#metric-ip").textContent(), "198.51.100.63");
  await page.locator('.nav-button[data-view="access"]').click();
  assert.match(await page.locator("#client-config-summary").textContent(), /规则模式/);
  assert.match(await page.locator("#client-config-summary").textContent(), /自动同步/);
  await page.locator('.nav-button[data-view="routing"]').click();
  assert.equal(await page.locator("#direct-domains").inputValue(), "example.cn\nbilibili.com\nnew.example.cn");
  await page.screenshot({path:path.join(output,"panel-smart-routing-desktop.png"),fullPage:true,animations:"disabled"});
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  await page.screenshot({path:path.join(output,"panel-smart-routing-mobile.png"),fullPage:true,animations:"disabled"});

  await page.locator("#routing-mode").selectOption("services");
  assert.equal(await page.locator("#routing-smart-summary").isVisible(), false);
  await page.locator("#routing-service-summary").waitFor({state:"visible"});
  await save();
  assert.match(await page.locator("#toast").textContent(), /导入配置一次/);
  await page.locator("#routing-mode").selectOption("manual");
  assert.equal(await page.locator("#routing-service-summary").isVisible(), false);
  await save();
  assert.match(await page.locator("#toast").textContent(), /导入配置一次/);
  assert.deepEqual(errors, []);
  console.log("Smart UI smoke passed: two domain lists, mode change and subscription save feedback, server exit preserved, legacy modes, desktop and 390 px layout.");
} finally {
  if (browser) await browser.close();
  demo.kill();
}
