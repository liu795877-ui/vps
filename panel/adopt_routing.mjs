import { chromium } from "playwright";
import fs from "node:fs/promises";
import path from "node:path";
import assert from "node:assert/strict";

const root = path.resolve("..");
const login = JSON.parse(await fs.readFile(path.join(root,"panel-login.private.json"),"utf8"));
const browser = await chromium.launch({channel:"msedge",headless:true});
try {
  const context = await browser.newContext();
  const origin = new URL(login.url).origin;
  const response = await context.request.post(login.url + "api/login", {
    headers:{Origin:origin}, data:{username:login.username,password:login.password},
  });
  assert.equal(response.status(),200,"Existing panel login should succeed");
  const {csrf} = await response.json();
  const state = await (await context.request.get(login.url+"api/state")).json();
  assert(state.active && state.download_ready,"An applied exit is needed before adopting service routing");
  const current = await context.request.get(login.url + "api/profile");
  try {
    await fs.writeFile(path.join(root,".validation","routing-profile-before.private.yaml"),await current.body(),{flag:"wx"});
  } catch (error) { if (error.code !== "EEXIST") throw error; }
  const saved = await context.request.post(login.url + "api/routing", {
    headers:{Origin:origin,"X-CSRF-Token":csrf}, data:{mode:"services",domains:[]},
  });
  assert.equal(saved.status(),200,"Service routing should regenerate the client profile");
  const after = await (await context.request.get(login.url + "api/state")).json();
  assert.equal(after.routing_mode,"services");
  assert.deepEqual(after.exits,state.exits);
  assert.deepEqual(after.active,state.active);
  const download = await context.request.get(login.url + "api/profile");
  assert.equal(download.status(),200);
  const bytes = await download.body();
  assert(bytes.toString("utf8").includes("MATCH, Others"));
  assert(bytes.toString("utf8").includes("rule-providers:"));
  await fs.writeFile(path.join(root,"clash-service-routing.private.yaml"),bytes);
  console.log("Service routing selected and private client profile downloaded. Existing exit settings and active route were preserved.");
  await context.request.post(login.url+"api/logout", {headers:{Origin:origin,"X-CSRF-Token":csrf},data:{}});
} finally { await browser.close(); }
