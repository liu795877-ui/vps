import {chromium} from '../../panel/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';

const folder=path.dirname(fileURLToPath(import.meta.url));
const login=JSON.parse(await fs.readFile(path.join(folder,'panel-login.private.json'),'utf8'));
const output=path.join(folder,'ui-verification');
await fs.mkdir(output,{recursive:true});
const browser=await chromium.launch({channel:'msedge',headless:true,
    proxy:process.env.NODE_CONSOLE_TEST_PROXY ? {server:process.env.NODE_CONSOLE_TEST_PROXY}:undefined});
try {
  const context=await browser.newContext({viewport:{width:1440,height:1000}});
  const page=await context.newPage();
  const errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  const response=await page.goto(login.url,{waitUntil:'networkidle',timeout:35000});
  assert.equal(response.status(),200);
  await page.locator('#login-user').fill(login.username);
  await page.locator('#login-password').fill(login.password);
  await page.getByRole('button',{name:/进入控制台/}).click();
  await page.locator('#console').waitFor({state:'visible'});
  await page.waitForFunction(()=>document.querySelector('#server-pill').textContent.includes('节点服务运行中'));
  await page.waitForFunction(()=>document.querySelector('#metric-server-detail').textContent.includes('美国'),{},{timeout:35000});
  const apiState=await page.evaluate(async()=> {
    for(let attempt=0;attempt<3;attempt++) {
      try {
        const response=await fetch('./api/state');
        if(response.ok) return await response.json();
      } catch {}
    }
    throw new Error('Console state request failed after retries');
  });
  assert.equal(apiState.server_location.ip,'198.200.49.158');
  assert.equal(apiState.server_location.country_code,'US');
  const region=new Intl.DisplayNames(['zh-CN'],{type:'region'}).of(apiState.server_location.country_code);
  const city=apiState.server_location.city || apiState.server_location.region;
  assert.equal(await page.locator('#metric-server-detail').textContent(),[region,city,apiState.server_protocol].filter(Boolean).join(' · '));
  assert.equal(await page.locator('#path-server-name').textContent(),[region,city].filter(Boolean).join(' · ')+' VPS');
  assert.equal(await page.locator('#path-server').textContent(),apiState.server_ip+' : '+apiState.server_port);
  assert(!(await page.locator('#console').textContent()).includes('东京'));
  assert.equal(apiState.client_config.group,'STATIC-SELECT');
  assert.equal(apiState.client_config.auto_node,'AUTO · 网页切换');
  assert.equal(apiState.client_config.nodes.length,apiState.client_config.exit_count);
  assert.equal(await page.locator('.exit-card').count(),apiState.exits.length);
  await page.locator('#add-exit').click();
  await page.locator('#exit-dialog').waitFor({state:'visible'});
  await page.locator('#cancel-dialog').click();
  await page.locator('#exit-dialog').waitFor({state:'hidden'});
  await page.screenshot({path:path.join(output,'desktop.png'),fullPage:true,animations:'disabled'});
  await page.locator('.nav-button[data-view="access"]').click();
  if(apiState.download_ready) {
    assert((await page.locator('#client-config-summary').textContent()).includes('AUTO · 网页切换'));
    assert.equal(await page.locator('#view-access .download-button').isEnabled(),true);
  }
  assert((await page.locator('#view-access').textContent()).includes('STATIC-SELECT'));
  assert((await page.locator('#view-access').textContent()).includes('无需重新下载'));
  await page.screenshot({path:path.join(output,'unified-config-desktop.png'),fullPage:true,animations:'disabled'});
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await page.screenshot({path:path.join(output,'mobile.png'),fullPage:true,animations:'disabled'});
  await page.locator('#logout-mobile').click();
  await page.locator('#login-screen').waitFor({state:'visible'});
  assert.deepEqual(errors,[]);
  await fs.writeFile(path.join(folder,'panel-browser-verification.json'),JSON.stringify({
    checked_at:new Date().toISOString(),
    success:true,checks:['Automatic server location, protocol and port','Unified configuration metadata and client instructions','Trusted HTTPS','Login','Node running','Exit form opens','Desktop/mobile layout','Logout','No JavaScript errors'],
    server_location:apiState.server_location,
    applied_exit_count:apiState.client_config.exit_count,
    added_or_switched_exits:false},null,2));
  console.log('Browser checks passed: trusted HTTPS, login, exit form, desktop/mobile layout, logout.');
} finally {await browser.close();}
