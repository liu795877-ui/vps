import {chromium} from '../../panel/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const folder = path.dirname(fileURLToPath(import.meta.url));
const origin = 'https://198-200-49-63.sslip.io:8443';
const output = path.join(folder, 'traffic-charts-browser-ui');
const report = {success:false, checked_at:new Date().toISOString(), deployment_ip:'198.200.49.63',
  trusted_https:true, physical_wlan:true, server_mutations_allowed:false,
  secrets_included:false, checks:[], users:[], screenshots:[], assets:{}};
const contexts = [], errors = [], blocked = [];
let browser, stage = 'deployment_gate';
const hash = value => createHash('sha256').update(value).digest('hex');
const check = name => report.checks.push(name);
function bytes(value) {
  if (value === null || value === undefined || value === '') return '未知';
  let number = Number(value), index = 0;
  if (!Number.isFinite(number) || number < 0) return '未知';
  const units = ['B','KB','MB','GB','TB'];
  while (number >= 1000 && index < units.length-1) {number /= 1000; index++;}
  return number.toFixed(index ? 2 : 0) + ' ' + units[index];
}
async function current(page) {
  return page.evaluate(() => {
    const keys = ['user','server_ip','server_port','exits','active','active_target','routing_mode',
      'domains','direct_domains','dirty','download_ready','client_config'];
    return {traffic:state.traffic, user:{role:state.user.role, port:state.server_port},
      core:JSON.stringify(Object.fromEntries(keys.map(key => [key,state[key]])))};
  });
}
async function fit(page) {
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false,
    'Page fits viewport');
  assert.equal(await page.locator('.traffic-card').evaluate(element => element.scrollWidth > element.clientWidth),
    false, 'Traffic card fits viewport');
}
async function shot(page, name) {
  await page.locator('.traffic-card').screenshot({path:path.join(output,name)});
  report.screenshots.push(name);
}
async function verifyLiveNumbers(page) {
  const snapshot = await current(page), t = snapshot.traffic;
  const display = await page.evaluate(() => Object.fromEntries(
    ['traffic-total','traffic-up-total','traffic-down-total','traffic-up-rate','traffic-down-rate',
      'traffic-connections'].map(id => [id,document.getElementById(id).textContent.trim()])));
  if (t.up_bytes !== null && t.up_bytes !== undefined) assert.equal(display['traffic-up-total'], bytes(t.up_bytes));
  if (t.down_bytes !== null && t.down_bytes !== undefined) assert.equal(display['traffic-down-total'], bytes(t.down_bytes));
  if (t.total_bytes !== null && t.total_bytes !== undefined) assert.equal(display['traffic-total'], bytes(t.total_bytes));
  const at = t.sampled_at ? Date.parse(t.sampled_at) : NaN;
  const sampling = Number(t.sampling_seconds) > 0 ? Number(t.sampling_seconds) : 10;
  const fresh = t.available === true && Number.isFinite(at) &&
    Date.now()-at <= Math.max(30000,sampling*3000) && at-Date.now() <= 30000;
  if (fresh) {
    if (t.up_rate !== null && t.up_rate !== undefined) assert.equal(display['traffic-up-rate'], bytes(t.up_rate)+'/s');
    if (t.down_rate !== null && t.down_rate !== undefined) assert.equal(display['traffic-down-rate'], bytes(t.down_rate)+'/s');
    if (t.connections !== null && t.connections !== undefined) assert.equal(display['traffic-connections'], String(t.connections));
  } else {
    assert.match(display['traffic-up-rate'], /未知|不可用|过期/);
    assert.match(display['traffic-down-rate'], /未知|不可用|过期/);
    assert.match(display['traffic-connections'], /未知|不可用|过期/);
  }
  assert(await page.locator('#traffic-donut').isVisible());
  assert(await page.locator('#traffic-rate-chart').isVisible());
  return snapshot;
}
async function guide(page) {
  await page.evaluate(() => window.NodeGuide.start('usage-history'));
  await page.locator('#guide-tour').waitFor({state:'visible'});
  for (let step=0; step<2; step++) {
    await page.waitForFunction(() => !!document.querySelector('#guide-tour-highlight').dataset.targetSelector);
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    const geometry = await page.evaluate(() => {
      const panel=document.querySelector('#guide-tour-panel').getBoundingClientRect();
      const target=document.querySelector(document.querySelector('#guide-tour-highlight').dataset.targetSelector);
      return {fits:panel.left>=-1&&panel.top>=-1&&panel.right<=innerWidth+1&&panel.bottom<=innerHeight+1,
        target:!!target&&target.getClientRects().length>0, arrow:!document.querySelector('#guide-tour-arrow').hasAttribute('hidden')};
    });
    assert(geometry.fits && geometry.target && geometry.arrow, 'Usage guide remains visible and points at chart');
    await page.locator('#guide-tour-next').click();
  }
  await page.evaluate(() => window.NodeGuide.stop());
  if (await page.locator('#user-guide-dialog').isVisible()) await page.locator('#guide-close').click();
}

await fs.mkdir(output, {recursive:true});
try {
  const deployment=JSON.parse(await fs.readFile(path.join(folder,'traffic-charts-update.json'),'utf8'));
  const release=JSON.parse(await fs.readFile(path.join(folder,'traffic-charts-release-manifest.json'),'utf8'));
  assert(deployment.success && release.deployment_ip==='198.200.49.63', 'Chart deployment is complete');
  assert(process.env.NODE_CONSOLE_TEST_PROXY, 'Use the physical WLAN wrapper');
  browser=await chromium.launch({channel:'msedge',headless:true,proxy:{server:process.env.NODE_CONSOLE_TEST_PROXY}});
  const loginFiles=['panel-login.private.json','multiuser-user-a-login.private.json','multiuser-user-b-login.private.json'];
  for (let index=0; index<loginFiles.length; index++) {
    const key=['admin','user-a','user-b'][index];
    const login=JSON.parse(await fs.readFile(path.join(folder,loginFiles[index]),'utf8'));
    assert.equal(login.url,origin+'/node-console/');
    stage='trusted_login_'+key;
    const context=await browser.newContext({viewport:{width:1440,height:1100},reducedMotion:'reduce'});
    contexts.push(context);
    await context.route('**/*', async route => {
      const request=route.request(), url=new URL(request.url());
      if (url.origin!==origin || (request.method()!=='GET' &&
        !(request.method()==='POST'&&['/node-console/api/login','/node-console/api/logout'].includes(url.pathname)))) {
        blocked.push(url.origin===origin?url.pathname:'external_origin');return route.abort();
      }
      return route.continue();
    });
    const page=await context.newPage();
    page.on('pageerror',()=>errors.push('Browser JavaScript exception'));
    page.on('console',entry=>{if(entry.type()==='error')errors.push('Browser console error');});
    assert.equal((await page.goto(login.url,{waitUntil:'domcontentloaded',timeout:35000})).status(),200);
    await page.locator('#login-user').fill(login.username);
    await page.locator('#login-password').fill(login.password);
    await page.locator('#login-form button[type="submit"]').click();
    await page.locator('#console').waitFor({state:'visible',timeout:35000});
    await page.waitForFunction(username=>document.querySelector('#current-user-handle').textContent===username,login.username);
    stage='actual_chart_data_'+key;
    const before=await verifyLiveNumbers(page), fingerprint=hash(before.core);
    assert.equal(before.user.role,index===0?'admin':'member');
    const initialCount=Number(await page.locator('#traffic-rate-chart').getAttribute('data-sample-count'));
    if (before.traffic.available && before.traffic.sampled_at && initialCount) {
      await page.waitForFunction(count=>Number(document.querySelector('#traffic-rate-chart').dataset.sampleCount)>count,
        initialCount,{timeout:32000});
      await verifyLiveNumbers(page);
      const count=Number(await page.locator('#traffic-rate-chart').getAttribute('data-sample-count'));
      assert(count>=2, 'Auto refresh collects genuine new samples');
      const point=page.locator('#traffic-rate-points [data-traffic-sample][tabindex="0"]').first();
      await point.focus();assert.match(await point.getAttribute('aria-label'),/上传|下载/);
      await page.keyboard.press('ArrowLeft');
      assert.equal(await page.evaluate(()=>document.activeElement.hasAttribute('data-traffic-sample')),true);
      check(key+': real server samples update trend and keyboard values');
    }
    for (const width of [1440,390]) {
      stage='viewport_'+key+'_'+width;
      await page.setViewportSize({width,height:width===390?844:1100});
      await fit(page);await verifyLiveNumbers(page);await shot(page,key+'-traffic-'+width+'.png');
      if (width===390) {
        const sizes=await page.locator('.traffic-sample-controls button').evaluateAll(elements=>elements.map(element=>element.getBoundingClientRect().height));
        assert.equal(sizes.length,3);assert(sizes.every(height=>height>=44),'Mobile sampling controls have usable tap height');
      }
      await guide(page);await fit(page);
    }
    assert.equal(hash((await current(page)).core),fingerprint,'Chart inspection preserves account configuration');
    report.users.push({account:key,role:before.user.role,port:before.user.port,traffic_available:before.traffic.available,
      monthly_totals_match:true,desktop_and_mobile:true,sample_count:Number(await page.locator('#traffic-rate-chart').getAttribute('data-sample-count'))});
    check(key+': real monthly totals, desktop/mobile, arrow guide and configuration preservation');
    if (index===0) {
      stage='served_asset_hashes';
      for (const [name,resource] of Object.entries({'panel/web/index.html':'./','panel/web/app.js':'app.js','panel/web/style.css':'style.css'})) {
        const payload=await page.evaluate(async resource=>{const response=await fetch(new URL(resource,location.href),
          {cache:'no-store',signal:AbortSignal.timeout(20000)});if(!response.ok)throw new Error('Asset unavailable');return response.text();},resource);
        const digest=hash(payload);assert.equal(digest,release.source_sha256[name]);
        report.assets[name]={sha256:digest,release_match:true};
      }
    }
    await page.locator('#logout:visible, #logout-mobile:visible').click();await page.locator('#login-screen').waitFor({state:'visible'});
    assert.equal(await page.locator('#traffic-rate-points [data-traffic-sample]').count(),0,'Logout clears chart samples');
  }
  assert.deepEqual(errors,[],'No browser or CSP errors');assert.deepEqual(blocked,[],'No forbidden request');
  report.success=true;
} catch(error) {
  report.failure={stage,message:String(error.message||error).replace(/https?:\/\/\S+/g,'[URL redacted]')};
  process.exitCode=1;
} finally {
  report.browser_errors=errors;report.blocked_requests=blocked;
  for (const context of contexts) await context.close();
  await browser?.close();
  await fs.writeFile(path.join(folder,'traffic-charts-browser-verification.json'),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({success:report.success,stage,accounts:report.users.length,checks:report.checks.length}));
}
