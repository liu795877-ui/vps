import {chromium} from '../../panel/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const folder=path.dirname(fileURLToPath(import.meta.url));
const origin='https://198-200-49-63.sslip.io:8443';
const output=path.join(folder,'frontend-motion-ui');
const report={checked_at:new Date().toISOString(),deployment_ip:'198.200.49.63',success:false,checks:[]};
let browser;
let stage='prepared_release';
const errors=[];
const blockedMutations=[];
await fs.mkdir(output,{recursive:true});

try {
  const release=JSON.parse(await fs.readFile(path.join(folder,'frontend-motion-release-manifest.json'),'utf8'));
  const deployed=JSON.parse(await fs.readFile(path.join(folder,'frontend-motion-update.json'),'utf8'));
  assert.equal(release.deployment_ip,'198.200.49.63');
  assert.equal(deployed.deployment_ip,'198.200.49.63');
  assert.equal(deployed.success,true,'Deploy the frozen release before online acceptance');
  assert.deepEqual(deployed.source_sha256,release.source_sha256);
  const login=JSON.parse(await fs.readFile(path.join(folder,'panel-login.private.json'),'utf8'));
  assert.equal(login.url,origin+'/node-console/');
  assert(process.env.NODE_CONSOLE_TEST_PROXY,'Use run_frontend_motion_browser.py to bind physical WLAN');

  stage='trusted_login';
  browser=await chromium.launch({channel:'msedge',headless:true,proxy:{server:process.env.NODE_CONSOLE_TEST_PROXY}});
  const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'no-preference'});
  await context.route('**/api/**',async route=> {
    const request=route.request();
    const name=new URL(request.url()).pathname;
    if(request.method()!=='GET'&&!['/node-console/api/login','/node-console/api/logout'].includes(name)) {
      blockedMutations.push(name);
      await route.abort('blockedbyclient');
      return;
    }
    await route.continue();
  });
  const page=await context.newPage();
  page.on('pageerror',error=>errors.push(error.message));
  let response;
  for(let attempt=0;attempt<3;attempt++) {
    try {
      response=await page.goto(login.url,{waitUntil:'domcontentloaded',timeout:25000});
      if(response?.status()===200) break;
      assert([502,503,504].includes(response?.status()),'Unexpected public navigation status');
    } catch(error) {if(attempt===2) throw error;}
    await new Promise(resolve=>setTimeout(resolve,400));
  }
  assert.equal(response.status(),200);
  await page.locator('#login-user').fill(login.username);
  await page.locator('#login-password').fill(login.password);
  await page.getByRole('button',{name:/进入控制台/}).click();
  await page.locator('#console').waitFor({state:'visible',timeout:35000});
  await page.waitForFunction(()=>document.querySelector('#metric-server').textContent==='198.200.49.63');
  report.checks.push('Trusted HTTPS login through the physical WLAN');

  async function state() {
    return page.evaluate(async()=> {
      const response=await fetch('./api/state',{credentials:'same-origin',signal:AbortSignal.timeout(12000)});
      if(!response.ok) throw new Error('Read-only state request failed');
      return response.json();
    });
  }
  async function screenshot(name) {
    await page.evaluate(()=>window.scrollTo({top:0,behavior:'instant'}));
    await page.screenshot({path:path.join(output,name),fullPage:true});
  }
  async function layout() {
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,
      'The page must fit the current viewport');
  }
  async function viewVisible(name) {
    await page.locator('#view-'+name).waitFor({state:'visible'});
    await page.waitForFunction(name=> {
      const style=getComputedStyle(document.querySelector('#view-'+name));
      return style.opacity==='1'&&style.transform==='none';
    },name);
  }
  const before=await state();
  assert.equal(before.server_ip,'198.200.49.63');
  assert.equal(before.demo,false);
  assert.equal(before.service_active,true);
  assert.notEqual(before.job?.status,'running','A live exit operation must be idle');
  report.state={active_target:before.active_target,exit_count:before.exits.length,routing_mode:before.routing_mode};

  stage='public_release_fingerprint';
  const assets={'panel/web/index.html':'','panel/web/style.css':'style.css','panel/web/app.js':'app.js'};
  for(const [name,resource] of Object.entries(assets)) {
    const source=await page.evaluate(async resource=> {
      const response=await fetch(new URL(resource||'./',location.href),{cache:'no-store',signal:AbortSignal.timeout(12000)});
      if(!response.ok) throw new Error('Public asset request failed');
      return {content:await response.text(),cache:response.headers.get('cache-control')};
    },resource);
    assert.equal(createHash('sha256').update(source.content).digest('hex'),release.source_sha256[name]);
    assert.match(source.cache,/no-store/);
  }
  report.checks.push('All three public assets match the reviewed frozen release and use no-store');

  stage='animated_desktop_path';
  assert.equal(await page.locator('#path-device svg').count(),1);
  assert.equal(await page.locator('#path-server-button svg').count(),1);
  assert.equal(await page.locator('#path-server-button').getAttribute('aria-pressed'),String(before.active_target==='server'));
  assert.match(await page.locator('.path-motion-note').textContent(),/客户端确认/);
  const motion=await page.evaluate(()=> {
    const css=selector=>getComputedStyle(document.querySelector(selector)).animationName;
    return {device:css('.device-scan'),server:css('.server-led'),path:css('#client-connector .flow-particle')};
  });
  if(before.active_target) {
    assert.match(motion.device,/screen-scan/);
    assert.match(motion.server,/rack-breathe/);
    assert.match(motion.path,/path-particle/);
  }
  report.motion=motion;
  await page.locator('#path-server-button').hover();
  await page.locator('#path-server-button').focus();
  await layout();
  await screenshot('overview-desktop.png');
  report.checks.push('Desktop device, server indicators and configured path animations render; hover and focus remain read-only');

  stage='mobile_and_navigation';
  await page.setViewportSize({width:390,height:844});
  await layout();
  await screenshot('overview-mobile.png');
  for(const name of ['routing','access','overview']) {
    await page.locator('.nav-button[data-view="'+name+'"]').click();
    await viewVisible(name);
    await layout();
  }
  await page.setViewportSize({width:1440,height:1000});
  await layout();
  report.checks.push('Overview, routing and access fit desktop and 390 px mobile without horizontal overflow');

  stage='reduced_motion';
  await page.emulateMedia({reducedMotion:'reduce'});
  await page.waitForFunction(()=>matchMedia('(prefers-reduced-motion: reduce)').matches);
  await page.waitForFunction(()=>['.device-scan','.server-led','#client-connector .flow-particle']
    .every(selector=>getComputedStyle(document.querySelector(selector)).animationName==='none'));
  await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
  const reduced=await page.evaluate(()=> {
    const names=['.device-scan','.server-led','#client-connector .flow-particle'];
    return names.map(selector=>({name:getComputedStyle(document.querySelector(selector)).animationName,
      duration:getComputedStyle(document.querySelector(selector)).animationDuration}));
  });
  assert(reduced.every(value=>value.name==='none'||value.duration.split(',').every(raw=>parseFloat(raw)<=.001)),
    'Reduced motion must disable ongoing device, server and path animations');
  assert.equal(await page.evaluate(()=>document.querySelector('#network-card').getAnimations({subtree:true})
    .some(animation=>animation.playState==='running')),false,
    'Reduced motion must immediately cancel every running network card animation');
  await page.locator('.nav-button[data-view="routing"]').click();
  await viewVisible('routing');
  await page.locator('.nav-button[data-view="overview"]').click();
  await viewVisible('overview');
  await layout();
  await screenshot('overview-reduced-motion.png');
  report.checks.push('The operating system reduced motion preference disables ongoing motion and preserves navigation');

  stage='state_preservation_and_logout';
  assert.deepEqual(await state(),before,'All authenticated state must remain unchanged after read-only inspection');
  assert.deepEqual(blockedMutations,[],'The page must not attempt configuration mutations during inspection');
  assert.deepEqual(errors,[],'The page must not raise JavaScript exceptions');
  await page.locator('#logout').click();
  await page.locator('#login-screen').waitFor({state:'visible'});
  report.complete_public_state_unchanged=true;
  report.configuration_mutations_attempted=0;
  report.checks.push('Complete public state is unchanged; no configuration POSTs or JavaScript exceptions; logout succeeds');
  report.success=true;
} catch(error) {
  report.failed_stage=stage;
  report.error='Frontend motion browser acceptance failed; inspect the private diagnostic log.';
  await fs.writeFile(path.join(folder,'frontend-motion-browser-error.private.log'),String(error.stack||error),'utf8');
} finally {
  if(browser) await browser.close();
  await fs.writeFile(path.join(folder,'frontend-motion-browser-verification.json'),JSON.stringify(report,null,2),'utf8');
}
console.log(JSON.stringify(report));
if(!report.success) process.exitCode=1;
