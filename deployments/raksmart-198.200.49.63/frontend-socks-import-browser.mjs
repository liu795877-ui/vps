import {chromium} from '../../panel/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const folder=path.dirname(fileURLToPath(import.meta.url));
const origin='https://198-200-49-63.sslip.io:8443';
const output=path.join(folder,'frontend-socks-import-ui');
const report={checked_at:new Date().toISOString(),deployment_ip:'198.200.49.63',success:false,checks:[]};
const errors=[];
const blockedMutations=[];
let stage='prepared_release';
let browser;
await fs.mkdir(output,{recursive:true});

try {
  const release=JSON.parse(await fs.readFile(path.join(folder,'frontend-socks-import-release-manifest.json'),'utf8'));
  const deployed=JSON.parse(await fs.readFile(path.join(folder,'frontend-socks-import-update.json'),'utf8'));
  assert.equal(release.deployment_ip,'198.200.49.63');
  assert.equal(deployed.deployment_ip,'198.200.49.63');
  assert.equal(deployed.success,true,'Deploy the frozen release before online acceptance');
  assert.deepEqual(deployed.source_sha256,release.source_sha256);
  const login=JSON.parse(await fs.readFile(path.join(folder,'panel-login.private.json'),'utf8'));
  assert.equal(login.url,origin+'/node-console/');
  assert(process.env.NODE_CONSOLE_TEST_PROXY,'Use run_frontend_socks_import_browser.py to bind physical WLAN');

  stage='trusted_login';
  browser=await chromium.launch({channel:'msedge',headless:true,proxy:{server:process.env.NODE_CONSOLE_TEST_PROXY}});
  const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce'});
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
  async function layout() {
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,
      'The page must fit the current viewport');
    assert.equal(await page.locator('#exit-dialog').evaluate(dialog=>dialog.scrollWidth>dialog.clientWidth),false,
      'The dialog must fit without horizontal overflow');
  }
  async function cancelAndClear() {
    await page.locator('#cancel-dialog').click();
    await page.waitForFunction(()=>!document.querySelector('#exit-dialog').open);
    for(const name of ['#exit-socks-link','#exit-user','#exit-password'])
      assert.equal(await page.locator(name).inputValue(),'','Closing must clear sensitive dialog values');
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

  stage='synthetic_authenticated_parse';
  await page.locator('#add-exit').click();
  await page.locator('#exit-dialog').waitFor({state:'visible'});
  assert.equal(await page.locator('#exit-socks-link').getAttribute('type'),'password');
  assert.equal(await page.locator('#parse-socks-link').getAttribute('type'),'button');
  await layout();
  await page.screenshot({path:path.join(output,'add-exit-desktop.png'),fullPage:true});
  const syntheticUsername='demo@name';
  const syntheticPassword='demo:secret#%/+';
  const syntheticURI='socks5://'+encodeURIComponent(syntheticUsername)+':'+encodeURIComponent(syntheticPassword)+
    '@192.0.2.42:1443#'+encodeURIComponent('测试出口');
  await page.locator('#exit-socks-link').fill(syntheticURI);
  await page.locator('#parse-socks-link').click();
  assert.equal(await page.locator('#exit-address').inputValue(),'192.0.2.42');
  assert.equal(await page.locator('#exit-port').inputValue(),'1443');
  assert.equal(await page.locator('#exit-auth').inputValue(),'credentials');
  assert.equal(await page.locator('#exit-user').inputValue(),syntheticUsername);
  assert.equal(await page.locator('#exit-password').inputValue(),syntheticPassword);
  assert.equal(await page.locator('#exit-name').inputValue(),'测试出口');
  assert.equal(await page.locator('#exit-expected').inputValue(),'');
  assert.equal(await page.locator('#exit-socks-link').inputValue(),'');
  await cancelAndClear();
  report.checks.push('Local synthetic authenticated URI decodes fields and optional name, clears the URI, then cancel clears credentials');

  stage='synthetic_mobile_paste';
  await page.setViewportSize({width:390,height:844});
  await page.locator('#add-exit').click();
  await page.locator('#exit-dialog').waitFor({state:'visible'});
  await layout();
  await page.screenshot({path:path.join(output,'add-exit-mobile.png'),fullPage:true});
  await page.locator('#exit-name').fill('验收保留名称');
  await page.locator('#exit-socks-link').evaluate((input,uri)=> {
    const clipboardData=new DataTransfer();
    clipboardData.setData('text/plain',uri);
    // Untrusted ClipboardEvents have no native paste default action. Populate
    // the value that a real paste would insert before testing its deferred hook.
    input.value=uri;
    input.dispatchEvent(new ClipboardEvent('paste',{clipboardData,bubbles:true,cancelable:true}));
  },'socks5://192.0.2.43:1080#'+encodeURIComponent('不覆盖名称'));
  await page.waitForFunction(()=>document.querySelector('#exit-address').value==='192.0.2.43');
  assert.equal(await page.locator('#exit-address').inputValue(),'192.0.2.43');
  assert.equal(await page.locator('#exit-port').inputValue(),'1080');
  assert.equal(await page.locator('#exit-auth').inputValue(),'none');
  assert.equal(await page.locator('#exit-user').inputValue(),'');
  assert.equal(await page.locator('#exit-password').inputValue(),'');
  assert.equal(await page.locator('#exit-name').inputValue(),'验收保留名称');
  assert.equal(await page.locator('#exit-socks-link').inputValue(),'');
  await cancelAndClear();
  report.checks.push('390 px mobile dialog fits; synthetic unauthenticated paste fills locally and retains an existing custom name');

  stage='state_preservation_and_logout';
  assert.deepEqual(await state(),before,'All authenticated state must remain unchanged after read-only inspection');
  assert.deepEqual(blockedMutations,[],'The page must not attempt configuration mutations during inspection');
  assert.deepEqual(errors,[],'The page must not raise JavaScript exceptions');
  await page.setViewportSize({width:1440,height:1000});
  await page.locator('#logout').click();
  await page.locator('#login-screen').waitFor({state:'visible'});
  report.complete_public_state_unchanged=true;
  report.configuration_mutations_attempted=0;
  report.synthetic_exits_saved=0;
  report.exit_switches=0;
  report.checks.push('Complete public state is unchanged; no saves, switches, configuration POSTs or JavaScript exceptions; logout succeeds');
  report.success=true;
} catch(error) {
  report.failed_stage=stage;
  report.error='Frontend SOCKS5 import browser acceptance failed; inspect the private diagnostic log.';
  await fs.writeFile(path.join(folder,'frontend-socks-import-browser-error.private.log'),String(error.stack||error),'utf8');
} finally {
  if(browser) await browser.close();
  await fs.writeFile(path.join(folder,'frontend-socks-import-browser-verification.json'),JSON.stringify(report,null,2),'utf8');
}
console.log(JSON.stringify(report));
if(!report.success) process.exitCode=1;
