import {chromium} from '../../panel/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';

const folder=path.dirname(fileURLToPath(import.meta.url));
const expectedOrigin='https://198-200-49-63.sslip.io:8443';
const expectedIP='198.200.49.63';
const output=path.join(folder,'ui-verification');
const report={checked_at:new Date().toISOString(),success:false,checks:[]};
const pause=(ms)=>new Promise(resolve=>setTimeout(resolve,ms));
let browser;
let stage='local_credentials';
await fs.mkdir(output,{recursive:true});
try {
  const login=JSON.parse(await fs.readFile(path.join(folder,'panel-login.private.json'),'utf8'));
  assert.equal(new URL(login.url).origin,expectedOrigin);
  assert.equal(new URL(login.url).pathname,'/node-console/');
  assert(process.env.NODE_CONSOLE_TEST_PROXY,'Run through run_browser_smoke.py to bind physical WLAN');
  stage='trusted_https_and_login';
  browser=await chromium.launch({channel:'msedge',headless:true,
    proxy:{server:process.env.NODE_CONSOLE_TEST_PROXY}});
  const context=await browser.newContext({viewport:{width:1440,height:1000}});
  const page=await context.newPage();
  const errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  async function get(resource,{raw=false}={}) {
    return page.evaluate(async({resource,raw})=> {
      for(let attempt=0;attempt<3;attempt++) {
        try {
          const response=await fetch('./api/'+resource,{credentials:'same-origin',signal:AbortSignal.timeout(12000)});
          if(response.ok) return raw?await response.text():await response.json();
          if(![502,503,504].includes(response.status)) throw new Error('Authenticated GET failed: '+response.status);
        } catch(error) {if(attempt===2) throw error;}
        await new Promise(resolve=>setTimeout(resolve,400));
      }
      throw new Error('Authenticated GET failed after bounded retries');
    },{resource,raw});
  }
  let response;
  for(let attempt=0;attempt<3;attempt++) {
    try {
      response=await page.goto(login.url,{waitUntil:'domcontentloaded',timeout:25000});
      if(response?.status()===200) break;
      if(![502,503,504].includes(response?.status())) throw new Error('Panel navigation failed');
    } catch(error) {if(attempt===2) throw error;}
    await pause(400);
  }
  assert.equal(response.status(),200);
  await page.locator('#login-user').fill(login.username);
  await page.locator('#login-password').fill(login.password);
  await page.getByRole('button',{name:/进入控制台/}).click();
  await page.locator('#console').waitFor({state:'visible',timeout:35000});
  await page.waitForFunction(()=>document.querySelector('#server-pill').textContent.includes('节点服务运行中'));
  report.checks.push('Normal TLS trust over physical WLAN and authenticated login');
  stage='live_server_and_region';
  const initialState=await get('state');
  assert.equal(initialState.server_ip,expectedIP);
  assert.equal(initialState.demo,false);
  assert.equal(initialState.service_active,true);
  assert.equal(initialState.server_location.ip,expectedIP);
  assert.equal(initialState.server_location.country_code,'US');
  const region=new Intl.DisplayNames(['zh-CN'],{type:'region'}).of(initialState.server_location.country_code);
  const city=initialState.server_location.city||initialState.server_location.region;
  await page.waitForFunction(({region,city,protocol})=>
    document.querySelector('#metric-server-detail').textContent===[region,city,protocol].filter(Boolean).join(' · '),
    {region,city,protocol:initialState.server_protocol},{timeout:35000});
  assert.equal(await page.locator('#path-server-name').textContent(),[region,city].filter(Boolean).join(' · ')+' VPS');
  assert.equal(await page.locator('#path-server').textContent(),expectedIP+' : '+initialState.server_port);
  assert(!(await page.locator('#console').textContent()).includes('东京'));
  assert.equal(initialState.client_config.group,'STATIC-SELECT');
  assert.equal(initialState.client_config.auto_node,'AUTO · 网页切换');
  assert.equal(initialState.client_config.refresh_required,false);
  assert.equal(initialState.client_config.nodes.length,initialState.client_config.exit_count);
  assert.equal(await page.locator('.exit-card').count(),initialState.exits.length);
  assert.equal(await page.locator('#path-server-button').isEnabled(),true);
  report.state={server_ip:expectedIP,active_target:initialState.active_target,exit_count:initialState.exits.length};
  report.checks.push('63 server location, protocol, port and stable AUTO metadata');
  stage='server_click';
  // Reapply only an already active server target. Existing static use is preserved.
  if(initialState.active_target==='server') {
    const responsePromise=page.waitForResponse(item=>{
      if(!item.url().endsWith('/api/apply')||item.request().method()!=='POST') return false;
      try{return item.request().postDataJSON().id==='server';}catch{return false;}
    },{timeout:35000});
    await page.locator('#path-server-button').click();
    const acceptedResponse=await responsePromise;
    assert.equal(acceptedResponse.status(),202);
    const accepted=await acceptedResponse.json();
    const deadline=Date.now()+90000;
    let complete=false;
    while(Date.now()<deadline) {
      const job=await get('jobs/'+encodeURIComponent(accepted.job_id));
      assert.notEqual(job.status,'failed');
      if(job.status==='success') {complete=true;break;}
      assert.equal(job.status,'running');
      await pause(600);
    }
    assert(complete,'Server click exceeded bounded job wait');
    const applied=await get('state');
    assert.equal(applied.active_target,'server');
    assert.equal(applied.service_active,true);
    assert.equal(applied.server_exit.observed_ip,expectedIP);
    await page.waitForFunction(()=>document.querySelector('#path-server-button').getAttribute('aria-pressed')==='true'&&
      document.querySelector('#network-card').dataset.target==='server');
    await page.waitForFunction(()=>!document.querySelector('#path-server-button').disabled);
    report.server_clicked=true;
    report.checks.push('Real server card click successfully applies the server target');
  } else {
    assert.equal(initialState.active_target,'static');
    report.server_clicked=false;
    report.checks.push('Server card enabled; existing static target preserved');
  }
  stage='exit_form_and_layout';
  if(initialState.exits.length<8) {
    await page.locator('#add-exit').click();
    await page.locator('#exit-dialog').waitFor({state:'visible'});
    for(const selector of ['#exit-name','#exit-address','#exit-port','#exit-auth','#save-exit'])
      assert.equal(await page.locator(selector).isVisible(),true);
    await page.locator('#cancel-dialog').click();
    await page.locator('#exit-dialog').waitFor({state:'hidden'});
    report.checks.push('New static exit form opens and cancels without saving an account');
  } else assert.equal(await page.locator('#add-exit').isEnabled(),false);
  if(initialState.exits.length===0) {
    assert.equal(await page.locator('#empty-state').isVisible(),true);
    assert.equal(await page.locator('#path-empty').isVisible(),true);
  }
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await page.screenshot({path:path.join(output,'desktop.png'),fullPage:true,animations:'disabled'});
  await page.locator('.nav-button[data-view="access"]').click();
  const ready=await get('state');
  assert.equal(ready.download_ready,true);
  assert((await page.locator('#client-config-summary').textContent()).includes('AUTO · 网页切换'));
  assert.equal(await page.locator('#view-access .download-button').isEnabled(),true);
  assert((await page.locator('#view-access').textContent()).includes('STATIC-SELECT'));
  assert((await page.locator('#view-access').textContent()).includes('无需重新下载'));
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await page.screenshot({path:path.join(output,'access-desktop.png'),fullPage:true,animations:'disabled'});
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await page.screenshot({path:path.join(output,'access-mobile.png'),fullPage:true,animations:'disabled'});
  await page.locator('.nav-button[data-view="overview"]').click();
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await page.screenshot({path:path.join(output,'mobile.png'),fullPage:true,animations:'disabled'});
  report.checks.push('1440px desktop and 390px mobile views have no horizontal overflow');
  stage='logout';
  await page.locator('#logout-mobile').click();
  await page.locator('#login-screen').waitFor({state:'visible'});
  assert.deepEqual(errors,[]);
  report.checks.push('Logout and no JavaScript exceptions');
  report.success=true;
} catch(error) {
  report.failed_stage=stage;
  report.error='Browser verification failed; inspect the private diagnostic log.';
  await fs.writeFile(path.join(folder,'browser-error.private.log'),String(error.stack||error),'utf8');
} finally {
  if(browser) await browser.close();
  await fs.writeFile(path.join(folder,'panel-browser-verification.json'),JSON.stringify(report,null,2),'utf8');
}
console.log(JSON.stringify(report));
if(!report.success) process.exitCode=1;
