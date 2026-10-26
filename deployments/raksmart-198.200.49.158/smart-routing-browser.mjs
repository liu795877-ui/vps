import {chromium} from '../../panel/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';

const folder=path.dirname(fileURLToPath(import.meta.url));
const expectedOrigin='https://198-200-49-158.sslip.io:8443';
const output=path.join(folder,'ui-verification');
const report={checked_at:new Date().toISOString(),success:false,checks:[]};
let browser;
let stage='local_credentials';
await fs.mkdir(output,{recursive:true});
function autoId(profile) {
  const section=profile.split('\nproxies:\n')[1]?.split('\nproxy-groups:\n')[0];
  assert(section,'Client profile must contain proxy nodes');
  const auto=section.split(/\n(?=  - name:)/).find(block=> {
    const raw=block.match(/^  - name: (.+)$/m)?.[1];
    return raw && JSON.parse(raw)==='AUTO · 网页切换';
  });
  assert(auto,'Client profile must contain the AUTO node');
  const raw=auto.match(/^    uuid: (.+)$/m)?.[1];
  assert(raw,'AUTO node must contain its stable UUID');
  return JSON.parse(raw);
}
try {
  const login=JSON.parse(await fs.readFile(path.join(folder,'panel-login.private.json'),'utf8'));
  assert.equal(new URL(login.url).origin,expectedOrigin);
  assert.equal(new URL(login.url).pathname,'/node-console/');
  assert(process.env.NODE_CONSOLE_TEST_PROXY,'Run through run_smart_browser.py to bind physical WLAN');
  stage='trusted_https_and_login';
  browser=await chromium.launch({channel:'msedge',headless:true,
    proxy:{server:process.env.NODE_CONSOLE_TEST_PROXY}});
  const context=await browser.newContext({viewport:{width:1440,height:1000}});
  const page=await context.newPage();
  const errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  async function screenshot(name) {
    await page.evaluate(()=>window.scrollTo({top:0,behavior:'instant'}));
    await page.waitForFunction(()=>window.scrollY===0);
    await page.screenshot({path:path.join(output,name),fullPage:true,animations:'disabled'});
  }
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
    await new Promise(resolve=>setTimeout(resolve,400));
  }
  assert.equal(response.status(),200);
  await page.locator('#login-user').fill(login.username);
  await page.locator('#login-password').fill(login.password);
  await page.getByRole('button',{name:/进入控制台/}).click();
  await page.locator('#console').waitFor({state:'visible',timeout:35000});
  report.checks.push('Trusted HTTPS login over physical WLAN');

  stage='smart_state_and_form';
  const before=await get('state');
  assert.equal(before.server_ip,'198.200.49.158');
  assert.equal(before.demo,false);
  assert.equal(before.service_active,true);
  assert.equal(before.routing_mode,'smart');
  assert.equal(before.download_ready,true);
  assert.equal(before.routing_subscription.enabled,true);
  assert.equal(before.routing_subscription.interval,300);
  assert.equal(before.active_target,'static','Existing active static exit must be preserved');
  assert(before.active?.id,'Existing static target must have an identity');
  assert.notEqual(before.job?.status,'running','Wait until deployment activation completes');
  const profileBefore=await get('profile',{raw:true});
  const uuidBefore=autoId(profileBefore);
  const providersLine=profileBefore.match(/^rule-providers: (.+)$/m)?.[1];
  assert(providersLine,'Smart routing profile must include subscriptions');
  const providers=JSON.parse(providersLine);
  for (const [name,direction,domains] of [
    ['Custom Direct','direct',before.direct_domains],['Custom Proxy','proxy',before.domains],
  ]) {
    const provider=providers[name];
    assert(provider,'Both domain lists must have rule subscriptions');
    assert.equal(provider.type,'http');
    assert.equal(provider.interval,300);
    assert.equal(provider.proxy,'DIRECT');
    const location=new URL(provider.url);
    assert.equal(location.origin,expectedOrigin);
    assert.match(location.pathname,new RegExp('/node-console/rules/custom/[A-Za-z0-9_-]{32,128}/'+direction+'\\.yaml$'));
    const content=await page.evaluate(async url=> {
      const response=await fetch(url,{credentials:'omit',signal:AbortSignal.timeout(12000)});
      if (!response.ok) throw new Error('Read-only rule subscription check failed: '+response.status);
      return await response.text();
    },provider.url);
    const payload=content.split('\n').filter(line=>line.startsWith('  - ')).map(line=>JSON.parse(line.slice(4)));
    assert.deepEqual(payload,domains.length?domains.map(domain=>'DOMAIN-SUFFIX,'+domain):['DOMAIN,empty-custom-'+direction+'.invalid']);
  }
  report.checks.push('Both 300-second rule subscriptions match the existing domain lists over trusted HTTPS');
  await page.locator('.nav-button[data-view="routing"]').click();
  assert.equal(await page.locator('#routing-mode').inputValue(),'smart');
  assert.equal(await page.locator('#routing-mode option[value="smart"]').textContent(),'智能分流 · 国内直连');
  assert.equal(await page.locator('#domains').inputValue(),before.domains.join('\n'));
  assert.equal(await page.locator('#direct-domains').inputValue(),before.direct_domains.join('\n'));
  assert.equal(await page.locator('#routing-smart-summary').isVisible(),true);
  assert.equal(await page.locator('#routing-service-summary').isVisible(),false);
  assert.match(await page.locator('#routing-mode-hint').textContent(),/本机网络/);
  assert.match(await page.locator('#routing-update-description').textContent(),/每 5 分钟自动同步/);
  report.checks.push('Smart mode and both domain lists agree with the authenticated API');

  stage='same_value_save';
  const pending=page.waitForResponse(value=>value.url().endsWith('/api/routing')&&value.request().method()==='POST',
    {timeout:35000});
  await page.getByRole('button',{name:'保存分流规则'}).click();
  const saved=await pending;
  assert.equal(saved.status(),200);
  assert.deepEqual(saved.request().postDataJSON(),{domains:before.domains.length?before.domains:[''],
    direct_domains:before.direct_domains.length?before.direct_domains:[''],mode:'smart'});
  await page.waitForFunction(()=>!document.querySelector('#routing-form button[type="submit"]').disabled);
  const feedback=await page.locator('#toast').textContent();
  assert.match(feedback,/5 分钟自动同步/);
  assert.match(feedback,/刷新客户端规则集/);
  assert.doesNotMatch(feedback,/重新下载|导入配置一次/);
  const after=await get('state');
  assert.equal(after.routing_mode,'smart');
  assert.deepEqual(after.domains,before.domains);
  assert.deepEqual(after.direct_domains,before.direct_domains);
  assert.equal(after.active_target,before.active_target);
  assert.equal(after.active?.id,before.active?.id);
  assert.deepEqual(after.active,before.active);
  assert.deepEqual(after.exits,before.exits);
  assert.deepEqual(after.client_config,before.client_config);
  assert.equal(autoId(await get('profile',{raw:true})),uuidBefore);
  report.state={server_ip:after.server_ip,active_target:after.active_target,
    exit_count:after.exits.length,direct_domain_count:after.direct_domains.length,
    proxy_domain_count:after.domains.length,subscription_interval_seconds:after.routing_subscription.interval};
  report.preservation={domain_lists:true,active_exit:true,exit_list:true,auto_uuid:true,client_metadata:true};
  report.checks.push('Saving the existing values preserves domain lists, active exit and AUTO UUID; feedback explains automatic updates');

  stage='routing_and_access_layout';
  await page.locator('#toast').waitFor({state:'hidden'});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await screenshot('smart-routing-desktop.png');
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await screenshot('smart-routing-mobile.png');
  await page.locator('.nav-button[data-view="access"]').click();
  assert.match(await page.locator('#client-config-summary').textContent(),/规则模式/);
  assert.match(await page.locator('#client-config-summary').textContent(),/AUTO · 网页切换/);
  assert.match(await page.locator('#client-config-summary').textContent(),/自动同步/);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await screenshot('smart-access-mobile.png');
  await page.setViewportSize({width:1440,height:1000});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await screenshot('smart-access-desktop.png');
  report.checks.push('Smart routing and client import guidance fit 1440 px desktop and 390 px mobile without horizontal overflow');

  stage='logout';
  await page.setViewportSize({width:390,height:844});
  await page.locator('#logout-mobile').click();
  await page.locator('#login-screen').waitFor({state:'visible'});
  assert.deepEqual(errors,[]);
  report.checks.push('Logout succeeds and the page reports no JavaScript exceptions');
  report.success=true;
} catch(error) {
  report.failed_stage=stage;
  report.error='Smart routing browser verification failed; inspect the private diagnostic log.';
  await fs.writeFile(path.join(folder,'smart-browser-error.private.log'),String(error.stack||error),'utf8');
} finally {
  if(browser) await browser.close();
  await fs.writeFile(path.join(folder,'smart-routing-browser-verification.json'),JSON.stringify(report,null,2),'utf8');
}
console.log(JSON.stringify(report));
if(!report.success) process.exitCode=1;
