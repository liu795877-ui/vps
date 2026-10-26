import {chromium} from '../../panel/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const folder=path.dirname(fileURLToPath(import.meta.url));
const origin='https://198-200-49-63.sslip.io:8443';
const output=path.join(folder,'multiuser-browser-ui');
const report={checked_at:new Date().toISOString(),deployment_ip:'198.200.49.63',success:false,
  trusted_https:true,transport:'physical WLAN; restricted CONNECT proxy',checks:[],screenshots:[],users:[]};
const errors=[];
const blocked=[];
const contexts=[];
const profiles=[];
let stage='deployment_gate';
let browser;
await fs.mkdir(output,{recursive:true});

function profileInfo(profile) {
  const program="import hashlib,json,sys,yaml\np=yaml.safe_load(sys.stdin.read())\nproxies=p['proxies']\nprint(json.dumps({'ports':[item['port'] for item in proxies],'count':len(proxies),'identities':[hashlib.sha256(item['uuid'].encode()).hexdigest() for item in proxies]}))";
  return JSON.parse(execFileSync('python',['-c',program],{input:profile,encoding:'utf8',windowsHide:true}));
}
async function readState(page) {
  return page.evaluate(async()=>{
    const response=await fetch('./api/state',{credentials:'same-origin',signal:AbortSignal.timeout(15000)});
    if(!response.ok) throw new Error('Authenticated state could not be read');
    return response.json();
  });
}
async function readUsers(page) {
  return page.evaluate(async()=>{
    const response=await fetch('./api/users',{credentials:'same-origin',signal:AbortSignal.timeout(15000)});
    if(!response.ok) throw new Error('Administrator user list could not be read');
    return response.json();
  });
}
async function noOverflow(page) {
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,
    'Page must fit the viewport');
}
async function screenshot(page,name) {
  await page.evaluate(()=>{document.querySelector('#toast').hidden=true;window.scrollTo({top:0,behavior:'instant'});});
  await page.screenshot({path:path.join(output,name),fullPage:true});
  report.screenshots.push(name);
}

try {
  const deployment=JSON.parse(await fs.readFile(path.join(folder,'multiuser-update.json'),'utf8'));
  const release=JSON.parse(await fs.readFile(path.join(folder,'multiuser-release-manifest.json'),'utf8'));
  assert.equal(deployment.success,true,'Complete deployment before browser acceptance');
  assert.equal(release.deployment_ip,'198.200.49.63');
  assert(process.env.NODE_CONSOLE_TEST_PROXY,'Run multiuser-browser-run.py to bind the physical WLAN');
  const names=['panel-login.private.json','multiuser-user-a-login.private.json','multiuser-user-b-login.private.json'];
  const logins=await Promise.all(names.map(async name=>JSON.parse(await fs.readFile(path.join(folder,name),'utf8'))));
  for(const login of logins) assert.equal(login.url,origin+'/node-console/');
  browser=await chromium.launch({channel:'msedge',headless:true,proxy:{server:process.env.NODE_CONSOLE_TEST_PROXY}});
  for(let index=0;index<logins.length;index++) {
    const login=logins[index];
    stage='trusted_login_'+index;
    const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce'});
    contexts.push(context);
    await context.route('**/*',async route=>{
      const request=route.request(),url=new URL(request.url());
      if(url.origin!==origin) {blocked.push('external_origin');await route.abort('blockedbyclient');return;}
      if(request.method()!=='GET'&&!['/node-console/api/login','/node-console/api/logout'].includes(url.pathname)) {
        blocked.push(url.pathname);await route.abort('blockedbyclient');return;
      }
      await route.continue();
    });
    const page=await context.newPage();
    page.on('pageerror',()=>errors.push('Browser JavaScript exception'));
    page.on('console',message=>{if(message.type()==='error') errors.push('Browser console error');});
    let navigation;
    for(let attempt=0;attempt<3;attempt++) {
      try {
        navigation=await page.goto(login.url,{waitUntil:'domcontentloaded',timeout:25000});
        if(navigation?.status()===200) break;
        assert([502,503,504].includes(navigation?.status()));
      } catch(error) {if(attempt===2) throw error;}
      await new Promise(resolve=>setTimeout(resolve,400));
    }
    assert.equal(navigation.status(),200);
    await page.locator('#login-user').fill(login.username);
    await page.locator('#login-password').fill(login.password);
    await page.locator('#login-form button[type="submit"]').click();
    await page.locator('#console').waitFor({state:'visible',timeout:35000});
    await page.waitForFunction(username=>document.querySelector('#current-user-handle').textContent===username,login.username);
    const before=await readState(page);
    assert.equal(before.user.username,login.username);
    assert.equal(before.user.role,index===0?'admin':'member');
    assert.equal(before.server_ip,'198.200.49.63');
    assert.equal(before.server_port,index===0?443:index===1?1443:2443);
    assert.equal(before.service_active,true);
    assert.equal(before.demo,false);
    assert.notEqual(before.job?.status,'running','Run browser checks after service verification settles');
    assert.equal(await page.locator('#users-nav').isVisible(),index===0);
    assert.equal(await page.locator('.nav-button:visible').count(),index===0?4:3);
    assert.equal(await page.locator('#current-user-space').innerText(),index===0?'管理员':'个人空间');
    if(index>0) {
      assert.equal(before.exits.length,0,'Fresh members have no administrator static exits');
      assert.equal(before.active_target,'server');
      assert(await page.locator('#empty-state').isVisible());
      assert.equal(await page.locator('#metric-active').innerText(),'服务器自身出口');
      assert.match(await page.locator('#path-server').innerText(),new RegExp(' : '+before.server_port+'$'));
    }
    const key=index===0?'admin':index===1?'user-a':'user-b';
    report.users.push({username:login.username,role:before.user.role,port:before.server_port,
      exit_count:before.exits.length,active_target:before.active_target,service_active:before.service_active});
    stage='profile_download_'+index;
    const waitDownload=page.waitForEvent('download');
    await page.locator('#download-top').click();
    const download=await waitDownload;
    assert.equal(download.suggestedFilename(),'clash-node-console-'+login.username+'.yaml');
    const privateProfile=path.join(folder,'multiuser-browser-'+key+'-profile.private.yaml');
    await download.saveAs(privateProfile);
    const profile=await fs.readFile(privateProfile,'utf8');
    const info=profileInfo(profile);
    assert(info.count>0);
    assert(info.ports.every(port=>port===before.server_port),'Profile must contain only this user entrance');
    profiles.push(info);
    report.checks.push(key+': trusted login, own identity/navigation and isolated '+before.server_port+' profile');
    stage='desktop_mobile_'+index;
    await noOverflow(page);await screenshot(page,key+'-overview-desktop.png');
    await page.locator('[data-view="routing"]').first().click();
    assert.equal(await page.locator('#domains').inputValue(),before.domains.join('\n'));
    assert.equal(await page.locator('#direct-domains').inputValue(),before.direct_domains.join('\n'));
    await page.locator('[data-view="access"]').first().click();
    assert.equal(await page.locator('#current-password').getAttribute('type'),'password');
    assert.equal(await page.locator('#new-password').inputValue(),'');
    await page.locator('[data-view="overview"]').first().click();
    await page.locator('#add-exit').click();
    assert.equal(await page.locator('#exit-socks-link').getAttribute('type'),'password');
    assert(await page.locator('#parse-socks-link').isVisible());
    await page.locator('#cancel-dialog').click();
    await page.waitForFunction(()=>!document.querySelector('#exit-dialog').open);
    await page.setViewportSize({width:390,height:844});
    await noOverflow(page);await screenshot(page,key+'-overview-mobile.png');
    if(index===0) {
      stage='administrator_users';
      await page.locator('#users-nav').click();
      await page.waitForFunction(()=>document.querySelector('#user-list').children.length===3);
      const listing=await readUsers(page);
      assert.equal(listing.users.length,3);
      assert.deepEqual(listing.users.map(user=>user.port).sort((a,b)=>a-b),[443,1443,2443]);
      assert.equal(await page.locator('#user-slots').innerText(),'3 / 3 个账号');
      assert(await page.locator('#create-user-submit').isDisabled());
      assert.equal(await page.locator('#create-user-password').getAttribute('type'),'password');
      assert.equal(await page.locator('#user-list [data-user-action="enabled"]:visible').count(),2);
      assert.equal(await page.locator('#user-list [data-user-action="reset"]:visible').count(),2);
      await noOverflow(page);await screenshot(page,'admin-users-mobile.png');
      await page.setViewportSize({width:1440,height:1000});
      await noOverflow(page);await screenshot(page,'admin-users-desktop.png');
      assert.deepEqual(await readUsers(page),listing);
      report.checks.push('Administrator sees three accounts, protected admin controls, masked empty forms and capacity limit');
      stage='public_assets';
      for(const [name,resource] of Object.entries({'panel/web/index.html':'','panel/web/style.css':'style.css','panel/web/app.js':'app.js'})) {
        const source=await page.evaluate(async resource=>{
          const response=await fetch(new URL(resource||'./',location.href),{cache:'no-store',signal:AbortSignal.timeout(15000)});
          if(!response.ok) throw new Error('Public asset read failed');
          return {text:await response.text(),cache:response.headers.get('cache-control')};
        },resource);
        assert.equal(createHash('sha256').update(source.text).digest('hex'),release.source_sha256[name]);
        assert.match(source.cache,/no-store/);
      }
      report.checks.push('All three public assets match the frozen reviewed release');
    }
    assert.deepEqual(await readState(page),before,'Browsing must preserve complete own public state');
    context.before=before;context.page=page;
    report.checks.push(key+': desktop/mobile fit, own routing/access views, SOCKS5 import preserved, state unchanged');
  }
  stage='cross_context_preservation';
  for(let a=0;a<profiles.length;a++) for(let b=a+1;b<profiles.length;b++)
    assert(profiles[a].identities.every(value=>!profiles[b].identities.includes(value)),'Users must have independent proxy credentials');
  for(const context of contexts) assert.deepEqual(await readState(context.page),context.before,
    'A different context browsing must not change this user state');
  assert.deepEqual(blocked,[],'No configuration mutation or external requests attempted');
  assert.deepEqual(errors,[],'No browser JavaScript or console errors');
  for(const context of contexts) {
    await context.page.setViewportSize({width:1440,height:1000});
    await context.page.locator('#logout').click();
    await context.page.locator('#login-screen').waitFor({state:'visible'});
    assert.equal(await context.page.locator('#user-list .user-card').count(),0);
  }
  report.independent_node_credentials=true;
  report.all_public_states_preserved=true;
  report.configuration_mutations_attempted=0;
  report.exit_switches=0;
  report.account_changes=0;
  report.checks.push('Three independent contexts retain states and credentials, clear user data on logout, and make no configuration mutations');
  report.success=true;
} catch(error) {
  report.failed_stage=stage;
  report.error='Multi-user browser acceptance failed; inspect its private diagnostic log.';
  await fs.writeFile(path.join(folder,'multiuser-browser-error.private.log'),String(error.stack||error),'utf8');
} finally {
  if(browser) await browser.close();
  await fs.writeFile(path.join(folder,'multiuser-browser-verification.json'),JSON.stringify(report,null,2),'utf8');
}
console.log(JSON.stringify(report));
if(!report.success) process.exitCode=1;
