import {chromium} from '../../panel/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const folder=path.dirname(fileURLToPath(import.meta.url)),origin='https://198-200-49-63.sslip.io:8443';
const output=path.join(folder,'operations-browser-ui');
const report={success:false,checked_at:new Date().toISOString(),deployment_ip:'198.200.49.63',trusted_https:true,
  safety:{server_mutations_allowed:false,subscription_tokens_redacted:true,profile_downloads:false,physical_wlan:true},checks:[],users:[],screenshots:[],assets:{}};
const errors=[],blocked=[],contexts=[];
let browser,stage='deployment_gate';
await fs.mkdir(output,{recursive:true});
const hash=value=>createHash('sha256').update(value).digest('hex');
const check=name=>report.checks.push(name);
async function api(page,resource){return page.evaluate(async resource=>{const response=await fetch('./api/'+resource,{credentials:'same-origin',signal:AbortSignal.timeout(20000)});if(!response.ok)throw new Error('Read-only endpoint unavailable');return response.json();},resource);}
async function fit(page){assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'Page fits desktop/mobile viewport');}
async function shot(page,name){
  await page.evaluate(()=>{document.querySelector('#subscription-url').type='password';document.querySelector('#toast').hidden=true;window.scrollTo({top:0,behavior:'instant'});});
  await page.screenshot({path:path.join(output,name),fullPage:true,mask:[page.locator('#subscription-url')],maskColor:'#f4f2eb'});report.screenshots.push(name);
}
function core(state){const keys=['user','server_ip','server_port','exits','active','active_target','routing_mode','domains','direct_domains','dirty','download_ready','client_config'];return hash(JSON.stringify(Object.fromEntries(keys.map(key=>[key,state[key]]))));}
async function nav(page,name){await page.locator('.nav-button[data-view="'+name+'"]').click();await page.locator('#view-'+name).waitFor({state:'visible'});}
async function tour(page,topic){
  await page.evaluate(topic=>window.NodeGuide.start(topic),topic);await page.locator('#guide-tour').waitFor({state:'visible'});
  for(let index=0;index<15;index++){
    await page.waitForFunction(()=>{const ring=document.querySelector('#guide-tour-highlight');return !ring.hidden&&!!ring.dataset.targetSelector;});
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    const geometry=await page.evaluate(()=>{
      const ring=document.querySelector('#guide-tour-highlight'),panel=document.querySelector('#guide-tour-panel'),svg=document.querySelector('#guide-tour-arrow'),line=document.querySelector('#guide-tour-arrow-line');
      const box=panel.getBoundingClientRect(),target=ring.dataset.targetSelector?document.querySelector(ring.dataset.targetSelector):null,targetBox=target?.getBoundingClientRect();
      const point=line.getTotalLength()>0?line.getPointAtLength(line.getTotalLength()):null,end=point?new DOMPoint(point.x,point.y).matrixTransform(line.getScreenCTM()):null;
      return {panelFits:box.left>=0&&box.top>=0&&box.right<=innerWidth+1&&box.bottom<=innerHeight+1,external:ring.hidden,
        arrowVisible:!svg.hasAttribute('hidden')&&svg.getClientRects().length>0,
        targetVisible:!!targetBox&&targetBox.width>0&&targetBox.height>0,
        targetDistance:targetBox&&end?Math.hypot(Math.max(targetBox.left-end.x,0,end.x-targetBox.right),Math.max(targetBox.top-end.y,0,end.y-targetBox.bottom)):null};
    });
    assert(geometry.panelFits,'Guide instruction card fits viewport');
    if(!geometry.external){assert(geometry.arrowVisible&&geometry.targetVisible,'Guide arrow has a visible control');assert(geometry.targetDistance<=20,'Arrow points to the actual control');}
    await page.locator('#guide-tour-next').click();if(!await page.locator('#guide-tour').isVisible())break;if(index===14)throw new Error('Guide did not end');
  }
  await page.evaluate(()=>window.NodeGuide.stop());
}
try{
  const deployment=JSON.parse(await fs.readFile(path.join(folder,'operations-update.json'),'utf8'));
  const release=JSON.parse(await fs.readFile(path.join(folder,'operations-release-manifest.json'),'utf8'));
  assert(deployment.success,'Wait until operations deployment is complete');assert.equal(release.deployment_ip,'198.200.49.63');
  const assets=release.source_sha256;assert(assets['panel/web/app.js']&&assets['panel/web/index.html']&&assets['panel/web/style.css']);
  assert(process.env.NODE_CONSOLE_TEST_PROXY,'Run the physical WLAN browser wrapper');
  const loginFiles=['panel-login.private.json','multiuser-user-a-login.private.json','multiuser-user-b-login.private.json'];
  const logins=await Promise.all(loginFiles.map(async name=>JSON.parse(await fs.readFile(path.join(folder,name),'utf8'))));
  browser=await chromium.launch({channel:'msedge',headless:true,proxy:{server:process.env.NODE_CONSOLE_TEST_PROXY}});
  const subscriptionHashes=[];
  for(let index=0;index<logins.length;index++){
    const login=logins[index],key=index===0?'admin':index===1?'user-a':'user-b';assert.equal(login.url,origin+'/node-console/');stage='trusted_login_'+key;
    const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce'});contexts.push(context);
    await context.route('**/*',async route=>{
      const req=route.request(),url=new URL(req.url());
      if(url.origin!==origin){blocked.push('external_origin');return route.abort();}
      if(req.method()!=='GET'&&!(req.method()==='POST'&&['/node-console/api/login','/node-console/api/logout'].includes(url.pathname))){blocked.push(url.pathname);return route.abort();}
      return route.continue();
    });
    const page=await context.newPage();page.on('pageerror',()=>errors.push('Browser JavaScript exception'));page.on('console',entry=>{if(entry.type()==='error')errors.push('Browser console error');});
    const navigation=await page.goto(login.url,{waitUntil:'domcontentloaded',timeout:35000});assert.equal(navigation.status(),200);
    await page.locator('#login-user').fill(login.username);await page.locator('#login-password').fill(login.password);await page.locator('#login-form button[type="submit"]').click();await page.locator('#console').waitFor({state:'visible',timeout:35000});
    await page.waitForFunction(username=>document.querySelector('#current-user-handle').textContent===username,login.username);
    const before=await api(page,'state'),fingerprint=core(before);assert.equal(before.user.username,login.username);assert.equal(before.user.role,index===0?'admin':'member');assert.equal(before.server_ip,'198.200.49.63');assert(before.service_active);assert(!before.demo);
    assert.equal(await page.locator('.nav-button:visible').count(),index===0?5:3);assert.equal(await page.locator('#maintenance-nav').isVisible(),index===0);
    assert(await page.locator('#health-settings-form').isVisible());assert(await page.locator('#traffic-summary').isVisible());assert(before.health);assert(before.traffic);
    report.users.push({account:key,role:before.user.role,port:before.server_port,service_active:before.service_active,exit_count:before.exits.length,health_status:before.health.status,traffic_available:before.traffic.available});
    stage='own_subscription_'+key;await nav(page,'access');await page.waitForFunction(()=>document.querySelector('#subscription-url').value.length>0);
    const subscription=await api(page,'subscription');assert.equal(await page.locator('#subscription-url').getAttribute('type'),'password');assert.equal(await page.locator('#subscription-url').inputValue(),subscription.url);assert.match(await page.locator('#subscription-version').innerText(),/网页无法确认/);subscriptionHashes.push(hash(subscription.url));
    const audit=await api(page,'audit?limit=50');if(index>0)assert.equal(audit.scope,'own');assert(Array.isArray(audit.events));
    stage='routing_and_draft_'+key;await nav(page,'routing');assert(await page.locator('#diagnostic-url').isVisible());assert.match(await page.locator('#client-checklist').innerText(),/规则模式/);assert.match(await page.locator('#client-checklist').innerText(),/服务器无法/);
    await page.locator('#direct-domains').fill('https://mooc1.chaoxing.com/path?readonly=synthetic');await page.locator('.nav-button[data-view="access"]').click();await page.locator('#draft-dialog').waitFor({state:'visible'});await page.locator('#draft-stay').click();assert(await page.locator('#view-routing').isVisible());await page.locator('.nav-button[data-view="access"]').click();await page.locator('#draft-discard').click();await page.locator('#view-access').waitFor({state:'visible'});assert.equal(await page.locator('#direct-domains').inputValue(),before.direct_domains.join('\n'));
    const topics=['draft-safety','rule-diagnostic','health-fallback','profile-subscription','usage-history',...(index===0?['admin-backups','admin-lifecycle']:[])];
    for(const width of [1440,390]){
      stage='new_guides_'+key+'_'+width;await page.setViewportSize({width,height:width===390?844:1000});await fit(page);
      for(const topic of topics){await tour(page,topic);await fit(page);}
      await nav(page,'overview');await shot(page,key+'-overview-'+width+'.png');await nav(page,'access');await page.waitForFunction(()=>document.querySelector('#subscription-url').value.length>0);await shot(page,key+'-access-'+width+'.png');
      if(index===0){await nav(page,'maintenance');await page.waitForFunction(()=>document.querySelector('#backup-list').textContent.trim().length>0);assert.match(await page.locator('#backup-file').getAttribute('accept'),/\.nvbackup/);await shot(page,'admin-maintenance-'+width+'.png');await nav(page,'users');await page.waitForFunction(()=>document.querySelectorAll('#user-list .user-card').length===3);const listing=await api(page,'users');assert(listing.users.every(user=>user.traffic&&typeof user.traffic.available==='boolean'),'Actual backend user listing provides account telemetry');assert.match(await page.locator('#users-traffic-summary').innerText(),/3 个账号/);assert.equal(await page.locator('#users-traffic-facts dt').count(),4);assert.equal(await page.locator('#user-list .user-traffic-facts dt').count(),24);assert.match(await page.locator('#create-user-capacity').innerText(),/删除.*释放名额.*停用.*保留名额/);assert.equal(await page.locator('[data-user-action="delete"]:visible').count(),2);assert.equal(await page.locator('[data-user-action="rotate"]:visible').count(),2);await shot(page,'admin-users-'+width+'.png');}
      else {await page.evaluate(()=>switchView('maintenance'));assert(!await page.locator('#view-maintenance').isVisible());await page.evaluate(()=>switchView('users'));assert(!await page.locator('#view-users').isVisible());}
    }
    await nav(page,'overview');assert.equal(core(await api(page,'state')),fingerprint,'Read-only UI checks preserve account configuration');
    check(key+': own subscription and scoped history, protected drafts, all new guides, desktop/mobile views and preserved configuration');
    if(index===0){stage='asset_hashes';for(const [name,resource] of Object.entries({'panel/web/index.html':'./','panel/web/app.js':'app.js','panel/web/style.css':'style.css'})){const text=await page.evaluate(async resource=>{const response=await fetch(new URL(resource,location.href),{cache:'no-store',signal:AbortSignal.timeout(20000)});if(!response.ok)throw new Error('Asset unavailable');return response.text();},resource);const digest=hash(text);assert.equal(digest,assets[name]);report.assets[name]={sha256:digest,release_match:true};}}
  }
  assert.equal(new Set(subscriptionHashes).size,3,'Full configuration subscription URLs are independent');assert.deepEqual(blocked,[],'No mutating request or other origin was attempted');assert.deepEqual(errors,[],'No JavaScript/console errors');check('Three independent subscription URLs and deployed asset hashes match frozen release');report.success=true;
}catch(error){report.failure={stage,message:String(error.message||error).replace(/https?:\/\/\S+/g,'[URL redacted]')};process.exitCode=1;}
finally{report.browser_errors=errors;report.blocked_requests=blocked;for(const context of contexts)await context.close();await browser?.close();await fs.writeFile(path.join(folder,'operations-browser-verification.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({success:report.success,stage,accounts:report.users.length,checks:report.checks.length,report:path.join(folder,'operations-browser-verification.json')}));}
