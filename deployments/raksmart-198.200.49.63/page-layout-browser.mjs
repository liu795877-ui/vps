import {chromium} from '../../panel/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const folder=path.dirname(fileURLToPath(import.meta.url)),origin='https://198-200-49-63.sslip.io:8443';
const output=path.join(folder,'page-layout-browser-ui');
const report={success:false,checked_at:new Date().toISOString(),deployment_ip:'198.200.49.63',
  trusted_https:true,physical_wlan:true,secrets_included:false,configuration_mutations:0,
  checks:[],users:[],screenshots:[],assets:{},layout_measurements:[]};
const errors=[],blocked=[],contexts=[],secretValues=[];
let browser,stage='deployment_gate';
const hash=value=>createHash('sha256').update(value).digest('hex');
const check=name=>report.checks.push(name);
async function api(page,resource){return page.evaluate(async resource=>{
  const response=await fetch('./api/'+resource,{credentials:'same-origin',signal:AbortSignal.timeout(20000)});
  if(!response.ok)throw new Error('Read-only endpoint unavailable');return response.json();
},resource);}
function core(state){const keys=['user','server_ip','server_port','exits','active','active_target',
  'routing_mode','domains','direct_domains','dirty','download_ready','client_config'];
  return hash(JSON.stringify(Object.fromEntries(keys.map(key=>[key,state[key]]))));}
async function nav(page,name){await page.locator('.nav-button[data-view="'+name+'"]').click();
  await page.locator('#view-'+name).waitFor({state:'visible'});}
async function fit(page){assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),
  false,'Page fits viewport');}
async function order(page,selectors){const result=await page.evaluate(selectors=>selectors.every((selector,index)=>{
  const current=document.querySelector(selector),previous=index?document.querySelector(selectors[index-1]):null;
  return !!current&&(!previous||!!(previous.compareDocumentPosition(current)&Node.DOCUMENT_POSITION_FOLLOWING));
}),selectors);assert(result,'Content follows the approved reading and keyboard order');}
async function openDetails(page,id){
  if(!await page.locator(id).evaluate(element=>element.open))await page.locator(id+' > summary').click();
  assert.equal(await page.locator(id).evaluate(element=>element.open),true);
}
async function closeDetails(page,id){
  if(await page.locator(id).evaluate(element=>element.open))await page.locator(id+' > summary').click();
  assert.equal(await page.locator(id).evaluate(element=>element.open),false);
}
async function shot(page,name){
  await page.evaluate(()=>{document.querySelector('#subscription-url').type='password';
    document.querySelector('#toast').hidden=true;window.scrollTo({top:0,behavior:'instant'});});
  await page.screenshot({path:path.join(output,name),fullPage:true,
    mask:[page.locator('#subscription-url')],maskColor:'#f4f2eb'});report.screenshots.push(name);
}
async function targetReady(page,selector){await page.waitForFunction(selector=>{
  const ring=document.querySelector('#guide-tour-highlight');
  return !ring.hidden&&!!ring.dataset.targetSelector&&(!selector||ring.dataset.targetSelector===selector);
},selector||null,{timeout:12000});}
async function tour(page,topic){
  const before=await page.locator('details[id]').evaluateAll(elements=>Object.fromEntries(elements.map(element=>[element.id,element.open])));
  await page.evaluate(topic=>window.NodeGuide.start(topic),topic);
  await page.locator('#guide-tour').waitFor({state:'visible'});
  for(let index=0;index<16;index++){
    await page.waitForFunction(step=>Number(document.querySelector('#guide-tour-counter').textContent.split('/')[0])===step,
      index+1,{timeout:12000});
    // These three steps explain actions in FlClash and intentionally have no
    // webpage target. Keep the other steps strict so broken arrows cannot pass.
    const external=topic==='first-client'&&index>=2&&index<=4;
    if(external)await page.waitForFunction(()=>document.querySelector('#guide-tour-highlight').hidden&&
      !document.querySelector('#guide-tour-highlight').dataset.targetSelector&&
      document.querySelector('#guide-tour-arrow').hasAttribute('hidden'),null,{timeout:12000});
    else await targetReady(page);
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    const geometry=await page.evaluate(()=>{
      const ring=document.querySelector('#guide-tour-highlight'),panel=document.querySelector('#guide-tour-panel'),
        svg=document.querySelector('#guide-tour-arrow'),line=document.querySelector('#guide-tour-arrow-line');
      const box=panel.getBoundingClientRect(),target=ring.dataset.targetSelector?
        document.querySelector(ring.dataset.targetSelector):null,targetBox=target?.getBoundingClientRect();
      const point=targetBox&&!svg.hasAttribute('hidden')&&line.getTotalLength()>0?
        line.getPointAtLength(line.getTotalLength()):null,
        end=point?new DOMPoint(point.x,point.y).matrixTransform(line.getScreenCTM()):null;
      return {fits:box.left>=-1&&box.top>=-1&&box.right<=innerWidth+1&&box.bottom<=innerHeight+1,
        target:!!targetBox&&targetBox.width>0&&targetBox.height>0,arrow:!svg.hasAttribute('hidden'),
        distance:targetBox&&end?Math.hypot(Math.max(targetBox.left-end.x,0,end.x-targetBox.right),
          Math.max(targetBox.top-end.y,0,end.y-targetBox.bottom)):null};
    });
    assert(geometry.fits,'Tour panel fits the viewport');
    if(external)assert(!geometry.target&&!geometry.arrow,'External client steps do not invent a webpage target');
    else{
      assert(geometry.target&&geometry.arrow,'Tour stays usable at the actual control');
      assert(geometry.distance<=20,'Arrow points to the target');
    }
    await page.locator('#guide-tour-next').click();
    if(!await page.locator('#guide-tour').isVisible())break;
    if(index===15)throw new Error('Guide did not finish');
  }
  await page.evaluate(()=>window.NodeGuide.stop());
  const after=await page.locator('details[id]').evaluateAll(elements=>Object.fromEntries(elements.map(element=>[element.id,element.open])));
  assert.deepEqual(after,before,'Tour restores each disclosure to its previous state');
  if(await page.locator('#user-guide-dialog').isVisible())await page.locator('#guide-close').click();
}
async function overview(page,width){
  await nav(page,'overview');await order(page,['.metrics-grid','#network-card','#job-panel','#exit-section','#health-card','.traffic-card']);
  assert(await page.locator('#network-card').isVisible());assert(await page.locator('#traffic-rate-chart').isVisible());
  assert(await page.locator('#health-summary').isVisible());
  await page.evaluate(()=>window.scrollTo({top:0,behavior:'instant'}));
  const geometry=await page.evaluate(()=>{
    const path=document.querySelector('#network-card').getBoundingClientRect(),health=document.querySelector('#health-card').getBoundingClientRect();
    const cards=[...document.querySelectorAll('#exit-list .exit-card')].map(element=>element.getBoundingClientRect());
    const server=document.querySelector('#path-server-button').getBoundingClientRect();
    return {pathTop:path.top,pathBottom:path.bottom,viewportHeight:innerHeight,
      pathDirection:getComputedStyle(document.querySelector('.connection-path')).flexDirection,
      serverControlVisible:server.width>0&&server.height>=44,
      fullHealth:Math.abs(path.width-health.width)<2,
      oneColumn:cards.every(card=>Math.abs(card.width-document.querySelector('#exit-list').getBoundingClientRect().width)<2)};
  });
  report.layout_measurements.push({stage,width,...geometry});
  assert(geometry.fullHealth,'Health card uses the full content width');
  assert(geometry.serverControlVisible,'Server switch remains visible with a usable touch target');
  if(width>=1280)assert(geometry.pathTop>=0&&geometry.pathBottom<=geometry.viewportHeight+1,
    'Desktop path fits the first viewport');
  if(width===390){
    assert(geometry.oneColumn,'Mobile exit cards use a single column');
    assert.equal(geometry.pathDirection,'column','Mobile path follows a vertical order');
  }
}
const innerHeightFor=width=>width===390?844:1000;

await fs.mkdir(output,{recursive:true});
try{
  const deployment=JSON.parse(await fs.readFile(path.join(folder,'page-layout-update.json'),'utf8'));
  const manifest=JSON.parse(await fs.readFile(path.join(folder,'page-layout-release-manifest.json'),'utf8'));
  assert(deployment.success&&manifest.deployment_ip==='198.200.49.63','Reviewed layout is deployed');
  assert(process.env.NODE_CONSOLE_TEST_PROXY,'Use the physical WLAN browser wrapper');
  browser=await chromium.launch({channel:'msedge',headless:true,proxy:{server:process.env.NODE_CONSOLE_TEST_PROXY}});
  const logins=await Promise.all(['panel-login.private.json','multiuser-user-a-login.private.json','multiuser-user-b-login.private.json']
    .map(async name=>JSON.parse(await fs.readFile(path.join(folder,name),'utf8'))));
  logins.forEach(login=>secretValues.push(login.password));
  for(let index=0;index<logins.length;index++){
    const login=logins[index],key=['admin','user-a','user-b'][index];
    assert.equal(login.url,origin+'/node-console/');stage='trusted_login_'+key;
    const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce'});contexts.push(context);
    await context.route('**/*',async route=>{
      const req=route.request(),url=new URL(req.url());
      if(url.origin!==origin){blocked.push('external_origin');return route.abort();}
      if(req.method()!=='GET'&&!(req.method()==='POST'&&['/node-console/api/login','/node-console/api/logout'].includes(url.pathname))){
        blocked.push(url.pathname);return route.abort();}
      return route.continue();
    });
    const page=await context.newPage();page.on('pageerror',()=>errors.push('Browser JavaScript exception'));
    page.on('console',entry=>{if(entry.type()==='error')errors.push('Browser console error');});
    assert.equal((await page.goto(login.url,{waitUntil:'domcontentloaded',timeout:35000})).status(),200);
    await page.locator('#login-user').fill(login.username);await page.locator('#login-password').fill(login.password);
    await page.locator('#login-form button[type="submit"]').click();await page.locator('#console').waitFor({state:'visible',timeout:35000});
    await page.waitForFunction(username=>document.querySelector('#current-user-handle').textContent===username,login.username);
    const before=await api(page,'state'),fingerprint=core(before);
    assert.equal(before.server_ip,'198.200.49.63');assert.equal(before.user.role,index===0?'admin':'member');assert(before.service_active);
    assert.equal(await page.locator('.nav-button:visible').count(),index===0?5:3);
    await page.waitForFunction(()=>!document.querySelector('#traffic-summary').textContent.includes('正在读取'));
    stage='collapsed_controls_'+key;
    assert.equal(await page.locator('#health-settings-form').isVisible(),false);
    await openDetails(page,'#health-settings-details');assert(await page.locator('#health-mode').isVisible());
    await tour(page,'health-fallback');assert.equal(await page.locator('#health-settings-details').evaluate(element=>element.open),true);
    await closeDetails(page,'#health-settings-details');await tour(page,'health-fallback');
    assert.equal(await page.locator('#health-settings-form').isVisible(),false);
    await nav(page,'access');await page.waitForFunction(()=>document.querySelector('#subscription-url').value.length>0);
    await order(page,['#subscription-card','.download-card','#password-details','#identity-card','#personal-audit-card']);
    assert.equal(await page.locator('#subscription-url').getAttribute('type'),'password');
    const audit=await api(page,'audit?limit=20');if(index>0)assert.equal(audit.scope,'own');
    await nav(page,'routing');assert(await page.locator('#direct-domains').isVisible());
    await order(page,['#routing-form','#routing-diagnostic-form','#routing-sync-details','#client-check-details']);
    stage='protected_draft_'+key;
    await page.locator('#direct-domains').fill('https://mooc1.chaoxing.com/path?readonly=synthetic');
    await page.locator('.nav-button[data-view="access"]').click();await page.locator('#draft-dialog').waitFor({state:'visible'});
    await page.locator('#draft-stay').click();assert(await page.locator('#view-routing').isVisible());
    await page.locator('.nav-button[data-view="access"]').click();await page.locator('#draft-discard').click();
    await page.locator('#view-access').waitFor({state:'visible'});
    assert.equal(await page.locator('#direct-domains').inputValue(),before.direct_domains.join('\n'));
    const topics=['overview','first-client','smart-routing','rule-diagnostic','password-logout','profile-subscription','usage-history',
      ...(index===0?['admin-create','admin-backups']:[])];
    for(const width of [1440,390]){
      stage='viewports_'+key+'_'+width;await page.setViewportSize({width,height:innerHeightFor(width)});
      await overview(page,width);await fit(page);await shot(page,key+'-overview-'+width+'.png');
      for(const name of ['routing','access']){await nav(page,name);await fit(page);await shot(page,key+'-'+name+'-'+width+'.png');}
      if(index===0){
        await nav(page,'users');await page.waitForFunction(()=>document.querySelectorAll('#user-list .user-card').length===3);
        await order(page,['#create-user-details','#members-list-card','#users-traffic-card']);
        assert.equal(await page.locator('#create-user-form').isVisible(),false);
        await openDetails(page,'#create-user-details');assert(await page.locator('#create-username').isVisible());
        assert.match(await page.locator('#create-user-capacity').textContent(),/删除.*释放名额/);
        await closeDetails(page,'#create-user-details');await fit(page);await shot(page,'admin-users-'+width+'.png');
        await nav(page,'maintenance');await page.waitForFunction(()=>document.querySelector('#backup-list').textContent.trim().length>0);
        await order(page,['#backup-schedule-form','#backup-create-card','#backup-restore-card','#admin-audit-card']);
        assert.match(await page.locator('#backup-file').getAttribute('accept'),/\.nvbackup/);await fit(page);
        await shot(page,'admin-maintenance-'+width+'.png');
      }else{
        await page.evaluate(()=>switchView('maintenance'));assert(!await page.locator('#view-maintenance').isVisible());
        await page.evaluate(()=>switchView('users'));assert(!await page.locator('#view-users').isVisible());
      }
      stage='folded_guides_'+key+'_'+width;
      for(const topic of topics){await tour(page,topic);await fit(page);}
    }
    await page.setViewportSize({width:1280,height:1000});await overview(page,1280);await fit(page);
    assert.equal(core(await api(page,'state')),fingerprint,'Layout inspection preserves real account settings');
    report.users.push({account:key,role:before.user.role,port:before.server_port,service_active:before.service_active,
      viewports:[1440,1280,390],own_settings_preserved:true,all_permitted_pages_verified:true,disclosure_guides_verified:true});
    check(key+': approved reading order, first viewport path, full-width health, mobile layouts, drafts and folded guides');
    if(index===0){stage='asset_hashes';for(const [name,resource] of Object.entries({'panel/web/index.html':'./','panel/web/app.js':'app.js','panel/web/style.css':'style.css'})){
      const payload=await page.evaluate(async resource=>{const response=await fetch(new URL(resource,location.href),
        {cache:'no-store',signal:AbortSignal.timeout(20000)});if(!response.ok)throw new Error('Asset unavailable');return response.text();},resource);
      const digest=hash(payload);assert.equal(digest,manifest.source_sha256[name]);report.assets[name]={sha256:digest,release_match:true};}
    }
    await page.locator('#logout:visible, #logout-mobile:visible').click();await page.locator('#login-screen').waitFor({state:'visible'});
    assert.equal(await page.locator('#subscription-url').inputValue(),'');
    assert.equal(await page.locator('#traffic-rate-points [data-traffic-sample]').count(),0);
    assert.equal(await page.locator('details[open]').count(),0,'Logout resets disclosure states');
  }
  assert.deepEqual(blocked,[],'No server mutation or other origin attempted');
  assert.deepEqual(errors,[],'No JavaScript or CSP errors');report.success=true;
}catch(error){let message=String(error.message||error).replace(/https?:\/\/\S+/g,'[URL redacted]');
  for(const value of secretValues)if(value)message=message.split(value).join('[redacted]');
  report.failure={stage,message};process.exitCode=1;
}finally{report.browser_errors=errors;report.blocked_requests=blocked;
  for(const context of contexts)await context.close();await browser?.close();
  await fs.writeFile(path.join(folder,'page-layout-browser-verification.json'),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({success:report.success,stage,accounts:report.users.length,checks:report.checks.length}));}
