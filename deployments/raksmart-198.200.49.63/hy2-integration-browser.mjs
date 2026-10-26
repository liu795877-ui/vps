import {chromium} from '../../panel/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const folder=path.dirname(fileURLToPath(import.meta.url));
const origin='https://198-200-49-63.sslip.io:8443';
const output=path.join(folder,'hy2-browser-ui');
const report={success:false,checked_at:new Date().toISOString(),deployment_ip:'198.200.49.63',
  trusted_https:true,physical_wlan:true,secrets_included:false,configuration_mutations:0,
  checks:[],users:[],screenshots:[],assets:{}};
const errors=[],blocked=[],contexts=[],secretValues=[];
let browser,stage='local_preparation_gate';
const hash=value=>createHash('sha256').update(value).digest('hex');
const check=name=>report.checks.push(name);

async function api(page,resource){return page.evaluate(async resource=>{
  const response=await fetch('./api/'+resource,{credentials:'same-origin',signal:AbortSignal.timeout(20000)});
  if(!response.ok)throw new Error('Read-only endpoint unavailable');return response.json();
},resource);}
function core(state){const keys=['user','server_ip','server_port','exits','active','active_target',
  'routing_mode','domains','direct_domains','dirty','download_ready','client_config','transport'];
  return hash(JSON.stringify(Object.fromEntries(keys.map(key=>[key,state[key]]))));}
async function nav(page,name){await page.locator('.nav-button[data-view="'+name+'"]').click();
  await page.locator('#view-'+name).waitFor({state:'visible'});}
async function fit(page){assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1),
  false,'Page fits viewport');}
async function order(page,selectors){assert(await page.evaluate(selectors=>selectors.every((selector,index)=>{
  const current=document.querySelector(selector),previous=index?document.querySelector(selectors[index-1]):null;
  return !!current&&(!previous||!!(previous.compareDocumentPosition(current)&Node.DOCUMENT_POSITION_FOLLOWING));
}),selectors),'Approved reading order is preserved');}
async function shot(page,name){
  await page.evaluate(()=>{document.querySelector('#subscription-url').type='password';
    document.querySelector('#toast').hidden=true;window.scrollTo({top:0,behavior:'instant'});});
  await page.screenshot({path:path.join(output,name),fullPage:true,
    mask:[page.locator('#subscription-url')],maskColor:'#f4f2eb'});report.screenshots.push(name);
}
async function guide(page,topic,steps=2){
  const before=await page.locator('details[id]').evaluateAll(elements=>Object.fromEntries(elements.map(element=>[element.id,element.open])));
  await page.evaluate(topic=>window.NodeGuide.start(topic),topic);
  await page.locator('#guide-tour').waitFor({state:'visible'});
  for(let step=0;step<steps;step++){
    await page.waitForFunction(step=>Number(document.querySelector('#guide-tour-counter').textContent.split('/')[0])===step,
      step+1,{timeout:12000});
    await page.waitForFunction(()=>!document.querySelector('#guide-tour-highlight').hidden&&
      !!document.querySelector('#guide-tour-highlight').dataset.targetSelector,null,{timeout:12000});
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    const geometry=await page.evaluate(()=>{
      const ring=document.querySelector('#guide-tour-highlight'),box=document.querySelector('#guide-tour-panel').getBoundingClientRect();
      const target=document.querySelector(ring.dataset.targetSelector),targetBox=target?.getBoundingClientRect();
      const svg=document.querySelector('#guide-tour-arrow'),line=document.querySelector('#guide-tour-arrow-line');
      const point=targetBox&&!svg.hasAttribute('hidden')&&line.getTotalLength()>0?
        line.getPointAtLength(line.getTotalLength()):null;
      const end=point?new DOMPoint(point.x,point.y).matrixTransform(line.getScreenCTM()):null;
      return {fits:box.left>=-1&&box.top>=-1&&box.right<=innerWidth+1&&box.bottom<=innerHeight+1,
        target:!!targetBox&&targetBox.width>0&&targetBox.height>0,arrow:!svg.hasAttribute('hidden'),
        distance:targetBox&&end?Math.hypot(Math.max(targetBox.left-end.x,0,end.x-targetBox.right),
          Math.max(targetBox.top-end.y,0,end.y-targetBox.bottom)):null};
    });
    assert(geometry.fits&&geometry.target&&geometry.arrow&&geometry.distance<=20,'Guide points to a real visible control');
    if(step+1<steps)await page.locator('#guide-tour-next').click();
  }
  await page.evaluate(()=>window.NodeGuide.stop());
  const after=await page.locator('details[id]').evaluateAll(elements=>Object.fromEntries(elements.map(element=>[element.id,element.open])));
  assert.deepEqual(after,before,'Guide restores prior disclosure states');
  if(await page.locator('#user-guide-dialog').isVisible())await page.locator('#guide-close').click();
}
async function transport(page,state){
  assert.equal(state.transport?.enabled,true,'Account HY2 integration is enabled');
  assert.deepEqual(state.transport.protocols,['hysteria2','vless']);
  assert.equal(state.transport.hy2_port,state.server_port);
  assert.match(await page.locator('#metric-server-detail').textContent(),/HY2.*REALITY.*双入口/);
  const traffic=await api(page,'traffic');
  assert.deepEqual(Object.keys(traffic.sources||{}).sort(),['hy2','xray']);
  assert.equal(traffic.sources.hy2.available,true,'HY2 live counter source is available');
  assert.equal(traffic.sources.xray.available,true,'REALITY live counter source is available');
  assert.match(traffic.scope,/本服务器.*本机 DIRECT.*不计入/);
  assert.match(traffic.connection_scope,/REALITY TCP.*HY2 QUIC.*不等于设备数/);
  assert.match(await page.locator('#traffic-accounting-note').textContent(),/HY2.*REALITY.*月额度.*限速.*DIRECT.*不计入.*QUIC/);
  assert(await page.locator('#traffic-donut').isVisible());assert(await page.locator('#traffic-rate-chart').isVisible());
  return traffic;
}

await fs.mkdir(output,{recursive:true});
try{
  const expectations=JSON.parse(await fs.readFile(path.join(folder,'hy2-browser-expectations.json'),'utf8'));
  assert.equal(expectations.deployment_ip,'198.200.49.63');
  assert.equal(expectations.scenario_sha256,hash(await fs.readFile(fileURLToPath(import.meta.url))));
  assert(process.env.NODE_CONSOLE_TEST_PROXY,'Use the restricted physical-WLAN wrapper');
  browser=await chromium.launch({channel:'msedge',headless:true,proxy:{server:process.env.NODE_CONSOLE_TEST_PROXY}});
  const loginFiles=['panel-login.private.json','multiuser-user-a-login.private.json','multiuser-user-b-login.private.json'];
  for(let index=0;index<loginFiles.length;index++){
    const login=JSON.parse(await fs.readFile(path.join(folder,loginFiles[index]),'utf8'));
    secretValues.push(login.password);
    const key=['admin','user-a','user-b'][index];
    assert.equal(login.url,origin+'/node-console/');stage='trusted_login_'+key;
    const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce',ignoreHTTPSErrors:false});
    contexts.push(context);
    await context.route('**/*',async route=>{
      const request=route.request(),url=new URL(request.url());
      if(url.origin!==origin || (request.method()!=='GET' &&
        !(request.method()==='POST'&&['/node-console/api/login','/node-console/api/logout'].includes(url.pathname)))){
        blocked.push(url.origin===origin?url.pathname:'external_origin');return route.abort();
      }
      return route.continue();
    });
    const page=await context.newPage();
    page.on('pageerror',()=>errors.push('Browser JavaScript exception'));
    page.on('console',entry=>{if(entry.type()==='error')errors.push('Browser console or CSP error');});
    assert.equal((await page.goto(login.url,{waitUntil:'domcontentloaded',timeout:35000})).status(),200);
    await page.locator('#login-user').fill(login.username);await page.locator('#login-password').fill(login.password);
    await page.locator('#login-form button[type="submit"]').click();
    await page.locator('#console').waitFor({state:'visible',timeout:35000});
    await page.waitForFunction(username=>document.querySelector('#current-user-handle').textContent===username,login.username);
    const before=await api(page,'state'),configurationHash=core(before);
    assert.equal(before.server_ip,'198.200.49.63');assert.equal(before.user.role,index===0?'admin':'member');assert(before.service_active);
    assert.equal(await page.locator('.nav-button:visible').count(),index===0?5:3);
    stage='dual_transport_telemetry_'+key;
    await page.waitForFunction(()=>!document.querySelector('#traffic-summary').textContent.includes('正在读取'));
    const traffic=await transport(page,before);
    for(const width of [1440,390]){
      stage='approved_layout_'+key+'_'+width;
      await page.setViewportSize({width,height:width===390?844:1000});
      await nav(page,'overview');await fit(page);
      await order(page,['.metrics-grid','#network-card','#job-panel','#exit-section','#health-card','.traffic-card']);
      assert(await page.locator('#network-card').isVisible());assert(await page.locator('#health-summary').isVisible());
      assert.equal(await page.locator('#health-settings-details').evaluate(element=>element.open),false);
      await transport(page,before);await shot(page,key+'-overview-'+width+'.png');
      await guide(page,'usage-history',2);
      await nav(page,'routing');await fit(page);
      await order(page,['#routing-form','#routing-diagnostic-form','#routing-sync-details','#client-check-details']);
      assert(await page.locator('#direct-domains').isVisible());assert(await page.locator('#domains').isVisible());
      await shot(page,key+'-routing-'+width+'.png');await guide(page,'smart-routing',2);
      await nav(page,'access');await page.waitForFunction(()=>document.querySelector('#subscription-url').value.length>0);
      await fit(page);await order(page,['#subscription-card','.download-card','#password-details','#identity-card','#personal-audit-card']);
      assert.equal(await page.locator('#subscription-url').getAttribute('type'),'password');
      assert(await page.locator('#transport-update-notice').isVisible());
      assert.match(await page.locator('#transport-update-notice').textContent(),/首次.*完整订阅.*AUTO.*网页不确认/);
      assert.match(await page.locator('#client-config-update').textContent(),/HY2.*REALITY.*TCP兼容.*客户端连接记录.*无法确认/);
      assert.doesNotMatch(await page.locator('#transport-update-notice').textContent(),/当前使用 HY2|客户端已更新|客户端已同步|HY2 已连接/);
      assert.equal(await page.locator('#password-details').evaluate(element=>element.open),false);
      assert.equal(await page.locator('#identity-details').evaluate(element=>element.open),false);
      await shot(page,key+'-access-'+width+'.png');await guide(page,'password-logout',1);
      if(index===0){
        await nav(page,'users');await page.waitForFunction(()=>document.querySelectorAll('#user-list .user-card').length===3);
        await fit(page);await order(page,['#create-user-details','#members-list-card','#users-traffic-card']);
        assert.equal(await page.locator('#create-user-details').evaluate(element=>element.open),false);
        const users=await api(page,'users');assert.equal(users.users.length,3);
        assert(users.users.every(user=>Object.keys(user.traffic?.sources||{}).sort().join(',')==='hy2,xray'));
        await shot(page,'admin-users-'+width+'.png');await guide(page,'admin-create',1);
        await nav(page,'maintenance');await page.waitForFunction(()=>document.querySelector('#backup-list').textContent.trim().length>0);
        await fit(page);await order(page,['#backup-schedule-form','#backup-create-card','#backup-restore-card','#admin-audit-card']);
        await shot(page,'admin-maintenance-'+width+'.png');await guide(page,'admin-backups',1);
      }else{
        assert.equal(await page.locator('#users-nav').isVisible(),false);assert.equal(await page.locator('#maintenance-nav').isVisible(),false);
      }
      check(key+' '+width+': dual entrance notices, permitted page order, charts and arrows are usable');
    }
    stage='configuration_preservation_'+key;
    assert.equal(core(await api(page,'state')),configurationHash,'Browser inspection preserves account configuration');
    if(index===0){
      stage='frozen_frontend_assets';
      for(const [name,resource] of Object.entries({'panel/web/index.html':'./','panel/web/app.js':'app.js','panel/web/style.css':'style.css'})){
        const payload=await page.evaluate(async resource=>{
          const response=await fetch(new URL(resource,location.href),{cache:'no-store',signal:AbortSignal.timeout(20000)});
          if(!response.ok)throw new Error('Public asset unavailable');return response.text();
        },resource);
        const digest=hash(payload);assert.equal(digest,expectations.frozen_frontend_sha256[name]);
        report.assets[name]={sha256:digest,freeze_match:true};
      }
    }
    report.users.push({account:key,role:before.user.role,port:before.server_port,
      traffic_sources:Object.keys(traffic.sources).sort(),traffic_scope_verified:true,
      dual_transport_notice_verified:true,desktop_and_mobile:true,settings_preserved:true,
      permitted_page_count:index===0?5:3,guide_verified:true});
    stage='logout_'+key;
    await page.locator('#logout:visible, #logout-mobile:visible').first().click();
    await page.locator('#login-screen').waitFor({state:'visible'});
    assert.equal(await page.locator('#transport-update-notice').textContent(),'');
    assert.equal(await page.locator('#subscription-url').inputValue(),'');
    assert.equal(await page.locator('#traffic-rate-points [data-traffic-sample]').count(),0);
  }
  assert.deepEqual(blocked,[],'No configuration mutation or external origin was requested');
  assert.deepEqual(errors,[],'No browser or CSP errors');report.success=true;
}catch(error){
  let message=String(error.message||error).replace(/https?:\/\/\S+/g,'[URL redacted]');
  for(const value of secretValues)if(value)message=message.split(value).join('[redacted]');
  report.failure={stage,message};process.exitCode=1;
}finally{
  report.browser_errors=errors;report.blocked_requests=blocked;
  for(const context of contexts)await context.close();await browser?.close();
  await fs.writeFile(path.join(folder,'hy2-browser-verification.json'),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({success:report.success,stage,accounts:report.users.length,checks:report.checks.length}));
}
