import {chromium} from 'playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const panel=path.dirname(fileURLToPath(import.meta.url)),web=path.join(panel,'web');
const output=path.join(panel,'..','.validation','layout-ui');
const report={success:false,checked_at:new Date().toISOString(),checks:[],screenshots:[],assets:{},
  safety:{mock_api:true,external_network_blocked:true,credentials:'synthetic only',production_csp:true,successful_configuration_mutations:0}};
await fs.mkdir(output,{recursive:true});
for(const name of ['app.js','index.html','style.css'])report.assets[name]=createHash('sha256').update(await fs.readFile(path.join(web,name))).digest('hex');
const files={'/':'index.html','/app.js':'app.js','/style.css':'style.css','/mark.svg':'mark.svg'};
const server=http.createServer(async(req,res)=>{
  const file=files[new URL(req.url,'http://localhost').pathname];
  if(!file){res.writeHead(404);res.end();return;}
  const type=file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.svg')?'image/svg+xml':'text/html';
  res.writeHead(200,{'Content-Type':type+'; charset=utf-8','Cache-Control':'no-store',
    'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"});
  res.end(await fs.readFile(path.join(web,file)));
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin='http://127.0.0.1:'+server.address().port,at='2026-10-10T08:00:00Z';
const users=[{id:'admin',username:'admin',display_name:'管理员',role:'admin',enabled:true,port:443},
  {id:'member-a',username:'member_a',display_name:'使用者 A',role:'member',enabled:true,port:1443}];
const traffic={available:true,month:'2026-10',period_timezone:'UTC',sampled_at:at,sampling_seconds:10,
  up_bytes:250e6,down_bytes:750e6,total_bytes:1e9,up_rate:20e3,down_rate:80e3,connections:27,
  quota_bytes:0,rate_bps:0,over_quota:false,quota_enforced:false,rate_enforced:false};
const states=new Map(users.map(user=>{
  const exits=[{id:user.id+'-exit',name:user.display_name+'专属出口',address:'203.0.113.10',port:443,observed_ip:'203.0.113.20',authenticated:true,active:true,pending:false,tested_at:at},
    {id:user.id+'-backup',name:'备用出口',address:'203.0.113.11',port:443,observed_ip:'203.0.113.21',authenticated:true,active:false,pending:false,tested_at:at}];
  return[user.id,{user,server_ip:'198.51.100.63',server_port:user.port,server_protocol:'VLESS Reality',demo:false,service_active:true,
    exits,active:structuredClone(exits[0]),active_target:'static',server_exit:{id:'server',name:'服务器自身出口',observed_ip:'198.51.100.63',active:false},
    routing_mode:'smart',domains:['github.com'],direct_domains:['chaoxing.com'],routing_subscription:{enabled:true,interval:300},dirty:false,
    updated:at,download_ready:true,rollback_ready:true,client_config:{group:'STATIC-SELECT',auto_node:'AUTO · 网页切换',exit_count:2,fixed_nodes_refresh_required:false},job:null,
    health:{status:'healthy',message:'出口连接正常',last_checked_at:at,last_success_at:at,consecutive_failures:0,checking:false,mode:'manual',fallback_exit_id:null},traffic:structuredClone(traffic)}];
}));
const requests=[],errors=[],cspErrors=[];const check=name=>report.checks.push({name,passed:true});
let browser,pendingCreate,announceCreate,pendingPassword,announcePassword;
try{
  browser=await chromium.launch({channel:'msedge',headless:true});
  async function contextFor(width=1440){
    const context=await browser.newContext({viewport:{width,height:width===390?844:width===1280?800:900},reducedMotion:'reduce'});let session=null;
    await context.route('**/*',async route=>{
      const req=route.request(),url=new URL(req.url());
      if(url.origin!==origin){errors.push('Unexpected external network request');return route.abort();}
      if(!url.pathname.startsWith('/api/'))return route.continue();
      const resource=url.pathname.slice(5),body=req.postData()?req.postDataJSON():null;
      requests.push({resource,method:req.method(),id:session?.id});
      const reply=(value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
      if(resource==='session')return reply({authenticated:!!session,csrf:session?'synthetic-layout-csrf':null,user:session});
      if(resource==='login'){session=users.find(user=>user.username===body.username);assert(session);return reply({csrf:'synthetic-layout-csrf',user:session});}
      if(!session)return reply({error:'请重新登录。'},401);
      if(resource==='logout'){session=null;return reply({ok:true});}
      if(resource==='state')return reply(states.get(session.id));
      if(resource==='users')return reply({users:users.map(user=>({...user,traffic:states.get(user.id).traffic,service_active:true,exit_count:2,active_target:'static'}))});
      if(resource==='users/create'){
        await new Promise(resolve=>{pendingCreate={release:resolve};announceCreate?.();});pendingCreate=null;
        return reply({error:'模拟创建失败，请核对账号'},400);
      }
      if(resource==='password'){
        await new Promise(resolve=>{pendingPassword={release:resolve};announcePassword?.();});pendingPassword=null;
        return reply({error:'模拟密码更新失败'},400);
      }
      if(resource==='subscription')return reply({url:origin+'/subscription/synthetic-'+session.id+'.yaml',version:'synthetic-layout-v1',updated:at,download_ready:true});
      if(resource==='audit')return reply({events:[{id:'own',at,actor:session.username,action:'routing.save',status:'success',summary:'更新自己的分流规则'}],scope:session.role==='admin'?'all':'own'});
      if(resource==='backups')return reply({backups:[{id:'synthetic',name:'示例加密备份',created_at:at,size:2400,scope:'system',portable:true}],schedule:{enabled:true,interval_hours:24,last_backup:at,next_backup:'2026-10-11T08:00:00Z'}});
      errors.push('Unexpected endpoint '+resource);return reply({error:'Unexpected mocked endpoint'},500);
    });
    const page=await context.newPage();await page.clock.setFixedTime(new Date(at));
    page.on('pageerror',error=>errors.push(error.message));
    page.on('console',message=>{if(/Content Security Policy|Refused to|violates.*directive/i.test(message.text()))cspErrors.push(message.text());});
    return{context,page};
  }
  async function login(page,name='admin'){
    await page.goto(origin,{waitUntil:'networkidle'});await page.locator('#login-user').fill(name);
    await page.locator('#login-password').fill('Synthetic-layout-password');await page.locator('#login-form button[type="submit"]').click();
    await page.locator('#console').waitFor({state:'visible'});await page.waitForFunction(name=>document.querySelector('#current-user-handle').textContent===name,name);
  }
  async function nav(page,name){await page.locator('.nav-button[data-view="'+name+'"]').click();await page.locator('#view-'+name).waitFor({state:'visible'});}
  async function frame(page){await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));}
  async function fit(page){assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'Page fits viewport');}
  async function before(page,first,second){assert(await page.evaluate(({first,second})=>{
    const a=document.querySelector(first),b=document.querySelector(second);return !!a&&!!b&&!!(a.compareDocumentPosition(b)&Node.DOCUMENT_POSITION_FOLLOWING);
  },{first,second}),first+' precedes '+second);}
  async function ancestorDetails(page,selector){
    const id=await page.locator(selector).evaluate(element=>element.closest('details')?.id);assert(id,'The control is in a named details disclosure: '+selector);
    return page.locator('#'+id);
  }
  async function openFor(page,selector){const details=await ancestorDetails(page,selector);if(!await details.evaluate(element=>element.open))await details.locator('summary').first().click();return details;}
  async function shot(page,name){await page.evaluate(()=>{document.querySelector('#toast').hidden=true;window.scrollTo({top:0,behavior:'instant'});});await page.screenshot({path:path.join(output,name),fullPage:true,mask:[page.locator('#subscription-url')]});report.screenshots.push(name);}

  // Scenarios will assert the public DOM order, visible geometry and user actions.

  const entry=await contextFor(),page=entry.page;await login(page);
  for(const width of [1440,1280]){
    await page.setViewportSize({width,height:width===1280?800:900});await nav(page,'overview');
    await page.evaluate(()=>window.scrollTo({top:0,behavior:'instant'}));await frame(page);await fit(page);
    const path=await page.locator('#network-card').boundingBox(),server=await page.locator('#path-server-button').boundingBox();
    assert(path&&server);assert(server.y>=0&&server.y+server.height<=(width===1280?800:900),'Server outlet is actionable in the first viewport');
    assert(await page.locator('#path-routes .path-route').first().isVisible());
    const metrics=await page.locator('.metrics-grid').boundingBox();assert(metrics.height<150,'Status bar stays compact');
    for(const[first,second]of[['.metrics-grid','#network-card'],['#network-card','#job-panel'],['#job-panel','#exit-section'],['#exit-section','#health-card'],['#health-card','.traffic-card']])await before(page,first,second);
    const view=await page.locator('#view-overview').boundingBox(),health=await page.locator('#health-card').boundingBox();
    assert(Math.abs(health.width-view.width)<4,'Health occupies the complete content width');
    assert(await page.locator('#health-summary').isVisible());assert(await page.locator('#check-health').isVisible());
    assert.equal(await page.locator('#health-settings-details').evaluate(element=>element.open),false);
    await shot(page,'overview-'+width+'.png');check(width+': compact status and actionable path precede exits, full-width health and charts');
  }

  const foldControls=[['overview','#health-settings-details','#health-mode'],['routing','#routing-priority-details','#routing-smart-summary'],
    ['routing','#routing-sync-details','#routing-update-description'],['routing','#client-check-details','#client-checklist'],
    ['access','#password-details','#current-password'],['access','#identity-details','#rotate-credentials'],['users','#create-user-details','#create-username']];
  for(const[view,selector,target]of foldControls){
    await nav(page,view);const details=page.locator(selector),summary=details.locator('summary').first();
    assert.equal(await details.evaluate(element=>element.open),false,'Advanced section starts collapsed: '+selector);
    await summary.focus();await page.keyboard.press('Space');await frame(page);
    assert.equal(await details.evaluate(element=>element.open),true);assert(await page.locator(target).isVisible());
    await page.keyboard.press('Enter');await frame(page);assert.equal(await details.evaluate(element=>element.open),false);
    check(selector+': native summary supports keyboard opening and closing');
  }

  await nav(page,'routing');
  for(const[first,second]of[['#routing-mode','.routing-domain-lists'],['.routing-domain-lists','#routing-form button[type="submit"]'],['#routing-form','#routing-diagnostic-form'],['#routing-diagnostic-form','#routing-priority-details'],['#routing-diagnostic-form','#routing-sync-details'],['#routing-diagnostic-form','#client-check-details']])await before(page,first,second);
  assert(await page.locator('#direct-domains').isVisible());assert(await page.locator('#domains').isVisible());
  const directDraft='https://mooc1.chaoxing.com/course?draft=synthetic';await page.locator('#direct-domains').fill(directDraft);
  const sync=await openFor(page,'#routing-update-description');await sync.locator('summary').first().click();
  assert.equal(await page.locator('#direct-domains').inputValue(),directDraft);
  await page.locator('.nav-button[data-view="access"]').click();await page.locator('#draft-dialog').waitFor({state:'visible'});await page.locator('#draft-stay').click();
  assert(await page.locator('#view-routing').isVisible());assert.equal(await page.locator('#direct-domains').inputValue(),directDraft);
  await page.locator('.nav-button[data-view="access"]').click();await page.locator('#draft-discard').click();await page.locator('#view-access').waitFor({state:'visible'});
  check('Rule editing and saving precede query and folded explanations; folding or navigation cannot overwrite a draft');

  for(const[first,second]of[['#subscription-card','#view-access .download-card'],['#access-setup-grid','#password-details'],['#access-setup-grid','#identity-details'],['#password-details','#personal-audit-card'],['#identity-details','#personal-audit-card']])await before(page,first,second);
  await page.waitForFunction(()=>document.querySelector('#subscription-url').value.length>0);
  assert.equal(await page.locator('#subscription-url').getAttribute('type'),'password');assert(await page.locator('#copy-subscription').isVisible());
  assert(await page.locator('#view-access .download-button').isVisible());
  assert.equal(await page.locator('#current-password').isVisible(),false);assert.equal(await page.locator('#rotate-credentials').isVisible(),false);
  await page.waitForFunction(()=>document.querySelector('#audit-list').textContent.includes('更新自己的分流规则'));
  check('Masked subscription and download lead access; password and identity controls are folded before own history');

  const passwordDetails=page.locator('#password-details');
  await page.evaluate(()=>document.querySelector('#password-form').requestSubmit());await frame(page);
  assert.equal(await passwordDetails.evaluate(element=>element.open),true,'Native invalid control expands its enclosing disclosure');
  assert(await page.locator('#current-password').isVisible());
  assert(!requests.some(request=>request.resource==='password'),'Invalid password form is never sent');
  await passwordDetails.locator('summary').click();check('Validation in a collapsed required form exposes the invalid field');

  await page.evaluate(()=>window.NodeGuide.start('password-logout'));await page.locator('#guide-tour').waitFor({state:'visible'});
  await page.waitForFunction(()=>document.querySelector('#guide-tour-highlight').dataset.targetSelector==='#current-password');
  assert.equal(await passwordDetails.evaluate(element=>element.open),true);await page.evaluate(()=>window.NodeGuide.stop());
  assert.equal(await passwordDetails.evaluate(element=>element.open),false,'Tutorial restores an initially closed disclosure');
  if(await page.locator('#user-guide-dialog').isVisible())await page.locator('#guide-close').click();
  await passwordDetails.locator('summary').click();await page.locator('#current-password').fill('Synthetic-unsaved-password');
  await page.evaluate(()=>window.NodeGuide.start('password-logout'));await page.locator('#guide-tour').waitFor({state:'visible'});
  await page.evaluate(()=>window.NodeGuide.stop());
  assert.equal(await passwordDetails.evaluate(element=>element.open),true,'Tutorial retains a user-opened disclosure');
  assert.equal(await page.locator('#current-password').inputValue(),'Synthetic-unsaved-password');
  if(await page.locator('#user-guide-dialog').isVisible())await page.locator('#guide-close').click();
  await passwordDetails.locator('summary').click();await page.locator('.nav-button[data-view="overview"]').click();
  await page.locator('#draft-dialog').waitFor({state:'visible'});await page.locator('#draft-stay').click();
  assert.equal(await page.locator('#current-password').inputValue(),'Synthetic-unsaved-password');
  await page.locator('.nav-button[data-view="overview"]').click();await page.locator('#draft-discard').click();await page.locator('#view-overview').waitFor({state:'visible'});
  check('Tutorial opens its real folded target and restores owned folds while retaining user-opened sections and drafts');

  await page.evaluate(()=>window.NodeGuide.start('health-fallback'));await page.locator('#guide-tour').waitFor({state:'visible'});
  await page.locator('#guide-tour-next').click();await page.locator('#guide-tour-next').click();
  await page.waitForFunction(()=>document.querySelector('#guide-tour-highlight').dataset.targetSelector==='#health-mode');
  assert.equal(await page.locator('#health-settings-details').evaluate(element=>element.open),true);
  await page.evaluate(()=>window.NodeGuide.stop());assert.equal(await page.locator('#health-settings-details').evaluate(element=>element.open),false);
  if(await page.locator('#user-guide-dialog').isVisible())await page.locator('#guide-close').click();
  const healthDetails=await openFor(page,'#health-mode');await page.locator('#health-mode').selectOption('auto');
  await page.locator('#health-fallback').selectOption('server');await page.locator('#health-mode').dispatchEvent('input');
  await healthDetails.locator('summary').click();assert.equal(await page.locator('#health-mode').inputValue(),'auto');
  assert(await page.locator('#health-settings-draft').isVisible());
  await page.locator('#refresh').click();await frame(page);assert.equal(await page.locator('#health-mode').inputValue(),'auto');
  await healthDetails.locator('summary').click();assert.equal(await page.locator('#health-fallback').inputValue(),'server');
  check('Health guide reveals the settings; collapsed health drafts remain marked and survive state refresh');

  await nav(page,'users');await page.waitForFunction(()=>document.querySelectorAll('#user-list .user-card').length===2);
  await before(page,'#create-user-details','#members-list-card');await before(page,'#members-list-card','#users-traffic-card');
  assert.equal(await page.locator('#create-user-details').evaluate(element=>element.open),false);assert.equal(await page.locator('#user-slots').innerText(),'2 / 3 个账号');
  const createDetails=await openFor(page,'#create-username');await page.locator('#create-username').fill('member_new');await page.locator('#create-user-password').fill('Synthetic-create-password');
  const createReady=new Promise(resolve=>{announceCreate=resolve;});await page.locator('#create-user-submit').click();await createReady;
  await createDetails.locator('summary').click();assert.equal(await createDetails.evaluate(element=>element.open),false);
  pendingCreate.release();await page.waitForFunction(()=>document.querySelector('#create-user-error').textContent.includes('模拟创建失败'));
  assert.equal(await createDetails.evaluate(element=>element.open),true);assert(await page.locator('#create-user-error').isVisible());
  assert.equal(await page.locator('#create-username').inputValue(),'member_new');assert.equal(await page.locator('#user-list .user-card').count(),2);
  await page.evaluate(()=>document.querySelector('#create-user-form').reset());await createDetails.locator('summary').click();
  check('User list precedes aggregate traffic; a failed asynchronous create reopens its hidden error without losing account draft');

  await nav(page,'maintenance');await page.waitForFunction(()=>document.querySelector('#backup-schedule-status').textContent.includes('最近'));
  for(const[first,second]of[['#backup-schedule-form','#backup-create-card'],['#backup-create-card','#backup-restore-card'],['#backup-restore-card','#admin-audit-card']])await before(page,first,second);
  assert(await page.locator('#backup-schedule-form').isVisible());assert(await page.locator('#backup-create-form').isVisible());assert(await page.locator('#backup-preview-form').isVisible());
  assert.equal(await page.locator('#backup-list .backup-entry').count(),1);check('Maintenance presents schedule, create/list, restore preview and history in operational order');

  for(const width of [1440,1280,1024,390]){
    await page.setViewportSize({width,height:width===390?844:width===1280?800:900});
    for(const view of ['overview','routing','access','users','maintenance']){
      await nav(page,view);await frame(page);await fit(page);
      const visibleView=await page.locator('#view-'+view).boundingBox();assert(visibleView.width>0&&visibleView.x>=0&&visibleView.x+visibleView.width<=width+1);
      if(width===390||width===1280)await shot(page,view+'-'+width+'.png');
      check(width+': '+view+' stays within the viewport');
    }
  }
  await nav(page,'overview');assert.equal(await page.locator('#traffic-total').innerText(),'1.00 GB');
  assert.equal(await page.locator('#traffic-up-share').innerText(),'25.0%');assert.equal(await page.locator('#traffic-rate-chart').getAttribute('data-sample-count'),'1');
  assert.equal(await page.locator('#traffic-rate-points circle[data-traffic-sample]').count(),2);
  assert.equal(await page.locator('script:not([src])').count(),0);assert.equal(await page.locator('[onclick], [onsubmit]').count(),0);
  assert(!/\sstyle\s*=/i.test(await fs.readFile(path.join(web,'index.html'),'utf8')),'HTML contains no inline styles');
  check('Reordered usage retains actual totals, shares, one real sample, and external scripts/styles');

  await nav(page,'access');await openFor(page,'#current-password');await page.locator('#current-password').fill('Synthetic-secret-to-clear');
  await page.locator('#new-password').fill('Synthetic-new-password');await page.locator('#confirm-password').fill('Synthetic-new-password');
  const passwordReady=new Promise(resolve=>{announcePassword=resolve;});await page.locator('#password-form button[type="submit"]').click();await passwordReady;
  await openFor(page,'#rotate-credentials');
  await page.locator('#logout-mobile').click();await page.locator('#login-screen').waitFor({state:'visible'});
  const passwordFailure=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/password'&&response.status()===400);
  pendingPassword.release();await passwordFailure;await frame(page);
  assert.equal(await page.locator('#current-password').inputValue(),'');assert.equal(await page.locator('#create-user-password').inputValue(),'');assert.equal(await page.locator('#subscription-url').inputValue(),'');
  assert.equal(await page.locator('#user-list .user-card').count(),0);assert.equal(await page.locator('#traffic-rate-chart').getAttribute('data-sample-count'),'0');
  assert.equal(await page.locator('#console details[open]').count(),0);
  await page.locator('#login-user').fill('member_a');await page.locator('#login-password').fill('Synthetic-layout-password');await page.locator('#login-form button[type="submit"]').click();await page.locator('#console').waitFor({state:'visible'});
  assert.equal(await page.locator('.nav-button:visible').count(),3);assert.equal(await page.locator('#users-nav').isVisible(),false);assert.equal(await page.locator('#maintenance-nav').isVisible(),false);
  assert.equal(await page.locator('#password-details').evaluate(element=>element.open),false);await fit(page);
  check('Logout clears hidden drafts, disclosures, privileged lists and charts; pending password failure cannot reopen the old account form');

  assert.deepEqual(errors,[],'No runtime errors or outside network requests');assert.deepEqual(cspErrors,[],'The production CSP remains valid');
  assert(requests.filter(request=>request.method!=='GET').every(request=>['login','logout','users/create','password'].includes(request.resource)),'Only login/logout and deliberately rejected synthetic form requests are sent');
  report.success=true;
}catch(error){report.failure=error.stack;report.browser_errors=errors;report.csp_errors=cspErrors;throw error;}
finally{pendingCreate?.release();pendingPassword?.release();await browser?.close();await new Promise(resolve=>server.close(resolve));await fs.writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({success:report.success,checks:report.checks.length,report:path.join(output,'report.json')}));}
