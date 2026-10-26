import {chromium} from 'playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const panel = path.dirname(fileURLToPath(import.meta.url));
const output = path.join(panel,'..','.validation','optimization-ui');
const web = path.join(panel,'web');
const report = {success:false,checked_at:new Date().toISOString(),checks:[],screenshots:[],assets:{},safety:{mock_api:true,external_network_blocked:true,credentials:'synthetic only'}};
await fs.mkdir(output,{recursive:true});
for (const name of ['index.html','app.js','style.css']) report.assets[name] = createHash('sha256').update(await fs.readFile(path.join(web,name))).digest('hex');
const files = {'/':'index.html','/index.html':'index.html','/app.js':'app.js','/style.css':'style.css','/mark.svg':'mark.svg'};
const server = http.createServer(async (request,response) => {
  const file = files[new URL(request.url,'http://localhost').pathname];
  if (!file) {response.writeHead(404);response.end();return;}
  const type = file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.svg') ? 'image/svg+xml' : 'text/html';
  response.writeHead(200,{'Content-Type':type+'; charset=utf-8','Cache-Control':'no-store'});
  response.end(await fs.readFile(path.join(web,file)));
});
await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
const origin = 'http://127.0.0.1:'+server.address().port;
const at = '2026-10-12T12:00:00Z';
const users = [{id:'admin',username:'admin',display_name:'管理员',role:'admin',enabled:true,port:443,hy2_port:443,service_active:true,hy2_service_active:true},
  {id:'user-a',username:'user-a',display_name:'成员 A',role:'member',enabled:true,port:1443,hy2_port:1443,service_active:true,hy2_service_active:null},
  {id:'user-b',username:'user-b',display_name:'成员 B',role:'member',enabled:true,port:2443,hy2_port:2443,service_active:true,hy2_service_active:true}];
let memberPorts = [1443,2443,3444,4444];
const supported = [1443,2443,3444,4444,5444,6445,7445];
const tasks = [],submissions = [],requests = [],pageErrors = [];
let outcome = 'running',abortOnce = false,createdCount = 0;
const stepIds = ['validating','allocating','configuration','services','local_ready','complete'];
const labels = ['检查成员资料','分配独立入口','生成代理配置','启动本机服务','核对本机入口','完成准备'];
const steps = (stage) => stepIds.map((id,index) => ({id,label:labels[index],status:index < stage ? 'succeeded' : index === stage ? 'running' : 'pending'}));
function entrances() {
  return {capacity:memberPorts.length+1,total_users:users.length,available_count:memberPorts.filter(port=>!users.some(user=>user.port===port)).length,member_ports:memberPorts,supported_member_ports:supported,
    allocations:memberPorts.map(port => ({port,assigned:users.some(user=>user.port===port),username:users.find(user=>user.port===port)?.username,status:'not_checked'})),
    firewall_text:memberPorts.map(port=>'TCP '+port+' / UDP '+port).join('\n'),public_verification:'not_checked'};
}
function fixture(user) {
  return {user,server_ip:'198.51.100.63',server_port:user.port,server_protocol:'VLESS Reality',demo:true,service_active:true,exits:[],active:null,active_target:'server',server_exit:{id:'server',name:'服务器自身出口',observed_ip:'198.51.100.63',active:true},routing_mode:'smart',domains:[],direct_domains:[],routing_subscription:{enabled:true,interval:300},dirty:false,updated:at,download_ready:true,rollback_ready:false,client_config:{group:'STATIC-SELECT',auto_node:'AUTO · 网页切换',exit_count:0,fixed_nodes_refresh_required:false},job:null,transport:{enabled:true,hy2_port:user.port},health:{status:'unknown',checking:false,mode:'manual'},traffic:{available:false,reason:'等待真实采样',month:'2026-10',total_bytes:0,up_rate:null,down_rate:null,connections:null,quota_bytes:0,rate_bps:0}};
}
const check = name => report.checks.push({name,passed:true});
let browser;
try {
  browser = await chromium.launch({channel:'msedge',headless:true});
  const context = await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'no-preference'});
  let session = null;
  await context.addInitScript(() => Object.defineProperty(navigator,'clipboard',{value:{writeText:async value=>{window.syntheticClipboard=value;}}}));
  await context.route('**/*',async route => {
    const request = route.request(),url = new URL(request.url());
    if (url.origin !== origin) {pageErrors.push('Unexpected external request');return route.abort();}
    if (!url.pathname.startsWith('/api/')) return route.continue();
    const resource = url.pathname.slice(5),body = request.postData() ? request.postDataJSON() : null;
    requests.push({resource,method:request.method(),role:session?.role});
    const reply = (value,status=200) => route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
    if (resource === 'session') return reply({authenticated:!!session,csrf:session?'synthetic-csrf':null,user:session});
    if (resource === 'login') {
      await new Promise(resolve=>setTimeout(resolve,350));
      if (body.password === 'wrong') return reply({error:'账号或密码不正确，请重新输入。'},401);
      session = users.find(user=>user.username===body.username);
      return session ? reply({csrf:'synthetic-csrf',user:session}) : reply({error:'账号不存在。'},401);
    }
    if (!session) return reply({error:'请登录。'},401);
    if (resource === 'logout') {session=null;return reply({ok:true});}
    if (resource === 'state') return reply(fixture(session));
    if (resource === 'audit') return reply({events:[]});
    if (resource === 'subscription') return reply({url:origin+'/subscription/synthetic-'+session.id+'.yaml',version:'synthetic',updated:at,download_ready:true});
    if (resource === 'backups') return reply({backups:[],schedule:{enabled:false}});
    if (['users','users/provision','entrances/configure','entrances'].includes(resource)) {
      if (session.role !== 'admin') return reply({error:'仅管理员可执行。'},403);
      if (body) assert.equal(request.headers()['x-csrf-token'],'synthetic-csrf');
      if (resource === 'users') return reply({users,entrances:entrances()});
      if (resource === 'entrances') return reply({entrances:entrances()});
      if (resource === 'entrances/configure') {
        assert.equal(body.cloud_confirmed,true);assert(body.member_ports.every(port=>supported.includes(port)));memberPorts=body.member_ports;return reply({entrances:entrances()});
      }
      if (body) {
        assert.match(body.username,/^[a-z][a-z0-9_-]{2,23}$/);assert(body.password.length>=12);assert(body.request_id);
        submissions.push(body);
        let task = tasks.find(task=>task.id===body.request_id);
        if (!task) {task={id:body.request_id,username:body.username,display_name:body.display_name,status:'queued',stage:'validating',message:'已排队，等待服务器处理',steps:steps(-1),created_at:at};tasks.unshift(task);createdCount++;}
        if (abortOnce) {abortOnce=false;return route.abort('failed');}
        return reply({task},202);
      }
      const task = tasks.find(task=>['queued','running'].includes(task.status));
      if (task) {
        if (outcome === 'running') Object.assign(task,{status:'running',stage:'services',message:'正在启动本机入口服务',steps:steps(3)});
        if (outcome === 'failed') Object.assign(task,{status:'failed',stage:'services',message:'本机服务准备未完成',error:'模拟服务启动失败 <img src=x onerror="window.syntheticXSS=true">',steps:steps(3).map(step=>({...step,status:step.id==='services'?'failed':step.status}))});
        if (outcome === 'succeeded') {
          const submitted=submissions.find(item=>item.request_id===task.id);
          const port=memberPorts.find(port=>!users.some(user=>user.port===port));
          const user={id:submitted.username,username:submitted.username,display_name:submitted.display_name,role:'member',enabled:true,port,hy2_port:port,service_active:true,hy2_service_active:true};users.push(user);
          Object.assign(task,{status:'succeeded',stage:'complete',message:'成员本机服务已准备',steps:steps(6),user});
        }
      }
      return reply({tasks});
    }
    pageErrors.push('Unexpected API '+resource);return reply({error:'未定义的模拟接口'},500);
  });
  const page = await context.newPage();page.on('pageerror',error=>pageErrors.push(error.message));
  const waitText = async (selector,text) => page.waitForFunction(({selector,text})=>document.querySelector(selector)?.textContent.includes(text),{selector,text});
  const nav = async name => {await page.locator('.nav-button[data-view="'+name+'"]').click();await page.locator('#view-'+name).waitFor({state:'visible'});};
  const fit = async () => assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'Horizontal page overflow');
  await page.goto(origin,{waitUntil:'networkidle'});
  await page.screenshot({path:path.join(output,'login-desktop.png'),fullPage:true});report.screenshots.push('login-desktop.png');
  await page.locator('#login-password').fill('wrong');await page.locator('#login-submit').click();
  await waitText('#login-submit-label','正在验证');assert(await page.locator('#login-submit').isDisabled());
  await waitText('#login-error','不正确');assert.equal(await page.locator('#login-submit').isDisabled(),false);
  check('Login waits for authentication response, prevents duplicate submission and shows field error');
  await page.locator('#login-motion').selectOption('off');
  assert(await page.locator('body').evaluate(element=>element.classList.contains('motion-off')));
  assert.deepEqual(await page.evaluate(()=>Object.keys(localStorage)),['node-motion-preference']);
  await page.reload();assert.equal(await page.locator('#login-motion').inputValue(),'off');
  await page.locator('#login-password').fill('Synthetic-admin-password');await page.locator('#login-submit').click();
  await page.locator('#console').waitFor({state:'visible'});await page.locator('#admin-shortcuts').waitFor({state:'visible'});
  await waitText('#quick-entrance-summary','2 个');
  assert.equal(await page.locator('#console-motion').inputValue(),'off');assert.equal(requests.filter(item=>item.method==='POST' && item.resource!=='login').length,0);
  check('Only motion preference persists; administrator overview restores actual capacity without configuring ports');
  await page.locator('#quick-entrances').click();await page.locator('#entrances-details[open]').waitFor();
  assert.equal(await page.locator('#entrances-cloud-confirmed').isChecked(),false);
  await page.locator('#prepare-next-entrance').click();
  assert.match(await page.locator('#entrances-member-ports').inputValue(),/5444/);
  assert.match(await page.locator('#entrances-firewall-text').inputValue(),/TCP 5444 \/ UDP 5444/);
  assert.equal(await page.locator('#entrances-cloud-confirmed').isChecked(),false);
  assert.equal(requests.filter(item=>item.resource==='entrances/configure').length,0,'Next entrance only changes the draft');
  await page.locator('#save-entrances').click();assert.equal(requests.filter(item=>item.resource==='entrances/configure').length,0);
  await page.locator('#entrances-cloud-confirmed').check();await page.locator('#save-entrances').click();
  await waitText('#entrances-capacity-summary','3 个');assert.match(await page.locator('#entrances-status').innerText(),/公网.*未核验/);
  check('Pool expansion requires explicit TCP and UDP cloud declaration, preserves assigned ports and reports public verification unknown');
  await page.locator('#create-user-details summary').click();
  await page.locator('#create-username').fill('new_member');await page.locator('#create-display-name').fill('新成员');
  await page.locator('.nav-button[data-view="overview"]').click();await page.locator('#draft-dialog').waitFor({state:'visible'});assert.equal(await page.locator('#draft-save').isVisible(),false);
  await page.locator('#draft-stay').click();assert.equal(await page.locator('#create-username').inputValue(),'new_member');
  check('Unsubmitted member and pool drafts are protected without implicit creation');
  abortOnce=true;
  await page.locator('#create-user-submit').click();await waitText('#create-user-error','Failed to fetch');
  await page.locator('#create-user-submit').click();await page.locator('#member-task-panel').waitFor({state:'visible'});
  assert.equal(createdCount,1);assert.equal(submissions.length,2);assert.equal(submissions[0].request_id,submissions[1].request_id);
  assert.equal(await page.locator('#create-user-password').inputValue(),'');assert.equal(await page.locator('#member-delivery').isVisible(),false);
  check('Retry after ambiguous network failure reuses creation key; password generation is strong and task queue is real');
  await waitText('#member-task-list','正在启动本机入口服务');
  assert.equal(await page.locator('.member-task-steps li[data-status="running"]').count(),1);
  await page.evaluate(()=>{Object.defineProperty(document,'hidden',{configurable:true,value:true});document.dispatchEvent(new Event('visibilitychange'));});
  const hiddenCount=requests.filter(item=>item.resource==='users/provision' && item.method==='GET').length;
  await page.waitForTimeout(2400);assert.equal(requests.filter(item=>item.resource==='users/provision' && item.method==='GET').length,hiddenCount);
  assert(await page.locator('body').evaluate(element=>element.classList.contains('motion-background')));
  outcome='succeeded';
  await page.evaluate(()=>{Object.defineProperty(document,'hidden',{configurable:true,value:false});document.dispatchEvent(new Event('visibilitychange'));});
  await page.locator('#member-delivery').waitFor({state:'visible'});await waitText('#delivery-username','new_member');
  assert.equal(await page.locator('#delivery-password').getAttribute('type'),'password');assert.match(await page.locator('#member-delivery').innerText(),/公网连接尚未核验/);
  await page.locator('#copy-member-delivery').click();assert.match(await page.evaluate(()=>window.syntheticClipboard),/new_member/);
  assert((await page.evaluate(()=>window.syntheticClipboard)).includes(submissions[0].password));
  assert.deepEqual(await page.evaluate(()=>Object.keys(localStorage)),['node-motion-preference']);assert.equal(await page.evaluate(()=>sessionStorage.length),0);
  assert.equal(await page.locator('#user-list .member-usage-details[open]').count(),0);
  await waitText('[data-user-id="new_member"] .user-port','UDP');assert.match(await page.locator('[data-user-id="user-a"] .user-service').innerText(),/HY2 待检查/);
  users.find(user => user.username === 'user-a').service_active=false;users.find(user => user.username === 'user-a').hy2_port=null;
  await page.locator('#refresh-users').click();await waitText('[data-user-id="user-a"] .user-service','TCP 已停止');
  assert.match(await page.locator('[data-user-id="user-a"] .user-service').innerText(),/TCP 已停止.*HY2 未配置/);
  Object.assign(users.find(user=>user.username==='user-a'),{enabled:false,service_active:null,hy2_port:1443,hy2_service_active:null});
  await page.locator('#refresh-users').click();await waitText('[data-user-id="user-a"] .user-status','已停用');
  assert.equal(await page.locator('[data-user-id="user-a"] .user-service').innerText(),'TCP 待检查 · HY2 待检查','Disabled account does not fabricate stopped when observation is null');
  users.find(user=>user.username==='user-a').hy2_service_active=false;
  await page.locator('#refresh-users').click();await waitText('[data-user-id="user-a"] .user-service','HY2 已停止');
  Object.assign(users.find(user=>user.username==='user-a'),{enabled:true,service_active:true,hy2_service_active:true});
  await page.locator('#refresh-users').click();await waitText('[data-user-id="user-a"] .user-service','TCP 运行中 · HY2 运行中');
  check('Member service cards distinguish TCP false=stopped, null=unknown and absent HY2=unconfigured');
  check('Hidden page pauses task polling; resume uses real completion, masked one-time delivery and truthful per-protocol service state');
  await page.locator('#console-motion').selectOption('system');
  for (const width of [1440,390]) {
    await page.setViewportSize({width,height:width===390?844:1000});await page.evaluate(()=>{document.querySelector('#toast').hidden=true;window.scrollTo({top:0,behavior:'instant'});});await fit();
    const file='members-'+width+'.png';await page.screenshot({path:path.join(output,file),fullPage:true});report.screenshots.push(file);
  }
  check('Desktop and phone forms, task steps, port pool and member cards fit viewport without horizontal scroll');
  await page.setViewportSize({width:1440,height:1000});
  assert(await page.locator('#member-delivery').isVisible());assert((await page.locator('#delivery-password').inputValue()).length>=12);
  tasks.splice(0);await page.locator('#refresh-member-tasks').click();await page.locator('#member-task-panel').waitFor({state:'hidden'});assert.equal(await page.locator('#member-delivery').isVisible(),false);assert.equal(await page.locator('#delivery-password').inputValue(),'');
  check('Server task snapshot removes disappeared task and clears its one-time delivery');
  outcome='running';await page.locator('#create-username').fill('fail_member');await page.locator('#create-display-name').fill('失败成员');await page.locator('#create-user-submit').click();
  outcome='failed';await page.locator('#refresh-member-tasks').click();await waitText('#member-task-list','模拟服务启动失败');
  assert.equal(await page.locator('#member-delivery').isVisible(),false);assert.equal(await page.locator('#member-task-list img').count(),0);
  assert.match(await page.locator('.member-task[data-status="failed"] .member-task-heading').innerText(),/fail_member/);
  assert.equal(await page.evaluate(()=>window.syntheticXSS || false),false);assert.equal(await page.locator('#create-user-submit').isDisabled(),false);
  const failedRequest=submissions.at(-1),createRequests=submissions.length;
  await page.locator('#create-username').fill('keep_draft');await page.locator('#create-display-name').fill('保留草稿');await page.locator('#create-user-password').fill('Synthetic-new-draft-password');
  await page.locator('.member-task[data-status="failed"] [data-retry-member-task]').click();await page.locator('#confirm-dialog').waitFor({state:'visible'});await page.locator('#confirm-dialog button[value="cancel"]').click();
  assert.equal(await page.locator('#create-username').inputValue(),'keep_draft');assert.equal(await page.locator('#create-user-password').inputValue(),'Synthetic-new-draft-password');assert.equal(submissions.length,createRequests,'Retry cancellation makes no creation request');
  await page.locator('.member-task[data-status="failed"] [data-retry-member-task]').click();await page.locator('#confirm-ok').click();await waitText('#member-retry-notice','已预填失败任务');assert.equal(await page.locator('#create-username').inputValue(),'fail_member');assert.equal(await page.locator('#create-display-name').inputValue(),'失败成员');assert.equal(await page.locator('#create-user-password').inputValue(),'');
  outcome='running';await page.locator('#create-user-submit').click();await page.waitForFunction(()=>document.querySelector('#create-user-password').value==='');
  assert.notEqual(submissions.at(-1).request_id,failedRequest.request_id);assert.notEqual(submissions.at(-1).password,failedRequest.password);
  outcome='failed';await page.locator('#refresh-member-tasks').click();await page.waitForFunction(()=>!document.querySelector('#create-user-submit').disabled);
  check('Failed task retry pre-fills identity without retaining password');
  check('Failed service preparation remains retryable, has no success delivery and escapes task error text');
  await page.clock.install();outcome='running';await page.locator('#create-username').fill('expiry_member');await page.locator('#create-user-submit').click();
  outcome='succeeded';await page.locator('#refresh-member-tasks').click();await page.locator('#member-delivery').waitFor({state:'visible'});
  await page.clock.fastForward(600001);assert.equal(await page.locator('#member-delivery').isVisible(),false);assert.equal(await page.locator('#delivery-password').inputValue(),'');
  assert(await page.locator('#member-task-history').isVisible());assert.equal(await page.locator('#member-task-history').evaluate(element=>element.open),false);
  check('Completed task history folds older results');
  check('One-time delivery automatically clears after ten minutes');
  await page.reload({waitUntil:'networkidle'});await page.locator('#console').waitFor({state:'visible'});await nav('users');await page.locator('#member-task-panel').waitFor({state:'visible'});
  assert.equal(await page.locator('#member-delivery').isVisible(),false);assert.equal(await page.locator('#delivery-password').inputValue(),'');
  check('Reload restores task history without recovering initial password');
  await page.locator('#member-search').fill('expiry_member');await waitText('#member-filter-count','显示 1 /');assert.equal(await page.locator('#user-list .user-card:not([hidden])').count(),1);await page.locator('#member-status-filter').selectOption('disabled');assert(await page.locator('#member-filter-empty').isVisible());await page.locator('#reset-member-filters').click();assert.equal(await page.locator('#member-filter-empty').isVisible(),false);
  check('Member search and enabled-state filter report count and empty result without changing cards');
  outcome='running';await nav('users');await page.locator('#create-user-details summary').click();await page.locator('#create-username').fill('late_member');await page.locator('#create-user-submit').click();
  await page.waitForFunction(()=>document.querySelector('#create-user-password').value==='');await page.locator('#logout').click();await page.locator('#login-screen').waitFor({state:'visible'});
  await page.locator('#login-user').fill('user-a');await page.locator('#login-password').fill('Synthetic-member-password');await page.locator('#login-submit').click();
  await page.locator('#console').waitFor({state:'visible'});assert.equal(await page.locator('#admin-shortcuts').isVisible(),false);assert.equal(await page.locator('#users-nav').isVisible(),false);
  assert.equal(await page.locator('#member-delivery').isVisible(),false);assert.equal(await page.locator('#delivery-password').inputValue(),'');assert.equal(await page.locator('#member-task-list').innerText(),'');
  assert.equal(requests.filter(item=>item.role==='member' && ['users','users/provision','entrances/configure'].includes(item.resource)).length,0);
  check('Logout clears task timers and secrets; member session never requests admin APIs or sees administrator actions');
  assert.deepEqual(pageErrors,[]);report.success=true;
} catch (error) {report.error=error.stack;process.exitCode=1;}
finally {
  if (browser) await browser.close();await new Promise(resolve=>server.close(resolve));
  await fs.writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({success:report.success,checks:report.checks.length,report:path.join(output,'report.json'),error:report.error || null}));
}
