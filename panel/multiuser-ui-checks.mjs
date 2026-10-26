import {chromium} from 'playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const panel = path.dirname(fileURLToPath(import.meta.url));
const web = path.join(panel, 'web');
const output = path.join(panel, '..', '.validation', 'multiuser-ui');
const report = {checked_at:new Date().toISOString(),success:false,
  safety:{mock_api:true,external_network_blocked:true,credentials:'synthetic only'},checks:[],screenshots:[],assets:{}};
await fs.mkdir(output,{recursive:true});
for (const file of ['index.html','app.js','style.css']) report.assets[file] = createHash('sha256').update(await fs.readFile(path.join(web,file))).digest('hex');
const staticFiles = {'/':'index.html','/index.html':'index.html','/app.js':'app.js','/style.css':'style.css','/mark.svg':'mark.svg'};
const server = http.createServer(async (request,response) => {
  const file = staticFiles[new URL(request.url,'http://localhost').pathname];
  if (!file) {response.writeHead(404);response.end();return;}
  const type = file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.svg') ? 'image/svg+xml' : 'text/html';
  response.writeHead(200,{'Content-Type':type+'; charset=utf-8','Cache-Control':'no-store'});
  response.end(await fs.readFile(path.join(web,file)));
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin = 'http://127.0.0.1:'+server.address().port;
const time = '2026-10-09T05:30:00Z';
const adminPassword = 'Synthetic-admin-2026';
const memberPassword = 'Synthetic-member-2026';
const resetPassword = 'Synthetic-reset-2026';
const users = [{id:'admin',username:'admin',display_name:'管理员',role:'admin',enabled:true,port:443,password:adminPassword,revision:0}];
const states = new Map();
const requests = [];
const provisionTasks = [];
const errors = [];
function safeUser(user) {
  return Object.fromEntries(['id','username','display_name','role','enabled','port'].map(key=>[key,user[key]]));
}
function fixture(user,index=0) {
  const exits = [{id:user.id+'-exit',name:user.display_name+'专属出口',address:'203.0.113.'+(10+index),port:1080,
    observed_ip:'203.0.113.'+(20+index),authenticated:true,active:true,pending:false,tested_at:time}];
  return {user:safeUser(user),server_ip:'198.51.100.63',server_port:user.port,server_protocol:'VLESS Reality',demo:true,
    service_active:true,exits,active:structuredClone(exits[0]),active_target:'static',
    server_exit:{id:'server',name:'服务器自身出口',observed_ip:'198.51.100.63',active:false},
    routing_mode:'smart',domains:[user.username+'.example.com'],direct_domains:[user.username+'.example.cn'],
    routing_subscription:{enabled:true,interval:300},dirty:false,updated:time,download_ready:true,rollback_ready:true,
    client_config:{group:'STATIC-SELECT',auto_node:'AUTO · 网页切换',exit_count:1,fixed_nodes_refresh_required:false},job:null};
}
states.set('admin',fixture(users[0]));
const check = name=>report.checks.push({name,passed:true});
let browser;
try {
  browser = await chromium.launch({channel:'msedge',headless:true});
  async function contextFor(width=1440) {
    const context = await browser.newContext({viewport:{width,height:width===390?844:1050}});
    let session = null;
    let rejectRouting = false;
    await context.route('**/*',async route=>{
      const request = route.request(),url = new URL(request.url());
      if (url.origin !== origin) {errors.push('Unexpected external request '+url.origin);return route.abort();}
      if (!url.pathname.startsWith('/api/')) return route.continue();
      const resource = url.pathname.slice(5), body = request.postData() ? request.postDataJSON() : null;
      requests.push({resource,method:request.method(),id:session?.id||null});
      assert(!url.search,'API must not carry another user selector');
      if (body && !resource.startsWith('users/')) assert(!('user_id' in body),'Self APIs must not select another user');
      const respond = (value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
      const account = users.find(user=>user.id===session?.id);
      const authenticated = Boolean(account && account.enabled && account.revision===session.revision);
      if (resource==='session') return respond({authenticated,csrf:'synthetic-ui-csrf',user:authenticated?safeUser(account):null});
      if (resource==='login') {
        const user = users.find(item=>item.username===body.username && item.password===body.password && item.enabled);
        if (!user) return respond({error:'用户名或密码不正确。'},401);
        session={id:user.id,revision:user.revision};
        return respond({csrf:'synthetic-ui-csrf',user:safeUser(user)});
      }
      if (!authenticated) return respond({error:'请重新登录。'},401);
      if (resource==='logout') {session=null;return respond({ok:true});}
      const current = states.get(account.id);
      current.user=safeUser(account);
      if (resource==='state') return respond(current);
      if (resource==='subscription') return respond({url:origin+'/subscription/synthetic-'+account.id+'.yaml',version:'synthetic-v1',updated:time,download_ready:true});
      if (resource==='audit') return respond({events:[],scope:account.role==='admin'?'all':'own'});
      if (resource==='profile') return route.fulfill({status:200,contentType:'application/yaml',body:'proxies: []\n# synthetic '+account.username+' only\n'});
      if (resource==='routing') {
        if (rejectRouting) {rejectRouting=false;return respond({error:'账号权限不足。'},403);}
        current.domains=body.domains;current.direct_domains=body.direct_domains;current.routing_mode=body.mode;
        return respond({download_ready:true,routing_subscription:current.routing_subscription});
      }
      if (resource==='exits/save') {
        const exit={id:account.id+'-new',name:body.name,address:body.address,port:body.port,
          authenticated:body.auth==='credentials',active:false,pending:true,tested_at:null};
        current.exits.push(exit);current.dirty=true;return respond({id:exit.id});
      }
      if (resource==='password') {
        assert.equal(body.current,account.password);account.password=body.new;account.revision++;return respond({ok:true});
      }
      if (resource==='users' || resource.startsWith('users/')) {
        if (account.role!=='admin') return respond({error:'仅管理员可执行此操作。'},403);
        if (resource==='users') return respond({users:users.map(user=>({...safeUser(user),service_active:user.enabled,
          exit_count:states.get(user.id).exits.length,active_target:states.get(user.id).active_target}))});
        if (resource==='users/provision' && request.method()==='GET') return respond({tasks:provisionTasks});
        if (resource==='users/create' || resource==='users/provision') {
          assert(users.length<3);assert.match(body.username,/^[a-z][a-z0-9_-]{2,23}$/);assert(body.password.length>=12);
          const user={id:'member-'+users.length,username:body.username,display_name:body.display_name,role:'member',
            enabled:true,port:users.length===1?1443:2443,password:body.password,revision:0};
          users.push(user);states.set(user.id,fixture(user,users.length));
          if (resource==='users/provision') {
            assert(body.request_id);assert.equal(request.headers()['x-csrf-token'],'synthetic-ui-csrf');
            const task={id:body.request_id,status:'succeeded',stage:'complete',message:'本机服务准备完成',steps:['validating','allocating','configuration','services','local_ready','complete'].map(id=>({id,label:id,status:'succeeded'})),user:safeUser(user),created_at:time};
            provisionTasks.push(task);return respond({task},202);
          }
          return respond({user:safeUser(user)});
        }
        const target=users.find(user=>user.id===body.id);assert(target&&target.role==='member');
        if (resource==='users/set-enabled') {target.enabled=body.enabled;target.revision++;return respond({user:safeUser(target)});}
        if (resource==='users/reset-password') {target.password=body.password;target.revision++;return respond({ok:true});}
      }
      throw new Error('Unexpected endpoint '+resource);
    });
    const page = await context.newPage();
    page.on('pageerror',error=>errors.push(error.message));
    page.on('console',message=>{if(message.type()==='error'&&!/401|403/.test(message.text()))errors.push(message.text());});
    return {context,page,rejectNextRouting:()=>{rejectRouting=true;}};
  }
  async function login(page,username,password) {
    await page.goto(origin,{waitUntil:'networkidle'});
    await page.locator('#login-user').fill(username);
    await page.locator('#login-password').fill(password);
    await page.locator('#login-form button[type="submit"]').click();
    await page.locator('#console').waitFor({state:'visible'});
    await page.waitForFunction(name=>document.querySelector('#current-user-handle').textContent===name,username);
  }
  async function noOverflow(page) {
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'Page fits viewport');
  }
  const admin=await contextFor();
  await login(admin.page,'admin',adminPassword);
  assert(await admin.page.locator('#users-nav').isVisible());
  assert(requests.some(request=>request.resource==='users'),'Administrator overview reads actual member capacity for shortcuts');
  await admin.page.locator('#users-nav').click();
  await admin.page.waitForFunction(()=>document.querySelector('#user-list').children.length===1);
  await admin.page.locator('#create-user-details summary').click();
  await admin.page.locator('#create-username').fill('BAD_account');
  await admin.page.locator('#create-user-password').fill(memberPassword);
  await admin.page.locator('#create-user-submit').click();
  assert.match(await admin.page.locator('#create-user-error').innerText(),/小写字母/);
  assert.equal(users.length,1,'Invalid username never submitted');
  check('ASCII username validation before account creation');
  for (const [username,name] of [['member_a','小林'],['member_b','小陈']]) {
    await admin.page.locator('#create-username').fill(username);
    await admin.page.locator('#create-display-name').fill(name);
    await admin.page.locator('#create-user-password').fill(memberPassword);
    await admin.page.locator('#create-user-submit').click();
    await admin.page.waitForFunction(count=>document.querySelector('#user-list').children.length===count,username==='member_a'?2:3);
    assert.equal(await admin.page.locator('#create-user-password').inputValue(),'','Password clears after creation');
    assert.equal(await admin.page.locator('#current-user-handle').innerText(),'admin','Creation keeps administrator logged in');
  }
  assert(await admin.page.locator('#create-user-submit').isDisabled());
  assert.equal(await admin.page.locator('#user-slots').innerText(),'3 / 3 个账号');
  assert.equal(await admin.page.locator('#user-list [data-user-action="enabled"]:visible').count(),2,'Administrator cannot be disabled');
  check('Three slots, member creation, private passwords, administrator protected');
  for (const width of [1440,390]) {
    await admin.page.setViewportSize({width,height:width===390?844:1050});
    await admin.page.evaluate(()=>{document.querySelector('#toast').hidden=true;window.scrollTo({top:0,behavior:'instant'});});
    await noOverflow(admin.page);
    const name='users-'+width+'.png';await admin.page.screenshot({path:path.join(output,name),fullPage:true});report.screenshots.push(name);
  }
  check('Administrator desktop and mobile layouts');
  const a=await contextFor();const b=await contextFor(390);
  await login(a.page,'member_a',memberPassword);await login(b.page,'member_b',memberPassword);
  for (const [entry,username,display] of [[a,'member_a','小林'],[b,'member_b','小陈']]) {
    assert.equal(await entry.page.locator('#users-nav').isVisible(),false);
    assert.equal(await entry.page.locator('.nav-button:visible').count(),3);
    assert.equal(await entry.page.locator('#metric-active').innerText(),display+'专属出口');
    await entry.page.evaluate(()=>switchView('users'));
    assert.equal(await entry.page.locator('#view-users').isVisible(),false,'Member cannot open user management');
    await entry.page.locator('[data-view="routing"]').first().click();
    assert.equal(await entry.page.locator('#domains').inputValue(),username+'.example.com');
    await noOverflow(entry.page);
    await entry.page.locator('[data-view="overview"]').first().click();
    await entry.page.locator('#add-exit').click();
    await entry.page.locator('#exit-socks-link').fill('socks5://synthetic:socks-password@203.0.113.90:443');
    await entry.page.locator('#parse-socks-link').click();
    assert.equal(await entry.page.locator('#exit-address').inputValue(),'203.0.113.90');
    assert.equal(await entry.page.locator('#exit-password').getAttribute('type'),'password');
    await entry.page.locator('#cancel-dialog').click();
    const downloadWait=entry.page.waitForEvent('download');
    await entry.page.locator('#download-top').click();
    assert.equal((await downloadWait).suggestedFilename(),'clash-node-console-'+username+'.yaml');
  }
  check('Three browser sessions show independent states, members have three views and their own downloads');
  check('Existing SOCKS5 import remains available and masked for both members');
  await a.page.locator('[data-view="routing"]').first().click();
  await a.page.locator('#domains').fill('only-a.example.com');
  await a.page.locator('#routing-form button[type="submit"]').click();
  await a.page.waitForFunction(()=>document.querySelector('#domains').value==='only-a.example.com'&&document.querySelector('#routing-form button[type="submit"]').disabled===false);
  assert.deepEqual(states.get('admin').domains,['admin.example.com']);
  assert.deepEqual(states.get('member-2').domains,['member_b.example.com']);
  check('Member rule changes preserve administrator and other member state');
  b.rejectNextRouting();
  await b.page.locator('[data-view="routing"]').first().click();
  await b.page.locator('#routing-form button[type="submit"]').click();
  await b.page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('没有执行此操作的权限'));
  check('403 receives explicit permission feedback');
  const card=admin.page.locator('.user-card[data-user-id="member-1"]');
  await card.locator('[data-user-action="enabled"]').click();
  await admin.page.locator('#confirm-ok').click();
  await admin.page.waitForFunction(()=>document.querySelector('[data-user-id="member-1"] .user-status').textContent==='已停用');
  await a.page.locator('#refresh').click();
  await a.page.locator('#login-screen').waitFor({state:'visible'});
  assert.equal(await b.page.locator('#console').isVisible(),true);
  await card.locator('[data-user-action="enabled"]').click();
  await admin.page.waitForFunction(()=>document.querySelector('[data-user-id="member-1"] .user-status').textContent==='已启用');
  await login(a.page,'member_a',memberPassword);
  check('Disable and reenable affect only target member and retain their configuration');
  await card.locator('[data-user-action="reset"]').click();
  await admin.page.locator('#reset-user-password').fill(resetPassword);
  await admin.page.locator('#reset-user-confirm').fill(resetPassword+'-mismatch');
  await admin.page.locator('#reset-user-submit').click();
  assert.match(await admin.page.locator('#reset-user-error').innerText(),/不一致/);
  await admin.page.locator('#reset-user-confirm').fill(resetPassword);
  await admin.page.locator('#reset-user-submit').click();
  await admin.page.locator('#user-password-dialog').waitFor({state:'hidden'});
  assert.equal(await admin.page.locator('#reset-user-password').inputValue(),'');
  assert.equal((await admin.page.locator('body').innerText()).includes(resetPassword),false);
  await a.page.locator('#refresh').click();await a.page.locator('#login-screen').waitFor({state:'visible'});
  await b.page.locator('#refresh').click();assert(await b.page.locator('#console').isVisible());
  assert.equal(await admin.page.locator('#current-user-handle').innerText(),'admin');
  await login(a.page,'member_a',resetPassword);
  check('Masked reset validates confirmation, clears secrets, invalidates only target session');
  await card.locator('[data-user-action="reset"]').click();
  await admin.page.locator('#reset-user-password').fill('Synthetic-leftover-secret');
  await admin.page.evaluate(()=>document.querySelector('#logout').click());
  await admin.page.locator('#login-screen').waitFor({state:'visible'});
  assert.equal(await admin.page.locator('#user-list .user-card').count(),0);
  assert.equal(await admin.page.locator('#reset-user-id').inputValue(),'');
  assert.equal(await admin.page.locator('#reset-user-password').inputValue(),'');
  assert.equal(await admin.page.locator('#user-password-dialog').evaluate(dialog=>dialog.open),false);
  await login(admin.page,'member_b',memberPassword);
  assert.equal(await admin.page.locator('#users-nav').isVisible(),false);
  assert.equal(await admin.page.locator('#user-list .user-card').count(),0);
  check('Logging out clears admin list, dialogs and secrets before another user signs in');
  assert.deepEqual(errors,[],'No console or page errors');
  report.success=true;report.browser_errors=[];
} catch (error) {
  report.failure=error.stack;report.browser_errors=errors;
  throw error;
} finally {
  await browser?.close();await new Promise(resolve=>server.close(resolve));
  await fs.writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({success:report.success,checks:report.checks.length,report:path.join(output,'report.json')}));
}
