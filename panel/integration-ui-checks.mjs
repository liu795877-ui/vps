import {chromium} from 'playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const panel=path.dirname(fileURLToPath(import.meta.url)),web=path.join(panel,'web');
const output=path.join(panel,'..','.validation','integration-ui');
const report={success:false,checked_at:new Date().toISOString(),checks:[],assets:{},screenshots:[],
  safety:{mock_api:true,external_network_blocked:true,production_csp:true,credentials:'synthetic only'}};
await fs.mkdir(output,{recursive:true});
for(const name of ['app.js','index.html','style.css'])report.assets[name]=createHash('sha256').update(await fs.readFile(path.join(web,name))).digest('hex');
const files={'/':'index.html','/app.js':'app.js','/style.css':'style.css','/mark.svg':'mark.svg'};
const server=http.createServer(async(req,res)=>{
  const file=files[new URL(req.url,'http://localhost').pathname];if(!file){res.writeHead(404);res.end();return;}
  const type=file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.svg')?'image/svg+xml':'text/html';
  res.writeHead(200,{'Content-Type':type+'; charset=utf-8','Cache-Control':'no-store',
    'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"});
  res.end(await fs.readFile(path.join(web,file)));
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin='http://127.0.0.1:'+server.address().port,at=new Date().toISOString();
const users=[{id:'admin',username:'admin',display_name:'管理员',role:'admin',enabled:true,port:443},
  {id:'member-a',username:'user-a',display_name:'用户 A',role:'member',enabled:true,port:1443}];
const states=new Map(users.map(user=>[user.id,{user,server_ip:'198.51.100.63',server_port:user.port,
  server_protocol:'VLESS Reality',demo:true,service_active:true,exits:[],active:null,active_target:'server',
  server_exit:{id:'server',name:'服务器自身出口',observed_ip:'198.51.100.63',active:true},routing_mode:'smart',
  domains:['github.com'],direct_domains:['chaoxing.com'],routing_subscription:{enabled:true,interval:300},
  dirty:false,updated:at,download_ready:true,rollback_ready:true,job:null,
  client_config:{group:'STATIC-SELECT',auto_node:'AUTO · 网页切换',exit_count:0,fixed_nodes_refresh_required:false},
  health:{status:'unknown',message:'尚未完成后台检测',checking:false,mode:'manual',fallback_exit_id:null},
  transport:{enabled:true,protocols:['hysteria2','vless'],hy2_port:user.port,initial_update_required:true},
  traffic:{available:true,month:'2026-10',sampled_at:at,sampling_seconds:10,up_bytes:250e6,down_bytes:750e6,
    total_bytes:1e9,up_rate:20e3,down_rate:80e3,connections:4,quota_bytes:10e9,rate_bps:20e6,
    over_quota:false,quota_enforced:false,rate_enforced:true,
    connection_scope:'REALITY TCP socket 与 HY2 QUIC 会话合计，不代表业务流或设备',
    sources:{xray:{available:true},hy2:{available:true}}}}]));
const errors=[],cspErrors=[],requests=[];const check=name=>report.checks.push({name,passed:true});
let browser;
try{
  browser=await chromium.launch({channel:'msedge',headless:true});
  const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce'});let session=null;
  await context.route('**/*',async route=>{
    const req=route.request(),url=new URL(req.url());
    if(url.origin!==origin){errors.push('External request blocked');return route.abort();}
    if(!url.pathname.startsWith('/api/'))return route.continue();
    const resource=url.pathname.slice(5),body=req.postData()?req.postDataJSON():null;
    requests.push({resource,method:req.method()});
    const reply=(value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
    if(resource==='session')return reply({authenticated:!!session,csrf:session?'synthetic-integration-csrf':null,user:session});
    if(resource==='login'){session=users.find(user=>user.username===body.username);assert(session);return reply({csrf:'synthetic-integration-csrf',user:session});}
    if(!session)return reply({error:'请重新登录'},401);
    if(resource==='logout'){session=null;return reply({ok:true});}
    if(resource==='state')return reply(states.get(session.id));
    if(resource==='subscription')return reply({url:origin+'/subscription/synthetic-'+session.id+'.yaml',version:'integration-synthetic-v1',updated:at,download_ready:true});
    if(resource==='audit')return reply({events:[]});
    if(resource==='users')return reply({users:users.map(user=>({...user,traffic:states.get(user.id).traffic,service_active:true,exit_count:0,active_target:'server'}))});
    if(resource==='backups')return reply({backups:[],schedule:{enabled:false}});
    errors.push('Unexpected mocked endpoint '+resource);return reply({error:'Unexpected mocked endpoint'},500);
  });
  const page=await context.newPage();await page.clock.setFixedTime(new Date(at));
  page.on('pageerror',error=>errors.push(error.message));page.on('console',message=>{if(/Content Security Policy|Refused to|violates.*directive/i.test(message.text()))cspErrors.push(message.text());});
  const text=selector=>page.locator(selector).innerText();
  async function login(name){await page.locator('#login-user').fill(name);await page.locator('#login-password').fill('Synthetic-integration-password');await page.locator('#login-form button[type="submit"]').click();await page.locator('#console').waitFor({state:'visible'});await page.waitForFunction(name=>document.querySelector('#current-user-handle').textContent===name,name);}
  async function refresh(){const response=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/state');await page.locator('#refresh').click();await response;await page.waitForFunction(()=>document.querySelector('#global-error').hidden);}
  await page.goto(origin,{waitUntil:'networkidle'});await login('admin');
  assert.match(await text('#metric-server-detail'),/HY2.*REALITY.*双入口/);
  assert.match(await text('#traffic-accounting-note'),/HY2.*REALITY.*月额度.*限速.*DIRECT.*不计入.*QUIC.*不代表/);
  assert.equal(await text('#traffic-total'),'1.00 GB');assert.equal(await text('#traffic-connections'),'4');
  check('Unified transport capability and accounting scope are explicit; connection count is not described as TCP only or device count');
  await page.locator('[data-view="access"]').first().click();await page.locator('#subscription-version').filter({hasText:'integration-synthetic-v1'}).waitFor();
  assert.match(await text('#transport-update-notice'),/首次.*完整订阅.*AUTO.*网页不确认/);
  assert.match(await text('#client-config-update'),/HY2.*REALITY.*TCP兼容.*客户端连接记录.*无法确认/);
  assert.doesNotMatch(await text('#transport-update-notice'),/当前使用 HY2|客户端已更新|客户端已同步|HY2 已连接/);
  check('First protocol upgrade requires a full subscription refresh while the page never claims the client has updated or uses HY2');
  states.get('admin').client_config.fixed_nodes_refresh_required=true;await refresh();
  assert.match(await text('#client-config-update'),/首次使用双入口.*固定节点.*尚未进入运行配置/);
  check('Protocol upgrade instructions and unapplied fixed-node changes remain visible together');
  await page.locator('[data-view="overview"]').first().click();
  Object.assign(states.get('admin').traffic,{available:false,reason:'HY2 实时采样不可用，合计速率未知',up_rate:null,down_rate:null,connections:null,sources:{xray:{available:true},hy2:{available:false}}});await refresh();
  assert.equal(await text('#traffic-total'),'1.00 GB');assert.match(await text('#traffic-up-rate'),/不可用|未知/);assert.match(await text('#traffic-connections'),/不可用|未知/);assert.match(await text('#traffic-summary'),/HY2.*采样不可用/);
  check('A failed protocol source keeps recorded unified totals but never invents aggregate live rates or connections');
  await page.locator('[data-view="access"]').first().click();states.get('admin').transport.enabled=false;await refresh();
  assert.match(await text('#transport-update-notice'),/未启用.*REALITY/);assert.equal(await page.locator('#transport-update-notice').evaluate(element=>element.classList.contains('warning')),true);
  delete states.get('admin').transport;states.get('admin').client_config.fixed_nodes_refresh_required=false;await refresh();
  assert.equal(await page.locator('#transport-update-notice').isVisible(),false);assert.equal(await page.locator('#client-config-update').isVisible(),false);
  check('Unavailable or absent transport metadata produces no false dual-protocol readiness');
  states.get('admin').transport={enabled:true,protocols:['hysteria2','vless'],hy2_port:443,initial_update_required:true};await refresh();
  for(const width of [1440,390]){
    await page.setViewportSize({width,height:width===390?844:1000});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1),false);
    await page.locator('#subscription-card').screenshot({path:path.join(output,'transport-'+width+'.png'),mask:[page.locator('#subscription-url')]});report.screenshots.push('transport-'+width+'.png');
  }
  check('Desktop and mobile protocol instructions retain the approved layout without overflow');
  await page.locator('#logout-mobile:visible,#logout:visible').first().click();await page.locator('#login-screen').waitFor({state:'visible'});
  assert.equal(await page.locator('#transport-update-notice').evaluate(element=>element.hidden),true);assert.equal(await page.locator('#transport-update-notice').textContent(),'');
  await login('user-a');await page.locator('[data-view="access"]').first().click();assert.match(await text('#transport-update-notice'),/本账号配置支持/);assert.equal(await page.locator('#users-nav').isVisible(),false);
  check('Logout clears transport notices and the next member sees their independent account capability');
  assert.equal(requests.filter(request=>request.method==='POST'&&!['login','logout'].includes(request.resource)).length,0);
  assert.deepEqual(errors,[]);assert.deepEqual(cspErrors,[]);check('Read-only verification causes no configuration mutation, runtime error, or CSP violation');
  report.success=true;await context.close();
}catch(error){report.error=error.stack||String(error);throw error;}
finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));await fs.writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2)+'\n');}
console.log(JSON.stringify({success:report.success,checks:report.checks.length,report:path.join(output,'report.json')}));
