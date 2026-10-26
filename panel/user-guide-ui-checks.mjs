import {chromium} from 'playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';

const panel=path.dirname(fileURLToPath(import.meta.url));
const output=path.join(panel,'..','.validation','user-guide-ui');
await fs.mkdir(output,{recursive:true});
const report={success:false,checked_at:new Date().toISOString(),checks:[],screenshots:[],assets:{},
  safety:{mock_api:true,external_network_blocked:true,automatic_mutations_permitted:false}};
for(const name of ['app.js','index.html','style.css'])report.assets[name]=createHash('sha256').update(await fs.readFile(path.join(panel,'web',name))).digest('hex');
const staticFiles={'/':'index.html','/app.js':'app.js','/style.css':'style.css','/mark.svg':'mark.svg'};
const server=http.createServer(async(request,response)=>{
  const file=staticFiles[new URL(request.url,'http://localhost').pathname];
  if(!file){response.writeHead(404);response.end();return;}
  const type=file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.svg')?'image/svg+xml':'text/html';
  response.writeHead(200,{'Content-Type':type+'; charset=utf-8','Cache-Control':'no-store'});
  response.end(await fs.readFile(path.join(panel,'web',file)));
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin='http://127.0.0.1:'+server.address().port;
const users=[{id:'admin',username:'admin',display_name:'管理员',role:'admin',enabled:true,port:443},
  {id:'1111111111111111',username:'user-a',display_name:'用户 A',role:'member',enabled:true,port:1443},
  {id:'2222222222222222',username:'user-b',display_name:'用户 B',role:'member',enabled:true,port:2443}];
const requests=[],errors=[],mutations=[];
const check=name=>report.checks.push({name,passed:true});
function fixture(user,empty=false){return {
  user,server_ip:'198.51.100.63',server_port:user.port,server_protocol:'VLESS Reality',demo:true,
  service_active:true,exits:empty?[]:[{id:'demo-exit',name:'示例静态出口',address:'203.0.113.10',port:443,
    observed_ip:'203.0.113.20',authenticated:true,active:false,pending:false,tested_at:'2026-10-10T00:00:00Z'}],
  active:null,active_target:'server',server_exit:{id:'server',name:'服务器自身出口',observed_ip:'198.51.100.63',active:true},
  routing_mode:'smart',domains:['github.com'],direct_domains:['mooc1.chaoxing.com'],
  routing_subscription:{enabled:true,interval:300},dirty:false,updated:'2026-10-10T00:00:00Z',
  download_ready:true,rollback_ready:true,client_config:{group:'STATIC-SELECT',auto_node:'AUTO · 网页切换',exit_count:1,
    fixed_nodes_refresh_required:false,nodes:['AUTO · 网页切换']},job:null};}
let browser;
try{
  browser=await chromium.launch({channel:'msedge',headless:true});
  async function contextFor(width=1440,empty=false){
    const context=await browser.newContext({viewport:{width,height:width===390?844:1000},reducedMotion:'reduce'});
    let user=null;
    const states=new Map(users.map(entry=>[entry.id,fixture(entry,empty)]));
    await context.route('**/*',async route=>{
      const req=route.request(),url=new URL(req.url());
      if(url.origin!==origin){errors.push('Unexpected external network request');return route.abort();}
      if(!url.pathname.startsWith('/api/'))return route.continue();
      const resource=url.pathname.slice(5),method=req.method();
      requests.push({resource,method});
      const reply=(body,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
      if(method==='POST'&&resource==='login'){
        user=users.find(entry=>entry.username===req.postDataJSON().username);
        assert(user);return reply({csrf:'synthetic-guide-csrf',user});
      }
      if(method==='POST'&&resource==='logout'){user=null;return reply({ok:true});}
      if(method!=='GET'){mutations.push(resource);return route.abort('blockedbyclient');}
      if(resource==='session')return reply({authenticated:Boolean(user),csrf:user?'synthetic-guide-csrf':null,user});
      if(!user)return reply({error:'请重新登录。'},401);
      if(resource==='state')return reply(states.get(user.id));
      if(resource==='users')return reply({users:users.map(entry=>({...entry,service_active:true,exit_count:empty?0:1,active_target:'server'}))});
      if(resource==='users/provision' && method==='GET'){assert.equal(user.role,'admin');return reply({tasks:[]});}
      if(resource==='subscription')return reply({url:origin+'/subscription/synthetic-'+user.id+'.yaml',version:'synthetic-guide-v1',updated:'2026-10-10T00:00:00Z',download_ready:true});
      if(resource==='audit')return reply({events:[],scope:user.role==='admin'?'all':'own'});
      if(resource==='backups')return reply({backups:[],schedule:{enabled:false,interval_hours:24,last_backup:null,next_backup:null}});
      if(resource==='profile'){mutations.push('automatic_profile_download');return route.abort();}
      throw new Error('Unexpected guide endpoint '+resource);
    });
    const page=await context.newPage();
    page.on('pageerror',error=>errors.push(error.message));
    return {context,page};
  }
  async function login(page,name){
    await page.goto(origin,{waitUntil:'networkidle'});
    await page.locator('#login-user').fill(name);
    await page.locator('#login-password').fill('Synthetic-only-guide-password');
    await page.locator('#login-form button[type="submit"]').click();
    await page.locator('#console').waitFor({state:'visible'});
  }
  async function fit(page){
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'No horizontal page overflow');
  }
  async function arrowTargets(page){
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    const result=await page.evaluate(()=>{
      const ring=document.querySelector('#guide-tour-highlight');
      if(ring.hidden)return {external:true};
      const svg=document.querySelector('#guide-tour-arrow');
      const target=document.querySelector(ring.dataset.targetSelector);
      const line=document.querySelector('#guide-tour-arrow-line');
      if(!target||!line||line.getTotalLength()===0)return {invalid:true};
      const end=line.getPointAtLength(line.getTotalLength());
      const point=new DOMPoint(end.x,end.y).matrixTransform(line.getScreenCTM());
      const box=target.getBoundingClientRect();
      const dx=Math.max(box.left-point.x,0,point.x-box.right);
      const dy=Math.max(box.top-point.y,0,point.y-box.bottom);
      return {distance:Math.hypot(dx,dy),targetWidth:box.width,targetHeight:box.height,
        svgVisible:svg.getClientRects().length>0&&getComputedStyle(svg).visibility!=='hidden',
        selector:ring.dataset.targetSelector,step:document.querySelector('#guide-tour-counter').textContent,
        marker:line.getAttribute('marker-end')};
    });
    if(result.external)return;
    assert(!result.invalid,'An arrow has a real visible target');
    assert(result.targetWidth>0&&result.targetHeight>0,'Arrow target is displayed: '+JSON.stringify(result));
    assert(result.svgVisible,'The connecting SVG arrow is visibly rendered');
    assert(result.distance<=20,'Arrow tip points to the highlighted control');
    assert(result.marker,'The pointer has a visible arrowhead');
  }
  async function shot(page,name){await page.screenshot({path:path.join(output,name),fullPage:false});report.screenshots.push(name);}
  // The DOM contract is read after the implementation agents finish; tests below
  // use the exported guide API and stable topic names, never actual actions.
  const topics=['login','first-client','overview','socks-add','manual-add','edit-exit','switch-exit','server-exit',
    'delete-recovery','smart-routing','routing-modes','password-logout','admin-create','admin-reset','admin-enabled',
    'draft-safety','rule-diagnostic','health-fallback','profile-subscription','usage-history','admin-backups','admin-lifecycle'];
  for(const width of [1440,390]){
    const entry=await contextFor(width),page=entry.page;
    await page.goto(origin+'/#help',{waitUntil:'networkidle'});
    await page.locator('#user-guide-dialog').waitFor({state:'visible'});
    assert.equal(await page.locator('button[data-guide-topic^="admin-"]:visible').count(),0);
    await fit(page);await shot(page,'guest-manual-'+width+'.png');
    await page.evaluate(()=>window.NodeGuide.start('login'));
    await page.locator('#guide-tour').waitFor({state:'visible'});
    await arrowTargets(page);
    await page.keyboard.press('Escape');
    assert.equal(await page.locator('#guide-tour').isVisible(),false,'Escape exits a login walkthrough');
    check(width+': login walkthrough arrows and Escape');
    await page.evaluate(()=>window.NodeGuide.stop());
    await page.evaluate(()=>document.querySelector('#user-guide-dialog').close());
    await login(page,'admin');
    await page.locator('#open-user-guide').click();
    await page.locator('#user-guide-dialog').waitFor({state:'visible'});
    assert.equal(await page.locator('button[data-guide-topic^="admin-"]:visible').count(),5);
    await fit(page);await shot(page,'admin-manual-'+width+'.png');
    for(const topic of topics.filter(name=>name!=='login')){
      await page.evaluate(name=>window.NodeGuide.start(name),topic);
      await page.locator('#guide-tour').waitFor({state:'visible'});
      for(let step=0;step<30;step++){
        await fit(page);
        await arrowTargets(page);
        assert(await page.locator('#guide-tour-panel').isVisible());
        const geometry=await page.evaluate(()=>{
          const panel=document.querySelector('#guide-tour-panel').getBoundingClientRect();
          return {left:panel.left,top:panel.top,right:panel.right,bottom:panel.bottom,width:innerWidth,height:innerHeight};
        });
        assert(geometry.left>=0&&geometry.top>=0&&geometry.right<=geometry.width+1&&geometry.bottom<=geometry.height+1,'Instruction card fits viewport');
        if(step===1&&['socks-add','smart-routing','first-client','admin-reset'].includes(topic))
          await shot(page,topic+'-'+width+'.png');
        const button=page.locator('#guide-tour-next');
        assert(await button.isVisible());
        await button.click();
        if(!(await page.locator('#guide-tour').isVisible()))break;
        if(step===29)throw new Error('Tour did not finish: '+topic);
      }
      check(width+': '+topic+' arrow walkthrough finishes without requests that change settings');
    }
    await page.locator('[data-view="overview"]').first().click();
    await page.locator('#add-exit').click();
    await page.locator('#exit-name').fill('我的未保存出口');
    await page.locator('#exit-password').fill('Synthetic-only-unsaved-secret');
    await page.evaluate(()=>window.NodeGuide.start('socks-add'));
    await page.evaluate(()=>window.NodeGuide.stop());
    assert.equal(await page.locator('#exit-name').inputValue(),'我的未保存出口');
    assert.equal(await page.locator('#exit-password').inputValue(),'Synthetic-only-unsaved-secret','A drafted proxy password is never cleared or copied into the guide');
    if(await page.locator('#user-guide-dialog').isVisible())await page.locator('#guide-close').click();
    await page.locator('#cancel-dialog').click();
    check(width+': existing proxy form and credential draft are retained');
    await page.locator('[data-view="routing"]').first().click();
    await page.locator('#direct-domains').fill('https://unsaved.example.cn/course?draft=1');
    await page.evaluate(()=>window.NodeGuide.start('smart-routing'));
    await page.evaluate(()=>window.NodeGuide.stop());
    assert.equal(await page.locator('#direct-domains').inputValue(),'https://unsaved.example.cn/course?draft=1','An unsaved routing draft is retained');
    check(width+': unsaved routing draft is retained');
    await entry.context.close();
  }
  for(const [username,empty] of [['user-a',false],['user-b',true]]){
    const {context,page}=await contextFor(390,empty);
    await login(page,username);
    await page.locator('#open-user-guide').click();
    assert.equal(await page.locator('button[data-guide-topic^="admin-"]:visible').count(),0);
    await page.evaluate(()=>window.NodeGuide.start('admin-create'));
    assert.equal(await page.locator('#view-users').isVisible(),false,'A member cannot navigate to administrator guides');
    await page.evaluate(()=>window.NodeGuide.start('switch-exit'));
    await page.locator('#guide-tour').waitFor({state:'visible'});
    await page.evaluate(()=>window.NodeGuide.stop());
    await page.evaluate(()=>window.NodeGuide.open());
    await page.keyboard.press('Escape');
    assert.equal(await page.locator('#user-guide-dialog').isVisible(),false);
    check(username+': member-only guide, administrator guard, '+(empty?'empty-exit fallback':'existing-exit steps')+' and Escape');
    await context.close();
  }
  assert.deepEqual(mutations,[],'Walkthroughs never submit changes, test a proxy, switch exits, reset passwords, disable users, or download profiles');
  assert.deepEqual(errors,[],'No browser JavaScript errors');
  report.configuration_mutations_attempted=0;
  report.success=true;
}catch(error){
  report.error=String(error.stack||error);
}finally{
  report.browser_errors=errors;report.automatic_mutations=mutations;
  if(browser)await browser.close();
  await new Promise(resolve=>server.close(resolve));
  await fs.writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2),'utf8');
}
console.log(JSON.stringify(report));
if(!report.success)process.exitCode=1;
