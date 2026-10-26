import {chromium} from 'playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const panel = path.dirname(fileURLToPath(import.meta.url));
const web = path.join(panel, 'web');
const output = path.join(panel, '..', '.validation', 'connection-motion');
const report = {checked_at:new Date().toISOString(), success:false,
  safety:{mock_api:true, external_network_blocked:true, credentials:'synthetic only'},
  viewports:[], checks:[], screenshots:[]};
await fs.mkdir(output, {recursive:true});
const widths=process.env.MOTION_CHECK_WIDTHS?process.env.MOTION_CHECK_WIDTHS.split(',').map(Number):[1440,1024,768,390];
const reportName=process.env.MOTION_REPORT_NAME||'report.json';
assert(widths.every(width=>Number.isInteger(width)&&width>=320&&width<=2000));
assert(/^[a-z0-9-]+\.json$/.test(reportName));
const staticFiles = {'/':'index.html','/index.html':'index.html','/app.js':'app.js','/style.css':'style.css','/mark.svg':'mark.svg'};
const server = http.createServer(async (request, response) => {
  try {
    const file = staticFiles[new URL(request.url, 'http://localhost').pathname];
    if (!file) {response.writeHead(404);response.end();return;}
    const mime = file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.svg') ? 'image/svg+xml' : 'text/html';
    response.writeHead(200, {'Content-Type':mime + '; charset=utf-8','Cache-Control':'no-store'});
    response.end(await fs.readFile(path.join(web,file)));
  } catch {response.writeHead(500);response.end();}
});
await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
const origin = 'http://127.0.0.1:' + server.address().port;
const time = '2026-10-09T05:30:00Z';
function exit(id,name,address,observed_ip,active=false) {
  return {id,name,address,port:1080,observed_ip,expected_ip:observed_ip,
    authenticated:true,active,pending:false,tested_at:time};
}
function fixture() {
  const exits = [exit('exit-us','美国主出口','us.proxy.example.invalid','203.0.113.24',true),
    exit('exit-de','德国备用出口','de.proxy.example.invalid','203.0.113.86')];
  return {server_ip:'198.51.100.158',server_port:443,server_protocol:'VLESS Reality',
    server_location:{country_code:'US',country:'United States',region:'California',city:'San Jose'},
    demo:true,service_active:true,exits,active:structuredClone(exits[0]),active_target:'static',
    server_exit:{id:'server',name:'服务器自身出口',observed_ip:'198.51.100.158',active:false},
    routing_mode:'smart',domains:['example.com'],direct_domains:['example.cn'],
    routing_subscription:{enabled:true,interval:300},dirty:false,updated:time,
    download_ready:true,rollback_ready:true,client_config:{group:'STATIC-SELECT',
      auto_node:'AUTO · 网页切换',exit_count:2,nodes:['出口 · 美国主出口','出口 · 德国备用出口'],
      refresh_required:false,fixed_nodes_refresh_required:false},job:null};
}
function job(kind,id,status='running') {
  return {id:'mock-'+kind,kind,exit_id:id,testing_id:kind==='test'?id:null,status,
    percent:status==='failed'?40:55,message:status==='failed'?'检测未通过，原出口继续使用':kind==='test'?'正在检测实际出口…':'正在校验，等待切换…'};
}
const scenarios = [
  {name:'static',build:fixture,target:'static',mode:'active',cardPhase:'ready',devicePhase:'active',active:'exit-us'},
  {name:'server',build:()=>{const s=fixture();s.active_target='server';s.active=null;s.server_exit.active=true;s.exits.forEach(x=>x.active=false);return s;},target:'server',mode:'active',cardPhase:'ready',devicePhase:'active',active:null},
  {name:'checking',build:()=>({...fixture(),job:job('test','exit-de')}),target:'static',mode:'test',cardPhase:'working',devicePhase:'checking',active:'exit-us',phase:['exit-de','checking'],busy:true},
  {name:'applying',build:()=>({...fixture(),job:job('apply','exit-de')}),target:'static',mode:'apply',cardPhase:'working',devicePhase:'applying',active:'exit-us',phase:['exit-de','applying'],busy:true},
  {name:'server-applying',build:()=>({...fixture(),job:job('apply','server')}),target:'static',mode:'apply',cardPhase:'working',devicePhase:'applying',active:'exit-us',serverPhase:'applying',busy:true},
  {name:'failure',build:()=>({...fixture(),job:job('apply','exit-de','failed')}),target:'static',cardPhase:'error',devicePhase:'active',active:'exit-us',phase:['exit-de','error']},
  {name:'empty',build:()=>({...fixture(),exits:[],active:null,active_target:'server',server_exit:{id:'server',name:'服务器自身出口',observed_ip:'198.51.100.158',active:true},download_ready:false,rollback_ready:false}),target:'server',mode:'active',cardPhase:'ready',devicePhase:'active',active:null},
  {name:'offline',build:()=>({...fixture(),service_active:false}),target:'static',mode:'offline',cardPhase:'offline',devicePhase:'offline',active:'exit-us',phase:['exit-us','offline']},
];
let browser;
const errors=[];
try {
  browser=await chromium.launch({channel:'msedge',headless:true});
  for (const width of widths) {
    const context=await browser.newContext({viewport:{width,height:width===390?844:1050}});
    let mockState=fixture(),authenticated=false,requestLog=[],mockJob=null,polls=0,failNextJob=false,nextStateDelay=0;
    await context.route('**/*',async route=>{
      const request=route.request();const url=new URL(request.url());
      if (url.origin!==origin) {errors.push('Unexpected external request '+url.origin);return route.abort();}
      if (!url.pathname.startsWith('/api/')) return route.continue();
      const resource=url.pathname.slice(5);requestLog.push({resource,method:request.method()});
      const respond=body=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(body)});
      if (resource==='session') return respond({authenticated,csrf:'mock-ui-csrf'});
      if (resource==='login') {authenticated=true;return respond({csrf:'mock-ui-csrf'});}
      if (resource==='logout') {authenticated=false;return respond({ok:true});}
      if (resource==='subscription') return respond({url:origin+'/subscription/synthetic-motion.yaml',version:'synthetic-motion-v1',updated:time,download_ready:true});
      if (resource==='audit') return respond({events:[],scope:'own'});
      if (resource==='state') {
        const delay=nextStateDelay;nextStateDelay=0;
        if(delay)await new Promise(resolve=>setTimeout(resolve,delay));
        return respond(mockState);
      }
      if (resource==='apply'||resource==='test') {
        const body=request.postDataJSON();assert(body.id==='server'||mockState.exits.some(x=>x.id===body.id));
        mockJob=job(resource,body.id);polls=0;mockState.job=mockJob;
        return respond({job_id:mockJob.id});
      }
      if (resource.startsWith('jobs/')) {
        assert(mockJob);polls++;
        if(polls>=3) {
          mockJob={...mockJob,status:failNextJob?'failed':'success',percent:failNextJob?40:100,
            message:failNextJob?'检测未通过，原出口继续使用':'模拟操作完成'};
          if(mockJob.kind==='apply'&&!failNextJob) {
            mockState.active_target=mockJob.exit_id==='server'?'server':'static';
            mockState.server_exit.active=mockJob.exit_id==='server';
            mockState.exits.forEach(x=>x.active=x.id===mockJob.exit_id);
            mockState.active=mockJob.exit_id==='server'?null:structuredClone(mockState.exits.find(x=>x.id===mockJob.exit_id));
          }
          failNextJob=false;
          mockState.job=mockJob;
        }
        return respond(mockJob);
      }
      throw new Error('Unexpected mock endpoint '+resource);
    });
    const page=await context.newPage();
    page.on('pageerror',error=>errors.push(error.message));
    page.on('console',message=>{if(message.type()==='error')errors.push(message.text());});
    async function refreshState(checkBusy=false) {
      if(checkBusy)nextStateDelay=300;
      const response=page.waitForResponse(value=>value.url()===origin+'/api/state');
      await page.locator('#refresh').click();
      if(checkBusy) {
        assert.equal(await page.locator('#refresh').isDisabled(),true,'Refresh disabled while reading');
        assert.equal(await page.locator('#refresh').getAttribute('aria-busy'),'true','Refresh busy while reading');
      }
      await (await response).finished();
      await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
      assert.equal(await page.locator('#refresh').isDisabled(),false,'Refresh disabled clears');
      assert.equal(await page.locator('#refresh').getAttribute('aria-busy'),'false','Refresh busy clears');
    }
    await page.goto(origin,{waitUntil:'networkidle'});
    await page.locator('#login-password').fill('synthetic-ui-password');
    await page.getByRole('button',{name:/进入控制台/}).click();
    await page.locator('#console').waitFor({state:'visible'});
    const viewportReport={width,scenarios:[],assets:{}};
    for(const file of ['index.html','style.css','app.js'])viewportReport.assets[file]=createHash('sha256').update(await fs.readFile(path.join(web,file))).digest('hex');
    for(const scenario of scenarios) {
      mockState=scenario.build();
      await refreshState(scenario.name==='static');
      await page.waitForFunction(target=>document.querySelector('#network-card').dataset.target===target,scenario.target);
      const pathCard=page.locator('#network-card');
      assert.equal(await pathCard.getAttribute('data-target'),scenario.target,scenario.name+' target');
      if(scenario.mode)assert.equal(await pathCard.getAttribute('data-mode'),scenario.mode,scenario.name+' mode');
      assert.equal(await pathCard.getAttribute('data-phase'),scenario.cardPhase,scenario.name+' card phase');
      assert.equal(await page.locator('#path-device').getAttribute('data-phase'),scenario.devicePhase,scenario.name+' device phase');
      assert.equal(await page.locator('.flow-track').count(),2);
      assert.equal(await page.locator('.flow-particle').count(),6);
      assert(await page.locator('#path-device-status').textContent(),scenario.name+' visible device status');
      assert.equal(await page.locator('.path-route.is-current').count(),scenario.active?1:0);
      if(scenario.active)assert.equal(await page.locator('.path-route.is-current').getAttribute('data-exit-id'),scenario.active);
      if(scenario.phase)assert.equal(await page.locator('.path-route[data-exit-id="'+scenario.phase[0]+'"]').getAttribute('data-phase'),scenario.phase[1]);
      if(scenario.serverPhase)assert.equal(await page.locator('#path-server-button').getAttribute('data-phase'),scenario.serverPhase);
      assert.equal(await page.locator('#path-server-button').isDisabled(),!!scenario.busy,scenario.name+' busy guard');
      assert.equal(await page.locator('#path-empty').isVisible(),scenario.name==='empty');
      assert.equal(await page.locator('#exit-connector').isVisible(),scenario.target==='static');
      if(scenario.busy)assert.equal(await page.locator('.path-connector.is-flowing').count(),0,'Busy state suspends flowing path');
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,width+' '+scenario.name+' overflow');
      const motion=await page.locator('#network-card').evaluate(card=>({
        animations:card.getAnimations({subtree:true}).map(animation=>({name:animation.animationName||'WAAPI',
          state:animation.playState,iterations:animation.effect.getTiming().iterations===Infinity?'infinite':animation.effect.getTiming().iterations})),
        mode:card.dataset.mode,target:card.dataset.target,
        device:document.querySelector('#path-device')?.dataset.phase||document.querySelector('.device-icon')?.dataset.phase||null,
        server:document.querySelector('#path-server-button').dataset.phase,
        routes:[...document.querySelectorAll('.path-route')].map(node=>({id:node.dataset.exitId,phase:node.dataset.phase})),
      }));
      viewportReport.scenarios.push({name:scenario.name,no_overflow:true,motion});
      if(['static','server','applying','failure','offline'].includes(scenario.name)&&(width===1440||width===390||process.env.MOTION_CHECK_WIDTHS)) {
        const name=scenario.name+'-'+width+'.png';
        await page.evaluate(()=>scrollTo({top:0,behavior:'instant'}));
        await page.screenshot({path:path.join(output,name),fullPage:true});
        report.screenshots.push(name);
      }
    }
    mockState=fixture();await refreshState();
    await page.waitForFunction(()=>!document.querySelector('#network-card').classList.contains('is-path-changing'));
    await page.locator('.path-route[data-exit-id="exit-de"]').click();
    await page.locator('.path-route[data-exit-id="exit-de"][data-phase="applying"]').waitFor();
    assert.equal(await page.locator('.path-route.is-current').getAttribute('data-exit-id'),'exit-us','Keep applied route while checking');
    assert.equal(await page.locator('#path-server-button').isDisabled(),true);
    assert.equal(await page.locator('#network-card').evaluate(card=>card.classList.contains('is-path-changing')),false,'No success transition while checking');
    await page.waitForFunction(()=>document.querySelector('.path-route.is-current')?.dataset.exitId==='exit-de');
    await page.waitForFunction(()=>!document.querySelector('#path-server-button').disabled);
    assert.equal(await page.locator('#network-card').evaluate(card=>card.classList.contains('is-path-changing')),true,'Success transition when applied identity changes');
    await page.waitForFunction(()=>!document.querySelector('#network-card').classList.contains('is-path-changing'));
    await refreshState();
    assert.equal(await page.locator('#network-card').evaluate(card=>card.classList.contains('is-path-changing')),false,'Same-state refresh does not replay success transition');
    await page.locator('#path-server-button').click();
    await page.locator('#path-server-button[data-phase="applying"]').waitFor();
    await page.waitForFunction(()=>document.querySelector('#network-card').dataset.target==='server');
    await page.waitForFunction(()=>!document.querySelector('#path-server-button').disabled);
    assert.equal(await page.locator('#path-server-button').getAttribute('aria-pressed'),'true');
    failNextJob=true;
    await page.locator('.path-route[data-exit-id="exit-us"]').click();
    await page.locator('.path-route[data-exit-id="exit-us"][data-phase="applying"]').waitFor();
    await page.locator('.path-route[data-exit-id="exit-us"][data-phase="error"]').waitFor();
    await page.waitForFunction(()=>!document.querySelector('#path-server-button').disabled);
    assert.equal(await page.locator('#network-card').getAttribute('data-target'),'server','Failed switch preserves server path');
    assert.equal(await page.locator('#path-server-button').getAttribute('aria-pressed'),'true');
    await page.locator('#add-exit').click();await page.locator('#exit-dialog').waitFor({state:'visible'});
    await page.locator('#cancel-dialog').click();await page.locator('#exit-dialog').waitFor({state:'hidden'});
    await page.locator('.nav-button[data-view="routing"]').click();
    assert.equal(await page.locator('body').evaluate(body=>body.classList.contains('motion-paused')),true,'Pause on another view');
    assert.equal(await page.locator('#routing-mode').inputValue(),'smart');
    await page.waitForFunction(()=>getComputedStyle(document.querySelector('#view-routing')).opacity==='1' &&
      document.querySelector('#view-routing').getAnimations().every(animation=>animation.playState!=='running'));
    assert.equal(await page.locator('#view-routing').evaluate(view=>getComputedStyle(view).opacity),'1','Routing opacity must settle at one');
    assert.equal(await page.locator('#routing-mode').isEnabled(),true);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,width+' routing overflow');
    if(width===1440||width===390){
      const name='routing-'+width+'.png';await page.screenshot({path:path.join(output,name),fullPage:true});report.screenshots.push(name);
    }
    await page.locator('.nav-button[data-view="access"]').click();
    assert.equal(await page.locator('#client-config-summary').isVisible(),true);
    await page.waitForFunction(()=>getComputedStyle(document.querySelector('#view-access')).opacity==='1' &&
      document.querySelector('#view-access').getAnimations().every(animation=>animation.playState!=='running'));
    assert.equal(await page.locator('#view-access').evaluate(view=>getComputedStyle(view).opacity),'1','Access opacity must settle at one');
    assert.equal(await page.locator('#current-password').isEnabled(),true);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,width+' access overflow');
    if(width===1440||width===390){
      const name='access-'+width+'.png';await page.screenshot({path:path.join(output,name),fullPage:true});report.screenshots.push(name);
    }
    await page.locator('.nav-button[data-view="overview"]').click();
    assert.equal(await page.locator('body').evaluate(body=>body.classList.contains('motion-paused')),false,'Resume on overview');
    await page.emulateMedia({reducedMotion:'reduce'});
    await page.waitForFunction(()=>matchMedia('(prefers-reduced-motion: reduce)').matches &&
      [...document.querySelectorAll('.flow-particle,.device-scan,.server-led')].every(node=>getComputedStyle(node).animationName==='none'));
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    const reactiveReduced=await page.locator('#network-card').evaluate(card=>card.getAnimations({subtree:true})
      .filter(animation=>animation.playState==='running').map(animation=>({name:animation.animationName||'WAAPI',
        type:animation.constructor.name,target:animation.effect.target?.className?.baseVal||animation.effect.target?.className,
        id:animation.id,playState:animation.playState,computed:animation.effect.target?getComputedStyle(animation.effect.target).animationName:null,
        connected:animation.effect.target?.isConnected,duration:animation.effect.getTiming().duration,
        media:matchMedia('(prefers-reduced-motion: reduce)').matches})));
    if(reactiveReduced.length)report.motion_diagnostic={width,reactiveReduced};
    assert.deepEqual(reactiveReduced,[],width+' changing reduced motion must cancel existing animations');
    mockState=fixture();await refreshState();
    await page.waitForTimeout(150);
    const reduced=await page.locator('#network-card').evaluate(card=>card.getAnimations({subtree:true})
      .filter(animation=>animation.playState==='running').map(animation=>animation.animationName||'WAAPI'));
    assert.deepEqual(reduced,[],width+' reduced motion must stop animations');
    viewportReport.reduced_motion=true;
    viewportReport.mock_button_switches=true;
    viewportReport.request_count=requestLog.length;
    report.viewports.push(viewportReport);
    await page.locator(width<=700?'#logout-mobile':'#logout').click();
    await page.locator('#login-screen').waitFor({state:'visible'});
    await context.close();
  }
  assert.deepEqual(errors,[]);
  report.checks.push('8 network states mapped correctly at '+widths.join(', ')+' px without horizontal overflow',
    'Mock exit/server clicks preserve applied route while busy and update only after success; failure keeps prior server path',
    'Add dialog, navigation, login/logout and smart routing display still work; routing/access settle at visible opacity 1',
    'Switching views pauses motion; prefers-reduced-motion removes existing and new animations at all checked widths',
    'No browser exceptions or unexpected external network requests');
  report.success=true;
} catch(error) {
  report.error=String(error.stack||error);
} finally {
  if(browser)await browser.close();
  await new Promise(resolve=>server.close(resolve));
  await fs.writeFile(path.join(output,reportName),JSON.stringify(report,null,2));
}
console.log(JSON.stringify({success:report.success,report:path.join(output,reportName),screenshots:report.screenshots.length,error:report.error||null}));
if(!report.success)process.exitCode=1;
