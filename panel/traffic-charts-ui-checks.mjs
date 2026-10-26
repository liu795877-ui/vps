import {chromium} from 'playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const panel=path.dirname(fileURLToPath(import.meta.url)),web=path.join(panel,'web');
const output=path.join(panel,'..','.validation','traffic-charts-ui');
const report={success:false,checked_at:new Date().toISOString(),checks:[],screenshots:[],assets:{},
  safety:{mock_api:true,external_network_blocked:true,credentials:'synthetic only',production_csp:true}};
await fs.mkdir(output,{recursive:true});
for(const name of ['app.js','index.html','style.css']) report.assets[name]=createHash('sha256').update(await fs.readFile(path.join(web,name))).digest('hex');
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
const origin='http://127.0.0.1:'+server.address().port,initialAt='2026-10-10T01:00:00Z';
const users=[{id:'admin',username:'admin',display_name:'管理员',role:'admin',enabled:true,port:443},
  {id:'member-a',username:'user-a',display_name:'用户 A',role:'member',enabled:true,port:1443}];
const traffic=(extra={})=>({available:true,month:'2026-10',period_timezone:'UTC',sampled_at:initialAt,sampling_seconds:10,
  up_bytes:250e6,down_bytes:750e6,total_bytes:1e9,up_rate:20e3,down_rate:80e3,connections:27,
  quota_bytes:0,rate_bps:0,over_quota:false,quota_enforced:false,rate_enforced:false,...extra});
const fixture=user=>({user,server_ip:'198.51.100.63',server_port:user.port,server_protocol:'VLESS Reality',demo:true,
  service_active:true,exits:[],active:null,active_target:'server',server_exit:{id:'server',name:'服务器自身出口',observed_ip:'198.51.100.63',active:true},
  routing_mode:'smart',domains:['github.com'],direct_domains:['chaoxing.com'],routing_subscription:{enabled:true,interval:300},dirty:false,
  updated:initialAt,download_ready:true,rollback_ready:true,client_config:{group:'STATIC-SELECT',auto_node:'AUTO · 网页切换',exit_count:0,fixed_nodes_refresh_required:false},job:null,
  health:{status:'unknown',message:'尚未完成后台检测',checking:false,mode:'manual',fallback_exit_id:null},traffic:traffic()});
const states=new Map(users.map(user=>[user.id,fixture(user)])),requests=[],errors=[],cspErrors=[];
const clockTimes=new WeakMap();
let failedStateReads=0;
const check=name=>report.checks.push({name,passed:true});
let browser;
try{
  browser=await chromium.launch({channel:'msedge',headless:true});
  async function contextFor(width=1440){
    const context=await browser.newContext({viewport:{width,height:width===390?844:1100},reducedMotion:'reduce'});
    let session=null;
    await context.route('**/*',async route=>{
      const req=route.request(),url=new URL(req.url());
      if(url.origin!==origin){errors.push('Unexpected external network request: '+url.origin);return route.abort();}
      if(!url.pathname.startsWith('/api/'))return route.continue();
      const resource=url.pathname.slice(5),body=req.postData()?req.postDataJSON():null;
      requests.push({resource,method:req.method(),id:session?.id});
      const reply=(value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
      if(resource==='session')return reply({authenticated:!!session,csrf:session?'synthetic-chart-csrf':null,user:session});
      if(resource==='login'){session=users.find(user=>user.username===body.username);assert(session);return reply({csrf:'synthetic-chart-csrf',user:session});}
      if(!session)return reply({error:'请重新登录。'},401);
      if(resource==='logout'){session=null;return reply({ok:true});}
      if(resource==='state'){if(failedStateReads>0){failedStateReads--;return reply({error:'模拟服务器暂时不可用'},503);}return reply(states.get(session.id));}
      if(resource==='users')return reply({users:users.map(user=>({...user,traffic:states.get(user.id).traffic,service_active:true,exit_count:0,active_target:'server'}))});
      if(resource==='subscription')return reply({url:origin+'/subscription/synthetic-'+session.id+'.yaml',version:'synthetic-v1',updated:initialAt,download_ready:true});
      if(resource==='audit')return reply({events:[],scope:session.role==='admin'?'all':'own'});
      if(resource==='backups')return reply({backups:[],schedule:{enabled:false,interval_hours:24}});
      errors.push('Unexpected endpoint '+resource);return reply({error:'Unexpected mocked endpoint'},500);
    });
    const page=await context.newPage();
    await page.clock.setFixedTime(new Date(initialAt));clockTimes.set(page,Date.parse(initialAt));
    page.on('pageerror',error=>errors.push(error.message));
    page.on('console',message=>{if(/Content Security Policy|Refused to|violates.*directive/i.test(message.text()))cspErrors.push(message.text());});
    return {context,page};
  }
  async function login(page,name){
    if(!await page.locator('#login-screen').isVisible())await page.goto(origin,{waitUntil:'networkidle'});
    await page.locator('#login-user').fill(name);await page.locator('#login-password').fill('Synthetic-chart-password');
    await page.locator('#login-form button[type="submit"]').click();await page.locator('#console').waitFor({state:'visible'});
    await page.waitForFunction(name=>document.querySelector('#current-user-handle').textContent===name,name);
  }
  async function refresh(page,id,value,advanceClock=true){
    states.get(id).traffic=value;
    const sampleTime=Date.parse(value.sampled_at),currentTime=clockTimes.get(page);
    if(advanceClock&&Number.isFinite(sampleTime)&&sampleTime>=currentTime){await page.clock.setFixedTime(new Date(sampleTime));clockTimes.set(page,sampleTime);}
    const received=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/state');
    await page.locator('#refresh').click();await received;
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
  }
  async function fit(page){assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'Page fits viewport');}
  async function shot(page,name){await page.locator('#traffic-summary').scrollIntoViewIfNeeded();await page.screenshot({path:path.join(output,name),fullPage:true,mask:[page.locator('#subscription-url')]});report.screenshots.push(name);}

  // The scenarios below use the public DOM and visible graph data, never call
  // private chart helpers or synthesize points through the implementation.

  const desktop=await contextFor(),page=desktop.page;
  await page.goto(origin,{waitUntil:'networkidle'});await login(page,'admin');
  await page.locator('#traffic-donut').waitFor({state:'visible'});
  const text=selector=>page.locator(selector).innerText();
  const pointSelector='#traffic-rate-points circle[data-traffic-sample]';
  const count=()=>page.locator('#traffic-rate-chart').getAttribute('data-sample-count').then(Number);
  const points=()=>page.locator(pointSelector).evaluateAll(elements=>elements.map(element=>({
    series:element.dataset.series,sample:element.dataset.trafficSample,cx:Number(element.getAttribute('cx')),
    cy:Number(element.getAttribute('cy')),label:element.getAttribute('aria-label'),title:element.querySelector('title')?.textContent,
    tabindex:element.getAttribute('tabindex')})));
  assert.equal(await text('#traffic-total'),'1.00 GB');
  assert.equal(await text('#traffic-up-total'),'250.00 MB');assert.equal(await text('#traffic-down-total'),'750.00 MB');
  assert.match(await text('#traffic-up-share'),/25(?:\.0+)?%/);assert.match(await text('#traffic-down-share'),/75(?:\.0+)?%/);
  assert.equal(await text('#traffic-connections'),'27');assert.equal(await text('#traffic-up-rate'),'20.00 KB/s');assert.equal(await text('#traffic-down-rate'),'80.00 KB/s');
  const arcs=await page.locator('#traffic-donut-up, #traffic-donut-down').evaluateAll(elements=>elements.map(element=>({
    circumference:Number(element.getAttribute('pathLength'))||2*Math.PI*Number(element.getAttribute('r')),dash:Number(element.getAttribute('stroke-dasharray').split(/[ ,]+/)[0]),hidden:element.hasAttribute('hidden')})));
  assert(arcs.every(arc=>!arc.hidden&&arc.circumference>0));
  assert(Math.abs(arcs[0].dash/arcs[0].circumference-.25)<.001,'Upload arc represents 25% of real total');
  assert(Math.abs(arcs[1].dash/arcs[1].circumference-.75)<.001,'Download arc represents 75% of real total');
  check('Monthly totals, upload/download shares, donut arcs and live values match the API');

  assert.equal(await count(),1,'Initial chart contains one actual sample');
  assert.equal(await page.locator('#traffic-rate-lines path').count(),0,'No invented initial history curve');
  let currentPoints=await points();assert.equal(currentPoints.length,2);
  assert(currentPoints.every(point=>point.title&&point.label),'Every data point has an accessible numeric label');
  assert(currentPoints.find(point=>point.series==='down').cy<currentPoints.find(point=>point.series==='up').cy,'Higher throughput is plotted higher');
  assert.match(currentPoints.find(point=>point.series==='up').label,/20\.00 KB\/s/);
  assert.match(currentPoints.find(point=>point.series==='down').label,/80\.00 KB\/s/);
  check('First view has one real sample with correctly scaled, accessible upload/download points');

  for(let index=0;index<3;index++)await refresh(page,'admin',traffic());
  assert.equal(await count(),1);assert.equal((await points()).length,2);
  check('Repeated API reads of the same sampled_at do not fabricate extra samples');
  await refresh(page,'admin',traffic({sampled_at:'2026-10-10T01:00:10Z',up_rate:40e3,down_rate:160e3}));
  assert.equal(await count(),2);currentPoints=await points();assert.equal(currentPoints.length,4);
  const latestUp=currentPoints.filter(point=>point.series==='up').at(-1),firstUp=currentPoints.find(point=>point.series==='up');
  assert(latestUp.cx>firstUp.cx,'Distinct real samples progress left to right');
  assert.match(latestUp.label,/40\.00 KB\/s/);assert.match(currentPoints.filter(point=>point.series==='down').at(-1).label,/160\.00 KB\/s/);
  assert.equal(await page.locator('#traffic-rate-lines path').count(),2);
  check('New sampled_at appends the real rates and renders upload/download paths');

  await page.clock.setFixedTime(new Date('2026-10-10T01:00:55Z'));clockTimes.set(page,Date.parse('2026-10-10T01:00:55Z'));
  await refresh(page,'admin',traffic({sampled_at:'2026-10-10T01:00:10Z',up_rate:40e3,down_rate:160e3}));
  assert.match(await text('#traffic-up-rate'),/未知|不可用|过期/);assert.match(await text('#traffic-down-rate'),/未知|不可用|过期/);assert.match(await text('#traffic-connections'),/未知|不可用|过期/);
  assert.equal(await text('#traffic-total'),'1.00 GB');assert.equal(await count(),2);
  check('A 45-second-old sample cannot be presented as live; recorded totals and chart history remain');
  await page.clock.setFixedTime(new Date('2026-10-10T01:00:10Z'));clockTimes.set(page,Date.parse('2026-10-10T01:00:10Z'));
  await refresh(page,'admin',traffic({sampled_at:'2026-10-10T01:00:10Z',up_rate:40e3,down_rate:160e3}));

  const focusPoint=page.locator(pointSelector+'[tabindex="0"]');assert.equal(await focusPoint.count(),1);
  await focusPoint.focus();await page.keyboard.press('Home');
  assert.match(await text('#traffic-chart-readout'),/20\.00 KB\/s|80\.00 KB\/s/);
  await page.keyboard.press('End');assert.match(await text('#traffic-chart-readout'),/40\.00 KB\/s|160\.00 KB\/s/);
  await page.keyboard.press('ArrowLeft');assert.match(await text('#traffic-chart-readout'),/20\.00 KB\/s|80\.00 KB\/s/);
  const active=await page.evaluate(()=>document.activeElement.getAttribute('aria-label'));
  assert.match(active,/20\.00 KB\/s|80\.00 KB\/s/);
  check('Keyboard focus, Home, End and previous sample expose the recorded values');

  await refresh(page,'admin',traffic({sampled_at:'bad-timestamp',up_rate:50e3,down_rate:100e3}));
  assert.equal(await count(),2,'Malformed sampling timestamps never fabricate chart history');
  await refresh(page,'admin',traffic({sampled_at:'2026-10-10T00:59:50Z',up_rate:50e3,down_rate:100e3}));
  assert.equal(await count(),2,'Older responses never append out-of-order samples');
  await refresh(page,'admin',traffic({sampled_at:'2026-10-10T01:01:10Z',up_rate:50e3,down_rate:100e3}),false);
  assert.equal(await count(),2,'Future timestamps with a clock discrepancy never append samples');
  assert.match(await text('#traffic-up-rate'),/未知|不可用|过期/);
  check('Malformed, out-of-order and future timestamps do not invent or reorder historical data');

  await refresh(page,'admin',traffic({sampled_at:'2026-10-10T01:00:20Z',up_bytes:null,down_bytes:null,total_bytes:null,up_rate:null,down_rate:null,connections:null}));
  assert.match(await text('#traffic-total'),/未知/);assert.match(await text('#traffic-up-total'),/未知/);assert.match(await text('#traffic-down-total'),/未知/);
  assert.match(await text('#traffic-connections'),/未知|不可用/);assert.match(await text('#traffic-up-rate'),/未知|不可用/);assert.match(await text('#traffic-down-rate'),/未知|不可用/);
  assert.equal(await page.locator('#traffic-donut').getAttribute('data-state'),'unknown');
  assert.equal(await page.locator('#traffic-donut-up, #traffic-donut-down').evaluateAll(elements=>elements.every(element=>element.hasAttribute('hidden'))),true);
  assert.equal(await count(),2);check('Missing totals, rates and connections remain unknown and draw no false zero sample');

  await refresh(page,'admin',traffic({sampled_at:'2026-10-10T01:00:30Z',up_bytes:0,down_bytes:0,total_bytes:0,up_rate:0,down_rate:0,connections:0}));
  assert.equal(await text('#traffic-total'),'0 B');assert.equal(await text('#traffic-up-rate'),'0 B/s');assert.equal(await text('#traffic-down-rate'),'0 B/s');assert.equal(await text('#traffic-connections'),'0');
  assert.equal(await page.locator('#traffic-donut').getAttribute('data-state'),'empty');assert.equal(await count(),3);
  currentPoints=await points();assert.equal(currentPoints.filter(point=>/0 B\/s/.test(point.label)).length,2);
  const zeroPoints=currentPoints.filter(point=>/0 B\/s/.test(point.label));assert.equal(zeroPoints[0].cy,zeroPoints[1].cy);
  check('Recorded zero values remain valid zero data and show an empty donut');

  await refresh(page,'admin',traffic({sampled_at:'2026-10-10T01:00:40Z',available:false,reason:'无法读取节点实时统计',up_rate:9e6,down_rate:8e6,connections:99}));
  assert.match(await text('#traffic-summary'),/1\.00 GB.*无法读取节点实时统计/);assert.equal(await text('#traffic-total'),'1.00 GB');
  assert.equal(await text('#traffic-up-total'),'250.00 MB');assert.equal(await text('#traffic-down-total'),'750.00 MB');
  assert.match(await text('#traffic-up-rate'),/不可用|未知/);assert.match(await text('#traffic-down-rate'),/不可用|未知/);assert.match(await text('#traffic-connections'),/不可用|未知/);
  assert.equal(await count(),3);check('Unavailable telemetry preserves recorded monthly totals and reason without pretending stale rates are live');

  await refresh(page,'admin',traffic({sampled_at:'2026-10-10T01:00:50Z',up_bytes:2e9,down_bytes:6e9,total_bytes:8e9,quota_bytes:10e9,notice:'本月流量已使用 80%',rate_bps:20e6,rate_enforced:true}));
  assert.match(await text('#traffic-summary'),/80%/);assert.match(await text('#traffic-quota-label'),/8\.00 GB|80(?:\.0+)?%/);assert.match(await text('#traffic-rate-limit'),/20\.00 Mbps/);assert.match(await text('#traffic-rate-state'),/已执行/);
  let progress=await page.locator('#traffic-quota-progress').evaluate(element=>({value:element.value,max:element.max}));assert(Math.abs(progress.value/progress.max-.8)<.001);
  check('Configured quota is drawn proportionally with the original 80% notice and rate enforcement status');
  await refresh(page,'admin',traffic({sampled_at:'2026-10-10T01:01:00Z',up_bytes:3e9,down_bytes:9e9,total_bytes:12e9,quota_bytes:10e9,over_quota:true,quota_enforced:false,rate_bps:20e6,rate_enforced:false,enforcement_error:'限额或限速未能执行，请检查网络权限'}));
  assert.match(await text('#traffic-summary'),/12\.00 GB.*尚未阻断.*未能执行/);assert.match(await text('#traffic-quota-state'),/尚未|未执行|失败/);assert.match(await text('#traffic-rate-state'),/尚未|未执行|失败/);
  assert.equal(await page.locator('#traffic-summary').evaluate(element=>element.classList.contains('warning')),true);
  progress=await page.locator('#traffic-quota-progress').evaluate(element=>({value:element.value,max:element.max}));assert(progress.value<=progress.max);
  check('Over quota and enforcement failure remain explicit; the progress bar stays in bounds');

  const beforePartial=await count();
  await refresh(page,'admin',traffic({sampled_at:'2026-10-10T01:01:10Z',down_bytes:null,total_bytes:1e9,up_rate:30e3,down_rate:null}));
  assert.equal(await text('#traffic-total'),'1.00 GB');assert.match(await text('#traffic-down-total'),/未知/);
  assert.equal(await page.locator('#traffic-donut').getAttribute('data-state'),'unknown');assert.equal(await count(),beforePartial+1);
  currentPoints=await points();const partial=currentPoints.filter(point=>point.sample===String(Date.parse('2026-10-10T01:01:10Z')));
  assert.equal(partial.length,1);assert.equal(partial[0].series,'up');assert.match(partial[0].label,/30\.00 KB\/s/);
  assert.match(await text('#traffic-down-rate'),/未知|不可用/);
  check('A partial real sample keeps the known total and upload rate without inventing missing download values');

  for(let index=0;index<64;index++)await refresh(page,'admin',traffic({sampled_at:new Date(Date.parse('2026-10-10T02:00:00Z')+index*10000).toISOString(),up_rate:(index+1)*1000,down_rate:(index+1)*2000}));
  assert.equal(await count(),60);assert.equal((await points()).length,120);
  assert((await points()).every(point=>!Number.isNaN(point.cx)&&!Number.isNaN(point.cy)));
  check('Long running page retains a bounded 60 real samples without invalid geometry');

  await refresh(page,'admin',traffic({month:'2026-11',sampled_at:'2026-11-01T00:00:00Z',up_bytes:100e6,down_bytes:300e6,total_bytes:400e6}));
  assert.equal(await count(),1);assert.equal((await points()).length,2);assert.equal(await text('#traffic-total'),'400.00 MB');
  check('New monthly period starts its own history and displays the new recorded totals');
  await refresh(page,'admin',traffic({month:'2026-11',sampled_at:'2026-11-01T00:00:10Z',up_bytes:100e6,down_bytes:300e6,total_bytes:400e6,up_rate:40e3,down_rate:120e3}));
  await refresh(page,'admin',traffic({month:'2026-11',sampled_at:'2026-11-01T00:00:40Z',up_bytes:100e6,down_bytes:300e6,total_bytes:400e6,up_rate:10e3,down_rate:60e3}));
  const timePoints=(await points()).filter(point=>point.series==='up');
  assert.equal(timePoints.length,3);assert(Math.abs((timePoints[2].cx-timePoints[1].cx)/(timePoints[1].cx-timePoints[0].cx)-3)<.01);
  check('The horizontal time scale reflects 10-second and 30-second observed intervals');

  for(const width of [1440,390]){
    await page.setViewportSize({width,height:width===390?844:1100});await fit(page);
    assert(await page.locator('#traffic-donut').isVisible());assert(await page.locator('#traffic-rate-chart').isVisible());
    const graphBoxes=await page.locator('#traffic-donut, #traffic-rate-chart').evaluateAll(elements=>elements.map(element=>{const box=element.getBoundingClientRect();return {left:box.left,right:box.right,width:box.width,height:box.height};}));
    assert(graphBoxes.every(box=>box.left>=0&&box.right<=width+1&&box.width>0&&box.height>0),'Both graph viewports fit on screen');
    await shot(page,'charts-'+width+'.png');check(width+': actual charts and readable data fit with reduced motion');
  }

  await page.evaluate(()=>window.NodeGuide.start('usage-history'));await page.locator('#guide-tour').waitFor({state:'visible'});
  await page.locator('#guide-tour-next').click();
  await page.waitForFunction(()=>document.querySelector('#guide-tour-highlight').dataset.targetSelector==='#traffic-facts');
  assert(await page.locator('#traffic-facts').isVisible());await page.evaluate(()=>window.NodeGuide.stop());
  check('Existing usage walkthrough still points at the graph dashboard');
  if(await page.locator('#user-guide-dialog').isVisible())await page.locator('#guide-close').click();
  await page.locator('#logout-mobile').click();await page.locator('#login-screen').waitFor({state:'visible'});
  assert.equal(await count(),0);assert.equal((await points()).length,0);assert(!/400\.00 MB/.test(await text('#traffic-total')));
  states.get('member-a').traffic=traffic({sampled_at:'2026-10-10T03:00:00Z',up_bytes:500e6,down_bytes:1500e6,total_bytes:2e9,up_rate:333e3,down_rate:444e3});
  await page.clock.setFixedTime(new Date('2026-10-10T03:00:00Z'));clockTimes.set(page,Date.parse('2026-10-10T03:00:00Z'));
  await login(page,'user-a');assert.equal(await count(),1);assert.equal((await points()).length,2);assert.equal(await text('#traffic-total'),'2.00 GB');
  assert((await points()).every(point=>/333\.00 KB\/s|444\.00 KB\/s/.test(point.label)));
  await fit(page);check('Logout clears chart data and the next member sees only their own samples and totals');

  await page.clock.setFixedTime(new Date('2026-10-10T03:00:45Z'));clockTimes.set(page,Date.parse('2026-10-10T03:00:45Z'));
  await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));
  await page.waitForFunction(()=>/未知|不可用|过期/.test(document.querySelector('#traffic-up-rate').textContent));
  assert.match(await text('#traffic-connections'),/未知|不可用|过期/);assert.equal(await count(),1);
  check('Returning to a visible page invalidates stale instantaneous telemetry without inventing samples');
  await page.clock.setFixedTime(new Date('2026-10-10T03:00:00Z'));clockTimes.set(page,Date.parse('2026-10-10T03:00:00Z'));
  await refresh(page,'member-a',states.get('member-a').traffic);
  assert.equal(await text('#traffic-up-rate'),'333.00 KB/s');
  await page.clock.setFixedTime(new Date('2026-10-10T03:00:45Z'));clockTimes.set(page,Date.parse('2026-10-10T03:00:45Z'));
  failedStateReads=1;const failedResponse=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/state'&&response.status()===503);
  await page.locator('#refresh').click();await failedResponse;
  await page.waitForFunction(()=>/未知|不可用|过期/.test(document.querySelector('#traffic-up-rate').textContent));
  assert.equal(await text('#traffic-total'),'2.00 GB');assert.equal(await count(),1);
  check('A failed state refresh cannot leave stale rates labelled as live');
  assert(requests.filter(request=>request.method!=='GET').every(request=>['login','logout'].includes(request.resource)),'Graph reads do not mutate settings');
  assert(!requests.some(request=>request.resource==='traffic'),'Graphs use existing state refresh instead of adding independent polling');
  check('Graph views reuse read-only state data and leave all settings untouched');

  assert.deepEqual(errors,[],'No runtime failures or outside network requests');
  assert.deepEqual(cspErrors,[],'Charts satisfy the production script/style CSP');
  report.success=true;
}catch(error){report.failure=error.stack;report.browser_errors=errors;report.csp_errors=cspErrors;throw error;}
finally{
  await browser?.close();await new Promise(resolve=>server.close(resolve));
  await fs.writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({success:report.success,checks:report.checks.length,report:path.join(output,'report.json')}));
}
