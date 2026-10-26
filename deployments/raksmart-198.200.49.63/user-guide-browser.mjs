import {chromium} from '../../panel/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const folder=path.dirname(fileURLToPath(import.meta.url));
const origin='https://198-200-49-63.sslip.io:8443';
const output=path.join(folder,'user-guide-browser-ui');
const report={checked_at:new Date().toISOString(),deployment_ip:'198.200.49.63',success:false,
  trusted_https:true,transport:'physical WLAN; restricted CONNECT proxy',checks:[],screenshots:[],users:[],guide_tours:[]};
const errors=[];
const blocked=[];
const contexts=[];
const profiles=[];
let stage='deployment_gate';
let browser;
await fs.mkdir(output,{recursive:true});

function profileInfo(profile) {
  const program="import hashlib,json,sys,yaml\np=yaml.safe_load(sys.stdin.read())\nproxies=p['proxies']\nprint(json.dumps({'ports':[item['port'] for item in proxies],'count':len(proxies),'identities':[hashlib.sha256(item['uuid'].encode()).hexdigest() for item in proxies]}))";
  return JSON.parse(execFileSync('python',['-c',program],{input:profile,encoding:'utf8',windowsHide:true}));
}
async function readState(page) {
  return page.evaluate(async()=>{
    const response=await fetch('./api/state',{credentials:'same-origin',signal:AbortSignal.timeout(15000)});
    if(!response.ok) throw new Error('Authenticated state could not be read');
    return response.json();
  });
}
async function readUsers(page) {
  return page.evaluate(async()=>{
    const response=await fetch('./api/users',{credentials:'same-origin',signal:AbortSignal.timeout(15000)});
    if(!response.ok) throw new Error('Administrator user list could not be read');
    return response.json();
  });
}
async function noOverflow(page) {
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,
    'Page must fit the viewport');
}
async function screenshot(page,name) {
  await page.evaluate(()=>{document.querySelector('#toast').hidden=true;window.scrollTo({top:0,behavior:'instant'});});
  await page.screenshot({path:path.join(output,name),fullPage:true});
  report.screenshots.push(name);
}

async function guideScreenshot(page,name) {
  await page.evaluate(()=>{document.querySelector('#toast').hidden=true;});
  await page.screenshot({path:path.join(output,name),fullPage:false});
  report.screenshots.push(name);
}

async function guideLayout(page) {
  const layout=await page.evaluate(()=>{
    const dialog=document.querySelector('#user-guide-dialog'),topics=document.querySelector('#guide-topics');
    const rect=dialog.getBoundingClientRect();
    return {open:dialog.open,left:rect.left,right:rect.right,top:rect.top,bottom:rect.bottom,
      width:innerWidth,height:innerHeight,topicsOverflow:topics.scrollWidth>topics.clientWidth+1,
      cardOverflow:[...topics.querySelectorAll('.guide-topic-card')].some(card=>card.scrollWidth>card.clientWidth+1)};
  });
  assert(layout.open);
  assert(layout.left>=0&&layout.right<=layout.width+1&&layout.top>=0&&layout.bottom<=layout.height+1,
    'Guide dialog must fit its desktop or mobile viewport');
  assert.equal(layout.topicsOverflow,false,'Written guide must not require horizontal scrolling');
  assert.equal(layout.cardOverflow,false,'Operation cards must fit their guide column');
  await noOverflow(page);
}

async function closeGuide(page) {
  if(await page.locator('#user-guide-dialog').evaluate(dialog=>dialog.open)) {
    await page.locator('#guide-close').click();
    await page.waitForFunction(()=>!document.querySelector('#user-guide-dialog').open);
  }
}

async function tourGeometry(page,expectedSelector) {
  await page.waitForFunction(selector=>{
    const tour=document.querySelector('#guide-tour'),arrow=document.querySelector('#guide-tour-arrow-line');
    const highlight=document.querySelector('#guide-tour-highlight');
    return tour.open&&!document.querySelector('#guide-tour-panel').hidden&&arrow.getAttribute('d')&&
      highlight.dataset.targetSelector===selector;
  },expectedSelector);
  const geometry=await page.evaluate(()=>{
    const dialog=document.querySelector('#guide-tour'),panel=document.querySelector('#guide-tour-panel');
    const highlight=document.querySelector('#guide-tour-highlight'),svg=document.querySelector('#guide-tour-arrow');
    const arrow=document.querySelector('#guide-tour-arrow-line'),length=arrow.getTotalLength();
    const selector=highlight.dataset.targetSelector,target=document.querySelector(selector);
    const point=arrow.getPointAtLength(length),matrix=arrow.getScreenCTM();
    const endpoint=new DOMPoint(point.x,point.y).matrixTransform(matrix);
    const frame=panel.getBoundingClientRect(),box=highlight.getBoundingClientRect();
    const targetBox=target.getBoundingClientRect();
    const panelFront=document.elementFromPoint(frame.left+frame.width/2,frame.top+Math.min(20,frame.height/2));
    const distance=Math.hypot(Math.max(box.left-endpoint.x,0,endpoint.x-box.right),
      Math.max(box.top-endpoint.y,0,endpoint.y-box.bottom));
    const targetDistance=Math.hypot(Math.max(targetBox.left-endpoint.x,0,endpoint.x-targetBox.right),
      Math.max(targetBox.top-endpoint.y,0,endpoint.y-targetBox.bottom));
    return {open:dialog.open,modal:dialog.matches(':modal'),width:innerWidth,height:innerHeight,
      panel:{left:frame.left,right:frame.right,top:frame.top,bottom:frame.bottom},
      highlight:{left:box.left,right:box.right,top:box.top,bottom:box.bottom,width:box.width,height:box.height},
      arrowShown:!svg.hasAttribute('hidden')&&getComputedStyle(svg).visibility!=='hidden'&&
        getComputedStyle(svg).display!=='none'&&svg.getClientRects().length>0,
      highlightShown:!highlight.hidden&&getComputedStyle(highlight).visibility!=='hidden',
      length,endpoint:{x:endpoint.x,y:endpoint.y},endpointDistance:distance,
      targetSelector:selector,targetDistance,targetShown:target.getClientRects().length>0,
      targetDialogOpen:Boolean(target.closest('dialog[open]')),
      panelTopLayer:Boolean(panelFront?.closest('#guide-tour-panel')),
      counter:document.querySelector('#guide-tour-counter').textContent,
      title:document.querySelector('#guide-tour-title').textContent};
  });
  assert(geometry.open&&geometry.modal,'Tour must use the native modal top layer');
  assert(geometry.arrowShown&&geometry.highlightShown&&geometry.length>5,'Every tour step needs a visible real arrow');
  assert(geometry.highlight.width>0&&geometry.highlight.height>0,'Tour highlight needs a real visible target');
  assert(geometry.panel.left>=0&&geometry.panel.right<=geometry.width+1&&geometry.panel.top>=0&&
    geometry.panel.bottom<=geometry.height+1,'Tour step card must stay in the viewport');
  assert(geometry.panelTopLayer,'The step card must stay above the target page or native form dialog');
  assert(geometry.endpointDistance<=24,'The SVG arrow must end at the highlighted control');
  assert(geometry.targetShown&&geometry.targetDistance<=15,'The arrow must point to the actual named page control');
  return geometry;
}

const administratorTopics=['admin-create','admin-reset','admin-enabled'];

async function manualChecks(page,key,isAdministrator,guest=false) {
  await page.locator(guest?'#login-user-guide':'#open-user-guide').click();
  await page.locator('#user-guide-dialog').waitFor({state:'visible'});
  await guideLayout(page);
  const cards=await page.locator('#guide-topics .guide-topic-card').evaluateAll(elements=>elements.map(card=>({
    id:card.dataset.guideTopic,steps:[...card.querySelectorAll('.guide-step')].map(step=>({
      text:step.textContent,arrow:step.querySelector('.guide-step-arrow')?.textContent||''})),
    actions:card.querySelectorAll('button.guide-topic-action').length
  })));
  assert(cards.length>0,'Guide must include available operations');
  for(const card of cards) {
    assert(card.steps.length>0&&card.actions===1,'Each operation needs a written sequence and one arrow tour');
    for(const step of card.steps) assert.match(step.arrow,/[→↳↗↓]/,'Every written step must show an arrow');
  }
  for(const topic of administratorTopics)
    assert.equal(cards.some(card=>card.id===topic),isAdministrator&&!guest,'Administrator guides must follow the current role');
  if(guest) assert.deepEqual(cards.map(card=>card.id),['login'],'Guests only see the login operation');
  else {
    assert(cards.some(card=>card.id==='smart-routing')&&cards.some(card=>card.id==='socks-add'));
    assert.match(await page.locator('#guide-topics article[data-guide-topic="smart-routing"]').innerText(),/mooc1\.chaoxing\.com/);
    assert.match(await page.locator('#guide-topics article[data-guide-topic="smart-routing"]').innerText(),/手动填写 chaoxing\.com/);
  }
  await guideScreenshot(page,key+'-guide-'+(guest?'login':page.viewportSize().width<700?'mobile':'desktop')+'.png');
  await closeGuide(page);
  return cards.length;
}

async function runGuideTour(page,key,topic,selectors) {
  await page.locator('#open-user-guide').click();
  await page.locator('button.guide-topic-action[data-guide-topic="'+topic+'"]').click();
  for(let index=0;index<selectors.length;index++) {
    if(index) await page.locator('#guide-tour-next').click();
    const geometry=await tourGeometry(page,selectors[index]);
    assert.equal(await page.locator('#guide-tour-panel').getAttribute('data-topic'),topic);
    assert.match(geometry.counter,new RegExp('^'+(index+1)+' / '));
    if(topic==='socks-add'&&index>0) {
      assert(geometry.targetDialogOpen,'SOCKS5 form targets must stay visible under the modal guide');
      assert.equal(await page.locator('#exit-socks-link').inputValue(),'');
      assert.equal(await page.locator('#exit-user').inputValue(),'');
      assert.equal(await page.locator('#exit-password').inputValue(),'');
      assert.equal(await page.locator('#exit-socks-link').getAttribute('type'),'password');
    }
    report.guide_tours.push({account:key,topic,viewport:page.viewportSize().width,target:geometry.targetSelector,
      counter:geometry.counter,real_arrow_visible:true,actual_target_verified:true,modal_card_above_target:true});
    if(index===1) await guideScreenshot(page,key+'-'+topic+'-arrow-'+
      (page.viewportSize().width<700?'mobile':'desktop')+'.png');
  }
  await stopTour(page);
}

async function userGuideChecks(page,key,before,index) {
  const count=await manualChecks(page,key,index===0);
  await runGuideTour(page,key,'smart-routing',['#routing-mode','#direct-domains','#routing-url-hint']);
  await runGuideTour(page,key,'socks-add',['#add-exit','#exit-socks-link','#parse-socks-link','#exit-name']);
  await page.setViewportSize({width:390,height:844});
  await manualChecks(page,key,index===0);
  await runGuideTour(page,key,'smart-routing',['#routing-mode','#direct-domains','#routing-url-hint']);
  await runGuideTour(page,key,'socks-add',['#add-exit','#exit-socks-link','#parse-socks-link']);
  await noOverflow(page);
  await page.setViewportSize({width:1440,height:1000});
  await page.locator('[data-view="overview"]').first().click();
  assert.deepEqual(await readState(page),before,'Handbook and arrow tours must preserve the complete server state');
  report.checks.push(key+': '+count+' operation guides with arrows, role permissions, desktop/mobile real targets, '+
    'native exit-form top layer and safe Next/Stop');
}

async function stopTour(page) {
  await page.locator('#guide-tour-exit').click();
  await page.waitForFunction(()=>!document.querySelector('#guide-tour').open);
  await closeGuide(page);
  assert.equal(await page.locator('#exit-dialog').evaluate(dialog=>dialog.open),false,
    'A tour-created blank exit dialog must be closed when the tour ends');
}

try {
  const deployment=JSON.parse(await fs.readFile(path.join(folder,'user-guide-update.json'),'utf8'));
  const release=JSON.parse(await fs.readFile(path.join(folder,'user-guide-release-manifest.json'),'utf8'));
  assert.equal(deployment.success,true,'Complete deployment before browser acceptance');
  assert.equal(release.deployment_ip,'198.200.49.63');
  const expectedAssets=release.source_sha256;
  assert.deepEqual(Object.keys(expectedAssets).sort(),['panel/web/app.js','panel/web/index.html','panel/web/style.css']);
  assert.equal(release.deployment_scope,'frontend_only');
  assert(process.env.NODE_CONSOLE_TEST_PROXY,'Run run_user_guide_browser.py to bind the physical WLAN');
  const names=['panel-login.private.json','multiuser-user-a-login.private.json','multiuser-user-b-login.private.json'];
  const logins=await Promise.all(names.map(async name=>JSON.parse(await fs.readFile(path.join(folder,name),'utf8'))));
  for(const login of logins) assert.equal(login.url,origin+'/node-console/');
  browser=await chromium.launch({channel:'msedge',headless:true,proxy:{server:process.env.NODE_CONSOLE_TEST_PROXY}});
  for(let index=0;index<logins.length;index++) {
    const login=logins[index];
    stage='trusted_login_'+index;
    const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce'});
    contexts.push(context);
    await context.route('**/*',async route=>{
      const request=route.request(),url=new URL(request.url());
      if(url.origin!==origin) {blocked.push('external_origin');await route.abort('blockedbyclient');return;}
      if(request.method()!=='GET'&&!(request.method()==='POST'&&['/node-console/api/login','/node-console/api/logout'].includes(url.pathname))) {
        blocked.push(url.pathname);await route.abort('blockedbyclient');return;
      }
      await route.continue();
    });
    const page=await context.newPage();
    page.on('pageerror',()=>errors.push('Browser JavaScript exception'));
    page.on('console',message=>{if(message.type()==='error') errors.push('Browser console error');});
    let navigation;
    for(let attempt=0;attempt<3;attempt++) {
      try {
        navigation=await page.goto(login.url,{waitUntil:'domcontentloaded',timeout:25000});
        if(navigation?.status()===200) break;
        assert([502,503,504].includes(navigation?.status()));
      } catch(error) {if(attempt===2) throw error;}
      await new Promise(resolve=>setTimeout(resolve,400));
    }
    assert.equal(navigation.status(),200);
    if(index===0) {
      stage='guest_user_guide';
      await manualChecks(page,'guest',false,true);
      report.checks.push('Unauthenticated operation guide has only login steps and per-step arrows');
    }
    await page.locator('#login-user').fill(login.username);
    await page.locator('#login-password').fill(login.password);
    await page.locator('#login-form button[type="submit"]').click();
    await page.locator('#console').waitFor({state:'visible',timeout:35000});
    await page.waitForFunction(username=>document.querySelector('#current-user-handle').textContent===username,login.username);
    const before=await readState(page);
    assert.equal(before.user.username,login.username);
    assert.equal(before.user.role,index===0?'admin':'member');
    assert.equal(before.server_ip,'198.200.49.63');
    assert.equal(before.server_port,index===0?443:index===1?1443:2443);
    assert.equal(before.service_active,true);
    assert.equal(before.demo,false);
    assert.notEqual(before.job?.status,'running','Run browser checks after service verification settles');
    assert.equal(await page.locator('#users-nav').isVisible(),index===0);
    assert.equal(await page.locator('.nav-button:visible').count(),index===0?4:3);
    assert.equal(await page.locator('#current-user-space').innerText(),index===0?'管理员':'个人空间');
    assert.match(await page.locator('#path-server').innerText(),new RegExp(' : '+before.server_port+'$'));
    if(index===0) assert(before.direct_domains.includes('mooc1.chaoxing.com'),'Administrator learning-site DIRECT rule is present');
    const key=index===0?'admin':index===1?'user-a':'user-b';
    report.users.push({username:login.username,role:before.user.role,port:before.server_port,
      exit_count:before.exits.length,active_target:before.active_target,service_active:before.service_active});
    stage='operation_guides_'+index;
    await userGuideChecks(page,key,before,index);
    stage='profile_download_'+index;
    const waitDownload=page.waitForEvent('download');
    await page.locator('#download-top').click();
    const download=await waitDownload;
    assert.equal(download.suggestedFilename(),'clash-node-console-'+login.username+'.yaml');
    const privateProfile=path.join(folder,'user-guide-browser-'+key+'-profile.private.yaml');
    await download.saveAs(privateProfile);
    const profile=await fs.readFile(privateProfile,'utf8');
    const info=profileInfo(profile);
    assert(info.count>0);
    assert(info.ports.every(port=>port===before.server_port),'Profile must contain only this user entrance');
    profiles.push(info);
    report.checks.push(key+': trusted login, own identity/navigation and isolated '+before.server_port+' profile');
    stage='desktop_mobile_'+index;
    await noOverflow(page);await screenshot(page,key+'-overview-desktop.png');
    await page.locator('[data-view="routing"]').first().click();
    assert.equal(await page.locator('#domains').inputValue(),before.domains.join('\n'));
    assert.equal(await page.locator('#direct-domains').inputValue(),before.direct_domains.join('\n'));
    for(const selector of ['direct-domains','domains']) {
      assert.match(await page.locator('label[for="'+selector+'"]').innerText(),/域名或网址/);
      assert.match(await page.locator('#'+selector).getAttribute('aria-describedby'),/routing-url-hint/);
    }
    assert.match(await page.locator('#routing-url-hint').innerText(),/完整 HTTP \/ HTTPS 网址/);
    assert.match(await page.locator('#routing-url-hint').innerText(),/去掉路径、参数与端口/);
    assert.match(await page.locator('#routing-url-hint').innerText(),/不会自动扩大到父域名/);
    assert.match(await page.locator('#direct-domains-hint').innerText(),/提取 mooc1\.chaoxing\.com/);
    assert.match(await page.locator('#direct-domains-hint').innerText(),/手动填 chaoxing\.com/);
    assert.match(await page.locator('#routing-domains-hint').innerText(),/显示提取出的域名/);
    await noOverflow(page);await screenshot(page,key+'-routing-desktop.png');
    await page.setViewportSize({width:390,height:844});
    await noOverflow(page);await screenshot(page,key+'-routing-mobile.png');
    await page.setViewportSize({width:1440,height:1000});
    report.checks.push(key+': full URL/domain labels, exact host extraction and explicit parent scope, desktop/mobile routing fit');
    await page.locator('[data-view="access"]').first().click();
    assert.equal(await page.locator('#current-password').getAttribute('type'),'password');
    assert.equal(await page.locator('#new-password').inputValue(),'');
    await page.locator('[data-view="overview"]').first().click();
    await page.locator('#add-exit').click();
    assert.equal(await page.locator('#exit-socks-link').getAttribute('type'),'password');
    assert(await page.locator('#parse-socks-link').isVisible());
    await page.locator('#cancel-dialog').click();
    await page.waitForFunction(()=>!document.querySelector('#exit-dialog').open);
    await page.setViewportSize({width:390,height:844});
    await noOverflow(page);await screenshot(page,key+'-overview-mobile.png');
    if(index===0) {
      stage='administrator_users';
      await page.locator('#users-nav').click();
      await page.waitForFunction(()=>document.querySelector('#user-list').children.length===3);
      const listing=await readUsers(page);
      assert.equal(listing.users.length,3);
      assert.deepEqual(listing.users.map(user=>user.port).sort((a,b)=>a-b),[443,1443,2443]);
      assert.equal(await page.locator('#user-slots').innerText(),'3 / 3 个账号');
      assert(await page.locator('#create-user-submit').isDisabled());
      assert.equal(await page.locator('#create-user-password').getAttribute('type'),'password');
      assert.equal(await page.locator('#user-list [data-user-action="enabled"]:visible').count(),2);
      assert.equal(await page.locator('#user-list [data-user-action="reset"]:visible').count(),2);
      await noOverflow(page);await screenshot(page,'admin-users-mobile.png');
      await page.setViewportSize({width:1440,height:1000});
      await noOverflow(page);await screenshot(page,'admin-users-desktop.png');
      assert.deepEqual(await readUsers(page),listing);
      report.checks.push('Administrator sees three accounts, protected admin controls, masked empty forms and capacity limit');
      stage='public_assets';
      for(const [name,resource] of Object.entries({'panel/web/index.html':'','panel/web/style.css':'style.css','panel/web/app.js':'app.js'})) {
        const source=await page.evaluate(async resource=>{
          const response=await fetch(new URL(resource||'./',location.href),{cache:'no-store',signal:AbortSignal.timeout(15000)});
          if(!response.ok) throw new Error('Public asset read failed');
          return {text:await response.text(),cache:response.headers.get('cache-control')};
        },resource);
        assert.equal(createHash('sha256').update(source.text).digest('hex'),expectedAssets[name]);
        assert.match(source.cache,/no-store/);
      }
      report.checks.push('All three public assets match the frozen reviewed release');
    }
    assert.deepEqual(await readState(page),before,'Browsing must preserve complete own public state');
    context.before=before;context.page=page;
    report.checks.push(key+': desktop/mobile fit, own routing/access views, SOCKS5 import preserved, state unchanged');
  }
  stage='cross_context_preservation';
  for(let a=0;a<profiles.length;a++) for(let b=a+1;b<profiles.length;b++)
    assert(profiles[a].identities.every(value=>!profiles[b].identities.includes(value)),'Users must have independent proxy credentials');
  for(const context of contexts) assert.deepEqual(await readState(context.page),context.before,
    'A different context browsing must not change this user state');
  assert.deepEqual(blocked,[],'No configuration mutation or external requests attempted');
  assert.deepEqual(errors,[],'No browser JavaScript or console errors');
  for(const context of contexts) {
    await context.page.setViewportSize({width:1440,height:1000});
    await context.page.locator('[data-view="routing"]').first().click();
    const example='https://mooc1.chaoxing.com/mycourse/studentstudy?chapterId=example';
    await context.page.locator('#direct-domains').fill(example);
    await context.page.locator('#domains').fill('https://github.com/example/project?tab=readme');
    assert.equal(await context.page.locator('#direct-domains').inputValue(),example);
    assert.deepEqual(await readState(context.page),context.before,'Unsubmitted URL drafts preserve own server state');
    await context.page.locator('#open-user-guide').click();
    assert.equal(await context.page.locator('#user-guide-dialog').evaluate(dialog=>dialog.open),true);
    // Programmatic logout tests cleanup even while a native guide dialog is open.
    // The sole permitted POST is the existing logout endpoint.
    await context.page.evaluate(()=>document.querySelector('#logout').click());
    await context.page.locator('#login-screen').waitFor({state:'visible'});
    assert.equal(await context.page.locator('#user-list .user-card').count(),0);
    assert.equal(await context.page.locator('#direct-domains').inputValue(),'');
    assert.equal(await context.page.locator('#domains').inputValue(),'');
    assert.equal(await context.page.locator('#user-guide-dialog').evaluate(dialog=>dialog.open),false);
    assert.equal(await context.page.locator('#guide-tour').evaluate(dialog=>dialog.open),false);
    assert.equal(await context.page.locator('#guide-topics').evaluate(element=>element.children.length),0);
    for(const selector of ['#guide-tour-panel','#guide-tour-arrow','#guide-tour-highlight'])
      assert.equal(await context.page.locator(selector).evaluate(element=>element.hasAttribute('hidden')),true,
        'Logout must clear all guide overlays');
    assert(await context.page.locator('#login-user-guide').isVisible());
  }
  report.independent_node_credentials=true;
  report.all_public_states_preserved=true;
  report.configuration_mutations_attempted=0;
  report.exit_switches=0;
  report.account_changes=0;
  report.guide_logout_cleanup_verified=true;
  report.real_arrows_and_targets_verified=true;
  report.desktop_and_mobile_guides_verified=true;
  report.administrator_guide_isolation_verified=true;
  report.checks.push('Three independent contexts retain states and credentials; unsubmitted URL drafts and guide contents clear on logout; POST is limited to login/logout');
  report.success=true;
} catch(error) {
  report.failed_stage=stage;
  report.error='User guide browser acceptance failed; inspect its private diagnostic log.';
  await fs.writeFile(path.join(folder,'user-guide-browser-error.private.log'),String(error.stack||error),'utf8');
} finally {
  if(browser) await browser.close();
  await fs.writeFile(path.join(folder,'user-guide-browser-verification.json'),JSON.stringify(report,null,2),'utf8');
}
console.log(JSON.stringify(report));
if(!report.success) process.exitCode=1;
