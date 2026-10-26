import {chromium} from '../../panel/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const folder=path.dirname(fileURLToPath(import.meta.url));
const origin='https://198-200-49-63.sslip.io:8443';
const base=origin+'/node-console/';
const args=process.argv.slice(2);
const releaseName=args.length===2&&args[0]==='--release-name'?args[1]:'';
const output=path.join(folder,'console-optimization-browser-ui');
const reportFile=path.join(folder,'console-optimization-browser-verification.json');
const report={success:false,checked_at:new Date().toISOString(),deployment_ip:'198.200.49.63',
  release_name:releaseName,trusted_https:true,owned_physical_wlan_proxy:true,secrets_included:false,
  configuration_mutations:0,checks:[],assets:{},accounts:[],screenshots:[]};
const accountNames=['admin','user-a','user-b'];
const contexts=[];
const browserErrors=[];
let browser,stage='local_manifest',blockedMutations=0,blockedExternal=0,profileRequests=0,allowedSessionPosts=0;
let expected403=0;
const safeFailureMessages=new Set();
function require(condition,message){if(!condition){safeFailureMessages.add(message);throw new Error(message);}}
function check(name){report.checks.push(name);}
function same(a,b){return JSON.stringify(a)===JSON.stringify(b);}
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
async function nav(page,name){
  await page.locator('.nav-button[data-view="'+name+'"]').click();
  await page.locator('#view-'+name).waitFor({state:'visible'});
}
async function get(page,resource,status=200){
  const response=await page.evaluate(async resource=>{
    for(let attempt=0;attempt<3;attempt++){
      const reply=await fetch('./api/'+resource,{credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(20000)});
      if([502,503,504].includes(reply.status)&&attempt<2){await new Promise(resolve=>setTimeout(resolve,400));continue;}
      return {status:reply.status,body:reply.status===200?await reply.json():null};
    }
  },resource);
  require(response?.status===status,'Read-only endpoint returned an unexpected status');
  return response.body;
}
async function fit(page){
  require(!await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),'Page exceeds viewport width');
}
async function shot(page,name){
  await page.evaluate(()=>{
    document.querySelector('#toast').hidden=true;
    document.querySelector('#login-password').value='';
    document.querySelector('#subscription-url').type='password';
    window.scrollTo({top:0,behavior:'instant'});
  });
  await page.screenshot({path:path.join(output,name),fullPage:true,
    mask:[page.locator('input[type="password"]'),page.locator('#subscription-url'),
      page.locator('.exit-endpoint,.exit-observed,.route-ip')],maskColor:'#f4f3ee'});
  report.screenshots.push(name);
}
async function waitText(page,selector,text){
  await page.waitForFunction(({selector,text})=>document.querySelector(selector)?.textContent.includes(text),{selector,text});
}
async function openDetails(page,selector){
  if(!await page.locator(selector).evaluate(element=>element.open))await page.locator(selector+' > summary').click();
}
function serviceLabel(value){return value===true?'运行中':value===false?'已停止':'待检查';}
function baselinePool(value){
  require(value&&value.capacity===3&&value.total_users===3&&value.available_count===0,'Production account capacity changed unexpectedly');
  require(same(value.member_ports,[1443,2443]),'Existing member port pool differs from baseline');
  require(value.public_verification==='not_checked','Public reachability must remain explicitly unverified');
  require(Array.isArray(value.supported_member_ports)&&value.supported_member_ports.includes(3444),'Next safe candidate is unavailable');
}
async function logout(page){
  await page.locator('#logout').evaluate(button=>button.click());
  await page.locator('#login-screen').waitFor({state:'visible'});
  require(await page.locator('#delivery-password').inputValue()==='','Logout retained a delivery password');
  require(!await page.locator('#member-delivery').isVisible(),'Logout retained delivery card');
  require(await page.locator('#create-user-password').inputValue()==='','Logout retained member password draft');
}

await fs.mkdir(output,{recursive:true});
try{
  require(/^console-optimization-release-[A-Za-z0-9_-]+$/.test(releaseName),'A valid --release-name is required');
  const manifestBytes=await fs.readFile(path.join(folder,releaseName,'manifest.json'));
  const manifest=JSON.parse(manifestBytes.toString('utf8'));
  require(manifest.release_name===releaseName&&manifest.deployment_ip==='198.200.49.63','Release manifest target differs');
  const assets=['index.html','app.js','style.css'];
  for(const asset of assets)require(/^[a-f0-9]{64}$/.test(manifest.release_sha256?.['panel/web/'+asset]||''),'Release manifest lacks asset hash');
  report.manifest_sha256=hash(manifestBytes);
  require(/^http:\/\/127\.0\.0\.1:\d+$/.test(process.env.NODE_CONSOLE_TEST_PROXY||''),'Run only through the owned CONNECT proxy wrapper');
  const logins=await Promise.all(['panel-login.private.json','multiuser-user-a-login.private.json','multiuser-user-b-login.private.json']
    .map(async name=>JSON.parse(await fs.readFile(path.join(folder,name),'utf8'))));
  for(let index=0;index<logins.length;index++){
    require(logins[index].url===base&&logins[index].username===accountNames[index]&&typeof logins[index].password==='string'&&logins[index].password.length>0,'Local account metadata differs from intended baseline');
  }
  browser=await chromium.launch({channel:'msedge',headless:true,proxy:{server:process.env.NODE_CONSOLE_TEST_PROXY}});
  for(let index=0;index<logins.length;index++){
    const login=logins[index],account=accountNames[index];stage='trusted_login_'+account;
    const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce',serviceWorkers:'block'});contexts.push(context);
    await context.addInitScript(()=>{window.nodeAcceptanceCspErrors=0;document.addEventListener('securitypolicyviolation',()=>window.nodeAcceptanceCspErrors++);});
    await context.route('**/*',async route=>{
      const request=route.request(),url=new URL(request.url());
      if(url.origin!==origin){blockedExternal++;return route.abort();}
      const sessionPost=request.method()==='POST'&&['/node-console/api/login','/node-console/api/logout'].includes(url.pathname);
      if(request.method()!=='GET'&&!sessionPost){blockedMutations++;return route.abort();}
      if(url.pathname==='/node-console/api/profile'||url.pathname.startsWith('/node-console/subscription/')){profileRequests++;return route.abort();}
      if(sessionPost)allowedSessionPosts++;
      return route.continue();
    });
    const page=await context.newPage();
    page.on('pageerror',()=>browserErrors.push('JavaScript exception'));
    page.on('console',entry=>{
      if(entry.type()!=='error')return;
      if(/Failed to load resource:.*403/.test(entry.text())){expected403++;return;}
      browserErrors.push(/Content Security Policy|Refused to (?:execute|load|connect)/i.test(entry.text())?'CSP console error':'Browser console error');
    });
    const navigation=await page.goto(base,{waitUntil:'domcontentloaded',timeout:40000});
    require(navigation?.status()===200,'Trusted HTTPS page navigation failed');
    await page.locator('#login-screen').waitFor({state:'visible'});
    for(const width of [1440,390]){
      await page.setViewportSize({width,height:width===390?844:1000});await fit(page);
      if(index===0)await shot(page,'login-'+width+'.png');
    }
    await page.setViewportSize({width:1440,height:1000});
    await page.locator('#login-user').fill(login.username);await page.locator('#login-password').fill(login.password);
    await page.locator('#login-submit').click();
    await page.locator('#console').waitFor({state:'visible',timeout:40000});
    await waitText(page,'#current-user-handle',account);
    require(await page.locator('#login-password').inputValue()==='','Login password remains in the page');
    const own=await get(page,'state');
    require(own.server_ip==='198.200.49.63'&&own.demo===false&&own.user.username===account,'Account state points to wrong server or identity');
    require(own.user.role===(index===0?'admin':'member'),'Account role differs');
    require(own.server_port===[443,1443,2443][index],'Account port differs from existing allocation');
    require(await page.locator('.nav-button:visible').count()===(index===0?5:3),'Account navigation does not match role');
    report.accounts.push({account,role:own.user.role,port:own.server_port,tcp_service:own.service_active===true?'running':own.service_active===false?'stopped':'unknown'});
    check(account+': trusted TLS login and isolated own state');
    if(index===0){
      stage='public_assets';
      for(const asset of assets){
        const bytes=await page.evaluate(async asset=>{
          const response=await fetch(new URL(asset==='index.html'?'./':asset,location.href),{cache:'no-store',signal:AbortSignal.timeout(20000)});
          if(response.status!==200)throw new Error('Public asset fetch failed');
          return Array.from(new Uint8Array(await response.arrayBuffer()));
        },asset);
        const digest=hash(Buffer.from(bytes));require(digest===manifest.release_sha256['panel/web/'+asset],'Public asset differs from final release');
        report.assets[asset]={sha256:digest,release_match:true};
      }
      check('Public HTML, JavaScript and CSS match final release SHA-256');
      stage='admin_existing_accounts';await nav(page,'users');
      const accountList=await get(page,'users'),pool=(await get(page,'entrances')).entrances;
      baselinePool(accountList.entrances);baselinePool(pool);
      require(Array.isArray(accountList.users)&&accountList.users.length===3,'Existing account count differs');
      require(same(accountList.users.map(user=>user.username).sort(),accountNames.slice().sort()),'Existing identities differ');
      await page.waitForFunction(()=>document.querySelectorAll('#user-list .user-card').length===3);
      const taskList=await get(page,'users/provision');require(Array.isArray(taskList.tasks)&&taskList.tasks.length===0,'Production preparation tasks are unexpectedly present');
      require(!await page.locator('#member-task-panel').isVisible(),'An empty task list shows stale task UI');
      require(await page.locator('#create-user-submit').isDisabled(),'Full capacity still permits creation');
      for(const user of accountList.users){
        require(user.service_active===true&&user.hy2_service_active===true&&user.hy2_port===user.port,'An existing protocol service is not running');
        const card=page.locator('#user-list .user-card').filter({has:page.locator('.user-username',{hasText:user.username})});
        require(await card.count()===1,'Member card missing or duplicate');
        require((await card.locator('.user-port').textContent()).includes('TCP '+user.port)&&(await card.locator('.user-port').textContent()).includes('UDP '+user.hy2_port),'Protocol ports differ from API');
        require(await card.locator('.user-service').textContent()==='TCP '+serviceLabel(user.service_active)+' · HY2 '+serviceLabel(user.hy2_service_active),'Service status differs from actual observation');
      }
      check('Administrator sees three preserved accounts, both running protocols, full pool and empty tasks');
      stage='admin_local_filters';await page.locator('#member-search').fill('user-a');await waitText(page,'#member-filter-count','显示 1 / 3');
      require(await page.locator('#user-list .user-card:visible').count()===1,'Member search returned wrong count');
      await page.locator('#member-status-filter').selectOption('disabled');
      require(await page.locator('#member-filter-empty').isVisible(),'Disabled filter should have empty result');
      await page.locator('#reset-member-filters').click();require(await page.locator('#user-list .user-card:visible').count()===3,'Filter reset did not restore all accounts');
      check('Search, disabled filter and reset work entirely in the page');
      stage='admin_entrance_draft';await openDetails(page,'#create-user-details');await page.locator('#prepare-member-entrance').click();
      require(await page.locator('#entrances-details').evaluate(element=>element.open),'Capacity action did not open port pool');
      await page.locator('#prepare-next-entrance').click();
      require(same((await page.locator('#entrances-member-ports').inputValue()).split(/[\s,，]+/).filter(Boolean).map(Number),[1443,2443,3444]),'Next entrance did not prepare only the safe candidate');
      require(!await page.locator('#entrances-cloud-confirmed').isChecked(),'Draft bypassed explicit cloud declaration');
      require((await page.locator('#entrances-firewall-text').inputValue()).includes('TCP 3444 / UDP 3444'),'Draft firewall list omitted candidate');
      require(same((await get(page,'entrances')).entrances,pool),'Local draft changed server pool');
      page.once('dialog',dialog=>dialog.accept());await page.reload({waitUntil:'domcontentloaded',timeout:40000});
      await page.locator('#console').waitFor({state:'visible',timeout:40000});await nav(page,'users');await openDetails(page,'#entrances-details');
      // Session restoration displays the console before its independent
      // member/pool GET finishes. Wait for actual completion indicators,
      // without waiting for the input value that this assertion tests.
      await page.waitForFunction(()=>
        document.querySelectorAll('#user-list .user-card').length===3&&
        document.querySelector('#users-loading').hidden&&
        document.querySelector('#create-user-submit').disabled&&
        document.querySelector('#quick-entrance-summary').textContent==='0 个可分配入口'&&
        document.querySelector('#entrance-next-note').textContent.startsWith('下一候选：')&&
        !document.querySelector('#prepare-next-entrance').disabled,
        null,{timeout:40000});
      require(same((await page.locator('#entrances-member-ports').inputValue()).split(/[\s,，]+/).filter(Boolean).map(Number),[1443,2443]),'Reload retained unpublished port draft');
      require(same((await get(page,'entrances')).entrances,pool),'Pool differs after draft-only interactions');
      check('Capacity action prepares 3444 only in draft; server pool stays unchanged and reload discards draft');
    }else{
      stage='member_permission_'+account;
      require(!await page.locator('#users-nav').isVisible()&&!await page.locator('#maintenance-nav').isVisible()&&!await page.locator('#admin-shortcuts').isVisible(),'Member sees administrator controls');
      for(const resource of ['users','entrances','users/provision','backups'])await get(page,resource,403);
      check(account+': users, entrances, provisioning and backup reads correctly return 403');
    }
    stage='viewports_'+account;
    for(const width of [1440,390]){
      await page.setViewportSize({width,height:width===390?844:1000});
      await nav(page,'overview');await fit(page);await shot(page,account+'-overview-'+width+'.png');
      await nav(page,'access');await page.waitForFunction(()=>document.querySelector('#subscription-url').value.length>0);
      require(await page.locator('#subscription-url').getAttribute('type')==='password','Access subscription is unmasked');await fit(page);
      await shot(page,account+'-access-'+width+'.png');
      if(index===0){await nav(page,'users');await fit(page);await shot(page,'admin-users-'+width+'.png');}
    }
    check(account+': desktop 1440 and phone 390 overview/access layouts fit with secrets masked');
    const unchanged=await get(page,'state');
    require(unchanged.user.username===own.user.username&&unchanged.server_port===own.server_port&&unchanged.active_target===own.active_target&&same(unchanged.domains,own.domains)&&same(unchanged.direct_domains,own.direct_domains)&&unchanged.dirty===own.dirty,'Read-only browser actions altered own configuration');
    require(await page.evaluate(()=>window.nodeAcceptanceCspErrors||0)===0,'Browser reported a CSP violation');
    await logout(page);await context.close();check(account+': logout clears password and delivery fields');
  }
  require(blockedMutations===0,'The page attempted an unapproved configuration POST');
  require(blockedExternal===0&&profileRequests===0,'The page attempted an external or profile request');
  require(browserErrors.length===0,'JavaScript or CSP/console error occurred');
  report.success=true;
}catch(error){
  // Only our fixed error messages are retained; Playwright exceptions may
  // contain request URLs, private input or DOM text, so retain their type only.
  const safe=safeFailureMessages.has(error?.message);
  report.failure={stage,message:safe?error.message:'Browser acceptance assertion or operation failed'};process.exitCode=1;
}finally{
  report.network_summary={session_posts:allowedSessionPosts,blocked_configuration_requests:blockedMutations,external_requests:blockedExternal,profile_requests:profileRequests,expected_403_console_entries:expected403};
  report.browser_errors=browserErrors;
  for(const context of contexts)await context.close().catch(()=>{});
  await browser?.close();
  await fs.writeFile(reportFile,JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({success:report.success,stage,checks:report.checks.length,accounts:report.accounts.length,report:path.basename(reportFile)}));
}
