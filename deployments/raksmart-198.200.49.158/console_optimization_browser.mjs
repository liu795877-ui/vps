import {chromium} from '../../panel/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const folder=path.dirname(fileURLToPath(import.meta.url));
const origin='https://198-200-49-158.sslip.io:8443',base=origin+'/node-console/';
const args=process.argv.slice(2);
const releaseName=args.length===2&&args[0]==='--release-name'?args[1]:'';
const output=path.join(folder,'console-optimization-browser-ui');
const reportFile=path.join(folder,'console-optimization-browser-verification.json');
const report={success:false,checked_at:new Date().toISOString(),deployment_ip:'198.200.49.158',
  release_name:releaseName,trusted_https:true,owned_physical_wlan_proxy:true,secrets_included:false,
  configuration_mutations:0,checks:[],assets:{},accounts:[],screenshots:[]};
const contexts=[],browserErrors=[],safeFailureMessages=new Set();
let browser,stage='local_manifest',blockedMutations=0,blockedExternal=0,profileRequests=0,allowedSessionPosts=0;
function require(condition,message){if(!condition){safeFailureMessages.add(message);throw new Error(message);}}
function check(name){report.checks.push(name);}
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const ports=value=>value.split(/[\s,，]+/).filter(Boolean).map(Number);
function signature(state){return {user:state.user,server_ip:state.server_ip,server_port:state.server_port,
  active_target:state.active_target,active:state.active,exits:state.exits,domains:state.domains,
  direct_domains:state.direct_domains,routing_mode:state.routing_mode,dirty:state.dirty};}
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
  await page.evaluate(()=>{document.querySelector('#toast').hidden=true;window.scrollTo({top:0,behavior:'instant'});});
  await page.screenshot({path:path.join(output,name),fullPage:true,
    mask:[page.locator('input[type="password"]'),page.locator('#subscription-url'),
      page.locator('.exit-endpoint,.exit-observed,.route-ip')],maskColor:'#f4f3ee'});
  report.screenshots.push(name);
}
async function openDetails(page,selector){
  if(!await page.locator(selector).evaluate(element=>element.open))await page.locator(selector+' > summary').click();
}
function poolBaseline(value){
  require(value&&value.capacity===3&&value.total_users===1&&value.available_count===2,'Production account capacity differs from preserved single-administrator baseline');
  require(same(value.member_ports,[1443,2443]),'Default member port pool differs from intended baseline');
  require(value.public_verification==='not_checked','Public reachability must remain explicitly unverified');
  require(Array.isArray(value.supported_member_ports)&&value.supported_member_ports.includes(3444),'Next safe entrance candidate is unavailable');
}

await fs.mkdir(output,{recursive:true});
try{
  require(/^console-optimization-release-[A-Za-z0-9_-]+$/.test(releaseName),'A valid --release-name is required');
  const releaseFolder=path.join(folder,releaseName);
  const manifestBytes=await fs.readFile(path.join(releaseFolder,'manifest.json'));
  const manifest=JSON.parse(manifestBytes.toString('utf8'));
  require(manifest.release_name===releaseName&&manifest.deployment_ip==='198.200.49.158','Release manifest target differs');
  require(Array.isArray(manifest.application_files)&&manifest.application_files.length===41,'Frozen application does not contain 41 source files');
  for(const relative of manifest.application_files){
    require(typeof relative==='string'&&!path.isAbsolute(relative)&&!relative.includes('..')&&!relative.includes('\\'),'Invalid release source path');
    require(/^[a-f0-9]{64}$/.test(manifest.release_sha256?.[relative]||''),'Release source hash is missing');
    require(hash(await fs.readFile(path.join(releaseFolder,'release',relative)))===manifest.release_sha256[relative],'Local frozen application hash differs');
  }
  report.manifest_sha256=hash(manifestBytes);report.local_release_files_verified=41;
  check('All 41 local frozen application files match the target manifest');
  require(/^http:\/\/127\.0\.0\.1:\d+$/.test(process.env.NODE_CONSOLE_TEST_PROXY||''),'Run only through the owned CONNECT proxy wrapper');
  const login=JSON.parse(await fs.readFile(path.join(folder,'panel-login.private.json'),'utf8'));
  require(login.url===base&&login.username==='admin'&&typeof login.password==='string'&&login.password.length>0,'Local administrator metadata differs from intended baseline');
  browser=await chromium.launch({channel:'msedge',headless:true,proxy:{server:process.env.NODE_CONSOLE_TEST_PROXY}});
  const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce',serviceWorkers:'block'});
  contexts.push(context);
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
  page.on('console',entry=>{if(entry.type()==='error')browserErrors.push(/Content Security Policy|Refused to (?:execute|load|connect)/i.test(entry.text())?'CSP console error':'Browser console error');});
  stage='trusted_https_login';
  const navigation=await page.goto(base,{waitUntil:'domcontentloaded',timeout:40000});
  require(navigation?.status()===200,'Trusted HTTPS page navigation failed');
  await page.locator('#login-screen').waitFor({state:'visible'});
  require((await get(page,'session')).authenticated===false,'Fresh browser context is unexpectedly authenticated');
  require((await page.request.get(base+'api/state')).status()===401,'Anonymous state read is not protected');
  for(const width of [1440,390]){
    await page.setViewportSize({width,height:width===390?844:1000});await fit(page);await shot(page,'login-'+width+'.png');
  }
  require(await page.evaluate(()=>matchMedia('(prefers-reduced-motion: reduce)').matches),'Reduced motion browser preference is inactive');
  require(await page.locator('.login-trajectories path').first().evaluate(element=>getComputedStyle(element).animationName)==='none','Login motion ignores reduced motion');
  check('Trusted TLS, anonymous state protection, desktop/mobile login and reduced motion');
  await page.setViewportSize({width:1440,height:1000});
  await page.locator('#login-user').fill(login.username);await page.locator('#login-password').fill(login.password);
  await page.locator('#login-submit').click();
  await page.locator('#console').waitFor({state:'visible',timeout:40000});
  await page.waitForFunction(()=>document.querySelector('#current-user-handle').textContent==='admin');
  require(await page.locator('#login-password').inputValue()==='','Login password remains in the page');
  const own=await get(page,'state');
  require(own.server_ip==='198.200.49.158'&&own.demo===false&&own.user.username==='admin'&&own.user.role==='admin'&&own.server_port===443,'Own state targets wrong server, account or entrance');
  require(own.service_active===true,'Administrator REALITY service is not active');
  require(await page.locator('.nav-button:visible').count()===5,'Administrator navigation does not match role');
  report.accounts.push({account:'admin',role:'admin',port:443,tcp_service:'running'});
  check('Preserved administrator login and own state at TCP 443');
  stage='public_assets';
  for(const asset of ['index.html','app.js','style.css','mark.svg']){
    const bytes=await page.evaluate(async asset=>{
      const response=await fetch(new URL(asset==='index.html'?'./':asset,location.href),{cache:'no-store',signal:AbortSignal.timeout(20000)});
      if(response.status!==200)throw new Error('Public asset fetch failed');
      return Array.from(new Uint8Array(await response.arrayBuffer()));
    },asset);
    const digest=hash(Buffer.from(bytes));require(digest===manifest.release_sha256['panel/web/'+asset],'Public asset differs from frozen target release');
    report.assets[asset]={sha256:digest,release_match:true};
  }
  check('Public HTML, JavaScript, CSS and SVG match final release SHA-256');
  stage='admin_preserved_accounts';await nav(page,'users');
  const accountList=await get(page,'users'),pool=(await get(page,'entrances')).entrances;
  poolBaseline(accountList.entrances);poolBaseline(pool);
  require(Array.isArray(accountList.users)&&accountList.users.length===1&&accountList.users[0].username==='admin','Existing single-administrator account baseline changed');
  await page.waitForFunction(()=>document.querySelectorAll('#user-list .user-card').length===1&&document.querySelector('#users-loading').hidden);
  const tasks=await get(page,'users/provision');require(Array.isArray(tasks.tasks)&&tasks.tasks.length===0,'Preparation tasks are unexpectedly present');
  require(!await page.locator('#member-task-panel').isVisible(),'Empty tasks show stale preparation UI');
  require(!await page.locator('#create-user-submit').isDisabled(),'Two free entrances do not permit member preparation');
  const user=accountList.users[0];
  require(user.service_active===true&&user.hy2_service_active===true&&user.hy2_port===443,'An administrator protocol service is not running at the preserved entrance');
  require(await page.locator('#user-list .user-service').textContent()==='TCP 运行中 · HY2 运行中','Protocol UI differs from observed services');
  require((await page.locator('#user-list .user-port').textContent()).includes('TCP 443 / UDP 443'),'Protocol UI differs from preserved entrance');
  check('Single existing account, running REALITY/HY2, two free member entrances and empty preparation tasks');
  stage='admin_filters';
  await page.locator('#member-search').fill('unmatched_acceptance');
  require(await page.locator('#member-filter-empty').isVisible(),'Search empty result is missing');
  await page.locator('#reset-member-filters').click();
  await page.locator('#member-status-filter').selectOption('disabled');
  require(await page.locator('#member-filter-empty').isVisible(),'Disabled filter returned unexpected account');
  await page.locator('#reset-member-filters').click();
  require(await page.locator('#user-list .user-card:visible').count()===1,'Reset did not restore existing account');
  check('Local member search, status filtering and reset');
  stage='member_frontend_draft';await nav(page,'overview');
  await page.locator('#quick-add-member').click();
  require(await page.locator('#create-user-details').evaluate(element=>element.open),'Quick add did not reveal member form');
  await page.locator('#create-username').fill('acceptance_draft');
  await page.locator('#create-display-name').fill('验收草稿');
  await page.locator('#generate-member-password').click();
  require((await page.locator('#create-user-password').inputValue()).length>=12&&await page.locator('#create-user-password').getAttribute('type')==='password','Generated member password is missing or unmasked');
  require(await page.locator('#member-draft-indicator').isVisible(),'Member draft indicator is missing');
  // Clear member-only draft locally before navigating; never submit the form.
  await page.locator('#create-username').fill('');await page.locator('#create-display-name').fill('');await page.locator('#create-user-password').fill('');
  check('Quick member action reveals the form and generates a masked password without submission');
  stage='entrance_draft';await nav(page,'overview');await page.locator('#quick-entrances').click();
  require(await page.locator('#entrances-details').evaluate(element=>element.open),'Quick entrance action did not reveal the pool');
  await page.locator('#prepare-next-entrance').click();
  require(same(ports(await page.locator('#entrances-member-ports').inputValue()),[1443,2443,3444]),'Next entrance did not prepare only safe candidate 3444');
  require(!await page.locator('#entrances-cloud-confirmed').isChecked(),'Entrance draft bypassed cloud confirmation');
  require((await page.locator('#entrances-firewall-text').inputValue()).includes('TCP 3444 / UDP 3444'),'Draft firewall list lacks both candidate protocols');
  require(same((await get(page,'entrances')).entrances,pool),'Local draft changed production pool');
  page.once('dialog',dialog=>dialog.accept());await page.reload({waitUntil:'domcontentloaded',timeout:40000});
  await page.locator('#console').waitFor({state:'visible',timeout:40000});await nav(page,'users');await openDetails(page,'#entrances-details');
  await page.waitForFunction(()=>document.querySelectorAll('#user-list .user-card').length===1&&document.querySelector('#users-loading').hidden&&
    !document.querySelector('#create-user-submit').disabled&&document.querySelector('#quick-entrance-summary').textContent==='2 个可分配入口'&&
    document.querySelector('#entrance-next-note').textContent.startsWith('下一候选：')&&!document.querySelector('#prepare-next-entrance').disabled,null,{timeout:40000});
  require(same(ports(await page.locator('#entrances-member-ports').inputValue()),[1443,2443]),'Reload retained unpublished entrance draft');
  require(same((await get(page,'entrances')).entrances,pool),'Pool changed after draft-only interactions');
  check('3444 remains a local draft, both protocols require cloud confirmation, and refresh discards the draft');
  stage='maintenance_readonly';await nav(page,'maintenance');
  const backups=await get(page,'backups');
  require(Array.isArray(backups.backups)&&backups.schedule&&typeof backups.schedule.enabled==='boolean','Backup listing or schedule is unavailable');
  await page.waitForFunction(()=>document.querySelector('#backup-schedule-status').textContent.includes('最近'));
  require((await get(page,'audit?limit=50')).events instanceof Array,'Administrator audit listing is unavailable');
  report.backup_count=backups.backups.length;
  check('Backup library, schedule and administrator audit are readable without writes');
  stage='all_viewports';
  for(const width of [1440,390]){
    await page.setViewportSize({width,height:width===390?844:1000});
    for(const view of ['overview','routing','access','users','maintenance']){
      await nav(page,view);
      if(view==='access'){
        await page.waitForFunction(()=>document.querySelector('#subscription-url').value.length>0);
        require(await page.locator('#subscription-url').getAttribute('type')==='password','Subscription URL is unmasked');
      }
      await fit(page);await shot(page,'admin-'+view+'-'+width+'.png');
    }
  }
  check('All five administrator views fit desktop 1440 and phone 390 with masked secrets');
  require(same(signature(await get(page,'state')),signature(own)),'Browser acceptance altered routing, exit or identity state');
  require(same((await get(page,'entrances')).entrances,pool),'Browser acceptance altered entrance pool');
  require((await get(page,'users')).users.length===1&&(await get(page,'users/provision')).tasks.length===0,'Browser acceptance created an account or task');
  require(await page.evaluate(()=>window.nodeAcceptanceCspErrors||0)===0,'Browser reported a CSP violation');
  stage='logout_secret_clearing';await nav(page,'users');await openDetails(page,'#create-user-details');
  await page.locator('#create-username').fill('logout_draft');await page.locator('#generate-member-password').click();
  // This application prompts before abandoning a local draft. Confirming the
  // native browser dialog affects only the page; no preparation request is sent.
  page.on('dialog',dialog=>dialog.accept());
  await page.locator('#logout').evaluate(button=>button.click());
  const draftDialog=page.locator('#draft-dialog');
  if(await draftDialog.isVisible())await page.locator('#draft-discard').click();
  await page.locator('#login-screen').waitFor({state:'visible',timeout:15000});
  for(const selector of ['#delivery-password','#create-user-password','#subscription-url','#backup-password','#restore-password'])
    require(await page.locator(selector).inputValue()==='','Logout retained a sensitive page field');
  require(!await page.locator('#member-delivery').isVisible(),'Logout retained member delivery card');
  check('Logout clears locally generated member password, delivery, subscription and backup fields');
  require(blockedMutations===0,'Page attempted a configuration mutation');
  require(blockedExternal===0&&profileRequests===0,'Page attempted an external or profile request');
  require(browserErrors.length===0,'JavaScript or CSP/console error occurred');
  report.success=true;
}catch(error){
  report.failure={stage,message:safeFailureMessages.has(error?.message)?error.message:'Browser acceptance assertion or operation failed'};process.exitCode=1;
}finally{
  report.network_summary={session_posts:allowedSessionPosts,blocked_configuration_requests:blockedMutations,external_requests:blockedExternal,profile_requests:profileRequests};
  report.browser_errors=browserErrors;
  for(const context of contexts)await context.close().catch(()=>{});
  await browser?.close();
  await fs.writeFile(reportFile,JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({success:report.success,stage,checks:report.checks.length,accounts:report.accounts.length,report:path.basename(reportFile)}));
}
