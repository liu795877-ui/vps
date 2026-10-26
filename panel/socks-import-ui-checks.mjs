import {chromium} from 'playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const panel = path.dirname(fileURLToPath(import.meta.url));
const web = path.join(panel, 'web');
const output = path.join(panel, '..', '.validation', 'socks-import');
const widths = [1440, 390];
const report = {checked_at:new Date().toISOString(), success:false,
  safety:{mock_api:true, external_network_blocked:true, credentials:'synthetic only'},
  viewports:[], checks:[], screenshots:[]};
await fs.mkdir(output, {recursive:true});
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
function fixture() {
  const exits = [{id:'existing-exit',name:'已保存出口',address:'203.0.113.10',port:1080,
    observed_ip:'203.0.113.11',expected_ip:'203.0.113.11',authenticated:true,active:true,pending:false,tested_at:time}];
  return {server_ip:'198.51.100.63',server_port:443,server_protocol:'VLESS Reality',
    server_location:{country_code:'US',country:'United States',region:'California',city:'San Jose'},
    demo:true,service_active:true,exits,active:structuredClone(exits[0]),active_target:'static',
    server_exit:{id:'server',name:'服务器自身出口',observed_ip:'198.51.100.63',active:false},
    routing_mode:'smart',domains:['example.com'],direct_domains:['example.cn'],
    routing_subscription:{enabled:true,interval:300},dirty:false,updated:time,
    download_ready:true,rollback_ready:true,client_config:{group:'STATIC-SELECT',
      auto_node:'AUTO · 网页切换',exit_count:1,nodes:['出口 · 已保存出口'],
      refresh_required:false,fixed_nodes_refresh_required:false},job:null};
}
const cases = [
  {name:'IPv4 credentials paste',uri:'socks5://synthetic-user:synthetic-pass@203.0.113.90:443',
    address:'203.0.113.90',port:'443',auth:'credentials',username:'synthetic-user',password:'synthetic-pass'},
  {name:'percent encoded credentials',uri:'socks5://user%2Bencoded:p%40ss%3A%2Fword@203.0.113.91:1081',
    address:'203.0.113.91',port:'1081',auth:'credentials',username:'user+encoded',password:'p@ss:/word'},
  {name:'without authentication',uri:'socks5://203.0.113.92:1080',
    address:'203.0.113.92',port:'1080',auth:'none',username:'',password:''},
  {name:'fragment name',uri:'socks5://fragment-user:fragment-pass@203.0.113.93:443#%E6%B5%8B%E8%AF%95%E5%87%BA%E5%8F%A3',
    address:'203.0.113.93',port:'443',auth:'credentials',username:'fragment-user',password:'fragment-pass',parsedName:'测试出口'},
  {name:'trailing slash',uri:'socks5://slash-user:slash-pass@203.0.113.94:1080/',
    address:'203.0.113.94',port:'1080',auth:'credentials',username:'slash-user',password:'slash-pass'},
];
const invalidLinks = [
  ['unsupported scheme','https://reject-user:reject-pass@203.0.113.95:443'],
  ['missing port','socks5://reject-user:reject-pass@203.0.113.95'],
  ['zero port','socks5://reject-user:reject-pass@203.0.113.95:0'],
  ['too large port','socks5://reject-user:reject-pass@203.0.113.95:65536'],
  ['malformed percent encoding','socks5://reject-user:reject%ZZpass@203.0.113.95:1080'],
  ['unexpected query','socks5://reject-user:reject-pass@203.0.113.95:1080?password=reject-pass'],
  ['unexpected path','socks5://reject-user:reject-pass@203.0.113.95:1080/private'],
];
let browser;
const errors = [];
try {
  browser = await chromium.launch({channel:'msedge',headless:true});
  for (const width of widths) {
    const context = await browser.newContext({viewport:{width,height:width===390?844:1050}});
    let authenticated = false, mockState = fixture(), saved = null, requestCount = 0;
    await context.route('**/*',async route => {
      const request = route.request(), url = new URL(request.url());
      if (url.origin !== origin) {errors.push('Unexpected external request '+url.origin);return route.abort();}
      if (!url.pathname.startsWith('/api/')) return route.continue();
      requestCount++;
      const resource = url.pathname.slice(5);
      const respond = body => route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(body)});
      if (resource === 'session') return respond({authenticated,csrf:'synthetic-ui-csrf'});
      if (resource === 'login') {authenticated=true;return respond({csrf:'synthetic-ui-csrf'});}
      if (resource === 'logout') {authenticated=false;return respond({ok:true});}
      if (resource === 'state') return respond(mockState);
      if (resource === 'exits/save') {
        assert.equal(request.method(),'POST');
        saved = request.postDataJSON();
        const id = saved.id || 'saved-'+mockState.exits.length;
        const updated = {id,name:saved.name,address:saved.address,port:saved.port,
          authenticated:saved.auth==='credentials',active:false,pending:true,observed_ip:null,
          expected_ip:saved.expected_ip||null,tested_at:null};
        const index = mockState.exits.findIndex(exit=>exit.id===id);
        if (index < 0) mockState.exits.push(updated); else mockState.exits[index]=updated;
        mockState.client_config.exit_count = mockState.exits.length;
        mockState.dirty=true;
        return respond({id});
      }
      throw new Error('Unexpected mock endpoint '+resource);
    });
    const page = await context.newPage();
    page.on('pageerror',error=>errors.push(error.message));
    page.on('console',message=>{if(message.type()==='error')errors.push(message.text());});
    const viewportReport = {width,cases:[],invalid_cases:[],assets:{}};
    for (const file of ['index.html','app.js','style.css']) viewportReport.assets[file] = createHash('sha256').update(await fs.readFile(path.join(web,file))).digest('hex');
    async function openDialog() {
      await page.locator('#add-exit').click();
      await page.locator('#exit-dialog').waitFor({state:'visible'});
      assert.equal(await page.locator('#exit-socks-link').getAttribute('type'),'password','URI must mask credentials');
      assert.equal(await page.locator('#exit-socks-link').inputValue(),'','Opening a fresh dialog clears URI');
      assert.equal(await page.locator('#exit-user').inputValue(),'','Opening a fresh dialog clears username');
      assert.equal(await page.locator('#exit-password').inputValue(),'','Opening a fresh dialog clears password');
    }
    async function paste(uri) {
      await page.locator('#exit-socks-link').evaluate((field,text)=>{
        field.focus();
        const clipboard = new DataTransfer();clipboard.setData('text/plain',text);
        const proceed = field.dispatchEvent(new ClipboardEvent('paste',{bubbles:true,cancelable:true,clipboardData:clipboard}));
        if (proceed) {
          field.value = text;
          field.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertFromPaste',data:text}));
        }
      },uri);
    }
    async function fields() {
      return page.evaluate(()=>Object.fromEntries(['name','address','port','auth','user','password','expected']
        .map(name=>[name,document.querySelector('#exit-'+name).value])));
    }
    async function noLeak(...tokens) {
      const visible = await page.locator('body').innerText();
      for (const token of tokens.filter(Boolean)) assert.equal(visible.includes(token),false,'Credentials must not appear in visible status');
    }
    async function noOverflow() {
      const metrics = await page.locator('#exit-dialog').evaluate(dialog=>({
        document:document.documentElement.scrollWidth > innerWidth,
        dialog:dialog.scrollWidth > dialog.clientWidth+1,
        form:document.querySelector('#exit-form').scrollWidth > document.querySelector('#exit-form').clientWidth+1,
        left:dialog.getBoundingClientRect().left,right:dialog.getBoundingClientRect().right,width:innerWidth,
      }));
      assert.equal(metrics.document,false,width+' document overflow');
      assert.equal(metrics.dialog,false,width+' dialog overflow');
      assert.equal(metrics.form,false,width+' form overflow');
      assert(metrics.left>=0&&metrics.right<=metrics.width+1,width+' dialog stays in viewport');
    }
    async function closeDialog() {
      await page.locator('#cancel-dialog').click();
      await page.locator('#exit-dialog').waitFor({state:'hidden'});
      await page.waitForFunction(()=>['socks-link','user','password'].every(name=>document.querySelector('#exit-'+name).value===''));
    }
    await page.goto(origin,{waitUntil:'networkidle'});
    await page.locator('#login-password').fill('synthetic-ui-password');
    await page.getByRole('button',{name:/进入控制台/}).click();
    await page.locator('#console').waitFor({state:'visible'});
    for (const scenario of cases) {
      await openDialog();
      await paste(scenario.uri);
      await page.waitForFunction(expected=>document.querySelector('#exit-address').value===expected,scenario.address);
      const actual = await fields();
      assert.equal(actual.address,scenario.address);assert.equal(actual.port,scenario.port);
      assert.equal(actual.auth,scenario.auth);assert.equal(actual.user,scenario.username);assert.equal(actual.password,scenario.password);
      if (scenario.parsedName) assert.equal(actual.name,scenario.parsedName); else assert.match(actual.name,/SOCKS5/);
      assert.equal(await page.locator('#credential-fields').isVisible(),scenario.auth==='credentials');
      assert.equal(await page.locator('#allowlist-hint').isVisible(),scenario.auth==='none');
      assert((await page.locator('#socks-import-status').innerText()).trim(),'Successful import has accessible status');
      await noLeak(scenario.username,scenario.password,scenario.uri);
      await noOverflow();
      viewportReport.cases.push({name:scenario.name,passed:true});
      if (scenario===cases[0]) {
        const screenshot='import-'+width+'.png';
        await page.screenshot({path:path.join(output,screenshot),fullPage:true});report.screenshots.push(screenshot);
      }
      await closeDialog();
    }
    await openDialog();
    await page.locator('#exit-name').fill('我的自定义名称');
    await page.locator('#exit-expected').fill('203.0.113.200');
    await page.locator('#exit-socks-link').fill(cases[3].uri);
    await page.locator('#parse-socks-link').click();
    assert.equal((await fields()).name,'我的自定义名称','Import preserves a manually entered name');
    assert.equal((await fields()).expected,'','Import clears stale expected egress for the new proxy');
    assert.equal((await fields()).address,cases[3].address,'Fallback parse button fills endpoint');
    viewportReport.cases.push({name:'parse button, manual name preservation and stale expected IP clearing',passed:true});
    const before = await fields();
    for (const [name,uri] of invalidLinks) {
      await page.locator('#exit-socks-link').fill(uri);
      await page.locator('#parse-socks-link').click();
      assert.deepEqual(await fields(),before,name+' must preserve existing form');
      assert((await page.locator('#socks-import-status').innerText()).trim(),name+' shows a safe error');
      await noLeak('reject-user','reject-pass','reject%ZZpass',uri);
      viewportReport.invalid_cases.push({name,passed:true});
    }
    await closeDialog();

    await openDialog();
    await paste(cases[1].uri);
    await page.waitForFunction(expected=>document.querySelector('#exit-address').value===expected,cases[1].address);
    await page.locator('#save-exit').click();
    await page.locator('#exit-dialog').waitFor({state:'hidden'});
    assert(saved,'Save sent existing exits/save request');
    assert.equal(saved.address,cases[1].address);assert.equal(saved.port,Number(cases[1].port));
    assert.equal(saved.auth,cases[1].auth);assert.equal(saved.username,cases[1].username);assert.equal(saved.password,cases[1].password);
    assert.deepEqual(Object.keys(saved).sort(),['address','auth','expected_ip','name','password','port','username'].sort(),'Only existing API fields are submitted');
    await page.waitForFunction(()=>document.querySelector('#exit-socks-link').value==='');
    await noLeak(cases[1].username,cases[1].password,cases[1].uri);
    viewportReport.cases.push({name:'parsed credentials saved through existing API',passed:true});

    await openDialog();
    await page.locator('#exit-name').fill('手动添加');
    await page.locator('#exit-address').fill('203.0.113.96');
    await page.locator('#exit-port').fill('1234');
    await page.locator('#exit-user').fill('manual-synthetic-user');
    await page.locator('#exit-password').fill('manual-synthetic-pass');
    await page.locator('#save-exit').click();
    await page.locator('#exit-dialog').waitFor({state:'hidden'});
    assert.equal(saved.name,'手动添加');assert.equal(saved.address,'203.0.113.96');assert.equal(saved.port,1234);
    assert.equal(saved.username,'manual-synthetic-user');assert.equal(saved.password,'manual-synthetic-pass');
    await noLeak('manual-synthetic-user','manual-synthetic-pass');
    viewportReport.cases.push({name:'manual entry still saves',passed:true});
    await page.locator('.exit-card[data-id="existing-exit"] [data-action="edit"]').click();
    await page.locator('#exit-dialog').waitFor({state:'visible'});
    assert.equal(await page.locator('#exit-name').inputValue(),'已保存出口');
    assert.equal(await page.locator('#exit-socks-link').inputValue(),'');
    assert.equal(await page.locator('#exit-user').inputValue(),'');
    assert.equal(await page.locator('#exit-password').inputValue(),'');
    await closeDialog();
    viewportReport.cases.push({name:'edit retains safe blank credentials',passed:true});
    viewportReport.no_overflow=true;viewportReport.sensitive_fields_clear_on_close=true;viewportReport.request_count=requestCount;
    report.viewports.push(viewportReport);
    await page.locator(width<=700?'#logout-mobile':'#logout').click();
    await page.locator('#login-screen').waitFor({state:'visible'});
    await context.close();
  }
  assert.deepEqual(errors,[]);
  report.checks.push('IPv4 credentials, percent decoding, no authentication, optional fragment names and trailing slash parse correctly',
    'Paste and explicit parse button work; manual names remain intact and stale expected IP clears',
    'Invalid links preserve every prior field and show errors without leaking credentials',
    'Existing save API and manual entry work; opening, closing and saving clear sensitive fields',
    'Desktop and mobile dialogs stay inside viewport without horizontal overflow',
    'No browser exceptions or external network requests');
  report.success=true;
} catch (error) {
  report.error=String(error.stack||error);
} finally {
  if (browser) await browser.close();
  await new Promise(resolve=>server.close(resolve));
  await fs.writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2));
}
console.log(JSON.stringify({success:report.success,report:path.join(output,'report.json'),screenshots:report.screenshots.length,error:report.error||null}));
if (!report.success) process.exitCode=1;
