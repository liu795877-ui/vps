import {chromium} from '../../panel/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';

const folder=path.dirname(fileURLToPath(import.meta.url));
const release=process.argv[2];
assert.match(release||'',/^console-optimization-release-\d{8}-[A-Za-z0-9_-]+$/);
const manifest=JSON.parse(await fs.readFile(path.join(folder,release,'manifest.json'),'utf8'));
const site='https://198-200-49-63.sslip.io:8443/node-console/';
const output=path.join(folder,'member-nickname-live-ui-20261023');
await fs.mkdir(output,{recursive:true});
const report={success:false,release,checked_at:new Date().toISOString(),checks:[],errors:[],configuration_mutations:0,real_nicknames_changed:false,private_values_included:false};
const check=name=>report.checks.push(name);
let browser;
try{
  assert.ok(process.env.NODE_CONSOLE_TEST_PROXY);
  browser=await chromium.launch({channel:'msedge',headless:true,proxy:{server:process.env.NODE_CONSOLE_TEST_PROXY}});
  for(const [index,filename] of ['panel-login.private.json','multiuser-user-a-login.private.json','multiuser-user-b-login.private.json'].entries()){
    const login=JSON.parse(await fs.readFile(path.join(folder,filename),'utf8'));
    assert.equal(login.url,site);
    const context=await browser.newContext({viewport:{width:index?390:1440,height:index?844:1000}});
    const page=await context.newPage();let allowedNickname=null;
    page.on('pageerror',error=>report.errors.push(error.name));
    await context.route('**/*',async route=>{
      const request=route.request(),url=new URL(request.url());
      if(url.origin!==new URL(site).origin)return route.abort();
      if(request.method()!=='GET'&&!['/node-console/api/login','/node-console/api/logout'].includes(url.pathname)){
        const body=request.postDataJSON();
        if(url.pathname!=='/node-console/api/users/nickname'||!allowedNickname||body.id!==allowedNickname.id||body.display_name!==allowedNickname.display_name||Object.keys(body).length!==2){
          report.configuration_mutations++;return route.abort();
        }
      }
      return route.continue();
    });
    await page.goto(site,{waitUntil:'networkidle',timeout:60000});
    const anonymous=await context.request.post(new URL('api/users/nickname',site).href,{headers:{Origin:new URL(site).origin},data:{id:'admin',display_name:'管理员'}});
    assert.equal(anonymous.status(),401);
    await page.locator('#login-user').fill(login.username);await page.locator('#login-password').fill(login.password);
    await page.locator('#login-submit').click();login.password='';
    await page.locator('#console').waitFor({state:'visible',timeout:45000});
    if(!index){
      for(const name of ['index.html','app.js','style.css','access-records.css']){
        const response=await context.request.get(new URL(name==='index.html'?'./':name,site).href);
        assert.equal(response.status(),200);
        assert.equal(createHash('sha256').update(await response.body()).digest('hex'),manifest.release_sha256['panel/web/'+name]);
      }
      check('four public assets match the frozen nickname release');
      await page.locator('#users-nav').click();
      const before=await page.evaluate(async()=>(await(await fetch('./api/users')).json()).users);
      const members=before.filter(user=>user.role==='member');
      report.registered_members=members.length;
      await page.waitForFunction(count=>document.querySelectorAll('#user-list .user-card').length===count,before.length);
      assert.equal(await page.locator('[data-user-action=nickname]:visible').count(),members.length);
      check('administrator can open nickname editor for all registered members');
      const target=members.find(user=>user.enabled)||members[0];
      assert.ok(target);
      const card=page.locator('.user-card[data-user-id="'+target.id+'"]');
      await card.locator('[data-user-action=nickname]').click();
      assert.equal(await page.locator('#nickname-value').inputValue(),target.display_name);
      assert.equal(await page.locator('#nickname-username').inputValue(),target.username);
      assert.equal(await page.locator('#nickname-username').evaluate(element=>element.readOnly),true);
      await page.locator('#cancel-user-nickname').click();
      check('editor prefills the current nickname and keeps the login account read-only');
      await page.setViewportSize({width:390,height:844});
      await card.locator('[data-user-action=nickname]').click();
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
      const box=await page.locator('#user-nickname-dialog').boundingBox();
      assert.ok(box.x>=0&&box.width<=390);
      check('nickname dialog fits a mobile viewport');
      allowedNickname={id:target.id,display_name:target.display_name};
      const saved=page.waitForResponse(response=>response.url().endsWith('/api/users/nickname')&&response.request().method()==='POST');
      await page.locator('#save-user-nickname').click();
      assert.equal((await saved).status(),200);
      await page.locator('#user-nickname-dialog').waitFor({state:'hidden'});
      allowedNickname=null;
      const after=await page.evaluate(async()=>(await(await fetch('./api/users')).json()).users);
      const stable=users=>users.map(({id,username,display_name,enabled,port})=>({id,username,display_name,enabled,port}));
      assert.deepEqual(stable(after),stable(before));
      check('same-value save succeeds while preserving every real nickname and account state');
      await page.locator('#visits-nav').click();
      await page.waitForFunction(()=>document.querySelector('#visits-member option[value]')&&document.querySelector('#visits-member').options.length>1);
      const access=await page.evaluate(async()=>(await(await fetch('./api/access-records?hours=168')).json()));
      for(const record of access.records){
        const current=before.find(user=>user.id===record.member_id);
        if(current)assert.equal(record.display_name,current.display_name);
      }
      check('existing visit records resolve member names from the current account registry');
    }else{
      assert.equal(await page.locator('#users-nav').isVisible(),false);
      const session=await page.evaluate(async()=>(await(await fetch('./api/session')).json()));
      const denied=await context.request.post(new URL('api/users/nickname',site).href,{headers:{Origin:new URL(site).origin,'X-CSRF-Token':session.csrf},data:{id:session.user.id,display_name:session.user.display_name}});
      assert.equal(denied.status(),403);
      check('member '+index+' cannot rename accounts');
    }
    await page.locator('#logout-mobile').click();await page.locator('#login-screen').waitFor({state:'visible'});
    assert.equal(await page.locator('#nickname-value').inputValue(),'');
    await context.close();
  }
  check('anonymous users are rejected and logout clears nickname fields');
  assert.deepEqual(report.errors,[]);assert.equal(report.configuration_mutations,0);
  report.success=true;
}catch(error){report.failure_type=error.name;}
finally{
  await browser?.close();
  await fs.writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2));
  process.stdout.write(JSON.stringify({success:report.success,checks:report.checks.length,report:path.join(output,'report.json')})+'\n');
}
process.exitCode=report.success?0:1;
