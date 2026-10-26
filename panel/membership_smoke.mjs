import {chromium} from 'playwright';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const output = path.join(root,'.validation','membership-ui-20261018');
await fs.mkdir(output,{recursive:true});
const fixture = spawn('python',['-B',path.join(root,'deployments/raksmart-198.200.49.63/serve_membership_demo.py')],{cwd:root,windowsHide:true,stdio:['ignore','pipe','pipe']});
const lines = createInterface({input:fixture.stdout});
const first = await Promise.race([new Promise((resolve,reject) => {lines.once('line',resolve);fixture.once('exit',() => reject(new Error('Fixture exited')));}),new Promise((_,reject) => setTimeout(() => reject(new Error('Fixture startup timeout')),15000))]);
const origin = JSON.parse(first).origin;
const report = {success:false,checks:[],errors:[],production_changed:false};
let browser;
function check(name) {report.checks.push(name);}
async function login(page,username,password) {
  await page.goto(origin,{waitUntil:'networkidle'});
  await page.locator('#login-user').fill(username);
  await page.locator('#login-password').fill(password);
  await page.locator('#login-form button[type=submit]').click();
  await page.locator('#console').waitFor({state:'visible'});
  await page.waitForFunction(() => document.querySelector('#metric-server').textContent !== '—');
}
async function api(page,resource,body) {
  return page.evaluate(async ({resource,body}) => {
    const session = await (await fetch('./api/session')).json();
    const options = body === undefined ? {} : {method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrf},body:JSON.stringify(body)};
    const response = await fetch('./api/'+resource,options);
    return {status:response.status,body:response.headers.get('content-type')?.includes('application/json') ? await response.json() : await response.text()};
  },{resource,body});
}
async function waitFor(condition) {
  const deadline = Date.now()+12000;
  while (Date.now()<deadline) {if (await condition()) return;await new Promise(resolve => setTimeout(resolve,150));}
  throw new Error('Condition did not become true');
}
try {
  browser = await chromium.launch({channel:'msedge',headless:true});
  const adminContext = await browser.newContext({viewport:{width:1440,height:1000},timezoneId:'America/Los_Angeles'});
  const memberContext = await browser.newContext({viewport:{width:390,height:844},timezoneId:'America/Los_Angeles'});
  const admin = await adminContext.newPage(),member = await memberContext.newPage();
  for (const page of [admin,member]) page.on('pageerror',error => report.errors.push(error.message));
  await login(admin,'admin','demo-password-2026');
  assert.equal(await admin.locator('#membership-card').isVisible(),false);
  await admin.locator('#users-nav').click();
  await admin.locator('#create-user-details > summary').click();
  await admin.locator('#create-username').fill('member_sub');
  await admin.locator('#create-display-name').fill('订阅测试成员');
  await admin.locator('#create-user-password').fill('membership-browser-2026');
  await admin.locator('#create-user-submit').click();
  const card = admin.locator('.user-card').filter({hasText:'member_sub'});
  await card.waitFor();
  let user = (await api(admin,'users')).body.users.find(value => value.username === 'member_sub');
  assert.equal(user.membership.expires_at-user.membership.updated_at,30*86400);
  check('new member receives 30 days without extra provisioning steps');
  const firstDeadline = user.membership.expires_at;
  await card.locator('[data-user-action=membership]').click();
  assert.equal(await admin.locator('#membership-expires').inputValue(),new Date(user.membership.expires_at*1000+8*3600000).toISOString().slice(0,19));
  await admin.locator('[data-extend-days="30"]').click();
  await admin.locator('#save-membership').click();
  await admin.locator('#membership-dialog').waitFor({state:'hidden'});
  user = (await api(admin,'users')).body.users.find(value => value.id === user.id);
  assert.equal(user.membership.expires_at,firstDeadline+30*86400);
  check('administrator extends from the existing deadline in Beijing time');
  await login(member,'member_sub','membership-browser-2026');
  assert.equal(await member.locator('#users-nav').isVisible(),false);
  assert.equal((await api(member,'users/membership',{id:user.id})).status,403);
  check('member cannot edit subscription terms or open administrator pages');
  const result = await api(admin,'users/membership',{id:user.id,revision:user.membership.revision,plan:'月度订阅',expires_at:Math.floor(Date.now()/1000)+2,note:'到期请申请续费'});
  assert.equal(result.status,200);
  await waitFor(async () => (await api(member,'state')).body.user.membership.expired);
  await member.locator('#refresh').click();
  await member.locator('#membership-status').filter({hasText:'订阅已到期'}).waitFor();
  assert.equal(await member.locator('#add-exit').isDisabled(),true);
  assert.equal(await member.locator('#network-card').getAttribute('inert'),'');
  assert.equal((await api(member,'profile')).status,403);
  check('scheduled expiry keeps the web session and disables proxy operations');
  await member.locator('#renewal-details > summary').click();
  await member.locator('#renewal-message').fill('请续费30天');
  await member.locator('#request-renewal').click();
  await member.locator('#renewal-details > summary').filter({hasText:'申请已提交'}).waitFor();
  assert.equal(await member.locator('#request-renewal').isDisabled(),true);
  assert.equal(await member.evaluate(() => document.documentElement.scrollWidth<=innerWidth),true);
  await member.screenshot({path:path.join(output,'member-expired-mobile.png'),fullPage:true});
  check('expired member submits one durable renewal request on mobile');
  await admin.locator('#refresh-users').click();
  await card.locator('.user-renewal-status').filter({hasText:'请续费30天'}).waitFor();
  await admin.locator('#show-renewals').click();
  assert.equal(await admin.locator('#member-status-filter').inputValue(),'renewal');
  assert.equal(await admin.locator('.user-card:visible').count(),1);
  await card.locator('[data-user-action=membership]').click();
  assert.match(await admin.locator('#membership-renewal-request').textContent(),/请续费30天/);
  await admin.locator('[data-extend-days="30"]').click();
  assert.equal(await admin.locator('#membership-resolve').isChecked(),true);
  await admin.setViewportSize({width:390,height:844});
  assert.equal(await admin.evaluate(() => document.documentElement.scrollWidth<=innerWidth),true);
  await admin.screenshot({path:path.join(output,'admin-renewal-mobile.png'),fullPage:true});
  await admin.locator('#save-membership').click();
  await admin.locator('#membership-dialog').waitFor({state:'hidden'});
  await member.locator('#refresh').click();
  await member.locator('#membership-status').filter({hasText:'订阅生效中'}).waitFor();
  assert.equal(await member.locator('#network-card').getAttribute('inert'),null);
  assert.equal((await api(member,'profile')).status,200);
  check('administrator resolves request and renewal restores original access');
  await member.locator('#logout-mobile').click();
  await member.locator('#login-screen').waitFor({state:'visible'});
  assert.equal(await member.locator('#renewal-message').inputValue(),'');
  check('logout clears renewal form and subscription state');
  assert.deepEqual(report.errors,[]);
  report.success = true;
} catch (error) {report.failure = error.message;throw error;}
finally {
  await browser?.close();fixture.kill();lines.close();
  await fs.writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2));
  process.stdout.write(JSON.stringify({success:report.success,checks:report.checks.length,report:path.join(output,'report.json')})+'\n');
}
