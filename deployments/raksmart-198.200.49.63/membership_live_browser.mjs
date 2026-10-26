import {chromium} from '../../panel/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';

const folder = path.dirname(fileURLToPath(import.meta.url));
const release = process.argv[2];
if (!/^console-optimization-release-\d{8}-[A-Za-z0-9_-]+$/.test(release || '')) throw new Error('Unexpected release name');
const manifest = JSON.parse(await fs.readFile(path.join(folder,release,'manifest.json'),'utf8'));
const output = path.join(folder,'membership-live-ui-20261018');
await fs.mkdir(output,{recursive:true});
const site = 'https://198-200-49-63.sslip.io:8443/node-console/';
const report = {success:false,checked_at:new Date().toISOString(),release,checks:[],errors:[],configuration_mutations:0,private_values_included:false};
let browser;
try {
  assert.ok(process.env.NODE_CONSOLE_TEST_PROXY);
  browser = await chromium.launch({channel:'msedge',headless:true,proxy:{server:process.env.NODE_CONSOLE_TEST_PROXY}});
  for (const [index,name] of ['panel-login.private.json','multiuser-user-a-login.private.json','multiuser-user-b-login.private.json'].entries()) {
    const login = JSON.parse(await fs.readFile(path.join(folder,name),'utf8'));
    assert.equal(login.url,site);
    const context = await browser.newContext({viewport:{width:index ? 390 : 1440,height:index ? 844 : 1000}});
    const page = await context.newPage();
    page.on('pageerror',error => report.errors.push(error.name));
    await context.route('**/*',async route => {
      const request = route.request(),url = new URL(request.url());
      if (url.origin !== new URL(site).origin) return route.abort();
      if (request.method() !== 'GET' && !['/node-console/api/login','/node-console/api/logout'].includes(url.pathname)) {
        report.configuration_mutations++;return route.abort();
      }
      return route.continue();
    });
    await page.goto(site,{waitUntil:'networkidle',timeout:60000});
    await page.locator('#login-user').fill(login.username);
    await page.locator('#login-password').fill(login.password);
    await page.locator('#login-submit').click();
    login.password = '';
    await page.waitForFunction(() => !document.querySelector('#console').hidden && document.querySelector('#metric-server').textContent !== '—',null,{timeout:45000});
    const user = await page.evaluate(async () => (await (await fetch('./api/session')).json()).user);
    assert.ok(user.enabled);assert.equal(user.membership.expired,false);
    if (!index) {
      for (const name of ['app.js','index.html','style.css']) {
        const response = await page.request.get(new URL(name === 'index.html' ? './' : name,site).href);
        assert.equal(response.status(),200);
        assert.equal(createHash('sha256').update(await response.body()).digest('hex'),manifest.release_sha256['panel/web/'+name]);
      }
      await page.locator('#users-nav').click();
      await page.waitForFunction(() => document.querySelectorAll('.user-card').length >= 1);
      const accounts = await page.evaluate(async () => (await (await fetch('./api/users')).json()).users);
      assert.equal(await page.locator('.user-card').count(),accounts.length);
      assert.ok(accounts.every(value => value.enabled && value.membership.status === (value.role === 'admin' ? 'admin' : 'unlimited')));
      report.account_count = accounts.length;report.member_count = accounts.filter(value => value.role !== 'admin').length;
      const member = page.locator('.user-card').filter({has:page.locator('[data-user-action=membership]:visible')}).first();
      await member.locator('[data-user-action=membership]').click();
      assert.equal(await page.locator('#membership-unlimited').isChecked(),true);
      assert.equal(await page.locator('#membership-expires').isDisabled(),true);
      await page.locator('#cancel-membership').click();
      report.checks.push('administrator reads all live terms and opens subscription editor without saving');
    } else {
      await page.locator('#membership-card').waitFor({state:'visible'});
      assert.match(await page.locator('#membership-status').textContent(),/长期有效/);
      assert.equal(await page.locator('#users-nav').isVisible(),false);
      await page.locator('#renewal-details > summary').click();
      assert.equal(await page.locator('#request-renewal').isEnabled(),true);
      report.checks.push('existing member '+index+' retains access and can open renewal form on mobile');
    }
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth<=innerWidth),true);
    await page.screenshot({path:path.join(output,index ? 'member-'+index+'-mobile.png' : 'admin-members.png'),fullPage:true,mask:[page.locator('input[type=password]'),page.locator('#subscription-url'),page.locator('.exit-endpoint,.exit-observed,.route-ip')]});
    await page.locator(index ? '#logout-mobile' : '#logout').click();
    await page.locator('#login-screen').waitFor({state:'visible'});
    await context.close();
  }
  assert.deepEqual(report.errors,[]);assert.equal(report.configuration_mutations,0);
  report.success = true;
} catch (error) {report.failure_type = error.name;}
finally {
  await browser?.close();
  await fs.writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2));
  process.stdout.write(JSON.stringify({success:report.success,checks:report.checks.length,account_count:report.account_count,report:path.join(output,'report.json')})+'\n');
}
process.exitCode = report.success ? 0 : 1;
