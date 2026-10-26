import {chromium} from '../../panel/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';

const folder = path.dirname(fileURLToPath(import.meta.url));
const release = process.argv[2];
assert.match(release || '',/^console-optimization-release-\d{8}-[A-Za-z0-9_-]+$/);
const manifest = JSON.parse(await fs.readFile(path.join(folder,release,'manifest.json'),'utf8'));
const site = 'https://198-200-49-63.sslip.io:8443/node-console/';
const output = path.join(folder,'member-access-live-ui-20261023');
await fs.mkdir(output,{recursive:true});
const report = {success:false,checked_at:new Date().toISOString(),release,checks:[],errors:[],configuration_mutations:0,private_values_included:false};
const check = name => report.checks.push(name);
let browser;
try {
  assert.ok(process.env.NODE_CONSOLE_TEST_PROXY);
  browser = await chromium.launch({channel:'msedge',headless:true,proxy:{server:process.env.NODE_CONSOLE_TEST_PROXY}});
  for (const [index,filename] of ['panel-login.private.json','multiuser-user-a-login.private.json','multiuser-user-b-login.private.json'].entries()) {
    const login = JSON.parse(await fs.readFile(path.join(folder,filename),'utf8'));
    assert.equal(login.url,site);
    const context = await browser.newContext({viewport:{width:index ? 390 : 1440,height:index ? 844 : 1000},timezoneId:'America/Los_Angeles'});
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
    assert.equal((await context.request.get(new URL('api/access-records',site).href)).status(),401);
    await page.locator('#login-user').fill(login.username);
    await page.locator('#login-password').fill(login.password);
    await page.locator('#login-submit').click();login.password='';
    await page.waitForFunction(() => !document.querySelector('#console').hidden,null,{timeout:45000});
    if (!index) {
      for (const name of ['index.html','app.js','style.css','access-records.css']) {
        const response = await context.request.get(new URL(name === 'index.html' ? './' : name,site).href);
        assert.equal(response.status(),200);
        assert.equal(createHash('sha256').update(await response.body()).digest('hex'),manifest.release_sha256['panel/web/'+name]);
      }
      check('all four public assets match the frozen release');
      await page.locator('#visits-nav').click();
      await page.locator('#visits-hours').selectOption('168');
      await page.waitForFunction(() => document.querySelector('#visits-rows tr') && !document.querySelector('#refresh-visits').disabled,null,{timeout:45000});
      const result = await page.evaluate(async () => (await (await fetch('./api/access-records?hours=168')).json()));
      assert.ok(result.summary.connections>0);
      assert.equal(result.status.error,null);
      assert.equal(result.status.retention_days,7);
      assert.equal(result.status.max_records,100000);
      assert.ok(result.records.every(row => row.member_id!=='admin'));
      assert.ok(result.members.every(member => member.id!=='admin' && member.role!=='admin'));
      assert.ok(result.records.every(row => !('source_ip' in row) && !('message' in row) && !('url' in row)));
      report.visible_connection_count=result.summary.connections;
      report.member_count=result.members.length;
      report.catching_up=result.status.catching_up;
      check('administrator can read real member metadata with owner excluded');
      const member = result.records[0].member_id;
      await page.locator('#visits-member').selectOption(member);
      await page.waitForFunction(() => !document.querySelector('#refresh-visits').disabled);
      const filtered = await page.evaluate(async id => (await (await fetch('./api/access-records?hours=168&member='+id)).json()),member);
      assert.ok(filtered.records.length>0 && filtered.records.every(row => row.member_id===member));
      check('member filter returns only the selected member');
      for (const protocol of ['hy2','reality']) {
        const data = await page.evaluate(async value => (await (await fetch('./api/access-records?hours=168&protocol='+value)).json()),protocol);
        assert.ok(data.records.every(row => row.protocol===protocol));
      }
      check('HY2 and REALITY filters preserve protocol attribution');
      await page.setViewportSize({width:390,height:844});
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth<=innerWidth),true);
      check('production access records page fits a mobile viewport');
    } else {
      assert.equal(await page.locator('#visits-nav').isVisible(),false);
      assert.equal((await context.request.get(new URL('api/access-records',site).href)).status(),403);
      assert.equal(await page.locator('#visits-rows tr').count(),0);
      check('member '+index+' cannot view the page or read the API');
    }
    await page.locator('#logout-mobile').click();
    await page.locator('#login-screen').waitFor({state:'visible'});
    assert.equal(await page.locator('#visits-rows tr').count(),0);
    assert.equal((await context.request.get(new URL('api/access-records',site).href)).status(),401);
    await context.close();
  }
  check('logout clears connection rows and revokes the session');
  assert.deepEqual(report.errors,[]);assert.equal(report.configuration_mutations,0);
  report.success=true;
} catch (error) {report.failure_type=error.name;}
finally {
  await browser?.close();
  await fs.writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2));
  process.stdout.write(JSON.stringify({success:report.success,checks:report.checks.length,report:path.join(output,'report.json')})+'\n');
}
process.exitCode=report.success ? 0 : 1;
