"""Verify real web clicks against one unchanged, previously downloaded AUTO client.

This performs the two authorized exit switches and restores the original exit.
It never downloads a replacement profile, deploys code, edits upstream accounts,
or opens/modifies the active FlClash configuration. Diagnostics and the isolated
Mihomo client are private; the public report contains IPs and check conclusions.
"""

from datetime import datetime, timedelta, timezone
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import select
import socket
import socketserver
import subprocess
import threading
import time
import traceback
from urllib.request import ProxyHandler, build_opener

import yaml

from verify_unified_profile import (
    BINARY, CURL, controller_api, free_port, panel_request, panel_transport,
)


FOLDER = Path(__file__).resolve().parent
OLD_PROFILE = FOLDER / "clash-unified-exits.private.yaml"
VALIDATION = FOLDER / "web-switch-validation"
REPORT = FOLDER / "web-switch-verification.json"
HOST = "198-200-49-158.sslip.io"
IP = "198.200.49.158"
ORIGIN = "https://" + HOST + ":8443"
AUTO_NAME = "AUTO · 网页切换"
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


BROWSER_SCRIPT = r'''
import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import net from 'node:net';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import path from 'node:path';

const settings=JSON.parse(process.env.NODE_CONSOLE_SWITCH_TEST);
const {chromium}=await import(pathToFileURL(settings.playwright).href);
const login=JSON.parse(await fs.readFile(settings.login,'utf8'));
const expectedOrigin='https://198-200-49-158.sslip.io:8443';
assert.equal(new URL(login.url).origin,expectedOrigin);
assert.equal(new URL(login.url).pathname,'/node-console/');
const initialHash=crypto.createHash('sha256').update(await fs.readFile(settings.old_profile)).digest('hex');
const emit=(value)=>process.stdout.write(JSON.stringify(value)+'\n');
const pause=(ms)=>new Promise(resolve=>setTimeout(resolve,ms));
const log=async (value)=>fs.appendFile(settings.browser_log,String(value)+'\n','utf8');
const report={success:false,counts:{},checks:{},ips:[],original_exit_restored:false};
let browser, page, originalId, configuration, initialState;
let switched=false;
const pageErrors=[];
const applyRequests=[];

function targetId(state) {
  return state.active_target==='server' ? 'server' : state.active?.id;
}
function signature(state) {
  return JSON.stringify({
    exits:state.exits.map(exit=>({id:exit.id,name:exit.name,address:exit.address,port:exit.port,
      authenticated:exit.authenticated,expected_ip:exit.expected_ip,pending:exit.pending})),
    domains:state.domains,routing_mode:state.routing_mode,
  });
}
async function get(resource) {
  return page.evaluate(async(resource)=> {
    for(let attempt=0;attempt<3;attempt++) {
      try {
        const response=await fetch('./api/'+resource,{credentials:'same-origin',
          signal:AbortSignal.timeout(15000)});
        if(response.ok) return await response.json();
        if(response.status===401) throw new Error('Authenticated session expired');
      } catch(error) {if(attempt===2) throw error;}
      await new Promise(resolve=>setTimeout(resolve,400));
    }
    throw new Error('Authenticated GET failed after three attempts');
  },resource);
}
async function waitJob(identity,timeout=180000) {
  const deadline=Date.now()+timeout;
  while(Date.now()<deadline) {
    const job=await get('jobs/'+encodeURIComponent(identity));
    if(job.status==='failed') throw new Error('Switch job failed: '+job.message);
    if(job.status==='success') return job;
    assert.equal(job.status,'running');
    await pause(600);
  }
  throw new Error('Switch job exceeded its bounded wait');
}
async function waitIdle(timeout=180000) {
  const deadline=Date.now()+timeout;
  while(Date.now()<deadline) {
    const state=await get('state');
    if(state.job?.status!=='running') return state;
    await pause(700);
  }
  throw new Error('Existing switch did not finish before restoration');
}
function selector(id) {
  assert(/^[a-f0-9-]+$/i.test(id)||id==='server');
  return id==='server' ? '#path-server-button' :
    'button.path-route[data-exit-id="'+id+'"]';
}
async function assertApplied(id) {
  const state=await get('state');
  assert.equal(targetId(state),id);
  assert.equal(state.service_active,true);
  assert.equal(signature(state),configuration,'Upstream draft or routing settings changed during verification');
  await page.waitForFunction(({id,query})=> {
    const button=document.querySelector(query);
    return button?.classList.contains('is-current') && button.getAttribute('aria-pressed')==='true' &&
      document.querySelector('#network-card').dataset.target===(id==='server'?'server':'static');
  },{id,query:selector(id)},{timeout:35000});
  return state;
}
async function clickTarget(id) {
  const before=await waitIdle();
  assert.equal(signature(before),configuration,'Configuration changed before switch');
  const responsePromise=page.waitForResponse(response=> {
    if(!response.url().endsWith('/node-console/api/apply')||response.request().method()!=='POST') return false;
    try {return response.request().postDataJSON().id===id;} catch {return false;}
  },{timeout:35000});
  // Mark the operation before the click, so finally also restores a request
  // whose response was interrupted after the server had accepted it.
  switched=true;
  await page.locator(selector(id)).click({timeout:35000});
  const response=await responsePromise;
  assert.equal(response.status(),202);
  const accepted=await response.json();
  assert.equal(typeof accepted.job_id,'string');
  await waitJob(accepted.job_id);
  return assertApplied(id);
}
async function restoreByApi(id) {
  const accepted=await page.evaluate(async(id)=> {
    const sessionResponse=await fetch('./api/session',{credentials:'same-origin',signal:AbortSignal.timeout(15000)});
    if(!sessionResponse.ok) throw new Error('Recovery session GET failed');
    const session=await sessionResponse.json();
    if(!session.authenticated||!session.csrf) throw new Error('Recovery session is unavailable');
    const response=await fetch('./api/apply',{method:'POST',credentials:'same-origin',
      headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrf},body:JSON.stringify({id}),
      signal:AbortSignal.timeout(15000)});
    if(response.status!==202) throw new Error('Recovery switch was not accepted');
    return response.json();
  },id);
  await waitJob(accepted.job_id);
  const state=await get('state');
  assert.equal(targetId(state),id);
  assert.equal(state.service_active,true);
  return state;
}
function runCurl() {
  return new Promise(resolve=> {
    const process=spawn(settings.curl,['--proxy','socks5h://127.0.0.1:'+settings.proxy_port,
      '--noproxy','','--connect-timeout','8','--max-time','25','--fail','--silent','--show-error',
      'https://api.ipify.org'],{windowsHide:true,stdio:['ignore','pipe','pipe']});
    let output='',error='',finished=false;
    const timer=setTimeout(()=>process.kill(),30000);
    const done=(code)=> {
      if(finished) return;
      finished=true;clearTimeout(timer);
      resolve({code,output:output.trim(),error});
    };
    process.stdout.on('data',chunk=>output+=chunk.toString('utf8'));
    process.stderr.on('data',chunk=>error+=chunk.toString('utf8'));
    process.on('error',failure=>{error=String(failure);done(-1);});
    process.on('close',done);
  });
}
async function probe(kind,expected) {
  const attempts=[];
  for(let attempt=1;attempt<=3;attempt++) {
    const result=await runCurl();
    await log(JSON.stringify({kind,attempt,...result}));
    const observed=result.code===0&&net.isIP(result.output) ? result.output : null;
    const success=observed===expected;
    attempts.push({attempt,ip:observed,success});
    if(success) {
      const check={kind,ip:observed,expected_ip:expected,success:true,attempts};
      report.ips.push(check);
      emit({type:'probe',kind,ip:observed,success:true});
      return check;
    }
    if(attempt<3) await pause(800);
  }
  report.ips.push({kind,ip:attempts.at(-1).ip,expected_ip:expected,success:false,attempts});
  throw new Error('The unchanged AUTO client did not reach the expected '+kind+' IP');
}

try {
  browser=await chromium.launch({channel:'msedge',headless:true,
    proxy:{server:settings.console_proxy}});
  const context=await browser.newContext({viewport:{width:1440,height:1000},ignoreHTTPSErrors:false});
  page=await context.newPage();
  page.on('pageerror',error=>pageErrors.push(error.stack||String(error)));
  page.on('request',async request=> {
    if(request.url().endsWith('/node-console/api/apply')&&request.method()==='POST') {
      const headers=await request.allHeaders();
      applyRequests.push({csrf_present:Boolean(headers['x-csrf-token']),origin:headers.origin});
    }
  });
  for(let attempt=1;attempt<=3;attempt++) {
    try {
      const response=await page.goto(login.url,{waitUntil:'domcontentloaded',timeout:35000});
      assert.equal(response.status(),200);
      await page.locator('#login-user').waitFor({state:'visible',timeout:15000});
      break;
    } catch(error) {if(attempt===3) throw error;await log(error.stack||String(error));}
  }
  await page.locator('#login-user').fill(login.username);
  await page.locator('#login-password').fill(login.password);
  await page.getByRole('button',{name:/进入控制台/}).click();
  await page.locator('#console').waitFor({state:'visible',timeout:35000});
  const cookies=await context.cookies(expectedOrigin+'/node-console/');
  assert(cookies.some(cookie=>cookie.secure&&cookie.httpOnly&&cookie.sameSite==='Strict'&&
    cookie.path==='/node-console/'));
  initialState=await get('state');
  await fs.writeFile(path.join(settings.output,'initial-state.private.json'),JSON.stringify(initialState,null,2));
  assert.equal(initialState.demo,false);
  assert.equal(initialState.server_ip,'198.200.49.158');
  assert.equal(initialState.service_active,true);
  assert.equal(initialState.client_config?.auto_node,'AUTO · 网页切换');
  assert.equal(initialState.dirty,false,'Unapplied drafts must be resolved before switch verification');
  assert(initialState.job?.status!=='running','An operation is already running');
  assert(['server','static'].includes(initialState.active_target));
  originalId=targetId(initialState);
  assert(originalId,'Original applied exit is unavailable');
  configuration=signature(initialState);
  const candidates=initialState.exits.filter(exit=>!exit.pending&&net.isIP(exit.observed_ip));
  const target=candidates.find(exit=>exit.id===originalId)||candidates[0];
  assert(target,'No unchanged, verified static exit is available');
  if(originalId!=='server') assert(candidates.some(exit=>exit.id===originalId),
    'Original static exit must still exist as an unchanged draft for safe restoration');
  report.counts={configured_static_exits:initialState.exits.length,tested_static_exits:1,auto_clients:1};
  report.original_target=initialState.active_target;
  emit({type:'initial',original_id:originalId,original_target:initialState.active_target});
  report.checks.trusted_https_and_secure_login=true;
  report.checks.auto_client_uses_previous_download=true;

  emit({type:'stage',stage:'click_server'});
  await clickTarget('server');
  await probe('server','198.200.49.158');
  await page.screenshot({path:path.join(settings.output,'server-exit.private.png'),fullPage:true,animations:'disabled'});
  report.checks.server_button_applied=true;

  emit({type:'stage',stage:'click_static'});
  const staticState=await clickTarget(target.id);
  assert.equal(staticState.active.observed_ip,target.observed_ip);
  await probe('static',target.observed_ip);
  await page.screenshot({path:path.join(settings.output,'static-exit.private.png'),fullPage:true,animations:'disabled'});
  report.checks.static_card_applied=true;
  report.checks.both_clicks_used_csrf=applyRequests.length>=2&&applyRequests.every(request=>
    request.csrf_present&&request.origin===expectedOrigin);
  assert.equal(report.checks.both_clicks_used_csrf,true);
  assert.deepEqual(pageErrors,[]);
  report.checks.no_browser_errors=true;
  report.success=true;
} catch(error) {
  await log(error.stack||String(error));
  report.error='Web switch verification failed; inspect private diagnostics.';
} finally {
  if(page&&originalId&&switched) {
    emit({type:'stage',stage:'restore_original'});
    try {
      const state=await waitIdle();
      assert.equal(signature(state),configuration,'Concurrent settings change prevents safe automatic reapplication');
      if(targetId(state)!==originalId) {
        try {await clickTarget(originalId);}
        catch(error) {
          await log('Browser restore failed: '+(error.stack||String(error)));
          const current=await waitIdle();
          if(targetId(current)!==originalId) await restoreByApi(originalId);
        }
      }
      const restored=await get('state');
      assert.equal(targetId(restored),originalId);
      assert.equal(restored.service_active,true);
      report.original_exit_restored=true;
      const expected=originalId==='server' ? '198.200.49.158' : initialState.active.observed_ip;
      await probe('restored',expected);
    } catch(error) {
      await log('Restoration failed: '+(error.stack||String(error)));
      report.original_exit_restored=false;
      report.success=false;
      report.restore_error='Automatic restoration needs private diagnostic review.';
    }
  } else if(originalId) {
    report.original_exit_restored=true;
  }
  const finalHash=crypto.createHash('sha256').update(await fs.readFile(settings.old_profile)).digest('hex');
  report.checks.previous_profile_sha256_unchanged=finalHash===initialHash;
  if(finalHash!==initialHash) report.success=false;
  if(pageErrors.length) await log(JSON.stringify({page_errors:pageErrors}));
  if(page&&originalId) {
    try {
      const logout=(await page.locator('#logout').isVisible()) ? '#logout' : '#logout-mobile';
      await page.locator(logout).click({timeout:15000});
      await page.locator('#login-screen').waitFor({state:'visible',timeout:15000});
      report.checks.browser_logout=true;
    } catch(error) {await log('Logout: '+(error.stack||String(error)));}
  }
  if(browser) await browser.close();
  emit({type:'result',report});
}
'''


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def checksum(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def previous_auto():
    profile = yaml.safe_load(OLD_PROFILE.read_bytes())
    require(isinstance(profile, dict), "Previous client profile is not a YAML mapping")
    nodes = [node for node in profile.get("proxies", [])
             if isinstance(node, dict) and node.get("name") == AUTO_NAME]
    require(len(nodes) == 1, "Previous profile must contain exactly one AUTO node")
    node = nodes[0]
    require(node.get("type") == "vless" and node.get("server") == IP and node.get("port") == 443,
            "Previous AUTO node is not the expected REALITY entry")
    require(isinstance(node.get("uuid"), str) and node["uuid"], "Previous AUTO UUID is unavailable")
    require(node.get("tls") is True and node.get("skip-cert-verify", False) is False,
            "Previous AUTO node does not preserve TLS validation")
    require(not {"username", "password"}.intersection(node),
            "Unexpected upstream credentials in previous AUTO node")
    groups = [group for group in profile.get("proxy-groups", [])
              if isinstance(group, dict) and group.get("name") == "STATIC-SELECT"]
    require(len(groups) == 1 and AUTO_NAME in groups[0].get("proxies", []),
            "Previous profile does not offer the AUTO selection")
    return copy.deepcopy(node)


class ConsoleProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_console_proxy(wifi):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            upstream = None
            try:
                self.request.settimeout(12)
                header = b""
                while b"\r\n\r\n" not in header and len(header) < 8192:
                    chunk = self.request.recv(1024)
                    if not chunk:
                        return
                    header += chunk
                request = header.split(b"\r\n", 1)[0].decode("ascii").split()
                if len(request) != 3 or request[0] != "CONNECT" or request[1] not in (
                    HOST + ":8443", IP + ":8443",
                ):
                    self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    return
                upstream = socket.socket()
                upstream.settimeout(12)
                upstream.setsockopt(socket.IPPROTO_IP, 31, socket.htonl(wifi["InterfaceIndex"]))
                upstream.bind((wifi["IPAddress"], 0))
                upstream.connect((IP, 8443))
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                trailing = header.split(b"\r\n\r\n", 1)[1]
                if trailing:
                    upstream.sendall(trailing)
                self.request.settimeout(None)
                upstream.settimeout(None)
                while True:
                    ready, _, _ = select.select([self.request, upstream], [], [], 20)
                    if not ready:
                        return
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        destination = upstream if source is self.request else self.request
                        destination.sendall(data)
            except (OSError, UnicodeError, IndexError):
                pass
            finally:
                if upstream is not None:
                    upstream.close()

    server = ConsoleProxy(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def fallback_restore(original_id, log):
    """Restore even if the browser process exits before its own finally block."""
    panel = panel_transport()
    csrf = None
    try:
        login = json.loads((FOLDER / "panel-login.private.json").read_text(encoding="utf-8"))
        status, headers, body = panel.request("POST", "api/login", {
            "username": login["username"], "password": login["password"],
        })
        require(status == 200, "Recovery login failed")
        panel.cookie = headers["Set-Cookie"].split(";", 1)[0]
        csrf = json.loads(body)["csrf"]

        def current_state():
            status, _, body = panel_request(panel, "GET", "api/state")
            require(status == 200, "Recovery state GET failed")
            return json.loads(body)

        def current_target(state):
            return "server" if state.get("active_target") == "server" else (state.get("active") or {}).get("id")

        deadline = time.monotonic() + 180
        while True:
            state = current_state()
            if (state.get("job") or {}).get("status") != "running":
                break
            require(time.monotonic() < deadline, "Running switch did not settle for recovery")
            time.sleep(0.7)
        if current_target(state) == original_id and state.get("service_active"):
            return True
        require(not state.get("dirty"), "Concurrent draft change prevents safe recovery reapplication")
        if original_id != "server":
            require(any(item.get("id") == original_id and not item.get("pending")
                        for item in state.get("exits", [])), "Original static exit is unavailable for recovery")
        # Mutations are submitted once. A lost response is reconciled by GET,
        # avoiding automatic repetition of a possibly accepted apply request.
        try:
            status, _, body = panel.request("POST", "api/apply", {"id": original_id},
                                          headers={"X-CSRF-Token": csrf})
            require(status == 202, "Recovery apply was not accepted")
            identity = json.loads(body)["job_id"]
        except OSError:
            traceback.print_exc(file=log)
            reconciled = current_state()
            if current_target(reconciled) == original_id and reconciled.get("service_active"):
                return True
            job = reconciled.get("job") or {}
            require(job.get("status") == "running" and job.get("exit_id") == original_id,
                    "Recovery mutation outcome could not be reconciled")
            identity = job["id"]
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            status, _, body = panel_request(panel, "GET", "api/jobs/" + identity)
            require(status == 200, "Recovery job GET failed")
            job = json.loads(body)
            require(job["status"] != "failed", "Recovery job failed")
            if job["status"] == "success":
                state = current_state()
                return current_target(state) == original_id and state.get("service_active") is True
            time.sleep(0.7)
        raise RuntimeError("Recovery job exceeded its bounded wait")
    finally:
        if csrf:
            try:
                panel.request("POST", "api/logout", {}, headers={"X-CSRF-Token": csrf})
            except Exception:
                traceback.print_exc(file=log)
        panel.cookie = None


def main():
    VALIDATION.mkdir(exist_ok=True)
    run_folder = VALIDATION / ("run-" + secrets.token_hex(6))
    run_folder.mkdir()
    report = {
        "checked_at": datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds"),
        "success": False, "counts": {}, "checks": {}, "ips": [],
        "original_exit_restored": False,
    }
    process = None
    browser_process = None
    console_proxy = None
    original_id = None
    old_hash = None
    auto_node = None
    client_config = None
    client_hash = None
    stage = "previous_auto_client"
    with (run_folder / "verification.private.log").open("w", encoding="utf-8") as log:
        try:
            require(OLD_PROFILE.is_file(), "Previously downloaded client file was not found")
            old_hash = checksum(OLD_PROFILE)
            auto_node = previous_auto()
            require(BINARY.is_file(), "Official local Mihomo binary was not found")
            stage = "physical_wlan"
            discovery = subprocess.run([
                "powershell.exe", "-NoProfile", "-Command",
                "Get-NetIPAddress -InterfaceAlias WLAN -AddressFamily IPv4 | "
                "Where-Object AddressState -eq Preferred | "
                "Select-Object -First 1 IPAddress,InterfaceIndex | ConvertTo-Json -Compress",
            ], capture_output=True, check=True, timeout=15, stdin=subprocess.DEVNULL,
                creationflags=NO_WINDOW)
            wifi = json.loads(discovery.stdout.decode("utf-8-sig"))
            require(wifi.get("InterfaceIndex") and wifi.get("IPAddress"), "Physical WLAN is unavailable")
            proxy_port, control_port = free_port(), free_port()
            while proxy_port == control_port:
                control_port = free_port()
            secret = secrets.token_urlsafe(24)
            temporary = {
                "mixed-port": proxy_port, "bind-address": "127.0.0.1", "allow-lan": False,
                "external-controller": "127.0.0.1:" + str(control_port), "secret": secret,
                "mode": "rule", "interface-name": "WLAN", "tun": {"enable": False},
                "dns": {"enable": False}, "log-level": "warning",
                "unified-delay": True, "tcp-concurrent": True,
                "profile": {"store-selected": False, "store-fake-ip": False},
                "proxies": [auto_node],
                "proxy-groups": [{"name": "STATIC-SELECT", "type": "select", "proxies": [AUTO_NAME]}],
                "rules": ["MATCH,STATIC-SELECT"],
            }
            client_dir = run_folder / "isolated-client"
            client_dir.mkdir()
            client_config = client_dir / "mihomo-old-auto.private.yaml"
            client_config.write_text(yaml.safe_dump(temporary, allow_unicode=True), encoding="utf-8")
            client_hash = checksum(client_config)
            stage = "isolated_client_start"
            check = subprocess.run([str(BINARY), "-t", "-d", str(client_dir), "-f", str(client_config)],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                   timeout=45, creationflags=NO_WINDOW)
            require(check.returncode == 0, "Isolated previous AUTO client failed syntax validation")
            log.flush()
            process = subprocess.Popen([str(BINARY), "-d", str(client_dir), "-f", str(client_config)],
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                       creationflags=NO_WINDOW)
            opener = build_opener(ProxyHandler({}))
            address = "http://127.0.0.1:" + str(control_port)
            for _ in range(50):
                require(process.poll() is None, "Isolated Mihomo exited before becoming ready")
                try:
                    controller_api(opener, address, secret, "/version")
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("Isolated Mihomo controller did not become ready")
            report["checks"]["isolated_client_has_only_original_auto_node"] = True
            report["checks"]["physical_wlan_and_active_flclash_untouched"] = True
            stage = "browser_switches"
            console_proxy = start_console_proxy(wifi)
            browser_script = run_folder / "web-switch.private.mjs"
            browser_script.write_text(BROWSER_SCRIPT, encoding="utf-8")
            environment = os.environ.copy()
            environment["NODE_CONSOLE_SWITCH_TEST"] = json.dumps({
                "playwright": str(FOLDER.parent.parent / "panel" / "node_modules" / "playwright" / "index.mjs"),
                "login": str(FOLDER / "panel-login.private.json"), "old_profile": str(OLD_PROFILE),
                "output": str(run_folder), "browser_log": str(run_folder / "browser.private.log"),
                "curl": CURL, "proxy_port": proxy_port,
                "console_proxy": "http://127.0.0.1:" + str(console_proxy.server_address[1]),
            })
            browser_process = subprocess.Popen(["node", str(browser_script)], env=environment,
                                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=log,
                                               text=True, encoding="utf-8", creationflags=NO_WINDOW)
            received = False
            for line in browser_process.stdout:
                log.write(line)
                log.flush()
                event = json.loads(line)
                if event.get("type") == "initial":
                    original_id = event["original_id"]
                    report["original_target"] = event["original_target"]
                elif event.get("type") in ("stage", "probe"):
                    print(json.dumps(event), flush=True)
                elif event.get("type") == "result":
                    received = True
                    browser_report = event["report"]
                    report["checks"].update(browser_report.pop("checks", {}))
                    report.update(browser_report)
            browser_process.wait(timeout=10)
            require(browser_process.returncode == 0 and received, "Browser verification did not return a complete result")
            for item in report["ips"]:
                for field in ("ip", "expected_ip"):
                    if item.get(field):
                        require(ipaddress.ip_address(item[field]).is_global, "Probe did not return a public IP")
            require(report["success"], "Browser verification or exit restoration failed")
            stage = "unchanged_client_evidence"
        except Exception:
            traceback.print_exc(file=log)
            report["success"] = False
            report["failed_stage"] = stage
            report["error"] = "Verification failed; inspect the private diagnostic log."
        finally:
            # The browser normally restores by clicking the original path.
            # Keep a trusted HTTPS/CSRF fallback if it stopped before cleanup.
            if original_id and not report.get("original_exit_restored"):
                try:
                    report["original_exit_restored"] = bool(fallback_restore(original_id, log))
                    report["checks"]["restored_by_https_fallback"] = report["original_exit_restored"]
                except Exception:
                    traceback.print_exc(file=log)
                    report["original_exit_restored"] = False
            if auto_node is not None and old_hash is not None:
                try:
                    report["checks"]["previous_profile_sha256_unchanged"] = checksum(OLD_PROFILE) == old_hash
                    report["checks"]["previous_auto_uuid_unchanged"] = previous_auto()["uuid"] == auto_node["uuid"]
                    isolated = yaml.safe_load(client_config.read_bytes()) if client_config else {}
                    report["checks"]["isolated_auto_uuid_matches_previous_download"] = (
                        (isolated.get("proxies") or [{}])[0].get("uuid") == auto_node["uuid"])
                    report["checks"]["isolated_client_file_sha256_unchanged"] = (
                        bool(client_config) and checksum(client_config) == client_hash)
                    if not all(report["checks"][name] for name in (
                        "previous_profile_sha256_unchanged", "previous_auto_uuid_unchanged",
                        "isolated_auto_uuid_matches_previous_download", "isolated_client_file_sha256_unchanged",
                    )):
                        report["success"] = False
                except Exception:
                    traceback.print_exc(file=log)
                    report["success"] = False
            if browser_process is not None and browser_process.poll() is None:
                browser_process.terminate()
                browser_process.wait(timeout=5)
            if console_proxy is not None:
                console_proxy.shutdown()
                console_proxy.server_close()
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
    REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False), flush=True)
    return 0 if report["success"] and report["original_exit_restored"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
