// The real FAST frontend in a fresh Edge context. No production/client changes.
import {chromium} from '../../panel/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const folder=path.dirname(fileURLToPath(import.meta.url));
const options=Object.fromEntries(process.argv.slice(2).reduce((rows,item,index,list)=>{
  if(item.startsWith('--'))rows.push([item.slice(2),list[index+1]?.startsWith('--')?true:list[index+1]??true]);
  return rows;
},[]));
const mode=options.mode,label=options.label??mode;
const maximumMiB=Number(options['max-mib']??256);
if(!['http-proxy','tun'].includes(mode)||!/^[a-z0-9][a-z0-9-]{0,63}$/.test(label??'')||![256,1024].includes(maximumMiB)){
  process.stdout.write(JSON.stringify({success:false,failure_category:'use --mode http-proxy|tun --label simple-lowercase-label'})+'\n');
  process.exit(2);
}
const output=path.join(folder,`fast-browser-${label}.json`);
const screenshot=path.join(folder,`fast-browser-${label}.png`);
try{await fs.access(output);throw new Error('existing-report');}catch(error){
  if(error.message==='existing-report'){process.stdout.write(JSON.stringify({success:false,failure_category:'report-already-exists'})+'\n');process.exit(2);}
}
const cap=maximumMiB*1024*1024,stopAt=(maximumMiB-16)*1024*1024,seconds=120;
const report={success:false,mode,label,started_at:new Date().toISOString(),browser:'msedge',headless:true,
  fresh_browser_context:true,personal_profile_used:false,configuration_changes:0,fast_settings_changes:0,
  signed_urls_saved:false,tokens_saved:false,requested_url:'https://fast.com/',
  network_mode:mode==='http-proxy'?'explicit HTTP proxy 127.0.0.1:7890':'browser proxy disabled; current OS/TUN route, verified separately',
  method:{official_frontend_unmodified:true,maximum_seconds:seconds,maximum_bytes:cap,
    early_stop_bytes:stopAt,byte_accounting:'Per-request maximum of CDP decoded chunks, encoded chunks and loadingFinished length.',
    byte_limit_scope:'Soft limit: context closes at early stop; parallel in-flight bytes may arrive before closure.',
    cache_disabled_for_fresh_measurement:true},samples:[],targets:[],cleanup_errors:[]};
const requests=new Map(),hosts=new Map();
let browser,context,page,session,closing=false,total=0,stopReason=null,started=Date.now(),timer;
function host(raw){try{const value=new URL(raw).hostname;return /^[a-zA-Z0-9.-]{1,253}$/.test(value)?value:null;}catch{return null;}}
function aggregate(item){
  if(!item.host)return;
  if(!hosts.has(item.host))hosts.set(item.host,{hostname:item.host,requests:0,finished:0,failed:0,
    bytes_observed:0,statuses:{},protocols:{}});
  return hosts.get(item.host);
}
function bytes(item){
  const next=Math.max(item.decoded??0,item.encoded??0,item.finishedLength??0),delta=next-(item.counted??0);
  if(delta>0){item.counted=next;total+=delta;const row=aggregate(item);if(row)row.bytes_observed+=delta;}
  if(total>=stopAt)void close('byte-cap');
}
async function close(reason){
  if(closing)return;closing=true;stopReason=reason;
  clearTimeout(timer);
  try{await context?.close();}catch{report.cleanup_errors.push('context-close');}
}
async function ui(){
  return page.evaluate(()=>{
    const visible=element=>!!element&&getComputedStyle(element).display!=='none'&&getComputedStyle(element).visibility!=='hidden'&&element.getClientRects().length>0;
    const speed=document.querySelector('#speed-value'),units=document.querySelector('#speed-units');
    const pause=document.querySelector('#pause-button'),refresh=document.querySelector('#refresh-button');
    const progress=document.querySelector('#speed-progress-indicator');
    const value=(speed?.textContent??'').trim().replace(/\s+/g,'');
    const unit=(units?.textContent??'').trim();
    const safeNumber=/^[0-9]+(?:[.,][0-9]+)?$/.test(value)?value:null;
    const safeUnit=/^(?:[KMGT]?bps|[KMGT]?bit\/s)$/i.test(unit)?unit:null;
    const speedClass=(speed?.className??'').split(/\s+/).filter(v=>/^[a-zA-Z0-9_-]{1,40}$/.test(v));
    const completed=!!speed?.classList.contains('succeeded')||
      (!!safeNumber&&visible(refresh)&&!visible(pause)&&!visible(progress));
    const settings={};
    for(const id of ['min-connections','max-connections','min-duration','max-duration','measure-loaded-latency','always-show-metrics','save-settings']){
      const element=document.getElementById(id);
      if(element){const value=element.value??'';settings[id]=element.type==='checkbox'?element.checked:/^[0-9.]{1,8}$/.test(value)?value:null;}
    }
    return {speed:safeNumber,units:safeUnit,speed_classes:speedClass,
      completion_evidence:{succeeded_class:!!speed?.classList.contains('succeeded'),refresh_visible:visible(refresh),pause_visible:visible(pause),progress_visible:visible(progress)},
      completed,official_settings:settings};
  });
}
try{
  const launch={channel:'msedge',headless:true,timeout:30000};
  if(mode==='http-proxy')launch.proxy={server:'http://127.0.0.1:7890'};
  else launch.args=['--no-proxy-server'];
  browser=await chromium.launch(launch);
  context=await browser.newContext({viewport:{width:1280,height:900},ignoreHTTPSErrors:false});
  page=await context.newPage();session=await context.newCDPSession(page);
  await session.send('Network.enable');await session.send('Network.setCacheDisabled',{cacheDisabled:true});
  session.on('Network.requestWillBeSent',event=>{
    const hostname=host(event.request.url);
    if(!hostname)return;
    if(requests.size>=2000){void close('request-accounting-cap');return;}
    // Raw URL is consumed immediately and never retained, logged or saved.
    const item={host:hostname};requests.set(event.requestId,item);aggregate(item).requests++;
  });
  session.on('Network.responseReceived',event=>{
    const item=requests.get(event.requestId);if(!item)return;
    const row=aggregate(item),status=String(event.response.status);
    if(/^[0-9]{3}$/.test(status))row.statuses[status]=(row.statuses[status]??0)+1;
    const protocol=event.response.protocol;
    if(/^[a-zA-Z0-9/. -]{1,24}$/.test(protocol??''))row.protocols[protocol]=(row.protocols[protocol]??0)+1;
  });
  session.on('Network.dataReceived',event=>{
    const item=requests.get(event.requestId);if(!item)return;
    item.decoded=(item.decoded??0)+event.dataLength;item.encoded=(item.encoded??0)+event.encodedDataLength;bytes(item);
  });
  session.on('Network.loadingFinished',event=>{
    const item=requests.get(event.requestId);if(!item)return;
    item.finishedLength=event.encodedDataLength;aggregate(item).finished++;bytes(item);
  });
  session.on('Network.loadingFailed',event=>{const item=requests.get(event.requestId);if(item)aggregate(item).failed++;});
  started=Date.now();timer=setTimeout(()=>void close('time-cap'),seconds*1000);
  await page.goto('https://fast.com/',{waitUntil:'domcontentloaded',timeout:35000});
  while(!closing){
    const state=await ui();
    if(report.samples.length<240)report.samples.push({...state,elapsed_seconds:Number(((Date.now()-started)/1000).toFixed(3))});
    report.visible_result=state;report.official_settings=state.official_settings;
    if(state.completed){
      report.official_download_completed=true;
      await page.screenshot({path:screenshot,fullPage:false,timeout:4000});report.screenshot=screenshot;
      await close('official-download-complete');break;
    }
    await new Promise(resolve=>setTimeout(resolve,500));
  }
}catch(error){
  report.failure_category=closing?'bounded-stop':'browser-or-page-failure';
  report.error_type=error?.name??'Error';
}finally{
  await close(stopReason??'failure');
  try{await browser?.close();report.browser_closed=true;}catch{report.browser_closed=false;report.cleanup_errors.push('browser-close');}
  report.stop_reason=stopReason;report.elapsed_seconds=Number(((Date.now()-started)/1000).toFixed(3));
  report.total_observed_bytes=total;report.byte_cap_exceeded=total>cap;
  report.targets=[...hosts.values()].filter(row=>row.hostname.endsWith('.nflxvideo.net'));
  report.frontend_transfers=[...hosts.values()].filter(row=>['fast.com','api.fast.com'].includes(row.hostname));
  report.observed_protocol_scope='Browser-to-origin HTTP protocol; this does not identify HY2 versus REALITY transport.';
  report.partial=!report.official_download_completed;
  report.success=!!report.official_download_completed&&!!report.visible_result?.speed&&!!report.visible_result?.units&&report.browser_closed&&!report.byte_cap_exceeded;
  report.finished_at=new Date().toISOString();report.report=output;
  await fs.writeFile(output,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
  process.stdout.write(JSON.stringify({success:report.success,partial:report.partial,mode,label,report:output,
    stop_reason:report.stop_reason,total_observed_bytes:total,visible_result:report.visible_result??null})+'\n');
}
process.exitCode=report.success?0:1;
