"use strict";

const $ = (selector) => document.querySelector(selector);
let csrf = null;
let state = null;
let busy = false;
let toastTimer;
let completedJob;
let selectedExitId = null;
let operationView = null;
let operationFailure = null;
let pathBooted = false;
let lastActiveId = null;
let pathChangeTimer;
let currentView = "overview";
const motionPreference = matchMedia("(prefers-reduced-motion: reduce)");
const dateFormat = new Intl.DateTimeFormat("zh-CN", {timeZone:"Asia/Shanghai", month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",hour12:false});

function endpoint(path) { return new URL("./api/" + path, location.href); }
function date(value) { return value ? dateFormat.format(new Date(value)) : "尚未检测"; }
function toast(message, error = false) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.toggle("error", error);
  element.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { element.hidden = true; }, 5000);
}

function showLogin() {
  csrf = null;
  state = null;
  selectedExitId = null;
  operationView = null;
  operationFailure = null;
  pathBooted = false;
  lastActiveId = null;
  clearTimeout(pathChangeTimer);
  $("#network-card").classList.remove("is-path-changing");
  $("#path-routes").replaceChildren();
  $("#exit-list").replaceChildren();
  $("#console").hidden = true;
  $("#login-screen").hidden = false;
  syncMotion();
}

async function api(path, body) {
  const options = {credentials:"same-origin",headers:{Accept:"application/json"}};
  if (body !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.headers["X-CSRF-Token"] = csrf || "";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(endpoint(path), options);
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401 && path !== "login") showLogin();
    throw new Error(data.error || "操作未完成，请稍后再试。");
  }
  return data;
}

function switchView(name) {
  const changed = currentView !== name;
  currentView = name;
  document.querySelectorAll(".view").forEach((element) => { element.hidden = element.id !== "view-" + name; });
  document.querySelectorAll(".nav-button").forEach((element) => element.classList.toggle("selected", element.dataset.view === name));
  $("#breadcrumb-title").textContent = {overview:"出口管理",routing:"网站分流",access:"客户端与访问"}[name];
  if (name === "routing" && state) {
    $("#domains").value = (state.domains || []).join("\n");
    $("#direct-domains").value = (state.direct_domains || []).join("\n");
    $("#routing-mode").value = state.routing_mode || "manual";
    renderRoutingMode();
  }
  syncMotion();
  if (changed) animateChange($("#view-" + name), [{opacity:0,transform:"translateY(8px)"},{opacity:1,transform:"translateY(0)"}], 250);
  window.scrollTo({top:0,behavior:motionPreference.matches ? "instant" : "smooth"});
}

function animateChange(element, frames, duration = 480) {
  if (element && typeof element.animate === "function" && !motionPreference.matches && !document.hidden && element.getClientRects().length) {
    element.animate(frames, {duration, easing:"cubic-bezier(.2,.8,.2,1)"});
  }
}

function syncMotion() {
  document.body.classList.toggle("motion-paused", document.hidden || !state || currentView !== "overview");
  document.body.classList.toggle("motion-background", document.hidden);
  if (motionPreference.matches) {
    clearTimeout(pathChangeTimer);
    $("#network-card").classList.remove("is-path-changing");
    for (const animation of document.getAnimations()) {
      if (!("animationName" in animation) && !("transitionProperty" in animation)) animation.cancel();
    }
  }
}
document.addEventListener("visibilitychange", syncMotion);
motionPreference.addEventListener("change", syncMotion);

function renderPath() {
  if (!state) return;
  const job = operationView || operationFailure || state.job;
  const running = job?.status === "running";
  const active = state.active;
  const activeTarget = state.active_target ?? (active ? "static" : null);
  const server = state.server_exit || {id:"server",name:"服务器自身出口",observed_ip:state.server_ip};
  const serverCurrent = activeTarget === "server";
  const activeId = serverCurrent ? "server" : active?.id || null;
  const routes = state.exits.map((exit) => ({...exit, current:activeTarget === "static" && exit.id === active?.id}));
  if (activeTarget === "static" && active && !routes.some((exit) => exit.id === active.id)) {
    routes.push({...active, current:true, removed:true});
  }
  if (selectedExitId !== "server" && !routes.some((exit) => exit.id === selectedExitId)) selectedExitId = activeId || "server";
  const selected = selectedExitId === "server" ? {...server,current:serverCurrent} : routes.find((exit) => exit.id === selectedExitId);
  const card = $("#network-card");
  card.dataset.target = activeTarget || "unconfigured";
  card.dataset.mode = !state.service_active ? "offline" : running ? job.kind : activeTarget ? "active" : "draft";
  card.dataset.phase = !state.service_active ? "offline" : running ? "working" : job?.status === "failed" ? "error" : activeTarget ? "ready" : "idle";
  card.setAttribute("aria-busy", String(running));
  const device = $("#path-device");
  device.dataset.phase = !state.service_active ? "offline" : running ? (job.kind === "test" ? "checking" : "applying") : activeTarget ? "active" : "draft";
  $("#path-device-status").textContent = !state.service_active ? "代理入口待检查" : running ? (job.kind === "test" ? "正在检测出口路径" : "正在准备新路径") : activeTarget ? "代理路径已应用" : "等待选择出口";
  const tag = $("#path-status");
  tag.textContent = !state.service_active ? "节点服务待检查" : running ? (
    {test:"正在检测出口",apply:"正在校验与切换",rollback:"正在恢复路径"}[job.kind]
  ) : job?.status === "failed" ? (activeTarget ? "操作未完成 · 原路径保留" : "操作未完成 · 可重试") : serverCurrent ? "当前使用服务器出口" : active ? "当前使用静态出口" : "点击选择网络出口";
  tag.classList.toggle("is-working", running);
  $("#client-connector").classList.toggle("is-flowing", !!activeTarget && state.service_active && !running);
  $("#exit-connector").hidden = activeTarget !== "static";
  $("#exit-connector").classList.toggle("is-flowing", state.service_active && activeTarget === "static" && !running);
  $("#exit-connector").classList.toggle("is-checking", running && job.exit_id !== "server");
  $("#path-exit-group").classList.toggle("is-detached", activeTarget !== "static");
  $("#path-exits-label").textContent = activeTarget === "static" ? "03 / EXITS" : "可切换的静态出口";
  const serverButton = $("#path-server-button");
  const serverApplying = running && job.kind === "apply" && job.exit_id === "server";
  const serverFailed = job?.status === "failed" && job.exit_id === "server";
  serverButton.disabled = busy;
  serverButton.classList.toggle("is-current", serverCurrent);
  serverButton.dataset.phase = serverApplying ? "applying" : serverFailed ? "error" : !state.service_active ? "offline" : serverCurrent ? "active" : "ready";
  serverButton.setAttribute("aria-pressed", String(serverCurrent));
  serverButton.setAttribute("aria-label", "切换到服务器自身出口");
  $("#path-server-badge").textContent = serverCurrent ? "当前出口" : serverApplying ? "切换中" : "点击切换";
  $("#path-server-exit").textContent = serverApplying ? "正在校验，等待切换…" : serverFailed ? "切换未完成 · 可重试" : serverCurrent ? "直接出网 · " + server.observed_ip : "点击使用 VPS 自身出口";
  $("#path-count").textContent = routes.length;
  $("#path-empty").hidden = routes.length > 0;
  const list = $("#path-routes");
  const oldHeight = list.getBoundingClientRect().height;
  for (const node of [...list.children]) {
    if (!routes.some((exit) => exit.id === node.dataset.exitId)) node.remove();
  }
  for (const exit of routes) {
    let node = [...list.children].find((item) => item.dataset.exitId === exit.id);
    if (!node) {
      node = $("#path-route-template").content.firstElementChild.cloneNode(true);
      node.dataset.exitId = exit.id;
      list.append(node);
      animateChange(node, [{opacity:0,transform:"translateX(18px)"},{opacity:1,transform:"translateX(0)"}]);
    }
    const probing = running && job.testing_id === exit.id;
    const applying = running && job.kind === "apply" && job.exit_id === exit.id;
    const failed = job?.status === "failed" && (job.testing_id || job.exit_id) === exit.id;
    const phase = probing ? "checking" : applying ? "applying" : failed ? "error" : (
      exit.current ? (state.service_active ? "active" : "offline") : exit.tested_at ? "ready" : "draft"
    );
    node.dataset.phase = phase;
    node.disabled = busy || exit.removed;
    node.classList.toggle("is-current", exit.current);
    node.classList.toggle("is-selected", selectedExitId === exit.id);
    node.setAttribute("aria-pressed", String(exit.current));
    node.setAttribute("aria-label", "切换到出口：" + exit.name);
    const visibleName = exit.current ? active.name : exit.name;
    node.querySelector(".route-name").textContent = visibleName;
    node.querySelector(".route-name").title = visibleName;
    node.querySelector(".route-badge").textContent = exit.current ? "当前" : applying ? "切换中" : "点击切换";
    const observed = exit.current ? active.observed_ip : exit.observed_ip;
    node.querySelector(".route-ip").textContent = observed || exit.address + " : " + exit.port;
    node.querySelector(".route-ip").title = observed || exit.address + " : " + exit.port;
    node.querySelector(".route-status").textContent = probing ? "正在检测实际出口…" : applying ? "校验中，等待切换…" : failed ? "上次操作未通过" : (
      exit.removed ? "已从草稿移除 · 当前连接保留" : exit.current ? (
        !state.service_active ? "节点服务待检查" : exit.pending ? "当前出口 · 修改待应用" : "已应用 · 新建连接使用此出口"
      ) : exit.tested_at ? "检测通过 · 点击切换" : "已保存 · 点击检测并切换"
    );
  }
  const newHeight = list.getBoundingClientRect().height;
  if (pathBooted && Math.abs(newHeight - oldHeight) > 1) {
    animateChange(list, [{height:oldHeight + "px"},{height:newHeight + "px"}]);
  }
  if (pathBooted && activeId && lastActiveId !== activeId && state.service_active && !running) {
    const activeIcon = serverCurrent ? serverButton.querySelector(".node-icon") : list.querySelector(".is-current .node-icon");
    animateChange(activeIcon, [{boxShadow:"0 0 0 0 #769c5660"},{boxShadow:"0 0 0 14px #769c5600"}], 750);
    animateChange($("#metric-ip"), [{opacity:.4,transform:"translateY(4px)"},{opacity:1,transform:"translateY(0)"}], 320);
    if (!motionPreference.matches && !document.hidden && currentView === "overview") {
      clearTimeout(pathChangeTimer);
      card.classList.add("is-path-changing");
      pathChangeTimer = setTimeout(() => card.classList.remove("is-path-changing"), 650);
    }
  }
  lastActiveId = activeId;
  pathBooted = true;
  syncMotion();
  $("#path-preview").hidden = !selected;
  if (!selected) return;
  $("#path-preview-name").textContent = selected.name;
  const relevant = (job?.testing_id || job?.exit_id) === selected.id;
  const message = running && (relevant || job.kind === "rollback") ? job.message : job?.status === "failed" && relevant ? job.message : (
    selected.removed ? "该出口已从草稿移除。应用其他出口后，当前路径才会改变。" : selected.current ? (
      selected.pending ? "此出口有修改尚未应用；当前连接仍使用上一次应用的配置。" : "这是当前已应用的出口。切换其他出口时，已有连接可能短暂重新建立。"
    ) : selected.id === "server" ? "点击中间的服务器，即可切换到 VPS 自身出口。" : "点击右侧的出口即可检测并切换。新增或修改出口后，AUTO 无需重新下载配置。"
  );
  if ($("#path-message").textContent !== message) $("#path-message").textContent = message;
  $("#path-test").hidden = selected.id === "server";
  $("#path-test").disabled = busy || selected.removed;
  $("#path-apply").disabled = busy || selected.removed;
  $("#path-apply").textContent = selected.current ? (selected.pending ? "应用修改 ↗" : "重新应用 ↗") : "切换到此出口 ↗";
}

function render() {
  if (!state) return;
  $("#demo-banner").hidden = !state.demo;
  const pill = $("#server-pill");
  pill.classList.toggle("offline", !state.service_active);
  pill.lastChild.textContent = state.service_active ? "节点服务运行中" : "节点服务待检查";
  $("#metric-server").textContent = state.server_ip;
  $("#metric-server").title = state.server_ip;
  const locationInfo = state.server_location || {};
  let country = locationInfo.country || "";
  if (locationInfo.country_code && typeof Intl.DisplayNames === "function") {
    country = new Intl.DisplayNames(["zh-CN"], {type:"region"}).of(locationInfo.country_code) || country;
  }
  const region = [country, locationInfo.city || locationInfo.region].filter(Boolean).join(" · ");
  $("#metric-server-detail").textContent = [region, state.server_protocol || "代理节点"].filter(Boolean).join(" · ");
  $("#path-server-name").textContent = region ? region + " VPS" : "入口 VPS";
  $("#path-server-name").title = region ? region + "（根据入口 IP 查询）" : state.server_ip;
  $("#path-server").textContent = state.server_ip + " : " + state.server_port;
  $("#metric-count").textContent = state.exits.length;
  $("#exit-total").textContent = state.exits.length;
  $("#empty-state").hidden = state.exits.length > 0;
  $("#draft-notice").hidden = !state.dirty || state.exits.length === 0;
  const routingMode = state.routing_mode || "manual";
  const smart = routingMode === "smart";
  $("#routing-page-description").textContent = smart ? "国内视频与国内网站使用本机网络；海外及未匹配流量跟随网页当前出口。" : routingMode === "services" ? "使用上传的服务分类规则，按分类选择直连或网页当前出口。" : "强制代理列表中的网站经过网页当前出口，其他网站使用本机网络。";
  $("#path-routing-caption").textContent = smart ? "智能分流：国内走本机；海外与未匹配流量经过这条路径。" : routingMode === "services" ? "服务分类决定流量去向；代理流量跟随网页当前出口。" : "指定网站经过这条路径；未匹配的网站使用本机网络。";
  const serverCurrent = state.active_target === "server";
  const activeExit = serverCurrent ? state.server_exit : state.active;
  $("#metric-active").textContent = activeExit?.name || "尚未配置";
  $("#metric-active-detail").textContent = serverCurrent ? "VPS 使用自身网络直接出网" : state.active ? "网页已应用的静态出口" : "点击服务器或静态出口开始使用";
  $("#metric-ip").textContent = activeExit?.observed_ip || "—";
  $("#metric-tested").textContent = activeExit?.tested_at ? "最近检测 " + date(activeExit.tested_at) : serverCurrent ? "服务器公网出口地址" : "应用时会检测实际出口";
  $("#last-updated").textContent = state.updated ? "最近应用 " + date(state.updated) + " · 北京时间" : "尚未应用出口";
  $("#rollback").disabled = !state.rollback_ready || busy;
  const clientConfig = state.client_config;
  document.querySelectorAll(".download-button").forEach((button) => {
    button.disabled = !state.download_ready;
    button.title = state.download_ready ? "首次导入后选择 AUTO · 网页切换，以后在此网页切换出口" : "先点击服务器或静态出口，再下载首次配置";
  });
  $("#client-config-summary").textContent = !state.download_ready ? "先点击服务器或一个静态出口，然后下载并导入首次配置。" : smart ? "导入智能分流配置一次，使用规则模式，并在 STATIC-SELECT 中选择“AUTO · 网页切换”。国内网站使用本机网络，海外跟随网页出口；此后切换出口无需重新下载，两个域名列表约每 5 分钟自动同步。" : "首次导入这份 YAML，使用规则模式，并在 STATIC-SELECT 中选择“AUTO · 网页切换”。以后添加、删除、修改与切换出口，都可在此网页完成，无需重新下载。修改分流方案后需更新并导入配置一次。";
  $("#client-config-update").hidden = !state.download_ready || !clientConfig?.fixed_nodes_refresh_required;
  $("#add-exit").disabled = state.exits.length >= 8 || busy;
  $("#add-first").disabled = busy;
  for (const card of [...$("#exit-list").children]) {
    if (!state.exits.some((exit) => exit.id === card.dataset.id)) card.remove();
  }
  for (const exit of state.exits) {
    let card = [...$("#exit-list").children].find((item) => item.dataset.id === exit.id);
    if (!card) {
      card = $("#exit-template").content.firstElementChild.cloneNode(true);
      card.dataset.id = exit.id;
      $("#exit-list").append(card);
    }
    const fragment = card;
    card.classList.toggle("is-active", exit.active);
    fragment.querySelector(".exit-monogram").textContent = exit.name.slice(0, 2).toUpperCase();
    fragment.querySelector(".exit-badge").textContent = exit.active ? "当前出口" : "SOCKS5";
    fragment.querySelector(".exit-name").textContent = exit.name;
    fragment.querySelector(".exit-name").title = exit.name;
    fragment.querySelector(".exit-endpoint").textContent = exit.address + " : " + exit.port;
    fragment.querySelector(".exit-endpoint").title = exit.address + " : " + exit.port;
    fragment.querySelector(".exit-observed").textContent = exit.observed_ip || "待检测";
    fragment.querySelector(".exit-auth-type").textContent = exit.authenticated ? "账号密码 · 已保存" : "无账号密码 / 白名单";
    fragment.querySelector(".exit-tested").textContent = exit.tested_at ? "检测于 " + date(exit.tested_at) : "尚未检测";
    const apply = fragment.querySelector('[data-action="apply"]');
    apply.textContent = exit.active ? (exit.pending ? "应用修改 ↗" : "重新应用 ↗") : "切换到此出口 ↗";
    fragment.querySelectorAll("button").forEach((button) => { button.disabled = busy; });
  }
  renderPath();
  if (operationView || operationFailure || state.job) renderJob(operationView || operationFailure || state.job);
}

function renderJob(job) {
  $("#job-panel").hidden = false;
  $("#job-panel").classList.toggle("failed", job.status === "failed");
  $("#job-message").textContent = job.message;
  $("#job-percent").textContent = (job.percent || 0) + "%";
  $("#job-progress").value = job.percent || 0;
  $("#job-detail").textContent = job.kind === "test" ? "检测从 VPS 发起，以返回的实际出口 IP 为准。" : "应用期间，现有节点连接可能短暂重新建立。";
}

async function refresh(quiet = false) {
  try {
    state = await api("state");
    $("#global-error").hidden = true;
    busy = state.job?.status === "running";
    render();
  } catch (error) {
    if (!quiet && csrf) {
      $("#global-error").textContent = error.message;
      $("#global-error").hidden = false;
    }
    throw error;
  }
}

async function runJob(kind, id) {
  if (busy) return;
  busy = true;
  operationFailure = null;
  let accepted = false;
  if (id) selectedExitId = id;
  operationView = {kind,exit_id:id,testing_id:kind === "test" ? id : null,status:"running",message:kind === "test" ? "正在检测代理连接…" : "正在准备校验配置…"};
  render();
  try {
    const result = await api(kind, id ? {id} : {});
    accepted = true;
    let failures = 0;
    for (let attempt = 0; attempt < 500; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 650));
      let job;
      try { job = await api("jobs/" + result.job_id); failures = 0; }
      catch (error) { if (!csrf || ++failures > 12) throw error; continue; }
      renderJob(job);
      operationView = job;
      renderPath();
      if (job.status !== "running") {
        completedJob = job.id;
        toast(job.message, job.status === "failed");
        operationView = null;
        await refresh();
        return;
      }
    }
    throw new Error("任务仍在执行。可以稍后刷新页面查看结果。");
  } catch (error) {
    if (!accepted && state) operationFailure = {kind,exit_id:id,status:"failed",message:error.message,percent:0};
    toast(error.message, true);
  }
  finally { busy = false; operationView = null; if (state) await refresh(true).catch(() => {}); }
}

function toggleAuth() {
  const authenticated = $("#exit-auth").value === "credentials";
  $("#credential-fields").hidden = !authenticated;
  $("#allowlist-hint").hidden = authenticated;
}

function openExit(exit = null) {
  $("#exit-form").reset();
  $("#exit-id").value = exit?.id || "";
  $("#exit-name").value = exit?.name || "";
  $("#exit-address").value = exit?.address || "";
  $("#exit-port").value = exit?.port || 1080;
  $("#exit-expected").value = exit?.expected_ip || "";
  $("#exit-auth").value = exit && !exit.authenticated ? "none" : "credentials";
  $("#exit-user").value = $("#exit-password").value = "";
  $("#exit-error").textContent = "";
  $("#dialog-title").textContent = exit ? "编辑静态出口" : "添加静态出口";
  $("#credential-hint").textContent = exit ? "已保存的账号和密码不会显示。留空可以保留原值。" : "代理资料保存在服务器，不会写入下载的客户端配置。";
  $("#exit-password").type = "password";
  $('[data-toggle-password="exit-password"]').textContent = "显示";
  toggleAuth();
  $("#exit-dialog").showModal();
}

function confirmAction(title, message, action) {
  const dialog = $("#confirm-dialog");
  $("#confirm-title").textContent = title;
  $("#confirm-message").textContent = message;
  $("#confirm-ok").textContent = action;
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm"), {once:true});
    dialog.showModal();
  });
}

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  $("#login-error").textContent = "";
  try {
    const result = await api("login", {username:$("#login-user").value.trim(),password:$("#login-password").value});
    csrf = result.csrf;
    $("#login-password").value = "";
    $("#login-screen").hidden = true;
    $("#console").hidden = false;
    await refresh();
  } catch (error) { $("#login-error").textContent = error.message; }
  finally { button.disabled = false; }
});

$("#exit-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#save-exit");
  button.disabled = true;
  $("#exit-error").textContent = "";
  try {
    const saved = await api("exits/save", {id:$("#exit-id").value || undefined,name:$("#exit-name").value,
      address:$("#exit-address").value,port:Number($("#exit-port").value),auth:$("#exit-auth").value,
      username:$("#exit-user").value,password:$("#exit-password").value,expected_ip:$("#exit-expected").value});
    selectedExitId = saved.id;
    $("#exit-user").value = $("#exit-password").value = "";
    $("#exit-dialog").close();
    await refresh();
    toast("出口已保存。点击右侧的出口即可切换，AUTO 无需重新下载配置。");
  } catch (error) { $("#exit-error").textContent = error.message; }
  finally { button.disabled = false; }
});

$("#path-empty").addEventListener("click", () => openExit());
$("#path-routes").addEventListener("click", (event) => {
  const route = event.target.closest(".path-route");
  if (!route || route.disabled || busy) return;
  runJob("apply", route.dataset.exitId);
});
$("#path-server-button").addEventListener("click", () => runJob("apply", "server"));
$("#path-test").addEventListener("click", () => runJob("test", selectedExitId));
$("#path-apply").addEventListener("click", () => runJob("apply", selectedExitId));

$("#exit-list").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-action]");
  if (!button || busy) return;
  const exit = state.exits.find((item) => item.id === button.closest(".exit-card").dataset.id);
  if (!exit) return;
  if (button.dataset.action === "edit") return openExit(exit);
  if (button.dataset.action === "test") return runJob("test", exit.id);
  if (button.dataset.action === "apply") return runJob("apply", exit.id);
  if (button.dataset.action === "delete") {
    if (!await confirmAction("删除这个出口？", "将从草稿中移除“" + exit.name + "”。已应用的连接在你再次应用配置之前保持原状。", "删除出口")) return;
    try { await api("exits/delete", {id:exit.id}); await refresh(); toast("出口已从草稿移除。"); }
    catch (error) { toast(error.message, true); }
  }
});

document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));
$("#add-exit").addEventListener("click", () => openExit());
$("#add-first").addEventListener("click", () => openExit());
$("#close-dialog").addEventListener("click", () => $("#exit-dialog").close());
$("#cancel-dialog").addEventListener("click", () => $("#exit-dialog").close());
$("#exit-dialog").addEventListener("close", () => { $("#exit-user").value = $("#exit-password").value = ""; });
$("#exit-auth").addEventListener("change", toggleAuth);
$("#refresh").addEventListener("click", async () => {
  const button = $("#refresh");
  button.disabled = true;
  button.classList.add("is-refreshing");
  button.setAttribute("aria-busy", "true");
  try { await refresh(); toast("状态已更新。"); }
  catch {}
  finally {
    button.disabled = false;
    button.classList.remove("is-refreshing");
    button.setAttribute("aria-busy", "false");
  }
});
document.querySelectorAll("[data-toggle-password]").forEach((button) => button.addEventListener("click", () => {
  const field = document.getElementById(button.dataset.togglePassword);
  const show = field.type === "password";
  field.type = show ? "text" : "password";
  button.textContent = show ? "隐藏" : "显示";
}));

for (const selector of ["#logout", "#logout-mobile"]) {
  $(selector).addEventListener("click", async () => {
    try { await api("logout", {}); }
    catch (error) { toast(error.message, true); }
    finally { showLogin(); }
  });
}
$("#routing-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const mode = $("#routing-mode").value;
  const modeChanged = mode !== (state?.routing_mode || "manual");
  const save = $("#routing-form button[type='submit']");
  save.disabled = true;
  try {
    const result = await api("routing", {domains:$("#domains").value.split(/\r?\n/),direct_domains:$("#direct-domains").value.split(/\r?\n/),mode});
    await refresh();
    $("#domains").value = (state.domains || []).join("\n");
    $("#direct-domains").value = (state.direct_domains || []).join("\n");
    renderRoutingMode();
    const subscription = state.routing_subscription || result.routing_subscription;
    const interval = Math.max(1, Math.ceil((subscription?.interval || 300) / 60));
    toast(!result.download_ready ? "分流规则已保存。先点击服务器或一个静态出口，再下载并导入配置。" : modeChanged ? "分流规则已保存。分流方案已更改，请下载并导入配置一次，使用规则模式后生效。" : mode === "smart" && subscription?.enabled ? "分流规则已保存。已导入智能分流配置的客户端约 " + interval + " 分钟自动同步；立即生效可刷新客户端规则集。" : "分流规则已保存。请下载并导入更新后的配置，使用规则模式后生效。");
  }
  catch (error) { toast(error.message, true); }
  finally { save.disabled = false; }
});

function renderRoutingMode() {
  const mode = $("#routing-mode").value;
  const services = mode === "services";
  const smart = mode === "smart";
  $("#routing-service-summary").hidden = !services;
  $("#routing-smart-summary").hidden = !smart;
  $("#routing-mode-hint").textContent = smart ? "国内视频、音乐和日常网站走本机网络，海外与未匹配流量跟随网页选择的服务器或静态出口。" : services ? "沿用上传配置的服务分类与策略组。下面两个域名列表可覆盖分类规则。" : "仅强制代理列表中的网站通过网页当前出口，其他网站使用本机网络。";
  $("#routing-domains-hint").textContent = smart ? "填写域名即可同时匹配它的子域名。保存后，已导入智能分流配置的客户端约每 5 分钟自动同步；可刷新客户端规则集立即更新。" : "填写域名即可同时匹配它的子域名。列表优先于分类规则；保存后需下载并导入更新后的配置。";
  $("#routing-update-title").textContent = smart ? "首次导入，之后自动同步" : "更新配置后生效";
  $("#routing-update-description").textContent = smart ? "首次选择智能分流，需要下载并导入配置一次。之后修改这两个域名列表约每 5 分钟自动同步；想立即生效，可在客户端刷新规则集。切换分流方案仍需更新并导入配置一次。" : "修改分流方案或域名列表后，需要下载并导入更新后的配置。客户端请使用规则模式，才会按这些规则选择流量去向。";
  $("#routing-extra-note").textContent = services ? "服务策略可在客户端单独调整；代理策略保持使用 STATIC-SELECT，即可跟随网页出口。" : smart ? "本机网络指你当前的宽带、Wi-Fi 或移动网络。即使网页选择服务器出口，国内直连流量也由本机出网。" : "适合只让少数指定网站使用代理。强制直连列表优先，其他未匹配网站也会直连。";
}
$("#routing-mode").addEventListener("change", renderRoutingMode);

document.querySelectorAll(".download-button").forEach((button) => button.addEventListener("click", async () => {
  try {
    const response = await fetch(endpoint("profile"), {credentials:"same-origin"});
    if (!response.ok) { const data = await response.json(); throw new Error(data.error); }
    const url = URL.createObjectURL(await response.blob());
    const anchor = document.createElement("a");
    anchor.href = url; anchor.download = "clash-node-console.yaml"; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
    toast(state?.routing_mode === "smart" ? "配置已下载。导入后使用规则模式并选择“AUTO · 网页切换”；以后出口在网页切换，域名列表自动同步。" : "配置已下载。导入后使用规则模式并选择“AUTO · 网页切换”，以后在此网页管理和切换出口。");
  } catch (error) { toast(error.message, true); }
}));

$("#rollback").addEventListener("click", async () => {
  if (await confirmAction("恢复上次配置？", "会恢复上一次应用前的出口与分流设置，节点连接将短暂重新建立。", "恢复配置")) await runJob("rollback");
});

$("#password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if ($("#new-password").value !== $("#confirm-password").value) return toast("两次输入的新密码不一致。", true);
  try {
    await api("password", {current:$("#current-password").value,new:$("#new-password").value});
    $("#password-form").reset();
    showLogin();
    toast("密码已更新，请使用新密码重新登录。");
  } catch (error) { toast(error.message, true); }
});

async function initialize() {
  try {
    const session = await api("session");
    if (session.authenticated) {
      csrf = session.csrf;
      $("#login-screen").hidden = true;
      $("#console").hidden = false;
      await refresh();
    }
  } catch { $("#login-error").textContent = "暂时无法连接控制台，请稍后刷新。"; }
}
setInterval(() => {
  if (!csrf || busy || $("#exit-dialog").open || document.hidden) return;
  refresh(true).then(() => {
    if (state?.job?.status !== "running" && state?.job?.id && state.job.id !== completedJob) {
      completedJob = state.job.id;
    }
  }).catch(() => {});
}, 12000);
initialize();
