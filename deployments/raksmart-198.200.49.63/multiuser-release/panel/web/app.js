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
let socksPasteTimer;
let currentUser = null;
let users = [];
let usersBusy = false;
let usersLoading = false;
let sessionGeneration = 0;
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
  sessionGeneration++;
  csrf = null;
  state = null;
  currentUser = null;
  users = [];
  usersBusy = false;
  usersLoading = false;
  currentView = "overview";
  busy = false;
  $("#users-nav").hidden = true;
  $("#user-list").replaceChildren();
  $("#users-error").textContent = "";
  $("#create-user-form").reset();
  $("#create-user-error").textContent = "";
  $("#user-password-dialog").close();
  $("#user-password-form").reset();
  $("#reset-user-id").value = "";
  $("#reset-user-label").textContent = "";
  $("#reset-user-error").textContent = "";
  $("#password-form").reset();
  $("#exit-dialog").close();
  $("#confirm-dialog").close();
  $("#direct-domains").value = $("#domains").value = "";
  $("#current-user-handle").textContent = "";
  $("#current-user-space").textContent = "个人空间";
  $("#current-user-name").textContent = "当前用户";
  $("#current-user-role").textContent = "个人空间";
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
  const requestToken = csrf;
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
    if (response.status === 401 && path !== "login" && requestToken === csrf) showLogin();
    if (response.status === 403) throw new Error("你没有执行此操作的权限。" + (data.error ? " " + data.error : "请联系管理员。"));
    throw new Error(data.error || "操作未完成，请稍后再试。");
  }
  return data;
}

function switchView(name) {
  if (!["overview", "routing", "access", "users"].includes(name)) return;
  if (name === "users" && currentUser?.role !== "admin") return;
  const changed = currentView !== name;
  currentView = name;
  document.querySelectorAll(".view").forEach((element) => { element.hidden = element.id !== "view-" + name; });
  document.querySelectorAll(".nav-button").forEach((element) => element.classList.toggle("selected", element.dataset.view === name));
  $("#breadcrumb-title").textContent = {overview:"出口管理",routing:"网站分流",access:"客户端与访问",users:"用户管理"}[name];
  if (name === "routing" && state) {
    $("#domains").value = (state.domains || []).join("\n");
    $("#direct-domains").value = (state.direct_domains || []).join("\n");
    $("#routing-mode").value = state.routing_mode || "manual";
    renderRoutingMode();
  }
  syncMotion();
  if (changed) animateChange($("#view-" + name), [{opacity:0,transform:"translateY(8px)"},{opacity:1,transform:"translateY(0)"}], 250);
  if (name === "users") refreshUsers().catch(() => {});
  window.scrollTo({top:0,behavior:motionPreference.matches ? "instant" : "smooth"});
}

function renderIdentity() {
  const admin = currentUser?.role === "admin";
  const name = currentUser?.display_name || currentUser?.username || "当前用户";
  $("#current-user-name").textContent = name;
  $("#current-user-name").title = currentUser?.username || name;
  $("#current-user-avatar").textContent = name.slice(0, 1).toUpperCase();
  $("#current-user-role").textContent = admin ? "管理员 · 个人空间" : "个人空间";
  $("#workspace-label").textContent = "个人空间";
  $("#current-user-handle").textContent = currentUser?.username || "";
  $("#current-user-space").textContent = admin ? "管理员" : "个人空间";
  $("#current-user-tag").title = name + (admin ? " · 管理员" : " · 个人空间");
  $("#users-nav").hidden = !admin;
  $(".sidebar nav").classList.toggle("has-user-management", admin);
  if (!admin && currentView === "users") switchView("overview");
}

function renderUsers() {
  if (currentUser?.role !== "admin") return;
  $("#user-slots").textContent = users.length + " / 3 个账号";
  $("#users-loading").hidden = !usersLoading;
  $("#refresh-users").disabled = usersLoading || usersBusy;
  $("#create-user-submit").disabled = users.length >= 3 || usersBusy || usersLoading;
  $("#create-user-capacity").hidden = users.length < 3;
  for (const card of [...$("#user-list").children]) {
    if (!users.some((user) => user.id === card.dataset.userId)) card.remove();
  }
  for (const user of users) {
    let card = [...$("#user-list").children].find((item) => item.dataset.userId === user.id);
    if (!card) {
      card = $("#user-template").content.firstElementChild.cloneNode(true);
      card.dataset.userId = user.id;
      $("#user-list").append(card);
      animateChange(card, [{opacity:0,transform:"translateY(7px)"},{opacity:1,transform:"translateY(0)"}], 250);
    }
    const isAdmin = user.role === "admin";
    const display = user.display_name || user.username;
    card.classList.toggle("is-disabled", !user.enabled);
    card.querySelector(".user-avatar").textContent = display.slice(0, 1).toUpperCase();
    card.querySelector(".user-display-name").textContent = display;
    card.querySelector(".user-display-name").title = display;
    card.querySelector(".user-username").textContent = user.username + (user.id === currentUser.id ? " · 你" : "");
    card.querySelector(".user-status").textContent = user.enabled ? "已启用" : "已停用";
    card.querySelector(".user-port").textContent = "TCP " + user.port;
    card.querySelector(".user-exit-count").textContent = (user.exit_count || 0) + " 个";
    card.querySelector(".user-active-target").textContent = {static:"静态出口",server:"服务器出口"}[user.active_target] || "尚未选择";
    card.querySelector(".user-service").textContent = user.service_active ? "运行中" : user.enabled ? "待检查" : "已停止";
    card.querySelector(".user-role").textContent = isAdmin ? "管理员" : "独立用户";
    const enabled = card.querySelector('[data-user-action="enabled"]');
    enabled.hidden = isAdmin;
    enabled.textContent = user.enabled ? "停用账号" : "启用账号";
    enabled.disabled = usersBusy;
    const reset = card.querySelector('[data-user-action="reset"]');
    reset.hidden = isAdmin;
    reset.disabled = usersBusy;
  }
}

async function refreshUsers() {
  if (currentUser?.role !== "admin" || usersLoading) return;
  const generation = sessionGeneration;
  usersLoading = true;
  $("#users-error").textContent = "";
  renderUsers();
  try {
    const result = await api("users");
    if (generation !== sessionGeneration || currentUser?.role !== "admin") return;
    users = result.users || [];
  } catch (error) {
    if (generation === sessionGeneration && currentUser?.role === "admin") $("#users-error").textContent = error.message;
    throw error;
  } finally {
    if (generation === sessionGeneration) {
      usersLoading = false;
      renderUsers();
    }
  }
}

function validateUserPassword(password) {
  if (password.length < 12 || password.length > 128) throw new Error("密码需要包含 12–128 个字符。");
}

function openUserPassword(user) {
  $("#user-password-form").reset();
  $("#reset-user-id").value = user.id;
  $("#reset-user-label").textContent = "为“" + (user.display_name || user.username) + "”（" + user.username + "）设置新密码。";
  $("#reset-user-error").textContent = "";
  $("#reset-user-password").type = $("#reset-user-confirm").type = "password";
  $("#user-password-dialog").showModal();
}

function clearUserPassword() {
  $("#user-password-form").reset();
  $("#reset-user-id").value = "";
  $("#reset-user-label").textContent = "";
  $("#reset-user-error").textContent = "";
}

function closeUserPassword() {
  clearUserPassword();
  $("#user-password-dialog").close();
}

function animateChange(element, frames, duration = 480) {
  if (element && typeof element.animate === "function" && !motionPreference.matches && !document.hidden && element.getClientRects().length) {
    element.animate(frames, {duration, easing:"cubic-bezier(.2,.8,.2,1)"});
  }
}

function syncMotion() {
  document.body.classList.toggle("motion-paused", document.hidden || !state || currentView !== "overview");
  if (motionPreference.matches) {
    clearTimeout(pathChangeTimer);
    $("#network-card").classList.remove("is-path-changing");
    for (const animation of document.getAnimations()) {
      if (!(animation instanceof CSSAnimation) && !(animation instanceof CSSTransition)) animation.cancel();
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
  if (state.user) currentUser = state.user;
  renderIdentity();
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
  const generation = sessionGeneration;
  try {
    const updated = await api("state");
    if (generation !== sessionGeneration || !csrf) return;
    state = updated;
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
  const generation = sessionGeneration;
  busy = true;
  operationFailure = null;
  let accepted = false;
  if (id) selectedExitId = id;
  operationView = {kind,exit_id:id,testing_id:kind === "test" ? id : null,status:"running",message:kind === "test" ? "正在检测代理连接…" : "正在准备校验配置…"};
  render();
  try {
    const result = await api(kind, id ? {id} : {});
    if (generation !== sessionGeneration) return;
    accepted = true;
    let failures = 0;
    for (let attempt = 0; attempt < 500; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 650));
      if (generation !== sessionGeneration) return;
      let job;
      try { job = await api("jobs/" + result.job_id); failures = 0; }
      catch (error) { if (!csrf || ++failures > 12) throw error; continue; }
      if (generation !== sessionGeneration) return;
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
    if (generation !== sessionGeneration) return;
    if (!accepted && state) operationFailure = {kind,exit_id:id,status:"failed",message:error.message,percent:0};
    toast(error.message, true);
  }
  finally { if (generation === sessionGeneration) { busy = false; operationView = null; if (state) await refresh(true).catch(() => {}); } }
}

function toggleAuth() {
  const authenticated = $("#exit-auth").value === "credentials";
  $("#credential-fields").hidden = !authenticated;
  $("#allowlist-hint").hidden = authenticated;
}

function parseSocks5Link(value) {
  const text = value.trim();
  if (!/^socks5:\/\//i.test(text)) throw new Error("请使用 socks5:// 开头的链接。");
  if (text.length > 4096 || /[\u0000-\u0020\u007f]/.test(text)) throw new Error("链接包含空格或不支持的字符。特殊字符请使用百分号编码。");
  let link;
  try { link = new URL(text); }
  catch { throw new Error("链接格式不正确，请检查地址和端口。"); }
  if (link.protocol !== "socks5:" || !link.hostname || (link.pathname && link.pathname !== "/") || link.search) {
    throw new Error("请填写 SOCKS5 地址与端口，不要附带路径或查询参数。");
  }
  if (!link.port || !/^\d+$/.test(link.port) || Number(link.port) < 1 || Number(link.port) > 65535) {
    throw new Error("链接需要包含 1 至 65535 的端口。");
  }
  let username, password, name;
  try {
    username = decodeURIComponent(link.username);
    password = decodeURIComponent(link.password);
    name = decodeURIComponent(link.hash.slice(1)).trim();
  } catch { throw new Error("链接中的百分号编码不正确，请检查账号、密码或名称。"); }
  if (Boolean(username) !== Boolean(password)) throw new Error("带认证的链接需要同时包含账号和密码。");
  if (username.includes(":") || [username, password].some((item) => /[\u0000-\u001f\u007f]/.test(item) || new TextEncoder().encode(item).length > 255)) {
    throw new Error("账号或密码包含不支持的字符，或长度超过 255 字节。");
  }
  if (/[\u0000-\u001f\u007f]/.test(name) || name.length > 32) throw new Error("链接中的出口名称需要在 32 个字符以内，且不能包含控制字符。");
  const address = link.hostname.replace(/^\[|\]$/g, "");
  if (!address.includes(":") && (address.length > 253 || !address.split(".").every((part) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(part)))) {
    throw new Error("代理地址需要是 IP 地址或有效域名。");
  }
  return {address, port:Number(link.port), username, password, name, auth:username ? "credentials" : "none"};
}

function importSocks5Link() {
  const input = $("#exit-socks-link");
  const status = $("#socks-import-status");
  clearTimeout(socksPasteTimer);
  status.classList.remove("is-error", "is-success");
  try {
    const parsed = parseSocks5Link(input.value);
    $("#exit-address").value = parsed.address;
    $("#exit-port").value = parsed.port;
    $("#exit-auth").value = parsed.auth;
    $("#exit-user").value = parsed.username;
    $("#exit-password").value = parsed.password;
    $("#exit-password").type = "password";
    $('[data-toggle-password="exit-password"]').textContent = "显示";
    $("#exit-expected").value = "";
    if (!$("#exit-name").value.trim()) $("#exit-name").value = parsed.name || ("SOCKS5 · " + parsed.address).slice(0, 32);
    toggleAuth();
    input.value = "";
    input.type = "password";
    $('[data-toggle-password="exit-socks-link"]').textContent = "显示";
    input.setAttribute("aria-invalid", "false");
    $("#exit-error").textContent = "";
    status.textContent = "已填入地址、端口" + (parsed.auth === "credentials" ? "和认证资料" : "，使用无账号密码认证") + "。确认后点击“保存出口”。";
    status.classList.add("is-success");
    return true;
  } catch (error) {
    input.setAttribute("aria-invalid", "true");
    status.textContent = error.message;
    status.classList.add("is-error");
    return false;
  }
}

function clearSocks5Import() {
  clearTimeout(socksPasteTimer);
  $("#exit-socks-link").value = "";
  $("#exit-socks-link").type = "password";
  $("#exit-socks-link").removeAttribute("aria-invalid");
  $('[data-toggle-password="exit-socks-link"]').textContent = "显示";
  $("#socks-import-status").textContent = "";
  $("#socks-import-status").classList.remove("is-error", "is-success");
}

function openExit(exit = null) {
  $("#exit-form").reset();
  clearSocks5Import();
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
    sessionGeneration++;
    csrf = result.csrf;
    currentUser = result.user || null;
    renderIdentity();
    switchView("overview");
    $("#login-password").value = "";
    $("#login-screen").hidden = true;
    $("#console").hidden = false;
    await refresh();
  } catch (error) { $("#login-error").textContent = error.message; }
  finally { button.disabled = false; }
});

$("#exit-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if ($("#exit-socks-link").value.trim() && !importSocks5Link()) return;
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
$("#exit-dialog").addEventListener("close", () => {
  $("#exit-user").value = $("#exit-password").value = "";
  clearSocks5Import();
});
$("#parse-socks-link").addEventListener("click", importSocks5Link);
$("#exit-socks-link").addEventListener("paste", () => {
  clearTimeout(socksPasteTimer);
  socksPasteTimer = setTimeout(() => {
    if ($("#exit-dialog").open && $("#exit-socks-link").value.trim()) importSocks5Link();
  }, 0);
});
$("#exit-socks-link").addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    importSocks5Link();
  }
});
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

$("#refresh-users").addEventListener("click", () => refreshUsers().catch(() => {}));
$("#create-user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (usersBusy || currentUser?.role !== "admin") return;
  const generation = sessionGeneration;
  $("#create-user-error").textContent = "";
  try {
    const username = $("#create-username").value.trim();
    const display_name = $("#create-display-name").value.trim();
    const password = $("#create-user-password").value;
    if (!/^[a-z][a-z0-9_-]{2,23}$/.test(username)) throw new Error("账号需为 3–24 个字符，以小写字母开头，只能使用小写字母、数字、下划线或短横线。");
    if (display_name.length > 48) throw new Error("显示名称最多 48 个字符。");
    validateUserPassword(password);
    usersBusy = true;
    renderUsers();
    const result = await api("users/create", {username,display_name:display_name || username,password});
    if (generation !== sessionGeneration) return;
    $("#create-user-form").reset();
    await refreshUsers();
    toast("独立账号“" + (result.user?.username || username) + "”已创建。请将登录资料交给该使用者。");
  } catch (error) {
    if (generation === sessionGeneration) $("#create-user-error").textContent = error.message;
  } finally {
    if (generation === sessionGeneration) {
      usersBusy = false;
      renderUsers();
    }
  }
});

$("#user-list").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-user-action]");
  if (!button || usersBusy || currentUser?.role !== "admin") return;
  const user = users.find((item) => item.id === button.closest(".user-card").dataset.userId);
  if (!user || user.role === "admin") return;
  if (button.dataset.userAction === "reset") return openUserPassword(user);
  const generation = sessionGeneration;
  const enabled = !user.enabled;
  if (!enabled && !await confirmAction("停用这个账号？", "“" + (user.display_name || user.username) + "”的代理入口将停止，其网页登录也将退出。启用后可以继续使用原配置。", "停用账号")) return;
  if (generation !== sessionGeneration) return;
  usersBusy = true;
  renderUsers();
  try {
    await api("users/set-enabled", {id:user.id,enabled});
    if (generation !== sessionGeneration) return;
    await refreshUsers();
    toast(enabled ? "账号已启用，可以继续使用原配置。" : "账号已停用，其代理入口已停止。");
  } catch (error) {
    if (generation === sessionGeneration) toast(error.message, true);
  } finally {
    if (generation === sessionGeneration) { usersBusy = false; renderUsers(); }
  }
});

$("#user-password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (usersBusy || currentUser?.role !== "admin") return;
  const generation = sessionGeneration;
  $("#reset-user-error").textContent = "";
  try {
    const id = $("#reset-user-id").value;
    const user = users.find((item) => item.id === id);
    if (!user || user.role === "admin") throw new Error("请在个人空间修改自己的密码。");
    const password = $("#reset-user-password").value;
    validateUserPassword(password);
    if (password !== $("#reset-user-confirm").value) throw new Error("两次输入的新密码不一致。");
    usersBusy = true;
    $("#reset-user-submit").disabled = true;
    await api("users/reset-password", {id,password});
    if (generation !== sessionGeneration) return;
    closeUserPassword();
    toast("该用户的密码已重置。请将新密码交给使用者重新登录。");
  } catch (error) {
    if (generation === sessionGeneration) $("#reset-user-error").textContent = error.message;
  } finally {
    if (generation === sessionGeneration) {
      usersBusy = false;
      $("#reset-user-submit").disabled = false;
      renderUsers();
    }
  }
});
for (const selector of ["#close-user-password", "#cancel-user-password"]) {
  $(selector).addEventListener("click", closeUserPassword);
}
$("#user-password-dialog").addEventListener("close", clearUserPassword);
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
    anchor.href = url; anchor.download = "clash-node-console" + (currentUser?.username ? "-" + currentUser.username : "") + ".yaml"; anchor.click();
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
      sessionGeneration++;
      csrf = session.csrf;
      currentUser = session.user || null;
      renderIdentity();
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
