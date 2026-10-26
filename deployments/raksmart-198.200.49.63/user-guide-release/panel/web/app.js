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
  const generation = sessionGeneration;
  const mode = $("#routing-mode").value;
  const modeChanged = mode !== (state?.routing_mode || "manual");
  const domains = $("#domains").value.split(/\r?\n/);
  const directDomains = $("#direct-domains").value.split(/\r?\n/);
  const save = $("#routing-form button[type='submit']");
  save.disabled = true;
  try {
    const result = await api("routing", {domains,direct_domains:directDomains,mode});
    if (generation !== sessionGeneration || !csrf) return;
    await refresh();
    if (generation !== sessionGeneration || !csrf || !state) return;
    $("#domains").value = (state.domains || []).join("\n");
    $("#direct-domains").value = (state.direct_domains || []).join("\n");
    renderRoutingMode();
    const extracted = domains.filter((line) => line.trim()).join("\n") !== $("#domains").value || directDomains.filter((line) => line.trim()).join("\n") !== $("#direct-domains").value;
    const saved = extracted ? "分流规则已保存，列表已提取并整理为域名。" : "分流规则已保存。";
    const subscription = state.routing_subscription || result.routing_subscription;
    const interval = Math.max(1, Math.ceil((subscription?.interval || 300) / 60));
    toast(saved + (!result.download_ready ? "先点击服务器或一个静态出口，再下载并导入配置。" : modeChanged ? "分流方案已更改，请下载并导入配置一次，使用规则模式后生效。" : mode === "smart" && subscription?.enabled ? "已导入智能分流配置的客户端约 " + interval + " 分钟自动同步；立即生效可刷新客户端规则集。" : "请下载并导入更新后的配置，使用规则模式后生效。"));
  }
  catch (error) { if (generation === sessionGeneration && csrf) toast(error.message, true); }
  finally { save.disabled = false; }
});

function renderRoutingMode() {
  const mode = $("#routing-mode").value;
  const services = mode === "services";
  const smart = mode === "smart";
  $("#routing-service-summary").hidden = !services;
  $("#routing-smart-summary").hidden = !smart;
  $("#routing-mode-hint").textContent = smart ? "国内视频、音乐和日常网站走本机网络，海外与未匹配流量跟随网页选择的服务器或静态出口。" : services ? "沿用上传配置的服务分类与策略组。下面两个域名列表可覆盖分类规则。" : "仅强制代理列表中的网站通过网页当前出口，其他网站使用本机网络。";
  $("#routing-domains-hint").textContent = smart ? "保存后，列表会显示提取出的域名。已导入智能分流配置的客户端约每 5 分钟自动同步；可刷新客户端规则集立即更新。" : "保存后，列表会显示提取出的域名。列表优先于分类规则；需下载并导入更新后的配置。";
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
const nodeConsoleReady = initialize();

// The handbook and arrow tours explain existing controls without activating them.
(() => {
  const guide = document.querySelector("#user-guide-dialog");
  const tour = document.querySelector("#guide-tour");
  if (!guide || !tour) return;
  const topicsElement = document.querySelector("#guide-topics");
  const notice = document.querySelector("#guide-notice");
  const panel = document.querySelector("#guide-tour-panel");
  const title = document.querySelector("#guide-tour-title");
  const body = document.querySelector("#guide-tour-body");
  const counter = document.querySelector("#guide-tour-counter");
  const previous = document.querySelector("#guide-tour-prev");
  const next = document.querySelector("#guide-tour-next");
  const arrow = document.querySelector("#guide-tour-arrow");
  const line = document.querySelector("#guide-tour-arrow-line");
  const highlight = document.querySelector("#guide-tour-highlight");
  const S = (target, heading, text, extra = {}) => ({target, heading, text, ...extra});
  const topics = [
    {id:"login",name:"登录自己的账号",summary:"每个人使用自己的账号。成员只能管理自己的出口与分流。",guest:true,steps:[
      S("#login-user","填写登录账号","在这里填写管理员分配给你的网页登录账号。网页登录账号与 SOCKS5 代理账号分开使用。"),
      S("#login-password","填写登录密码","在这里输入你的网页登录密码。需要核对时，可以自己点击右侧“显示”；不要向别人展示密码。"),
      S('[data-toggle-password="login-password"]',"核对密码显示","“显示 / 隐藏”只改变密码的可见状态，不会更改密码。教程不会展示或代填你的密码。"),
      S('#login-form button[type="submit"]',"进入控制台","确认资料后，关闭指引再点击“进入控制台”。登录后看右上角账号，确认进入自己的个人空间。")]},
    {id:"first-client",name:"首次连接：下载与客户端导入",view:"access",summary:"每人各下载一份首次配置。以后选择 AUTO，就能从网页切换出口。",steps:[
      S('[data-view="overview"]',"先准备一个可用出口","先到“出口管理”选择服务器自身出口，或添加并切换到你的静态出口。教程不会代你应用出口。"),
      S('#view-access .download-button',"下载自己的首次配置","在此下载当前账号的 YAML 配置。按钮不可用时，先完成出口应用。请将各自账号的配置交给对应使用者。"),
      S(null,"在 FlClash 操作：导入配置","打开 FlClash 的“配置”，导入刚下载的 YAML；Clash Verge 等 Mihomo 客户端也可使用。此步骤在客户端完成，网页没有对应按钮。",{external:true}),
      S(null,"在 FlClash 操作：选择 AUTO","启用这份配置，使用“规则模式”。在 STATIC-SELECT 中选“AUTO · 网页切换”；服务策略组也使用 STATIC-SELECT。此步骤在客户端完成。",{external:true}),
      S(null,"在 FlClash 操作：开启代理并核对 IP","开启系统代理；需要接管更多应用时，按客户端说明使用 TUN。访问 api.ipify.org 核对网页当前出口。国内直连网站仍使用本机网络。此步骤在客户端或浏览器完成。",{external:true}),
      S('#client-config-update',"以后何时需要重新下载","保持 AUTO 后，网页切换或新增静态出口无需重新下载。首次改用智能分流、切换分流方案，或需要同步客户端的固定节点列表时，再更新配置。",{fallback:'#client-config-summary'})]},
    {id:"overview",name:"看状态与刷新",view:"overview",summary:"读懂入口、出口和实际 IP；动效显示已应用路径。",steps:[
      S('#current-user-tag',"确认当前账号","这里显示你当前登录的账号。多人使用同一服务器时，各自的出口与分流相互独立，服务器带宽和流量额度共享。"),
      S('#server-pill',"查看节点服务","“节点服务运行中”表示服务器入口服务已启动；设备是否真的连接，需要在你的客户端确认。"),
      S('#metric-server',"看入口服务器","这是设备连接的入口服务器。入口地址通常固定，出口可以在网页切换。"),
      S('#metric-active',"看当前出口","这里显示已应用的服务器或静态出口。新增出口只会保存资料，要点击切换后才用于新连接。"),
      S('#metric-ip',"看实际出口 IP","这是应用或检测得到的实际出网 IP。静态代理服务器地址可能与最终出口 IP 不同。"),
      S('#network-card',"看连接路径","设备 → 入口 VPS → 静态出口是代理路径。使用服务器出口时由 VPS 出网；强制直连的网站仍由你的本机出网。动效不代表设备一定在线。"),
      S('#refresh',"刷新状态","需要查看最新状态时，关闭指引后点击这里刷新。刷新不会切换出口。")]},
    {id:"socks-add",name:"用 SOCKS5 链接添加出口",view:"overview",summary:"粘贴 socks5:// 链接，核对自动解析结果，再保存。",steps:[
      S('#add-exit',"打开添加出口","关闭指引后点击“添加出口”。本教程接下来只打开空白表单供你认识各项，不会输入代理资料。"),
      S('#exit-socks-link',"粘贴 SOCKS5 链接","在这里粘贴服务商提供的 socks5://账号:密码@地址:端口 链接。粘贴后自动解析，链接默认隐藏；教程不代填或显示真实凭据。",{prepare:'add'}),
      S('#parse-socks-link',"手动解析链接","如果没有自动解析，点击“解析链接”。这会填写下方地址、端口与认证资料，尚未保存或切换出口。",{prepare:'add'}),
      S('#exit-name',"确认出口名称","给出口一个容易识别的名称，例如“自己的主出口”。名称用于出口卡片和路径显示。",{prepare:'add'}),
      S('#exit-address',"核对地址与端口","核对解析出的代理服务器地址与右侧端口。代理服务器地址与最终出口 IP 可以不同。",{prepare:'add'}),
      S('#exit-auth',"核对认证方式","服务商提供账号密码时选“账号与密码”；来源 IP 白名单代理选“无账号密码 / 来源 IP 白名单”，并在服务商允许你的 VPS 出口 IP。",{prepare:'add'}),
      S('#exit-expected',"填写预期出口 IP（可选）","知道服务商分配的最终出口 IP 时可填写，不知道就留空；检测后会显示实际出口。",{prepare:'add'}),
      S('#save-exit',"保存出口","关闭指引后核对资料并点击“保存出口”。保存只增加你的出口，随后点击出口切换。AUTO 无需重新下载配置。",{prepare:'add'})]},
    {id:"manual-add",name:"手动填写静态出口",view:"overview",summary:"没有链接时填写地址、端口与认证资料。",steps:[
      S('#add-exit',"打开添加表单","关闭指引后点击“添加出口”，不填写顶部链接，直接使用下方字段。"),
      S('#exit-name',"填写名称","为这个静态出口填写容易区分的名称。",{prepare:'add'}),
      S('#exit-address',"填写代理服务器地址","填写服务商的 IP 地址或域名，不要在这里填写完整网页网址。",{prepare:'add'}),
      S('#exit-port',"填写代理端口","填写服务商给出的端口，范围为 1–65535。",{prepare:'add'}),
      S('#exit-auth',"选择认证方式","有代理账号密码时选“账号与密码”；没有账号密码而使用来源 IP 白名单时选另一个选项，并先在服务商允许 VPS 的公网出口地址。",{prepare:'add'}),
      S('#exit-user',"填写代理账号","填写 SOCKS5 服务商提供的账号，和网页账号分开。白名单方式不需要此字段。",{prepare:'add',fallback:'#exit-auth',missing:'当前认证方式未显示账号字段；白名单方式无需账号密码。'}),
      S('#exit-password',"填写代理密码","填写 SOCKS5 服务商提供的密码，和网页登录密码分开。需要核对时可自己使用右侧“显示”。教程不显示或代填。",{prepare:'add',fallback:'#exit-auth',missing:'当前认证方式未显示密码字段；白名单方式无需账号密码。'}),
      S('#exit-expected',"填写预期 IP（可选）","知道最终固定出网 IP 时填写；不知道时留空，应用时会检测实际 IP。",{prepare:'add'}),
      S('#save-exit',"保存并准备切换","资料正确后，关闭指引再保存。回到出口管理后点击这个出口，完成检测与切换。",{prepare:'add'})]},
    {id:"edit-exit",name:"修改已有静态出口",view:"overview",summary:"编辑保留原凭据，保存后重新应用才会改变路径。",steps:[
      S('#exit-list [data-action="edit"]',"打开出口编辑","每张出口卡片右上角的“⋯”用于编辑该出口。没有静态出口时，先添加一个。",{fallback:'#add-exit',missing:'当前没有可编辑的静态出口；请先添加出口，再使用这项操作。'}),
      S('#exit-name',"修改名称或连接资料","可修改名称、地址、端口和认证方式。教程只展示第一张卡片的现有表单，不会更改资料。",{prepare:'edit'}),
      S('#credential-hint',"凭据留空可保留","编辑时已有账号密码不会显示；留空保留原值。要替换凭据时，再填写服务商的新资料。",{prepare:'edit'}),
      S('#save-exit',"保存修改","关闭指引后保存。保存后资料处于待应用状态，当前连接继续使用上一次应用的配置。",{prepare:'edit'}),
      S('#exit-list [data-action="apply"]',"重新应用修改","保存后点击该出口的“应用修改 / 重新应用”，完成检测并应用。已有连接可能短暂重新建立。",{fallback:'#add-exit',missing:'当前没有可应用的静态出口；先添加并保存出口。'})]},
    {id:"switch-exit",name:"检测并切换静态出口",view:"overview",summary:"卡片可以单独检测，路径上的出口可以直接切换。",steps:[
      S('#exit-list [data-action="test"]',"先检测连接（可选）","卡片上的“检测连接”从 VPS 发起检测，显示实际出网 IP；检测本身不切换当前出口。",{fallback:'#add-exit',missing:'当前没有静态出口可检测；先添加你的出口。'}),
      S('#path-routes .path-route',"从路径直接切换","点击右侧对应的静态出口，会检测并切换到该出口。保持客户端选择 AUTO，即可使用网页新选的出口。",{fallback:'#add-exit',missing:'路径上还没有静态出口；先添加并保存出口。'}),
      S('#exit-list [data-action="apply"]',"也可从出口卡片切换","在对应卡片点击“切换到此出口 / 应用修改”也可切换。操作只影响你这个账号的连接。",{fallback:'#add-exit',missing:'当前没有可切换的静态出口。'}),
      S('#path-test',"路径预览中的检测","选中静态出口时，路径下方也可能显示检测按钮；当前预览服务器时没有此按钮，可以用卡片上的检测。",{fallback:'#exit-list [data-action="test"]',missing:'当前路径未显示静态出口检测按钮。'}),
      S('#metric-ip',"核对切换结果","等待操作完成，看当前出口与实际 IP。客户端仍需选择 AUTO；固定“出口 · 名称”节点始终使用它指定的出口。")]},
    {id:"server-exit",name:"切回服务器自身出口",view:"overview",summary:"点击路径中间的服务器；智能分流国内流量继续走本机。",steps:[
      S('#path-server-button',"点击中间服务器","关闭指引后点击路径中间的服务器，即可检测并切换到 VPS 自身出口。此操作不会删除你保存的静态出口。"),
      S('#metric-active',"确认当前出口","成功后这里显示“服务器自身出口”。新建代理连接通过 VPS 出网；旧连接可能短暂重新建立。"),
      S('#metric-ip',"核对实际 IP","实际出口 IP 应显示服务器的公网出网 IP。保持客户端 AUTO 后，无需重新下载配置。"),
      S('[data-view="routing"]',"国内直连依旧由本机出网","即使当前选择服务器出口，智能分流识别的国内网站和强制直连网站仍走本机的宽带、Wi-Fi 或移动网络。")]},
    {id:"delete-recovery",name:"删除出口与恢复上次配置",view:"overview",summary:"删除先移除草稿；恢复会应用前一次配置。",steps:[
      S('#exit-list [data-action="delete"]',"删除一张出口卡片","关闭指引后点击对应卡片的“删除”，页面会要求确认。删除会移除出口草稿，不会立即替换已应用的连接。",{fallback:'#add-exit',missing:'当前没有静态出口可删除；无需操作。'}),
      S('#exit-list',"阅读删除确认再决定","在实际删除确认弹窗中，核对出口名称；不想删除时点击取消。教程不会打开或确认删除弹窗。"),
      S('#path-server-button',"删除后再选择需要的路径","若刚删除的出口仍是当前已应用路径，请再选择服务器或其他静态出口。应用其他路径后，当前连接才改变。"),
      S('#rollback',"恢复上次配置","“恢复上次配置”恢复上一次应用前的出口与分流设置，需要确认，连接可能重新建立。没有备份时按钮不可用；它不代替逐项编辑。")]},
    {id:"smart-routing",name:"智能分流：直连、代理与完整网址",view:"routing",summary:"每行一个域名或完整网址；学习通可单独加入强制直连。",steps:[
      S('#routing-mode',"选择智能分流","想让国内网站走本机、海外与未匹配网站走网页出口，选择“智能分流 · 国内直连”。教程不更改你当前选择的方案。"),
      S('#direct-domains',"添加强制直连","每行一个域名或完整 HTTP / HTTPS 网址。学习通可填 mooc1.chaoxing.com，或粘贴课程完整网址；这类流量由本机出网，不经过 VPS 转发。"),
      S('#routing-url-hint',"了解自动提取的范围","保存时只保留网址的域名，去掉路径、参数和端口。mooc1.chaoxing.com 匹配它及其子域名；要包含 chaoxing.com 下其他服务，请手动填写 chaoxing.com。"),
      S('#domains',"添加强制代理","必须走服务器或静态出口的网站填在这里，每行一个。它们跟随网页当前出口。同一域名及其子域名只放在一个列表，重叠时需调整。"),
      S('#routing-smart-summary',"看分流优先级","自定义直连与代理列表优先于网站分类。api.ipify.org 固定走网页出口，用于核对实际 IP，不可加入强制直连。",{fallback:'#routing-domains-hint',missing:'当前尚未选择智能分流；切换方案后可查看完整优先级。'}),
      S('#routing-form button[type="submit"]',"保存分流规则","关闭指引后再编辑并保存。完整网址会整理为域名显示在列表。首次更换分流方案需要重新下载并导入配置一次。"),
      S('#routing-update-description',"让客户端同步规则","已导入智能分流配置后，这两个列表约每 5 分钟自动同步；想立即生效，在客户端刷新规则集。需要规则模式，保持 AUTO 让代理流量跟随网页出口。")]},
    {id:"routing-modes",name:"选择其他分流方案",view:"routing",summary:"理解智能、手动和服务分类方案的区别与更新方式。",steps:[
      S('#routing-mode',"比较三种方案","智能分流：国内直连，海外和未匹配代理。手动域名：只有强制代理列表走代理，其余直连。服务分类：沿用上传配置中的服务策略。"),
      S('#direct-domains',"自定义直连例外","两个域名列表可作为你的自定义例外。强制直连匹配的流量使用本机网络。每个人保存自己的列表。"),
      S('#domains',"自定义代理例外","强制代理匹配的流量跟随网页当前出口；完整网址也可以粘贴，保存后仅保留域名。"),
      S('#routing-form button[type="submit"]',"保存与更新配置","切换分流方案后，保存并重新下载、导入配置一次。手动和服务分类方案修改列表后也需更新配置；智能方案列表可以自动同步。"),
      S('#routing-update-description',"查看当前方案的生效说明","这里按你选中的方案说明是否需要重新导入。客户端必须使用规则模式，才能按网站规则分流。")]},
    {id:"password-logout",name:"修改网页登录密码与退出",view:"access",summary:"只更改自己的网页登录密码；代理服务密码在出口里修改。",steps:[
      S('#current-password',"输入当前网页登录密码","这里使用当前账号的网页登录密码，不是 SOCKS5 服务密码。教程不会填入或显示密码。"),
      S('#new-password',"输入新密码","新密码需要 12–128 个字符。请为自己的账号设置并妥善保存。"),
      S('#confirm-password',"再次确认新密码","再次填写完全相同的新密码，确认无误再提交。"),
      S('#password-form button[type="submit"]',"更新登录密码","关闭指引后点击更新。修改成功后，这个账号的设备需要重新登录；其他使用者的账号不受影响。"),
      S(()=>visible('#logout')||visible('#logout-mobile'),"退出当前账号","共用设备使用完后点击退出。退出会清除页面中的账户资料和分流草稿。下次用自己的新密码重新登录。")]},
    {id:"admin-create",name:"管理员：创建独立使用者",view:"users",admin:true,summary:"最多三个账号，各自管理自己的出口和分流。",steps:[
      S('#users-nav',"打开用户管理","管理员可以管理服务器使用者；普通成员没有此入口。创建账号后，把对应登录资料交给该使用者。"),
      S('#user-slots',"查看账号名额","服务器最多三个账号，包含管理员。名额满时创建按钮不可用，可以管理已有成员。"),
      S('#create-username',"填写登录账号","3–24 个字符，以小写字母开头，可使用小写字母、数字、下划线和短横线。账号用于网页登录。"),
      S('#create-display-name',"填写显示名称（可选）","可以填写容易识别的名字，方便在用户列表找到使用者。"),
      S('#create-user-password',"设置初始密码","填写 12–128 个字符的初始网页登录密码。创建后不会再次显示，使用者可以自行更改。"),
      S('#create-user-submit',"创建独立账号","关闭指引后确认资料，再点击创建。成员会获得自己的入口、配置、出口与分流；创建不会共享管理员的静态出口。")]},
    {id:"admin-reset",name:"管理员：重置成员密码",view:"users",admin:true,summary:"重置只影响这个成员的网页登录会话。",steps:[
      S('#user-list [data-user-action="reset"]:not([hidden])',"找到成员的重置按钮","在目标成员卡片点击“重置密码”。管理员自己的密码通过“客户端与访问”修改。",{fallback:'#create-username',missing:'当前没有成员可重置；先创建使用者。'}),
      S('#reset-user-label',"核对目标成员","实际操作时先核对这里的显示名称和账号，避免给其他人重置。教程只展示第一位成员的空白重置表单。",{prepare:'reset'}),
      S('#reset-user-password',"填写新的网页登录密码","填写 12–128 个字符的新密码；重置后只交给对应使用者。教程不会代填或显示凭据。",{prepare:'reset'}),
      S('#reset-user-confirm',"再次输入新密码","两次输入需完全一致。",{prepare:'reset'}),
      S('#reset-user-submit',"保存新密码","关闭指引后确认目标和密码，再保存。该成员的所有网页登录会话需要重新登录，其他账号不受影响。",{prepare:'reset'})]},
    {id:"admin-enabled",name:"管理员：停用、启用与刷新成员",view:"users",admin:true,summary:"停用停止该成员入口，启用可恢复使用；管理员不能停用。",steps:[
      S('#user-list',"查看成员独立入口","每张成员卡片显示自己的端口、出口数量、当前路径和服务状态。成员配置只连接自己的入口。"),
      S('#user-list [data-user-action="enabled"]:not([hidden])',"停用或启用目标成员","先核对成员，再关闭指引点击“停用账号 / 启用账号”。停用会停止该成员代理入口并退出其网页会话；管理员不会出现停用按钮。",{fallback:'#create-username',missing:'当前没有成员可启用或停用。'}),
      S('#refresh-users',"刷新成员列表","点击刷新读取最新状态。它不会改变账号启用状态，也不会替成员切换出口。")]}];
  let active = null;
  let returnFocus = null;
  let ownedDialog = null;
  let ownedKind = null;
  let frame = 0;
  let revision = 0;
  let handbookGeneration = null;
  let observedGeneration = sessionGeneration;
  const visible = (selector) => [...document.querySelectorAll(selector)].find((element) => element.getClientRects().length && !element.closest('[hidden]')) || null;
  const permitted = (topic) => topic.guest ? !csrf : !!csrf && (!topic.admin || currentUser?.role === 'admin');
  function say(message) {notice.textContent = message;notice.hidden = !message;}
  function renderTopics() {
    topicsElement.replaceChildren();
    for (const topic of topics.filter(permitted)) {
      const card = document.createElement('article');card.className = 'guide-topic-card';card.dataset.guideTopic = topic.id;
      const heading = document.createElement('h3');heading.className = 'guide-topic-heading';heading.textContent = topic.name;
      const summary = document.createElement('p');summary.className = 'guide-topic-summary';summary.textContent = topic.summary;
      const list = document.createElement('ol');list.className = 'guide-steps';
      for (const [index, step] of topic.steps.entries()) {
        const item = document.createElement('li');item.className = 'guide-step';
        const mark = document.createElement('span');mark.className = 'guide-step-arrow';mark.textContent = '↳';mark.setAttribute('aria-hidden','true');
        const text = document.createElement('span');text.textContent = (index + 1) + '. ' + step.heading + '：' + step.text;
        item.append(mark,text);list.append(item);
      }
      const button = document.createElement('button');button.type = 'button';button.className = 'button secondary guide-topic-action';button.dataset.guideTopic = topic.id;
      button.textContent = '用箭头逐步讲解 →';button.addEventListener('click', () => start(topic.id));
      card.append(heading,summary,list,button);topicsElement.append(card);
    }
  }
  function modalOpen() {return [...document.querySelectorAll('dialog[open]')].find((element) => element !== guide && element !== tour);}
  function routingDraft() {
    if (!state || currentView !== 'routing') return false;
    return document.querySelector('#domains').value !== (state.domains || []).join('\n') || document.querySelector('#direct-domains').value !== (state.direct_domains || []).join('\n') || document.querySelector('#routing-mode').value !== (state.routing_mode || 'manual');
  }
  function focusBack(element) {if (element?.isConnected && element.getClientRects().length) element.focus({preventScroll:true});}
  function open() {
    if (active) stop(false);
    if (modalOpen()) {toast('当前表单仍然打开。请先保存或自行取消该表单，再打开操作说明。');return false;}
    returnFocus = document.activeElement;
    handbookGeneration = sessionGeneration;
    renderTopics();say('教程只讲解。下一步仅移动箭头；关闭指引后，再按箭头指出的位置自己操作。');
    if (!guide.open) guide.showModal();
    document.querySelector('#guide-close').focus({preventScroll:true});
    return true;
  }
  function closeOwned() {
    if (ownedDialog?.open) ownedDialog.close();
    ownedDialog = null;ownedKind = null;
  }
  function stop(restore = true) {
    revision++;
    const old = active;active = null;
    cancelAnimationFrame(frame);frame = 0;
    if (tour.open) tour.close();
    panel.hidden = highlight.hidden = true;
    arrow.toggleAttribute('hidden',true);
    highlight.dataset.targetSelector = '';
    highlight.dataset.target = '';
    panel.dataset.topic = '';
    closeOwned();
    if (restore && old && old.generation === sessionGeneration && csrf && currentView !== old.returnView) switchView(old.returnView);
    if (restore) focusBack(old?.returnFocus || returnFocus);
  }
  async function start(id) {
    const topic = topics.find((item) => item.id === id);
    if (!topic || !permitted(topic)) return false;
    if (modalOpen()) {say('请先保存或自行取消当前打开的表单，再开始箭头讲解；你的草稿没有改动。');return false;}
    if (topic.view && currentView !== topic.view && routingDraft()) {say('你的网站分流有未保存草稿。请先保存，或自行确认放弃后离开；教程不会覆盖这些内容。');return false;}
    if (active) stop(false);
    active = {topic,index:0,generation:sessionGeneration,returnView:currentView,returnFocus:returnFocus || document.activeElement,target:null,targetSelector:''};
    panel.dataset.topic = topic.id;
    if (guide.open) guide.close();
    panel.hidden = false;
    await showStep();
    return !!active;
  }
  async function prepare(kind) {
    if (ownedKind === kind && ownedDialog?.open) return true;
    if (tour.open) tour.close();
    closeOwned();
    if (!kind) return true;
    if (kind === 'add') {openExit();ownedDialog = document.querySelector('#exit-dialog');}
    else if (kind === 'edit') {
      const exit = state?.exits?.[0];
      if (!exit) return false;
      openExit(exit);ownedDialog = document.querySelector('#exit-dialog');
    } else if (kind === 'reset') {
      const member = users.find((item) => item.role !== 'admin');
      if (!member) return false;
      openUserPassword(member);ownedDialog = document.querySelector('#user-password-dialog');
    }
    ownedKind = kind;
    return true;
  }
  function resolve(step) {
    const selector = typeof step.target === 'function' ? null : step.target;
    let target = typeof step.target === 'function' ? step.target() : selector ? visible(selector) : null;
    let targetSelector = selector || (target ? '#' + target.id : '');
    let explanation = '';
    if (!target && !step.external) {
      explanation = step.missing || '当前没有对应控件。先完成前面的准备操作，再使用此功能；本步骤可以继续。';
      if (step.fallback) {target = visible(step.fallback);targetSelector = step.fallback;}
      if (!target) {target = visible(active?.topic.view === 'users' ? '#users-nav' : active?.topic.view === 'routing' ? '#routing-mode' : '#add-exit');targetSelector = target ? '#' + target.id : '';}
    }
    if (target?.disabled) explanation += (explanation ? ' ' : '') + '当前按钮不可用；先完成需要的准备，或等待现有操作结束。';
    return {target,targetSelector,explanation};
  }
  async function showStep() {
    if (!active) return;
    arrow.toggleAttribute('hidden',true);
    highlight.hidden = true;
    highlight.dataset.targetSelector = highlight.dataset.target = '';
    const thisRevision = ++revision;
    const context = active;
    const step = context.topic.steps[context.index];
    if (context.generation !== sessionGeneration || !permitted(context.topic)) {stop(false);return;}
    if (context.topic.view && currentView !== context.topic.view) {
      if (routingDraft()) {stop();toast('检测到未保存分流草稿，已结束指引并保留内容。');return;}
      if (tour.open) tour.close();closeOwned();switchView(context.topic.view);
    }
    if (context.topic.view === 'users' && users.length === 0) {
      try {await refreshUsers();} catch {}
      while (usersLoading && thisRevision === revision && active === context) await new Promise((resolve) => setTimeout(resolve,40));
      if (thisRevision !== revision || active !== context) return;
    }
    const prepared = await prepare(step.prepare || null);
    if (thisRevision !== revision || active !== context) return;
    const resolved = prepared ? resolve(step) : {target:visible(context.topic.view === 'users' ? '#create-username' : '#add-exit'),targetSelector:context.topic.view === 'users' ? '#create-username' : '#add-exit',explanation:'当前没有可用的静态出口或成员，表单未打开。先添加对应项目，本步骤可以继续。'};
    context.target = resolved.target;context.targetSelector = resolved.targetSelector;
    title.textContent = step.heading;
    body.textContent = step.text + (resolved.explanation ? '\n\n' + resolved.explanation : '');
    counter.textContent = (context.index + 1) + ' / ' + context.topic.steps.length;
    previous.disabled = context.index === 0;
    next.textContent = context.index === context.topic.steps.length - 1 ? '完成讲解' : '下一步 →';
    panel.hidden = false;
    if (!tour.open) tour.showModal();
    panel.focus({preventScroll:true});
    if (context.target) context.target.scrollIntoView({block:'center',inline:'nearest',behavior:'instant'});
    schedule();
  }
  function geometry() {
    frame = 0;
    if (!active) return;
    if (active.generation !== sessionGeneration || !permitted(active.topic)) {stop(false);return;}
    const step = active.topic.steps[active.index];
    const resolved = resolve(step);
    if (active.target?.isConnected && active.target.getClientRects().length) resolved.target = active.target;
    else {active.target = resolved.target;active.targetSelector = resolved.targetSelector;}
    const target = active.target;
    const width = window.innerWidth,height = window.innerHeight;
    const box = target?.getBoundingClientRect();
    panel.style.right = panel.style.bottom = 'auto';
    const panelWidth = Math.min(panel.offsetWidth || 380,width - 24),panelHeight = panel.offsetHeight || 210;
    const centerX = box ? box.left + box.width / 2 : width / 2;
    const centerY = box ? box.top + box.height / 2 : height / 2;
    let left = width <= 700 ? Math.max(12,(width-panelWidth)/2) : centerX < width / 2 ? width-panelWidth-16 : 16;
    let top = width <= 700 ? centerY > height / 2 ? 12 : height-panelHeight-12 : Math.max(12,Math.min(height-panelHeight-12,centerY-panelHeight/2));
    if (!box) {left = Math.max(12,(width-panelWidth)/2);top = Math.max(12,(height-panelHeight)/2);}
    left = Math.max(12,Math.min(width-panelWidth-12,left));top = Math.max(12,Math.min(height-panelHeight-12,top));
    panel.style.left = Math.round(left) + 'px';panel.style.top = Math.round(top) + 'px';
    if (!box || box.bottom < 0 || box.top > height || box.right < 0 || box.left > width || step.external) {arrow.toggleAttribute('hidden',true);highlight.hidden = true;highlight.dataset.targetSelector = highlight.dataset.target = '';return;}
    const rect = {left:Math.max(3,box.left-5),top:Math.max(3,box.top-5),right:Math.min(width-3,box.right+5),bottom:Math.min(height-3,box.bottom+5)};
    highlight.style.left = rect.left + 'px';highlight.style.top = rect.top + 'px';highlight.style.width = Math.max(1,rect.right-rect.left) + 'px';highlight.style.height = Math.max(1,rect.bottom-rect.top) + 'px';
    highlight.dataset.targetSelector = active.targetSelector || '';
    highlight.dataset.target = active.targetSelector || '';
    highlight.hidden = false;
    arrow.toggleAttribute('hidden',false);
    arrow.setAttribute('viewBox','0 0 ' + width + ' ' + height);
    const endX = Math.max(rect.left+2,Math.min(rect.right-2,centerX)),endY = Math.max(rect.top+2,Math.min(rect.bottom-2,centerY));
    const card = panel.getBoundingClientRect();
    const startX = Math.max(card.left+14,Math.min(card.right-14,endX));
    const startY = endY < card.top ? card.top : endY > card.bottom ? card.bottom : Math.max(card.top+14,Math.min(card.bottom-14,endY));
    const fromX = endX > card.right ? card.right : endX < card.left ? card.left : startX;
    const bendX = fromX + (endX-fromX)*.55;
    line.setAttribute('d','M ' + fromX.toFixed(1) + ' ' + startY.toFixed(1) + ' Q ' + bendX.toFixed(1) + ' ' + startY.toFixed(1) + ' ' + endX.toFixed(1) + ' ' + endY.toFixed(1));
  }
  function schedule() {if (active && !frame) frame = requestAnimationFrame(geometry);}
  previous.addEventListener('click', () => {if (active && active.index > 0) {active.index--;showStep();}});
  next.addEventListener('click', () => {if (!active) return;if (active.index === active.topic.steps.length-1) stop();else {active.index++;showStep();}});
  document.querySelector('#guide-tour-exit').addEventListener('click', () => stop());
  document.querySelector('#guide-close').addEventListener('click', () => guide.close());
  for (const selector of ['#open-user-guide','#login-user-guide']) document.querySelector(selector)?.addEventListener('click',open);
  guide.addEventListener('close', () => {handbookGeneration = null;if (!active) focusBack(returnFocus);});
  tour.addEventListener('cancel', (event) => {event.preventDefault();stop();});
  document.addEventListener('keydown', (event) => {
    if (!active) return;
    if (event.key === 'Escape') {event.preventDefault();event.stopPropagation();stop();return;}
    if (event.key !== 'Tab') return;
    const controls = [...panel.querySelectorAll('button:not(:disabled)')].filter((element) => element.getClientRects().length);
    if (!controls.length) {event.preventDefault();panel.focus();return;}
    const first = controls[0],last = controls[controls.length-1];
    if (!panel.contains(document.activeElement) || document.activeElement === panel || (event.shiftKey && document.activeElement === first)) {event.preventDefault();(event.shiftKey ? last : first).focus();}
    else if (!event.shiftKey && document.activeElement === last) {event.preventDefault();first.focus();}
  },true);
  document.addEventListener('scroll',schedule,true);
  window.addEventListener('resize',schedule);
  window.visualViewport?.addEventListener('resize',schedule);
  window.visualViewport?.addEventListener('scroll',schedule);
  function sessionCheck() {
    if (observedGeneration !== sessionGeneration) {
      observedGeneration = sessionGeneration;
      topicsElement.replaceChildren();
      returnFocus = null;
    }
    if (active && active.generation !== sessionGeneration) stop(false);
    if (guide.open && handbookGeneration !== sessionGeneration) {guide.close();topicsElement.replaceChildren();}
    schedule();
  }
  const observer = new MutationObserver(sessionCheck);
  for (const selector of ['#console','#login-screen','#exit-dialog','#user-password-dialog']) {
    const element = document.querySelector(selector);if (element) observer.observe(element,{subtree:true,childList:true,attributes:true,attributeFilter:['hidden','class','open','disabled']});
  }
  for (const selector of ['#logout','#logout-mobile']) document.querySelector(selector)?.addEventListener('click',() => {stop(false);if (guide.open) guide.close();topicsElement.replaceChildren();});
  async function hashHelp() {await nodeConsoleReady;if (location.hash === '#help') open();}
  window.addEventListener('hashchange',hashHelp);
  window.NodeGuide = Object.freeze({open,start,stop});
  hashHelp();
})();
