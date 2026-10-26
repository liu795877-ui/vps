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
let draftPromptBusy = false;
let routingReady = false;
let subscription = null;
let backupPreview = null;
let enhancementLoading = new Set();
let trafficSamples = [];
let trafficSampleKey = null;
let trafficGapPending = false;
let trafficInspectedAt = null;
let entrancePool = null;
let entranceDraft = false;
let entranceSaving = false;
let memberTasks = [];
let taskTimer;
let taskLoading = false;
let taskRestoredGeneration = -1;
let pendingProvision = null;
let memberSecrets = new Map();
let completedMemberTasks = new Set();
let deliveryExpiryTimer;
let memberDelivery = null;
let loginBusy = false;
let storedMotion = 'system';
try { storedMotion = localStorage.getItem('node-motion-preference') === 'off' ? 'off' : 'system'; } catch {}
const motionPreference = matchMedia("(prefers-reduced-motion: reduce)");
function reduceMotion() {return storedMotion === 'off' || motionPreference.matches;}
const dateFormat = new Intl.DateTimeFormat("zh-CN", {timeZone:"Asia/Shanghai", month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",hour12:false});

function endpoint(path) { return new URL("./api/" + path, location.href); }
function date(value) { return value ? dateFormat.format(new Date(value)) : "尚未检测"; }
function layoutDetailsAncestors(element) {
  const details = [];
  for (let parent = element?.parentElement;parent;parent = parent.parentElement) if (parent.matches('details.layout-details')) details.unshift(parent);
  return details;
}
function revealLayoutTarget(element) {
  for (const details of layoutDetailsAncestors(element)) details.open = true;
}
function syncLayoutDrafts() {
  $('#health-settings-draft').hidden = !$('#health-settings-form').dataset.dirty;
  $('#password-draft-indicator').hidden = !['#current-password','#new-password','#confirm-password'].some((selector) => $(selector).value);
  $('#member-draft-indicator').hidden = !['#create-username','#create-display-name','#create-user-password'].some((selector) => $(selector).value);
  $('#backup-schedule-draft').hidden = !$('#backup-schedule-form').dataset.dirty;
}
function layoutFormError(form,message) {
  if (!form) return;
  const error = form.id === 'password-form' ? $('#password-error') : form.id === 'health-settings-form' ? $('#health-settings-error') : null;
  if (error) error.textContent = message || '';
  if (message) revealLayoutTarget(form);
}
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
  clearMemberOperations();
  csrf = null;
  state = null;
  currentUser = null;
  users = [];
  usersBusy = false;
  usersLoading = false;
  currentView = "overview";
  routingReady = false;
  subscription = null;
  backupPreview = null;
  enhancementLoading.clear();
  busy = false;
  $("#users-nav").hidden = true;
  $("#maintenance-nav").hidden = true;
  $('#admin-shortcuts').hidden = true;
  $("#subscription-url").value = "";
  $("#subscription-url").type = "password";
  $("#diagnostic-url").value = "";
  $("#diagnostic-result").replaceChildren();
  $("#diagnostic-result").hidden = true;
  for (const selector of ["#audit-list", "#admin-audit-list", "#backup-list", "#backup-preview-summary", "#health-facts", "#users-traffic-facts"]) $(selector).replaceChildren();
  resetTrafficHistory();
  renderTrafficDashboard(null);
  $('#users-traffic-summary').textContent = '正在读取服务器用量';
  $('#transport-update-notice').hidden = true;$('#transport-update-notice').textContent = '';
  for (const selector of ["#backup-create-form", "#backup-preview-form", "#backup-schedule-form", "#health-settings-form", "#user-limits-form"]) $(selector).reset();
  for (const selector of ["#draft-dialog", "#user-limits-dialog"]) $(selector).close();
  $("#backup-preview").hidden = true;
  $("#restore-confirmation").value = "";
  for (const selector of ['#typed-confirm-dialog','#backup-export-dialog']) $(selector).close();
  $('#backup-export-form').reset();$('#typed-confirm-input').value = '';
  $('#limits-user-id').value = '';$('#limits-user-label').textContent = '';$('#export-backup-id').value = '';
  for (const selector of ['#health-settings-form','#backup-schedule-form']) delete $(selector).dataset.dirty;
  for (const selector of ['#health-settings-error','#password-error']) $(selector).textContent = '';
  for (const details of document.querySelectorAll('details.layout-details')) details.open = false;
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
  syncLayoutDrafts();
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
  if (!["overview", "routing", "access", "users", "maintenance"].includes(name)) return;
  if (["users", "maintenance"].includes(name) && currentUser?.role !== "admin") return;
  const changed = currentView !== name;
  if (!changed && !$("#view-" + name).hidden) return;
  currentView = name;
  document.querySelectorAll(".view").forEach((element) => { element.hidden = element.id !== "view-" + name; });
  document.querySelectorAll(".nav-button").forEach((element) => element.classList.toggle("selected", element.dataset.view === name));
  $("#breadcrumb-title").textContent = {overview:"出口管理",routing:"网站分流",access:"客户端与访问",users:"用户管理",maintenance:"维护与记录"}[name];
  if (name === "routing" && state) {
    $("#domains").value = (state.domains || []).join("\n");
    $("#direct-domains").value = (state.direct_domains || []).join("\n");
    $("#routing-mode").value = state.routing_mode || "manual";
    renderRoutingMode();
    routingReady = true;
  }
  syncMotion();
  if (changed) animateChange($("#view-" + name), [{opacity:0,transform:"translateY(8px)"},{opacity:1,transform:"translateY(0)"}], 250);
  if (name === "users") refreshUsers().catch(() => {});
  if (name === "access" || name === "maintenance") loadEnhancementView(name).catch(() => {});
  window.scrollTo({top:0,behavior:reduceMotion() ? "instant" : "smooth"});
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
  $("#maintenance-nav").hidden = !admin;
  $('#admin-shortcuts').hidden = !admin;
  $(".sidebar nav").classList.toggle("has-user-management", admin);
  if (!admin && ["users", "maintenance"].includes(currentView)) switchView("overview");
  if (admin && taskRestoredGeneration !== sessionGeneration) {
    taskRestoredGeneration = sessionGeneration;
    refreshUsers().catch(() => {});
    loadMemberTasks().catch(() => {});
  }
}

function renderUsers() {
  if (currentUser?.role !== "admin") return;
  renderServerTraffic();
  const capacity = Number(entrancePool?.capacity) || 3;
  const available = entrancePool ? Math.max(0,Number(entrancePool.available_count) || 0) : Math.max(0,capacity-users.length);
  $("#user-slots").textContent = users.length + " / " + capacity + " 个账号";
  $("#users-loading").hidden = !usersLoading;
  $("#refresh-users").disabled = usersLoading || usersBusy;
  $("#create-user-submit").disabled = available < 1 || usersBusy || usersLoading;
  for (const input of $('#create-user-form').querySelectorAll('input')) input.disabled = usersBusy;
  $('#generate-member-password').disabled = usersBusy;
  $('#create-user-submit').textContent = usersBusy ? '正在准备成员…' : '准备成员与入口 ↗';
  $("#create-user-capacity").hidden = available > 0;
  $('#member-capacity-summary').textContent = available < 1 ? '入口已分配完，先准备资源池' : '还可添加 ' + available + ' 个账号';
  $('#quick-entrance-summary').textContent = entrancePool ? available + ' 个可分配入口' : '入口清单尚未读取';
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
    card.querySelector(".user-port").textContent = "TCP " + user.port + (user.hy2_port ? ' / UDP ' + user.hy2_port + ' · HY2' : ' / HY2 待核验');
    card.querySelector(".user-exit-count").textContent = (user.exit_count || 0) + " 个";
    card.querySelector(".user-active-target").textContent = {static:"静态出口",server:"服务器出口"}[user.active_target] || "尚未选择";
    card.querySelector(".user-service").textContent = 'TCP ' + (user.service_active ? "运行中" : user.enabled ? "待检查" : "已停止") + ' · HY2 ' + (user.hy2_service_active === true ? '运行中' : user.hy2_service_active === false ? '已停止' : '待检查');
    card.querySelector(".user-role").textContent = isAdmin ? "管理员" : "独立用户";
    const enabled = card.querySelector('[data-user-action="enabled"]');
    enabled.hidden = isAdmin;
    enabled.textContent = user.enabled ? "停用账号" : "启用账号";
    enabled.disabled = usersBusy;
    const reset = card.querySelector('[data-user-action="reset"]');
    reset.hidden = isAdmin;
    reset.disabled = usersBusy;
    for (const action of ['limits','rotate','delete']) {
      const control = card.querySelector('[data-user-action="'+action+'"]');
      control.hidden = isAdmin && action !== 'limits';
      control.disabled = usersBusy;
    }
    renderUserTraffic(card.querySelector('.user-usage'),user.traffic);
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
    if (result.entrances) {entrancePool = result.entrances;renderEntrancePool();}
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
  if (element && typeof element.animate === "function" && !reduceMotion() && !document.hidden && element.getClientRects().length) {
    element.animate(frames, {duration, easing:"cubic-bezier(.2,.8,.2,1)"});
  }
}

function syncMotion() {
  document.body.classList.toggle("motion-paused", document.hidden || !state || currentView !== "overview");
  document.body.classList.toggle('motion-off', reduceMotion());
  document.body.classList.toggle('motion-background', document.hidden);
  for (const select of document.querySelectorAll('[data-motion-setting]')) select.value = storedMotion;
  if (reduceMotion()) {
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
    if (!reduceMotion() && !document.hidden && currentView === "overview") {
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
  $("#metric-server-detail").textContent = [region, state.transport?.enabled ? 'HY2 / REALITY 双入口' : state.server_protocol || "代理节点"].filter(Boolean).join(" · ");
  $("#path-server-name").textContent = region ? region + " VPS" : "入口 VPS";
  $("#path-server-name").title = region ? region + "（根据入口 IP 查询）" : state.server_ip;
  $("#path-server").textContent = state.server_ip + " : " + state.server_port;
  $("#metric-count").textContent = state.exits.length;
  $("#exit-total").textContent = state.exits.length;
  $("#empty-state").hidden = state.exits.length > 0;
  $("#draft-notice").hidden = !state.dirty;
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
  const transport = state.transport;
  const transportUpdate = transport?.enabled && transport.initial_update_required;
  const updates = [];
  if (transportUpdate) updates.push('首次使用双入口：刷新完整配置订阅，或重新下载并导入一次。保留规则模式，在 STATIC-SELECT 中选择“AUTO · 网页切换”。AUTO 优先尝试 HY2，不可用时使用 REALITY；也可在同组选择“REALITY · TCP兼容”。实际协议请查看客户端连接记录，网页无法确认客户端已更新。');
  if (clientConfig?.fixed_nodes_refresh_required) updates.push('服务器上的固定节点列表与出口草稿有差异。未应用的出口修改尚未进入运行配置；客户端固定节点需在应用后刷新订阅或重新下载。保持 AUTO 后，网页切换出口无需更新。');
  $("#client-config-update").hidden = !state.download_ready || updates.length === 0;
  $("#client-config-update").textContent = updates.join(' ');
  const transportNotice = $('#transport-update-notice');
  transportNotice.hidden = !transport;
  transportNotice.textContent = transport?.enabled ? '本账号配置支持 HY2 优先与 REALITY TCP 兼容。首次使用请刷新完整订阅或重新导入一次，保持 AUTO；之后出口继续通过网页切换。网页不确认客户端当前采用哪种协议。' : transport ? 'HY2 加速入口当前未启用。请继续使用本账号的 REALITY 配置；入口可用状态由服务器提供。' : '';
  transportNotice.classList.toggle('warning',!!transport && !transport.enabled);
  $('#traffic-accounting-note').textContent = '统计本账号经过服务器的' + (transport?.enabled ? ' HY2 与 REALITY 代理流量，两种入口共用本账号的月额度和限速。' : '代理流量。') + '国内 DIRECT 由本机出网，不计入这里。月累计按 UTC 月份结算；曲线保留本页最近 60 次有效采样，断采样处不连线。' + (state.traffic?.connection_scope ? '连接口径：' + state.traffic.connection_scope + '。' : '') + '入口连接数不代表在线设备数。';
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
  renderEnhancements();
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
  if (loginBusy) return;
  loginBusy = true;
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  $('#login-form').setAttribute('aria-busy','true');
  $('#login-submit-label').textContent = '正在验证…';
  $('#login-submit').classList.add('is-loading');
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
    animateChange($('#console'), [{opacity:0,transform:'translateY(8px)'},{opacity:1,transform:'translateY(0)'}],350);
    await refresh();
  } catch (error) { $("#login-error").textContent = error.message;if (!csrf) $('#login-password').focus(); }
  finally { loginBusy = false;button.disabled = false;$('#login-form').removeAttribute('aria-busy');$('#login-submit-label').textContent = '进入控制台';$('#login-submit').classList.remove('is-loading'); }
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

document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => requestView(button.dataset.view)));
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
  if (!await guardDraftTransition()) return;
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

function generateMemberPassword() {
  const random = crypto.getRandomValues(new Uint8Array(24));
  return btoa(String.fromCharCode(...random)).replace(/\+/g,'-').replace(/\//g,'_');
}
function randomRequestId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return [...crypto.getRandomValues(new Uint8Array(16))].map((byte) => byte.toString(16).padStart(2,'0')).join('');
}
function clearMemberDelivery() {
  clearTimeout(deliveryExpiryTimer);
  memberDelivery = null;
  $('#member-delivery').hidden = true;
  for (const selector of ['#delivery-login-url','#delivery-username','#delivery-expiry']) $(selector).textContent = '';
  $('#delivery-password').value = '';
  $('#delivery-password').type = 'password';
  const toggle = $('[data-toggle-password="delivery-password"]');
  toggle.textContent = '显示';toggle.setAttribute('aria-label','显示交付密码');
}
function clearMemberOperations() {
  clearTimeout(taskTimer);
  clearMemberDelivery();
  memberTasks = [];
  memberSecrets.clear();
  completedMemberTasks.clear();
  pendingProvision = null;
  taskLoading = false;
  entrancePool = null;
  entranceDraft = false;
  entranceSaving = false;
  $('#member-task-list').replaceChildren();
  $('#member-task-panel').hidden = true;
  $('#member-task-notice').textContent = '按服务器返回的实际步骤更新。';
  $('#entrances-form').reset();
  $('#entrances-error').textContent = '';
  $('#entrance-allocations').replaceChildren();
  $('#entrances-firewall-text').value = '';
  $('#entrances-status').textContent = '尚未读取资源池';
  $('#entrances-capacity-summary').textContent = '正在读取';
}
function renderEntrancePool() {
  if (currentUser?.role !== 'admin' || !entrancePool) return;
  const available = Math.max(0,Number(entrancePool.available_count) || 0);
  $('#entrances-capacity-summary').textContent = available + ' 个可分配入口';
  $('#entrances-status').textContent = '账号容量 ' + entrancePool.capacity + ' · 已使用 ' + entrancePool.total_users + ' · 公网连接尚未核验';
  if (!entranceDraft) $('#entrances-firewall-text').value = entrancePool.firewall_text || '';
  if (!entranceDraft) $('#entrances-member-ports').value = (entrancePool.member_ports || []).join(', ');
  $('#entrance-allocations').replaceChildren();
  for (const allocation of entrancePool.allocations || []) {
    const card = document.createElement('div');card.className = 'entrance-allocation';
    const port = document.createElement('strong'),status = document.createElement('span');
    port.textContent = allocation.port + ' / TCP + UDP';
    status.textContent = allocation.assigned ? '已分配 · ' + (allocation.username || '成员') : '可分配 · 公网未核验';
    card.classList.toggle('is-assigned',!!allocation.assigned);card.append(port,status);$('#entrance-allocations').append(card);
  }
  const candidates = $('#entrance-candidates');candidates.replaceChildren();
  const selected = new Set((entrancePool.member_ports || []).map(Number));
  for (const port of entrancePool.supported_member_ports || []) {
    if (selected.has(Number(port))) continue;
    const button = document.createElement('button');button.type = 'button';button.className = 'button secondary small';button.textContent = '＋ ' + port;
    button.addEventListener('click',() => {
      const ports = $('#entrances-member-ports').value.split(/[\s,，]+/).filter(Boolean);
      if (!ports.includes(String(port))) ports.push(String(port));
      $('#entrances-member-ports').value = ports.join(', ');entranceDraft = true;$('#entrances-cloud-confirmed').checked = false;renderEntranceDraft();syncLayoutDrafts();
    });
    candidates.append(button);
  }
  $('#save-entrances').disabled = entranceSaving || usersBusy;
}
function renderEntranceDraft() {
  const tokens = $('#entrances-member-ports').value.split(/[\s,，]+/).filter(Boolean);
  const valid = tokens.length && tokens.every((port) => /^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535);
  $('#entrances-firewall-text').value = (entrancePool?.firewall_text || '') + '\n\n本次拟配置成员入口（尚未保存，公网未核验）：\n' + (valid ? [...new Set(tokens.map(Number))].map((port) => 'TCP '+port+' / UDP '+port).join('\n') : '请先填写有效端口，再核对放行清单。');
}
function upsertMemberTask(task) {
  const index = memberTasks.findIndex((item) => item.id === task.id);
  if (index < 0) memberTasks.unshift(task);else memberTasks[index] = task;
}
function renderMemberTasks() {
  if (currentUser?.role !== 'admin') return;
  $('#member-task-panel').hidden = !memberTasks.length;
  const list = $('#member-task-list');list.replaceChildren();
  for (const task of memberTasks.slice(0,10)) {
    const card = document.createElement('article');card.className = 'member-task';card.dataset.status = task.status;
    const heading = document.createElement('div');heading.className = 'member-task-heading';
    const title = document.createElement('strong'),status = document.createElement('span');
    title.textContent = task.user?.username || task.username || memberSecrets.get(task.id)?.username || '成员准备';
    status.textContent = ({queued:'等待处理',running:'正在准备',succeeded:'本机准备完成',failed:'准备未完成'})[task.status] || '状态待确认';
    heading.append(title,status);
    const message = document.createElement('p');message.className = 'operation-status';message.textContent = task.message || task.error || '等待服务器返回进度';
    const steps = document.createElement('ol');steps.className = 'member-task-steps';
    for (const step of task.steps || []) {
      const row = document.createElement('li'),marker = document.createElement('span'),label = document.createElement('span');
      row.dataset.status = step.status;
      const done = ['done','succeeded','completed','complete'].includes(step.status);
      marker.className = 'step-marker';marker.textContent = done ? '✓' : ['failed','error'].includes(step.status) ? '!' : String(steps.children.length+1);
      label.textContent = step.label;row.append(marker,label);steps.append(row);
    }
    card.append(heading,message,steps);
    if (task.status === 'succeeded') {const note = document.createElement('p');note.className = 'field-hint';note.textContent = '配置与本机服务已准备，真实公网 HY2 / REALITY 连接待验证。';card.append(note);}
    if (task.status === 'failed') {
      const error = document.createElement('p');error.className = 'field-error';error.textContent = task.error || '请核对错误原因后重试。';
      const retry = document.createElement('button');retry.type = 'button';retry.className = 'button secondary small';retry.textContent = '返回资料，核对后重试';
      retry.addEventListener('click',() => {$('#create-user-details').open = true;$('#create-username').focus();});card.append(error,retry);
    }
    list.append(card);
  }
}
function processCompletedMemberTasks() {
  for (const task of memberTasks) {
    if (!['succeeded','failed'].includes(task.status) || completedMemberTasks.has(task.id)) continue;
    completedMemberTasks.add(task.id);
    const secret = memberSecrets.get(task.id);memberSecrets.delete(task.id);
    if (task.status === 'succeeded' && secret?.generation === sessionGeneration) {
      clearMemberDelivery();
      memberDelivery = {...secret,expires_at:Date.now()+600000};
      $('#delivery-login-url').textContent = new URL('./',location.href).href;
      $('#delivery-username').textContent = secret.username;
      $('#delivery-password').value = secret.password;
      $('#delivery-expiry').textContent = '本次资料十分钟后自动清除';
      $('#member-delivery').hidden = false;
      animateChange($('#member-delivery'),[{opacity:0,transform:'translateY(8px)'},{opacity:1,transform:'translateY(0)'}],300);
      deliveryExpiryTimer = setTimeout(clearMemberDelivery,600000);
    }
  }
}
async function loadMemberTasks() {
  if (currentUser?.role !== 'admin' || !csrf || taskLoading || document.hidden) return;
  const generation = sessionGeneration;taskLoading = true;
  try {
    const result = await api('users/provision');
    if (generation !== sessionGeneration || currentUser?.role !== 'admin') return;
    for (const task of result.tasks || []) upsertMemberTask(task);
    usersBusy = memberTasks.some((task) => ['queued','running'].includes(task.status));
    $('#member-task-notice').textContent = '按服务器返回的实际步骤更新。刷新后可恢复任务记录；初始密码不会恢复。';
    renderMemberTasks();processCompletedMemberTasks();renderUsers();renderEntrancePool();
    if (!usersBusy) refreshUsers().catch(() => {});
  } catch (error) {
    if (generation === sessionGeneration && currentUser?.role === 'admin') $('#member-task-notice').textContent = '任务状态暂未更新：' + error.message;
  } finally {
    if (generation === sessionGeneration) {taskLoading = false;scheduleMemberTaskPoll();}
  }
}
function scheduleMemberTaskPoll() {
  clearTimeout(taskTimer);
  if (!document.hidden && csrf && currentUser?.role === 'admin' && memberTasks.some((task) => ['queued','running'].includes(task.status))) {
    taskTimer = setTimeout(() => loadMemberTasks().catch(() => {}),1800);
  }
}
for (const select of document.querySelectorAll('[data-motion-setting]')) select.addEventListener('change',(event) => {
  storedMotion = event.target.value === 'off' ? 'off' : 'system';
  try {localStorage.setItem('node-motion-preference',storedMotion);} catch {}
  syncMotion();
});
document.addEventListener('visibilitychange',() => {
  if (memberDelivery && Date.now() >= memberDelivery.expires_at) clearMemberDelivery();
  if (document.hidden) clearTimeout(taskTimer);else if (currentUser?.role === 'admin') loadMemberTasks().catch(() => {});
});
window.addEventListener('pagehide',clearMemberDelivery);
$('#generate-member-password').addEventListener('click',() => {$('#create-user-password').value = generateMemberPassword();$('#create-user-password').type = 'password';syncLayoutDrafts();});
$('#clear-member-delivery').addEventListener('click',clearMemberDelivery);
$('#copy-member-delivery').addEventListener('click',async () => {
  if (!memberDelivery || memberDelivery.generation !== sessionGeneration || currentUser?.role !== 'admin') return;
  if (Date.now() >= memberDelivery.expires_at) {clearMemberDelivery();return;}
  const generation = sessionGeneration;
  try {await navigator.clipboard.writeText('NODE 成员登录资料\n登录地址：'+new URL('./',location.href).href+'\n登录账号：'+memberDelivery.username+'\n初始密码：'+memberDelivery.password+'\n登录后，在“客户端与访问”获取自己的订阅，更新客户端并选择 AUTO · 网页切换。\n本机服务已准备，真实公网 HY2 / REALITY 连接仍需验证。');if (generation === sessionGeneration) toast('交付说明已复制，包含初始密码。');}
  catch {if (generation === sessionGeneration) toast('浏览器无法复制，请展开资料后手动复制。',true);}
});
$('#copy-firewall-text').addEventListener('click',async () => {
  if (!$('#entrances-firewall-text').value) return;
  try {await navigator.clipboard.writeText($('#entrances-firewall-text').value);toast('放行清单已复制，请在云控制台完成设置。');}catch {toast('浏览器无法复制，请手动选择清单复制。',true);}
});
$('#refresh-member-tasks').addEventListener('click',() => loadMemberTasks().catch(() => {}));
for (const [selector,view,target] of [['#quick-add-member','users','#create-user-details'],['#quick-entrances','users','#entrances-details'],['#quick-maintenance','maintenance',null]]) {
  $(selector).addEventListener('click',async () => {if (currentUser?.role !== 'admin') return;await requestView(view);if (currentView !== view || !target) return;$(target).open = true;$(target).scrollIntoView({behavior:reduceMotion() ? 'instant' : 'smooth',block:'start'});});
}
$('#entrances-member-ports').addEventListener('input',() => {entranceDraft = true;$('#entrances-cloud-confirmed').checked = false;renderEntranceDraft();});
$('#entrances-cloud-confirmed').addEventListener('change',() => {entranceDraft = true;});
$('#entrances-form').addEventListener('submit',async (event) => {
  event.preventDefault();
  if (currentUser?.role !== 'admin' || entranceSaving || usersBusy) return;
  const generation = sessionGeneration;$('#entrances-error').textContent = '';
  try {
    const tokens = $('#entrances-member-ports').value.split(/[\s,，]+/).filter(Boolean);
    if (!tokens.length || tokens.some((port) => !/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535)) throw new Error('请输入 1–65535 范围内的整数端口，用逗号分隔。');
    const ports = tokens.map(Number);if (new Set(ports).size !== ports.length) throw new Error('清单中有重复端口，请核对。');
    if (entrancePool?.supported_member_ports?.length && ports.some((port) => !entrancePool.supported_member_ports.map(Number).includes(port))) throw new Error('清单含有未受服务器支持的端口，请使用下方候选端口并保留已分配入口。');
    if (!$('#entrances-cloud-confirmed').checked) throw new Error('请先完成云安全组放行，再勾选声明。');
    entranceSaving = true;renderEntrancePool();
    const result = await api('entrances/configure',{member_ports:ports,cloud_confirmed:true});
    if (generation !== sessionGeneration || currentUser?.role !== 'admin') return;
    entrancePool = result.entrances;entranceDraft = false;$('#entrances-cloud-confirmed').checked = false;
    renderEntrancePool();await refreshUsers();toast('资源池已保存。公网连接尚未核验。');
  } catch (error) {if (generation === sessionGeneration) $('#entrances-error').textContent = error.message;}
  finally {if (generation === sessionGeneration) {entranceSaving = false;renderEntrancePool();}}
});
syncMotion();

$("#refresh-users").addEventListener("click", () => refreshUsers().catch(() => {}));
$("#create-user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (usersBusy || currentUser?.role !== "admin") return;
  const generation = sessionGeneration;
  $("#create-user-error").textContent = "";
  try {
    const username = $("#create-username").value.trim();
    const display_name = $("#create-display-name").value.trim();
    const password = $("#create-user-password").value || generateMemberPassword();
    if (!/^[a-z][a-z0-9_-]{2,23}$/.test(username)) throw new Error("账号需为 3–24 个字符，以小写字母开头，只能使用小写字母、数字、下划线或短横线。");
    if (display_name.length > 48) throw new Error("显示名称最多 48 个字符。");
    validateUserPassword(password);
    $('#create-user-password').value = password;
    usersBusy = true;
    renderUsers();
    if (!pendingProvision || pendingProvision.username !== username || pendingProvision.display_name !== display_name || pendingProvision.password !== password) {
      pendingProvision = {username,display_name,password,request_id:randomRequestId()};
    }
    const result = await api("users/provision", {...pendingProvision,display_name:display_name || username});
    if (generation !== sessionGeneration) return;
    if (!result.task?.id) throw new Error('服务器没有返回准备任务，请刷新任务记录后重试。');
    completedMemberTasks.delete(result.task.id);
    memberSecrets.set(result.task.id,{username,display_name:display_name || username,password,generation});
    pendingProvision = null;
    upsertMemberTask(result.task);
    $("#create-user-form").reset();
    $('#create-user-password').type = 'password';
    renderMemberTasks();
    processCompletedMemberTasks();
    scheduleMemberTaskPoll();
    if (['succeeded','failed'].includes(result.task.status)) await refreshUsers();
    toast('已提交成员准备任务。请在下方查看实际进度。');
  } catch (error) {
    if (generation === sessionGeneration) $("#create-user-error").textContent = error.message;
  } finally {
    if (generation === sessionGeneration) {
      usersBusy = memberTasks.some((task) => ['queued','running'].includes(task.status));
      renderUsers();
    }
  }
});

$("#user-list").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-user-action]");
  if (!button || usersBusy || currentUser?.role !== "admin") return;
  const user = users.find((item) => item.id === button.closest(".user-card").dataset.userId);
  if (!user || (user.role === "admin" && button.dataset.userAction !== "limits")) return;
  if (['limits','rotate','delete'].includes(button.dataset.userAction)) return enhancedUserAction(user,button.dataset.userAction);
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
  await saveRouting();
});

async function saveRouting() {
  const generation = sessionGeneration;
  const mode = $("#routing-mode").value;
  const modeChanged = mode !== (state?.routing_mode || "manual");
  const domains = $("#domains").value.split(/\r?\n/);
  const directDomains = $("#direct-domains").value.split(/\r?\n/);
  const save = $("#routing-form button[type='submit']");
  save.disabled = true;
  try {
    const result = await api("routing", {domains,direct_domains:directDomains,mode});
    if (generation !== sessionGeneration || !csrf) return false;
    await refresh();
    if (generation !== sessionGeneration || !csrf || !state) return false;
    $("#domains").value = (state.domains || []).join("\n");
    $("#direct-domains").value = (state.direct_domains || []).join("\n");
    renderRoutingMode();
    const extracted = domains.filter((line) => line.trim()).join("\n") !== $("#domains").value || directDomains.filter((line) => line.trim()).join("\n") !== $("#direct-domains").value;
    const saved = extracted ? "分流规则已保存，列表已提取并整理为域名。" : "分流规则已保存。";
    const subscription = state.routing_subscription || result.routing_subscription;
    const interval = Math.max(1, Math.ceil((subscription?.interval || 300) / 60));
    toast(saved + (!result.download_ready ? "先点击服务器或一个静态出口，再下载并导入配置。" : modeChanged ? "分流方案已更改，请下载并导入配置一次，使用规则模式后生效。" : mode === "smart" && subscription?.enabled ? "已导入智能分流配置的客户端约 " + interval + " 分钟自动同步；立即生效可刷新客户端规则集。" : "请下载并导入更新后的配置，使用规则模式后生效。"));
    return true;
  }
  catch (error) { if (generation === sessionGeneration && csrf) toast(error.message, true);return false; }
  finally { save.disabled = false; }
}

function renderRoutingMode() {
  const mode = $("#routing-mode").value;
  const services = mode === "services";
  const smart = mode === "smart";
  $("#routing-service-summary").hidden = !services;
  $("#routing-smart-summary").hidden = !smart;
  $('#routing-manual-explanation').hidden = smart || services;
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
  const form = event.currentTarget;
  const generation = sessionGeneration;
  layoutFormError(form,'');
  if ($("#new-password").value !== $("#confirm-password").value) {layoutFormError(form,'两次输入的新密码不一致。');return toast("两次输入的新密码不一致。", true);}
  try {
    await api("password", {current:$("#current-password").value,new:$("#new-password").value});
    if (generation !== sessionGeneration) return;
    $("#password-form").reset();
    showLogin();
    toast("密码已更新，请使用新密码重新登录。");
  } catch (error) { if (generation === sessionGeneration) {layoutFormError(form,error.message);toast(error.message, true);} }
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

function hasRoutingDraft() {
  return routingReady && currentView === 'routing' && state && ($('#domains').value !== (state.domains || []).join('\n') || $('#direct-domains').value !== (state.direct_domains || []).join('\n') || $('#routing-mode').value !== (state.routing_mode || 'manual'));
}
function hasPasswordDraft() {return (currentView === 'access' && ['#current-password','#new-password','#confirm-password'].some((selector) => $(selector).value)) || (currentView === 'maintenance' && (['#backup-password','#backup-password-confirm','#restore-password'].some((selector) => $(selector).value) || $('#backup-file').files.length > 0));}
function hasMemberDraft() {return currentView === 'users' && (entranceDraft || ['#create-username','#create-display-name','#create-user-password'].some((selector) => $(selector).value));}
function discardRoutingDraft() {
  if (!state) return;
  $('#domains').value = (state.domains || []).join('\n');$('#direct-domains').value = (state.direct_domains || []).join('\n');$('#routing-mode').value = state.routing_mode || 'manual';renderRoutingMode();
}
async function guardDraftTransition() {
  const routing = hasRoutingDraft(), password = hasPasswordDraft(),member = hasMemberDraft();
  if (!routing && !password && !member) return true;
  if (draftPromptBusy) return false;
  draftPromptBusy = true;
  const generation = sessionGeneration;
  const dialog = $('#draft-dialog');
  $('#draft-dialog-message').textContent = member ? '成员资料或端口资源池有未提交的修改。可以继续编辑，或放弃草稿后离开；离开不会自动创建成员或放行端口。' : password ? '密码或备份文件还未提交。内容只暂存于本页；可放弃后继续，或继续编辑。教程与导航不会自动提交密码、创建备份或上传文件。' : '分流规则有未保存的修改。可以保存成功后继续、放弃修改，或留在本页继续编辑。';
  $('#draft-save').hidden = password || member;
  const choice = await new Promise((resolve) => {
    dialog.addEventListener('close', () => resolve(dialog.returnValue), {once:true});
    dialog.returnValue = 'stay';dialog.showModal();$('#draft-stay').focus();
  });
  draftPromptBusy = false;
  if (generation !== sessionGeneration) return false;
  if (choice === 'discard') {if (routing) discardRoutingDraft();if (password) {$('#password-form').reset();$('#backup-create-form').reset();$('#backup-preview-form').reset();}if (member) {$('#create-user-form').reset();$('#entrances-form').reset();entranceDraft = false;pendingProvision = null;renderEntrancePool();}return true;}
  return choice === 'save' && routing ? await saveRouting() : false;
}
async function requestView(name) {if (name === currentView) return;if (await guardDraftTransition()) switchView(name);}
for (const [selector,value] of [['#draft-save','save'],['#draft-discard','discard'],['#draft-stay','stay']]) $(selector).addEventListener('click',() => $('#draft-dialog').close(value));
window.addEventListener('beforeunload', (event) => {
  const secret = ['#exit-user','#exit-password','#exit-socks-link','#create-user-password','#reset-user-password','#backup-password','#restore-password','#export-password'].some((selector) => $(selector)?.value);
  if (csrf && (hasRoutingDraft() || hasPasswordDraft() || hasMemberDraft() || secret || memberDelivery)) {event.preventDefault();event.returnValue = '';}
});

function bytes(value) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return '未知';
  const number = Math.max(0,Number(value));const units = ['B','KB','MB','GB','TB'];let scaled = number,index = 0;
  while (scaled >= 1000 && index < units.length-1) {scaled /= 1000;index++;}
  return scaled.toFixed(index ? 2 : 0) + ' ' + units[index];
}
function time(value) {return value ? date(value) : '尚无记录';}
function facts(element,rows) {
  element.replaceChildren();for (const [label,value] of rows) {const row = document.createElement('div'),term = document.createElement('dt'),description = document.createElement('dd');term.textContent = label;description.textContent = String(value ?? '未知');row.append(term,description);element.append(row);}
}
function trafficSummary(value) {
  if (!value) return '用量统计暂不可用';
  let summary = (value.month || '本月') + '已记录 ' + bytes(recordedTraffic(value)) + (validTrafficValue(value.quota_bytes) ? Number(value.quota_bytes) > 0 ? ' / ' + bytes(value.quota_bytes) : ' · 额度不限' : ' · 额度未知');
  if (value.available !== true) summary += ' · 实时统计不可用：' + (value.reason || '尚未提供有效采样');
  if (value.over_quota) summary += ' · 月额度已到，代理入口' + (value.quota_enforced ? '已阻断' : '尚未阻断');
  else if (value.notice) summary += ' · ' + value.notice;
  if (value.enforcement_error) summary += ' · ' + value.enforcement_error;
  return summary;
}
function validTrafficValue(value) {return value !== null && value !== undefined && value !== '' && Number.isFinite(Number(value)) && Number(value) >= 0;}
function recordedTraffic(value) {
  if (validTrafficValue(value?.total_bytes)) return Number(value.total_bytes);
  return validTrafficValue(value?.up_bytes) && validTrafficValue(value?.down_bytes) ? Number(value.up_bytes) + Number(value.down_bytes) : null;
}
function resetTrafficHistory() {
  trafficSamples = [];trafficSampleKey = null;trafficGapPending = false;trafficInspectedAt = null;
}
function trafficRate(value) {return validTrafficValue(value) ? bytes(value) + '/s' : '统计不可用';}
function trafficSampleTime(at) {
  return new Intl.DateTimeFormat('zh-CN',{timeZone:'Asia/Shanghai',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}).format(new Date(at));
}
function trafficSampleStatus(value) {
  const at = value?.sampled_at ? Date.parse(value.sampled_at) : NaN;
  if (value?.available !== true) return {realtime:false,at,reason:value?.reason || '尚未提供有效采样'};
  if (!Number.isFinite(at)) return {realtime:false,at,reason:'有效采样时间未知'};
  const samplingSeconds = validTrafficValue(value.sampling_seconds) && Number(value.sampling_seconds) > 0 ? Number(value.sampling_seconds) : 10;
  if (at-Date.now() > 30000) return {realtime:false,at,reason:'服务器采样时间超前，请核对时钟'};
  if (Date.now()-at > Math.max(30000,samplingSeconds*3000)) return {realtime:false,at,reason:'实时采样已过期'};
  return {realtime:true,at,reason:''};
}
function captureTrafficSample(value) {
  const identity = sessionGeneration + ':' + (currentUser?.id || currentUser?.username || '') + ':' + (value?.month || '');
  if (trafficSampleKey !== identity) {resetTrafficHistory();trafficSampleKey = identity;}
  const at = value?.sampled_at ? Date.parse(value.sampled_at) : NaN;
  const up = validTrafficValue(value?.up_rate) ? Number(value.up_rate) : null;
  const down = validTrafficValue(value?.down_rate) ? Number(value.down_rate) : null;
  if (!trafficSampleStatus(value).realtime || (up === null && down === null)) {trafficGapPending = true;return;}
  const previous = trafficSamples.at(-1);
  if (previous && at <= previous.at) return;
  const samplingSeconds = validTrafficValue(value.sampling_seconds) && Number(value.sampling_seconds) > 0 ? Number(value.sampling_seconds) : 10;
  trafficSamples.push({at,up,down,breakBefore:trafficGapPending || !!previous && at-previous.at > Math.max(30000,samplingSeconds*3000)});
  trafficSamples = trafficSamples.slice(-60);trafficGapPending = false;
}
function trafficSvg(tag,attributes = {},content) {
  const element = document.createElementNS('http://www.w3.org/2000/svg',tag);
  for (const [name,value] of Object.entries(attributes)) element.setAttribute(name,String(value));
  if (content !== undefined) element.textContent = content;
  return element;
}
function trafficSampleDescription(sample,series) {
  const timestamp = new Intl.DateTimeFormat('zh-CN',{timeZone:'Asia/Shanghai',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}).format(new Date(sample.at));
  return timestamp + ' · ' + (series === 'up' ? '上传速度 ' : '下载速度 ') + trafficRate(sample[series]);
}
function showTrafficSample(sample) {
  const index = sample ? trafficSamples.indexOf(sample) : -1;
  $('#traffic-sample-prev').disabled = index <= 0;$('#traffic-sample-next').disabled = index < 0 || index >= trafficSamples.length-1;$('#traffic-sample-latest').disabled = !sample || index === trafficSamples.length-1 && trafficInspectedAt === null;
  if (!sample) {$('#traffic-chart-readout').textContent = '暂无采样明细';return;}
  $('#traffic-chart-readout').textContent = trafficSampleTime(sample.at) + ' · 上传 ' + trafficRate(sample.up) + ' · 下载 ' + trafficRate(sample.down);
}
function renderTrafficRateChart(value) {
  const svg = $('#traffic-rate-chart'),lines = $('#traffic-rate-lines'),points = $('#traffic-rate-points'),axis = $('#traffic-rate-axis');
  const active = document.activeElement,focused = points.contains(active) && active.dataset.trafficSample ? active.dataset.series + ':' + active.dataset.trafficSample : null;
  lines.replaceChildren();points.replaceChildren();axis.replaceChildren();
  svg.dataset.sampleCount = String(trafficSamples.length);
  const sampleStatus = trafficSampleStatus(value),realtime = sampleStatus.realtime,last = trafficSamples.at(-1);
  $('#traffic-sample-count').textContent = trafficSamples.length ? trafficSamples.length + ' 次有效采样' : '尚无采样';
  $('#traffic-chart-empty').toggleAttribute('hidden',trafficSamples.length > 0);
  if (!trafficSamples.length) {
    $('#traffic-chart-empty').textContent = realtime ? '正在收集速率采样' : '等待有效速率采样';
    $('#traffic-chart-status').textContent = realtime ? '服务器尚未提供带时间戳的有效速率采样。曲线从本次打开页面开始记录。' : sampleStatus.reason + '；已记录的月累计仍保留。曲线从打开页面开始收集。';
    showTrafficSample(null);return;
  }
  const observedMax = Math.max(...trafficSamples.flatMap((sample) => [sample.up ?? 0,sample.down ?? 0]));
  const maximum = observedMax > 0 ? observedMax*1.15 : 1;
  const first = trafficSamples[0],duration = last.at-first.at;
  const x = (sample) => duration > 0 ? 64 + (sample.at-first.at)/duration*416 : 272;
  const y = (rate) => 142-rate/maximum*122;
  for (const [position,label] of [[24,observedMax ? trafficRate(maximum) : '0 B/s'],[85,observedMax ? trafficRate(maximum/2) : '0 B/s'],[146,'0 B/s']]) axis.append(trafficSvg('text',{x:2,y:position},label));
  axis.append(trafficSvg('text',{x:64,y:173,'text-anchor':'start'},trafficSampleTime(first.at)));
  if (duration > 0) axis.append(trafficSvg('text',{x:480,y:173,'text-anchor':'end'},trafficSampleTime(last.at)));
  for (const series of ['up','down']) {
    let segment = [];
    const finishSegment = () => {
      if (segment.length > 1) lines.append(trafficSvg('path',{d:segment.map((sample,index) => (index ? 'L' : 'M') + x(sample).toFixed(2) + ' ' + y(sample[series]).toFixed(2)).join(' '),class:'traffic-rate-line traffic-series-' + series,'data-series':series}));
      segment = [];
    };
    trafficSamples.forEach((sample,index) => {
      if (sample.breakBefore || sample[series] === null) finishSegment();
      if (sample[series] === null) return;
      segment.push(sample);
      const point = trafficSvg('circle',{cx:x(sample).toFixed(2),cy:y(sample[series]).toFixed(2),r:3.8,class:'traffic-rate-point traffic-series-' + series,tabindex:-1,role:'button','aria-label':trafficSampleDescription(sample,series),'data-traffic-sample':sample.at,'data-series':series,'data-index':index});
      point.append(trafficSvg('title',{},trafficSampleDescription(sample,series)));points.append(point);
    });
    finishSegment();
  }
  const focusPoint = focused ? [...points.children].find((point) => point.dataset.series + ':' + point.dataset.trafficSample === focused) : null;
  const entryPoint = focusPoint || points.lastElementChild;
  if (entryPoint) entryPoint.setAttribute('tabindex','0');
  if (focusPoint) {focusPoint.focus({preventScroll:true});showTrafficSample(trafficSamples[Number(focusPoint.dataset.index)]);}else showTrafficSample(trafficSamples.find((sample) => sample.at === trafficInspectedAt) || last);
  const gap = trafficSamples.slice(1).some((sample) => sample.breakBefore || sample.up === null || sample.down === null);
  $('#traffic-chart-status').textContent = !realtime ? sampleStatus.reason + '；保留此前真实采样，恢复后从新采样继续。' : trafficSamples.length === 1 ? '已读取 1 次真实采样，等待下一次形成曲线；不会补绘打开页面前的历史。' : '仅展示本页收集的真实采样，约每 12 秒读取；服务器采样间隔约 ' + (validTrafficValue(value?.sampling_seconds) && Number(value.sampling_seconds) > 0 ? Number(value.sampling_seconds) : 10) + ' 秒。' + (gap ? ' 断采样处未连线。' : '');
}
function renderTrafficDashboard(value) {
  captureTrafficSample(value);
  const recorded = recordedTraffic(value),up = validTrafficValue(value?.up_bytes) ? Number(value.up_bytes) : null,down = validTrafficValue(value?.down_bytes) ? Number(value.down_bytes) : null;
  const splitReady = up !== null && down !== null && Number.isFinite(up+down),splitTotal = splitReady ? up+down : null;
  const sampleStatus = trafficSampleStatus(value);
  $('#traffic-summary').textContent = value ? trafficSummary(value) + (value.available === true && !sampleStatus.realtime ? ' · ' + sampleStatus.reason : '') : '用量统计尚未提供';
  $('#traffic-summary').classList.toggle('warning',!!value && (!sampleStatus.realtime || !!value.over_quota || !!value.notice || !!value.enforcement_error));
  $('#traffic-sampled-at').textContent = '最近服务器采样：' + (Number.isFinite(sampleStatus.at) ? date(sampleStatus.at) + ' (' + trafficSampleTime(sampleStatus.at) + ')' : '尚无有效时间') + (!sampleStatus.realtime && value ? ' · ' + sampleStatus.reason : '');
  $('#traffic-total').textContent = recorded === null ? '未知' : bytes(recorded);
  $('#traffic-month').textContent = (value?.month || '本月') + ' · UTC';
  $('#traffic-up-total').textContent = up === null ? '未知' : bytes(up);$('#traffic-down-total').textContent = down === null ? '未知' : bytes(down);
  const donut = $('#traffic-donut');donut.dataset.state = !splitReady ? 'unknown' : splitTotal === 0 ? 'empty' : 'ready';
  for (const [series,total] of [['up',up],['down',down]]) {
    const share = splitReady && splitTotal > 0 ? total/splitTotal*100 : null;
    $('#traffic-' + series + '-share').textContent = share === null ? splitReady ? '暂无已记录流量' : '占比未知' : share.toFixed(1) + '%';
    const arc = $('#traffic-donut-' + series);arc.toggleAttribute('hidden',share === null || share === 0);
    arc.setAttribute('stroke-dasharray',share === null ? '0 100' : share + ' ' + (100-share));
    if (series === 'down') arc.setAttribute('stroke-dashoffset',splitReady && splitTotal > 0 ? String(-up/splitTotal*100) : '0');
  }
  $('#traffic-mix-description').textContent = !splitReady ? '上传或下载明细未知，不绘制占比；月累计已记录 ' + (recorded === null ? '未知' : bytes(recorded)) : splitTotal === 0 ? '上传与下载均为 0 B，暂无已记录流量。' : '上传 ' + bytes(up) + '，占 ' + (up/splitTotal*100).toFixed(1) + '%；下载 ' + bytes(down) + '，占 ' + (down/splitTotal*100).toFixed(1) + '%。';
  const realtime = sampleStatus.realtime;
  $('#traffic-connections').textContent = realtime && validTrafficValue(value.connections) ? String(value.connections) : '统计不可用';
  $('#traffic-up-rate').textContent = realtime ? trafficRate(value.up_rate) : '统计不可用';$('#traffic-down-rate').textContent = realtime ? trafficRate(value.down_rate) : '统计不可用';
  const rate = validTrafficValue(value?.rate_bps) ? Number(value.rate_bps) : null;
  $('#traffic-rate-limit').textContent = rate === null ? '未知' : rate === 0 ? '不限速' : (rate/1e6).toFixed(2) + ' Mbps';
  $('#traffic-rate-state').textContent = rate === null ? '限速状态未知' : rate === 0 ? '未设置限速' : value.rate_enforced ? '限速已执行' : '限速尚未执行';
  const quota = validTrafficValue(value?.quota_bytes) ? Number(value.quota_bytes) : null,progress = $('#traffic-quota-progress');
  const percentage = quota !== null && quota > 0 && recorded !== null ? recorded/quota*100 : null;
  progress.hidden = percentage === null;progress.value = percentage === null ? 0 : Math.min(100,percentage);progress.classList.toggle('near-quota',percentage !== null && percentage >= 80);progress.classList.toggle('over-quota',!!value?.over_quota);
  if (percentage === null) progress.removeAttribute('aria-valuetext');else progress.setAttribute('aria-valuetext','本月已用 ' + percentage.toFixed(1) + '%，' + bytes(recorded) + ' / ' + bytes(quota));
  $('#traffic-quota-label').textContent = quota === null ? '额度未知' : quota === 0 ? '不限额度' : percentage === null ? bytes(quota) + ' · 用量未知' : percentage.toFixed(1) + '% · ' + bytes(quota);
  $('#traffic-quota-state').textContent = quota === null ? '服务器尚未提供额度设置。' : quota === 0 ? '未设置月额度，当前无额度限制。' : value.over_quota ? '额度已到 · ' + (value.quota_enforced ? '代理入口已阻断' : '代理入口尚未阻断') : recorded === null ? '用量未知，无法判断额度是否到达。' : value.quota_enforced ? '额度限制已执行 · 剩余 ' + bytes(Math.max(0,quota-recorded)) : '额度尚未达到 · 剩余 ' + bytes(Math.max(0,quota-recorded));
  $('#traffic-quota-state').classList.toggle('warning',!!value?.over_quota);
  renderTrafficRateChart(value);
}
$('#traffic-rate-points').addEventListener('focusin',(event) => {
  const point = event.target.closest('[data-traffic-sample]');if (point) {trafficInspectedAt = Number(point.dataset.trafficSample);showTrafficSample(trafficSamples[Number(point.dataset.index)]);}
});
$('#traffic-rate-points').addEventListener('pointerover',(event) => {
  const point = event.target.closest('[data-traffic-sample]');if (point) showTrafficSample(trafficSamples[Number(point.dataset.index)]);
});
$('#traffic-rate-points').addEventListener('pointerleave',() => {
  const focused = document.activeElement;showTrafficSample(focused?.dataset.trafficSample ? trafficSamples[Number(focused.dataset.index)] : trafficSamples.find((sample) => sample.at === trafficInspectedAt) || trafficSamples.at(-1));
});
$('#traffic-rate-points').addEventListener('click',(event) => {
  const point = event.target.closest('[data-traffic-sample]');if (!point) return;
  for (const other of $('#traffic-rate-points').children) other.setAttribute('tabindex',other === point ? '0' : '-1');
  point.focus({preventScroll:true});showTrafficSample(trafficSamples[Number(point.dataset.index)]);
});
$('#traffic-rate-points').addEventListener('keydown',(event) => {
  const point = event.target.closest('[data-traffic-sample]');if (!point || !['ArrowLeft','ArrowRight','ArrowUp','ArrowDown','Home','End','Enter',' '].includes(event.key)) return;
  event.preventDefault();
  if (event.key === 'Enter' || event.key === ' ') {showTrafficSample(trafficSamples[Number(point.dataset.index)]);return;}
  const points = [...$('#traffic-rate-points').children],seriesPoints = points.filter((other) => other.dataset.series === point.dataset.series),index = seriesPoints.indexOf(point);
  const next = event.key === 'Home' ? seriesPoints[0] : event.key === 'End' ? seriesPoints.at(-1) : event.key === 'ArrowLeft' ? seriesPoints[Math.max(0,index-1)] : event.key === 'ArrowRight' ? seriesPoints[Math.min(seriesPoints.length-1,index+1)] : points.find((other) => other.dataset.trafficSample === point.dataset.trafficSample && other.dataset.series !== point.dataset.series);
  if (next) {for (const other of points) other.setAttribute('tabindex',other === next ? '0' : '-1');next.focus({preventScroll:true});}
});
for (const [selector,offset] of [['#traffic-sample-prev',-1],['#traffic-sample-next',1]]) $(selector).addEventListener('click',() => {
  const inspected = trafficSamples.findIndex((sample) => sample.at === trafficInspectedAt),index = inspected < 0 ? trafficSamples.length-1 : inspected;
  const sample = trafficSamples[Math.max(0,Math.min(trafficSamples.length-1,index+offset))];
  if (sample) {trafficInspectedAt = sample.at;showTrafficSample(sample);}
});
$('#traffic-sample-latest').addEventListener('click',() => {trafficInspectedAt = null;showTrafficSample(trafficSamples.at(-1));});
document.addEventListener('visibilitychange',() => {if (csrf && state) renderTrafficDashboard(state.traffic);});
function renderServerTraffic() {
  const summary = $('#users-traffic-summary'),element = $('#users-traffic-facts');
  if (!users.length) {summary.textContent = usersLoading ? '正在读取所有账号的用量' : '尚未读取账号用量';element.replaceChildren();return;}
  const samples = users.map((user) => user.traffic),months = [...new Set(samples.map((sample) => sample?.month).filter(Boolean))];
  const recorded = samples.map(recordedTraffic),totalReady = recorded.every(validTrafficValue) && months.length === 1;
  const available = samples.filter((sample) => sample?.available === true).length;
  const sum = (key) => samples.every((sample) => sample?.available === true && validTrafficValue(sample[key])) ? samples.reduce((total,sample) => total + Number(sample[key]),0) : null;
  const connections = sum('connections'),up = sum('up_rate'),down = sum('down_rate');
  summary.textContent = users.length + ' 个账号 · ' + (months.length === 1 ? months[0] : '本月') + '已记录代理用量 ' + (totalReady ? bytes(recorded.reduce((total,value) => total + value,0)) : '未知') + ' · 实时统计 ' + available + ' / ' + users.length + ' 个账号可用';
  const alerts = samples.filter((sample) => sample?.notice || sample?.over_quota).length,failures = samples.filter((sample) => sample?.enforcement_error).length;
  if (alerts) summary.textContent += ' · ' + alerts + ' 个账号有额度提醒';
  if (failures) summary.textContent += ' · ' + failures + ' 个账号限额执行失败：' + [...new Set(samples.map((sample) => sample?.enforcement_error).filter(Boolean))].join('；');
  summary.classList.toggle('warning',available < users.length || alerts > 0 || failures > 0);
  facts(element,[['全账号月累计',totalReady ? bytes(recorded.reduce((total,value) => total + value,0)) : '未知'],['总当前连接',connections === null ? '统计不可用' : connections],['总上传速度',up === null ? '统计不可用' : bytes(up) + '/s'],['总下载速度',down === null ? '统计不可用' : bytes(down) + '/s']]);
}
function renderUserTraffic(element,value) {
  const summary = element.querySelector('.user-usage-summary'),details = element.querySelector('.user-traffic-facts');
  if (!value) {summary.textContent = '用量统计尚未提供';summary.classList.remove('warning');details.replaceChildren();return;}
  const realtime = value.available === true,monthly = recordedTraffic(value);
  summary.textContent = trafficSummary(value);
  summary.classList.toggle('warning',!realtime || !!value.over_quota || !!value.notice || !!value.enforcement_error);
  const quota = validTrafficValue(value.quota_bytes) ? Number(value.quota_bytes) : null,rate = validTrafficValue(value.rate_bps) ? Number(value.rate_bps) : null;
  const quotaStatus = quota === null ? '未知' : quota === 0 ? '未设置额度' : value.over_quota ? value.quota_enforced ? '额度已到，已阻断' : '额度已到，尚未阻断' : '尚未达到额度';
  const rateStatus = rate === null ? '未知' : rate === 0 ? '未设置限速' : value.rate_enforced ? '已执行' : '尚未执行';
  facts(details,[['本月已记录',monthly === null ? '未知' : bytes(monthly)],['月额度',quota === null ? '未知' : quota === 0 ? '不限制' : bytes(quota)],['当前连接',realtime && validTrafficValue(value.connections) ? value.connections : '统计不可用'],['最高速度',rate === null ? '未知' : rate === 0 ? '不限制' : (rate/1e6).toFixed(2) + ' Mbps'],['上传速度',realtime && validTrafficValue(value.up_rate) ? bytes(value.up_rate) + '/s' : '统计不可用'],['下载速度',realtime && validTrafficValue(value.down_rate) ? bytes(value.down_rate) + '/s' : '统计不可用'],['额度状态',quotaStatus],['限速状态',rateStatus]]);
}
function renderEnhancements() {
  if (!state) return;
  const health = state.health || {},settings = health.settings || health;
  const status = health.checking ? 'checking' : health.status || 'unknown';
  $('#health-summary').textContent = ({healthy:'最近检查通过',ok:'最近检查通过',failed:'最近检查失败',unhealthy:'出口出现故障',checking:'正在检查',unknown:'尚未完成出口检查',unavailable:'健康检查暂不可用'})[status] || String(health.message || status);
  if (health.message) $('#health-summary').textContent += ' · ' + health.message;
  $('#check-health').disabled = !!health.checking;
  $('#health-summary').classList.toggle('warning',Number(health.consecutive_failures || 0) > 0);
  facts($('#health-facts'),[['最近检查',time(health.last_checked_at || health.last_check)],['最近成功',time(health.last_success_at || health.last_success)],['连续失败',health.consecutive_failures || 0],['故障处理',(settings.mode || 'manual') === 'auto' ? '自动切换到指定备用' : '仅提醒，手动切换']]);
  const form = $('#health-settings-form');
  if (!form.dataset.dirty) {
    $('#health-mode').value = settings.mode || 'manual';
    const fallback = $('#health-fallback');fallback.replaceChildren();
    for (const [id,name] of [['','请选择备用出口'],['server','服务器自身出口'],...state.exits.map((exit) => [exit.id,exit.name])]) {const option = document.createElement('option');option.value = id;option.textContent = name;fallback.append(option);}
    fallback.value = settings.fallback_exit_id || '';
  }
  const configuredFallback = settings.fallback_exit_id === 'server' ? '服务器自身出口' : state.exits.find((exit) => exit.id === settings.fallback_exit_id)?.name || '备用出口未指定';
  $('#health-settings-summary').textContent = (settings.mode || 'manual') === 'auto' ? '自动备用 · ' + configuredFallback : '仅提醒，手动切换';
  syncLayoutDrafts();
  renderTrafficDashboard(state.traffic);
  const pending = state.exits.filter((exit) => exit.pending).map((exit) => exit.name + '：已保存，尚未应用。' + (exit.active ? '当前连接使用上一次应用的资料。' : '点击此出口检测并应用。'));
  if (state.active && !state.exits.some((exit) => exit.id === state.active.id)) pending.push(state.active.name + '：已从草稿删除，当前连接仍使用它；应用服务器或其他出口后路径才改变。');
  $('#pending-exit-list').replaceChildren();for (const message of pending) {const row = document.createElement('p');row.textContent = message;$('#pending-exit-list').append(row);}
  $('#pending-exit-list').hidden = pending.length === 0;
  if (state.subscription) renderSubscription(state.subscription);
}
function renderSubscription(value) {
  subscription = value;
  $('#subscription-url').value = value.url || '';
  $('#subscription-version').textContent = '服务器配置版本 ' + (value.version ?? '未知') + ' · 更新于 ' + time(value.updated) + '。客户端是否已刷新或导入，网页无法确认。';
  $('#copy-subscription').disabled = !value.url || !value.download_ready;
}
async function loadSubscription() {
  const generation = sessionGeneration;const value = await api('subscription');if (generation === sessionGeneration && csrf) renderSubscription(value);
}
async function loadAudit(admin = false) {
  if (admin && currentUser?.role !== 'admin') return;
  const generation = sessionGeneration;const element = $(admin ? '#admin-audit-list' : '#audit-list');
  const result = await api('audit?limit=50');if (generation !== sessionGeneration || !csrf) return;
  element.replaceChildren();
  const events = admin || currentUser.role !== 'admin' ? result.events || [] : (result.events || []).filter((item) => !item.actor || item.actor === currentUser.username);
  if (!events.length) {element.textContent = '暂无操作记录';return;}
  for (const event of events) {const row = document.createElement('article'),heading = document.createElement('strong'),detail = document.createElement('p'),stamp = document.createElement('small');row.className = 'audit-entry';row.classList.toggle('failed',['failed','failure','error'].includes(event.status));heading.textContent = event.summary || event.action || '操作';detail.textContent = [event.actor,event.action,event.status].filter(Boolean).join(' · ');stamp.textContent = time(event.at);row.append(heading,detail,stamp);element.append(row);}
}
async function loadEnhancementView(name) {
  const key = sessionGeneration + ':' + name;if (enhancementLoading.has(key)) return;enhancementLoading.add(key);
  try {
    const results = await Promise.allSettled(name === 'access' ? [loadSubscription(),loadAudit()] : currentUser?.role === 'admin' ? [loadBackups(),loadAudit(true)] : []);
    for (const result of results) if (result.status === 'rejected' && csrf) toast(result.reason.message,true);
  } finally {enhancementLoading.delete(key);}
}
$('#health-settings-form').addEventListener('input',() => {$('#health-settings-form').dataset.dirty = 'true';});
$('#health-settings-form').addEventListener('submit',async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  layoutFormError(form,'');
  const mode = $('#health-mode').value,fallback = $('#health-fallback').value;
  if (mode === 'auto' && !fallback) {layoutFormError(form,'请明确选择自动切换的备用出口。');return toast('请明确选择自动切换的备用出口。',true);}
  if (mode === 'auto' && !await confirmAction('启用自动备用出口？','连续失败后，本账号会切换到你指定的备用出口，出网 IP 可能变化。','启用自动切换')) return;
  await enhancedMutation(form,'health/settings',{mode,fallback_exit_id:fallback || null,interval_seconds:300,threshold:3},'故障处理设置已保存。',() => {delete form.dataset.dirty;});
});
$('#check-health').addEventListener('click',async () => {
  const button = $('#check-health'),generation = sessionGeneration;if (button.disabled) return;button.disabled = true;
  try {const result = await api('health/check',{});if (generation !== sessionGeneration || !csrf) return;if (state && result.health) {state.health = result.health;renderEnhancements();}await refresh();if (generation === sessionGeneration) toast(result.accepted ? '已提交出口健康检查，完成后结果会自动更新。' : '当前出口正在检查，完成后结果会自动更新。');}
  catch (error) {if (generation === sessionGeneration) toast(error.message,true);}
  finally {if (generation === sessionGeneration) button.disabled = !!state?.health?.checking;}
});
$('#routing-diagnostic-form').addEventListener('submit',async (event) => {
  event.preventDefault();const generation = sessionGeneration,button = event.currentTarget.querySelector('button');button.disabled = true;
  try {
    const result = await api('diagnostics',{url:$('#diagnostic-url').value});if (generation !== sessionGeneration || !csrf) return;
    const element = $('#diagnostic-result');element.replaceChildren();element.hidden = false;element.classList.toggle('warning',result.decision === 'unknown');
    const heading = document.createElement('strong');heading.textContent = (result.domain || '目标域名') + '：' + ({direct:'规则判断为本机 DIRECT',proxy:'规则判断为网页出口代理',unknown:'需在客户端确认'})[result.decision];element.append(heading);
    for (const message of [result.explanation,result.rule ? '命中规则：' + result.rule : null,result.source ? '依据：' + result.source : null,'这是已保存规则的判断，尚未验证客户端实际流量。请展开下方的客户端核对说明，并查看 FlClash 连接记录。',...(result.checks || []).map((check) => typeof check === 'string' ? check : check.message || check.explanation || check.name)]) {if (!message) continue;const row = document.createElement('p');row.textContent = message;element.append(row);}
    $('#diagnostic-url').value = result.domain || '';
  } catch (error) {if (generation === sessionGeneration) toast(error.message,true);}finally {button.disabled = false;}
});
async function enhancedMutation(control,path,payload,message,onSuccess) {
  const generation = sessionGeneration,button = control.matches('button') ? control : control.querySelector('button[type="submit"]');if (button?.disabled) return false;if (button) button.disabled = true;
  try {const result = await api(path,payload);if (generation !== sessionGeneration || !csrf) return false;onSuccess?.(result);await refresh();if (generation === sessionGeneration) toast(message);return true;}
  catch (error) {if (generation === sessionGeneration) {layoutFormError(control,error.message);toast(error.message,true);}return false;}finally {if (button) button.disabled = false;}
}
$('#copy-subscription').addEventListener('click',async () => {
  if (!subscription?.url) return;
  try {await navigator.clipboard.writeText(subscription.url);toast('私密订阅链接已复制。请只粘贴到自己的客户端。');}catch {toast('浏览器未允许复制。可在本页显示链接后手动复制。',true);}
});
$('#rotate-subscription').addEventListener('click',async () => {
  if (!await confirmAction('撤销旧订阅链接？','旧完整配置订阅链接将失效，节点身份不改变。需要在客户端换成新订阅链接。','撤销并换新')) return;
  if (await enhancedMutation($('#rotate-subscription'),'subscription/rotate',{},'旧订阅链接已撤销，请更新客户端订阅。')) await loadSubscription();
});
$('#rotate-credentials').addEventListener('click',async () => {
  if (!await confirmAction('撤销我的旧节点身份？','旧节点配置和规则/配置订阅地址会失效，连接可能中断。完成后重新获取并导入自己的配置。网页登录密码不改变。','撤销旧身份')) return;
  if (await enhancedMutation($('#rotate-credentials'),'credentials/rotate',{},'节点身份已更换，旧配置失效。请重新获取配置并导入。')) await loadSubscription();
});
$('#refresh-audit').addEventListener('click',() => loadAudit().catch((error) => toast(error.message,true)));
$('#refresh-admin-audit').addEventListener('click',() => loadAudit(true).catch((error) => toast(error.message,true)));

function typedConfirmation(username,title,message) {
  const dialog = $('#typed-confirm-dialog');$('#typed-confirm-title').textContent = title;$('#typed-confirm-message').textContent = message;
  $('#typed-confirm-input').value = '';$('#typed-confirm-ok').disabled = true;
  dialog.dataset.username = username;dialog.returnValue = 'cancel';
  return new Promise((resolve) => {dialog.addEventListener('close',() => {const matched = dialog.returnValue === 'confirm' && $('#typed-confirm-input').value === username;$('#typed-confirm-input').value = '';delete dialog.dataset.username;resolve(matched);},{once:true});dialog.showModal();$('#typed-confirm-input').focus();});
}
$('#typed-confirm-input').addEventListener('input',() => {$('#typed-confirm-ok').disabled = $('#typed-confirm-input').value !== $('#typed-confirm-dialog').dataset.username;});
async function enhancedUserAction(user,action) {
  if (currentUser?.role !== 'admin') return;
  const generation = sessionGeneration;
  if (action === 'limits') {
    $('#limits-user-id').value = user.id;$('#limits-user-label').textContent = (user.display_name || user.username) + '（' + user.username + '）';
    $('#limits-quota').value = Number(user.traffic?.quota_bytes || user.quota_bytes || 0)/1e9;
    $('#limits-rate').value = Number(user.traffic?.rate_bps || user.rate_bps || 0)/1e6;
    $('#limits-error').textContent = '';$('#user-limits-dialog').showModal();return;
  }
  if (user.role === 'admin') return;
  const deleting = action === 'delete';
  if (!await typedConfirmation(user.username,deleting ? '永久删除这个成员？' : '撤销这个成员的旧节点身份？',deleting ? '会删除此成员的账号、入口、出口和规则，原配置失效。请输入目标成员的登录账号确认。' : '该成员的旧节点配置和订阅地址会失效，需要重新获取并导入。请输入目标成员的登录账号确认。')) return;
  if (generation !== sessionGeneration || currentUser?.role !== 'admin') return;
  usersBusy = true;renderUsers();
  try {
    await api(deleting ? 'users/delete' : 'users/rotate-credentials',{id:user.id,confirm_username:user.username});
    if (generation !== sessionGeneration) return;
    await refreshUsers();await refresh();toast(deleting ? '成员已删除，原配置失效。' : '该成员节点身份已更换，请让使用者更新配置。');
  } catch (error) {if (generation === sessionGeneration) toast(error.message,true);}finally {if (generation === sessionGeneration) {usersBusy = false;renderUsers();}}
}
$('#close-user-limits').addEventListener('click',() => $('#user-limits-dialog').close());
$('#user-limits-dialog').addEventListener('close',() => {$('#user-limits-form').reset();$('#limits-user-id').value = '';$('#limits-user-label').textContent = '';$('#limits-error').textContent = '';});
$('#user-limits-form').addEventListener('submit',async (event) => {
  event.preventDefault();if (currentUser?.role !== 'admin') return;
  const generation = sessionGeneration,quota = Number($('#limits-quota').value),rate = Number($('#limits-rate').value),id = $('#limits-user-id').value;
  if (!Number.isFinite(quota) || !Number.isFinite(rate) || quota < 0 || rate < 0) return $('#limits-error').textContent = '额度和速度需填写非负数字。';
  if (quota > 1e7 || rate > 1e4 || rate > 0 && rate < 0.1) return $('#limits-error').textContent = '额度最多 10000000 GB；速度为 0（不限）或 0.1–10000 Mbps。';
  const button = event.currentTarget.querySelector('button[type="submit"]');button.disabled = true;
  try {await api('traffic/limits',{id,quota_bytes:Math.round(quota*1e9),rate_bps:Math.round(rate*1e6)});if (generation !== sessionGeneration) return;$('#user-limits-dialog').close();await refreshUsers();await refresh();toast('额度设置已保存，请核对服务器执行状态。');}
  catch (error) {if (generation === sessionGeneration) $('#limits-error').textContent = error.message;}finally {button.disabled = false;}
});
async function loadBackups() {
  if (currentUser?.role !== 'admin') return;
  const generation = sessionGeneration,result = await api('backups');if (generation !== sessionGeneration || currentUser?.role !== 'admin') return;
  $('#backup-list').replaceChildren();
  if (!(result.backups || []).length) $('#backup-list').textContent = '尚无备份';
  for (const backup of result.backups || []) {
    const row = document.createElement('article'),heading = document.createElement('strong'),stamp = document.createElement('small'),button = document.createElement('button');row.className = 'backup-entry';
    heading.textContent = backup.name || '完整加密备份';stamp.textContent = time(backup.created_at) + ' · ' + bytes(backup.size) + ' · ' + (backup.portable ? '独立密码加密' : '服务器密钥加密');
    button.type = 'button';button.className = 'button secondary small';button.textContent = backup.portable ? '输入备份密码并下载' : '设置导出密码并下载';button.addEventListener('click',() => {if (currentUser?.role !== 'admin') return;$('#backup-export-form').reset();$('#export-backup-id').value = backup.id;$('#backup-export-dialog h2').textContent = backup.portable ? '验证原备份密码并下载' : '导出为可携带的加密备份';$('label[for="export-password"]').textContent = backup.portable ? '此备份创建时的原密码' : '独立导出密码';$('#backup-export-dialog .field-hint').textContent = backup.portable ? '输入创建这个加密备份时使用的密码。下载文件保持加密；服务端不会保留密码。' : '设置 12–128 个字符的独立密码；下载文件始终加密，恢复到其他环境时使用此密码。';$('#backup-export-dialog').showModal();});
    row.append(heading,stamp,button);$('#backup-list').append(row);
  }
  const schedule = result.schedule || {};
  if (!$('#backup-schedule-form').dataset.dirty) $('#backup-schedule-enabled').value = schedule.enabled ? 'on' : 'off';
  $('#backup-schedule-status').textContent = (schedule.enabled ? '每 24 小时自动加密备份' : '定时备份已关闭') + ' · 最近 ' + time(schedule.last_backup) + ' · 下次 ' + time(schedule.next_backup);
  syncLayoutDrafts();
}
$('#refresh-backups').addEventListener('click',() => loadBackups().catch((error) => toast(error.message,true)));
$('#backup-create-form').addEventListener('submit',async (event) => {
  event.preventDefault();if (currentUser?.role !== 'admin') return;
  const password = $('#backup-password').value;
  if (password !== $('#backup-password-confirm').value) return toast('两次备份密码不一致。',true);
  if (password.length < 12 || password.length > 128) return toast('备份密码需要 12–128 个字符。',true);
  const ok = await enhancedMutation(event.currentTarget,'backups/create',{password},'加密备份已创建，可在列表导出。');
  $('#backup-password').value = $('#backup-password-confirm').value = '';
  if (ok) await loadBackups();
});
$('#backup-schedule-form').addEventListener('input',() => {$('#backup-schedule-form').dataset.dirty = 'true';});
$('#backup-schedule-form').addEventListener('submit',async (event) => {
  event.preventDefault();if (currentUser?.role !== 'admin') return;
  if (await enhancedMutation(event.currentTarget,'backups/schedule',{enabled:$('#backup-schedule-enabled').value === 'on'},'每日备份计划已保存。',() => {delete $('#backup-schedule-form').dataset.dirty;})) await loadBackups();
});
$('#close-backup-export').addEventListener('click',() => $('#backup-export-dialog').close());
$('#backup-export-dialog').addEventListener('close',() => {$('#backup-export-form').reset();$('#export-backup-id').value = '';});
async function downloadBackup(token,filename) {
  const generation = sessionGeneration,response = await fetch(endpoint('backups/download?token=' + encodeURIComponent(token)),{credentials:'same-origin'});
  if (!response.ok) {const data = await response.json();throw new Error(data.error || '备份下载失败');}
  const blob = await response.blob();if (generation !== sessionGeneration || !csrf) return;
  const url = URL.createObjectURL(blob),anchor = document.createElement('a');anchor.href = url;anchor.download = filename || 'node-console.vpsbackup';anchor.click();setTimeout(() => URL.revokeObjectURL(url),1500);
}
$('#backup-export-form').addEventListener('submit',async (event) => {
  event.preventDefault();if (currentUser?.role !== 'admin') return;
  const password = $('#export-password').value,button = event.currentTarget.querySelector('button[type="submit"]'),generation = sessionGeneration;
  if (password !== $('#export-password-confirm').value) return toast('两次导出密码不一致。',true);
  if (password.length < 12 || password.length > 128) return toast('导出密码需要 12–128 个字符。',true);
  button.disabled = true;
  try {const result = await api('backups/export',{id:$('#export-backup-id').value,password});if (generation !== sessionGeneration) return;$('#backup-export-dialog').close();await downloadBackup(result.download_token,result.filename);toast('加密备份已下载，请妥善保存文件与导出密码。');}
  catch (error) {if (generation === sessionGeneration) toast(error.message,true);}finally {$('#export-password').value = $('#export-password-confirm').value = '';button.disabled = false;}
});
function clearBackupPreview() {backupPreview = null;$('#backup-preview').hidden = true;$('#backup-preview-summary').replaceChildren();$('#restore-confirmation').value = '';$('#restore-backup').disabled = true;}
$('#backup-preview-form').addEventListener('submit',async (event) => {
  event.preventDefault();if (currentUser?.role !== 'admin') return;
  const file = $('#backup-file').files[0];if (!file) return;
  if (file.size > 32*1024*1024) return toast('备份文件过大，请使用 32 MiB 以内的加密备份。',true);
  const generation = sessionGeneration,button = event.currentTarget.querySelector('button');button.disabled = true;clearBackupPreview();
  try {
    const data = await new Promise((resolve,reject) => {const reader = new FileReader();reader.onload = () => resolve(String(reader.result).split(',')[1]);reader.onerror = () => reject(new Error('无法读取备份文件'));reader.readAsDataURL(file);});
    const result = await api('backups/preview',{data,password:$('#restore-password').value});if (generation !== sessionGeneration || currentUser?.role !== 'admin') return;
    backupPreview = {token:result.preview_token,generation,expires_at:result.expires_at};$('#backup-preview').hidden = false;
    const element = $('#backup-preview-summary');
    for (const message of ['备份创建于 ' + time(result.created_at),'将恢复 ' + (result.changes?.files ?? '未知') + ' 项文件、' + (result.changes?.users ?? (result.users || []).length) + ' 个账号。','涉及账号：' + (result.users || []).map((user) => user.username).join('、'),...(result.warnings || []).map((warning) => typeof warning === 'string' ? warning : warning.message || '需核对备份变更')]) {const row = document.createElement('p');row.textContent = message;element.append(row);}
  } catch (error) {if (generation === sessionGeneration) toast(error.message,true);}finally {$('#restore-password').value = '';$('#backup-file').value = '';button.disabled = false;}
});
$('#restore-confirmation').addEventListener('input',() => {$('#restore-backup').disabled = !backupPreview || $('#restore-confirmation').value !== 'RESTORE';});
$('#cancel-restore').addEventListener('click',clearBackupPreview);
$('#restore-backup').addEventListener('click',async () => {
  const preview = backupPreview;if (!preview || preview.generation !== sessionGeneration || currentUser?.role !== 'admin' || $('#restore-confirmation').value !== 'RESTORE') return;
  if (!await confirmAction('确认恢复完整备份？','将恢复预览涉及的账号与配置，当前登录可能失效，连接可能重新建立。','恢复此备份')) return;
  const button = $('#restore-backup');button.disabled = true;
  try {const result = await api('backups/restore',{preview_token:preview.token,confirmation:'RESTORE'});if (preview.generation !== sessionGeneration) return;clearBackupPreview();if (result.requires_login) {showLogin();toast('备份已恢复，请使用恢复后的账号重新登录。');}else {await refresh();await loadBackups();toast('备份已恢复。');}}
  catch (error) {if (preview.generation === sessionGeneration) toast(error.message,true);}finally {if (backupPreview) button.disabled = $('#restore-confirmation').value !== 'RESTORE';}
});
setInterval(() => {
  if (!csrf) return;
  if (state) renderTrafficDashboard(state.traffic);
  if (busy || $("#exit-dialog").open || document.hidden) return;
  refresh(true).then(() => {
    if (currentView === 'users' && !usersBusy) refreshUsers().catch(() => {});
    if (state?.job?.status !== "running" && state?.job?.id && state.job.id !== completedJob) {
      completedJob = state.job.id;
    }
  }).catch(() => {});
}, 12000);
const nodeConsoleReady = initialize();

document.addEventListener('invalid',(event) => revealLayoutTarget(event.target),true);
document.addEventListener('input',syncLayoutDrafts);
document.addEventListener('change',syncLayoutDrafts);
document.addEventListener('reset',() => queueMicrotask(syncLayoutDrafts),true);
for (const [errorSelector,detailsSelector] of [['#create-user-error','#create-user-details'],['#password-error','#password-details'],['#health-settings-error','#health-settings-details']]) {
  const error = $(errorSelector),details = $(detailsSelector),indicator = details.querySelector('.layout-error-indicator');
  const update = () => {
    const failed = !!error.textContent.trim();
    indicator.hidden = !failed;
    if (failed) details.open = true;
  };
  new MutationObserver(update).observe(error,{childList:true,characterData:true,subtree:true});
}

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
      S('#client-config-update',"以后何时需要重新下载","首次使用 HY2 与 REALITY 双入口时，刷新完整订阅或重新导入一次；选择 AUTO 优先 HY2，不可用时使用 TCP 兼容入口，也可手动选 REALITY · TCP兼容。此后网页切换或新增出口无需重新下载。首次改用智能分流、切换分流方案或同步固定节点列表时，再更新配置。实际采用哪种协议请看客户端记录。",{fallback:'#client-config-summary'})]},
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
    {id:"admin-create",name:"管理员：创建独立使用者",view:"users",admin:true,summary:"自动分配独立入口，各自管理出口和分流。",steps:[
      S('#users-nav',"打开用户管理","管理员可以管理服务器使用者；普通成员没有此入口。创建账号后，把对应登录资料交给该使用者。"),
      S('#user-slots',"查看账号名额","账号容量由服务器的端口资源池决定，包含管理员。可用入口分配完后，先核对并准备更多成员端口。"),
      S('#create-username',"填写登录账号","3–24 个字符，以小写字母开头，可使用小写字母、数字、下划线和短横线。账号用于网页登录。"),
      S('#create-display-name',"填写显示名称（可选）","可以填写容易识别的名字，方便在用户列表找到使用者。"),
      S('#create-user-password',"设置初始密码","可以留空自动生成，或填写 12–128 个字符。成功后，初始密码只在本页交付卡暂存十分钟；清除、退出或刷新后无法恢复。使用者可自行更改。"),
      S('#create-user-submit',"准备独立账号","关闭指引后确认资料，再点击准备。按服务器真实任务进度更新；本机准备完成后复制交付资料，再分别验证 HY2 / REALITY 公网连接。初始密码只在本页交付卡暂存十分钟。")]},
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
  topics.push(
    {id:'draft-safety',name:'避免丢失未保存的修改',view:'routing',summary:'普通导航和刷新前可保存、放弃或继续编辑。',steps:[
      S('#direct-domains','编辑自己的分流草稿','修改域名列表后暂未保存，它只存在当前页面中。再次点击同一个导航不会覆盖它。'),
      S('[data-view="access"]','离开前选择如何处理','点击其他导航或刷新状态时，有未保存规则会提示：保存并继续、放弃并继续、继续编辑。保存失败仍留在原页面。教程不会替你选择。'),
      S('#routing-form button[type="submit"]','保存成功后再继续','保存使服务器规则更新。智能分流的自定义列表按客户端规则集周期同步；关闭浏览器或刷新页面前会提示未保存内容，密码不存入浏览器持久存储。')]},
    {id:'rule-diagnostic',name:'查询网站规则并检查客户端',view:'routing',summary:'分别看规则预期与客户端实际连接，避免误读当前出口。',steps:[
      S('#diagnostic-url','填写要查询的网址','域名或完整网址均可。查询只分析域名，不访问你的课程页面和查询参数；使用服务器已保存规则。'),
      S('#routing-diagnostic-form button','查询规则','关闭指引后点击查询，查看预计直连或代理、命中规则和理由。尚未保存的草稿不参与查询。'),
      S('#client-checklist','验证真正的客户端路径','服务器看不到绕过它的 DIRECT 请求。在 FlClash 连接记录查目标域名，核对规则模式、AUTO、代理接管与规则集刷新；已有连接需重建。')]},
    {id:'health-fallback',name:'出口健康与自选备用',view:'overview',summary:'默认仅提醒，明确启用后才自动改变出口。',steps:[
      S('#health-summary','查看真实检查结果','这里显示最近检查、成功时间和连续失败次数。尚未检查或统计不可用会明确显示，服务运行不等于出口一定健康。'),
      S('#check-health','立即检查当前出口','关闭指引后可以手动检查当前已应用出口。检测不会拿你的未应用草稿替换运行资料。'),
      S('#health-mode','选择故障处理','默认“仅提醒”，保持自己的固定 IP。只有你明确选择自动模式、指定备用并确认，连续失败后才会自动切换本账号。'),
      S('#health-fallback','指定自己的备用出口','选择本账号的另一个出口或服务器自身出口，备用需可用且与当前路径不同。备用切换可能改变出网 IP。'),
      S('#health-settings-form button','保存设置','核对模式和备用，关闭指引后保存。其他账号不受影响。')]},
    {id:'profile-subscription',name:'订阅配置与撤销泄露身份',view:'access',summary:'订阅属于自己；服务器版本不证明客户端已同步。',steps:[
      S('#subscription-version','看服务器配置版本','这里显示服务器最新配置版本和更新时间。网页无法确认你的客户端已刷新订阅或导入，不会把下载称为同步成功。'),
      S('#copy-subscription','复制自己的完整配置订阅','关闭指引后复制到客户端添加订阅，使用规则模式和 AUTO。链接可读取节点配置，只给对应使用者。'),
      S('#rotate-subscription','撤销旧订阅链接','链接泄露时可确认撤销并换新。节点身份不变，客户端需更换订阅地址；旧链接失效。'),
      S('#rotate-credentials','撤销旧节点身份','节点配置泄露时可更换本人的代理身份。旧 UUID 和规则/配置订阅失效，连接可能中断，需重新获取配置。网页密码独立。')]},
    {id:'usage-history',name:'自己的用量与操作记录',view:'overview',summary:'代理上传下载、连接与额度可核对；直连不计入服务器用量。',steps:[
      S('#traffic-summary','看本月代理用量','额度按本账号上传与下载合计。国内 DIRECT 走本机，不经过服务器，因此不计入这里；统计不可用会显示原因。'),
      S('#traffic-facts','核对速率、连接与执行状态','查看上传下载速率、入口连接、限速和额度是否执行。已启用的 HY2 与 REALITY 入口归入本账号统一用量，DIRECT 不计入；连接数不代表在线设备数。达到额度的提醒与人工停用账号分开。',{fallback:'#traffic-summary',missing:'当前统计尚不可用，速率与连接数没有显示。待服务器提供有效采样后再核对详情。'}),
      S('[data-view="access"]','查看自己的操作记录','到“客户端与访问”查看操作时间、结果和对象；记录不展示密码、完整订阅地址或私人网址参数。')]},
    {id:'admin-backups',name:'管理员：加密备份、预览与恢复',view:'maintenance',admin:true,summary:'所有下载都保持加密；恢复必须预览并输入确认。',steps:[
      S('#backup-password','设置完整备份密码','创建可携带备份时设置 12–128 字符密码并确认，另行保存密码。完整备份包含账号和节点资料。'),
      S('#backup-create-form button','创建加密备份','关闭指引后创建；密码在请求处理后清空，备份资料不会直接显示在页面。'),
      S('#backup-list','下载加密备份','服务器密钥备份下载前设置独立导出密码；已用独立密码创建的备份需输入原密码验证。下载文件始终加密。'),
      S('#backup-file','选择需要恢复的加密文件','选择备份并输入解密密码。只点击解密预览时尚未恢复任何资料。'),
      S('#backup-preview-form button','先核对恢复预览','先看时间、账号、文件和警告。密码与选中文件处理完后清空；教程不会上传或解密。'),
      S('#backup-preview','手动确认再恢复','预览正确后输入 RESTORE 再确认恢复，账号和配置会变化，连接可能重建，可能需要重新登录。', {fallback:'#backup-preview-form',missing:'尚未解密预览；实际恢复按钮只在有效预览后出现。'}),
      S('#backup-schedule-enabled','设置每日备份','定时备份每 24 小时执行，使用服务器保护的加密密钥。开启或关闭后需自行保存计划，不存用户密码。')]},
    {id:'admin-lifecycle',name:'管理员：额度与成员生命周期',view:'users',admin:true,summary:'用量额度、节点身份与永久删除都明确作用对象。',steps:[
      S('#user-list [data-user-action="limits"]','为账号设置额度与限速','先核对成员，点击“用量与额度”设置 GB 和 Mbps，0 为不限。保存后核对服务器执行状态，统计不可用不会被当作 0。'),
      S('#user-list [data-user-action="rotate"]:not([hidden])','更换成员节点身份','目标成员的旧配置和规则/配置订阅会失效；需手动输入其登录账号二次确认，使用者需重新获取配置。',{fallback:'#create-username',missing:'当前没有成员可以更换节点身份。'}),
      S('#user-list [data-user-action="delete"]:not([hidden])','永久删除成员','删除会移除目标账号、入口与资料，原配置失效。需手动输入登录账号确认；管理员不能删除自己。',{fallback:'#create-username',missing:'当前没有成员可删除。'}),
      S('#maintenance-nav','查看全部操作记录','管理员在“维护与记录”核对各账号的操作时间与结果。记录和备份不应暴露真实密码、完整token或私密参数。')]}
  );
  let active = null;
  let returnFocus = null;
  let ownedDialog = null;
  let ownedKind = null;
  let frame = 0;
  let revision = 0;
  let handbookGeneration = null;
  let observedGeneration = sessionGeneration;
  const visible = (selector) => [...document.querySelectorAll(selector)].find((element) => {const box = element.getBoundingClientRect();return box.width > 0 && box.height > 0 && !element.closest('[hidden]');}) || null;
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
  function focusBack(element) {
    const folded = element?.closest('details.layout-details:not([open])');
    const target = folded?.querySelector(':scope > summary') || element;
    if (target?.isConnected && target.getClientRects().length) target.focus({preventScroll:true});
  }
  function revealGuideElement(element) {
    if (!active || !element || element.closest('[hidden]')) return;
    for (const details of layoutDetailsAncestors(element)) {
      if (!details.open) {active.openedDetails.set(details,false);details.open = true;}
    }
  }
  function revealGuideStep(step) {
    const candidate = typeof step.target === 'function' ? step.target() : step.target ? [...document.querySelectorAll(step.target)].find((element) => !element.closest('[hidden]')) : null;
    revealGuideElement(candidate);
    if (!candidate || !candidate.getClientRects().length) {
      if (step.fallback) revealGuideElement([...document.querySelectorAll(step.fallback)].find((element) => !element.closest('[hidden]')));
    }
  }
  function restoreGuideDetails(context) {
    if (!context || context.generation !== sessionGeneration) return;
    for (const [details,original] of context.openedDetails) if (details.isConnected) details.open = original;
  }
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
    restoreGuideDetails(old);
    if (restore && old && old.generation === sessionGeneration && csrf && currentView !== old.returnView) switchView(old.returnView);
    if (restore) focusBack(old?.returnFocus || returnFocus);
  }
  async function start(id) {
    const topic = topics.find((item) => item.id === id);
    if (!topic || !permitted(topic)) return false;
    if (modalOpen()) {say('请先保存或自行取消当前打开的表单，再开始箭头讲解；你的草稿没有改动。');return false;}
    if (topic.view && currentView !== topic.view && (routingDraft() || hasPasswordDraft())) {say('当前页面有未保存草稿或密码输入。请先完成保存，或自行确认放弃后离开；教程不会覆盖或自动提交这些内容。');return false;}
    if (active) stop(false);
    active = {topic,index:0,generation:sessionGeneration,returnView:currentView,returnFocus:returnFocus || document.activeElement,target:null,targetSelector:'',openedDetails:new Map()};
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
    if (prepared) revealGuideStep(step);
    else revealGuideElement(document.querySelector(context.topic.view === 'users' ? '#create-username' : '#add-exit'));
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
    if (active.target?.isConnected && active.target.getBoundingClientRect().width > 0 && active.target.getBoundingClientRect().height > 0) resolved.target = active.target;
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
  document.addEventListener('click',(event) => {
    const summary = event.target.closest('details.layout-details > summary');
    if (active && summary) active.openedDetails.delete(summary.parentElement);
  },true);
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
