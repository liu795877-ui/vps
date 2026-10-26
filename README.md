# VPS 多用户网页出口管理

基于 Xray REALITY 与 Hysteria2 的中文管理控制台。管理员可准备成员入口、管理昵称和订阅期限、查看成员访问记录；成员可通过网页切换服务器或静态 SOCKS5 出口，并获取客户端配置。

当前 `.63` 发布版本为 `console-optimization-release-20261023-nickname-01`。最新功能和验收记录见 [.63 项目说明](deployments/raksmart-198.200.49.63/README.md)，另一台服务器的部署材料见 [.158 项目说明](deployments/raksmart-198.200.49.158/README.md)。

## 项目内容

- `panel/`：网页、后台、成员与订阅管理、访问记录、分流规则、统计及测试。
- `configure_reality.py`、`configure_static_exits.py`：节点及静态出口配置工具。
- `deployments/`：两台服务器的部署工具、冻结源码版本、发布清单、验证摘要与交接文档。
- `reports/`：VPS 线路和延迟比较；根目录中的调研脚本与整理数据一并保留。

## 本地验证

建议使用 Python 3.10 或更新版本及 Node.js。在已安装 Microsoft Edge 的 Windows 环境中，可运行：

```powershell
python -m pip install cryptography paramiko
npm ci --prefix panel
python -m unittest discover -s panel -t .
node panel/nickname_smoke.mjs
```

浏览器测试使用临时演示数据。生产 CentOS 7 / Python 3.6 发布另有冻结包和兼容性验证流程，见对应部署目录的说明及 `stage_console_optimization.py`、`validate_console_optimization.py`。

## 仓库内容与本地配置

仓库包含应用源码、测试、部署与恢复工具、历史源码发布包、验证摘要和项目文档。冻结版本按 SHA-256 校验；`.gitattributes` 保留原始文件字节，便于在 Windows 与 Linux 之间核对。

登录资料、SSH 密码与私钥、完整代理配置、运行数据库、成员访问原始记录、截图、下载的核心程序和依赖缓存按 `.gitignore` 排除，保留在本机。部署工具需要的服务器凭据在本地单独配置；历史诊断记录中指向这些本地文件的链接用于说明其原有位置。

## 历史安装与交接说明

以下为早期安装、测试及交接记录。当前运行状态与最新功能以部署目录顶部的更新记录为准。

当前项目交接入口（2026-10-12）：[.63 网页出口管理项目交接](deployments/raksmart-198.200.49.63/README.md#项目交接--2026-10-12)，交接编号 `vps-handoff-20261012-01`，机器索引在同目录 `task-state.json.handoff`，接续开场白在 `handoff-opener.txt`。该记录同时说明 `.158` 的架构差异、已交付功能、生产发布基线、测速证据和未完成事项；最近一次远程验证为 2026-10-11，本次仅保存材料。下文 `api.aiuzh.icu` 与早期单节点部署说明保留为历史，不能用于覆盖当前 `.63` 生产配置。

已于 2026-10-01 部署可视化管理网页。下面的命令行章节保留为备用说明，历史核验记录仅代表当时状态。

## 使用网页配置

入口：https://api.aiuzh.icu/node-console/

管理账号为 `admin`。随机初始密码保存在本机 `D:\CodexData\vps\panel-login.private.json`，不要公开该文件。
该文件已限制为当前 Windows 账号和 SYSTEM 读取。可以在网页的“客户端与访问”中修改管理密码；修改后本地初始密码文件不会自动更新。

1. 登录网页，点击“添加出口”，填写服务商提供的 SOCKS5 服务器地址、端口和认证资料。预期出口 IP 可以留空。
2. 点击“检测连接”，核对网页显示的实际出口 IP。使用来源 IP 白名单的服务商需要先允许 VPS 的公网出口。
3. 点击该出口的“应用并切换”。网页先检测全部已保存出口，再校验配置并应用；任一出口失败会停止应用。
4. 下载客户端 YAML，在 FlClash / Mihomo 客户端导入为新的本地配置，在 `STATIC-SELECT` 选择 `AUTO · 网页切换`，开启系统代理。
5. 访问 `https://api.ipify.org`，核对客户端实际出口。以后在网页切换已保存的出口即可，新建连接会使用所选出口。

“网站分流”支持手动域名和服务分类方案。已有出口时，保存会更新客户端下载配置，重新下载、导入后生效。
默认分流 GitHub 相关域名及出口检测网站，其他网站直连。选择“出口 · 名称”固定节点时，网页切换不会改变它的出口。
最多管理 8 个出口；只有一个代理出口时不能凭空生成其他 IP。切换应用会重启 Xray，现有代理连接可能短暂中断。

2026-10-08 新增“服务分类分流”方案，接入用户提供的 95 条规则、60 个规则集、23 个服务策略组，详细说明见 `routing-analysis.md`。
在“网站分流”选择该方案并保存，已有出口时会直接更新客户端下载文件，无需重启 Xray；重新下载并导入后生效。
Proxy 首选 STATIC-SELECT，可继续选择 AUTO · 网页切换。国内及 Apple / PayPal / Scholar / miHoYo 等默认直连，国外服务和未匹配流量默认代理。
59 个规则集使用公开上游；Domestic DNS 使用 2026-10-08 的 112402 条域名快照。原节点凭据和规则服务的访问参数没有写入规则模板。
“优先通过节点的域名”是分类规则之前的额外覆盖，留空保留原分类行为。api.ipify.org 自动经节点用于出口核对。
该规则方案已通过独立 Mihomo 配置检查及 19 项控制台后端测试；具体网站可达性仍以客户端访问结果为准。

连接路径图会随出口变化自动更新。添加出口后出现新的候选分支和展开动画，点击分支可以预览、检测或应用该出口。
检测中显示探测动画，失败时标记对应分支；应用成功后高亮当前路径。预览和保存草稿不会自动切换当前出口。
删除当前出口的草稿后，图中保留仍在使用的已应用路径，直到下一次应用其他出口。动画表示配置与检测状态，不表示实时流量。
手机端支持纵向分支布局，并尊重系统的减少动态效果设置。

网页使用 HTTPS 登录、会话和请求校验；代理密码仅保存在服务器的私有配置中，不写入下载的客户端 YAML。
管理后端仅监听服务器回环地址 `127.0.0.1:18787`，通过现有 Caddy HTTPS 路由访问，无需额外开放管理端口。
服务器状态目录为 `/var/lib/vps-panel`，服务为 `vps-panel.service`；原有业务、基础节点身份和 REALITY 密钥保留。
导出的配置自动继承现有 REALITY 握手域名，当前服务器使用 `www.cloudflare.com`。

本地演示界面的双出口切换、配置下载、凭据隐藏与手机端退出已验证，39 项后端、文件事务和官方 Xray 核心测试通过。
服务器也通过 Linux 文件权限、回滚和官方核心测试。首次部署时未填写真实 SOCKS5 代理资料；真实静态出口及 FlClash 全链路应按上述步骤核对。
线上 HTTPS 登录、Secure / HttpOnly 会话、未登录访问保护、来源与 CSRF 校验、规则保存、桌面和手机布局、退出登录均已通过浏览器检查。
Xray、Caddy 和管理页服务均运行并开机自启；部署没有修改原 Xray 配置，原有 Caddy 业务路由核对保留。
2026-10-01，动态路径更新已通过 16 项管理后端测试及本地分支交互检查，覆盖新增、检测、失败、预览、应用、删除当前草稿、恢复配置和减少动态效果。
线上验证继承用户已有的出口，核对当前分支与已应用出口一致，并检查桌面、手机布局。此次更新没有添加或切换真实代理，Xray 已应用配置核对保持一致。

## 网页项目文件

- `panel/web/`：中文管理界面。
- `panel/server.py`：登录、出口管理、异步检测、配置应用和恢复接口。
- `panel/install.py` / `panel/deploy.py`：服务器安装与部署脚本。
- `panel/test_panel.py`：后端验证；`panel/smoke.mjs`：本地演示 UI 验证；`panel/live-smoke.mjs`：线上 HTTPS 验证。

线上 UI 验证会读取本地私有登录文件，仅保存相同的网站规则，不填写示例出口或修改实际 Xray 配置。

## 已知环境

- 用户截图：Ubuntu 24.04.4 LTS、x86_64。
- 用户截图：Caddy 占用 80/443，Docker 业务需保留。
- 用户截图：UFW inactive；不启用、不清空 UFW。
- 用户截图：`www.microsoft.com:443` 的 TLS 1.3 握手成功。
- 节点计划独立监听 TCP 8443。执行时再次检查端口是否空闲。

## 在 VPS 上配置

打开 `vps-console-setup.txt`，在 VPS 的 Ubuntu 用户终端执行其中完整的一段命令。
提示 `VPS public IPv4` 时输入云控制台显示的公网 IPv4，不是密码。
它使用已经安装的 `/usr/local/bin/xray`，不重复下载或升级核心。

保护措施：

- 非空旧配置、已有客户端文件、端口占用、非标准服务均会停止。
- UUID 和 X25519 密钥只在 VPS 本地生成，不打印、不写入本地工作区。
- 根据 systemd 的运行组设置配置权限，并在替换前校验配置。
- 启动失败尝试恢复原配置；不主动修改 Caddy、Docker 或防火墙。
- 禁止经该代理访问回环、私网及链路本地地址，包含常见云元数据地址。
- Clash 文件保存为当前 Ubuntu 用户的 `~/clash-reality.yaml`，权限 0600。
- 不要将该文件放到网站目录、公开链接、聊天或公共 Git 仓库。

看到 `SUCCESS` 只说明 Xray 进程与本机 TCP 8443 监听正常，不等于外部连接成功。
若失败，只发送 `STOPPED` 提示和不含凭据的服务状态；不要自行删除旧配置再重试。

## 云防火墙

在云控制台为该实例添加入站 TCP 8443 放行规则，不替换已有规则。
来源可先限定客户端的公网 IP；需要移动网络时，再根据使用需求调整。
无需开放本地客户端的 7890，也无需修改服务器的 80/443。
不需要为这个节点开放 UDP 8443；当前传输使用 TCP。

## 下载与导入

Windows PowerShell 可以通过已有 SSH 登录方式下载：

```powershell
$VpsIp = Read-Host '请输入 VPS 公网 IPv4，再按回车'
if ([string]::IsNullOrWhiteSpace($VpsIp)) {
    throw '没有输入 IP，下载已停止。请在提示后的下一行输入地址。'
}
$VpsIp = $VpsIp.Trim()
$parsedIp = $null
if (-not [System.Net.IPAddress]::TryParse($VpsIp, [ref]$parsedIp)) {
    throw '输入的内容不是 IP 地址，下载已停止。'
}
scp "ubuntu@${VpsIp}:/home/ubuntu/clash-reality.yaml" "D:\CodexData\vps\clash-reality.yaml"
```

`Read-Host` 后面的文字只是提示语，不会自动赋值。
必须在提示出现后的下一行输入地址；只按回车会得到空值。
空地址会形成 `ubuntu@:/home/ubuntu/clash-reality.yaml`，本机已复现它触发
`You must specify a subsystem to invoke.`。

若填入有效地址后仍出现 `Connection closed`，那是另一个连接问题，
不能据此认定密码错误、SFTP 缺失或 Xray 配置有误。
应通过云控制台检查 SSH 状态和日志，不要直接关闭防火墙或重启现有服务。

SSH 密码或密钥只交给 SSH 客户端，不发送到聊天。
若没有本机 SSH 登录方式，可用云控制台文件下载功能；不要公开托管配置。

### FlClash TUN 下的 SSH 直连

2026-09-30，本机路由检查发现，到 VPS 的默认连接经过 FlClash TUN 网卡。
同一目标的对照测试结果：

- 默认 TUN 路由：收到服务器 SSH 版本信息之前，连接关闭。
- 指定物理 WLAN 网卡：收到 VPS 的 OpenSSH 版本信息。
- Windows OpenSSH 使用 `-b` 绑定 WLAN 的 IPv4 地址后，完成密钥交换，
  已有的服务器主机密钥校验通过，并进入身份认证阶段。

这定位了当前连接问题所在的 TUN 路径，但没有确定代理核心内部的具体原因。
服务器上的密码认证失败记录不能据此认定来自本机。
Windows OpenSSH 不支持本次测试中的 `-B WLAN`；请使用下面的 `BindAddress`。

在 Windows PowerShell 执行以下命令，只让这次 SCP 连接使用 WLAN 源地址，
不关闭代理、不修改订阅、不更改全局路由或服务器防火墙：

```powershell
$WiFiIp = Get-NetIPAddress -InterfaceAlias 'WLAN' -AddressFamily IPv4 |
    Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' } |
    Select-Object -First 1 -ExpandProperty IPAddress
if (-not $WiFiIp) {
    throw '没有找到可用的 WLAN IPv4 地址，下载已停止。'
}
if (Test-Path -LiteralPath 'D:\CodexData\vps\clash-reality.yaml') {
    throw '本地配置已存在，下载已停止以避免覆盖。'
}
scp -o "BindAddress=$WiFiIp" "ubuntu@43.130.238.204:/home/ubuntu/clash-reality.yaml" "D:\CodexData\vps\clash-reality.yaml"
```

源地址会自动从当前 WLAN 获取，不需要把本机内网地址写进配置。
这是本机当前网络环境下已验证的握手绕行方法；换网后需重新验证。
如出现 `Permission denied`，再检查 Ubuntu 用户的密码或授权密钥。
如出现远程文件不存在，先在云控制台执行 `ls -l ~/clash-reality.yaml`，
不要直接打印文件内容或重新生成节点凭据。

在 Mihomo 内核的 Clash 类客户端中导入为一个新的本地配置，保留原配置与订阅。
示例只把 GitHub 相关域名和 `api.ipify.org` 分配给 VPS，其他网站直接连接。
这不是完整的境内/境外规则集，不保证所有网站或全部系统流量都经过节点。

启动该配置，将 `VPS-SELECT` 选为 `TOKYO-VPS`，打开系统代理。
在浏览器访问 `https://api.ipify.org`，应显示 VPS 的实际公网出口地址。
如果客户端配置存在并且外部连接失败，检查云规则、8443 可达性和客户端日志；
不要仅依据延迟测试就宣布部署成功。

## 增加 SOCKS5 静态出口

用户已确认有 SOCKS5 代理。本方案让指定网站通过
`FlClash -> VPS 的 VLESS + REALITY -> SOCKS5 静态出口 -> 网站` 访问。
每个出口使用不同的客户端身份，FlClash 可在 `STATIC-SELECT` 中手动切换。
只有一个出口时无法凭空切换到新 IP；要增加可选 IP，需要其他已分配的代理出口。

先准备代理服务商提供的服务器地址、端口、认证方式及实际静态出口 IP。
代理服务器地址不一定等于最终出口地址。
若服务商使用来源 IP 白名单，需要允许 VPS 的实际公网出口地址。
账号和密码只在 VPS 终端中输入，不发送到聊天，不写入命令行。

执行顺序：

1. 在 VPS 云控制台确认原来的基础 REALITY 配置已成功运行。
   本脚本要求原服务端配置及 `~/clash-reality.yaml` 存在且匹配。
   不匹配时会停止，不覆盖其他配置，也不自动重跑基础安装。
2. 打开 `vps-console-static-exits.txt`，在 VPS 的 Ubuntu 用户终端中
   执行完整命令。首次提示输入 VPS 公网 IPv4。
3. `Number of static SOCKS5 exits` 输入现有出口数量，只有一个就按回车。
   之后依次输入每个出口的标签、服务器地址、端口、用户名和密码。
   用户名和密码均不显示输入字符。
4. `Expected exit IP` 填服务商分配的实际出口 IP；不知道时可以留空。
   每个出口必须通过 VPS 发起的 HTTPS 出口检测，失败则不应用配置。
5. 看到 `SUCCESS` 后，私有新配置位于 `~/clash-static-exits.yaml`。
   用下面的 Windows PowerShell 命令下载。

```powershell
$WiFiIp = Get-NetIPAddress -InterfaceAlias 'WLAN' -AddressFamily IPv4 |
    Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' } |
    Select-Object -First 1 -ExpandProperty IPAddress
if (-not $WiFiIp) { throw '没有找到可用的 Wi-Fi 地址' }
if (Test-Path -LiteralPath 'D:\CodexData\vps\clash-static-exits.yaml') {
    throw '本地静态出口配置已存在，停止下载以避免覆盖'
}
scp -o "BindAddress=$WiFiIp" "ubuntu@43.130.238.204:/home/ubuntu/clash-static-exits.yaml" "D:\CodexData\vps\clash-static-exits.yaml"
```

在 FlClash 中将这个文件作为新的本地配置导入，选中 `STATIC-SELECT` 中的出口，
打开系统代理，再用浏览器访问 `https://api.ipify.org`。
此时显示的地址应与该出口的 `PREFLIGHT OK` 结果一致。
有多个出口时切换节点后重新访问，核对新的出口 IP。
切换作用于新建连接；已有连接可能继续使用旧出口，可先在 FlClash 中关闭旧连接再核对。
现有示例只分流 GitHub 相关域名及出口检测网站，其他网站仍直连。
静态节点按 TCP 网页流量配置，UDP 请求在服务端阻断；不承诺服务商支持 UDP。

脚本会先校验候选配置，再备份原配置并重启 Xray，现有 Xray 连接可能短暂断开。
启动失败会尝试恢复原配置及服务；恢复失败会报告并保留私有备份路径。
原来的 REALITY 密钥、节点身份和直接出口保留在原配置中，原客户端文件不会被覆盖。
新静态节点匹配指定 SOCKS5 出站，连接失败不自动改走原来的 VPS 出口。
新配置选择组不包含 `DIRECT`；这不改变未匹配网站的 `MATCH,DIRECT` 规则。
代理账号和密码存于 VPS 上的 Xray 私有配置中，不写进客户端 YAML。
该脚本拒绝重复安装；日后添加出口或更换代理资料应单独更新现有配置。

SOCKS5 本身不加密 VPS 到代理服务器的这一段连接；REALITY 保护电脑到 VPS 的这一段。
网页使用 HTTPS 时，网页内容的 TLS 加密仍覆盖到目标网站。

## 核验记录

2026-09-30，本地完成以下检查：

- 10 项自动测试通过。
- 官方 Windows Xray 26.3.27 下载包 SHA256 与官方校验文件一致。
- 该核心接受生成的服务端配置，输出 `Configuration OK`。
- 生成的终端命令通过 Bash 语法检查。
- 生成的 Clash 配置通过 YAML 结构检查。

未在用户 VPS 上执行本配置程序，也未验证真实客户端连接。
这些检查不能替代 VPS 服务启动、云防火墙放行和真实客户端连接测试。

2026-10-01，静态出口脚本已通过本地官方核心配置检查及双出口身份路由测试。
本地路由测试使用无 TLS 的 VLESS 测试连接和模拟 SOCKS5 服务器，仅验证身份路由
及私网阻断；不等同于真实 VPS 上的 REALITY 全链路验证。
新增 14 项检查通过，覆盖代理凭据处理、客户端配置、真实核心双出口路由、
候选配置拒绝、文件替换和启动失败回滚。
生成的控制台命令通过 Git Bash 语法检查，内嵌 Python 通过执行加载检查，
客户端配置通过 YAML 解析和双节点身份对应检查。
Windows 上的文件事务测试使用可移植写入替身验证流程及权限参数；
本机 WSL 当前不可用，尚未在真实 Linux 文件系统上实测 0600/0640 权限。
服务商代理尚未在 VPS 上执行预检，本配置也尚未部署。

## 官方依据

- https://github.com/XTLS/REALITY
- https://github.com/XTLS/Xray-install
- https://github.com/XTLS/Xray-core/blob/main/main/commands/all/x25519.go
- https://wiki.metacubex.one/config/proxies/vless/
- https://documentation.ubuntu.com/server/how-to/security/firewalls/
- https://xtls.github.io/config/outbounds/socks.html
- https://xtls.github.io/config/routing.html
