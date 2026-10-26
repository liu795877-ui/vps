# 上传配置的分流规则分析

分析日期：2026-10-08。来源为本次上传的 Clash / Mihomo YAML；仅提取分流和 DNS 相关字段。

该配置包含 95 条入口规则、60 个规则集和 23 个策略组。规则从上到下执行，首次匹配后停止；策略组名称决定分类，组中当前选择决定直连或代理。下面的“默认”指新配置的首选项，客户端保存的旧选择可能覆盖默认值。

| 匹配阶段 | 规则用途 | 默认去向 |
| --- | --- | --- |
| 1 | Steam 更新、内容分发和下载域名的精确/后缀例外 | DIRECT |
| 2 | hf.co、huggingface.co | Proxy |
| 3 | AppleAI、OpenAI、Steam 规则集 | OpenAI / Steam，默认代理 |
| 4 | ip138.com、lan、local、home.arpa、Special | DIRECT |
| 5 | Netflix、Disney、YouTube、Spotify、Global TV、Apple TV | 对应服务组，默认代理 |
| 6 | Bilibili、爱奇艺、网易音乐、腾讯视频、优酷等 | Asian TV，默认直连 |
| 7 | Apple、PayPal、Scholar、miHoYo | 对应服务组，默认直连 |
| 8 | Telegram、Crypto、Discord、Google FCM、Microsoft、Speedtest | 对应服务组，默认代理 |
| 9 | PROXY 通用规则集 | Proxy |
| 10 | Domestic 与 Domestic IPs 的交集，以及 Domestic IPs 单独匹配 | Domestic，默认直连 |
| 11 | LAN 和中国 GeoIP | DIRECT / Domestic，默认直连 |
| 12 | MATCH, Others | Others，默认代理 |

“OpenAI”规则集实际引用 AI Suite，范围超过 ChatGPT/OpenAI；原规则集还包含其他 AI 服务及部分 Apple Intelligence 转发域名。AppleAI 排在 Apple 之前，因此这些 Apple AI 请求默认走代理，其他 Apple 服务仍按 Apple 组默认直连。

Steam 下载域名的直连规则优先于 Steam 服务规则；不能把 Steam 组的默认代理理解成全部 Steam 流量代理。Scholar 与 PayPal 默认 DIRECT，如果希望它们使用静态出口，应在客户端把对应组改为 Proxy。

Domestic 的 AND 规则要求域名与 IP 同时命中；后面又有单独的 Domestic IPs 指向相同组。因此它对最终路由目的地基本冗余，不能实现“所有国内域名都直连”。部分国内域名若解析到非国内 IP，仍可能落入 Others 走代理。本次保留原顺序和表达式。

DNS 采用 fake-ip。一般 DNS 查询通过 Proxy 访问 Cloudflare / Google DoH；cn、ip138.com、指定域名和 Domestic DNS 列表通过阿里 DoH 直连。代理服务器域名也通过指定的国内 DNS 解析。DNS 分流与连接分流是两套机制，命中国内 DNS 不代表连接一定直连。

原配置中的 60 个规则集 URL 含服务访问参数。迁移时，59 个规则集改用原路径对应的公开 GitHub 上游，按 86400 秒更新；Domestic DNS 的 112402 条规则保存为 2026-10-08 快照，由控制台提供不带凭据的固定资源地址。该快照不会自动跟随原服务商更新。

已将这套规则接入现有私人节点控制台，原 95 条规则及服务策略组保留。Proxy 首选 STATIC-SELECT，STATIC-SELECT 首选 AUTO · 网页切换；原来的单节点测速组保留为可选项。不同服务可以在客户端选择 Proxy 或 DIRECT。出口切换继续由网页管理。

下载配置额外在首位加入 api.ipify.org 的代理检测规则；“优先通过节点的域名”若填写，也会先于分类规则匹配。首次采用该方案时已清空额外域名，以使用原分类规则。

此迁移保持客户端仅本机访问的设置，未复制原配置中的节点密码、控制器密码、allow-lan 和 TUN 自动路由开关。TUN 是否开启由现有 FlClash 设置控制；系统代理通常只接管支持代理的应用。静态节点仍按 TCP 访问配置，不承诺游戏 UDP 或语音流量可用。

核验：60 个规则集均成功读取；独立 Mihomo v1.19.31 接受配置、逻辑 AND 规则和 DNS 策略；19 项控制台后端测试及分流方案选择/下载的桌面、手机界面检查通过。这些检查不等同于每个网站和服务的实际访问验证。
