# pihy2 · 树莓派 hy2 全局代理一键部署

> 把树莓派整机流量透明走代理节点（hysteria2 / vless / vmess / trojan / ss / tuic）。**不用手敲命令、不用手写配置**——
> 跟着向导填几项、把节点链接粘进去，就能一键装好；之后用中文 **WebUI** 可视化管理节点和分流。

底层用 **mihomo（Clash Meta）TUN + fake-ip**：DNS 在本地解析掉，不依赖节点 UDP 转发，
稳定不卡（原理与逐步手动做法见 [`docs/手动配置指南.md`](docs/手动配置指南.md)，已逐条实测验证）。

---

## ✨ 功能

- **一键部署向导**：准备 TUN → 下载 mihomo → 生成并校验配置 → 建服务开机自启 → 验证出口 IP，全程提示式。
- **多协议 · 粘贴即解析**：支持 **hysteria2 / vless / vmess / trojan / ss / tuic**，直接贴分享链接
  （或 base64 订阅）即自动识别协议并提取所有字段（含 reality / ws / grpc 传输、混淆、端口跳跃等）。
- **订阅自动更新**：填订阅链接（支持**链接列表 / base64 / Clash YAML** 三种格式），systemd timer **定时拉取更新**（走代理）；面板可手动“全部更新”，更新即生效。
- **一键分流预设**：勾选即用 **广告拦截 / 大陆直连 / 流媒体走代理 / Telegram / Google / Apple国内直连** 等（基于 GEOSITE/GEOIP）。
- **全屋网关模式**：一键让局域网里的手机/电视/电脑也走代理——填代理 `树莓派IP:7890`，或把设备网关/DNS 指向树莓派（自动开 IP 转发）。
- **实时流量面板**：WebUI 实时显示上/下行速度、活动连接列表与最近日志，可一键断开全部连接。
- **多节点管理**：可视化增/删/改、拖动排序、一键测速、点选切换当前出口（尽量免重启）。
- **路由分流**：指定哪些域名/IP 走直连、哪些走代理，**支持通配符**（`*.cn`、`github.com`、`1.2.3.0/24`），
  自动判别规则类型；私有网段始终直连，**保证 SSH 永不掉线**。
- **链式代理（住宅 IP 出口）**：在「节点」页点「+ 链式代理」，手填 HTTP/SOCKS5 住宅 IP 代理并指定一个
  国内可达的「前置代理」，流量即 `前置节点 → 住宅 IP 出口` 链式出网，用更干净的 IP 上网
  （这类住宅代理国内不可直连，故只能挂在前置节点后面作出口；底层用 mihomo 的 `dialer-proxy`）。
- **完整设置**：默认带宽、TUN 协议栈、日志级别、DNS、fake-ip 网段、下载镜像等，界面里改。
- **一键自检 / 恢复默认 / 卸载**：面板「工具」页或命令行即可——**自检**逐项体检安装/服务/配置/节点/出口是否正常；**恢复默认设置**把设置一键回出厂值（不动节点/订阅/规则/面板密码）；**一键卸载**停服务、撤开机自启与网关转发（可选 `--purge` 连二进制/配置/状态一并清除）。
- **WebUI 面板**：部署后自带中文管理面板（强制访问密码、登录限速、token 时效），手机/电脑浏览器即可打开。
- **稳与安全**：首次部署不依赖联网下载地理库（开箱即用）；二进制校验 SHA-256 后原子安装；密钥/密码文件 `600`。
- **零依赖**：纯 Python 标准库 + 单个 mihomo 二进制，不用 pip、不用 docker。

---

## 🚀 快速开始（树莓派上，root）

```bash
git clone https://github.com/1439616687/pi-hy2.git
cd pi-hy2
sudo bash install.sh
```

向导会让你：

1. **粘贴节点链接**（一行一个，支持多个）→ 自动解析并预览确认；
2. 填 **默认带宽**（接近你实际宽带即可）；
3. （可选）加几条 **直连/代理规则**；
4. 设 **WebUI 端口与访问密码**；
5. 自动完成安装与验证，打印出口 IP 和面板地址。

完成后浏览器打开 `http://<树莓派IP>:8088` 即可进入管理面板。
此时 Docker、apt、curl、Claude Code 等全部自动走节点，无需再单独配置。

> 首次会直连 GitHub 下载 mihomo，可能较慢；失败会自动回退到已知可用版本，也可在设置里填下载镜像。

---

## 🖥️ WebUI 面板

| 标签页 | 能做什么 |
|--------|----------|
| **节点** | 订阅管理（增删/更新/自动间隔）、粘贴多协议链接批量添加、表单编辑、删除、拖动/↑↓排序、测速、切换当前出口 |
| **路由分流** | 一键分流预设勾选、增删改规则（值 + 类型 + 直连/代理/拦截）、实时预览生成的 mihomo 规则、设兜底策略 |
| **流量** | 实时上/下行速度、活动连接列表、最近日志、一键断开全部连接 |
| **设置** | 默认带宽、混合端口、TUN 协议栈、日志级别、IPv6、全屋网关、DNS、fake-ip 网段、下载镜像、面板端口/密码 |
| **工具** | 预览将生成的配置、导出节点链接、重启/停止 mihomo、**一键自检**、**恢复默认设置**、**一键卸载**（可选 purge） |

改完任何东西，点右上角 **「应用配置并重启」** 即生效（应用前会用 `mihomo -t` 校验，**校验不过不会覆盖**线上配置）。

---

## ⌨️ 命令行（装好后可用 `pihy2`）

```bash
pihy2 install            # 部署向导；已部署时会先弹管理菜单（继续向导/自检/状态/恢复默认/卸载）
pihy2 add 'hy2://...'    # 快速加节点（也可管道：echo 链接 | pihy2 add）
pihy2 add 'hy2://...' --apply   # 加完直接应用
pihy2 sub add 'https://订阅URL' --name 机场 --apply   # 添加订阅（定时自动更新）
pihy2 sub update all --apply    # 立即更新全部订阅
pihy2 sub list                  # 查看订阅
pihy2 status --ip        # 查看服务状态 + 出口 IP
pihy2 apply              # 重新生成并应用配置
pihy2 config             # 打印将生成的 mihomo 配置
pihy2 restart            # 重启 mihomo
pihy2 web --port 8088    # 前台启动 WebUI（一般由 systemd 托管）
pihy2 selftest           # 运行期健康自检（安装/服务/配置/出口；--quick 跳过出口探测）
pihy2 logs -n 200        # 查看 pihy2 系统日志（异常/错误追溯；--grep/--level 过滤）
pihy2 restore-defaults   # 把设置恢复出厂默认（不动节点/订阅/规则/面板密码，--apply 立即生效）
pihy2 backup > bak.json  # 导出完整状态（节点/订阅/规则/设置，含明文密码，妥善保管）
pihy2 restore bak.json --apply   # 从备份恢复（经清洗后覆盖），--apply 立即生效
pihy2 update             # 刷新 mihomo 二进制（--code 同时更新 pihy2 代码，需 /opt/pihy2 为 git 仓库）
pihy2 uninstall          # 卸载（--purge 同时删二进制、配置与 /etc/pihy2 状态）
```

---

## 🔀 路由规则怎么写

在“路由分流”里每条规则填一个**值**并选**策略**（直连/代理/拦截），类型留“自动判别”即可：

| 你填的值 | 自动识别为 | 含义 |
|----------|-----------|------|
| `*.cn` 或 `cn` | `DOMAIN-SUFFIX,cn` | 所有 `.cn` 域名 |
| `github.com` | `DOMAIN-SUFFIX,github.com` | github.com 及其子域 |
| `netflix` | `DOMAIN-KEYWORD,netflix` | 含该关键词的域名 |
| `ex*ple.com` | `DOMAIN-WILDCARD,ex*ple.com` | 通配符匹配 |
| `1.2.3.0/24` | `IP-CIDR,1.2.3.0/24` | IP 段 |
| `CN`（类型选 GEOIP） | `GEOIP,CN` | 中国大陆 IP（需地理库，见下） |

默认已内置：**`.cn` 域名直连，其余走代理**（刻意不含 GEOIP，做到“开箱即用、首次部署不依赖联网下载地理库”）。
想要更全面的“大陆 IP 直连”，**部署完成后**在面板加一条 `GEOIP,CN → 直连` 即可——此时 mihomo 已在运行，
会自动通过代理下载地理库。私有网段（`192.168/16`、`10/8`、`172.16/12` 等）始终强制直连，确保 SSH/局域网访问不受影响。

---

## 🔗 链式代理（住宅 IP 出口）

想让出口用上**其他国家家庭原生 IP**（更干净、不易被风控），但这类住宅 HTTP/SOCKS5 代理**从国内不能直连**——
在「节点」页点 **「+ 链式代理」** 手填表单即可：

1. 选 **类型**（SOCKS5 / HTTP），填住宅代理的 **服务器 / 端口 / 用户名 / 密码**（无鉴权可留空）；
2. **前置代理（必选）**：选一个国内可达的普通节点（hy2/vless/…），住宅代理会挂在它后面出网；
3. 添加后，节点列表里会显示 `链式→<前置节点名>` 标记，点圆点把它设为当前出口即可。

流量路径：`树莓派 → 前置节点(国内可达) → 住宅 IP 出口(国外家宽) → 互联网`。前置只能选「非链式」节点，
天然避免循环链；前置节点被删时，该链式出口会自动跳过、不会下发坏配置。

> 链式出口节点没有分享链接格式，**「导出节点链接」会自动跳过它们**——增删改请通过面板表单。
> 底层即 mihomo 的 [`dialer-proxy`](https://wiki.metacubex.one/en/config/proxies/dialer-proxy/)。

---

## 📂 项目结构

```
install.sh            一键引导脚本（复制到 /opt/pihy2 并启动向导）
pihy2/
  parser.py           节点链接解析（hysteria2/hy2/base64 订阅）
  config_gen.py       生成 mihomo config.yaml（自带零依赖 YAML 序列化）
  store.py            状态持久化（/etc/pihy2/state.json）
  manager.py          TUN/下载/systemd/应用/状态/clash API
  wizard.py           交互式命令行向导
  webui.py            WebUI 服务 + REST API
  __main__.py         命令行入口（python3 -m pihy2）
web/                  WebUI 前端（原生 HTML/CSS/JS，无框架）
docs/手动配置指南.md   原始逐步手动配置指南（原理参考）
```

运行期文件：mihomo 在 `/usr/local/bin/mihomo`，配置在 `/etc/mihomo/config.yaml`，
pihy2 状态在 `/etc/pihy2/state.json`（所有节点/规则/设置的唯一来源，配置由它生成）。

---

## 🛠️ 排错

| 现象 | 处理 |
|------|------|
| 出口 IP 不是节点地区 | 在“工具”里看配置、`pihy2 status` 看日志；确认节点本身可用 |
| 日志报证书错误 | 编辑节点勾选“跳过证书校验”，应用配置 |
| TUN 起不来 / operation not supported | 设置里把 TUN 协议栈改成 `gvisor`，应用配置 |
| 下载 mihomo 太慢/失败 | 设置里填“GitHub 下载镜像前缀”，或手动放二进制到 `/usr/local/bin/mihomo` 后重跑 `pihy2 install` |
| 忘记/想改面板密码 | 设置→面板访问→输入新密码保存；要取消密码勾选“取消密码保护”（取消后只能本机访问） |
| 面板打不开 | `systemctl status pihy2-web`；确认端口与 `<树莓派IP>` 正确 |

更底层的原理与手动等价操作，见 [`docs/手动配置指南.md`](docs/手动配置指南.md)。

---

## ⚠️ 安全提示

WebUI 能修改系统级代理并以 root 运行后台服务，因此：

- 向导**强制设置访问密码**（留空会自动生成并显示）；**未设密码时面板只监听 `127.0.0.1`**，不会暴露到局域网。
- 登录有失败次数限制与延时（防爆破），token 有有效期；`state.json` / `config.yaml` 仅 root 可读（`600`）。
- clash 外部控制器被强制限定为本机回环、下载镜像强制 `https`，避免 SSRF 与二进制被替换；固定版本二进制校验 SHA-256。

请只在可信局域网内使用。本工具用于在你自己拥有的设备上配置合法代理。

---

## 🧪 开发 / 测试

零运行时依赖；回归自检只用标准库（装有 PyYAML 时再额外与其交叉校验，没有则自动跳过那部分）：

```bash
python3 test_smoke.py        # 开发期回归自检：协议解析 / 配置生成 / 脱敏 / YAML / 状态迁移 / 维护功能
pip install pyyaml           # 可选：开启与 PyYAML 的交叉校验（仅测试用，非运行时依赖）
```

> `test_smoke.py` 是**离线开发期**回归（不碰系统）；`pihy2 selftest` 是**运行期**体检（查这台机器此刻装好没、跑起来没、配置合不合法），两者互补。

CI 见 [`.github/workflows/test.yml`](.github/workflows/test.yml)（在 3.8 与 3.12 上跑上面的自检）。

代码注释里形如 `SEC-*/BUG-*/CONFLICT-*/DC-*/ROBUST-*/FRONT-*/FEAT-*` 的编号，是历次代码审查
发现项的稳定标签：每条注释自带完整说明、用作回归记忆，改动相关逻辑时勿无意回退（对应的逐轮
审查报告未随生产版仓库一起发布）。

---

## 📋 更新日志

### v1.3.2 —— 第二轮独立审计修复

- **A1/A2 scrub 绕过**：密码含 `@` 的订阅 URL（`https://u:p@ss@host`）原修复会漏出密码尾段——改为按 URL authority 里“最后一个 @”拆分（与 `urllib`/parser 一致），且只动 authority、不误伤 path/query 里的 `@`；`Authorization` 在 dict/JSON repr 形态（`{'authorization': '...'}`）原修复失效，现兼容引号包裹的键。
- **A4/A8 scrub 覆盖**：补“空格+引号裸值”（`password 'xxx'`，不误伤自然语言）；键名扩展 `access_token`/`api_token`/`csrf_token`/`api_key`/`private_key` 等；URL scheme 扩 `ws(s)`/`ftp`。
- **A3 悬空 dialer-proxy**：前置节点 build 抛异常被跳过时，引用它的链式出口会带悬空 `dialer-proxy` 让 `mihomo -t` 永久卡死——build 后按实际下发的名字过滤一遍（latent 兜底）。
- **A5 恶意 id XSS**：恢复恶意备份时，含引号/括号的节点 id 会进前端 inline `onclick` 造成存储型 XSS——在 `_migrate` 这个唯一入口校验 id 匹配 `^[A-Za-z0-9_-]{1,64}$`，不符即重发（比前端 N 处转义更稳）。
- **A6 文档化**：注明 `pihy2.log` 在多进程并发写下为 best-effort，systemd journal 才是权威可追溯来源。

### v1.3.1 —— 安全加固（独立审计修复）

- **H1 日志凭据泄漏**：订阅/webhook URL 内嵌的 `user:pass@` 现在落盘前被剥离（原 scrub 拦不住 URL userinfo）。
- **H2 本地提权原语**：`restore_state` 的 `tempfile.mktemp()`（符号链接竞争→root 任意文件覆盖）改为 `mkstemp`（O_EXCL）。
- **H3 scrub 残留**：`Authorization: Bearer <jwt>` 现整体脱敏（原正则只吃掉 `Bearer`、token 明文残留）；裸 `bearer <token>` 同样覆盖。
- **M1 并发数据完整性**：`/api/restore` 补上 webui 进程锁，与其它写端点对齐（避免与订阅更新并发静默丢数据）。
- **M4**：`pihy2 update --code` 的 `.bak` 备份目录收紧到 `0700`。
- **L1 测试**：补 scrub 回归 + 新端点（`/api/syslogs`/`/api/backup`/`/api/restore`）鉴权与 rebinding host 守卫的**实服务集成测试**。

### v1.3 —— 可运维性

- **完整状态备份/恢复**：`pihy2 backup > bak.json` / `pihy2 restore bak.json --apply`，面板「工具」页「下载备份 / 从文件恢复」。
  恢复经 `_migrate` 清洗后原子覆盖（脏备份会被拒，不会写坏 state）。
- **`pihy2 update`**：默认刷新 mihomo 二进制（重跑幂等的 `install_mihomo`）；`--code` 在 `/opt/pihy2` 为 git 仓库时**先打包备份**再 `git pull`。
- **掉线告警**：可选 Webhook（设置→高级）。订阅更新失败时 POST JSON；复用订阅抓取的 SSRF 钉死连接（拒绝内网/本机），超时短、绝不阻塞主流程；未配 Webhook 时仅写日志（v1.1 已让一切可追溯）。
- **地理库自检**：`pihy2 selftest` 新增「地理库」项——用了 GEOIP/GEOSITE 规则时提示地理库状态（mihomo 运行时自动下载，首次部署前可能缺失）。

### v1.2 —— 性能 + UDP 安全

**性能与连接复用**
- 全局下发 `tcp-concurrent`（并发建连）、`keep-alive-interval`/`keep-alive-idle`（TCP 保活，复用连接、减少重连）。
- 新增「mux 多路复用」开关（默认关）：开启后 vmess/vless/trojan 复用代理连接，减少逐流 TCP+TLS 握手。
- AUTO 自动测速组的 `interval`/`tolerance` 可在面板调整（节点不稳时切更快）。

**UDP 安全（直接回应“UDP 丢包/绕过/泄漏真实 IP”的担心）**
- 新增「强制 TCP」开关（`disable_proxy_udp`，默认关）：开启后所有可关 UDP 的出站一律 `udp:false`，
  浏览器不走 QUIC/UDP、降低 UDP 被限速的面；**hy2/tuic 本就是 UDP 协议，不受影响**（要 TCP 得换前置协议）。
- 节点级「启用 UDP 中继」开关：可对单个 vless/vmess/trojan/ss/socks5 节点关闭 UDP。
- `pihy2 selftest` 新增「UDP 防泄漏」项：体检 TUN 接管 + 出口 UDP 支持的结构保证，把“相信 UDP 没泄漏”变成“看得见”。
- 链式代理表单标注：树莓派这一端的传输层由前置协议决定（hy2/tuic=UDP，vless/vmess/trojan=TCP），链式出口改变不了前置段。

> 说明：TUN + fake-ip + 兜底走代理 的架构本身已让 UDP 经代理转发（不裸奔泄漏）；v1.2 在此基础上加了
> “强制 TCP”与“可观测自检”，把保证变成开关与绿灯。回归自检新增 15 项性能/UDP 断言。

### v1.1 —— 安全加固 + 可观测性基座

**可追溯（日志）**
- 新增结构化日志（零依赖，标准库 `logging`）：所有异常/错误落 `/var/log/pihy2/pihy2.log`
  （轮转，约 6MB 上限）+ stderr→journald；不可写时退化为仅 stderr，绝不因日志让程序起不来。
- **请求级追溯 ID**：面板每个请求绑定一个 ID，异常带完整堆栈入日志、并把 ID 回传前端
  （`服务器内部错误（ID a3f9…）`），`grep <ID>` 即可定位。
- 把原先“静默吞异常”的点（`webui._safe` / `manager.run` / 订阅抓取 / 出口 IP 探测 / 配置校验失败 /
  状态文件损坏）全部改成“记录后兜底”，不再无声丢失。
- 落盘前 scrub `password/uuid/secret/token` 等密钥——日志是新泄露面，明文凭据不进文件。
- 查看入口：`pihy2 logs [-n|--grep|--level]`、面板「工具」页「系统日志」、`pihy2 selftest` 新增“系统日志”项。

**安全加固**
- DNS 段显式 `ipv6`（跟随顶层），杜绝 AAAA 路径泄漏；新增可选「DNS 解析走代理规则」
  （`respect-rules`，默认关）让 DoH 经代理出网，连 DNS 服务器地址都不暴露给 ISP。
- 配置预览/`pihy2 config` 脱敏覆盖 http/socks5 链式出口的 `username`。

**正确性 / 工程**
- 订阅失败可追溯：订阅记录加 `last_error`，面板订阅卡直接显示“上次失败原因”，不再默默没更新。
- 补齐 CI：新增 `.github/workflows/test.yml`（Python 3.8 / 3.12 跑离线自检），兑现此前承诺。
- 回归自检新增 DNS/脱敏/日志/去重顺序无关/订阅 last_error 等断言（76 项全绿）。

