# pihy2 · 树莓派 hy2 全局代理一键部署

> 把树莓派整机流量透明走 hy2（hysteria2）节点。**不用手敲命令、不用手写配置**——
> 跟着向导填几项、把节点链接粘进去，就能一键装好；之后用中文 **WebUI** 可视化管理节点和分流。

底层用 **mihomo（Clash Meta）TUN + fake-ip**：DNS 在本地解析掉，不依赖节点 UDP 转发，
稳定不卡（原理与逐步手动做法见 [`docs/手动配置指南.md`](docs/手动配置指南.md)，已逐条实测验证）。

---

## ✨ 功能

- **一键部署向导**：准备 TUN → 下载 mihomo → 生成并校验配置 → 建服务开机自启 → 验证出口 IP，全程提示式。
- **粘贴即解析**：直接贴 `hysteria2://` / `hy2://` 链接（或 base64 订阅），自动提取
  服务器、端口、密码（`%2F` 等自动还原）、SNI、混淆、ALPN、带宽、端口跳跃、证书指纹。
- **多节点管理**：可视化增/删/改、拖动排序、一键测速、点选切换当前出口（尽量免重启）。
- **路由分流**：指定哪些域名/IP 走直连、哪些走代理，**支持通配符**（`*.cn`、`github.com`、`1.2.3.0/24`），
  自动判别规则类型；私有网段始终直连，**保证 SSH 永不掉线**。
- **完整设置**：默认带宽、TUN 协议栈、日志级别、DNS、fake-ip 网段、下载镜像等，界面里改。
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
| **节点** | 粘贴链接批量添加、表单编辑、删除、拖动排序、测速、点圆点切换当前出口 |
| **路由分流** | 增删改规则（值 + 类型 + 直连/代理/拦截），实时预览生成的 mihomo 规则，设兜底策略 |
| **设置** | 默认带宽、混合端口、TUN 协议栈、日志级别、IPv6、DNS、fake-ip 网段、下载镜像、面板端口/密码 |
| **工具** | 预览将生成的配置、导出节点链接、重启/停止 mihomo |

改完任何东西，点右上角 **「应用配置并重启」** 即生效（应用前会用 `mihomo -t` 校验，**校验不过不会覆盖**线上配置）。

---

## ⌨️ 命令行（装好后可用 `pihy2`）

```bash
pihy2 install            # 重新运行部署向导
pihy2 add 'hy2://...'    # 快速加节点（也可管道：echo 链接 | pihy2 add）
pihy2 add 'hy2://...' --apply   # 加完直接应用
pihy2 status --ip        # 查看服务状态 + 出口 IP
pihy2 apply              # 重新生成并应用配置
pihy2 config             # 打印将生成的 mihomo 配置
pihy2 restart            # 重启 mihomo
pihy2 web --port 8088    # 前台启动 WebUI（一般由 systemd 托管）
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
tests/test_basic.py   解析/规则/配置生成 + mihomo -t 校验测试
docs/手动配置指南.md   原始逐步手动配置指南（原理参考）
```

运行期文件：mihomo 在 `/usr/local/bin/mihomo`，配置在 `/etc/mihomo/config.yaml`，
pihy2 状态在 `/etc/pihy2/state.json`（所有节点/规则/设置的唯一来源，配置由它生成）。

---

## 🧪 测试

```bash
python3 tests/test_basic.py                 # 解析与配置生成逻辑
MIHOMO=/path/to/mihomo python3 tests/test_basic.py   # 额外用真实二进制做 mihomo -t 校验
```

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
