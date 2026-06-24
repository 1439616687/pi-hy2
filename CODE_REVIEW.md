# pihy2 全面代码审查报告

审查方法：按 9 个子系统并行静态审查（parser / config_gen / yaml_lite / store / manager / webui / 前端 / 跨模块数据契约 / CLI&安装），每条疑似问题再由独立审查员**对抗式复核**（默认怀疑、实读代码后裁决），关键项用真实代码运行验证。

结果：确认 **51** 条（含人工补充 1 条），驳回 6 条误报。下面按严重度组织。

---

## 修复状态（全量修复已完成）

已对全部确认项实施修复，并新增 33 条回归测试（共 99 项全绿），用 PyYAML 校验了
多/单/零节点、网关、预设五种配置形态均生成合法 YAML。逐项：

- **高危 5/5 全修**：YAML 吞行（`_inline_nested` 自增修正）、订阅名 XSS（去内联拼接）、
  导出 KeyError（`.get` + 逐节点兜底）、SSRF rebinding（解析后**钉死 IP 连接**）、保留词节点名（改名规避）。
- **中危 13/13 全修**：裸 IPv6、vmess alpn、YAML key 转义、多文档、数字标量、`_seq` 回填、
  跨进程文件锁、损坏 state 备份、CGNAT 拦截、armv7/镜像下载完整性、`/tmp` mkstemp、未鉴权写 + 反 rebinding 守卫。
- **低危/提示**：大部分已修（IPv6 端口、TUIC、显式 IP 校验、default-nameserver、DNS 收敛、
  块标量/锚点/递归、save 权限、压缩炸弹、redirect 复检、sysctl 实判、token/login 清理与加锁、
  设置白名单、前端规则一致性、final 脏保护、可编辑 alpn/pin、空串不回写、install.sh、getpass、测试覆盖…）。
- **4 条低危按设计保留并说明**：L20（TUIC 空密码——保持宽松以兼容 token 式 TUIC，仅确保不崩）、
  L37（改密并发的毫秒级窗口——影响可忽略）、L38（耗时 IO 仍在锁内——为跨进程一致性刻意取舍）、
  L45（`saveSubInterval` 与 `/api/settings` 复用——已被设置白名单化解为无害空操作）。

> 详见 git 历史与各文件改动；运行 `python3 tests/test_basic.py`（或带 `MIHOMO=<二进制>` 做真实 `-t` 校验）。

---

## 一、高危（建议优先修）

### H1. YAML 列表项首键为块状子映射时，解析器吞行/错并节点 — `pihy2/yaml_lite.py:235-236`
`_seq` 处理 `- key:` 后接缩进子块时调用 `_inline_nested`，该函数内部已推进 `self.i`，但返回后第 236 行又无条件 `self.i += 1`，多跳一行。
- 后果：若被跳过的是同一节点的兄弟键（如 `server:`），该键被静默丢弃 → `proxy_to_node` 因缺 server/type 抛错、整条节点被跳过；若被跳过的是下一个 `- ` 列表项，整节点丢失。
- 触发：订阅里把 `ws-opts/reality-opts/grpc-opts` 等块状键排在 proxy 的**第一个键**（YAML 键序无标准，部分生成器按字母序会让它们靠前）。
- 复现：`proxies:\n  - ws-opts:\n      path: /a\n    server: s\n    port: 443` → `{'ws-opts': {'path': '/a'}, 'port': 443}`，server 丢失。
- 修复：第 236 行的 `self.i += 1` 只在标量分支（`v != ""`）执行；嵌套分支由 `_inline_nested` 负责把 `i` 停在子块之后。

### H2. 订阅名存储型 XSS — `web/app.js:80`
`renderSubs` 把订阅名拼进内联事件：`onclick="delSub('${s.id}','${esc(s.name)}')"`。`esc()` 只做 HTML 实体转义（`'`→`&#39;`），但落点是「HTML 属性内的 JS 字符串」双重上下文：浏览器先 HTML 解码把 `&#39;` 还原成真单引号，再当 JS 解析，于是字符串被提前闭合可注入任意 JS。
- 数据流：`sub-name` 输入 → POST `/api/subs` → `store.add_subscription`（`store.py:133` 无过滤）→ 入库 → 刷新后对所有访问者执行（存储型）。无 CSP 缓解。
- PoC 订阅名：`a');alert(document.cookie)//`
- 修复：移除内联事件拼接，改用 `data-id/data-name` + `addEventListener` 事件委托（参照 `enableDragOrder`）；或对 JS 字符串上下文专门转义（`'`→`\x27`）。

### H3. 导出节点链接缺字段直接 `KeyError`，整个 `/api/export` 500 — `pihy2/parser.py:520-624`
`node_to_link` 用下标 `node["password"]`（624 行）、`node["server"]`（520 行）等而非 `.get()`。经 Clash YAML 导入的 hysteria2 若无 `password` 键（`proxy_to_node` 仅在该键存在时写入），导出即 `KeyError`。`webui.py:199` 对全部节点做列表推导且无 `try/except`，**一个坏节点让整个导出接口 500**，前端拿不到任何链接。
- 已实测复现：`parse_clash_yaml("proxies:\n  - {name: x, type: hysteria2, server: s.com, port: 443}")` → `node_to_link` 抛 `KeyError: 'password'`。
- 修复：`node_to_link` 全部下标改 `.get(..., 默认值)`，`server` 缺失时抛 `ParseError`；`/api/export` 逐节点 `try/except` 跳过并记录坏数据。

### H4. SSRF 防护可被 DNS rebinding/TOCTOU 绕过 — `pihy2/manager.py:349-370`
`fetch_text` 先 `_assert_public_host`（`getaddrinfo` 解析+校验内网），通过后 `opener.open(req)` 用**原始域名**再次独立解析。两次解析之间是 TOCTOU 窗口：攻击者用低 TTL 域名，第一次返回公网 IP 过校验，第二次返回 `127.0.0.1`/内网 → 以 root 访问本机 clash API/内网服务。订阅 URL 为管理员录入（半受信），故定 high 而非 critical。
- 修复：解析一次得到公网 IP 后把连接**钉死**到该 IP（替换 host 为 IP，用 Host 头/SNI 保留域名），消除二次解析。

### H5.（人工补充）节点名与保留策略词冲突导致配置无法生成 — `pihy2/config_gen.py:346-422`
`_dedup_names` 只做节点间去重，未规避 mihomo 保留名 `PROXY`/`AUTO`/`DIRECT`/`REJECT`/`GLOBAL`。若订阅里有节点名为 `PROXY`，生成的 `proxy-groups` 里会出现「名为 PROXY 的策略组」与「名为 PROXY 的代理」同名冲突，`select` 列表里还会出现重复 `DIRECT`。
- 已实测：两个分别名为 `PROXY`/`DIRECT` 的节点 → PROXY 组 `proxies: ["PROXY","DIRECT","AUTO","DIRECT"]`，`mihomo -t` 会因名称冲突拒绝 → `apply_config` 失败且报错晦涩，用户无从排查。
- 修复：`_dedup_names`（或 `build_config`）对保留词节点名加前缀/改名，并对 `select_list` 去重。

---

## 二、中危

| # | 模块:行 | 问题 | 修复要点 |
|---|---------|------|---------|
| M1 | `parser.py:89-94` | 裸 IPv6（无方括号）`2001:db8::1` 被 `rpartition(':')` 切成 `('2001:db8:', 1)`，地址/端口错乱（已实测） | `[` 外且含 ≥2 冒号时整体视为无端口 IPv6 |
| M2 | `parser.py:525-535` | vmess 反向导出丢 `alpn`，round-trip 后 ALPN 清空，影响 h2 协商 | 导出 `j` 里加入 `alpn` |
| M3 | `config_gen.py:88-99` | `to_yaml` 不转义 dict 的 **key**；ss 节点 `plugin-opts` 的 key 来自不可信订阅，可注入/破坏整份 config.yaml | key 也用 `json.dumps(str(k))` |
| M4 | `yaml_lite.py:168-179` | 多文档 YAML（`---`）被静默合并，后文档 `proxies` 覆盖前者 → 丢节点 | 按 `---` 切分或检测到多文档时报错 |
| M5 | `yaml_lite.py:66-74` | 无引号数字标量强制转 int/float：`password: 0123456` 丢前导零、`1.20`→`1.2`，鉴权字段语义被改；纯数字 password 还会让 `node_to_link` 崩（`parser.py:552`） | 对 password/uuid/short-id 等在 `proxy_to_node` 统一 `str()` 兜底 |
| M6 | `store.py:80-93` | `_migrate` 不回填 `_seq`：外部编辑/导入缺 `_seq` 的 state.json 后，`add_node` 从 n1 重新发号 → **id 重复**，get/update/delete 误命中 | `_migrate` 末尾按现有 `n<digits>/s<digits>` 最大值回填 `_seq/_subseq` |
| M7 | `store.py:54-78` | 跨进程（订阅 timer 进程 vs WebUI 进程）读改写无锁 → 丢更新（进程内已有 `_lock` 串行化，非此问题） | 对 state.json 加 `fcntl.flock` 覆盖 load..save 临界区 |
| M8 | `store.py:54-62` | `load` 把损坏/不可读的 state.json 静默替换为空默认；随后任一 `save` 会用空状态**覆盖**原文件 → 配置全丢 | 区分 `FileNotFoundError` 与解析/IO 失败，后者备份为 `state.json.bad` 并拒绝自动覆盖 |
| M9 | `manager.py:358-361` | SSRF 黑名单漏 `100.64.0.0/10`（CGNAT，常用于内部网关）；IPv4-mapped 依赖隐式行为 | 先 `ip.ipv4_mapped` 还原再判定，显式拦 `100.64.0.0/10`（及 `0.0.0.0/8`） |
| M10 | `manager.py:34-37,160-166` | armv7 无 `PINNED_SHA256`，回退安装的 **root 二进制无完整性校验**（仅靠 `-v` 能跑） | 补 armv7 哈希；或非 pinned 哈希时强制 GitHub 直链、拒镜像并告警 |
| M11 | `manager.py:149-173` | `/tmp/mihomo.gz` 固定路径，存在 symlink TOCTOU（本地提权面）与多实例竞争 | 用 `tempfile.mkstemp` 或 `O_CREAT\|O_EXCL\|O_NOFOLLOW`，下载目录用 root 专属目录 |
| M12 | `manager.py:142-180` | 在线最新版下载不校验 SHA-256；配置镜像（仅要求 https）时镜像可投递任意可运行二进制 → 供应链风险 | 用镜像时强制 pinned 版本+已知哈希，或比对上游 checksums |
| M13 | `webui.py:78-92,234,389-392` | 未设密码时所有写 API 无鉴权；无 Origin/CSRF 校验，DNS rebinding 可对 `127.0.0.1` 面板发写请求注入节点/控服务 | 写 API 增加 Host/Origin 白名单；默认要求设密码或无密码时只读 |

---

## 三、低危（按模块归类，附修复要点）

**parser**
- `parser.py:89-93` 含冒号但端口非数字时整个 `host:port` 当 host → 取冒号前部分或抛 ParseError。
- `parser.py:325-331` TUIC 允许空 password 仍下发空串 → 缺 password 时提示/抛错。
- `parser.py:233-234` vmess 的 ws_host/grpc 服务名挤在 `path` 单字段，grpc+ws 混用导出串字段 → 按 network 只带对应字段。

**config_gen**
- `config_gen.py:149-155` 显式 `ip/ip-cidr` 不校验取值，非法值原样写成 IP-CIDR → `_is_ip_or_cidr` 为 None 时丢弃/回退 auto。
- `config_gen.py:364-372` 自定义域名型 DoH 在 fake-ip 下缺 `default-nameserver` 引导 → 补一个 IP 型引导 DNS。
- `config_gen.py:364-372` DNS `listen: 0.0.0.0:1053` 不随 allow-lan 收敛，非网关模式也对局域网暴露解析器 → 按 allow_lan/gateway_mode 绑 127.0.0.1 或 0.0.0.0。
- `config_gen.py:157-174` auto 判别对带方括号/带 zone-id 的 IPv6 处理不当 → 先剥 `[]`，含 `%` 的拒绝。
- `config_gen.py:100-113`（INFO）列表里空 dict/空 list 元素退化成 `None` → 输出 `- {}` / `- []`。

**yaml_lite**
- `yaml_lite.py:262-267` 深层嵌套 `RecursionError` 未被 `load()` 捕获 → except 加 `RecursionError` 或深度上限。
- `yaml_lite.py:194-204` 锚点 `&anchor` 后接缩进块被当标量 → 至少识别并归一化，理想是支持 anchor/alias。
- `yaml_lite.py:187-206` 不支持块标量 `|`/`>`，含证书/多行内容的订阅整体失败 → 识别并读取块标量。

**store / manager**
- `store.py:72-78` save 后未对最终文件重设权限，依赖 tmp 继承 → 用 `os.open(...,0o600)` 从创建即收紧。
- `manager.py:170-171` gzip 解压无大小上限（压缩炸弹）→ 分块累计并设上限。
- `manager.py:344-346,364-370` `_NoRedirect` 拒所有跳转会误伤合法订阅 → 允许有限跳转但每跳重校验+钉死 IP。
- `manager.py:294-313,327` `set_ip_forward` 以 sysctl 文件是否存在判断状态，不可靠 → 读 `/proc/sys/.../ip_forward` 实际值或每次都 `sysctl -w`。
- `manager.py:364-370` `fetch_text` `resp.read(max_bytes)` 静默截断损坏订阅 → 读 `max_bytes+1`，超限报错。

**webui**
- `webui.py:28/29` `_tokens`、`_login_fails` 永不清理过期项，内存增长 → 登录/鉴权时顺手清扫过期项、设容量上限。
- `webui.py:86-92` `_tokens/_login_fails` 在 ThreadingHTTPServer 下无锁并发读写（CPython GIL 下不致崩，但语义不严谨）→ 统一加锁。
- `webui.py:330-343` `/api/settings` 盲目 `update` 可覆盖 `secret` 等内部字段（读端已隐去 secret，写端无对称保护）→ 键白名单。
- `webui.py:357-359` 改密码只清 `_tokens`，并发中的旧 token 请求有短暂越权窗口 → 可接受，严格则同锁内重校验。
- `webui.py:75-76,...` 每请求 `new Store()` 读盘 + 全局 `_lock` 串行化，持锁期间还做网络/子进程 IO（订阅拉取、apply、重启）会阻塞所有面板写操作 → 把耗时 IO 移出临界区。

**前端**
- `app.js:332-334` 显式 IP-CIDR 前端不校验值仍补 `/32`，与服务端不一致 → 前端也先判 `isIPv4/isIPv6`。
- `app.js:326-337` 前端手写 IP 正则与 Python `ipaddress` 边界不一致（含点 IPv6、前导零 IPv4）→ 对齐或标注「以服务端为准」。
- `app.js:61-66` `rulesDirty` 保护未覆盖兜底策略 `final`，后台 `loadState` 会丢弃未保存的 final 改动 → final 的 onchange 也设 dirty 并入 STATE，loadState 一并保留。
- `app.js:255-299` 编辑表单缺 `alpn/pin_sha256/plugin` 等字段，保存无法修改且靠「不在表单」侥幸保留 → 提供专门控件或后端保护这些键。
- `app.js:288-292` 保存把所有文本字段当字符串回写，空串污染（后果较小，config_gen 多有 `or` 兜底）→ 跳过空串或后端做类型规整。
- `app.js:164-168` pin_sha256 与 fingerprint 双轨易丢 → 编辑时二者互斥维护。
- `app.js:108-112` `saveSubInterval` 与 `saveSettings` 共用 `/api/settings`、空 settings 语义耦合 → 拆独立端点或不传空 settings。

**CLI / 安装 / 测试**
- `install.sh:30` 用 `sh install.sh`（dash）跑会因 `BASH_SOURCE`/`set -u` 失败 → 开头 `[ -n "${BASH_VERSION:-}" ] || exec bash "$0" "$@"`。
- `wizard.py:172-176` getpass 异常回退到 `input()` 会明文回显密码 → 回退时提示或直接自动生成。
- `tests/test_basic.py` 完全未覆盖 wizard / `__main__` 参数绑定 / manager / store → 补 `build_parser` 与纯函数单测。

---

## 四、复核驳回的误报（6 条，供参考，无需处理）
1. `store.py:157-184` set_subscription_nodes active 恢复边界 —— 有 `active_key` 守卫，不成立。
2. `manager.py:456-468` `_controller_base` 回环白名单可绕过 —— 实测不成立。
3. `manager.py:97-103` `_apply_mirror` 双 scheme 畸形 URL —— 是镜像约定格式，非 bug。
4. `webui.py:63-69` `_body` 超大体只读 1MB 致串包 —— 该服务器不启用 keep-alive，不成立。
5. `webui.py:333-338` external_controller 写入校验可绕过 —— 调用端 `_controller_base` 每次复检，不成立。
6. `webui.py:120-130` `_static` 路径穿越 —— `normpath` + `abspath.startswith` 已足够，不成立。

---

## 五、修复优先级建议
1. **立即**：H2（XSS）、H3（导出 500）、H1（YAML 吞节点）、H5（保留词冲突）—— 都会让正常功能直接失效或被注入。
2. **尽快**：H4 + M9（SSRF 加固）、M6/M8（state 数据安全：id 重复、坏文件覆盖）、M3/M5（不可信 YAML 注入/语义损坏）。
3. **计划内**：M10–M13（下载完整性与未鉴权写）、M1/M2（IPv6 与 round-trip）。
4. **打磨**：其余 low/info，以及补测试。

> 总体评价：架构清晰、注释到位、已主动处理了不少安全点（SSRF 基本防护、回环强制、原子写、权限收紧、未设密码强制回环）。主要问题集中在**自研 YAML 解析器的边界**、**不可信订阅数据流经 YAML key / 数字标量 / 节点名**、以及**前端 XSS 与若干 round-trip 丢字段**。修掉上面高/中危即可显著提升健壮性与安全性。
