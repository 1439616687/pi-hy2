"""由 节点 / 路由规则 / 设置 生成 mihomo config.yaml。

设计要点：
  * 不依赖 PyYAML —— 自带一个最小 YAML 序列化器，字符串用 json 转义（JSON 字符串
    是合法的 YAML 双引号标量），密码里的 / + 等特殊字符不会出错。
  * 始终在最前面注入“私有网段直连”安全规则，保证 SSH/局域网永远不被代理切断。
  * 路由规则支持通配符，自动判别规则类型（域名/后缀/关键词/通配/IP-CIDR/GEOIP/GEOSITE）。
  * 多节点时生成 PROXY(手动选择) 与 AUTO(自动测速) 两个策略组。
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
import urllib.parse

# 默认设置（store 会以此为模板）
DEFAULT_SETTINGS = {
    "mixed_port": 7890,
    "allow_lan": False,
    "gateway_mode": False,           # 全屋网关：allow-lan + 开启 IP 转发
    "log_level": "warning",          # silent/error/warning/info/debug
    "ipv6": False,
    "tun_stack": "system",           # system/gvisor/mixed
    "tun_dns_hijack": ["any:53"],    # TUN 劫持的 DNS 目标；与本机 Pi-hole/dnsmasq 冲突时可改/清空
    "tun_auto_redirect": True,       # nftables 重定向；与 Docker/firewalld 冲突或无 nft 时可关
    "fake_ip_range": "198.18.0.1/16",
    "dns_nameservers": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
    "dns_china": ["223.5.5.5", "119.29.29.29"],
    "default_up": "20 Mbps",
    "default_down": "100 Mbps",
    "presets": [],                   # 启用的一键分流预设 key 列表
    "final": "PROXY",                # 兜底策略：PROXY 或 DIRECT
    "github_mirror": "",             # mihomo 下载镜像前缀（须 https://，留空=直连 GitHub）
    "external_controller": "127.0.0.1:9090",  # clash API，供面板做实时切换/测速
    "secret": "",                    # clash API 密钥（首次安装随机生成）
}

# 始终直连的安全规则（保证 SSH 不断）。放在所有用户规则之前。
_SAFE_DIRECT_CIDRS = [
    "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12",
    "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
]

# 一键分流预设：key -> (显示名, 说明, [mihomo 规则行])。GEOSITE/GEOIP 需地理库，
# mihomo 运行时会自动下载（走代理），故预设只建议在部署完成后开启。
RULE_PRESETS = {
    "ads":      ("广告拦截", "拦截广告与追踪域名", ["GEOSITE,category-ads-all,REJECT"]),
    "streaming": ("流媒体走代理", "Netflix/YouTube/Disney 等强制走节点",
                  ["GEOSITE,netflix,PROXY", "GEOSITE,youtube,PROXY", "GEOSITE,disney,PROXY",
                   "GEOSITE,bahamut,PROXY", "GEOSITE,hbo,PROXY", "GEOSITE,spotify,PROXY"]),
    "google":   ("Google 走代理", "Google 全系走节点", ["GEOSITE,google,PROXY"]),
    "telegram": ("Telegram 走代理", "Telegram 域名与 IP 走节点",
                 ["GEOIP,telegram,PROXY,no-resolve", "GEOSITE,telegram,PROXY"]),
    "apple_cn": ("Apple 国内直连", "Apple 中国区资源直连", ["GEOSITE,apple-cn,DIRECT"]),
    "cn_direct": ("大陆直连(IP+域名)", "中国大陆 IP 与域名直连（比默认更全）",
                  ["GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT"]),
}
# 应用顺序（靠前优先级高）：拦截 -> 强制代理类 -> 直连类
_PRESET_ORDER = ["ads", "streaming", "google", "telegram", "apple_cn", "cn_direct"]


def expand_presets(enabled) -> list[str]:
    """把启用的预设 key 展开成 mihomo 规则行（按既定优先级排序，去重）。"""
    # 容错：presets 若被存成字符串/整数等非列表类型（脏 state / API 误传），按空处理而非崩溃
    if not isinstance(enabled, (list, tuple, set)):
        enabled = []
    enabled = set(enabled)
    out, seen = [], set()
    for key in _PRESET_ORDER:
        if key in enabled and key in RULE_PRESETS:
            for line in RULE_PRESETS[key][2]:
                if line not in seen:
                    seen.add(line)
                    out.append(line)
    return out


# ---------------------------------------------------------------- YAML 序列化
def _yaml_scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return str(v)
    # 字符串：用 json.dumps（ensure_ascii=False 保留中文），结果是合法 YAML 双引号标量
    return json.dumps(str(v), ensure_ascii=False)


_SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")


def _yaml_key(k) -> str:
    """安全输出 dict 的 key：普通键原样，含 ':'/'#'/空白/空串等不安全键用引号包裹转义。
    来自不可信订阅的 plugin-opts 等键可能含特殊字符，不处理会生成非法/被注入的 YAML。"""
    k = str(k)
    if k and _SAFE_KEY_RE.match(k):
        return k
    return json.dumps(k, ensure_ascii=False)


def to_yaml(data, indent: int = 0) -> str:
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            key = _yaml_key(k)
            if isinstance(v, dict) and v:
                lines.append(f"{pad}{key}:")
                lines.append(to_yaml(v, indent + 1))
            elif isinstance(v, list) and v:
                lines.append(f"{pad}{key}:")
                lines.append(to_yaml(v, indent + 1))
            elif isinstance(v, (dict, list)):  # 空容器
                lines.append(f"{pad}{key}: {'{}' if isinstance(v, dict) else '[]'}")
            else:
                lines.append(f"{pad}{key}: {_yaml_scalar(v)}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item:
                # 列表里的字典：第一个键跟在 '- ' 后，其余对齐
                inner = to_yaml(item, indent + 1)
                inner_lines = inner.split("\n")
                first = inner_lines[0][len(pad) + 2:]
                lines.append(f"{pad}- {first}")
                lines.extend(inner_lines[1:])
            elif isinstance(item, list) and item:
                lines.append(f"{pad}-")
                lines.append(to_yaml(item, indent + 1))
            elif isinstance(item, (dict, list)):  # 空容器，避免退化成 None
                lines.append(f"{pad}- {'{}' if isinstance(item, dict) else '[]'}")
            else:
                lines.append(f"{pad}- {_yaml_scalar(item)}")
    return "\n".join(lines)


# ---------------------------------------------------------------- 规则判别
def _is_ip_or_cidr(value: str):
    try:
        if "/" in value:
            return ipaddress.ip_network(value, strict=False)
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def classify_rule(value: str, rtype: str = "auto") -> tuple[str, str]:
    """把一条用户规则的值 + 类型，转成 (mihomo规则类型, 规范化后的值)。

    rtype 为 'auto' 时自动判别；否则按显式类型。返回如 ('DOMAIN-SUFFIX', 'google.com')。
    """
    value = str(value).strip()
    rtype = str(rtype or "auto").strip().lower()
    # 带方括号的 IPv6 字面量（[2001:db8::1] 或 [2001:db8::1]/64）先剥括号，便于判别
    mb = re.match(r"^\[([0-9A-Fa-f:]+)\](/\d+)?$", value)
    if mb:
        value = mb.group(1) + (mb.group(2) or "")
    # 去掉 IPv6 zone-id（如 fe80::1%eth0）：mihomo/Go 的 ParseCIDR 不接受 %zone。
    # 仅当“去 zone 后确为合法 IP/CIDR”时才采用，避免误伤恰好含 '%' 的域名/关键词规则。
    if "%" in value:
        stripped = re.sub(r"%[^/]+", "", value)
        if _is_ip_or_cidr(stripped) is not None:
            value = stripped

    explicit = {
        "domain": "DOMAIN",
        "domain-suffix": "DOMAIN-SUFFIX",
        "suffix": "DOMAIN-SUFFIX",
        "domain-keyword": "DOMAIN-KEYWORD",
        "keyword": "DOMAIN-KEYWORD",
        "domain-wildcard": "DOMAIN-WILDCARD",
        "wildcard": "DOMAIN-WILDCARD",
        "ip-cidr": "IP-CIDR",
        "ip": "IP-CIDR",
        "geoip": "GEOIP",
        "geosite": "GEOSITE",
        "process-name": "PROCESS-NAME",
    }
    if rtype in explicit:
        kind = explicit[rtype]
        if kind == "IP-CIDR":
            net = _is_ip_or_cidr(value)
            if net is None:
                # 显式标为 IP 却不是合法 IP/CIDR：抛错，由 build_config 兜底跳过该规则，
                # 避免把任意字符串当 IP-CIDR 下发导致 mihomo 校验失败。
                raise ValueError(f"非法 IP/CIDR：{value}")
            if "/" not in value:
                value = f"{value}/32" if "." in value else f"{value}/128"
        elif kind in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD") and not value:
            # 显式域名类却为空：抛错由 build_config 跳过，避免下发 DOMAIN-SUFFIX,, 这类被 mihomo -t 拒绝、
            # 进而卡住此后每一次 apply 的坏规则（含订阅定时器）。
            raise ValueError("规则值为空")
        return kind, value

    # auto 智能判别
    net = _is_ip_or_cidr(value)
    if net is not None:
        if "/" in value:
            return "IP-CIDR", value
        return "IP-CIDR", (f"{value}/32" if "." in value else f"{value}/128")

    if value.startswith("*."):
        sub = value[2:]
        # *.cn / *.example.com -> DOMAIN-SUFFIX,<sub>（README 文档化：连该域及其子域，ccTLD 亦然）。
        # 但剥前缀后为空（"*."）或仍含通配（"*.*"）无法构成合法 suffix，回落 DOMAIN-WILDCARD 字面量，
        # 避免下发 DOMAIN-SUFFIX,, 这类被 mihomo -t 拒绝、卡死后续每次 apply 的空载规则（BUG-1）。
        if sub and "*" not in sub and "?" not in sub:
            return "DOMAIN-SUFFIX", sub
        return "DOMAIN-WILDCARD", value
    if "*" in value or "?" in value:
        return "DOMAIN-WILDCARD", value
    if value.startswith("."):
        sub = value[1:]
        if not sub:
            raise ValueError("规则值为空")
        return "DOMAIN-SUFFIX", sub
    if not value:
        raise ValueError("规则值为空")
    if "." in value:
        return "DOMAIN-SUFFIX", value
    # 单个词，无点：按关键词
    return "DOMAIN-KEYWORD", value


def rule_to_mihomo(rule: dict) -> str:
    """单条规则字典 -> mihomo 规则行字符串。"""
    kind, value = classify_rule(rule.get("value", ""), rule.get("type", "auto"))
    policy = str(rule.get("policy", "PROXY")).strip().upper()
    if policy not in ("DIRECT", "PROXY", "REJECT"):
        policy = "PROXY"
    # 仅 IP-CIDR 加 no-resolve：纯 IP 规则无需触发 DNS。
    # GEOIP 不能加 no-resolve，否则 fake-ip 下的域名连接无法解析出真实 IP 来匹配（会漏判）。
    suffix = ",no-resolve" if kind == "IP-CIDR" else ""
    return f"{kind},{value},{policy}{suffix}"


# ---------------------------------------------------------------- 节点 -> proxy
def _safe_int(v, default: int) -> int:
    """宽松转 int，容忍 "443"/"1.0"/None/非法值，避免脏字段让整份配置生成崩掉。
    'inf'/'1e400' 这类 float() 成功但 int() 抛 OverflowError、以及 nan，一并回落默认。"""
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    return int(f) if math.isfinite(f) else default


def _port(node: dict) -> int:
    """节点端口规整为 1..65535 的 int；缺失/非法回落 443，render 永不因脏 port 崩。"""
    p = _safe_int(node.get("port"), 443)
    return p if 1 <= p <= 65535 else 443


def _bandwidth(value, default: str) -> str:
    """规整带宽字符串：必须含数字，否则回落默认。
    避免 UI 清空带宽框时拼出 ' Mbps' 这类无数字的非法值被原样下发给 mihomo。"""
    s = str(value or "").strip()
    return s if re.search(r"\d", s) else default


def _apply_transport(p: dict, node: dict):
    """把 ws/grpc 等传输层字段写进 mihomo proxy。"""
    net = node.get("network")
    if net in ("ws", "grpc", "httpupgrade"):
        p["network"] = net
    if net in ("ws", "httpupgrade"):          # httpupgrade 复用 ws-opts
        ws = {"path": node.get("ws_path") or "/"}
        if node.get("ws_host"):
            ws["headers"] = {"Host": node["ws_host"]}
        p["ws-opts"] = ws
    elif net == "grpc" and node.get("grpc_service_name"):
        p["grpc-opts"] = {"grpc-service-name": node["grpc_service_name"]}


def _proxy_hysteria2(node: dict, settings: dict) -> dict:
    p = {
        "name": node["name"], "type": "hysteria2",
        "server": node["server"], "port": _port(node),
        "password": str(node.get("password", "")),
        "sni": node.get("sni") or node["server"],
        "skip-cert-verify": bool(node.get("skip_cert_verify", False)),
        "alpn": node.get("alpn") or ["h3"],
        "up": _bandwidth(node.get("up") or settings.get("default_up"), "20 Mbps"),
        "down": _bandwidth(node.get("down") or settings.get("default_down"), "100 Mbps"),
    }
    if node.get("ports"):
        p["ports"] = str(node["ports"])
    if node.get("obfs"):
        p["obfs"] = node["obfs"]
        if node.get("obfs_password"):
            p["obfs-password"] = node["obfs_password"]
    fp = str(node.get("fingerprint", "")).replace(":", "").lower()
    if len(fp) == 64 and all(c in "0123456789abcdef" for c in fp):
        p["fingerprint"] = fp
    if node.get("fast_open"):
        p["fast-open"] = True
    return p


def _proxy_vless(node: dict, settings: dict) -> dict:
    p = {
        "name": node["name"], "type": "vless",
        "server": node["server"], "port": _port(node),
        "uuid": str(node.get("uuid", "")), "udp": True,
        "tls": bool(node.get("tls", False)),
    }
    # flow（xtls-rprx-vision 等）只在裸 TCP/REALITY 下有效；与 ws/grpc/httpupgrade 同时下发会被 mihomo 拒绝
    if node.get("flow") and node.get("network") in (None, "", "tcp"):
        p["flow"] = node["flow"]
    if node.get("sni"):
        p["servername"] = node["sni"]
    if node.get("alpn"):
        p["alpn"] = node["alpn"]
    if node.get("client_fingerprint"):
        p["client-fingerprint"] = node["client_fingerprint"]
    if node.get("skip_cert_verify"):
        p["skip-cert-verify"] = True
    if node.get("reality_pbk"):
        p["reality-opts"] = {"public-key": node["reality_pbk"],
                             "short-id": node.get("reality_sid", "")}
        p["tls"] = True   # REALITY 必须 tls:true；编辑面板若未勾 TLS，否则 mihomo 会拒绝该配置
    _apply_transport(p, node)
    return p


def _proxy_vmess(node: dict, settings: dict) -> dict:
    p = {
        "name": node["name"], "type": "vmess",
        "server": node["server"], "port": _port(node),
        "uuid": str(node.get("uuid", "")), "alterId": _safe_int(node.get("alter_id"), 0),
        "cipher": node.get("cipher") or "auto", "udp": True,
        "tls": bool(node.get("tls", False)),
    }
    if node.get("sni"):
        p["servername"] = node["sni"]
    if node.get("alpn"):
        p["alpn"] = node["alpn"]
    if node.get("skip_cert_verify"):
        p["skip-cert-verify"] = True
    _apply_transport(p, node)
    return p


def _proxy_trojan(node: dict, settings: dict) -> dict:
    p = {
        "name": node["name"], "type": "trojan",
        "server": node["server"], "port": _port(node),
        "password": str(node.get("password", "")), "udp": True,
        "sni": node.get("sni") or node["server"],
        "skip-cert-verify": bool(node.get("skip_cert_verify", False)),
    }
    if node.get("alpn"):
        p["alpn"] = node["alpn"]
    if node.get("client_fingerprint"):
        p["client-fingerprint"] = node["client_fingerprint"]
    _apply_transport(p, node)
    return p


def _proxy_ss(node: dict, settings: dict) -> dict:
    p = {
        "name": node["name"], "type": "ss",
        "server": node["server"], "port": _port(node),
        "cipher": node.get("cipher") or "aes-256-gcm",
        "password": str(node.get("password", "")), "udp": True,
    }
    if node.get("plugin"):
        p["plugin"] = node["plugin"]
        if node.get("plugin_opts"):
            p["plugin-opts"] = node["plugin_opts"]
    return p


def _proxy_tuic(node: dict, settings: dict) -> dict:
    p = {
        "name": node["name"], "type": "tuic",
        "server": node["server"], "port": _port(node),
        "uuid": str(node.get("uuid", "")), "password": str(node.get("password", "")),
        "sni": node.get("sni") or node["server"],
        "alpn": node.get("alpn") or ["h3"],
        "congestion-controller": node.get("congestion") or "bbr",
        "udp-relay-mode": node.get("udp_relay_mode") or "native",
        "skip-cert-verify": bool(node.get("skip_cert_verify", False)),
    }
    return p


_PROXY_BUILDERS = {
    "hysteria2": _proxy_hysteria2, "vless": _proxy_vless, "vmess": _proxy_vmess,
    "trojan": _proxy_trojan, "ss": _proxy_ss, "tuic": _proxy_tuic,
}


def node_to_proxy(node: dict, settings: dict) -> dict:
    """节点字典 -> mihomo proxies 条目（按协议分发）。"""
    builder = _PROXY_BUILDERS.get(node.get("type", "hysteria2"), _proxy_hysteria2)
    return builder(node, settings)



# mihomo 保留策略/策略组名：节点若同名会与策略组/内建策略冲突，导致 config 校验失败
_RESERVED_NAMES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE",
                   "GLOBAL", "PROXY", "AUTO"}


def display_names(nodes: list[dict]) -> dict:
    """返回 节点id -> mihomo 实际使用的（去重 / 规避保留词后的）名字 的映射。

    build_config 对节点名做了 _dedup_names 改写（同名追加 #2、保留词加 ·），
    使 config.yaml 里的 proxy 名与 state.json 里的原始 name 不一致。面板调用 clash API
    做切换/测速时必须用这里的名字（且传入与渲染相同顺序的 nodes，通常是 nodes_active_first），
    否则会按不存在的名字去操作而失败。
    """
    out: dict = {}
    for n in _dedup_names([x for x in (nodes or []) if x.get("server")]):
        if n.get("id"):
            out[n["id"]] = n["name"]
    return out


def _dedup_names(nodes: list[dict]) -> list[dict]:
    """节点名去重（同名追加 #2、#3…），并规避 mihomo 保留名，不改原对象。

    去重编号按**稳定键（节点 id，缺失退回原始下标）**确定，与传入顺序无关：否则
    build_config（apply 时顺序）与 display_names（点选时 active-first 顺序）会对同一批节点
    算出不同的 name->node 映射，导致面板「切换/测速」命中错误节点（DC-1）。
    输出仍保持传入顺序（供 PROXY 选择器把当前节点放最前作默认项）。"""
    out = [dict(n) for n in nodes]
    order = sorted(range(len(out)), key=lambda i: (str(out[i].get("id") or ""), i))
    seen: dict[str, int] = {}
    for i in order:
        n = out[i]
        # str(...)：外部编辑/表单可能把 name 存成 int/list，.strip() 会崩，先统一转字符串
        base = (str(n.get("name") or n.get("server") or "节点")).strip() or "节点"
        if base.upper() in _RESERVED_NAMES:
            base = base + "·"          # 避免与策略组名 PROXY/AUTO、内建 DIRECT 等冲突
        if base in seen:
            seen[base] += 1
            n["name"] = f"{base} #{seen[base]}"
        else:
            seen[base] = 1
            n["name"] = base
    return out


# ---------------------------------------------------------------- 总装
def build_config(nodes: list[dict], rules: list[dict], settings: dict) -> dict:
    """生成完整的 mihomo 配置（dict 形式）。"""
    s = {**DEFAULT_SETTINGS, **(settings or {})}
    nodes = _dedup_names([n for n in (nodes or []) if n.get("server")])

    mixed_port = _safe_int(s.get("mixed_port"), 7890)   # 脏值（字符串/越界）回落，避免 YAML 里出现非法端口
    if not 1 <= mixed_port <= 65535:
        mixed_port = 7890
    # 枚举型设置即便经外部编辑/旧版迁移带入非法值，也在此夹紧，避免坏值流进 config.yaml 被
    # mihomo -t 拒绝、卡住此后每次 apply（webui 层只在写入时校验，store/其它写入方不保证）。
    log_level = s.get("log_level") if s.get("log_level") in (
        "silent", "error", "warning", "info", "debug") else "warning"
    tun_stack = s.get("tun_stack") if s.get("tun_stack") in (
        "system", "gvisor", "mixed") else "system"
    cfg: dict = {
        "mixed-port": mixed_port,
        # 网关模式或显式 allow_lan 时，混合代理端口/DNS 对局域网开放
        "allow-lan": bool(s.get("allow_lan") or s.get("gateway_mode")),
        "mode": "rule",
        "log-level": log_level,
        "ipv6": bool(s.get("ipv6")),
    }
    ec = s.get("external_controller")
    if ec:
        # external-controller 必须回环：非回环值（手工编辑/未来校验回归）会把带 secret 的控制器
        # 暴露到 LAN，故在序列化时再夹一道（与 manager._controller_base / webui 校验同口径）。
        _host = urllib.parse.urlparse(
            ec if str(ec).startswith("http") else "http://" + str(ec)).hostname or ""
        if _host not in ("127.0.0.1", "::1", "localhost"):
            ec = "127.0.0.1:9090"
        cfg["external-controller"] = ec
        if s.get("secret"):
            cfg["secret"] = s["secret"]

    lan_open = bool(s.get("allow_lan") or s.get("gateway_mode"))
    # 用户清空 DNS 列表、或脏 state 把列表存成了字符串等非列表类型时回落默认，
    # 避免生成 nameserver: [] / 把字符串 list() 成单字符列表，让 mihomo 解析全失败
    ns_raw = s.get("dns_nameservers")
    nameservers = list(ns_raw) if isinstance(ns_raw, list) and ns_raw else list(DEFAULT_SETTINGS["dns_nameservers"])
    cn_raw = s.get("dns_china")
    china_dns = list(cn_raw) if isinstance(cn_raw, list) and cn_raw else list(DEFAULT_SETTINGS["dns_china"])
    # default-nameserver 必须是纯 IP（不能是 DoH 域名），用作解析上游域名/引导 DNS，
    # 否则 fake-ip 下自定义的域名型 DoH nameserver 可能无法自举解析、mihomo 起不来。
    bootstrap = [ip for ip in china_dns if _is_ip_or_cidr(ip) is not None] \
        or ["223.5.5.5", "119.29.29.29"]
    # fake-ip 网段必须是合法 CIDR：用户在面板清空或填非法值时回落默认，
    # 否则空值被持久化后，每次 apply（含订阅定时器）都会卡在 mihomo -t 校验失败。
    fake_ip = str(s.get("fake_ip_range") or "").strip()
    if _is_ip_or_cidr(fake_ip) is None:
        fake_ip = DEFAULT_SETTINGS["fake_ip_range"]
    cfg["dns"] = {
        "enable": True,
        # 仅在开放局域网（allow-lan/网关模式）时监听 0.0.0.0，否则收敛到回环，减少暴露面
        "listen": ("0.0.0.0:1053" if lan_open else "127.0.0.1:1053"),
        "enhanced-mode": "fake-ip",
        "fake-ip-range": fake_ip,
        "fake-ip-filter": ["*.lan", "*.local", "+.pool.ntp.org", "time.*.com"],
        "default-nameserver": bootstrap,
        "nameserver": nameservers,
        "proxy-server-nameserver": china_dns,
    }
    # dns-hijack / auto-redirect 可配：与本机 Pi-hole/dnsmasq（占 :53）或
    # Docker/firewalld（管 nftables）共存时，可改劫持目标或关掉 nft 重定向。默认保持原行为。
    hijack = s.get("tun_dns_hijack")
    if not isinstance(hijack, list):
        hijack = ["any:53"]      # 缺失/脏类型回落默认；显式清空（[]）则尊重用户、下发 dns-hijack: []
    cfg["tun"] = {
        "enable": True,
        "stack": tun_stack,
        "dns-hijack": hijack,
        "auto-route": True,
        "auto-redirect": bool(s.get("tun_auto_redirect", True)),
        "auto-detect-interface": True,
    }

    # proxies —— 单个坏节点（字段类型异常等）跳过而非拖垮整份配置；
    # 全部失败时按“零节点”处理（兜底 DIRECT），与下方规则/final 逻辑保持一致
    built_proxies, kept_nodes = [], []
    for n in nodes:
        try:
            built_proxies.append(node_to_proxy(n, s))
            kept_nodes.append(n)
        except Exception:
            continue
    nodes = kept_nodes
    if nodes:
        cfg["proxies"] = built_proxies
        names = [n["name"] for n in nodes]  # 已按“当前节点优先”排序
        # 当前选中的节点放在选择器最前 -> 重启后默认就是它；AUTO 仅作为可选项跟在后面
        select_list = names + (["AUTO"] if len(names) > 1 else []) + ["DIRECT"]
        select_list = list(dict.fromkeys(select_list))  # 去重保序，防节点名与 AUTO/DIRECT 撞
        groups = [{
            "name": "PROXY",
            "type": "select",
            "proxies": select_list,
        }]
        if len(names) > 1:
            groups.append({
                "name": "AUTO",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": names,
            })
        cfg["proxy-groups"] = groups

    # rules：安全直连 -> 用户规则 -> 预设 -> 兜底
    # 没有任何节点时，引用 PROXY 组的规则都无效，直接跳过用户规则/预设，整体走 DIRECT
    rule_lines = [f"IP-CIDR,{c},DIRECT,no-resolve" for c in _SAFE_DIRECT_CIDRS]
    if bool(s.get("ipv6")):
        # 开 IPv6 时，IPv6 私有/链路本地/回环网段也固定直连，避免 LAN IPv6（SSH/局域网）被代理切断
        rule_lines += [f"IP-CIDR6,{c},DIRECT,no-resolve"
                       for c in ("fc00::/7", "fe80::/10", "::1/128")]
    if nodes:
        for r in (rules or []):
            if not isinstance(r, dict):   # 防御：外部手编/历史毒丸 state 里的非 dict 规则项不该让整份渲染崩
                continue
            rv = r.get("value")
            if rv is None or not str(rv).strip():
                continue
            try:
                rule_lines.append(rule_to_mihomo(r))
            except Exception:
                continue
        rule_lines.extend(expand_presets(s.get("presets", [])))
    final = str(s.get("final", "PROXY")).upper()
    if final not in ("PROXY", "DIRECT"):
        final = "PROXY"
    if not nodes:
        final = "DIRECT"
    rule_lines.append(f"MATCH,{final}")
    cfg["rules"] = rule_lines

    return cfg


def render(nodes: list[dict], rules: list[dict], settings: dict) -> str:
    """生成 config.yaml 文本。"""
    header = (
        "# 本文件由 pihy2 自动生成，请通过命令行向导或 WebUI 修改，不要手改。\n"
        "# Generated by pihy2 — edit via the wizard or WebUI, not by hand.\n"
    )
    return header + to_yaml(build_config(nodes, rules, settings)) + "\n"
