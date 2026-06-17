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
import re

# 默认设置（store 会以此为模板）
DEFAULT_SETTINGS = {
    "mixed_port": 7890,
    "allow_lan": False,
    "log_level": "warning",          # silent/error/warning/info/debug
    "ipv6": False,
    "tun_stack": "system",           # system/gvisor/mixed
    "fake_ip_range": "198.18.0.1/16",
    "dns_nameservers": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
    "dns_china": ["223.5.5.5", "119.29.29.29"],
    "default_up": "20 Mbps",
    "default_down": "100 Mbps",
    "final": "PROXY",                # 兜底策略：PROXY 或 DIRECT
    "external_controller": "127.0.0.1:9090",  # clash API，供面板做实时切换/测速
    "secret": "",                    # clash API 密钥（首次安装随机生成）
}

# 始终直连的安全规则（保证 SSH 不断）。放在所有用户规则之前。
_SAFE_DIRECT_CIDRS = [
    "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12",
    "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
]


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


def to_yaml(data, indent: int = 0) -> str:
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, dict) and v:
                lines.append(f"{pad}{k}:")
                lines.append(to_yaml(v, indent + 1))
            elif isinstance(v, list) and v:
                lines.append(f"{pad}{k}:")
                lines.append(to_yaml(v, indent + 1))
            elif isinstance(v, (dict, list)):  # 空容器
                lines.append(f"{pad}{k}: {'{}' if isinstance(v, dict) else '[]'}")
            else:
                lines.append(f"{pad}{k}: {_yaml_scalar(v)}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                # 列表里的字典：第一个键跟在 '- ' 后，其余对齐
                inner = to_yaml(item, indent + 1)
                inner_lines = inner.split("\n")
                first = inner_lines[0][len(pad) + 2:]
                lines.append(f"{pad}- {first}")
                lines.extend(inner_lines[1:])
            elif isinstance(item, list):
                lines.append(f"{pad}-")
                lines.append(to_yaml(item, indent + 1))
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
    value = value.strip()
    rtype = (rtype or "auto").strip().lower()

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
            if net is not None and "/" not in value:
                value = f"{value}/32" if "." in value else f"{value}/128"
        return kind, value

    # auto 智能判别
    net = _is_ip_or_cidr(value)
    if net is not None:
        if "/" in value:
            return "IP-CIDR", value
        return "IP-CIDR", (f"{value}/32" if "." in value else f"{value}/128")

    if value.startswith("*."):
        # *.example.com —— 用户多半想连 example.com 及其子域，DOMAIN-SUFFIX 最贴切且高效
        return "DOMAIN-SUFFIX", value[2:]
    if "*" in value or "?" in value:
        return "DOMAIN-WILDCARD", value
    if value.startswith("."):
        return "DOMAIN-SUFFIX", value[1:]
    if "." in value:
        return "DOMAIN-SUFFIX", value
    # 单个词，无点：按关键词
    return "DOMAIN-KEYWORD", value


def rule_to_mihomo(rule: dict) -> str:
    """单条规则字典 -> mihomo 规则行字符串。"""
    kind, value = classify_rule(rule.get("value", ""), rule.get("type", "auto"))
    policy = rule.get("policy", "PROXY").strip().upper()
    if policy not in ("DIRECT", "PROXY", "REJECT"):
        policy = "PROXY"
    # 仅 IP-CIDR 加 no-resolve：纯 IP 规则无需触发 DNS。
    # GEOIP 不能加 no-resolve，否则 fake-ip 下的域名连接无法解析出真实 IP 来匹配（会漏判）。
    suffix = ",no-resolve" if kind == "IP-CIDR" else ""
    return f"{kind},{value},{policy}{suffix}"


# ---------------------------------------------------------------- 节点 -> proxy
def node_to_proxy(node: dict, settings: dict) -> dict:
    """节点字典 -> mihomo proxies 条目。"""
    p = {
        "name": node["name"],
        "type": "hysteria2",
        "server": node["server"],
        "port": int(node["port"]),
        "password": str(node["password"]),
        "sni": node.get("sni") or node["server"],
        "skip-cert-verify": bool(node.get("skip_cert_verify", False)),
        "alpn": node.get("alpn") or ["h3"],
        "up": node.get("up") or settings.get("default_up", "20 Mbps"),
        "down": node.get("down") or settings.get("default_down", "100 Mbps"),
    }
    if node.get("ports"):
        p["ports"] = str(node["ports"])
    if node.get("obfs"):
        p["obfs"] = node["obfs"]
        if node.get("obfs_password"):
            p["obfs-password"] = node["obfs_password"]
    if node.get("fingerprint"):
        p["fingerprint"] = node["fingerprint"]
    if node.get("fast_open"):
        p["fast-open"] = True
    return p


def _dedup_names(nodes: list[dict]) -> list[dict]:
    """节点名去重（同名追加 #2、#3…），不改原对象。"""
    seen: dict[str, int] = {}
    out = []
    for n in nodes:
        n = dict(n)
        base = (n.get("name") or n.get("server") or "节点").strip() or "节点"
        if base in seen:
            seen[base] += 1
            n["name"] = f"{base} #{seen[base]}"
        else:
            seen[base] = 1
            n["name"] = base
        out.append(n)
    return out


# ---------------------------------------------------------------- 总装
def build_config(nodes: list[dict], rules: list[dict], settings: dict) -> dict:
    """生成完整的 mihomo 配置（dict 形式）。"""
    s = {**DEFAULT_SETTINGS, **(settings or {})}
    nodes = _dedup_names([n for n in (nodes or []) if n.get("server")])

    cfg: dict = {
        "mixed-port": s["mixed_port"],
        "allow-lan": s["allow_lan"],
        "mode": "rule",
        "log-level": s["log_level"],
        "ipv6": s["ipv6"],
    }
    if s.get("external_controller"):
        cfg["external-controller"] = s["external_controller"]
        if s.get("secret"):
            cfg["secret"] = s["secret"]

    cfg["dns"] = {
        "enable": True,
        "listen": "0.0.0.0:1053",
        "enhanced-mode": "fake-ip",
        "fake-ip-range": s["fake_ip_range"],
        "fake-ip-filter": ["*.lan", "*.local", "+.pool.ntp.org", "time.*.com"],
        "nameserver": list(s["dns_nameservers"]),
        "proxy-server-nameserver": list(s["dns_china"]),
    }
    cfg["tun"] = {
        "enable": True,
        "stack": s["tun_stack"],
        "dns-hijack": ["any:53"],
        "auto-route": True,
        "auto-redirect": True,
        "auto-detect-interface": True,
    }

    # proxies
    if nodes:
        cfg["proxies"] = [node_to_proxy(n, s) for n in nodes]
        names = [n["name"] for n in nodes]  # 已按“当前节点优先”排序
        # 当前选中的节点放在选择器最前 -> 重启后默认就是它；AUTO 仅作为可选项跟在后面
        select_list = names + (["AUTO"] if len(names) > 1 else []) + ["DIRECT"]
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

    # rules：安全直连 -> 用户规则 -> 兜底
    rule_lines = [f"IP-CIDR,{c},DIRECT,no-resolve" for c in _SAFE_DIRECT_CIDRS]
    for r in (rules or []):
        if not r.get("value", "").strip():
            continue
        try:
            rule_lines.append(rule_to_mihomo(r))
        except Exception:
            continue
    final = s.get("final", "PROXY").upper()
    if final not in ("PROXY", "DIRECT"):
        final = "PROXY"
    # 没有任何节点时，兜底只能 DIRECT，避免引用不存在的策略组
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
