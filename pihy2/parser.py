"""hysteria2 / hy2 节点分享链接解析。

支持：
  * hysteria2://  与  hy2://  两种 scheme
  * 密码、SNI、节点名（fragment）的百分号编码自动还原（如 %2F -> /）
  * 常见参数及其别名：sni/peer、insecure/allowInsecure、obfs、obfs-password、
    alpn、up/upmbps、down/downmbps、端口跳跃 mport/ports、pinSHA256、fastopen
  * 一次粘贴多行链接（按行解析）
  * base64 编码的订阅内容（自动探测并解码）

解析结果是一个“节点字典”，字段与 config_gen 中的 mihomo 代理一一对应。
"""

from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import urlsplit, unquote, parse_qs


# 解析过程中可能抛出的错误，给用户友好的中文提示。
class ParseError(ValueError):
    pass


_SCHEMES = ("hysteria2://", "hy2://")


def _truthy(v: str) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _first(qs: dict, *keys: str, default: str = "") -> str:
    """从 parse_qs 结果里按多个候选键（忽略大小写）取第一个非空值。"""
    lowered = {k.lower(): v for k, v in qs.items()}
    for k in keys:
        vals = lowered.get(k.lower())
        if vals:
            for val in vals:
                if val != "":
                    return val
    return default


def _split_hostport(hostport: str) -> tuple[str, int]:
    """拆分 host:port，兼容 IPv6 字面量（[::1]:443）与缺省端口。"""
    hostport = hostport.strip()
    if hostport.startswith("["):  # IPv6
        m = re.match(r"^\[(?P<host>[^\]]+)\](?::(?P<port>\d+))?$", hostport)
        if not m:
            raise ParseError(f"无法解析地址：{hostport}")
        host = m.group("host")
        port = int(m.group("port")) if m.group("port") else 443
        return host, port
    if ":" in hostport:
        host, _, port_s = hostport.rpartition(":")
        if not port_s.isdigit():
            # 冒号但端口非数字 —— 当成没有端口（host 含冒号的情况极少）
            return hostport, 443
        return host, int(port_s)
    return hostport, 443


def parse_link(link: str) -> dict:
    """解析单条 hysteria2/hy2 链接，返回节点字典。失败抛 ParseError。"""
    link = link.strip()
    if not link:
        raise ParseError("空链接")

    low = link.lower()
    if not low.startswith(_SCHEMES):
        raise ParseError("不是 hysteria2:// 或 hy2:// 链接")

    sr = urlsplit(link)

    # 手动从 netloc 取 userinfo（密码）与 host:port，避免 username:password 歧义，
    # 因为 hy2 的鉴权是“单个密码串”，其本身可能含冒号。
    netloc = sr.netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
    else:
        userinfo, hostport = "", netloc

    host, port = _split_hostport(hostport)
    if not host:
        raise ParseError("缺少服务器地址")

    qs = parse_qs(sr.query, keep_blank_values=True)

    # 密码：优先 userinfo，其次 query 里的 auth/password
    password = unquote(userinfo) if userinfo else _first(qs, "auth", "password")
    if not password:
        raise ParseError("缺少密码")

    # SNI：sni / peer，缺省回退到服务器域名
    sni = _first(qs, "sni", "peer") or host

    # ALPN：逗号分隔，缺省 h3
    alpn_raw = _first(qs, "alpn")
    alpn = [a.strip() for a in alpn_raw.split(",") if a.strip()] if alpn_raw else ["h3"]

    # 混淆：仅 hy2 的 salamander
    obfs = _first(qs, "obfs").strip().lower()
    obfs_password = _first(qs, "obfs-password", "obfs_password", "obfsParam")
    if obfs and obfs != "salamander":
        # 未知混淆类型，保留原值让用户在面板里确认（mihomo -t 会校验）
        pass

    node = {
        "name": unquote(sr.fragment).strip() if sr.fragment else host,
        "type": "hysteria2",
        "server": host,
        "port": port,
        "ports": _first(qs, "mport", "ports").strip(),  # 端口跳跃，如 443-8443,8888
        "password": password,
        "sni": sni,
        "skip_cert_verify": _truthy(_first(qs, "insecure", "allowInsecure", default="0")),
        "alpn": alpn,
        "obfs": obfs,                       # "" 或 "salamander"
        "obfs_password": obfs_password,
        "up": _first(qs, "up", "upmbps").strip(),       # "" 表示用全局默认
        "down": _first(qs, "down", "downmbps").strip(),
        "fingerprint": _first(qs, "pinSHA256", "pinsha256").strip(),  # 证书指纹固定
        "fast_open": _truthy(_first(qs, "fastopen", default="0")),
    }
    return node


def _maybe_base64_decode(text: str) -> str | None:
    """若 text 整体像 base64 订阅，解码后返回明文，否则 None。"""
    compact = re.sub(r"\s+", "", text)
    if not compact or "://" in text:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        return None
    # URL-safe 与标准 base64 都试
    for variant in (compact, compact.replace("-", "+").replace("_", "/")):
        padded = variant + "=" * (-len(variant) % 4)
        try:
            decoded = base64.b64decode(padded).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if any(s in decoded.lower() for s in _SCHEMES):
            return decoded
    return None


def parse_many(text: str) -> tuple[list[dict], list[str]]:
    """解析一段文本（可能多行、可能是 base64 订阅）。

    返回 (节点列表, 错误信息列表)。能解析出的尽量解析，逐条报错不中断。
    """
    if not text or not text.strip():
        return [], ["输入为空"]

    decoded = _maybe_base64_decode(text)
    if decoded is not None:
        text = decoded

    nodes: list[dict] = []
    errors: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not line.lower().startswith(_SCHEMES):
            errors.append(f"已跳过（非 hy2 链接）：{line[:40]}")
            continue
        try:
            nodes.append(parse_link(line))
        except ParseError as e:
            errors.append(f"解析失败：{e} —— {line[:40]}")
    if not nodes and not errors:
        errors.append("未发现可用的 hy2 节点链接")
    return nodes, errors


def node_to_link(node: dict) -> str:
    """把节点字典反向拼成 hysteria2:// 分享链接（用于导出/复制）。"""
    from urllib.parse import quote, urlencode

    params: dict[str, str] = {}
    if node.get("sni") and node["sni"] != node["server"]:
        params["sni"] = node["sni"]
    if node.get("skip_cert_verify"):
        params["insecure"] = "1"
    if node.get("obfs"):
        params["obfs"] = node["obfs"]
        if node.get("obfs_password"):
            params["obfs-password"] = node["obfs_password"]
    alpn = node.get("alpn") or []
    if alpn and alpn != ["h3"]:
        params["alpn"] = ",".join(alpn)
    if node.get("ports"):
        params["mport"] = node["ports"]
    if node.get("up"):
        params["up"] = node["up"]
    if node.get("down"):
        params["down"] = node["down"]
    if node.get("fingerprint"):
        params["pinSHA256"] = node["fingerprint"]
    if node.get("fast_open"):
        params["fastopen"] = "1"

    auth = quote(str(node["password"]), safe="")
    host = node["server"]
    if ":" in host:  # IPv6
        host = f"[{host}]"
    query = ("?" + urlencode(params)) if params else ""
    frag = ("#" + quote(str(node.get("name", "")), safe="")) if node.get("name") else ""
    return f"hysteria2://{auth}@{host}:{node['port']}/{query}{frag}"
