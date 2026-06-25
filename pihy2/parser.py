"""节点分享链接解析（多协议）。

支持的 scheme：
  * hysteria2:// , hy2://     —— hysteria2
  * vless://                  —— VLESS（含 tls / reality / ws / grpc）
  * vmess://                  —— VMess（base64(JSON) 形式）
  * trojan://                 —— Trojan
  * ss://                     —— Shadowsocks（SIP002 与旧式 base64）
  * tuic://                   —— TUIC v5

还支持：百分号编码自动还原、一次粘贴多行、base64 订阅内容自动探测解码。
解析结果是一个“节点字典”，由 config_gen 映射为 mihomo proxies 条目。
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from urllib.parse import urlsplit, unquote, parse_qs


# 解析过程中可能抛出的错误，给用户友好的中文提示。
class ParseError(ValueError):
    pass


_SCHEMES = ("hysteria2://", "hy2://", "vless://", "vmess://",
            "trojan://", "ss://", "tuic://")


# ---------------------------------------------------------------- 通用小工具
def _truthy(v: str) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _int(v, default: int = 0) -> int:
    """宽松转 int，兼容 "443"/"1.0"/None/非法值，避免脏数据让整次订阅解析崩掉。"""
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _normalize_fingerprint(v: str) -> str:
    """把证书指纹规范化为 mihomo 期望的 64 位小写 hex；不是 hex 则返回 ""。

    分享链接里的 pinSHA256 通常是 ``sha256/<base64>`` 公钥固定，与 mihomo 的
    ``fingerprint``（证书 hex SHA-256）不同，混用会让 mihomo 启动直接报错。
    """
    s = v.strip().replace(":", "").lower()
    if len(s) == 64 and all(c in "0123456789abcdef" for c in s):
        return s
    return ""


def _raw_query(query: str, *keys: str) -> str:
    """从原始 query 串取参数值，用 unquote（而非 parse_qs 的 unquote_plus），
    避免密码里的 '+' 被误解成空格。"""
    wanted = {k.lower() for k in keys}
    for pair in query.split("&"):
        k, _, val = pair.partition("=")
        if k.lower() in wanted and val != "":
            return unquote(val)
    return ""


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


def _port_or_default(port_s: str, default: int = 443) -> int:
    """端口须为 1..65535 的数字，否则回落默认值。"""
    if port_s.isdigit():
        p = int(port_s)
        if 1 <= p <= 65535:
            return p
    return default


def _split_hostport(hostport: str) -> tuple[str, int]:
    """拆分 host:port，兼容 IPv6 字面量（[::1]:443 与裸 2001:db8::1）与缺省端口。"""
    hostport = hostport.strip()
    if hostport.startswith("["):  # 带方括号的 IPv6（可带端口）
        m = re.match(r"^\[(?P<host>[^\]]+)\](?::(?P<port>\d+))?$", hostport)
        if not m:
            raise ParseError(f"无法解析地址：{hostport}")
        return m.group("host"), _port_or_default(m.group("port") or "")
    # 裸 IPv6 字面量（无方括号、含 ≥2 个冒号）：整体视为地址，端口缺省
    if hostport.count(":") >= 2:
        return hostport, 443
    if ":" in hostport:
        host, _, port_s = hostport.rpartition(":")
        return host, _port_or_default(port_s)
    return hostport, 443


def _alpn(raw: str) -> list[str]:
    return [a.strip() for a in raw.split(",") if a.strip()]


def _b64decode(s: str) -> str:
    """宽松 base64 解码（兼容 url-safe 与缺省 padding）。"""
    s = s.strip()
    for variant in (s, s.replace("-", "+").replace("_", "/")):
        try:
            return base64.b64decode(variant + "=" * (-len(variant) % 4)).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
    raise ParseError("base64 解码失败")


def _userinfo_hostport(netloc: str) -> tuple[str, str]:
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
        return userinfo, hostport
    return "", netloc


def _base_node(name: str, typ: str, host: str, port: int) -> dict:
    if not host:
        raise ParseError("缺少服务器地址")
    return {"name": name.strip() or host, "type": typ, "server": host, "port": port}


def _net_fields(node: dict, network: str, *,
                ws_path="", ws_host="", grpc_sn=""):
    """填充传输层相关字段。仅支持会真正下发 opts 的 ws/httpupgrade/grpc，
    其余（tcp/h2/http）按 tcp 处理，避免出现“有 network 没 opts”的半截配置。"""
    network = (network or "tcp").lower()
    if network in ("ws", "httpupgrade"):
        node["network"] = network
        node["ws_path"] = ws_path or "/"
        node["ws_host"] = ws_host
    elif network == "grpc":
        node["network"] = "grpc"
        node["grpc_service_name"] = grpc_sn


# ---------------------------------------------------------------- hysteria2
def _parse_hysteria2(link: str) -> dict:
    sr = urlsplit(link)
    userinfo, hostport = _userinfo_hostport(sr.netloc)
    host, port = _split_hostport(hostport)
    qs = parse_qs(sr.query, keep_blank_values=True)

    password = unquote(userinfo) if userinfo else _raw_query(sr.query, "auth", "password")
    if not password:
        raise ParseError("缺少密码")

    obfs = _first(qs, "obfs").strip().lower()
    pin_raw = _first(qs, "pinSHA256", "pinsha256").strip()
    fingerprint = _normalize_fingerprint(pin_raw)

    node = _base_node(unquote(sr.fragment), "hysteria2", host, port)
    node.update({
        "password": password,
        "sni": _first(qs, "sni", "peer") or host,
        "skip_cert_verify": _truthy(_first(qs, "insecure", "allowInsecure", default="0")),
        "alpn": _alpn(_first(qs, "alpn")) or ["h3"],
        "obfs": obfs,
        # 与主密码同样走 _raw_query（unquote 而非 unquote_plus），避免混淆密码里的 '+' 被吃成空格
        "obfs_password": _raw_query(sr.query, "obfs-password", "obfs_password", "obfsParam"),
        "up": _first(qs, "up", "upmbps").strip(),
        "down": _first(qs, "down", "downmbps").strip(),
        "ports": _first(qs, "mport", "ports").strip(),
        "fingerprint": fingerprint,
        "pin_sha256": "" if fingerprint else pin_raw,
        "fast_open": _truthy(_first(qs, "fastopen", default="0")),
    })
    return node


# ---------------------------------------------------------------- vless
def _parse_vless(link: str) -> dict:
    sr = urlsplit(link)
    userinfo, hostport = _userinfo_hostport(sr.netloc)
    uuid = unquote(userinfo)
    if not uuid:
        raise ParseError("VLESS 缺少 UUID")
    host, port = _split_hostport(hostport)
    qs = parse_qs(sr.query, keep_blank_values=True)

    security = _first(qs, "security").lower()
    network = _first(qs, "type", "headerType", default="tcp").lower() or "tcp"
    pbk = _first(qs, "pbk")
    is_reality = security == "reality" or bool(pbk)   # 有公钥即按 reality 处理

    node = _base_node(unquote(sr.fragment), "vless", host, port)
    node.update({
        "uuid": uuid,
        "tls": security in ("tls", "reality", "xtls") or is_reality,
        "sni": _first(qs, "sni", "peer"),
        "flow": _first(qs, "flow"),
        "client_fingerprint": _first(qs, "fp"),
        "alpn": _alpn(_first(qs, "alpn")),
        "skip_cert_verify": _truthy(_first(qs, "allowInsecure", "insecure", default="0")),
    })
    if is_reality:
        node["reality_pbk"] = pbk
        node["reality_sid"] = _first(qs, "sid")
    _net_fields(node, network, ws_path=_first(qs, "path"),
                ws_host=_first(qs, "host"), grpc_sn=_first(qs, "serviceName"))
    return node


# ---------------------------------------------------------------- vmess
def _parse_vmess(link: str) -> dict:
    raw = link[len("vmess://"):]
    try:
        j = json.loads(_b64decode(raw))
    except (json.JSONDecodeError, ValueError):
        raise ParseError("VMess 链接不是合法的 base64(JSON)")
    host = j.get("add", "")
    port = _int(j.get("port"), 443)
    if not host:
        raise ParseError("VMess 缺少服务器地址")
    network = str(j.get("net", "tcp")).lower()
    alpn_raw = j.get("alpn")
    alpn_str = alpn_raw if isinstance(alpn_raw, str) else (
        ",".join(str(x) for x in alpn_raw) if isinstance(alpn_raw, (list, tuple)) else "")

    node = _base_node(str(j.get("ps", "")), "vmess", host, port)
    node.update({
        "uuid": str(j.get("id", "")),
        "alter_id": _int(j.get("aid"), 0),
        "cipher": j.get("scy") or "auto",
        "tls": str(j.get("tls", "")).lower() in ("tls", "true", "1"),
        "sni": j.get("sni") or "",
        "alpn": _alpn(alpn_str),
        "skip_cert_verify": _truthy(str(j.get("skip-cert-verify", j.get("verify_cert", "0")))),
    })
    if not node["uuid"]:
        raise ParseError("VMess 缺少 UUID")
    _net_fields(node, network, ws_path=j.get("path", ""),
                ws_host=j.get("host", ""), grpc_sn=j.get("path", ""))
    return node


# ---------------------------------------------------------------- trojan
def _parse_trojan(link: str) -> dict:
    sr = urlsplit(link)
    userinfo, hostport = _userinfo_hostport(sr.netloc)
    password = unquote(userinfo) if userinfo else _raw_query(sr.query, "password")
    if not password:
        raise ParseError("Trojan 缺少密码")
    host, port = _split_hostport(hostport)
    qs = parse_qs(sr.query, keep_blank_values=True)
    network = _first(qs, "type", default="tcp").lower()

    node = _base_node(unquote(sr.fragment), "trojan", host, port)
    node.update({
        "password": password,
        "sni": _first(qs, "sni", "peer") or host,
        "skip_cert_verify": _truthy(_first(qs, "allowInsecure", "insecure", default="0")),
        "alpn": _alpn(_first(qs, "alpn")),
        "client_fingerprint": _first(qs, "fp"),
    })
    _net_fields(node, network, ws_path=_first(qs, "path"),
                ws_host=_first(qs, "host"), grpc_sn=_first(qs, "serviceName"))
    return node


# ---------------------------------------------------------------- shadowsocks
def _parse_ss(link: str) -> dict:
    body = link[len("ss://"):]
    name = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        name = unquote(frag)
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)

    if "@" in body:                       # SIP002：base64(method:pass)@host:port
        userinfo, hostport = body.rsplit("@", 1)
        try:
            method, password = _b64decode(userinfo).split(":", 1)
        except (ParseError, ValueError):
            if ":" in userinfo:           # 少数已是明文
                method, password = unquote(userinfo).split(":", 1)
            else:
                raise ParseError("SS 用户信息无法解析")
        host, port = _split_hostport(hostport)
    else:                                 # 旧式：base64(method:pass@host:port)
        dec = _b64decode(body)
        if "@" not in dec or ":" not in dec:
            raise ParseError("SS 链接格式无法识别")
        cred, hostport = dec.rsplit("@", 1)
        method, password = cred.split(":", 1)
        host, port = _split_hostport(hostport)

    node = _base_node(name, "ss", host, port)
    node.update({"cipher": method, "password": password})

    if query:
        qs = parse_qs(query, keep_blank_values=True)
        plugin_raw = _first(qs, "plugin")
        if plugin_raw:
            parts = plugin_raw.split(";")
            pname = parts[0]
            opts = {}
            for kv in parts[1:]:
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    opts[k] = v
                elif kv:
                    opts[kv] = True
            if pname in ("obfs-local", "simple-obfs"):
                node["plugin"] = "obfs"
                node["plugin_opts"] = {"mode": opts.get("obfs", "http"),
                                       "host": opts.get("obfs-host", "")}
            elif pname == "v2ray-plugin":
                node["plugin"] = "v2ray-plugin"
                node["plugin_opts"] = {"mode": opts.get("mode", "websocket"),
                                       "host": opts.get("host", ""),
                                       "path": opts.get("path", "/")}
            else:
                node["plugin"] = pname
    return node


# ---------------------------------------------------------------- tuic
def _parse_tuic(link: str) -> dict:
    sr = urlsplit(link)
    userinfo, hostport = _userinfo_hostport(sr.netloc)
    if ":" in userinfo:
        uuid, password = userinfo.split(":", 1)
    else:
        uuid, password = userinfo, ""
    uuid, password = unquote(uuid), unquote(password)
    if not uuid:
        raise ParseError("TUIC 缺少 UUID")
    host, port = _split_hostport(hostport)
    qs = parse_qs(sr.query, keep_blank_values=True)

    node = _base_node(unquote(sr.fragment), "tuic", host, port)
    node.update({
        "uuid": uuid,
        "password": password,
        "sni": _first(qs, "sni", "peer") or host,
        "alpn": _alpn(_first(qs, "alpn")) or ["h3"],
        "congestion": _first(qs, "congestion_control", "congestion", default="bbr"),
        "udp_relay_mode": _first(qs, "udp_relay_mode", default="native"),
        "skip_cert_verify": _truthy(_first(qs, "allow_insecure", "insecure", default="0")),
    })
    return node


# ---------------------------------------------------------------- 分发
_PARSERS = {
    "hysteria2": _parse_hysteria2, "hy2": _parse_hysteria2,
    "vless": _parse_vless, "vmess": _parse_vmess,
    "trojan": _parse_trojan, "ss": _parse_ss, "tuic": _parse_tuic,
}


def parse_link(link: str) -> dict:
    """解析单条分享链接，自动识别协议。失败抛 ParseError。"""
    link = link.strip()
    if not link:
        raise ParseError("空链接")
    scheme = link.split("://", 1)[0].lower() if "://" in link else ""
    fn = _PARSERS.get(scheme)
    if not fn:
        raise ParseError("不支持的链接类型（支持 hysteria2/hy2/vless/vmess/trojan/ss/tuic）")
    return fn(link)


def _maybe_base64_decode(text: str) -> str | None:
    """若 text 整体像 base64 订阅，解码后返回明文，否则 None。"""
    compact = re.sub(r"\s+", "", text)
    if not compact or "://" in text:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        return None
    for variant in (compact, compact.replace("-", "+").replace("_", "/")):
        padded = variant + "=" * (-len(variant) % 4)
        try:
            decoded = base64.b64decode(padded).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if "://" in decoded or "proxies:" in decoded:   # base64 的链接列表或 Clash YAML
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

    # 没有任何 scheme 链接、但像 Clash/mihomo YAML 订阅 -> 走 YAML 解析
    has_link = any("://" in ln and ln.strip().split("://", 1)[0].lower() in _PARSERS
                   for ln in text.splitlines())
    if not has_link and "proxies:" in text:
        return parse_clash_yaml(text)

    nodes: list[dict] = []
    errors: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if "://" not in line or line.split("://", 1)[0].lower() not in _PARSERS:
            errors.append(f"已跳过（不支持的链接）：{line[:40]}")
            continue
        try:
            nodes.append(parse_link(line))
        except ParseError as e:
            errors.append(f"解析失败：{e} —— {line[:40]}")
        except Exception as e:  # 脏数据兜底：单条异常不拖垮整次解析
            errors.append(f"解析异常：{e} —— {line[:40]}")
    if not nodes and not errors:
        errors.append("未发现可用的节点链接")
    return nodes, errors


# ---------------------------------------------------------------- Clash YAML
# mihomo 代理字段 -> 内部节点字段（其余按传输/特殊逻辑单独处理）
_MIHOMO_FIELD_MAP = {
    "password": "password", "uuid": "uuid", "cipher": "cipher",
    "alterId": "alter_id", "flow": "flow", "client-fingerprint": "client_fingerprint",
    "fingerprint": "fingerprint", "obfs": "obfs", "obfs-password": "obfs_password",
    "up": "up", "down": "down", "ports": "ports", "plugin": "plugin",
    "congestion-controller": "congestion", "udp-relay-mode": "udp_relay_mode",
}
_SUPPORTED_TYPES = {"hysteria2", "vless", "vmess", "trojan", "ss", "tuic"}


def proxy_to_node(p: dict) -> dict:
    """把一条 mihomo proxies 条目转成内部节点字典。不支持的类型抛 ParseError。"""
    t = str(p.get("type", "")).lower()
    t = {"hy2": "hysteria2", "shadowsocks": "ss"}.get(t, t)
    if t not in _SUPPORTED_TYPES:
        raise ParseError(f"暂不支持的协议类型：{t or '空'}")
    server = str(p.get("server", "")).strip()
    if not server:
        raise ParseError("缺少服务器地址")
    node = _base_node(str(p.get("name") or server), t, server, _int(p.get("port"), 443))

    for src, dst in _MIHOMO_FIELD_MAP.items():
        if p.get(src) not in (None, ""):
            node[dst] = p[src]
    if "skip-cert-verify" in p:
        node["skip_cert_verify"] = bool(p["skip-cert-verify"])
    if p.get("tls"):
        node["tls"] = True
    if p.get("fast-open"):
        node["fast_open"] = True
    if "sni" not in node:
        sni = p.get("sni") or p.get("servername")
        if sni:
            node["sni"] = sni
    alpn = p.get("alpn")
    if isinstance(alpn, list):
        node["alpn"] = [str(a) for a in alpn]
    elif isinstance(alpn, str):
        node["alpn"] = _alpn(alpn)
    ro = p.get("reality-opts")
    if isinstance(ro, dict):
        node["reality_pbk"] = ro.get("public-key", "")
        node["reality_sid"] = ro.get("short-id", "")
        node["tls"] = True
    net = str(p.get("network", "")).lower()
    if net in ("ws", "grpc", "httpupgrade"):
        node["network"] = net
        ws = p.get("ws-opts")
        if isinstance(ws, dict):
            node["ws_path"] = ws.get("path", "/")
            h = ws.get("headers")
            if isinstance(h, dict):
                node["ws_host"] = h.get("Host") or h.get("host") or ""
        g = p.get("grpc-opts")
        if isinstance(g, dict):
            node["grpc_service_name"] = g.get("grpc-service-name", "")
    po = p.get("plugin-opts")
    if isinstance(po, dict):
        node["plugin_opts"] = dict(po)
    if t in ("vless", "vmess", "tuic") and not node.get("uuid"):
        raise ParseError(f"{t} 缺少 UUID")
    # YAML 里未加引号的纯数字 password/uuid/short-id 会被解析成 int，统一转回字符串，
    # 避免前导零丢失式的语义损坏与下游 quote()/拼接的 TypeError。
    for f in ("password", "uuid", "obfs_password", "reality_sid", "sni", "cipher"):
        if f in node and not isinstance(node[f], str):
            node[f] = str(node[f])
    # 数值字段统一规整为 int：YAML 里 alterId 可能是字符串/脏值，下游 config_gen 会 int()，
    # 在此先归一，避免类型不一致与脏值（与 port 经 _int 归一保持一致）。
    if "alter_id" in node:
        node["alter_id"] = _int(node["alter_id"], 0)
    return node


def parse_clash_yaml(text: str) -> tuple[list[dict], list[str]]:
    """解析 Clash/mihomo YAML 订阅的 proxies 段。返回 (节点列表, 错误列表)。"""
    from . import yaml_lite
    try:
        doc = yaml_lite.load(text)
    except yaml_lite.YamlError as e:
        return [], [f"YAML 解析失败：{e}"]
    if not isinstance(doc, dict) or not isinstance(doc.get("proxies"), list):
        return [], ["未找到 proxies 段（不是 Clash 订阅？）"]
    nodes, errors = [], []
    for p in doc["proxies"]:
        if not isinstance(p, dict):
            continue
        try:
            nodes.append(proxy_to_node(p))
        except ParseError as e:
            errors.append(f"跳过：{e} —— {p.get('name', '?')}")
        except Exception as e:
            errors.append(f"跳过（异常 {e}）：{p.get('name', '?')}")
    if not nodes and not errors:
        errors.append("proxies 段为空")
    return nodes, errors


# ---------------------------------------------------------------- 反向导出
def node_to_link(node: dict) -> str:
    """把节点字典反向拼成分享链接（用于导出/复制）。"""
    from urllib.parse import quote, urlencode

    t = node.get("type", "hysteria2")
    host = str(node.get("server", ""))
    if not host:
        raise ParseError("缺少服务器地址")
    hostb = f"[{host}]" if ":" in host else host
    port = node.get("port", 443)
    name = node.get("name", "")
    frag = ("#" + quote(str(name), safe="")) if name else ""

    if t == "vmess":
        net = node.get("network", "tcp")
        # 按传输类型只携带对应字段，避免 grpc/ws 串字段
        ws_host = node.get("ws_host", "") if net in ("ws", "httpupgrade") else ""
        path = (node.get("ws_path", "") if net in ("ws", "httpupgrade")
                else node.get("grpc_service_name", "") if net == "grpc" else "")
        j = {
            "v": "2", "ps": name, "add": host, "port": str(port),
            "id": str(node.get("uuid", "")), "aid": str(node.get("alter_id", 0)),
            "scy": node.get("cipher", "auto"), "net": net,
            "type": "none", "host": ws_host, "path": path,
            "tls": "tls" if node.get("tls") else "", "sni": node.get("sni", ""),
        }
        if node.get("alpn"):                       # round-trip 不丢 alpn
            j["alpn"] = ",".join(str(a) for a in node["alpn"])
        return "vmess://" + base64.b64encode(
            json.dumps(j, ensure_ascii=False).encode()).decode()

    if t in ("vless", "trojan", "tuic"):
        params: dict[str, str] = {}
        net = node.get("network", "tcp")
        if t == "vless":
            cred = quote(str(node.get("uuid", "")), safe="")
            params["encryption"] = "none"
            params["security"] = "reality" if node.get("reality_pbk") else ("tls" if node.get("tls") else "none")
            params["type"] = net
            if node.get("flow"):
                params["flow"] = node["flow"]
            if node.get("reality_pbk"):
                params["pbk"] = node["reality_pbk"]
                if node.get("reality_sid"):
                    params["sid"] = node["reality_sid"]
        elif t == "trojan":
            cred = quote(str(node.get("password", "")), safe="")
            if net != "tcp":
                params["type"] = net
        else:  # tuic
            cred = (quote(str(node.get("uuid", "")), safe="") + ":"
                    + quote(str(node.get("password", "")), safe=""))
            if node.get("congestion"):
                params["congestion_control"] = node["congestion"]
            if node.get("udp_relay_mode"):
                params["udp_relay_mode"] = node["udp_relay_mode"]
        if node.get("sni"):
            params["sni"] = node["sni"]
        if node.get("alpn"):
            params["alpn"] = ",".join(node["alpn"])
        if node.get("client_fingerprint"):
            params["fp"] = node["client_fingerprint"]
        if node.get("skip_cert_verify"):
            params["allowInsecure"] = "1"
        if net == "ws":
            if node.get("ws_path"):
                params["path"] = node["ws_path"]
            if node.get("ws_host"):
                params["host"] = node["ws_host"]
        if net == "grpc" and node.get("grpc_service_name"):
            params["serviceName"] = node["grpc_service_name"]
        q = ("?" + urlencode(params)) if params else ""
        return f"{t}://{cred}@{hostb}:{port}{q}{frag}"

    if t == "ss":
        userinfo = base64.b64encode(
            f"{node.get('cipher','')}:{node.get('password','')}".encode()).decode().rstrip("=")
        q = ""
        if node.get("plugin"):                       # 还原 SIP002 plugin，避免导出丢插件
            opts = node.get("plugin_opts") or {}
            if node["plugin"] == "obfs":
                ps = f"obfs-local;obfs={opts.get('mode', 'http')}"
                if opts.get("host"):
                    ps += f";obfs-host={opts['host']}"
            elif node["plugin"] == "v2ray-plugin":
                ps = f"v2ray-plugin;mode={opts.get('mode', 'websocket')}"
                if opts.get("host"):
                    ps += f";host={opts['host']}"
                if opts.get("path"):
                    ps += f";path={opts['path']}"
            else:
                ps = node["plugin"]
            q = "?" + urlencode({"plugin": ps})
        return f"ss://{userinfo}@{hostb}:{port}{q}{frag}"

    # hysteria2
    params = {}
    if node.get("sni") and node["sni"] != host:
        params["sni"] = node["sni"]
    if node.get("skip_cert_verify"):
        params["insecure"] = "1"
    if node.get("obfs"):
        params["obfs"] = node["obfs"]
        if node.get("obfs_password"):
            params["obfs-password"] = node["obfs_password"]
    if node.get("alpn") and node["alpn"] != ["h3"]:
        params["alpn"] = ",".join(node["alpn"])
    if node.get("ports"):
        params["mport"] = node["ports"]
    if node.get("up"):
        params["up"] = node["up"]
    if node.get("down"):
        params["down"] = node["down"]
    if node.get("pin_sha256"):
        params["pinSHA256"] = node["pin_sha256"]
    elif node.get("fingerprint"):
        params["pinSHA256"] = node["fingerprint"]
    if node.get("fast_open"):
        params["fastopen"] = "1"
    auth = quote(str(node.get("password", "")), safe="")
    q = ("?" + urlencode(params)) if params else ""
    return f"hysteria2://{auth}@{hostb}:{port}/{q}{frag}"
