"""可视化管理面板：HTTP 服务 + REST API。

零依赖（仅标准库 http.server）。前端静态文件在仓库的 web/ 目录。
鉴权：若设置了访问密码，则 /api/login 用密码换取 token，后续请求带
Authorization: Bearer <token>；未设密码则不鉴权（界面会提示风险）。
"""

from __future__ import annotations

import ipaddress
import json
import os
import secrets
import socket
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import manager, parser, config_gen
from .store import Store, state_lock

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")

TOKEN_TTL = 12 * 3600          # token 有效期（秒）
LOGIN_MAX_FAILS = 8            # 同一 IP 连续失败上限
LOGIN_LOCK_SECS = 60          # 触发上限后锁定时长

_lock = threading.Lock()
_tokens: dict[str, float] = {}          # token -> 过期时间戳
_login_fails: dict[str, list] = {}      # ip -> [失败次数, 最近失败时间]


def _valid_listen_port(v):
    """监听端口校验：返回 1..65535 的 int，否则 None。
    防止把 0/越界/非数字写进 state.json，导致下次 pihy2-web 重启 bind 崩溃、面板永久失联。"""
    try:
        p = int(v)
    except (TypeError, ValueError):
        return None
    return p if 1 <= p <= 65535 else None


def _valid_bind(v):
    """监听地址校验：返回合法 IP 或 'localhost'，否则 None。
    防止把无法解析的 bind 写进 state.json，导致下次重启 ThreadingHTTPServer 抛 gaierror。"""
    b = str(v or "").strip()
    if b == "localhost":
        return b
    try:
        ipaddress.ip_address(b)
        return b
    except ValueError:
        return None


def _sweep_locked():
    """清理过期 token 与陈旧的登录失败计数，防字典无界增长（调用方须持有 _lock）。"""
    now = time.time()
    for t in [k for k, exp in _tokens.items() if exp < now]:
        _tokens.pop(t, None)
    for ip in [k for k, v in _login_fails.items() if now - v[1] > LOGIN_LOCK_SECS]:
        _login_fails.pop(ip, None)

_MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "pihy2"

    def log_message(self, *a):  # 静默默认访问日志
        pass

    # ----------------------------------------------------------- 工具
    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _err(self, msg: str, code: int = 400):
        self._json({"ok": False, "error": msg}, code)

    def _body(self) -> dict:
        try:                                # 畸形 Content-Length（如 'abc'）不应让整个请求线程崩
            n = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            return {}
        if n <= 0:
            return {}
        if n > 4 * 1024 * 1024:          # 限制请求体大小，防止内存被撑爆
            self.rfile.read(min(n, 1 << 20))
            return {}
        try:
            d = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except (json.JSONDecodeError, ValueError):
            return {}
        # 合法但非对象的 JSON（如 [1,2] / 5 / "x" / null）会让各处 body.get(...) 崩，统一归一为 {}
        return d if isinstance(d, dict) else {}

    def _store(self) -> Store:
        return Store()  # 每次请求从磁盘加载，避免与 CLI 写入冲突

    def _need_auth(self, store: Store) -> bool:
        return bool(store.data["webui"].get("password"))

    def _authed(self, store: Store) -> bool:
        if not self._need_auth(store):
            return True
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        with _lock:                     # _tokens 在多线程下读改写须持锁
            exp = _tokens.get(token)
            if exp is None:
                return False
            if exp < time.time():       # 过期则清除
                _tokens.pop(token, None)
                return False
        return True

    def _client_ip(self) -> str:
        return self.client_address[0] if self.client_address else "?"

    # ----------------------------------------------------------- 防 CSRF / DNS rebinding
    def _host_only(self) -> str:
        h = (self.headers.get("Host", "") or "").strip()
        if h.startswith("["):                       # [ipv6]:port
            return h[1:h.index("]")] if "]" in h else h
        return h.rsplit(":", 1)[0] if ":" in h else h

    def _guard_write(self, store: Store) -> bool:
        """状态变更请求的防护：

        1) 带 Origin/Referer 时须与 Host 同源（挡跨站 CSRF）。
        2) 未设访问密码时，额外要求 Host 为 IP/localhost——此时写操作无凭证，
           DNS rebinding（把攻击者域名重绑到 127.0.0.1）是主要风险，拒绝域名 Host 即可遏制；
           而设了密码时，token 存于「面板真实源」的 localStorage，攻击者源读不到，
           rebinding 自然拿不到 token、写操作会被 401 挡下，故放行主机名访问（不误伤 *.local）。
        """
        host = self._host_only()
        origin = self.headers.get("Origin") or self.headers.get("Referer")
        if origin:
            # urlparse 把 Origin 主机名小写化，而 Host 原样；统一小写比较，避免误伤 MyPi.local 这类大小写
            oh = urllib.parse.urlparse(origin).hostname or ""
            if oh and oh.lower() != host.lower():
                self._err("拒绝：跨站请求", 403)
                return False
        if not store.data["webui"].get("password"):
            host_ok = host == "localhost"
            if not host_ok:
                try:
                    ipaddress.ip_address(host)
                    host_ok = True
                except ValueError:
                    host_ok = False
            if not host_ok:
                self._err("拒绝：未设密码时请用本机 IP 或 localhost 访问面板（防 DNS rebinding）", 403)
                return False
        return True

    # ----------------------------------------------------------- 路由
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/"):
            return self._api_get(path)
        return self._static(path)

    def do_POST(self):
        if not self.path.startswith("/api/"):
            return self._err("not found", 404)
        if not self._guard_write(self._store()):
            return
        return self._api_post(self.path.split("?", 1)[0])

    def do_PUT(self):
        if not self.path.startswith("/api/"):
            return self._err("not found", 404)
        if not self._guard_write(self._store()):
            return
        return self._api_put(self.path.split("?", 1)[0])

    def do_DELETE(self):
        if not self.path.startswith("/api/"):
            return self._err("not found", 404)
        if not self._guard_write(self._store()):
            return
        return self._api_delete(self.path.split("?", 1)[0])

    # ----------------------------------------------------------- 静态文件
    def _static(self, path: str):
        if path in ("/", ""):
            path = "/index.html"
        # 防目录穿越
        rel = os.path.normpath(path).lstrip("/\\")
        full = os.path.join(WEB_DIR, rel)
        if not os.path.abspath(full).startswith(os.path.abspath(WEB_DIR)) or not os.path.isfile(full):
            return self._send(404, b"not found", "text/plain; charset=utf-8")
        ext = os.path.splitext(full)[1].lower()
        with open(full, "rb") as f:
            self._send(200, f.read(), _MIME.get(ext, "application/octet-stream"))

    # ----------------------------------------------------------- GET API
    def _api_get(self, path: str):
        store = self._store()
        if path == "/api/authinfo":  # 公开：登录页据此判断是否需要登录（必须先于守卫）
            return self._json({"ok": True, "need_auth": self._need_auth(store)})
        # 所有数据型 GET 也走反 DNS-rebinding 守卫：未设密码时这些接口（/api/export 等）
        # 会泄露节点凭据/配置，必须和写操作一样要求 Host 为 IP/localhost、同源。
        if not self._guard_write(store):
            return
        if path == "/api/state":
            if not self._authed(store):
                return self._err("未登录", 401)
            return self._json({
                "ok": True,
                "need_auth": self._need_auth(store),
                "nodes": store.data["nodes"],
                "rules": store.data["rules"],
                "subscriptions": store.data.get("subscriptions", []),
                "sub_interval_hours": store.data.get("sub_interval_hours", 12),
                "preset_catalog": [{"key": k, "name": v[0], "desc": v[1]}
                                   for k, v in config_gen.RULE_PRESETS.items()],
                "settings": {k: v for k, v in store.data["settings"].items()
                             if k != "secret"},
                "webui": {"port": store.data["webui"]["port"],
                          "bind": store.data["webui"]["bind"],
                          "has_password": bool(store.data["webui"].get("password"))},
                "active": store.data["active"],
            })
        if not self._authed(store):
            return self._err("未登录", 401)
        if path == "/api/status":
            return self._json({
                "ok": True,
                "mihomo": manager.service_status("mihomo"),
                "webui": manager.service_status("pihy2-web"),
                "ip": manager.current_ip(),
                "installed": os.path.exists(manager.MIHOMO_BIN),
            })
        if path == "/api/delays":
            s = store.data["settings"]
            # 用配置里去重后的名字调用 clash API；并发探测，避免几十个节点串行拖很久
            names = config_gen.display_names(store.nodes_active_first())
            nodes = list(store.data["nodes"])
            out = {}
            if nodes:
                def _probe(n):
                    return n["id"], manager.clash_delay(names.get(n["id"], n["name"]), s)
                with ThreadPoolExecutor(max_workers=min(8, len(nodes))) as ex:
                    for nid, d in ex.map(_probe, nodes):
                        out[nid] = d
            return self._json({"ok": True, "delays": out})
        if path == "/api/traffic":  # 实时流量/连接快照
            data = manager.clash_connections(store.data["settings"]) or {}
            conns = data.get("connections") or []
            top = sorted(conns, key=lambda x: (x.get("upload", 0) + x.get("download", 0)),
                         reverse=True)[:40]
            brief = []
            for c in top:
                md = c.get("metadata", {}) or {}
                brief.append({
                    "host": md.get("host") or md.get("destinationIP") or "",
                    "dest": (md.get("destinationIP", "") + (":" + str(md.get("destinationPort", "")) if md.get("destinationPort") else "")),
                    "net": md.get("network", ""),
                    "chain": (c.get("chains") or [""])[0],
                    "rule": c.get("rule", ""),
                    "up": c.get("upload", 0), "down": c.get("download", 0),
                })
            return self._json({"ok": True, "running": bool(data),
                               "up_total": data.get("uploadTotal", 0),
                               "down_total": data.get("downloadTotal", 0),
                               "count": len(conns), "conns": brief})
        if path == "/api/logs":
            return self._json({"ok": True, "logs": manager.journal("mihomo", 60)})
        if path == "/api/config":  # 预览当前会生成的配置（隐去 clash 密钥）
            cfg = store.render_config()
            sec = store.data["settings"].get("secret")
            if sec:
                cfg = cfg.replace(sec, "******")
            return self._json({"ok": True, "config": cfg})
        if path == "/api/export":  # 导出所有节点链接（逐个兜底，单条坏数据不拖垮整次导出）
            links = []
            for n in store.data["nodes"]:
                try:
                    links.append(parser.node_to_link(n))
                except Exception:
                    continue
            return self._json({"ok": True, "links": links})
        return self._err("not found", 404)

    # ----------------------------------------------------------- POST API
    def _api_post(self, path: str):
        store = self._store()
        body = self._body()

        if path == "/api/login":
            ip = self._client_ip()
            pw = store.data["webui"].get("password", "")
            token = None
            locked = False
            # 检查锁定 + 比对密码 + 失败计数放进同一把锁的同一临界区，
            # 否则并发请求会都读到 fails=0 后一起通过，绕过“连续失败上限”限速。
            with _lock:
                _sweep_locked()                 # 顺手清理过期 token / 陈旧失败计数
                fails = _login_fails.get(ip, [0, 0.0])
                if fails[0] >= LOGIN_MAX_FAILS and time.time() - fails[1] < LOGIN_LOCK_SECS:
                    locked = True
                elif pw and secrets.compare_digest(str(body.get("password", "")), pw):
                    token = secrets.token_urlsafe(24)
                    _tokens[token] = time.time() + TOKEN_TTL
                    _login_fails.pop(ip, None)
                else:
                    _login_fails[ip] = [fails[0] + 1, time.time()]
            if locked:
                return self._err("尝试过于频繁，请稍后再试", 429)
            if token:
                return self._json({"ok": True, "token": token})
            time.sleep(0.5)             # 失败固定延时放锁外：抬高爆破成本，又不拖慢其它 IP 登录
            return self._err("密码错误", 401)

        if path == "/api/logout":
            auth = self.headers.get("Authorization", "")
            tok = auth[7:] if auth.startswith("Bearer ") else ""
            with _lock:
                _tokens.pop(tok, None)
            return self._json({"ok": True})

        if not self._authed(store):
            return self._err("未登录", 401)

        if path == "/api/parse":  # 仅预览，不保存
            nodes, errs = parser.parse_many(body.get("text", ""))
            return self._json({"ok": True, "nodes": nodes, "errors": errs})

        # 原则：进程锁/状态锁只罩住“内存读改写 + 存盘”这段；网络/子进程 IO（拉订阅、
        # mihomo -t/重启、clash API）一律放锁外，避免一个慢/卡住的请求把所有面板写操作冻住。
        if path in ("/api/nodes", "/api/nodes/order"):
            with _lock, state_lock():
                store = self._store()
                if path == "/api/nodes/order":
                    store.reorder_nodes(body.get("order", []))
                    store.save()
                    return self._json({"ok": True})
                if body.get("text"):  # 从链接批量添加
                    nodes, errs = parser.parse_many(body["text"])
                    added = store.add_nodes(nodes)
                    store.save()
                    return self._json({"ok": True, "added": added, "errors": errs})
                if body.get("node"):  # 从表单添加单个
                    added = store.add_node(body["node"])
                    store.save()
                    return self._json({"ok": True, "added": [added]})
                return self._err("缺少 text 或 node")

        if path == "/api/active":
            nid = body.get("id", "")
            with _lock, state_lock():
                store = self._store()
                node = store.get_node(nid)
                if not node:
                    return self._err("节点不存在")
                store.set_active(nid)
                store.save()
                # clash API 用的是配置里去重/规避保留词后的名字，与 state 原始 name 可能不同
                disp = config_gen.display_names(store.nodes_active_first()).get(nid, node["name"])
                settings = dict(store.data["settings"])
            ok, info = manager.clash_select("PROXY", disp, settings)   # 网络 IO，锁外
            return self._json({"ok": True, "live": ok, "info": info})

        if path == "/api/apply":
            ok, msg = manager.apply_config(self._store(), restart=True)  # 子进程 IO，锁外
            return self._json({"ok": ok, "message": msg})

        if path == "/api/service":
            action = body.get("action", "restart")
            if action not in ("restart", "stop", "start"):
                return self._err("非法操作")
            manager.service_action("mihomo", action)
            return self._json({"ok": True})

        if path == "/api/connections/close":
            return self._json({"ok": manager.clash_close_all(self._store().data["settings"])})

        if path == "/api/subs":              # 添加订阅并立即拉取 + 应用
            url = (body.get("url") or "").strip()
            if not url.lower().startswith(("http://", "https://")):
                return self._err("订阅地址需以 http(s):// 开头")
            with _lock, state_lock():            # 1) 锁内：登记订阅 + 存盘
                store = self._store()
                sub = store.add_subscription(body.get("name", ""), url)
                sid = sub["id"]
                store.save()
            nodes, errs = manager.fetch_sub_nodes(url)   # 2) 锁外：拉取（可能很慢）
            cnt = 0
            with _lock, state_lock():            # 3) 锁内：写回该订阅的节点
                store = self._store()
                if nodes and store.get_subscription(sid):
                    cnt = store.set_subscription_nodes(sid, nodes)
                    store.save()
            if cnt:
                manager.apply_config(self._store())   # 4) 锁外：应用
            return self._json({"ok": True, "sub": sub, "count": cnt, "errors": errs})

        if path == "/api/subs/update":       # 更新某个或全部订阅 + 应用
            sid = body.get("id", "all")
            subs = self._store().data.get("subscriptions", [])
            targets = subs if sid == "all" else [s for s in subs if s["id"] == sid]
            total = 0
            for s in targets:
                nodes, _errs = manager.fetch_sub_nodes(s["url"])   # 锁外逐个拉取
                if not nodes:
                    continue
                with _lock, state_lock():        # 锁内写回，不持锁做网络 IO
                    store = self._store()
                    if store.get_subscription(s["id"]):
                        total += store.set_subscription_nodes(s["id"], nodes)
                        store.save()
            applied = ""
            if total:
                applied = manager.apply_config(self._store())[1]   # 锁外应用
            return self._json({"ok": True, "count": total, "applied": applied})

        return self._err("not found", 404)

    # ----------------------------------------------------------- PUT API
    def _api_put(self, path: str):
        store = self._store()
        if not self._authed(store):
            return self._err("未登录", 401)
        body = self._body()
        timer_hours = None
        settings_saved = False
        with _lock, state_lock():
            store = self._store()
            if path.startswith("/api/nodes/"):
                nid = path.rsplit("/", 1)[-1]
                node = store.update_node(nid, body)
                if not node:
                    return self._err("节点不存在", 404)
                store.save()
                return self._json({"ok": True, "node": node})
            if path == "/api/rules":
                store.set_rules(body.get("rules", []))
                store.save()
                return self._json({"ok": True})
            if path == "/api/settings":
                # 仅接受面向用户的已知设置键，显式拒绝 secret 等内部字段被覆盖/注入
                allowed = set(config_gen.DEFAULT_SETTINGS) | {"github_mirror"}
                allowed.discard("secret")
                settings = {k: v for k, v in dict(body.get("settings", {})).items()
                            if k in allowed}
                # external_controller 必须是回环地址，否则带密钥外发会造成 SSRF/密钥外泄
                ec = settings.get("external_controller")
                if ec is not None:
                    if not str(ec).strip():
                        # 清空=保持原值，不用空串覆盖（否则前端清空该框会整份设置都存不进去）
                        settings.pop("external_controller", None)
                    else:
                        host = urllib.parse.urlparse(
                            ec if ec.startswith("http") else "http://" + ec).hostname or ""
                        if host not in ("127.0.0.1", "::1", "localhost"):
                            return self._err("外部控制器必须是本机回环地址（127.0.0.1）")
                # 下载镜像必须 https
                mir = settings.get("github_mirror", "")
                if mir and not mir.lower().startswith("https://"):
                    return self._err("下载镜像必须以 https:// 开头")
                # fake-ip 网段必须是合法 CIDR，否则 mihomo -t 失败且空/坏值被持久化、每次 apply 都卡住
                if "fake_ip_range" in settings:
                    fr = str(settings["fake_ip_range"]).strip()
                    try:
                        ipaddress.ip_network(fr, strict=False)
                    except ValueError:
                        return self._err("fake-ip 网段必须是合法 CIDR（如 198.18.0.1/16）")
                    settings["fake_ip_range"] = fr
                # 受限取值白名单
                if settings.get("tun_stack") not in (None, "system", "gvisor", "mixed"):
                    return self._err("TUN 协议栈必须是 system / gvisor / mixed")
                if settings.get("log_level") not in (None, "silent", "error", "warning", "info", "debug"):
                    return self._err("日志级别必须是 silent/error/warning/info/debug")
                # 类型规整：脏值/误传不应破坏配置渲染（presets/dns_* 必须是列表，否则丢弃该键回退原值）
                if "presets" in settings and not isinstance(settings["presets"], list):
                    settings.pop("presets")
                for _dk in ("dns_nameservers", "dns_china", "tun_dns_hijack"):
                    if _dk in settings and not isinstance(settings[_dk], list):
                        settings.pop(_dk)
                if "tun_auto_redirect" in settings:
                    settings["tun_auto_redirect"] = bool(settings["tun_auto_redirect"])
                # gateway_mode/allow_lan/ipv6 等布尔设置规整：Python 里非空字符串恒真，
                # 不转的话 "false"/"0"/"no" 会误开网关与系统 IP 转发。
                for _bk in ("gateway_mode", "allow_lan", "ipv6"):
                    if _bk in settings:
                        _v = settings[_bk]
                        settings[_bk] = (str(_v).strip().lower() not in ("", "0", "false", "no", "off")
                                         if isinstance(_v, str) else bool(_v))
                store.set_settings(settings)
                if "sub_interval_hours" in body:     # 订阅自动更新间隔
                    h = int(body["sub_interval_hours"]) if str(body["sub_interval_hours"]).isdigit() else 12
                    store.data["sub_interval_hours"] = max(1, h)
                    if os.path.exists(manager.SUB_TIMER):
                        timer_hours = store.data["sub_interval_hours"]   # 锁外再重写 timer
                store.save()
                settings_saved = True            # 落锁外执行 install_sub_timer 并返回
            elif path == "/api/webui":
                w = store.data["webui"]
                new_bind = w.get("bind", "0.0.0.0")
                if "bind" in body:
                    b = _valid_bind(body["bind"])
                    if b is None:
                        return self._err("监听地址必须是 IP 或 localhost")
                    new_bind = b
                new_pw = w.get("password", "")
                if "password" in body:          # 空字符串=取消密码
                    new_pw = body["password"]
                # 安全不变量：未设密码时只能监听回环——否则=局域网内无鉴权的 root 控制台。
                # serve() 仅在启动时兜底，这里在写入时就拦住危险组合（在线清密码却仍开放 LAN）。
                if not new_pw and new_bind not in ("127.0.0.1", "::1", "localhost"):
                    return self._err("未设访问密码时只能监听回环（127.0.0.1）。"
                                     "请先设密码，或把监听地址改为 127.0.0.1 后再取消密码。")
                if "port" in body:
                    p = _valid_listen_port(body["port"])
                    if p is None:
                        return self._err("监听端口必须是 1..65535 的整数")
                    w["port"] = p
                w["bind"] = new_bind
                if "password" in body:
                    w["password"] = body["password"]
                    _tokens.clear()
                store.save()
                return self._json({"ok": True})
        # /api/settings 走到这里：systemd timer 重写（daemon-reload/enable/start 子进程）放锁外执行，
        # 避免持有 _lock/state_lock 期间做慢 IO 冻结其它面板写操作。
        if settings_saved:
            if timer_hours is not None:
                manager.install_sub_timer(timer_hours)
            return self._json({"ok": True})
        return self._err("not found", 404)

    # ----------------------------------------------------------- DELETE API
    def _api_delete(self, path: str):
        store = self._store()
        if not self._authed(store):
            return self._err("未登录", 401)
        with _lock, state_lock():
            store = self._store()
            if path.startswith("/api/nodes/"):
                nid = path.rsplit("/", 1)[-1]
                ok = store.delete_node(nid)
                store.save()
                return self._json({"ok": ok})
            if path.startswith("/api/subs/"):
                sid = path.rsplit("/", 1)[-1]
                ok = store.delete_subscription(sid, remove_nodes=True)
                store.save()
                return self._json({"ok": ok})
        return self._err("not found", 404)


def serve(port: int | None = None, bind: str | None = None):
    store = Store()
    port = port or store.data["webui"]["port"]
    bind = bind or store.data["webui"].get("bind", "0.0.0.0")
    # 安全兜底：未设访问密码时，绝不监听非回环地址（否则=局域网内无鉴权的 root 控制台）
    if not store.data["webui"].get("password") and bind not in ("127.0.0.1", "::1", "localhost"):
        print("⚠️  未设置访问密码，为安全起见仅监听 127.0.0.1。"
              "请在面板/向导里设置密码后再开放到局域网。")
        bind = "127.0.0.1"
    # ThreadingHTTPServer 默认 AF_INET（仅 IPv4）；bind 是 IPv6 字面量时必须切到 AF_INET6，
    # 否则 ('::1', port) 会抛 gaierror 让面板起不来（_valid_bind 允许 ::1/:: 这类 IPv6）。
    try:
        family = socket.AF_INET6 if ipaddress.ip_address(bind).version == 6 else socket.AF_INET
    except ValueError:
        family = socket.AF_INET                  # 'localhost' 等主机名 -> 走 IPv4
    server_cls = type("_PiHy2Server", (ThreadingHTTPServer,), {"address_family": family})
    httpd = server_cls((bind, port), Handler)
    print(f"pihy2 WebUI 运行于 http://{bind}:{port}（静态目录 {WEB_DIR}）")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
