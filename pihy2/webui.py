"""可视化管理面板：HTTP 服务 + REST API。

零依赖（仅标准库 http.server）。前端静态文件在仓库的 web/ 目录。
鉴权：若设置了访问密码，则 /api/login 用密码换取 token，后续请求带
Authorization: Bearer <token>；未设密码则不鉴权（界面会提示风险）。
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import manager, parser
from .store import Store

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")

_lock = threading.Lock()
_tokens: set[str] = set()

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
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _err(self, msg: str, code: int = 400):
        self._json({"ok": False, "error": msg}, code)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0) or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except (json.JSONDecodeError, ValueError):
            return {}

    def _store(self) -> Store:
        return Store()  # 每次请求从磁盘加载，避免与 CLI 写入冲突

    def _need_auth(self, store: Store) -> bool:
        return bool(store.data["webui"].get("password"))

    def _authed(self, store: Store) -> bool:
        if not self._need_auth(store):
            return True
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        return token in _tokens

    # ----------------------------------------------------------- 路由
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/"):
            return self._api_get(path)
        return self._static(path)

    def do_POST(self):
        if not self.path.startswith("/api/"):
            return self._err("not found", 404)
        return self._api_post(self.path.split("?", 1)[0])

    def do_PUT(self):
        if not self.path.startswith("/api/"):
            return self._err("not found", 404)
        return self._api_put(self.path.split("?", 1)[0])

    def do_DELETE(self):
        if not self.path.startswith("/api/"):
            return self._err("not found", 404)
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
        if path == "/api/state":
            if not self._authed(store):
                return self._err("未登录", 401)
            return self._json({
                "ok": True,
                "need_auth": self._need_auth(store),
                "nodes": store.data["nodes"],
                "rules": store.data["rules"],
                "settings": {k: v for k, v in store.data["settings"].items()
                             if k != "secret"},
                "webui": {"port": store.data["webui"]["port"],
                          "bind": store.data["webui"]["bind"],
                          "has_password": bool(store.data["webui"].get("password"))},
                "active": store.data["active"],
            })
        if path == "/api/authinfo":  # 未鉴权也可访问：告诉前端是否需要登录
            return self._json({"ok": True, "need_auth": self._need_auth(store)})
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
            out = {n["id"]: manager.clash_delay(n["name"], s) for n in store.data["nodes"]}
            return self._json({"ok": True, "delays": out})
        if path == "/api/config":  # 预览当前会生成的配置
            return self._json({"ok": True, "config": store.render_config()})
        if path == "/api/export":  # 导出所有节点链接
            links = [parser.node_to_link(n) for n in store.data["nodes"]]
            return self._json({"ok": True, "links": links})
        return self._err("not found", 404)

    # ----------------------------------------------------------- POST API
    def _api_post(self, path: str):
        store = self._store()
        body = self._body()

        if path == "/api/login":
            pw = store.data["webui"].get("password", "")
            if pw and body.get("password") == pw:
                token = secrets.token_urlsafe(24)
                _tokens.add(token)
                return self._json({"ok": True, "token": token})
            return self._err("密码错误", 401)

        if not self._authed(store):
            return self._err("未登录", 401)

        if path == "/api/parse":  # 仅预览，不保存
            nodes, errs = parser.parse_many(body.get("text", ""))
            return self._json({"ok": True, "nodes": nodes, "errors": errs})

        with _lock:
            store = self._store()
            if path == "/api/nodes":
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

            if path == "/api/nodes/order":
                store.reorder_nodes(body.get("order", []))
                store.save()
                return self._json({"ok": True})

            if path == "/api/active":
                nid = body.get("id", "")
                node = store.get_node(nid)
                if not node:
                    return self._err("节点不存在")
                store.set_active(nid)
                store.save()
                # 尝试免重启实时切换；失败则需用户点“应用配置”
                ok, info = manager.clash_select("PROXY", node["name"], store.data["settings"])
                return self._json({"ok": True, "live": ok, "info": info})

            if path == "/api/apply":
                ok, msg = manager.apply_config(store, restart=True)
                return self._json({"ok": ok, "message": msg})

            if path == "/api/service":
                action = body.get("action", "restart")
                if action not in ("restart", "stop", "start"):
                    return self._err("非法操作")
                manager.service_action("mihomo", action)
                return self._json({"ok": True})

        return self._err("not found", 404)

    # ----------------------------------------------------------- PUT API
    def _api_put(self, path: str):
        store = self._store()
        if not self._authed(store):
            return self._err("未登录", 401)
        body = self._body()
        with _lock:
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
                store.set_settings(body.get("settings", {}))
                store.save()
                return self._json({"ok": True})
            if path == "/api/webui":
                w = store.data["webui"]
                if "port" in body and str(body["port"]).isdigit():
                    w["port"] = int(body["port"])
                if "bind" in body:
                    w["bind"] = body["bind"]
                if "password" in body:  # 空字符串=取消密码
                    w["password"] = body["password"]
                    _tokens.clear()
                store.save()
                return self._json({"ok": True})
        return self._err("not found", 404)

    # ----------------------------------------------------------- DELETE API
    def _api_delete(self, path: str):
        store = self._store()
        if not self._authed(store):
            return self._err("未登录", 401)
        with _lock:
            store = self._store()
            if path.startswith("/api/nodes/"):
                nid = path.rsplit("/", 1)[-1]
                ok = store.delete_node(nid)
                store.save()
                return self._json({"ok": ok})
        return self._err("not found", 404)


def serve(port: int | None = None, bind: str | None = None):
    store = Store()
    port = port or store.data["webui"]["port"]
    bind = bind or store.data["webui"].get("bind", "0.0.0.0")
    httpd = ThreadingHTTPServer((bind, port), Handler)
    print(f"pihy2 WebUI 运行于 http://{bind}:{port}（静态目录 {WEB_DIR}）")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
