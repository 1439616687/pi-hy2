"""状态持久化：节点 / 规则 / 设置，统一存于一个 JSON 文件。

mihomo 的 config.yaml 完全由本状态生成，因此“真相”只有这一个 state.json，
WebUI 与命令行向导都读写它，再调用 config_gen 渲染并 apply。
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets

try:
    import fcntl                       # Linux（树莓派）才有；缺失时锁退化为无操作
except ImportError:                    # pragma: no cover
    fcntl = None

from . import config_gen

STATE_DIR = os.environ.get("PIHY2_DIR", "/etc/pihy2")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
LOCK_FILE = STATE_FILE + ".lock"


@contextlib.contextmanager
def state_lock():
    """跨进程互斥锁，保护 state.json 的「读-改-写」临界区。

    CLI（如订阅定时更新进程）与 WebUI 进程会并发改写同一份 state.json，
    仅靠各自的原子写无法防丢更新。调用方应以
        with state_lock():
            store = Store(); ...修改...; store.save()
    形式把整个读改写包起来。拿不到锁文件时退化为无锁，至少不阻断功能。
    """
    if fcntl is None:
        yield
        return
    try:
        os.makedirs(os.path.dirname(LOCK_FILE) or ".", mode=0o700, exist_ok=True)
        f = open(LOCK_FILE, "w")
    except OSError:
        yield
        return
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        finally:
            f.close()


def _id_num(id_str) -> int:
    """取 id 末尾数字（n12 -> 12，s3 -> 3）；无数字返回 0。"""
    m = re.search(r"(\d+)$", str(id_str or ""))
    return int(m.group(1)) if m else 0

# 内置的常用直连规则（首次初始化时写入，用户可在面板里增删）。
# 刻意只用“不依赖 geodata”的规则：GEOIP/GEOSITE 需要 geoip.metadb/GeoSite.dat，
# 首次部署时 mihomo 还没起来、只能直连 GitHub 下载，被墙就会导致配置校验失败、服务起不来。
# 想要更全面的“大陆直连”，可在部署完成后（mihomo 已在跑、下载走代理）于面板添加 GEOIP,CN。
DEFAULT_RULES = [
    {"value": "cn", "policy": "DIRECT", "type": "domain-suffix"},  # .cn 域名直连
]


def _new_state() -> dict:
    settings = dict(config_gen.DEFAULT_SETTINGS)
    settings["secret"] = secrets.token_hex(16)       # clash API 密钥
    return {
        "version": 1,
        "nodes": [],          # 每个节点带一个稳定 id；来自订阅的带 sub=订阅id
        "rules": list(DEFAULT_RULES),
        "subscriptions": [],  # [{id,name,url,updated,count}]
        "settings": settings,
        "active": "",         # 当前选中的节点 id（空=未选/用第一个）
        "sub_interval_hours": 12,   # 订阅自动更新间隔
        "webui": {
            "port": 8088,
            "password": "",   # 空=不鉴权（向导会建议设置）
            "bind": "0.0.0.0",
        },
        "_seq": 0,            # 自增 id 计数
        "_subseq": 0,
    }


class Store:
    def __init__(self, path: str = STATE_FILE):
        self.path = path
        self.data = self.load()

    # ---------------------------------------------------------------- 读写
    def load(self) -> dict:
        if not os.path.exists(self.path):
            return _new_state()
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return self._migrate(json.load(f))
        except (json.JSONDecodeError, OSError):
            # 损坏/不可读：先把原文件改名备份，避免随后一次 save 用空状态把可抢救的数据覆盖清零
            try:
                os.replace(self.path, self.path + ".bad")
            except OSError:
                pass
            return _new_state()

    def save(self) -> None:
        # state.json 含明文密码/密钥，目录与文件都收紧权限到仅 root 可读
        d = os.path.dirname(self.path) or "."
        os.makedirs(d, mode=0o700, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        tmp = self.path + ".tmp"
        # 用 O_CREAT|0o600 创建，文件从诞生即为仅 root 可读，不存在可读窗口
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())          # 防掉电写一半
        os.replace(tmp, self.path)        # 原子替换，避免写一半损坏

    def _migrate(self, data: dict) -> dict:
        base = _new_state()
        base.update({k: v for k, v in data.items() if k in base})
        # settings/webui 做字段补全，兼容旧版本新增字段
        base["settings"] = {**config_gen.DEFAULT_SETTINGS, **data.get("settings", {})}
        if not base["settings"].get("secret"):
            base["settings"]["secret"] = secrets.token_hex(16)
        base["webui"] = {**_new_state()["webui"], **data.get("webui", {})}
        # 回填自增计数，避免（外部编辑/导入缺 _seq 的旧状态后）新 id 与既有 id 撞号
        base["_seq"] = max([base.get("_seq") or 0]
                           + [_id_num(n.get("id")) for n in base.get("nodes", [])])
        base["_subseq"] = max([base.get("_subseq") or 0]
                              + [_id_num(s.get("id")) for s in base.get("subscriptions", [])])
        return base

    # ---------------------------------------------------------------- 节点
    def _next_id(self) -> str:
        self.data["_seq"] += 1
        return f"n{self.data['_seq']}"

    def add_node(self, node: dict) -> dict:
        node = dict(node)
        node["id"] = self._next_id()
        self.data["nodes"].append(node)
        if not self.data.get("active"):
            self.data["active"] = node["id"]
        return node

    def add_nodes(self, nodes: list[dict]) -> list[dict]:
        return [self.add_node(n) for n in nodes]

    def update_node(self, node_id: str, fields: dict) -> dict | None:
        for n in self.data["nodes"]:
            if n["id"] == node_id:
                n.update({k: v for k, v in fields.items() if k != "id"})
                return n
        return None

    def delete_node(self, node_id: str) -> bool:
        before = len(self.data["nodes"])
        self.data["nodes"] = [n for n in self.data["nodes"] if n["id"] != node_id]
        if self.data.get("active") == node_id:
            self.data["active"] = self.data["nodes"][0]["id"] if self.data["nodes"] else ""
        return len(self.data["nodes"]) < before

    def get_node(self, node_id: str) -> dict | None:
        return next((n for n in self.data["nodes"] if n["id"] == node_id), None)

    def reorder_nodes(self, order: list[str]) -> None:
        idx = {nid: i for i, nid in enumerate(order)}
        self.data["nodes"].sort(key=lambda n: idx.get(n["id"], 1e9))

    # ---------------------------------------------------------------- 订阅
    def _next_sub_id(self) -> str:
        self.data["_subseq"] = self.data.get("_subseq", 0) + 1
        return f"s{self.data['_subseq']}"

    def add_subscription(self, name: str, url: str) -> dict:
        sub = {"id": self._next_sub_id(), "name": name.strip() or "订阅",
               "url": url.strip(), "updated": "", "count": 0}
        self.data.setdefault("subscriptions", []).append(sub)
        return sub

    def get_subscription(self, sid: str) -> dict | None:
        return next((s for s in self.data.get("subscriptions", []) if s["id"] == sid), None)

    def delete_subscription(self, sid: str, remove_nodes: bool = True) -> bool:
        subs = self.data.get("subscriptions", [])
        if not any(s["id"] == sid for s in subs):
            return False
        self.data["subscriptions"] = [s for s in subs if s["id"] != sid]
        if remove_nodes:
            keep = [n for n in self.data["nodes"] if n.get("sub") != sid]
            self.data["nodes"] = keep
            if self.data.get("active") and not self.get_node(self.data["active"]):
                self.data["active"] = keep[0]["id"] if keep else ""
        else:
            for n in self.data["nodes"]:
                if n.get("sub") == sid:
                    n.pop("sub", None)
        return True

    def set_subscription_nodes(self, sid: str, nodes: list[dict]) -> int:
        """用新解析的节点替换该订阅下的旧节点，尽量保住“当前节点”。"""
        sub = self.get_subscription(sid)
        if not sub:
            return 0
        # 记录当前节点的稳定标识（名字可能被机场改/复用，故用 名+服务器+端口）
        active_node = self.active_node()
        active_key = None
        if active_node and active_node.get("sub") == sid:
            active_key = (active_node.get("name"), active_node.get("server"), active_node.get("port"))
        # 删掉该订阅旧节点，追加新节点（标记 sub）
        self.data["nodes"] = [n for n in self.data["nodes"] if n.get("sub") != sid]
        added = []
        for nd in nodes:
            nd = dict(nd)
            nd["sub"] = sid
            added.append(self.add_node(nd))
        # 恢复 active：优先 名+服务器+端口 完全一致，其次同名，最后该订阅第一个
        if active_key:
            match = next((n for n in added if (n.get("name"), n.get("server"), n.get("port")) == active_key), None) \
                or next((n for n in added if n.get("name") == active_key[0]), None)
            self.data["active"] = (match or (added[0] if added else {})).get("id", self.data.get("active", ""))
        if self.data.get("active") and not self.get_node(self.data["active"]):
            self.data["active"] = self.data["nodes"][0]["id"] if self.data["nodes"] else ""
        import time
        sub["updated"] = time.strftime("%Y-%m-%d %H:%M")
        sub["count"] = len(added)
        return len(added)

    # ---------------------------------------------------------------- 规则/设置
    def set_rules(self, rules: list[dict]) -> None:
        self.data["rules"] = rules

    def set_settings(self, settings: dict) -> None:
        self.data["settings"].update(settings)

    def set_active(self, node_id: str) -> None:
        self.data["active"] = node_id

    # ---------------------------------------------------------------- 渲染
    def active_node(self) -> dict | None:
        nid = self.data.get("active")
        return self.get_node(nid) if nid else (
            self.data["nodes"][0] if self.data["nodes"] else None)

    def nodes_active_first(self) -> list[dict]:
        """把当前选中的节点排到最前，作为策略组的默认项。"""
        nodes = list(self.data["nodes"])
        act = self.data.get("active")
        if act:
            nodes.sort(key=lambda n: 0 if n["id"] == act else 1)
        return nodes

    def render_config(self) -> str:
        return config_gen.render(
            self.nodes_active_first(), self.data["rules"], self.data["settings"])
