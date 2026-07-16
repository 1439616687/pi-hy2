"""状态持久化：节点 / 规则 / 设置，统一存于一个 JSON 文件。

mihomo 的 config.yaml 完全由本状态生成，因此“真相”只有这一个 state.json，
WebUI 与命令行向导都读写它，再调用 config_gen 渲染并 apply。
"""

from __future__ import annotations

import contextlib
import copy
import json
import os
import re
import secrets
import time

try:
    import fcntl                       # Linux（树莓派）才有；缺失时锁退化为无操作
except ImportError:                    # pragma: no cover
    fcntl = None

from . import config_gen, parser
from .log import get_logger

_log = get_logger("store")

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


# id 安全模式：仅字母/数字/_/-。恶意备份/外部编辑可能塞入含引号括号的 id（如
# x');evil//），进前端 inline onclick 即存储型 XSS（A5）。在 _migrate 这个唯一 chokepoint 拦截：
# 不符模式一律重发为 n{seq}/s{seq}，比前端 N 处转义更稳。
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

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
            return _new_state()        # 全新安装：文件不存在是正常的，不算损坏
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return self._migrate(json.load(f))
        except (json.JSONDecodeError, ValueError, TypeError, AttributeError, OSError) as e:
            # 损坏/结构异常（非 dict 顶层、settings/webui 非 dict 等）/不可读：把原文件**非破坏性**
            # 改名备份（绝不覆盖已有 .bad），避免随后一次 save 用空状态把可抢救的数据覆盖清零；
            # 同时把原因打到 stderr，让“配置莫名清空”可见、可排查（systemd journal 也能收到）。
            self._backup_corrupt(e)
            return _new_state()

    def _backup_corrupt(self, err: Exception) -> None:
        bak = self.path + ".bad"
        i = 0
        while os.path.exists(bak):     # 非破坏性：第二次损坏不再覆盖第一次的可抢救备份
            i += 1
            bak = f"{self.path}.bad.{i}"
        try:
            os.replace(self.path, bak)
            _log.error(
                "无法读取状态文件 %s（%s: %s）；已备份为 %s 并以空白状态启动——"
                "请检查该备份能否抢救后再做改动。",
                self.path, type(err).__name__, err, bak)
        except OSError:
            _log.error("状态文件 %s 损坏且无法备份（%s: %s）。",
                       self.path, type(err).__name__, err)

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
        if not isinstance(data, dict):     # 顶层不是对象（list/str/number）：交给 load 的兜底备份+重置
            raise ValueError("state.json 顶层不是对象")
        base = _new_state()
        base.update({k: v for k, v in data.items() if k in base})
        # 外部/手工编辑的 state 里 nodes/subscriptions 可能含非 dict 元素：先过滤，避免
        # 后续 n.get(...) 在字符串/None 上抛 AttributeError，使整个工具在加载期就起不来。
        base["nodes"] = [n for n in base.get("nodes", []) if isinstance(n, dict)]
        base["subscriptions"] = [s for s in base.get("subscriptions", []) if isinstance(s, dict)]
        # settings/webui 做字段补全；**先把非 dict 的 settings/webui 归一为 {}** 再展开，
        # 否则 {**"pwned"} 抛 TypeError，使每个入口（CLI/面板/定时器）一加载就崩、且不走 .bad 备份。
        _s = data.get("settings")
        base["settings"] = {**config_gen.DEFAULT_SETTINGS, **(_s if isinstance(_s, dict) else {})}
        sec = base["settings"].get("secret")    # 非字符串 secret 会让 /api/config 脱敏与 clash 客户端崩
        base["settings"]["secret"] = sec if isinstance(sec, str) and sec else secrets.token_hex(16)
        _w = data.get("webui")
        base["webui"] = {**_new_state()["webui"], **(_w if isinstance(_w, dict) else {})}
        # 回填自增计数，避免（外部编辑/导入缺 _seq 的旧状态后）新 id 与既有 id 撞号
        base["_seq"] = max([base.get("_seq") or 0]
                           + [_id_num(n.get("id")) for n in base["nodes"]])
        base["_subseq"] = max([base.get("_subseq") or 0]
                              + [_id_num(s.get("id")) for s in base["subscriptions"]])
        # 给缺/非法/**重复** id 的节点（重）发稳定 id：重复 id 会让 update 命中错节点、delete 误删多个
        seen_ids: set = set()
        for n in base["nodes"]:
            nid = n.get("id")
            if not nid or nid in seen_ids or not _SAFE_ID_RE.match(str(nid)):
                n["id"] = self._next_id_on(base)
            seen_ids.add(n["id"])
        # 订阅：补全缺失字段（旧版/手工编辑的 state 缺 name/url/count/updated 会让 `pihy2 sub list` KeyError）、
        # 并对缺/重复 id 重发，确保 get/delete 按 id 唯一匹配
        seen_sids: set = set()
        for s in base["subscriptions"]:
            s.setdefault("name", "订阅")
            s.setdefault("url", "")
            s.setdefault("count", 0)
            s.setdefault("updated", "")
            s.setdefault("last_error", "")
            sid = s.get("id")
            if not sid or sid in seen_sids or not _SAFE_ID_RE.match(str(sid)):
                s["id"] = self._next_sub_id_on(base)
            seen_sids.add(s["id"])
        # active 指向已不存在的节点时（外部编辑/导入）回落到第一个有效 id，避免悬空 active
        ids = {n["id"] for n in base["nodes"]}
        if base.get("active") not in ids:
            base["active"] = next((n["id"] for n in base["nodes"]), "")
        return base

    @staticmethod
    def _next_id_on(state: dict) -> str:
        state["_seq"] = state.get("_seq", 0) + 1
        return f"n{state['_seq']}"

    @staticmethod
    def _next_sub_id_on(state: dict) -> str:
        state["_subseq"] = state.get("_subseq", 0) + 1
        return f"s{state['_subseq']}"

    # ---------------------------------------------------------------- 节点
    def _next_id(self) -> str:
        self.data["_seq"] += 1
        return f"n{self.data['_seq']}"

    def add_node(self, node: dict) -> dict:
        node = parser.normalize_node(node)   # 统一字段类型，杜绝 name=int/alpn=str 等坏形状进库（DC-2/DC-5）
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
                # 不接受经 PUT 改写 id / sub：sub 决定订阅归属，被改写会让节点在下次订阅刷新时凭空消失或残留
                for k, v in fields.items():
                    if k not in ("id", "sub"):
                        n[k] = v
                norm = parser.normalize_node(n)   # 规整类型，避免坏形状落库后让渲染/导出崩
                n.clear()
                n.update(norm)
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
               "url": url.strip(), "updated": "", "count": 0, "last_error": ""}
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
        sub["updated"] = time.strftime("%Y-%m-%d %H:%M")
        sub["count"] = len(added)
        sub["last_error"] = ""            # 成功：清掉上次失败原因
        return len(added)

    def mark_subscription_error(self, sid: str, msg: str) -> bool:
        """记录某订阅最近一次更新失败的原因（成功时由 set_subscription_nodes 清空），
        供面板订阅卡直接显示“为什么没更新”，把静默失败变成可追溯。"""
        sub = self.get_subscription(sid)
        if not sub:
            return False
        sub["last_error"] = (msg or "")[:200]
        sub["updated"] = time.strftime("%Y-%m-%d %H:%M")
        return True

    # ---------------------------------------------------------------- 规则/设置
    def set_rules(self, rules: list[dict]) -> None:
        # 只收 dict 规则项：非 dict（如外部传入 ["foo"]）会让 build_config 渲染时 r.get(...) 崩，
        # 且被持久化后变成毒丸——此后每次 config 预览/apply（含定时器）都 500，直到手改 state.json。
        # node（高级分流"指定节点"）只接受非空字符串 id；脏值剥掉，渲染时回落 policy（安全）。
        out = []
        for r in (rules or []):
            if not isinstance(r, dict):
                continue
            r = dict(r)
            n = r.get("node")
            if isinstance(n, str) and n.strip():
                r["node"] = n.strip()
            else:
                r.pop("node", None)
            out.append(r)
        self.data["rules"] = out

    # 已知可写设置键（DEFAULT_SETTINGS 全集，github_mirror 现已并入），永不让外部覆盖 secret。
    # 把这道硬保证放在 store 层，使 CLI/向导/未来任何写入方都继承；webui 仍各自保留用户友好的校验消息。
    _ALLOWED_SETTING_KEYS = set(config_gen.DEFAULT_SETTINGS) - {"secret"}

    def set_settings(self, settings: dict) -> None:
        clean = {k: v for k, v in dict(settings).items() if k in self._ALLOWED_SETTING_KEYS}
        self.data["settings"].update(clean)

    def restore_default_settings(self) -> dict:
        """把「设置」恢复为出厂默认（含存于 settings 的分流预设 presets / 兜底策略 final）。FEAT-3

        刻意保留 clash API 密钥 secret——重置它会让正在运行的 mihomo 与面板用的密钥不一致，
        免重启切换/测速/流量在下次 apply 重启前全部失效，且轮换密钥对“恢复默认”无任何安全收益。
        不触碰 节点 / 订阅 / 路由规则 / 面板访问（端口·地址·密码）：这些不属于「设置」页，
        贸然清掉会误删用户精心配置或把用户锁在面板外。调用方须随后 save()，并 apply 才生效。"""
        secret = self.data.get("settings", {}).get("secret")
        # 深拷贝：默认值里的 list（dns_*/tun_dns_hijack/presets 等）必须是独立对象，
        # 否则面板若原地改写某个 list 会污染模块级 DEFAULT_SETTINGS，殃及随后每一次恢复/新建。
        fresh = copy.deepcopy(config_gen.DEFAULT_SETTINGS)
        fresh["secret"] = secret if isinstance(secret, str) and secret else secrets.token_hex(16)
        self.data["settings"] = fresh
        return fresh

    def set_active(self, node_id: str) -> None:
        self.data["active"] = node_id

    # ---------------------------------------------------------------- 渲染
    def active_node(self) -> dict | None:
        nid = self.data.get("active")
        # active 可能是悬空 id（外部编辑/导入了引用不存在节点的 state）：回落到第一个节点，
        # 否则 get_node 返回 None 会让 status 误显示“当前: 无”、渲染选不到默认出口
        node = self.get_node(nid) if nid else None
        return node or (self.data["nodes"][0] if self.data["nodes"] else None)

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
