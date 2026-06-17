"""状态持久化：节点 / 规则 / 设置，统一存于一个 JSON 文件。

mihomo 的 config.yaml 完全由本状态生成，因此“真相”只有这一个 state.json，
WebUI 与命令行向导都读写它，再调用 config_gen 渲染并 apply。
"""

from __future__ import annotations

import json
import os
import secrets

from . import config_gen

STATE_DIR = os.environ.get("PIHY2_DIR", "/etc/pihy2")
STATE_FILE = os.path.join(STATE_DIR, "state.json")

# 内置的常用直连规则（首次初始化时写入，用户可在面板里增删）
DEFAULT_RULES = [
    {"value": "CN", "policy": "DIRECT", "type": "geoip"},          # 中国大陆 IP 直连
    {"value": "cn", "policy": "DIRECT", "type": "domain-suffix"},  # .cn 域名直连
]


def _new_state() -> dict:
    settings = dict(config_gen.DEFAULT_SETTINGS)
    settings["secret"] = secrets.token_hex(16)       # clash API 密钥
    return {
        "version": 1,
        "nodes": [],          # 每个节点带一个稳定 id
        "rules": list(DEFAULT_RULES),
        "settings": settings,
        "active": "",         # 当前选中的节点 id（空=未选/用第一个）
        "webui": {
            "port": 8088,
            "password": "",   # 空=不鉴权（向导会建议设置）
            "bind": "0.0.0.0",
        },
        "_seq": 0,            # 自增 id 计数
    }


class Store:
    def __init__(self, path: str = STATE_FILE):
        self.path = path
        self.data = self.load()

    # ---------------------------------------------------------------- 读写
    def load(self) -> dict:
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return self._migrate(data)
            except (json.JSONDecodeError, OSError):
                pass
        return _new_state()

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)  # 原子替换，避免写一半损坏

    def _migrate(self, data: dict) -> dict:
        base = _new_state()
        base.update({k: v for k, v in data.items() if k in base})
        # settings/webui 做字段补全，兼容旧版本新增字段
        base["settings"] = {**config_gen.DEFAULT_SETTINGS, **data.get("settings", {})}
        if not base["settings"].get("secret"):
            base["settings"]["secret"] = secrets.token_hex(16)
        base["webui"] = {**_new_state()["webui"], **data.get("webui", {})}
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
