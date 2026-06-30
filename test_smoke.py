#!/usr/bin/env python3
"""pihy2 回归自检：协议解析 / 配置生成 / 脱敏 / YAML / 状态迁移。

零运行时依赖；装有 PyYAML 时额外与其交叉校验生成与解析结果（没有则自动跳过那部分）。
直接运行： python3 test_smoke.py  —— 任一断言失败即以非零退出码结束，便于 CI 捕获。
"""
import base64
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pihy2 import parser, config_gen, yaml_lite, store  # noqa: E402

try:
    import yaml as PYYAML
except ImportError:
    PYYAML = None

FAILS = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else "  FAIL ") + name + ("" if cond else f": {detail}"))
    if not cond:
        FAILS.append(name)


def section(title):
    print("==", title, "==")


# 1. 六协议 parse -> node_to_link -> parse 往返一致
section("protocol round-trip")
_vmess = "vmess://" + base64.b64encode(json.dumps({
    "v": "2", "ps": "m", "add": "v.com", "port": "443", "id": "vmid", "aid": "0",
    "net": "ws", "path": "/wp", "host": "wh", "tls": "tls"}).encode()).decode()
_ss = "ss://" + base64.b64encode(b"aes-256-gcm:sspw").decode() + "@ss.com:8388#s"
LINKS = [
    "hysteria2://p%3Aa%23ss@1.2.3.4:443/?sni=h.com&obfs=salamander&obfs-password=op&insecure=1#nm",
    "vless://uuid@[2001:db8::1]:8443?security=reality&pbk=PB&sid=SS&type=ws&path=/x&host=h.com#v",
    _vmess,
    "trojan://pw@t.com:443?sni=s.com&alpn=h2,http/1.1#tj",
    _ss,
    "tuic://id:pp@tu.com:443?congestion_control=bbr&alpn=h3#tu",
]
for link in LINKS:
    n = parser.parse_link(link)
    n2 = parser.parse_link(parser.node_to_link(n))
    same = (n.get("server") == n2.get("server") and n.get("port") == n2.get("port")
            and n.get("password", "") == n2.get("password", "")
            and n.get("uuid", "") == n2.get("uuid", ""))
    check(f"round-trip {n['type']}", same, f"{n} != {n2}")

# 2. 配置生成对脏数据稳健，且规则值无法注入 YAML 结构
section("config generation")
NODES = [
    {"id": "n1", "type": "hysteria2", "name": 'weird: #n "q\' {b}',
     "server": "1.2.3.4", "port": 443, "password": "p:a#s s/+w@rd"},
    {"id": "n2", "type": "vless", "name": "PROXY", "server": "2001:db8::1", "port": 8443,
     "uuid": "uuidsecretZ", "tls": True, "network": "ws", "ws_path": "/p", "ws_host": "a.com"},
    {"id": "n3", "type": "ss", "name": "AUTO", "server": "e.com", "port": 8388,
     "cipher": "aes-256-gcm", "password": "pw"},
]
RULES = [{"value": "*.cn", "policy": "DIRECT", "type": "auto"},
         {"value": 'evil"\ninjected: true\nrules: [x]', "policy": "PROXY", "type": "domain"}]
SETTINGS = dict(config_gen.DEFAULT_SETTINGS)
SETTINGS["secret"] = "deadbeefcafe"
text = config_gen.render(NODES, RULES, SETTINGS)
check("render returns text", bool(text) and "proxies:" in text)
if PYYAML:
    doc = PYYAML.safe_load(text)
    check("output parses as YAML", isinstance(doc, dict))
    check("no top-level YAML injection", "injected" not in doc)
    check("rules stays a list", isinstance(doc.get("rules"), list))
    check("all 3 proxies present", len(doc.get("proxies", [])) == 3, str(len(doc.get("proxies", []))))
    check("reserved name PROXY renamed", all(p["name"] != "PROXY" for p in doc["proxies"]))
    _h2 = [p for p in doc["proxies"] if p["type"] == "hysteria2"][0]
    check("special-char password intact", _h2["password"] == "p:a#s s/+w@rd", repr(_h2["password"]))

# 3. 脱敏：节点密码/UUID/混淆密码/secret 全部打码且仍是合法 YAML
section("secret redaction")
red = config_gen.redact_secrets(text)
check("password redacted", "p:a#s s/+w@rd" not in red)
check("uuid redacted", "uuidsecretZ" not in red)
check("clash secret redacted", "deadbeefcafe" not in red)
check("mask present", "******" in red)
check("non-secret field intact (server)", "1.2.3.4" in red)
if PYYAML:
    check("redacted still valid YAML", isinstance(PYYAML.safe_load(red), dict))

# 4. yaml_lite 解析 Clash 订阅（嵌套 / 流式映射）与 PyYAML 一致
section("yaml_lite")
CLASH = """proxies:
  - name: a
    type: ss
    server: a.com
    port: 8388
    cipher: aes-256-gcm
    password: "p#1"
  - name: b
    type: vmess
    server: b.com
    port: 443
    uuid: bb
    network: ws
    ws-opts:
      path: /x
      headers: {Host: h.com}
"""
d = yaml_lite.load(CLASH)
check("yaml_lite proxies count", len(d["proxies"]) == 2, str(d))
check("yaml_lite nested header", d["proxies"][1]["ws-opts"]["headers"]["Host"] == "h.com")
ny, ey = parser.parse_clash_yaml(CLASH)
check("parse_clash_yaml nodes", len(ny) == 2, f"{len(ny)} {ey}")
if PYYAML:
    check("yaml_lite agrees with PyYAML", d == PYYAML.safe_load(CLASH), str(d))

# 块标量保留相对缩进（I2 修复点）
BLOCK = "root:\n  text: |\n    line1\n      indented2\n    line3\n"
bd = yaml_lite.load(BLOCK)
check("block scalar keeps relative indent",
      bd["root"]["text"] == "line1\n  indented2\nline3", repr(bd["root"]["text"]))

# 5. 脏 state.json 被非破坏性修复且仍能渲染
section("store migration")
bad = {"nodes": ["x",
                 {"name": 2024, "type": "ss", "server": "a", "port": "443", "id": "n1"},
                 {"type": "ss", "server": "b", "id": "n1"}],
       "settings": "pwned", "webui": ["x"],
       "rules": ["bad", {"value": "a", "policy": "DIRECT"}], "active": "ghost"}
p = tempfile.mktemp()
with open(p, "w") as f:
    f.write(json.dumps(bad))
st = store.Store(p)
os.remove(p)
check("non-dict nodes dropped", all(isinstance(x, dict) for x in st.data["nodes"]))
check("settings repaired to dict", isinstance(st.data["settings"], dict))
check("webui repaired to dict", isinstance(st.data["webui"], dict))
check("secret regenerated", isinstance(st.data["settings"].get("secret"), str)
      and bool(st.data["settings"]["secret"]))
check("node ids unique", len({x["id"] for x in st.data["nodes"]}) == len(st.data["nodes"]))
rt = st.render_config()
check("repaired state renders", "rules:" in rt)
if PYYAML:
    check("repaired render valid YAML", isinstance(PYYAML.safe_load(rt), dict))

# 6. 向导镜像选填：归一 / 校验 / 架构门控（桩掉真实 DNS 与 input，不打网络）
section("wizard mirror prompt")
from pihy2 import wizard, manager as _mgr  # noqa: E402

_orig_resolve, _orig_ask = _mgr._resolve_public, wizard.ask


def _fake_resolve(host):
    if host in ("ghproxy.com", "gh.test"):
        return ["1.2.3.4"]
    raise ValueError("blocked/internal/unresolvable")


def _mirror(seq):
    _it = iter(seq)
    wizard.ask = lambda prompt, default="": next(_it)
    return wizard._ask_mirror("")


def _mirror_real(seq, default):
    # 模拟真实 ask 语义：空输入回落 default（_mirror 的桩忽略 default，故另写一个用于验证“回车=默认”路径）
    _it = iter(seq)
    wizard.ask = lambda prompt, d="": (next(_it) or d)
    return wizard._ask_mirror(default)


_mgr._resolve_public = _fake_resolve
try:
    check("mirror empty -> direct", _mirror([""]) == "")
    check("mirror '-' -> direct", _mirror(["-"]) == "")
    check("mirror bare host -> https", _mirror(["ghproxy.com"]) == "https://ghproxy.com")
    check("mirror http rejected then accepts https",
          _mirror(["http://gh.test", "https://gh.test/"]) == "https://gh.test/")
    check("mirror LAN rejected then direct",
          _mirror(["https://192.168.5.2:2088/", "-"]) == "")
    check("arch gate: arm64 supported, armv7 not",
          "arm64" in _mgr.PINNED_SHA256 and "armv7" not in _mgr.PINNED_SHA256)
    # 重新部署死循环修复：带进来的旧默认镜像失效时，连按回车不再卡死——首次失败即清默认，二次回车=直连
    check("stale default mirror does not trap on enter",
          _mirror_real(["", ""], "https://gh-proxy.org/") == "")
    # 回车保留仍有效的旧默认镜像
    check("valid default mirror kept on enter",
          _mirror_real([""], "https://ghproxy.com/") == "https://ghproxy.com/")
finally:
    _mgr._resolve_public, wizard.ask = _orig_resolve, _orig_ask

# 7. 维护功能：恢复默认设置 / 卸载命令构造 / 运行期自检（FEAT-2/3/4）
section("maintenance features")
from pihy2 import manager as _mgr2  # noqa: E402

# restore_default_settings：重置设置但保留 secret 与节点/规则；结果与 DEFAULT_SETTINGS 一致（除 secret）
_sp = tempfile.mktemp()
_sst = store.Store(_sp)
_sst.add_node({"type": "ss", "name": "x", "server": "a.com", "port": 8388,
               "cipher": "aes-256-gcm", "password": "pw"})
_sst.data["settings"]["mixed_port"] = 1234
_sst.data["settings"]["log_level"] = "debug"
_sst.data["settings"]["github_mirror"] = "https://m.example/"
_old_secret = _sst.data["settings"]["secret"]
_sst.restore_default_settings()
if os.path.exists(_sp):
    os.remove(_sp)
check("restore resets changed setting", _sst.data["settings"]["mixed_port"] == 7890)
check("restore clears mirror", _sst.data["settings"]["github_mirror"] == "")
check("restore keeps clash secret", _sst.data["settings"]["secret"] == _old_secret)
check("restore keeps nodes", len(_sst.data["nodes"]) == 1)
check("restore equals DEFAULT_SETTINGS sans secret",
      {k: v for k, v in _sst.data["settings"].items() if k != "secret"}
      == {k: v for k, v in config_gen.DEFAULT_SETTINGS.items() if k != "secret"})
# 默认值的可变 list 不与模块级 DEFAULT_SETTINGS 共享同一对象（避免原地改写污染下一次恢复）
_sst.data["settings"]["dns_china"].append("8.8.4.4")
check("restore does not alias DEFAULT_SETTINGS lists",
      "8.8.4.4" not in config_gen.DEFAULT_SETTINGS["dns_china"])

# 卸载子进程命令构造：末位带/不带 --purge，且始终含 `-m pihy2 uninstall`
_argv = _mgr2._uninstall_argv(False)
check("uninstall argv has module entry", _argv[1:4] == ["-m", "pihy2", "uninstall"])
check("uninstall argv no purge by default", "--purge" not in _argv)
check("uninstall argv purge appends flag", _mgr2._uninstall_argv(True)[-1] == "--purge")

# self_test：结构完整、状态合法、单项兜底不抛异常（本机通常无 mihomo -> binary 判 fail）
_tp = tempfile.mktemp()
_tst = store.Store(_tp)
_res = _mgr2.self_test(_tst, probe_ip=False)   # probe_ip=False：不打网络，CI 可跑
if os.path.exists(_tp):
    os.remove(_tp)
check("self_test returns non-empty checks", isinstance(_res.get("checks"), list) and bool(_res["checks"]))
check("self_test summary totals match", sum(_res["summary"].values()) == len(_res["checks"]))
check("self_test rows well-formed",
      all({"key", "label", "status", "detail"} <= set(c)
          and c["status"] in ("ok", "warn", "fail", "skip") for c in _res["checks"]))
check("self_test ok flag reflects fails",
      _res["ok"] == (_res["summary"]["fail"] == 0))
check("self_test covers core checks",
      {"binary_installed", "config", "service_active", "egress", "state_perm"}
      <= {c["key"] for c in _res["checks"]})

print()
if FAILS:
    print(f"FAILED ({len(FAILS)}): " + ", ".join(FAILS))
    sys.exit(1)
print("ALL PASS" + ("" if PYYAML else "  (PyYAML absent: cross-checks skipped)"))
