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

# 2b. 链式代理：http/socks5 经 dialer-proxy 挂在前置节点后；前置缺失则跳过
section("chained proxy (dialer-proxy)")
_CHAIN = [
    {"id": "n1", "type": "hysteria2", "name": "relay", "server": "r.com", "port": 443, "password": "p"},
    {"id": "n2", "type": "socks5", "name": "home-exit", "server": "10.0.0.9", "port": 1080,
     "username": "u", "password": "pw", "dialer_proxy": "n1"},
    {"id": "n3", "type": "http", "name": "home-http", "server": "10.0.0.10", "port": 8080,
     "tls": True, "dialer_proxy": "n1"},
    {"id": "n4", "type": "socks5", "name": "dangling", "server": "10.0.0.11", "port": 1080,
     "dialer_proxy": "ghost"},   # 前置不存在 -> 应被跳过
    {"id": "n5", "type": "socks5", "name": "no-front", "server": "10.0.0.12", "port": 1080},  # 缺前置 -> 跳过
]
_ctext = config_gen.render(_CHAIN, [], dict(config_gen.DEFAULT_SETTINGS, secret="x"))
check("chain render has proxies", "proxies:" in _ctext)
check("dialer-proxy emitted in text", "dialer-proxy:" in _ctext)
# 出口节点的 password 在预览/打印时同样脱敏（redact_secrets 按行匹配 password: 键，覆盖 http/socks5）
check("socks5 exit password redacted", "pw" not in config_gen.redact_secrets(_ctext))
if PYYAML:
    _cdoc = PYYAML.safe_load(_ctext)
    _byname = {p["name"]: p for p in _cdoc["proxies"]}
    check("socks5 exit emitted", _byname.get("home-exit", {}).get("type") == "socks5")
    check("http exit emitted", _byname.get("home-http", {}).get("type") == "http")
    check("dialer-proxy resolves to front display name",
          _byname.get("home-exit", {}).get("dialer-proxy") == "relay", str(_byname.get("home-exit")))
    check("dangling-front chain node skipped", "dangling" not in _byname, str(list(_byname)))
    check("missing-front chain node skipped", "no-front" not in _byname, str(list(_byname)))
    check("front relay node still present", "relay" in _byname)
# node_to_link 对 http/socks5 抛错（无分享链接格式）-> 导出跳过
_ne = False
try:
    parser.node_to_link({"type": "socks5", "name": "x", "server": "s", "port": 1080})
except parser.ParseError:
    _ne = True
check("node_to_link refuses http/socks5", _ne)

# 2c. dialer-proxy 引用的显示名必须与 display_names()（面板 clash API 切换/测速用的名字）一致：
# 前置节点名被去重时（两个 relay -> relay / relay #2）渲染端与 API 端仍要对齐，
# 否则面板会按不存在的名字去切换/测速。这是链式代理可用性的关键不变量。
_DEDUP = [
    {"id": "f1", "type": "hysteria2", "name": "relay", "server": "a.com", "port": 443, "password": "p"},
    {"id": "f2", "type": "hysteria2", "name": "relay", "server": "b.com", "port": 443, "password": "p"},
    {"id": "c1", "type": "socks5", "name": "exit", "server": "10.0.0.9", "port": 1080, "dialer_proxy": "f2"},
]
_dn = config_gen.display_names(_DEDUP)
if PYYAML:
    _ddoc = PYYAML.safe_load(config_gen.render(_DEDUP, [], dict(config_gen.DEFAULT_SETTINGS, secret="x")))
    _exitp = next(p for p in _ddoc["proxies"] if p["type"] == "socks5")
    check("dialer-proxy matches display_names under dedup",
          _exitp.get("dialer-proxy") == _dn.get("f2") == "relay #2",
          str((_exitp.get("dialer-proxy"), _dn.get("f2"))))

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
      {"binary_installed", "config", "service_active", "egress", "state_perm", "logs", "udp_guard", "geodata"}
      <= {c["key"] for c in _res["checks"]})

# 8. v1.1 加固与可观测性：DNS 显式 ipv6 / respect-rules / redact username /
#    日志(scrub+read_logs) / 去重顺序无关 / 订阅 last_error
section("v1.1 hardening & observability")
from pihy2 import log as _logmod  # noqa: E402

# DNS 段显式 ipv6 跟随顶层；respect-rules 默认关、开启才下发
_d = config_gen.build_config(
    [{"id": "n1", "type": "hysteria2", "name": "x", "server": "1.1.1.1", "port": 443, "password": "p"}],
    [], dict(config_gen.DEFAULT_SETTINGS, secret="x"))
check("dns ipv6 explicit follows top", _d["dns"].get("ipv6") is False)
check("respect-rules omitted by default", "respect-rules" not in _d["dns"])
check("respect-rules emitted when on",
      config_gen.build_config([], [], dict(config_gen.DEFAULT_SETTINGS, secret="x",
                                          dns_respect_rules=True))["dns"].get("respect-rules") is True)

# redact 覆盖 http/socks5 出口的 username（链式出口半敏感凭据）
_red2 = config_gen.redact_secrets(config_gen.render([
    {"id": "n1", "type": "socks5", "name": "exit", "server": "10.0.0.9", "port": 1080,
     "username": "secretuser", "password": "pw", "dialer_proxy": "n0"},
    {"id": "n0", "type": "hysteria2", "name": "front", "server": "f.com", "port": 443, "password": "fp"},
], [], dict(config_gen.DEFAULT_SETTINGS, secret="x")))
check("socks5 username redacted", "secretuser" not in _red2)

# 链式 dialer-proxy 引用的显示名与输入顺序无关（_dedup_names 按稳定 id 编号）：
# 打乱顺序，f2 恒为 "relay #2"，c1 的前置仍解析到它（面板切换/测速不会命中错节点）
_or_a = [
    {"id": "f1", "type": "hysteria2", "name": "relay", "server": "a.com", "port": 443, "password": "p"},
    {"id": "f2", "type": "hysteria2", "name": "relay", "server": "b.com", "port": 443, "password": "p"},
    {"id": "c1", "type": "socks5", "name": "exit", "server": "10.0.0.9", "port": 1080, "dialer_proxy": "f2"},
]
_dn_a, _dn_b = config_gen.display_names(_or_a), config_gen.display_names(list(reversed(_or_a)))
check("dedup name order-independent (f2)", _dn_a.get("f2") == _dn_b.get("f2") == "relay #2")

# 订阅 last_error：失败记录、成功清空、迁移补默认
_sp2 = tempfile.mktemp()
_st2 = store.Store(_sp2)
_sub = _st2.add_subscription("s", "https://x.invalid/y")
_st2.mark_subscription_error(_sub["id"], "拉取超时")
_st2.save()
check("sub last_error recorded", store.Store(_sp2).get_subscription(_sub["id"])["last_error"] == "拉取超时")
_st3 = store.Store(_sp2)
_st3.set_subscription_nodes(_sub["id"], [{"type": "ss", "name": "z", "server": "z.com", "port": 8388,
                                          "cipher": "aes-256-gcm", "password": "p"}])
check("sub last_error cleared on success", _st3.get_subscription(_sub["id"])["last_error"] == "")
os.remove(_sp2)
_sp3 = tempfile.mktemp()
with open(_sp3, "w") as _f:
    json.dump({"nodes": [], "subscriptions": [{"id": "s1", "name": "old", "url": "u", "count": 0, "updated": ""}]}, _f)
check("migrate backfills last_error", "last_error" in store.Store(_sp3).data["subscriptions"][0])
os.remove(_sp3)

# 日志：scrub 已知密钥；read_logs 读取/过滤；setup 不可写时不崩（写到可写临时文件）
_tmplog = tempfile.mktemp(suffix=".log")
_logmod.setup_logging("DEBUG", _tmplog)
_lg = _logmod.get_logger("test")
_lg.warning("probe password=hunter2 uuid=abc")
_lg.error("plain marker-XYZ line")
_logmod.setup_logging("DEBUG", _tmplog)   # 幂等：第二次不应重复挂 handler
with open(_tmplog, "r", encoding="utf-8") as _f:
    _raw = _f.read()
check("log scrubs secret values", "hunter2" not in _raw and "abc" not in _raw)
check("log keeps non-secret text", "marker-XYZ" in _raw)
check("read_logs level filter", any("marker-XYZ" in _l for _l in _logmod.read_logs(0, "ERROR"))
      and not any("probe" in _l for _l in _logmod.read_logs(0, "ERROR")))
check("read_logs grep filter", any("marker-XYZ" in _l for _l in _logmod.read_logs(0, "", "marker-XYZ")))
os.remove(_tmplog)

# 9. v1.2 性能 + UDP 安全
section("v1.2 perf & udp safety")
_S2 = dict(config_gen.DEFAULT_SETTINGS, secret="x")
_N2 = [
    {"id": "n1", "type": "hysteria2", "name": "h", "server": "1.1.1.1", "port": 443, "password": "p"},
    {"id": "n2", "type": "vless", "name": "v", "server": "2.2.2.2", "port": 443, "uuid": "u"},
    {"id": "n3", "type": "vmess", "name": "m", "server": "3.3.3.3", "port": 443, "uuid": "u"},
    {"id": "n4", "type": "ss", "name": "s", "server": "4.4.4.4", "port": 8388,
     "cipher": "aes-256-gcm", "password": "p"},
]
_cfg2 = config_gen.build_config(_N2, [], _S2)
check("tcp-concurrent emitted", _cfg2.get("tcp-concurrent") is True)
check("keep-alive-interval emitted", _cfg2.get("keep-alive-interval") == 30)
check("keep-alive-idle emitted", _cfg2.get("keep-alive-idle") == 600)
_auto = config_gen.build_config(_N2, [], dict(_S2, auto_interval=120, auto_tolerance=10))
_ag = [g for g in _auto["proxy-groups"] if g["name"] == "AUTO"][0]
check("AUTO interval configurable", _ag["interval"] == 120)
check("AUTO tolerance configurable", _ag["tolerance"] == 10)
check("mux absent by default", all("mux" not in p for p in _cfg2["proxies"]))
_vm = [p for p in config_gen.build_config(_N2, [], dict(_S2, mux_enabled=True))["proxies"]
       if p["type"] == "vmess"][0]
check("mux emitted when on", _vm.get("mux") is True and "mux-opts" in _vm)
_by = {p["type"]: p for p in _cfg2["proxies"]}
check("vless udp default true", _by["vless"].get("udp") is True)
check("hysteria2 has no udp field", "udp" not in _by["hysteria2"])
_nby = {p["type"]: p for p in config_gen.build_config(_N2, [], dict(_S2, disable_proxy_udp=True))["proxies"]}
check("force-tcp disables vless udp", _nby["vless"].get("udp") is False)
check("force-tcp disables ss udp", _nby["ss"].get("udp") is False)
check("force-tcp leaves hy2 untouched", "udp" not in _nby["hysteria2"])
_ndudp = config_gen.build_config(
    [{"id": "x", "type": "vless", "name": "x", "server": "9.9.9.9", "port": 443, "uuid": "u", "udp": False}],
    [], _S2)
check("node-level udp:false respected", _ndudp["proxies"][0].get("udp") is False)
check("normalize coerces udp string false", parser.normalize_node({"type": "vless", "udp": "false"}).get("udp") is False)
check("normalize coerces udp string 1", parser.normalize_node({"type": "vless", "udp": "1"}).get("udp") is True)

# 10. v1.3 可运维性：备份/恢复、更新、告警、地理库自检
section("v1.3 operability")
# 备份/恢复往返（隔离临时路径）；恢复经 _migrate 清洗，脏备份（非对象）被拒
_sp4 = tempfile.mktemp()
_st4 = store.Store(_sp4)
_st4.add_node({"type": "ss", "name": "bk", "server": "bk.com", "port": 8388,
               "cipher": "aes-256-gcm", "password": "p"})
_st4.data["settings"]["mixed_port"] = 9999
_st4.save()
_bk = _mgr2.backup_state(_sp4)
check("backup returns full state", isinstance(_bk, dict) and _bk.get("settings", {}).get("mixed_port") == 9999)
_okr, _msgr = _mgr2.restore_state(_bk, _sp4)
check("restore ok with counts", _okr and "已恢复" in _msgr)
_okbad, _ = _mgr2.restore_state(["not", "a", "dict"], _sp4)
check("restore rejects non-dict backup", not _okbad)
os.remove(_sp4)
# 更新：no-op 返回 ok；非 git 安装目录被识别（不触发真实 git/下载）
_oku, _msgu = _mgr2.update_pihy2(mihomo=False, code=False)
check("update no-op ok", _oku and "更新完成" in _msgu)
_okc, _msgc = _mgr2.update_pihy2(mihomo=False, code=True)
check("update detects non-git dir", _okc and "git" in _msgc)
# 告警：无 webhook / 内网 webhook / 非 http(s) webhook 都不抛（SSRF 在发送期拦）
_mgr2.notify({}, "t", "m")
_mgr2.notify({"webhook_url": "http://127.0.0.1:9/x"}, "t", "m")
_mgr2.notify({"webhook_url": "ftp://x"}, "t", "m")
check("notify never raises", True)

# 11. v1.3.1 审计修复：scrub URL/bearer 脱敏（H1/H3）+ 新端点鉴权/host 守卫集成测试（L1）
section("v1.3.1 audit fixes")
check("scrub strips URL userinfo", "mypass123" not in _logmod._scrub("fail https://u:mypass123@h/x"))
check("scrub redacts Authorization bearer", "eyJabc" not in _logmod._scrub("Authorization: Bearer eyJabc.def"))
check("scrub still redacts KV", "sekret" not in _logmod._scrub("password=sekret"))

import threading
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
import pihy2.store as _sm
import pihy2.webui as _w
_RealStore = _sm.Store


def _req(method, path, port, headers=None, body=None):
    h = {"X-Requested-With": "pihy2"}
    if headers:
        h.update(headers)
    data, url = None, f"http://127.0.0.1:{port}{path}"
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _serve(sp):
    _sm.Store = lambda path=None: _RealStore(sp)
    _w.Store = _sm.Store
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _w.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# A. 设了密码：新端点须鉴权
_spA = tempfile.mktemp()
_stA = _RealStore(_spA)
_stA.data["webui"]["password"] = "testpw"
_stA.save()
srvA = _serve(_spA)
portA = srvA.server_address[1]
try:
    check("authinfo public", _req("GET", "/api/authinfo", portA)[0] == 200)
    check("syslogs requires auth", _req("GET", "/api/syslogs", portA)[0] == 401)
    check("backup requires auth", _req("GET", "/api/backup", portA)[0] == 401)
    st, b = _req("POST", "/api/login", portA, body={"password": "testpw"})
    token = json.loads(b).get("token", "") if st == 200 else ""
    check("login works", st == 200 and bool(token))
    check("syslogs ok with token", _req("GET", "/api/syslogs", portA, {"Authorization": "Bearer " + token})[0] == 200)
    st, b = _req("GET", "/api/backup", portA, {"Authorization": "Bearer " + token})
    check("backup ok with token", st == 200 and "state" in b)
    st, b = _req("POST", "/api/restore", portA, {"Authorization": "Bearer " + token},
                 body={"state": _RealStore(_spA).data})
    check("restore ok with token", st == 200)
finally:
    srvA.shutdown(); srvA.server_close()
    _sm.Store = _RealStore; _w.Store = _RealStore
    if os.path.exists(_spA):
        os.remove(_spA)

# B. 未设密码 + 域名 Host：rebinding 守卫拒绝；本机 IP 放行
_spB = tempfile.mktemp()
_RealStore(_spB).save()   # password 空
srvB = _serve(_spB)
portB = srvB.server_address[1]
try:
    check("rebinding host rejected (no pw)", _req("GET", "/api/state", portB, {"Host": "evil.attacker.com"})[0] == 403)
    check("localhost host allowed (no pw)", _req("GET", "/api/state", portB)[0] == 200)
finally:
    srvB.shutdown(); srvB.server_close()
    _sm.Store = _RealStore; _w.Store = _RealStore
    if os.path.exists(_spB):
        os.remove(_spB)

# 12. v1.3.2 第二轮审计修复：scrub 绕过(A1/A2/A4/A8) + 悬空 dialer-proxy(A3) + 恶意 id(A5)
section("v1.3.2 second-audit fixes")
_scr = _logmod._scrub
check("scrub @ in password (A2)", "ss" not in _scr("https://user:p@ss@sub.host/x") and "user:p" not in _scr("https://user:p@ss@sub.host/x"))
check("scrub keeps @ in query (A2 no false+)", "a@b.com" in _scr("GET https://example.com/p?email=a@b.com"))
check("scrub dict repr auth (A1)", "dXNlcjpwYXNz" not in _scr("{'authorization': 'Basic dXNlcjpwYXNz'}"))
check("scrub json repr auth (A1)", "abc.def.ghi" not in _scr('{"Authorization": "Token abc.def.ghi"}'))
check("scrub quoted bare value (A4)", "secret123" not in _scr("ValueError: node password 'secret123' invalid"))
check("scrub no false+ on prose (A4)", "required" in _scr("the password is required"))
check("scrub *_token keys (A8)", "abc123" not in _scr("api_token: abc123") and "xyz" not in _scr("?csrf_token=xyz"))

# A3：前置 build 抛异常被跳过 → 引用它的链式节点一并跳过（不下发悬空 dialer-proxy）
_orig_h2 = config_gen._proxy_hysteria2
config_gen._PROXY_BUILDERS["hysteria2"] = lambda node, settings: (_ for _ in ()).throw(RuntimeError("forced"))
try:
    _a3 = config_gen.build_config([
        {"id": "f1", "type": "hysteria2", "name": "front", "server": "f.com", "port": 443, "password": "p"},
        {"id": "c1", "type": "socks5", "name": "exit", "server": "10.0.0.9", "port": 1080, "dialer_proxy": "f1"},
    ], [], dict(config_gen.DEFAULT_SETTINGS, secret="x"))
    check("dangling-front chain dropped (A3)",
          "exit" not in {p["name"] for p in _a3.get("proxies", [])})
finally:
    config_gen._PROXY_BUILDERS["hysteria2"] = _orig_h2

# A5：恶意备份 id（含引号/括号）经 _migrate 重发为安全模式，挡住 inline onclick XSS
_sp5 = tempfile.mktemp()
with open(_sp5, "w") as _f:
    json.dump({"nodes": [{"id": "x');evil//", "type": "ss", "name": "bad", "server": "b.com", "port": 8388,
                          "cipher": "aes-256-gcm", "password": "p"}],
               "subscriptions": [{"id": "s';x//", "name": "sub", "url": "u", "count": 0, "updated": ""}]}, _f)
_mig = store.Store(_sp5).data
os.remove(_sp5)
check("malicious node id reissued (A5)",
      all(store._SAFE_ID_RE.match(str(n["id"])) for n in _mig["nodes"]) and _mig["nodes"][0]["id"] != "x');evil//")
check("malicious sub id reissued (A5)",
      all(store._SAFE_ID_RE.match(str(s["id"])) for s in _mig["subscriptions"]))

print()
if FAILS:
    print(f"FAILED ({len(FAILS)}): " + ", ".join(FAILS))
    sys.exit(1)
print("ALL PASS" + ("" if PYYAML else "  (PyYAML absent: cross-checks skipped)"))
