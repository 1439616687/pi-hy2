"""pihy2 基础测试：解析器 + 配置生成器 + （可选）mihomo -t 语法校验。

用法：
    python3 tests/test_basic.py
    MIHOMO=/tmp/mihomo python3 tests/test_basic.py   # 指定 mihomo 二进制做真实语法校验
"""

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pihy2 import parser, config_gen  # noqa: E402

_passed = 0
_failed = 0


def check(name, cond, detail=""):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  \033[32m✓\033[0m {name}")
    else:
        _failed += 1
        print(f"  \033[31m✗ {name}\033[0m  {detail}")


print("== 解析器 ==")

# 1. 标准链接：密码含 %2F、带 sni 与 fragment
n = parser.parse_link(
    "hysteria2://REDACTED@your-node.example.com:443/"
    "?sni=your-node.example.com#%E4%BF%9D%E5%8A%A0%E5%88%A9%E4%BA%9A"
)
check("scheme/host/port", n["server"] == "your-node.example.com" and n["port"] == 443)
check("密码 %2F 还原", n["password"] == "REDACTED", n["password"])
check("sni", n["sni"] == "your-node.example.com")
check("中文节点名还原", n["name"] == "某地区", n["name"])
check("默认 alpn=h3", n["alpn"] == ["h3"])

# 2. hy2:// 简写、insecure、obfs、端口跳跃、无 sni（回退 host）
n2 = parser.parse_link(
    "hy2://passw0rd@1.2.3.4:8443?insecure=1&obfs=salamander&obfs-password=ob123&mport=8443-9000#x"
)
check("hy2:// 简写", n2["server"] == "1.2.3.4" and n2["port"] == 8443)
check("insecure -> skip_cert_verify", n2["skip_cert_verify"] is True)
check("obfs", n2["obfs"] == "salamander" and n2["obfs_password"] == "ob123")
check("端口跳跃 mport", n2["ports"] == "8443-9000")
check("无 sni 回退到 host", n2["sni"] == "1.2.3.4")

# 3. 缺省端口 = 443
n3 = parser.parse_link("hysteria2://pw@example.com#noport")
check("缺省端口 443", n3["port"] == 443)

# 4. 多行 + 非法行混合
nodes, errs = parser.parse_many(
    "hysteria2://a@h1.com:443#n1\n"
    "# 注释行\n"
    "vmess://should-be-skipped\n"
    "hy2://b@h2.com:443#n2\n"
)
check("多行解析出 2 个节点", len(nodes) == 2, str([x["name"] for x in nodes]))
check("非法行被记录", any("vmess" in e for e in errs))

# 5. base64 订阅
import base64 as _b64
sub = _b64.b64encode(b"hysteria2://a@h1.com:443#sub1\nhy2://b@h2.com:443#sub2").decode()
nodes_b, _ = parser.parse_many(sub)
check("base64 订阅解码", len(nodes_b) == 2)

# 6. 反向导出再解析，关键字段一致（round-trip）
link = parser.node_to_link(n2)
n2b = parser.parse_link(link)
check("round-trip 密码一致", n2b["password"] == n2["password"], link)
check("round-trip 端口跳跃一致", n2b["ports"] == n2["ports"])

# 7. 报错：非 hy2 链接
try:
    parser.parse_link("ss://xxx")
    check("非 hy2 报错", False)
except parser.ParseError:
    check("非 hy2 报错", True)

# 8. 安全回归：pinSHA256 不能污染 fingerprint（base64 公钥固定会让 mihomo 启动失败）
pin = parser.parse_link("hysteria2://pw@h.com:443?pinSHA256=sha256%2FAAAA%3D%3D#x")
check("base64 pin 不进 fingerprint", pin["fingerprint"] == "" and pin["pin_sha256"].startswith("sha256/"))
hexpin = parser.parse_link("hysteria2://pw@h.com:443?pinSHA256="
                           "47de42a98fc1c149afbf4c89996fb9249cee41e4649b934ca495991b7852b855#x")
check("hex 指纹保留为 fingerprint", len(hexpin["fingerprint"]) == 64 and hexpin["pin_sha256"] == "")

# 9. 安全回归：query 形式密码里的 '+' 不被吃成空格
qp = parser.parse_link("hysteria2://h.com:443?auth=AB%2BCD#x")
check("query 密码 + 不丢", qp["password"] == "AB+CD", qp["password"])


print("== 多协议解析 ==")
import base64 as _b
import json as _json
_uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
proto_links = {
    "vless": (f"vless://{_uuid}@v.com:443?security=tls&type=ws&sni=v.com&path=%2Fws&host=v.com#V", "vless"),
    "vmess": ("vmess://" + _b.b64encode(
        b'{"v":"2","ps":"M","add":"m.com","port":"443","id":"' + _uuid.encode()
        + b'","aid":"0","net":"ws","path":"/p","tls":"tls"}').decode(), "vmess"),
    "trojan": ("trojan://tjpw@t.com:443?sni=t.com#T", "trojan"),
    "ss": ("ss://" + _b.b64encode(b"aes-256-gcm:sspw").decode() + "@s.com:8388#S", "ss"),
    "tuic": ("tuic://uu:pw@u.com:443?sni=u.com&alpn=h3#U", "tuic"),
}
proto_nodes = []
for label, (lnk, exp_type) in proto_links.items():
    nd = parser.parse_link(lnk)
    proto_nodes.append(nd)
    check(f"{label} 解析", nd["type"] == exp_type and nd["server"].endswith(".com"), str(nd.get("type")))
check("vless 解析出 ws 传输与 UUID", proto_nodes[0]["network"] == "ws" and proto_nodes[0]["uuid"] == _uuid)
check("vmess 解析出 UUID/网络", proto_nodes[1]["uuid"] == _uuid and proto_nodes[1]["network"] == "ws")
check("ss 解析出 cipher/password", proto_nodes[3]["cipher"] == "aes-256-gcm" and proto_nodes[3]["password"] == "sspw")
# round-trip 导出不崩、凭据保留
for nd in proto_nodes:
    back = parser.parse_link(parser.node_to_link(nd))
    cred_a = nd.get("password") or nd.get("uuid")
    cred_b = back.get("password") or back.get("uuid")
    check(f"{nd['type']} round-trip 凭据", cred_a == cred_b and back["server"] == nd["server"])

# 健壮性回归：vmess 脏数据(port/aid/alpn)不崩，且不拖垮同批其他节点
_bad_vm = "vmess://" + _b.b64encode(_json.dumps(
    {"add": "h.com", "port": "80x", "id": _uuid, "aid": "abc", "net": "ws", "alpn": 123}).encode()).decode()
vbad, _ = parser.parse_many(_bad_vm + "\nhysteria2://pw@1.2.3.4:443#good")
check("vmess 脏数据不拖垮同批", any(x["name"] == "good" for x in vbad))
_vt = parser.parse_link(_bad_vm)
check("vmess 非法 port/aid 回落默认", _vt["port"] == 443 and _vt["alter_id"] == 0)
# httpupgrade 保留 path/host
_hu = parser.parse_link("vless://" + _uuid + "@h.com:443?security=tls&type=httpupgrade&path=%2Fhu&host=h.com#HU")
check("httpupgrade 保留传输", _hu["network"] == "httpupgrade" and _hu["ws_path"] == "/hu")
# SS plugin 导出不丢
_ssp = parser.parse_link("ss://" + _b.b64encode(b"aes-256-gcm:pw").decode() + "@s.com:8388?plugin=obfs-local;obfs=http;obfs-host=cf.com#S")
_ssb = parser.parse_link(parser.node_to_link(_ssp))
check("SS plugin round-trip 不丢", _ssb.get("plugin") == "obfs" and _ssb.get("plugin_opts", {}).get("host") == "cf.com")
# vless 仅 pbk 也按 reality
_rl = parser.parse_link("vless://" + _uuid + "@h.com:443?type=grpc&pbk=ABC&sid=01&serviceName=s#R")
check("reality 仅 pbk 也识别", _rl["tls"] and _rl.get("reality_pbk") == "ABC")


print("== Clash YAML 订阅 ==")
_clash = '''
proxies:
  - {name: "香港", type: ss, server: a.com, port: 8388, cipher: aes-256-gcm, password: "p@ss"}
  - name: VM
    type: vmess
    server: b.com
    port: 443
    uuid: ''' + _uuid + '''
    alterId: 0
    network: ws
    tls: true
    servername: b.com
    ws-opts:
      path: /vm
      headers:
        Host: b.com
  - name: WG
    type: wireguard
    server: e.com
    port: 51820
'''
_yn, _ye = parser.parse_many(_clash)        # parse_many 自动识别 YAML
check("Clash YAML 解析出节点", len(_yn) == 2 and _yn[0]["type"] == "ss", str([n["type"] for n in _yn]))
check("YAML 中文名/特殊密码", _yn[0]["name"] == "香港" and _yn[0]["password"] == "p@ss")
check("YAML 嵌套 ws-opts", _yn[1]["network"] == "ws" and _yn[1]["ws_path"] == "/vm" and _yn[1]["ws_host"] == "b.com")
check("YAML 跳过不支持协议", any("wireguard" in e for e in _ye))
check("base64-of-YAML 也识别", len(parser.parse_many(_b.b64encode(_clash.encode()).decode())[0]) == 2)
# YAML 转出的配置可通过 mihomo -t（若提供二进制）—— 放到下方统一校验
_yaml_nodes = _yn


print("== 规则判别 ==")
cases = [
    (("*.cn", "auto"), ("DOMAIN-SUFFIX", "cn")),
    (("google.com", "auto"), ("DOMAIN-SUFFIX", "google.com")),
    (("netflix", "auto"), ("DOMAIN-KEYWORD", "netflix")),
    (("ex*ple.com", "auto"), ("DOMAIN-WILDCARD", "ex*ple.com")),
    (("1.1.1.1", "auto"), ("IP-CIDR", "1.1.1.1/32")),
    (("10.0.0.0/8", "auto"), ("IP-CIDR", "10.0.0.0/8")),
    (("CN", "geoip"), ("GEOIP", "CN")),
    ((".github.io", "auto"), ("DOMAIN-SUFFIX", "github.io")),
]
for (val, typ), expect in cases:
    got = config_gen.classify_rule(val, typ)
    check(f"{val} ({typ}) -> {expect[0]}", got == expect, str(got))


print("== 配置生成 ==")
nodes = [n, n2]
# 刻意不放 GEOIP/GEOSITE，保证 mihomo -t 离线也能过（不触发地理库下载）
rules = [
    {"value": "*.cn", "policy": "DIRECT", "type": "auto"},
    {"value": "baidu.com", "policy": "DIRECT", "type": "auto"},
    {"value": "openai.com", "policy": "PROXY", "type": "auto"},
    {"value": "1.2.3.0/24", "policy": "DIRECT", "type": "auto"},
]
settings = dict(config_gen.DEFAULT_SETTINGS)
settings["secret"] = "testsecret"
text = config_gen.render(nodes, rules, settings)
check("含 proxies", '"hysteria2"' in text)
check("含 PROXY 策略组", '"PROXY"' in text)
check("含 AUTO 测速组（多节点）", '"AUTO"' in text)
check("私有网段安全直连在前", text.index("192.168.0.0/16") < text.index("openai.com"))
check("密码被正确引号包裹", '"REDACTED"' in text)
check("中文节点名保留", "某地区" in text)

# 非 hex 的 fingerprint 必须被丢弃（否则 mihomo 启动报错）
bad_fp_node = dict(n); bad_fp_node["fingerprint"] = "sha256/AAAA=="
check("非 hex fingerprint 被丢弃", "fingerprint" not in config_gen.render([bad_fp_node], [], settings))

# 默认规则不含 GEOIP/GEOSITE（首次部署不依赖联网下载地理库）
from pihy2.store import DEFAULT_RULES
check("默认规则不依赖地理库",
      all(r["type"] not in ("geoip", "geosite") for r in DEFAULT_RULES))

# 一键分流预设：展开顺序（拦截在前、直连在后）+ 去重
pl = config_gen.expand_presets(["cn_direct", "ads", "ads"])
check("预设展开 ads 在前", pl and pl[0] == "GEOSITE,category-ads-all,REJECT", str(pl[:1]))
check("预设展开 cn_direct 在后", pl and pl[-1] == "GEOIP,CN,DIRECT", str(pl[-1:]))
check("预设去重", pl.count("GEOSITE,category-ads-all,REJECT") == 1)
# 零节点时，引用 PROXY 的用户规则/预设都不应出现（否则 mihomo 报未知策略组）
t0 = config_gen.render([], [{"value": "x.com", "policy": "PROXY", "type": "auto"}],
                       dict(config_gen.DEFAULT_SETTINGS, presets=["ads"]))
check("零节点不泄漏 PROXY 规则/预设", "GEOSITE" not in t0 and "x.com" not in t0 and "MATCH,DIRECT" in t0)
# 有节点时预设进入配置
tp = config_gen.render([n], [], dict(config_gen.DEFAULT_SETTINGS, secret="x", presets=["ads"]))
check("启用预设后含对应规则", "GEOSITE,category-ads-all,REJECT" in tp)

# 全屋网关模式 -> allow-lan
g_off = config_gen.render([n], [], dict(config_gen.DEFAULT_SETTINGS, secret="x", gateway_mode=False))
g_on = config_gen.render([n], [], dict(config_gen.DEFAULT_SETTINGS, secret="x", gateway_mode=True))
check("网关关 -> allow-lan: false", "allow-lan: false" in g_off)
check("网关开 -> allow-lan: true", "allow-lan: true" in g_on)

# mihomo -t 真实语法校验（若提供二进制）
mihomo = os.environ.get("MIHOMO")
if mihomo and os.path.exists(mihomo):
    print("== mihomo -t 语法校验 ==")
    d = tempfile.mkdtemp(prefix="pihy2-test-")
    with open(os.path.join(d, "config.yaml"), "w") as f:
        f.write(text)
    # 单节点也测一遍（策略组分支不同）
    text1 = config_gen.render([n], rules, settings)
    d1 = tempfile.mkdtemp(prefix="pihy2-test1-")
    with open(os.path.join(d1, "config.yaml"), "w") as f:
        f.write(text1)
    # 零节点（兜底 DIRECT）也测
    text0 = config_gen.render([], [], settings)
    d0 = tempfile.mkdtemp(prefix="pihy2-test0-")
    with open(os.path.join(d0, "config.yaml"), "w") as f:
        f.write(text0)
    # 多协议混合（vless/vmess/trojan/ss/tuic + hy2）
    textp = config_gen.render([n] + proto_nodes, [], settings)
    dp = tempfile.mkdtemp(prefix="pihy2-testp-")
    with open(os.path.join(dp, "config.yaml"), "w") as f:
        f.write(textp)
    # Clash YAML 订阅转出的节点
    texty = config_gen.render(_yaml_nodes, [], settings)
    dy = tempfile.mkdtemp(prefix="pihy2-testy-")
    with open(os.path.join(dy, "config.yaml"), "w") as f:
        f.write(texty)
    for label, folder in (("多节点", d), ("单节点", d1), ("零节点", d0),
                          ("多协议混合", dp), ("ClashYAML转出", dy)):
        r = subprocess.run([mihomo, "-d", folder, "-t"], capture_output=True, text=True)
        ok = r.returncode == 0 and "test is successful" in (r.stdout + r.stderr)
        check(f"{label}配置通过 mihomo -t", ok, (r.stdout + r.stderr).strip()[-300:])
else:
    print("== 跳过 mihomo -t（未设置 MIHOMO 环境变量）==")

print()
print(f"通过 {_passed}，失败 {_failed}")
sys.exit(1 if _failed else 0)
