"""交互式命令行向导：跟着提示填/选，一步步完成首次部署。

流程：检查环境 → 粘贴 hy2 节点 → 默认带宽 → 路由偏好 → WebUI 端口/密码
      → 准备 TUN → 安装 mihomo → 生成并校验配置 → 建服务并启动 → 验证出口 IP。
"""

from __future__ import annotations

import secrets
import sys

from . import manager, parser
from .store import Store, state_lock

C_TITLE = "\033[1;36m"
C_OK = "\033[32m"
C_WARN = "\033[33m"
C_ERR = "\033[31m"
C_DIM = "\033[2m"
C_END = "\033[0m"


def _p(msg=""):
    print(msg)


def title(msg):
    _p(f"\n{C_TITLE}== {msg} =={C_END}")


def ask(prompt: str, default: str = "") -> str:
    # EOFError 不吞掉，交给 run_wizard 顶层做“干净退出”，避免 stdin 关闭时死循环
    hint = f" [{default}]" if default else ""
    val = input(f"{prompt}{hint}: ").strip()
    return val or default


def ask_yn(prompt: str, default: bool = True) -> bool:
    d = "Y/n" if default else "y/N"
    val = ask(f"{prompt} ({d})").lower()
    if not val:
        return default
    return val in ("y", "yes", "是", "1")


def read_links() -> str:
    _p("粘贴一个或多个节点分享链接（每行一个，支持 hysteria2/vless/vmess/trojan/ss/tuic；")
    _p("也支持 base64 订阅内容）。粘贴完成后按回车进入空行结束：")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == "" and lines:
            break
        if line.strip():
            lines.append(line)
    return "\n".join(lines)


def show_nodes(nodes: list[dict]):
    for i, n in enumerate(nodes, 1):
        extra = []
        if n.get("obfs"):
            extra.append(f"混淆={n['obfs']}")
        if n.get("ports"):
            extra.append(f"端口跳跃={n['ports']}")
        if n.get("skip_cert_verify"):
            extra.append("跳过证书校验")
        tail = ("  " + C_DIM + " ".join(extra) + C_END) if extra else ""
        _p(f"  {i}. {C_OK}{n['name']}{C_END}  {n['server']}:{n['port']}{tail}")


def run_wizard():
    try:
        _run_wizard()
    except (EOFError, KeyboardInterrupt):
        _p(f"\n{C_WARN}已取消（输入结束）。可随时重跑：sudo pihy2 install{C_END}")
        sys.exit(130)


def _run_wizard():
    title("树莓派 hy2 全局代理 · 一键部署向导")

    if not manager.is_root():
        _p(f"{C_ERR}请用 root 运行：sudo python3 -m pihy2 install{C_END}")
        sys.exit(1)

    store = Store()
    if store.data["nodes"]:
        _p(f"{C_WARN}检测到已有 {len(store.data['nodes'])} 个节点配置。{C_END}")
        if not ask_yn("继续将向导添加新节点（不会删除现有），是否继续？", True):
            return

    # ---- 1. 节点 ----
    title("第 1 步 / 添加节点")
    # 1a. 可选：先加订阅地址（之后会定时自动更新）
    if ask_yn("有订阅地址吗？填了会定时自动更新（没有就跳过）", False):
        url = ask("订阅 URL")
        if url:
            sub = store.add_subscription(ask("给这个订阅起个名字", "我的订阅"), url)
            _p(f"  {C_DIM}正在拉取订阅…{C_END}")
            cnt, errs = manager.refresh_subscription(store, sub["id"], log=lambda m: _p("  " + m))
            for e in errs[:3]:
                _p(f"  {C_WARN}{e}{C_END}")
            if cnt:
                _p(f"  {C_OK}订阅添加成功，{cnt} 个节点{C_END}")
            else:
                _p(f"  {C_WARN}订阅暂未取到节点，可稍后在面板重试{C_END}")
    # 1b. 手动粘贴链接（已有订阅节点时可跳过）
    want_manual = True
    if store.data["nodes"]:
        want_manual = ask_yn("再手动粘贴一些链接吗？", False)
    while want_manual:
        text = read_links()
        nodes, errs = parser.parse_many(text)
        for e in errs:
            _p(f"  {C_WARN}{e}{C_END}")
        if nodes:
            _p(f"\n成功解析 {C_OK}{len(nodes)}{C_END} 个节点：")
            show_nodes(nodes)
            if ask_yn("确认添加这些节点？", True):
                store.add_nodes(nodes)
                break
        else:
            _p(f"{C_ERR}没有解析到节点。{C_END}")
        if not ask_yn("重新粘贴？", True):
            break
    if not store.data["nodes"]:
        _p("没有任何节点，已退出。")
        return

    # ---- 2. 默认带宽 ----
    title("第 2 步 / 默认带宽（影响 hy2 速度，填接近你实际宽带的值）")
    _p(f"{C_DIM}没有在链接里写明带宽的节点会用这里的默认值。填太高反而不稳。{C_END}")
    up = ask("上行 (Mbps)", "20")
    down = ask("下行 (Mbps)", "100")
    store.data["settings"]["default_up"] = f"{up} Mbps"
    store.data["settings"]["default_down"] = f"{down} Mbps"

    # ---- 3. 路由偏好 ----
    title("第 3 步 / 路由分流")
    _p("默认：中国大陆 IP 与 .cn 域名直连，其余走代理（已内置安全规则保证 SSH 不断）。")
    if ask_yn("现在添加自定义直连/代理规则吗？（之后也能在 WebUI 里改）", False):
        _p(f"{C_DIM}输入域名/IP，支持通配符，如  *.cn  github.com  1.2.3.0/24 。空行结束。{C_END}")
        while True:
            val = ask("规则值（空=结束）")
            if not val:
                break
            policy = "DIRECT" if ask_yn(f"“{val}” 走直连吗？(否=走代理)", True) else "PROXY"
            store.data["rules"].append({"value": val, "policy": policy, "type": "auto"})
            _p(f"  已添加：{val} -> {policy}")
    if ask_yn("兜底策略设为“走代理”（其余全部走节点）吗？否=兜底直连", True):
        store.data["settings"]["final"] = "PROXY"
    else:
        store.data["settings"]["final"] = "DIRECT"

    _p(f"{C_DIM}全屋网关：让局域网里别的设备也走代理。开启后两种用法——{C_END}")
    _p(f"{C_DIM}  ① 最稳：在设备上把 HTTP/SOCKS 代理填成 树莓派IP:7890（即开即用）；{C_END}")
    _p(f"{C_DIM}  ② 进阶：把设备网关指向树莓派做透明代理（依赖 TUN 转发，设好后请用该设备验证出口IP）。{C_END}")
    store.data["settings"]["gateway_mode"] = ask_yn("开启全屋网关模式吗？", False)

    # ---- 4. WebUI ----
    title("第 4 步 / WebUI 管理面板")
    port = ask("WebUI 端口", str(store.data["webui"]["port"]))
    pnum = int(port) if port.isdigit() else 0
    if not 1 <= pnum <= 65535:               # 越界（如 0 / 99999）会让 pihy2-web 启动崩溃，回落默认
        if port:
            _p(f"{C_WARN}  端口 {port} 非法（需 1..65535），改用 8088。{C_END}")
        pnum = 8088
    store.data["webui"]["port"] = pnum
    # 面板能以 root 改系统代理，必须有密码——否则只监听回环，无法局域网访问。
    _p(f"{C_WARN}面板以 root 运行、能改系统代理，必须设访问密码才会开放到局域网。{C_END}")
    import getpass
    pw = ""
    try:
        pw = getpass.getpass("设置访问密码（直接回车=自动生成）: ").strip()
    except Exception:
        # 无法隐藏输入的环境（如某些管道/无 tty）：不退回明文 input 回显密码，直接自动生成
        _p(f"{C_WARN}  当前环境无法隐藏输入，将自动生成随机密码以避免明文回显。{C_END}")
        pw = ""
    store.data["webui"]["password"] = pw or secrets.token_urlsafe(9)
    if not pw:
        _p(f"  已生成随机密码：{C_OK}{store.data['webui']['password']}{C_END}")
    with state_lock():        # 与订阅定时器/面板的并发写互斥，避免它们的更新被本次保存覆盖丢失
        store.save()

    # ---- 5. 安装 ----
    title("第 5 步 / 开始部署")
    _p("· 准备 TUN 设备")
    if not manager.ensure_tun(log=lambda m: _p("  " + m)):
        _p(f"{C_WARN}  未检测到 /dev/net/tun，TUN 全局代理可能无法工作。{C_END}")
        if not ask_yn("仍要继续吗？", False):
            _p("已中止。请确认内核 tun 模块可用后重试。")
            sys.exit(1)
    _p("· 安装 mihomo（首次直连 GitHub，可能较慢，请耐心等待）")
    try:
        manager.install_mihomo(mirror=store.data["settings"].get("github_mirror", ""),
                               log=lambda m: _p("  " + m))
    except Exception as e:
        _p(f"{C_ERR}  mihomo 安装失败：{e}{C_END}")
        _p("  可手动下载二进制放到 /usr/local/bin/mihomo 后重跑：python3 -m pihy2 install")
        sys.exit(1)

    _p("· 生成并校验配置")
    ok, msg = manager.apply_config(store, restart=False, log=lambda m: _p("  " + m))
    if not ok:
        _p(f"{C_ERR}{msg}{C_END}")
        sys.exit(1)
    _p(f"  {C_OK}配置校验通过{C_END}")

    _p("· 安装系统服务并设为开机自启")
    manager.install_services_with_timer(
        hours=store.data.get("sub_interval_hours", 12), log=lambda m: _p("  " + m))
    manager.enable_start("mihomo", log=lambda m: _p("  " + m))
    manager.enable_start("pihy2-web", log=lambda m: _p("  " + m))

    # ---- 6. 验证 ----
    title("第 6 步 / 验证")
    import time
    time.sleep(5)
    st = manager.service_status("mihomo")
    ok_run = st["active"] == "active"
    color = C_OK if ok_run else C_ERR
    _p(f"  mihomo 服务：{color}{st['active']}{C_END} / 开机自启 {st['enabled']}")
    if not ok_run:
        _p(f"{C_WARN}  mihomo 未在运行，查看日志：journalctl -u mihomo -n 30{C_END}")
        _p(manager.journal("mihomo", 12))
    else:
        _p(f"  {C_DIM}正在探测出口 IP（刚启动连接未热，会多试几次）…{C_END}")
        ip = manager.current_ip(retries=4)
        _p(f"  当前出口 IP：{C_OK}{ip}{C_END}")
        _p(f"  {C_DIM}若该 IP 是你节点所在地区，说明整机已走代理。{C_END}")
    web_st = manager.service_status("pihy2-web")
    if web_st["active"] != "active":
        _p(f"{C_WARN}  面板服务未运行：journalctl -u pihy2-web -n 30{C_END}")

    title("完成 🎉")
    webui = store.data["webui"]
    _p(f"WebUI 管理面板：{C_OK}http://<树莓派IP>:{webui['port']}{C_END}")
    if webui["password"]:
        _p(f"访问密码：{C_OK}{webui['password']}{C_END}")
    _p(f"{C_DIM}常用：python3 -m pihy2 status | apply | restart | uninstall{C_END}")
