"""交互式命令行向导：跟着提示填/选，一步步完成首次部署。

流程：检查环境 → 粘贴 hy2 节点 → 默认带宽 → 路由偏好 → WebUI 端口/密码
      → 准备 TUN → 安装 mihomo → 生成并校验配置 → 建服务并启动 → 验证出口 IP。
"""

from __future__ import annotations

import os
import secrets
import sys
import urllib.parse

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


def _ask_mirror(default: str = "") -> str:
    """选填 mihomo 下载镜像：回车=保持当前（无当前则=直连）；输入 ``-`` / ``直连`` / ``无`` =强制直连。

    就地把取值规整为 ``https://`` 前缀，并拒绝 http 与内网/本机地址（与 manager 的 SSRF 校验
    同口径——manager 在真正下载时还会再校验一次）。非法即重填，但**绝不卡死**：若带进来的旧默认
    本身已失效（如旧镜像域名当前解析不了），首次校验失败后即清掉该默认，使下一次回车=直连——
    这正是“重新部署时回车也过不去”死循环的根因修复（默认值粘住回车、而其又通不过校验）。
    """
    if default:
        _p(f"{C_DIM}  当前已存镜像：{default}（回车保留并校验；输入 - 改直连；或输入新的 https 镜像）{C_END}")
    while True:
        val = ask("下载镜像（- 或留空=直连 GitHub）", default).strip()
        if val in ("", "-", "直连", "无", "none", "skip"):
            return ""
        url = val if "://" in val else "https://" + val
        if not url.lower().startswith("https://"):
            _p(f"{C_WARN}  镜像必须以 https:// 开头；输入 - 直连，或重填。{C_END}")
            default = "" if val == default else default   # 失效的旧默认不再粘住回车
            continue
        try:
            manager._resolve_public(urllib.parse.urlparse(url).hostname or "")
        except Exception:
            _p(f"{C_WARN}  镜像主机无法解析或指向内网/本机；输入 - 直连，或换公网镜像。{C_END}")
            default = "" if val == default else default   # 同上：避免“回车=重填同一失效默认”的死循环
            continue
        return url


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


def _ask_choice(prompt: str, n: int) -> int:
    """读 0..n 的菜单选择；非法（空/非数字/越界）就重读，绝不因手误跳到别的动作。"""
    while True:
        v = ask(prompt).strip()
        if v.isdigit() and 0 <= int(v) <= n:
            return int(v)
        _p(f"{C_WARN}  请输入 0–{n} 之间的数字。{C_END}")


_ST_SYM = {"ok": (C_OK, "✓"), "warn": (C_WARN, "!"), "fail": (C_ERR, "✗"), "skip": (C_DIM, "–")}


def _print_selftest(store):
    """运行期自检并彩色打印（与 `pihy2 selftest` 同源 manager.self_test）。"""
    res = manager.self_test(store)
    _p("")
    for c in res["checks"]:
        col, s = _ST_SYM.get(c["status"], (C_DIM, "?"))
        line = f"  {col}{s}{C_END} {c['label']}"
        if c["detail"]:
            line += f"：{c['detail']}"
        _p(line)
    s = res["summary"]
    _p(f"  ——  {C_OK}通过 {s['ok']}{C_END} / {C_WARN}警告 {s['warn']}{C_END} / "
       f"{C_ERR}失败 {s['fail']}{C_END} / 跳过 {s['skip']}")


def _print_status(store):
    st = manager.service_status("mihomo")
    web = manager.service_status("pihy2-web")
    _p(f"\n  mihomo   ：{st['active']} / 开机自启 {st['enabled']}")
    _p(f"  pihy2-web：{web['active']} / 开机自启 {web['enabled']}")
    act = store.active_node()
    _p(f"  节点数   ：{len(store.data['nodes'])}  当前出口：{(act or {}).get('name', '无')}")
    w = store.data["webui"]
    tail = "（已设密码）" if w.get("password") else "（未设密码，仅本机可访问）"
    _p(f"  面板     ：http://<树莓派IP>:{w['port']}  {tail}")
    if st["active"] == "active":
        _p(f"  {C_DIM}正在探测出口 IP…{C_END}")
        _p(f"  出口 IP  ：{C_OK}{manager.current_ip(timeout=5, retries=2)}{C_END}")


def _do_restore_defaults(store):
    if not ask_yn("把设置恢复出厂默认？（重置带宽/DNS/TUN/预设等，不动节点/订阅/规则/面板密码）", False):
        return
    with state_lock():
        store.restore_default_settings()
        store.save()
    _p(f"  {C_OK}已恢复默认设置。{C_END}")
    if os.path.exists(manager.MIHOMO_BIN) and ask_yn("现在应用并重启 mihomo 使其生效吗？", True):
        ok, msg = manager.apply_config(store)
        _p("  " + msg)


def _do_uninstall() -> bool:
    """交互式卸载；返回 True=已卸载，False=用户取消。"""
    _p(f"{C_WARN}  卸载会停止并移除 mihomo 与面板服务、撤销开机自启与网关转发持久化。{C_END}")
    purge = ask_yn("同时删除二进制、配置与 /etc/pihy2 状态（--purge，不可恢复）？", False)
    prompt = ("确认卸载？（含 purge：节点/订阅/设置全部删除且不可恢复）" if purge
              else "确认卸载？（保留 /etc/pihy2 状态，可重装恢复）")
    if not ask_yn(prompt, False):
        _p("  已取消卸载。")
        return False
    manager.uninstall(purge=purge, log=lambda m: _p("  " + m))
    _p(f"  {C_OK}卸载完成。{C_END}")
    return True


def _manage_existing(store) -> bool:
    """已部署时的管理菜单。返回 True=继续走部署向导（添加/改节点与设置）；
    返回 False=用户选择退出或已执行完终态动作（卸载），调用方据此直接结束。"""
    while True:
        title("检测到 pihy2 已部署 · 选择要做什么")
        _p(f"  已有节点 {len(store.data['nodes'])} 个，面板端口 {store.data['webui']['port']}。")
        _p("  1) 继续部署向导（添加节点 / 修改带宽·路由·网关·面板等设置）")
        _p("  2) 运行自检（检查安装/服务/配置/出口是否正常）")
        _p("  3) 查看运行状态与面板地址")
        _p("  4) 恢复默认设置（不动节点/订阅/规则/面板密码）")
        _p(f"  5) {C_ERR}卸载 pihy2{C_END}")
        _p("  0) 退出（不改动任何东西）")
        choice = _ask_choice("输入序号", 5)
        if choice == 1:
            return True
        if choice == 0:
            _p("已退出，未改动任何东西。")
            return False
        if choice == 2:
            _print_selftest(store)
        elif choice == 3:
            _print_status(store)
        elif choice == 4:
            _do_restore_defaults(store)
        elif choice == 5:
            if _do_uninstall():
                return False          # 已卸载，结束；取消则回到菜单


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
    # 已部署（装了二进制/服务或已有节点）时先给管理菜单：继续向导 / 自检 / 状态 / 恢复默认 / 卸载。
    # 这样重新执行脚本不再被迫从头走一遍向导，卸载与恢复默认也都能在此一处完成（FEAT-2/3/4）。
    installed = (os.path.exists(manager.MIHOMO_BIN)
                 or os.path.exists(manager.MIHOMO_SERVICE)
                 or bool(store.data["nodes"]))
    if installed and not _manage_existing(store):
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
    existing_pw = store.data["webui"].get("password", "")
    if existing_pw:        # 重新部署：回车=保持原密码不变，绝不在用户没要求时悄悄改掉它
        _p(f"{C_DIM}已设置过访问密码。直接回车=保持不变；输入新密码=修改。{C_END}")
    prompt = "访问密码（回车=保持不变）: " if existing_pw else "设置访问密码（直接回车=自动生成）: "
    pw = ""
    try:
        pw = getpass.getpass(prompt).strip()
    except Exception:
        # 无法隐藏输入的环境（如某些管道/无 tty）：不退回明文 input 回显密码
        _p(f"{C_WARN}  当前环境无法隐藏输入，{'保持原密码' if existing_pw else '将自动生成随机密码'}以避免明文回显。{C_END}")
        pw = ""
    if pw:
        store.data["webui"]["password"] = pw
    elif existing_pw:
        store.data["webui"]["password"] = existing_pw         # 保持不变
        _p(f"  {C_DIM}保持原访问密码不变。{C_END}")
    else:
        store.data["webui"]["password"] = secrets.token_urlsafe(9)
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
    _p("· 安装 mihomo")
    # 已装好可用的二进制（重新部署的常见情形）：无需再问下载镜像、更不必重新下载——这也避免了
    # 旧的失效镜像默认值把“镜像”这一步卡死（用户报告的回车过不去即源于此）。
    if os.path.exists(manager.MIHOMO_BIN) and manager._binary_ok(manager.MIHOMO_BIN):
        _p(f"  {C_OK}已存在可用的 mihomo，跳过下载。{C_END}")
    else:
        arch = manager.detect_arch()
        # 镜像仅对内置 SHA-256 的架构（arm64/amd64）安全可用；其它架构 install_mihomo 会直接拒绝镜像，
        # 故只在受支持的架构上提供镜像选项，避免在 32 位树莓派上填了镜像却必然安装失败（兼容性关键点）。
        mirror_ok = arch in manager.PINNED_SHA256
        mirror = store.data["settings"].get("github_mirror", "")
        if mirror_ok:
            _p(f"{C_DIM}  直连 GitHub 慢/被墙时可填下载镜像（公网 https 前缀，如 https://ghproxy.com/）；{C_END}")
            _p(f"{C_DIM}  留空=直连。镜像会强制固定版本并校验 SHA-256，且不支持局域网地址。{C_END}")
            mirror = _ask_mirror(mirror)
        else:
            if mirror:
                _p(f"{C_WARN}  当前架构 {arch} 未内置校验和，下载镜像不可用，改为直连 GitHub。{C_END}")
            mirror = ""
            _p(f"{C_DIM}  架构 {arch}：镜像需 arm64/amd64；本架构直连 GitHub"
               f"（慢/失败可手动放二进制到 /usr/local/bin/mihomo 后重跑）。{C_END}")
        store.data["settings"]["github_mirror"] = mirror

        while True:                              # 失败可换镜像/改直连后重试，不丢前面几步的输入
            try:
                manager.install_mihomo(mirror=mirror, log=lambda m: _p("  " + m))
                break
            except Exception as e:
                _p(f"{C_ERR}  mihomo 安装失败：{e}{C_END}")
                if mirror_ok and ask_yn("换个镜像或留空直连后重试吗？（否=放弃）", True):
                    mirror = _ask_mirror(mirror)
                    store.data["settings"]["github_mirror"] = mirror
                    continue
                _p("  也可手动下载二进制放到 /usr/local/bin/mihomo 后重跑：python3 -m pihy2 install")
                sys.exit(1)
    with state_lock():                           # 持久化最终镜像选择（WebUI 设置页也读它做后续下载）
        store.save()

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
    # mihomo 此时已启动：网关模式下再 apply 一次，让 IP 转发等系统副作用真正生效——首次 apply 在
    # mihomo 启动之前，按安全策略（BUG-9）当时不会开启转发，需在确认运行后补提交。
    if store.data["settings"].get("gateway_mode"):
        manager.apply_config(store, restart=False, log=lambda m: _p("  " + m))

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
