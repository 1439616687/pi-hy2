"""交互式命令行向导：跟着提示填/选，一步步完成首次部署。

流程：检查环境 → 粘贴 hy2 节点 → 默认带宽 → 路由偏好 → WebUI 端口/密码
      → 准备 TUN → 安装 mihomo → 生成并校验配置 → 建服务并启动 → 验证出口 IP。
"""

from __future__ import annotations

import secrets
import sys

from . import manager, parser
from .store import Store

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
    _p("粘贴一个或多个 hy2 节点链接（hysteria2:// 或 hy2://，每行一个；")
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
    while True:
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
            if not store.data["nodes"]:
                _p("没有任何节点，已退出。")
                return
            break

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

    # ---- 4. WebUI ----
    title("第 4 步 / WebUI 管理面板")
    port = ask("WebUI 端口", str(store.data["webui"]["port"]))
    store.data["webui"]["port"] = int(port) if port.isdigit() else 8088
    _p(f"{C_WARN}面板能改系统代理，建议设访问密码。{C_END}")
    if ask_yn("设置访问密码吗？", True):
        import getpass
        try:
            pw = getpass.getpass("输入密码（输入时不显示）: ").strip()
        except Exception:
            pw = ask("输入密码")
        store.data["webui"]["password"] = pw or secrets.token_urlsafe(9)
        if not pw:
            _p(f"  未输入，已生成随机密码：{C_OK}{store.data['webui']['password']}{C_END}")
    store.save()

    # ---- 5. 安装 ----
    title("第 5 步 / 开始部署")
    _p("· 准备 TUN 设备")
    manager.ensure_tun(log=lambda m: _p("  " + m))
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
    manager.install_services(log=lambda m: _p("  " + m))
    manager.enable_start("mihomo", log=lambda m: _p("  " + m))
    manager.enable_start("pihy2-web", log=lambda m: _p("  " + m))

    # ---- 6. 验证 ----
    title("第 6 步 / 验证")
    import time
    time.sleep(4)
    st = manager.service_status("mihomo")
    _p(f"  mihomo 服务：{st['active']} / 开机自启 {st['enabled']}")
    ip = manager.current_ip()
    _p(f"  当前出口 IP：{C_OK}{ip}{C_END}")
    _p(f"  {C_DIM}若该 IP 是你节点所在地区，说明整机已走代理。{C_END}")

    title("完成 🎉")
    webui = store.data["webui"]
    _p(f"WebUI 管理面板：{C_OK}http://<树莓派IP>:{webui['port']}{C_END}")
    if webui["password"]:
        _p(f"访问密码：{C_OK}{webui['password']}{C_END}")
    _p(f"{C_DIM}常用：python3 -m pihy2 status | apply | restart | uninstall{C_END}")
