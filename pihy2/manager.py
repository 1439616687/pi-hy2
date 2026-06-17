"""系统层操作：TUN、下载 mihomo、systemd 服务、应用配置、状态、clash API。

约定路径：
    /usr/local/bin/mihomo          mihomo 二进制
    /etc/mihomo/config.yaml        由 pihy2 渲染出的配置
    /etc/pihy2/state.json          pihy2 状态（节点/规则/设置）
    /etc/systemd/system/mihomo.service
    /etc/systemd/system/pihy2-web.service
"""

from __future__ import annotations

import gzip
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
import urllib.error
import urllib.parse

MIHOMO_BIN = "/usr/local/bin/mihomo"
MIHOMO_DIR = "/etc/mihomo"
MIHOMO_CONFIG = os.path.join(MIHOMO_DIR, "config.yaml")
MIHOMO_SERVICE = "/etc/systemd/system/mihomo.service"
WEBUI_SERVICE = "/etc/systemd/system/pihy2-web.service"
INSTALL_DIR = "/opt/pihy2"

# 在线获取失败时退回到这个已知可用版本（与 README 验证一致）
PINNED_VERSION = "v1.19.27"


# ---------------------------------------------------------------- 基础工具
def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def run(cmd: list[str], check: bool = False, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=timeout)


def detect_arch() -> str:
    """返回 mihomo 资源命名用的架构：arm64 / amd64 / armv7。"""
    m = platform.machine().lower()
    if m in ("aarch64", "arm64"):
        return "arm64"
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m.startswith("armv7") or m.startswith("armv6") or m == "armhf":
        return "armv7"
    return "arm64"  # 目标是树莓派，默认 arm64


# ---------------------------------------------------------------- 下载 mihomo
def resolve_download_url(arch: str | None = None, timeout: int = 20) -> tuple[str, str]:
    """通过 GitHub API 解析最新版下载地址。返回 (url, version)。

    过滤逻辑与 README 一致：取 mihomo-linux-<arch>-vX.X.X.gz，排除 compatible/go12 变体。
    """
    arch = arch or detect_arch()
    api = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
    req = urllib.request.Request(api, headers={"User-Agent": "pihy2"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.load(resp)
    prefix = f"mihomo-linux-{arch}-v"
    for asset in data.get("assets", []):
        name = asset.get("name", "")
        if (name.startswith(prefix) and name.endswith(".gz")
                and "compatible" not in name and "go12" not in name):
            return asset["browser_download_url"], data.get("tag_name", "")
    raise RuntimeError(f"未在最新发行版中找到 {prefix}*.gz 资源")


def fallback_url(arch: str | None = None) -> tuple[str, str]:
    arch = arch or detect_arch()
    url = (f"https://github.com/MetaCubeX/mihomo/releases/download/"
           f"{PINNED_VERSION}/mihomo-linux-{arch}-{PINNED_VERSION}.gz")
    return url, PINNED_VERSION


def _download(url: str, dest: str, mirror: str = "", timeout: int = 600) -> None:
    if mirror:
        url = mirror.rstrip("/") + "/" + url
    req = urllib.request.Request(url, headers={"User-Agent": "pihy2"})
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as f:
        shutil.copyfileobj(resp, f)


def install_mihomo(mirror: str = "", log=print) -> str:
    """下载并安装 mihomo 到 MIHOMO_BIN。已存在则跳过。返回版本号或 'existing'。"""
    if os.path.exists(MIHOMO_BIN):
        log(f"已存在 {MIHOMO_BIN}，跳过下载。")
        return "existing"

    arch = detect_arch()
    log(f"检测到架构：{arch}")
    try:
        url, ver = resolve_download_url(arch)
        log(f"最新版本：{ver}")
    except (urllib.error.URLError, urllib.error.HTTPError, RuntimeError, OSError) as e:
        log(f"在线解析失败（{e}），回退到已知版本 {PINNED_VERSION}")
        url, ver = fallback_url(arch)

    gz = "/tmp/mihomo.gz"
    log(f"下载：{url}")
    try:
        _download(url, gz, mirror=mirror)
    except Exception:
        # 直链失败再试一次固定版本
        url, ver = fallback_url(arch)
        log(f"下载失败，改用固定版本：{url}")
        _download(url, gz, mirror=mirror)

    log("解压并安装…")
    with gzip.open(gz, "rb") as fin, open(MIHOMO_BIN, "wb") as fout:
        shutil.copyfileobj(fin, fout)
    os.chmod(MIHOMO_BIN, 0o755)
    os.remove(gz)
    r = run([MIHOMO_BIN, "-v"])
    log(r.stdout.strip() or r.stderr.strip())
    return ver


# ---------------------------------------------------------------- TUN
def ensure_tun(log=print) -> bool:
    run(["modprobe", "tun"])
    try:
        with open("/etc/modules-load.d/tun.conf", "w") as f:
            f.write("tun\n")
    except OSError as e:
        log(f"写入开机加载 tun 失败：{e}")
    ok = os.path.exists("/dev/net/tun")
    log("TUN 设备就绪" if ok else "未发现 /dev/net/tun（容器内可能不支持）")
    return ok


# ---------------------------------------------------------------- 配置
def write_config(text: str) -> None:
    os.makedirs(MIHOMO_DIR, exist_ok=True)
    tmp = MIHOMO_CONFIG + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, MIHOMO_CONFIG)


def test_config(text: str | None = None) -> tuple[bool, str]:
    """用 mihomo -t 校验配置。text 给定时写到临时目录校验，否则校验已落盘的配置。"""
    if not os.path.exists(MIHOMO_BIN):
        return False, "mihomo 尚未安装"
    if text is not None:
        import tempfile
        d = tempfile.mkdtemp(prefix="pihy2-")
        with open(os.path.join(d, "config.yaml"), "w", encoding="utf-8") as f:
            f.write(text)
        folder = d
    else:
        folder = MIHOMO_DIR
    r = run([MIHOMO_BIN, "-d", folder, "-t"])
    out = (r.stdout + r.stderr).strip()
    return (r.returncode == 0 and "test is successful" in out), out


# ---------------------------------------------------------------- systemd
def _write(path: str, content: str) -> None:
    with open(path, "w") as f:
        f.write(content)


def install_services(log=print) -> None:
    """写入并启用 mihomo 与 pihy2-web 两个 systemd 服务。"""
    _write(MIHOMO_SERVICE, f"""[Unit]
Description=mihomo (pihy2)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={MIHOMO_BIN} -d {MIHOMO_DIR}
Restart=on-failure
RestartSec=5
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
""")

    py = sys.executable or "/usr/bin/python3"
    # 不写死端口：web 子命令会从 state.json 读取端口/监听地址，
    # 这样在面板里改端口后 `systemctl restart pihy2-web` 即可生效。
    _write(WEBUI_SERVICE, f"""[Unit]
Description=pihy2 WebUI 管理面板
After=network.target

[Service]
Type=simple
WorkingDirectory={INSTALL_DIR}
Environment=PYTHONPATH={INSTALL_DIR}
ExecStart={py} -m pihy2 web
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
""")
    run(["systemctl", "daemon-reload"])
    log("systemd 服务已写入")


def service_action(name: str, action: str, log=print) -> subprocess.CompletedProcess:
    r = run(["systemctl", action, name])
    if r.returncode != 0 and (r.stderr.strip()):
        log(f"systemctl {action} {name}: {r.stderr.strip()}")
    return r


def enable_start(name: str, log=print) -> None:
    service_action(name, "enable", log)
    service_action(name, "restart", log)


# ---------------------------------------------------------------- 应用配置
def apply_config(store, restart: bool = True, log=print) -> tuple[bool, str]:
    """渲染 -> 校验 -> 落盘 -> 重启 mihomo。校验失败则不落盘。"""
    text = store.render_config()
    ok, out = test_config(text)
    if not ok:
        return False, f"配置校验失败，已保留原配置：\n{out}"
    write_config(text)
    if restart and os.path.exists(MIHOMO_SERVICE):
        service_action("mihomo", "restart", log)
    return True, "配置已应用" + ("（mihomo 已重启）" if restart else "")


# ---------------------------------------------------------------- 状态/排错
def service_status(name: str) -> dict:
    active = run(["systemctl", "is-active", name]).stdout.strip()
    enabled = run(["systemctl", "is-enabled", name]).stdout.strip()
    return {"active": active, "enabled": enabled}


def journal(name: str, lines: int = 30) -> str:
    return run(["journalctl", "-u", name, "-n", str(lines), "--no-pager"]).stdout


def current_ip(timeout: int = 15) -> str:
    try:
        req = urllib.request.Request("https://api.ipify.org",
                                     headers={"User-Agent": "pihy2"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode().strip()
    except Exception as e:
        return f"(获取失败: {e})"


# ---------------------------------------------------------------- clash API
def _clash_request(method: str, path: str, settings: dict, body=None, timeout: int = 10):
    base = settings.get("external_controller") or "127.0.0.1:9090"
    if not base.startswith("http"):
        base = "http://" + base
    url = base.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if settings.get("secret"):
        req.add_header("Authorization", "Bearer " + settings["secret"])
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode()
        return json.loads(raw) if raw else {}


def clash_select(group: str, name: str, settings: dict) -> tuple[bool, str]:
    """在 clash API 里把策略组 group 切到 name。成功则无需重启即生效。"""
    try:
        _clash_request("PUT", f"/proxies/{urllib.parse.quote(group)}",
                       settings, body={"name": name})
        return True, "已切换"
    except Exception as e:
        return False, str(e)


def clash_delay(name: str, settings: dict, timeout: int = 5000) -> int | None:
    """测某个节点的延迟（毫秒）。失败返回 None。"""
    try:
        path = (f"/proxies/{urllib.parse.quote(name)}/delay"
                f"?timeout={timeout}&url=http://www.gstatic.com/generate_204")
        r = _clash_request("GET", path, settings, timeout=timeout / 1000 + 3)
        return r.get("delay")
    except Exception:
        return None


# ---------------------------------------------------------------- 卸载
def uninstall(purge: bool = False, log=print) -> None:
    for svc in ("pihy2-web", "mihomo"):
        service_action(svc, "disable", log)
        service_action(svc, "stop", log)
    for path in (MIHOMO_SERVICE, WEBUI_SERVICE):
        if os.path.exists(path):
            os.remove(path)
    run(["systemctl", "daemon-reload"])
    if purge:
        for path in (MIHOMO_BIN,):
            if os.path.exists(path):
                os.remove(path)
        shutil.rmtree(MIHOMO_DIR, ignore_errors=True)
    log("已卸载" + ("（含二进制与配置）" if purge else "（保留 /etc/pihy2 状态，可重装恢复）"))
