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
# 固定版本各架构 .gz 的 SHA-256，用于校验下载完整性（离线/镜像场景的信任锚）
PINNED_SHA256 = {
    "arm64": "87db0c6660a9557a901b5750f997967e71d8c0af07ea1d1dd4d04c28da7f7e6f",
    "amd64": "fb3e34c55844f389ff54679e5a3aec331d5ec38006c20f8dcc476fb47768a58f",
}


# ---------------------------------------------------------------- 基础工具
def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def run(cmd: list[str], check: bool = False, timeout: int = 60) -> subprocess.CompletedProcess:
    """运行命令；命令不存在或超时时返回一个非零的合成结果而不是抛异常，
    这样调用方（状态查询、配置校验等）在非 systemd 环境或卡顿时也不会崩。"""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=timeout)
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", f"命令不存在: {cmd[0]}")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", f"命令超时({timeout}s): {' '.join(cmd)}")
    except OSError as e:  # 例如架构不符的二进制 Exec format error
        return subprocess.CompletedProcess(cmd, 126, "", f"无法执行 {cmd[0]}: {e}")


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


def _apply_mirror(url: str, mirror: str) -> str:
    """套用下载镜像前缀；只允许 https 镜像，避免明文下载被替换二进制（会以 root 运行）。"""
    if not mirror:
        return url
    if not mirror.lower().startswith("https://"):
        raise ValueError("下载镜像必须是 https:// 开头")
    return mirror.rstrip("/") + "/" + url


def _download(url: str, dest: str, mirror: str = "", timeout: int = 600) -> None:
    url = _apply_mirror(url, mirror)
    req = urllib.request.Request(url, headers={"User-Agent": "pihy2"})
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as f:
        shutil.copyfileobj(resp, f)


def _sha256(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _binary_ok(path: str) -> bool:
    """二进制能正常 `-v` 即视为可用（可识别截断/架构不符/损坏）。"""
    r = run([path, "-v"], timeout=15)
    return r.returncode == 0 and ("Mihomo" in r.stdout or "Meta" in r.stdout)


def install_mihomo(mirror: str = "", log=print) -> str:
    """下载校验并原子安装 mihomo 到 MIHOMO_BIN。返回版本号或 'existing'。

    安全要点：只允许 https 镜像；固定版本校验 SHA-256；安装前先 `-v` 验证；
    先落临时文件再 os.replace 原子替换，避免半截/损坏的 root 可执行文件留存。
    """
    if os.path.exists(MIHOMO_BIN):
        if _binary_ok(MIHOMO_BIN):
            log(f"已存在可用的 {MIHOMO_BIN}，跳过下载。")
            return "existing"
        log(f"{MIHOMO_BIN} 无法运行（可能损坏），重新下载。")

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
    except Exception as e:
        # 直链失败再试一次固定版本
        log(f"下载失败（{e}），改用固定版本 {PINNED_VERSION}")
        url, ver = fallback_url(arch)
        _download(url, gz, mirror=mirror)

    # 固定版本校验 SHA-256（在线最新版无法预知 hash，依赖 GitHub TLS + 下面的 -v 验证）
    if ver == PINNED_VERSION and arch in PINNED_SHA256:
        got = _sha256(gz)
        if got != PINNED_SHA256[arch]:
            os.remove(gz)
            raise RuntimeError(f"下载校验失败：SHA-256 不匹配（期望 {PINNED_SHA256[arch][:12]}…，"
                               f"实际 {got[:12]}…），已中止以防被替换。")
        log("SHA-256 校验通过")

    log("解压并安装…")
    tmp_bin = MIHOMO_BIN + ".new"
    with gzip.open(gz, "rb") as fin, open(tmp_bin, "wb") as fout:
        shutil.copyfileobj(fin, fout)
    os.chmod(tmp_bin, 0o755)
    os.remove(gz)
    if not _binary_ok(tmp_bin):
        r = run([tmp_bin, "-v"], timeout=15)
        os.remove(tmp_bin)
        raise RuntimeError(f"下载的二进制无法运行（可能损坏或架构不符）：{r.stderr.strip()}")
    os.replace(tmp_bin, MIHOMO_BIN)       # 原子替换
    log(run([MIHOMO_BIN, "-v"]).stdout.strip())
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
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)              # 含节点密码与 clash 密钥，仅 root 可读
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
    # After=mihomo.service 让启动次序确定（面板在路由就绪后再起）。面板端口处于
    # 始终直连的私有网段，局域网访问不受 TUN 影响；即使 mihomo 没起来面板也能用于排错。
    _write(WEBUI_SERVICE, f"""[Unit]
Description=pihy2 WebUI 管理面板
After=network.target mihomo.service

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


def install_services_with_timer(hours: int = 12, log=print) -> None:
    install_services(log)
    install_sub_timer(hours, log)


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


# ---------------------------------------------------------------- 订阅
SUB_SERVICE = "/etc/systemd/system/pihy2-sub-update.service"
SUB_TIMER = "/etc/systemd/system/pihy2-sub-update.timer"


def fetch_text(url: str, timeout: int = 30) -> str:
    """拉取订阅内容。部分机场按 User-Agent 返回不同格式，这里用通用 UA 期望拿到链接列表。"""
    req = urllib.request.Request(url, headers={"User-Agent": "pihy2/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "ignore")


def refresh_subscription(store, sid: str, log=print) -> tuple[int, list]:
    """拉取并解析一个订阅，替换其名下节点。返回 (节点数, 错误列表)。"""
    from . import parser
    sub = store.get_subscription(sid)
    if not sub:
        return 0, ["订阅不存在"]
    try:
        text = fetch_text(sub["url"])
    except Exception as e:
        return 0, [f"拉取失败：{e}"]
    nodes, errors = parser.parse_many(text)
    if not nodes:
        return 0, (errors or ["订阅里没有可解析的节点（若是 Clash YAML 订阅，暂不支持）"])
    n = store.set_subscription_nodes(sid, nodes)
    log(f"订阅「{sub['name']}」更新 {n} 个节点")
    return n, errors


def refresh_all_subscriptions(store, log=print) -> dict:
    return {s["id"]: refresh_subscription(store, s["id"], log)[0]
            for s in list(store.data.get("subscriptions", []))}


def install_sub_timer(hours: int = 12, log=print) -> None:
    """写入并启用订阅定时更新 timer。"""
    py = sys.executable or "/usr/bin/python3"
    _write(SUB_SERVICE, f"""[Unit]
Description=pihy2 订阅更新
After=network-online.target mihomo.service

[Service]
Type=oneshot
WorkingDirectory={INSTALL_DIR}
Environment=PYTHONPATH={INSTALL_DIR}
ExecStart={py} -m pihy2 sub update all --apply
""")
    _write(SUB_TIMER, f"""[Unit]
Description=pihy2 订阅定时更新

[Timer]
OnBootSec=10min
OnUnitActiveSec={max(1, int(hours))}h
Persistent=true

[Install]
WantedBy=timers.target
""")
    run(["systemctl", "daemon-reload"])
    service_action("pihy2-sub-update.timer", "enable", log)
    service_action("pihy2-sub-update.timer", "start", log)


# ---------------------------------------------------------------- 状态/排错
def service_status(name: str) -> dict:
    active = run(["systemctl", "is-active", name]).stdout.strip()
    enabled = run(["systemctl", "is-enabled", name]).stdout.strip()
    return {"active": active, "enabled": enabled}


def journal(name: str, lines: int = 30) -> str:
    return run(["journalctl", "-u", name, "-n", str(lines), "--no-pager"]).stdout


def current_ip(timeout: int = 8, retries: int = 1) -> str:
    """探测当前出口 IP。刚启动 mihomo 时连接未热，可多重试几次。"""
    import time
    last = ""
    for i in range(max(1, retries)):
        try:
            req = urllib.request.Request("https://api.ipify.org",
                                         headers={"User-Agent": "pihy2"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode().strip()
        except Exception as e:
            last = str(e)
            if i + 1 < retries:
                time.sleep(2 * (i + 1))
    return f"(获取失败: {last})"


# ---------------------------------------------------------------- clash API
def _controller_base(settings: dict) -> str:
    """返回 clash 外部控制器的 base URL，并强制其为本机回环地址。

    external_controller 可被面板修改；若指向非回环地址，带着 secret 发请求会造成
    SSRF 并把密钥外泄。这里统一拦截，只允许 127.0.0.1/::1/localhost。
    """
    base = settings.get("external_controller") or "127.0.0.1:9090"
    if not base.startswith("http"):
        base = "http://" + base
    host = urllib.parse.urlparse(base).hostname or ""
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise ValueError("clash 外部控制器必须是本机回环地址（127.0.0.1）")
    return base


def _clash_request(method: str, path: str, settings: dict, body=None, timeout: int = 10):
    url = _controller_base(settings).rstrip("/") + path
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
    for svc in ("pihy2-sub-update.timer", "pihy2-web", "mihomo"):
        service_action(svc, "disable", log)
        service_action(svc, "stop", log)
    for path in (MIHOMO_SERVICE, WEBUI_SERVICE, SUB_SERVICE, SUB_TIMER):
        if os.path.exists(path):
            os.remove(path)
    run(["systemctl", "daemon-reload"])
    if purge:
        from .store import STATE_DIR
        for path in (MIHOMO_BIN, "/etc/modules-load.d/tun.conf"):
            if os.path.exists(path):
                os.remove(path)
        shutil.rmtree(MIHOMO_DIR, ignore_errors=True)
        shutil.rmtree(STATE_DIR, ignore_errors=True)  # /etc/pihy2 状态
    log("已卸载" + ("（含二进制、配置与状态）" if purge else "（保留 /etc/pihy2 状态，可重装恢复）"))
