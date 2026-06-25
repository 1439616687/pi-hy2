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
import http.client
import ipaddress
import json
import os
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
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
    """套用下载镜像前缀；只允许 https 镜像、且镜像主机不得指向内网/本机（防 SSRF），
    避免明文下载被替换二进制（会以 root 运行）、或被借道探测/打内网服务。"""
    if not mirror:
        return url
    if not mirror.lower().startswith("https://"):
        raise ValueError("下载镜像必须是 https:// 开头")
    mhost = urllib.parse.urlparse(mirror).hostname or ""
    try:
        _resolve_public(mhost)                 # 解析并校验所有返回地址，命中内网即拒绝
    except ValueError:
        raise ValueError("下载镜像主机不能指向内网/本机地址")
    return mirror.rstrip("/") + "/" + url


def _download_to_file(url: str, dest: str, timeout: int = 600, _max_redirects: int = 5) -> None:
    """下载到文件，复用 fetch_text 的 SSRF 加固：每一跳都先解析+校验域名、再把连接钉死到该
    公网 IP（消除二次解析的 TOCTOU/DNS rebinding），有限跟随跳转且逐跳复检，超大小即报错。

    原先用 urllib.urlopen 下载会(a)二次解析镜像域名、(b)自动跟随跳转到任意主机且不复检，
    使 _apply_mirror 的预校验形同虚设——镜像可借此打内网/读元数据或投递任意二进制（以 root 运行）。
    """
    max_bytes = 2 * _MAX_BIN_BYTES        # 调用时 _MAX_BIN_BYTES 已定义；超此即中止，防超大/压缩炸弹
    for _ in range(_max_redirects + 1):
        parts = urllib.parse.urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError("下载地址必须以 http(s):// 开头")
        host = parts.hostname or ""
        if not host:
            raise ValueError("下载地址缺少主机名")
        port = parts.port or (443 if scheme == "https" else 80)
        _fam, ip = _resolve_public(host)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        if scheme == "https":
            conn = _PinnedHTTPSConnection(host, ip, port=port, timeout=timeout,
                                          context=ssl.create_default_context())
        else:
            conn = _PinnedHTTPConnection(host, ip, port=port, timeout=timeout)
        try:
            conn.request("GET", path, headers={"User-Agent": "pihy2/1.0", "Host": host})
            resp = conn.getresponse()
            if resp.status in (301, 302, 303, 307, 308):
                loc = resp.getheader("Location")
                if not loc:
                    raise ValueError("下载地址跳转缺少 Location")
                url = urllib.parse.urljoin(url, loc)
                continue                  # 下一跳重新解析+校验+钉死
            if resp.status != 200:
                raise ValueError(f"下载返回 HTTP {resp.status}")
            total = 0
            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError("下载体积超过上限，已中止")
                    f.write(chunk)
            return
        finally:
            conn.close()
    raise ValueError("下载地址跳转次数过多")


def _download(url: str, dest: str, mirror: str = "", timeout: int = 600) -> None:
    url = _apply_mirror(url, mirror)
    _download_to_file(url, dest, timeout=timeout)


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


_MAX_BIN_BYTES = 200 * 1024 * 1024     # 解压体积上限，防压缩炸弹耗尽磁盘


def install_mihomo(mirror: str = "", log=print) -> str:
    """下载校验并原子安装 mihomo 到 MIHOMO_BIN。返回版本号或 'existing'。

    安全要点：
      * 只允许 https 镜像；且镜像不可信，使用镜像时强制走「内置 SHA-256 的固定版本」，
        无内置校验和的架构（如 armv7）配镜像直接拒绝，避免投递任意可运行二进制。
      * 固定版本校验 SHA-256；不可校验时明确告警仅依赖 TLS + `-v`。
      * 下载落到 mkstemp 的唯一文件（O_EXCL），避开 /tmp 固定名 symlink 攻击与多实例竞争。
      * 解压设体积上限防压缩炸弹；先落临时文件再 os.replace 原子替换。
    """
    if os.path.exists(MIHOMO_BIN):
        if _binary_ok(MIHOMO_BIN):
            log(f"已存在可用的 {MIHOMO_BIN}，跳过下载。")
            return "existing"
        log(f"{MIHOMO_BIN} 无法运行（可能损坏），重新下载。")

    arch = detect_arch()
    log(f"检测到架构：{arch}")

    if mirror:
        if arch not in PINNED_SHA256:
            raise RuntimeError(
                f"{arch} 架构未内置校验和，使用下载镜像时无法保证完整性；"
                "请清除镜像改用 GitHub 直链，或手动安装 mihomo 到 /usr/local/bin/mihomo。")
        url, ver = fallback_url(arch)
        log(f"使用下载镜像 + 固定版本 {ver}（将校验 SHA-256）")
    else:
        try:
            url, ver = resolve_download_url(arch)
            log(f"最新版本：{ver}")
        except (urllib.error.URLError, urllib.error.HTTPError, RuntimeError, OSError) as e:
            log(f"在线解析失败（{e}），回退到已知版本 {PINNED_VERSION}")
            url, ver = fallback_url(arch)

    fd, gz = tempfile.mkstemp(prefix="mihomo-", suffix=".gz")
    os.close(fd)
    tmp_bin = MIHOMO_BIN + ".new"
    try:
        log(f"下载：{url}")
        try:
            _download(url, gz, mirror=mirror)
        except Exception as e:
            if mirror:
                raise                              # 镜像路径不静默回退到未校验直链
            log(f"下载失败（{e}），改用固定版本 {PINNED_VERSION}")
            url, ver = fallback_url(arch)
            _download(url, gz, mirror=mirror)

        if ver == PINNED_VERSION and arch in PINNED_SHA256:
            got = _sha256(gz)
            if got != PINNED_SHA256[arch]:
                raise RuntimeError(f"下载校验失败：SHA-256 不匹配（期望 {PINNED_SHA256[arch][:12]}…，"
                                   f"实际 {got[:12]}…），已中止以防被替换。")
            log("SHA-256 校验通过")
        else:
            log("注意：该下载未做 SHA-256 比对，仅依赖 GitHub TLS 与下面的可运行性校验。")

        log("解压并安装…")
        total = 0
        with gzip.open(gz, "rb") as fin, open(tmp_bin, "wb") as fout:
            while True:
                chunk = fin.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_BIN_BYTES:
                    raise RuntimeError("解压体积超过上限，疑似异常文件，已中止。")
                fout.write(chunk)
    except Exception:
        if os.path.exists(tmp_bin):
            os.remove(tmp_bin)
        raise
    finally:
        if os.path.exists(gz):
            os.remove(gz)

    os.chmod(tmp_bin, 0o755)
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
    tmp = None
    try:
        if text is not None:
            # 临时目录用完即删：否则每次 apply/订阅更新都会在 /tmp 堆积含密码与 clash 密钥的配置副本
            tmp = tempfile.mkdtemp(prefix="pihy2-")
            with open(os.path.join(tmp, "config.yaml"), "w", encoding="utf-8") as f:
                f.write(text)
            folder = tmp
        else:
            folder = MIHOMO_DIR
        r = run([MIHOMO_BIN, "-d", folder, "-t"])
        out = (r.stdout + r.stderr).strip()
        return (r.returncode == 0 and "test is successful" in out), out
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- systemd
def _write(path: str, content: str) -> None:
    with open(path, "w") as f:
        f.write(content)


def package_dir() -> str:
    """运行中的 pihy2 包所在父目录（含 pihy2/ 与 web/）。用于 systemd 单元的
    WorkingDirectory/PYTHONPATH——从任意目录跑 `python3 -m pihy2 install` 时，
    web / sub-update 服务也能正确导入 pihy2，而非写死 /opt/pihy2 导致 'No module named pihy2'。"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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
    pkg = package_dir()
    # 不写死端口：web 子命令会从 state.json 读取端口/监听地址，
    # 这样在面板里改端口后 `systemctl restart pihy2-web` 即可生效。
    # After=mihomo.service 让启动次序确定（面板在路由就绪后再起）。面板端口处于
    # 始终直连的私有网段，局域网访问不受 TUN 影响；即使 mihomo 没起来面板也能用于排错。
    # 适度加固：面板以 root + 局域网暴露，但仍需 systemctl/sysctl/写 /etc，故只加不影响这些
    # 操作的项（NoNewPrivileges 防提权扩张、PrivateTmp 隔离临时文件）。不加 ProtectHome/
    # ProtectKernelTunables——前者会挡住从 /home 跑的开发部署、后者会让 sysctl -w 失败。
    _write(WEBUI_SERVICE, f"""[Unit]
Description=pihy2 WebUI 管理面板
After=network.target mihomo.service

[Service]
Type=simple
WorkingDirectory={pkg}
Environment=PYTHONPATH={pkg}
ExecStart={py} -m pihy2 web
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes

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
SYSCTL_FILE = "/etc/sysctl.d/99-pihy2.conf"


def set_ip_forward(on: bool, log=print) -> None:
    """开/关全屋网关所需内核参数（IP 转发 + 宽松反向路径过滤）。
    rp_filter=2(loose) 是透明网关常见的关键项：TUN 代理下进出路径不对称，
    严格 rp_filter 会丢回程包。

    重要：ip_forward / rp_filter 是**全局**内核参数，Docker、K8s、其它 VPN、软路由
    都依赖它们。因此 pihy2 只在开启网关时主动置位；关闭网关时**只撤销自己的持久化文件、
    绝不把运行期值强制改回 0**——否则每次 apply（含订阅定时器自动 apply）都会把别人开启的
    转发踩掉，断开容器/下游设备网络。关闭即"不再由 pihy2 持有"，运行期值留给系统/其它软件。"""
    # 只设 conf.all.rp_filter=2：内核对每个接口取 max(all, iface)，all=2 已让所有接口
    # （含将来 Docker veth / 其它 VPN）走 loose。原先额外写 conf.default 是冗余的，且更易让人
    # 误以为只影响 pihy2；去掉它。注意 all=2 本身就是系统级放宽，这是透明网关非对称路由所必需。
    desired = ("net.ipv4.ip_forward=1\n"
               "net.ipv4.conf.all.rp_filter=2\n")
    try:
        if on:
            cur = ""
            if os.path.exists(SYSCTL_FILE):
                with open(SYSCTL_FILE) as f:
                    cur = f.read()
            if cur != desired:                 # 内容无变化则不写盘，避免每次 apply churn
                with open(SYSCTL_FILE, "w") as f:
                    f.write(desired)
        elif os.path.exists(SYSCTL_FILE):
            os.remove(SYSCTL_FILE)             # 关闭网关：仅移除 pihy2 的持久化，不动运行期全局值
    except OSError as e:
        log(f"持久化网关内核参数失败：{e}")
    # 仅在开启网关时主动应用运行期值；关闭时不调用 sysctl -w，避免踩 Docker 等其它转发用户
    if on:
        run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=2"])


def wait_active(name: str, timeout: float = 6.0) -> bool:
    """轮询 systemctl is-active，等待服务进入 active（重启后绑定端口需要一点时间）。"""
    import time
    deadline = time.time() + timeout
    while True:
        if run(["systemctl", "is-active", name]).stdout.strip() == "active":
            return True
        if time.time() >= deadline:
            return False
        time.sleep(0.4)


def apply_config(store, restart: bool = True, log=print) -> tuple[bool, str]:
    """渲染 -> 校验 -> 落盘 -> （动系统转发）-> 重启并确认 mihomo 真起来了。
    校验失败则不落盘、也不改系统转发。与现有配置完全一致时跳过落盘与重启。"""
    text = store.render_config()
    current = ""
    if os.path.exists(MIHOMO_CONFIG):
        try:
            with open(MIHOMO_CONFIG, "r", encoding="utf-8") as f:
                current = f.read()
        except OSError:
            pass
    gw = bool(store.data["settings"].get("gateway_mode"))
    warn = dns_conflict_warning()
    if warn:
        log("⚠️  " + warn)
    if text == current:
        set_ip_forward(gw, log)          # 无配置变化也把网关内核参数对齐到期望（幂等），但不重启
        return True, "配置无变化，未重启"
    ok, out = test_config(text)
    if not ok:
        # 校验失败：不写配置、也不动系统转发，保持原状——避免开了转发却没应用网关配置导致流量裸奔
        return False, f"配置校验失败，已保留原配置：\n{out}"
    write_config(text)
    set_ip_forward(gw, log)              # 仅在配置确实通过校验并落盘后，才提交系统级转发等副作用
    if restart and os.path.exists(MIHOMO_SERVICE):
        r = service_action("mihomo", "restart", log)
        if r.returncode != 0 or not wait_active("mihomo"):
            # -t 不绑定端口，真启动才会暴露端口占用（9090/7890/1053）等问题；如实回报失败 + 日志
            return False, ("配置已写入，但 mihomo 未能启动（常见原因：控制器/代理/DNS 端口被占用，"
                           "如 9090/7890/1053）。最近日志：\n" + journal("mihomo", 12))
    return True, "配置已应用" + ("（mihomo 已重启）" if restart else "")


# ---------------------------------------------------------------- 订阅
SUB_SERVICE = "/etc/systemd/system/pihy2-sub-update.service"
SUB_TIMER = "/etc/systemd/system/pihy2-sub-update.timer"


# 运营商级 NAT(CGNAT, RFC6598)：is_private 等标志不覆盖，需显式拦截
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _validate_ip(ipstr: str) -> str:
    """校验解析出的 IP 不指向内网/本机/保留/CGNAT 地址；IPv4-mapped 先还原。"""
    ip = ipaddress.ip_address(ipstr)
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified or ip in _CGNAT):
        raise ValueError("订阅地址不能指向内网/本机/保留地址")
    return str(ip)


def _resolve_public(host: str) -> tuple[int, str]:
    """解析域名并校验所有返回地址；返回钉死用的 (family, ip)。任一内网地址即整体拒绝。"""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        raise ValueError("无法解析订阅域名")
    chosen = None
    for fam, _, _, _, sa in infos:
        ok = _validate_ip(sa[0])
        if chosen is None:
            chosen = (fam, ok)
    if chosen is None:
        raise ValueError("订阅域名无解析结果")
    return chosen


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """连接到已校验并钉死的 IP，杜绝 getaddrinfo 二次解析（DNS rebinding/TOCTOU）。"""

    def __init__(self, host, ip, **kw):
        super().__init__(host, **kw)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, ip, **kw):
        super().__init__(host, **kw)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        # SNI/证书校验仍用真实域名 host，连接目标却是钉死的已校验 IP
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _decode_body(data: bytes) -> str:
    """解码订阅响应：优先 UTF-8，其次 GB18030（覆盖 GBK/GB2312，常见于国内机场），
    最后用 replace 兜底——让损坏可见（出现 �），而非 'ignore' 静默丢字节、把可恢复的
    编码问题变成悄悄出错/截断（如截断 base64、改坏节点名）。"""
    for enc in ("utf-8", "gb18030"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def fetch_text(url: str, timeout: int = 30, max_bytes: int = 8 * 1024 * 1024,
               _max_redirects: int = 5) -> str:
    """拉取订阅内容。订阅是 root 进程发起的服务端请求，须防 SSRF：

    每一跳都先解析+校验域名、再把连接钉死到该公网 IP（消除校验与连接之间的二次解析
    TOCTOU / DNS rebinding）；跳转有限跟随且逐跳复检；超大小直接报错而非静默截断。
    """
    for _ in range(_max_redirects + 1):
        parts = urllib.parse.urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError("订阅地址必须以 http(s):// 开头")
        host = parts.hostname or ""
        if not host:
            raise ValueError("订阅地址缺少主机名")
        port = parts.port or (443 if scheme == "https" else 80)
        _fam, ip = _resolve_public(host)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        if scheme == "https":
            conn = _PinnedHTTPSConnection(host, ip, port=port, timeout=timeout,
                                          context=ssl.create_default_context())
        else:
            conn = _PinnedHTTPConnection(host, ip, port=port, timeout=timeout)
        try:
            conn.request("GET", path, headers={"User-Agent": "pihy2/1.0", "Host": host})
            resp = conn.getresponse()
            if resp.status in (301, 302, 303, 307, 308):
                loc = resp.getheader("Location")
                if not loc:
                    raise ValueError("订阅地址跳转缺少 Location")
                url = urllib.parse.urljoin(url, loc)
                continue                       # 下一跳重新解析+校验+钉死
            if resp.status != 200:
                raise ValueError(f"订阅返回 HTTP {resp.status}")
            data = resp.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError("订阅内容超过大小限制")
            return _decode_body(data)
        finally:
            conn.close()
    raise ValueError("订阅地址跳转次数过多")


def fetch_sub_nodes(url: str) -> tuple[list, list]:
    """仅拉取 + 解析订阅内容为节点列表（不触碰 store）。返回 (节点列表, 错误列表)。

    把“网络 IO”与“改 store”分开，便于 WebUI 在不持有进程锁/状态锁的情况下做拉取，
    避免一个慢/卡住的订阅把整个面板的写操作冻住。
    """
    from . import parser
    try:
        text = fetch_text(url)
    except Exception as e:
        return [], [f"拉取失败：{e}"]
    try:
        return parser.parse_many(text)
    except Exception as e:                    # 解析器兜底，任何脏数据都不该拖垮定时更新
        return [], [f"解析失败：{e}"]


def refresh_subscription(store, sid: str, log=print) -> tuple[int, list]:
    """拉取并解析一个订阅，替换其名下节点。返回 (节点数, 错误列表)。"""
    sub = store.get_subscription(sid)
    if not sub:
        return 0, ["订阅不存在"]
    nodes, errors = fetch_sub_nodes(sub["url"])
    if not nodes:
        return 0, (errors or ["订阅里没有可解析的节点（可能是返回了登录页/空内容，或全是暂不支持的协议）"])
    n = store.set_subscription_nodes(sid, nodes)
    log(f"订阅「{sub['name']}」更新 {n} 个节点")
    return n, errors


def refresh_all_subscriptions(store, log=print) -> dict:
    return {s["id"]: refresh_subscription(store, s["id"], log)[0]
            for s in list(store.data.get("subscriptions", []))}


def install_sub_timer(hours: int = 12, log=print) -> None:
    """写入并启用订阅定时更新 timer。"""
    py = sys.executable or "/usr/bin/python3"
    pkg = package_dir()
    _write(SUB_SERVICE, f"""[Unit]
Description=pihy2 订阅更新
After=network-online.target mihomo.service

[Service]
Type=oneshot
WorkingDirectory={pkg}
Environment=PYTHONPATH={pkg}
ExecStart={py} -m pihy2 sub update all --apply
""")
    _write(SUB_TIMER, f"""[Unit]
Description=pihy2 订阅定时更新

[Timer]
OnBootSec=10min
OnUnitActiveSec={max(1, int(hours))}h

[Install]
WantedBy=timers.target
""")
    run(["systemctl", "daemon-reload"])
    service_action("pihy2-sub-update.timer", "enable", log)
    service_action("pihy2-sub-update.timer", "start", log)


# ---------------------------------------------------------------- 状态/排错
def dns_conflict_warning() -> str:
    """检测本机是否已运行占用 :53 的 DNS 服务（systemd-resolved/dnsmasq/Pi-hole）。
    有则返回一句中文告警（TUN 的 dns-hijack any:53 会劫持它们的查询），否则返回 ''。"""
    for svc, label in (("systemd-resolved", "systemd-resolved"),
                       ("dnsmasq", "dnsmasq"),
                       ("pihole-FTL", "Pi-hole")):
        if run(["systemctl", "is-active", svc]).stdout.strip() == "active":
            return (f"检测到本机正在运行 {label}（占用 53 端口）：TUN 的 dns-hijack=any:53 "
                    "会劫持本机/局域网的 DNS 查询，可能使其失效（如 Pi-hole 去广告停止）。"
                    "若需共存，可在设置里把「TUN DNS 劫持」改为仅 TUN 接口或清空。")
    return ""


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


def clash_connections(settings: dict, timeout: int = 5) -> dict | None:
    """取当前连接快照（含累计上下行字节与活动连接列表）。失败返回 None。"""
    try:
        return _clash_request("GET", "/connections", settings, timeout=timeout)
    except Exception:
        return None


def clash_close_all(settings: dict) -> bool:
    try:
        _clash_request("DELETE", "/connections", settings)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- 卸载
def uninstall(purge: bool = False, log=print) -> None:
    for svc in ("pihy2-sub-update.timer", "pihy2-web", "mihomo"):
        service_action(svc, "disable", log)
        service_action(svc, "stop", log)
    for path in (MIHOMO_SERVICE, WEBUI_SERVICE, SUB_SERVICE, SUB_TIMER):
        if os.path.exists(path):
            os.remove(path)
    set_ip_forward(False, log)            # 关掉网关模式开的 IP 转发
    run(["systemctl", "daemon-reload"])
    if purge:
        from .store import STATE_DIR
        # 也删 CLI 包装器，否则 purge 后 `pihy2` 命令还在、却指向被删空间，与“已彻底删除”不符
        for path in (MIHOMO_BIN, "/etc/modules-load.d/tun.conf", "/usr/local/bin/pihy2"):
            if os.path.exists(path):
                os.remove(path)
        shutil.rmtree(MIHOMO_DIR, ignore_errors=True)
        shutil.rmtree(STATE_DIR, ignore_errors=True)  # /etc/pihy2 状态
        # 标准安装目录 /opt/pihy2 一并清理；放最后（模块已加载进内存，删源码不影响本次运行）。
        # 只删约定的 INSTALL_DIR，不动从 git 检出目录直接运行的源码。
        shutil.rmtree(INSTALL_DIR, ignore_errors=True)
    log("已卸载" + ("（含二进制、配置、状态与安装目录）" if purge else "（保留 /etc/pihy2 状态，可重装恢复）"))
