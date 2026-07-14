"""结构化日志：让任何异常/错误都可追溯（零依赖，标准库 logging）。

设计要点：
  * RotatingFileHandler 落 /var/log/pihy2/pihy2.log（约 6MB 上限），同时 stderr -> journald。
  * 目录/文件收紧到仅 root；**无法写文件时（非 root / CI / 只读环境）退化为仅 stderr**，
    绝不因日志初始化失败让程序起不来（与 store.state_lock 拿不到锁退化为无锁同口径）。
  * 请求级追溯 ID（contextvar）：webui 每个请求绑定一个 8 位 hex，异常带 ID 入日志并回传前端，
    用户报错时 `grep <ID> /var/log/pihy2/pihy2.log` 即可定位完整堆栈——这是“任何异常可追溯”的关键。
  * 落盘前 scrub 已知密钥字段（password/uuid/secret/token/authorization）——日志是新泄露面，
    不让明文凭据进文件。（ponytail: 正则 scrub 是尽力而为，根本纪律是日志里只记节点名/id、
    不记节点字典明文；此正则覆盖凭据类键=值/键: 值的常见写法，升级路径是按字段名白名单显式打印。）
  * 库态静默：模块导入即给 "pihy2" logger 挂 NullHandler 且 propagate=False，
    未调用 setup_logging 时（如 test_smoke 导入）不向 stderr 喷任何东西。
"""

from __future__ import annotations

import contextvars
import logging
import os
import re
import secrets
from logging.handlers import RotatingFileHandler

DEFAULT_LOG_DIR = os.environ.get("PIHY2_LOG_DIR", "/var/log/pihy2")
DEFAULT_LOG_FILE = os.path.join(DEFAULT_LOG_DIR, "pihy2.log")

# 请求级追溯 ID：默认 "-"（非请求上下文，如订阅定时器、CLI）。webui 在 _safe 里 bind 新值。
_reqid: contextvars.ContextVar[str] = contextvars.ContextVar("pihy2_reqid", default="-")

# 库态静默：未 setup_logging 时一切吞掉、不向 stderr 输出（避免污染 test_smoke 等）。
_logger = logging.getLogger("pihy2")
_logger.addHandler(logging.NullHandler())
_logger.propagate = False

# 已知敏感内容 -> 落盘时换成 ******。五类，按顺序套用：
#   1) URL userinfo：按 authority（scheme://到首个 / 前）里“最后一个 @”拆分（与 urllib/parser 的
#      rsplit('@',1) 一致），正确处理密码含 @；只动 authority、不碰 path/query 里的 @。
#   2) Authorization 头：键可能被引号包裹（dict/JSON repr），值可能跨 token（Bearer/Token <jwt>），贪婪到行尾。
#   3) 裸 bearer token。
#   4) 普通凭据键值：password/uuid/secret/token/access_token/api_key… = 单值。
#   5) 空格分隔的引号裸值：password 'xxx'（不碰无引号自然语言，避免误伤）。
# （ponytail: 自由文本完美脱敏难；此处覆盖凭据类常见写法，根本纪律是日志只记节点名/id、不记节点字典明文。
#  另：RotatingFileHandler 无跨进程锁，webui/订阅定时器/CLI 多进程并发写同一文件偶发丢条——
#  systemd journal（stderr）才是权威可追溯来源，pihy2.log 为 best-effort。A6）
_SECRET_KEYS = ("password|obfs[-_]?password|uuid|secret|token|"
                "access_token|api_token|auth_token|csrf_token|refresh_token|id_token|"
                "api_key|secret_key|private_key|access_key")
_URL_CREDS_RE = re.compile(r"(?i)((?:https?|wss?|ftp)://)([^/\s]+)")   # group2 = authority（到首个 / 前）


def _strip_url_creds(text: str) -> str:
    def _sub(m):
        auth = m.group(2)
        return m.group(1) + (auth.rsplit("@", 1)[1] if "@" in auth else auth)
    return _URL_CREDS_RE.sub(_sub, text)


_AUTHZ_RE = re.compile(r"(?i)(\bauthorization\b\s*['\"]?\s*[:=]\s*).*")   # .* 不跨行；吃掉 Bearer/Token <jwt>
_BEARER_RE = re.compile(r"(?i)(\bbearer\s+)\S+")
_SECRET_KV_RE = re.compile(
    r"(?i)\b(" + _SECRET_KEYS + r")\b\s*['\"]?\s*[:=]\s*(\"[^\"]*\"|'[^']*'|\S+)")
_SECRET_QUOTED_RE = re.compile(
    r"(?i)\b(" + _SECRET_KEYS + r")\b\s+(\"[^\"]*\"|'[^']*')")


def _scrub(text: str) -> str:
    text = _strip_url_creds(text)
    text = _AUTHZ_RE.sub(r"\1******", text)
    text = _BEARER_RE.sub(r"\1******", text)
    text = _SECRET_KV_RE.sub(lambda m: f"{m.group(1)}=******", text)
    return _SECRET_QUOTED_RE.sub(lambda m: f"{m.group(1)} ******", text)


class _ScrubFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return _scrub(super().format(record))


class _ReqIdFilter(logging.Filter):
    """把当前 contextvar 里的 reqid 注入每条 record，供格式串 %(reqid)s 使用。"""

    def filter(self, record: logging.LogRecord) -> bool:
        record.reqid = _reqid.get()
        return True


_CONFIGURED = False
_log_file: str | None = None      # 实际成功打开的日志文件（None=仅 stderr，无文件可读）


def current_log_file() -> str | None:
    """返回 setup_logging 实际写入的日志文件路径（未配置/退化仅 stderr 时为 None）。"""
    return _log_file


def setup_logging(level: str = "INFO", file_path: str | None = None) -> logging.Logger:
    """配置 "pihy2" logger（幂等）。file_path 默认 DEFAULT_LOG_FILE；不可写时退化仅 stderr。"""
    global _CONFIGURED, _log_file
    if _CONFIGURED:
        return _logger
    _CONFIGURED = True
    _logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    fmt = _ScrubFormatter(
        "%(asctime)s %(levelname)s [pihy2] [%(reqid)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    rid = _ReqIdFilter()
    # stderr handler：始终挂（systemd 下自动进 journald）
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    sh.addFilter(rid)
    _logger.addHandler(sh)
    # rotating file handler：best-effort，失败即退化（非 root/CI/只读）
    path = file_path or DEFAULT_LOG_FILE
    try:
        os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
        fh = RotatingFileHandler(path, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        fh.setFormatter(fmt)
        fh.addFilter(rid)
        _logger.addHandler(fh)
        _log_file = path                  # 记下实际文件，供 read_logs/selftest 用
    except OSError:
        # 不抛：日志初始化失败不该阻断功能；仅 stderr 仍可追溯（journald 收得到）；_log_file 留 None
        _logger.warning("无法写入日志文件 %s，仅输出到 stderr", path)
    return _logger


def get_logger(name: str = "") -> logging.Logger:
    return logging.getLogger("pihy2" + (f".{name}" if name else ""))


def new_request_id() -> str:
    return secrets.token_hex(4)


def bind_request_id(rid: str | None = None) -> str:
    """为当前上下文绑定一个请求 ID（webui 在每个请求入口调用）。返回绑定后的 ID。"""
    rid = rid or new_request_id()
    _reqid.set(rid)
    return rid


def get_request_id() -> str:
    return _reqid.get()


def read_logs(lines: int = 200, level: str = "", grep: str = "") -> list:
    """读取并过滤日志文件尾部，供 `pihy2 logs` 与 /api/logs 复用。

    level/grep 都是对“格式化后整行”做子串过滤（level 匹配形如 " WARNING "，grep 大小写不敏感）。
    文件不存在/不可读时返回一条提示行，绝不抛——日志查看本身不该再制造异常。"""
    path = _log_file or DEFAULT_LOG_FILE
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            buf = f.readlines()
    except OSError as e:
        return [f"（无法读取日志 {path}：{e}）\n"]
    if level:
        token = f" {level.upper()} "
        buf = [ln for ln in buf if token in ln]
    if grep:
        gl = grep.lower()
        buf = [ln for ln in buf if gl in ln.lower()]
    return buf[-lines:] if lines else buf
