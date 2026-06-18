"""极简 YAML 读取器——只为解析 Clash/mihomo 订阅里的 proxies 段，零依赖。

支持该场景需要的子集：
  * 块状映射（key: value / key: 后接缩进子结构）
  * 块状序列（- item / - key: value）
  * 流式 {a: b, c: [d, e]} 与 [a, b]
  * 单/双引号标量、布尔/null/整数/浮点、UTF-8（中文节点名）
不追求完整 YAML 规范；解析失败时调用方应回退到“暂不支持”，不影响其它功能。
"""

from __future__ import annotations


class YamlError(ValueError):
    pass


def _strip_comment(line: str) -> str:
    """去掉行内 # 注释（引号内的 # 不算）。"""
    out, q, i = [], None, 0
    while i < len(line):
        c = line[i]
        if q:
            out.append(c)
            if c == "\\" and q == '"' and i + 1 < len(line):
                out.append(line[i + 1]); i += 2; continue
            if c == q:
                q = None
        elif c in ('"', "'"):
            q = c; out.append(c)
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        else:
            out.append(c)
        i += 1
    return "".join(out).rstrip()


def _unquote(v: str) -> str:
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        s = v[1:-1]
        if v[0] == '"':
            s = s.replace('\\"', '"').replace("\\\\", "\\")
        else:
            s = s.replace("''", "'")
        return s
    return v


def _scalar(v: str):
    v = v.strip()
    if v == "" or v == "~" or v.lower() == "null":
        return None
    if v[0] in "[{":
        val, rest = _parse_flow(v)
        if rest.strip():
            raise YamlError(f"流式标量解析残留: {rest!r}")
        return val
    if v[0] in ("'", '"'):
        return _unquote(v)
    low = v.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v


# ---------------------------------------------------------------- 流式 {}/[]
def _parse_flow(s: str):
    s = s.lstrip()
    if s[0] == "[":
        return _parse_flow_seq(s)
    if s[0] == "{":
        return _parse_flow_map(s)
    raise YamlError("非流式起始")


def _read_flow_token(s: str) -> tuple[str, str]:
    """读到下一个顶层 , 或 终止符；返回 (token, 剩余从分隔符开始)。"""
    depth, q, i = 0, None, 0
    while i < len(s):
        c = s[i]
        if q:
            if c == "\\" and q == '"' and i + 1 < len(s):
                i += 2; continue
            if c == q:
                q = None
        elif c in ('"', "'"):
            q = c
        elif c in "[{":
            depth += 1
        elif c in "]}":
            if depth == 0:
                break
            depth -= 1
        elif c == "," and depth == 0:
            break
        i += 1
    return s[:i], s[i:]


def _parse_flow_seq(s: str):
    s = s[1:]  # skip [
    items = []
    while True:
        s = s.lstrip()
        if s.startswith("]"):
            return items, s[1:]
        if not s:
            raise YamlError("流式序列未闭合")
        tok, s = _read_flow_token(s)
        items.append(_scalar(tok.strip()))
        s = s.lstrip()
        if s.startswith(","):
            s = s[1:]
        elif s.startswith("]"):
            return items, s[1:]


def _parse_flow_map(s: str):
    s = s[1:]  # skip {
    d = {}
    while True:
        s = s.lstrip()
        if s.startswith("}"):
            return d, s[1:]
        if not s:
            raise YamlError("流式映射未闭合")
        tok, s = _read_flow_token(s)
        key, _, val = tok.partition(":")
        d[_unquote(key.strip())] = _scalar(val.strip())
        s = s.lstrip()
        if s.startswith(","):
            s = s[1:]
        elif s.startswith("}"):
            return d, s[1:]


# ---------------------------------------------------------------- 块状
def _split_kv(text: str) -> tuple[str, str | None]:
    """拆 `key: value`，返回 (key, value-or-None)。冒号需在引号外。"""
    q, i = None, 0
    while i < len(text):
        c = text[i]
        if q:
            if c == q:
                q = None
        elif c in ('"', "'"):
            q = c
        elif c == ":" and (i + 1 == len(text) or text[i + 1] in " \t"):
            return text[:i].strip(), text[i + 1:].strip()
        i += 1
    return text.strip(), None


class _Reader:
    def __init__(self, text: str):
        self.lines = []
        for raw in text.replace("\t", "    ").splitlines():
            s = _strip_comment(raw)
            if not s.strip() or s.strip() in ("---", "..."):
                continue
            indent = len(s) - len(s.lstrip(" "))
            self.lines.append((indent, s.strip()))
        self.i = 0

    def parse(self):
        if not self.lines:
            return None
        return self._block(self.lines[0][0])

    def _block(self, indent: int):
        ind, text = self.lines[self.i]
        if text.startswith("- ") or text == "-":
            return self._seq(indent)
        return self._map(indent)

    def _map(self, indent: int):
        d = {}
        while self.i < len(self.lines):
            ind, text = self.lines[self.i]
            if ind < indent:
                break
            if ind > indent:
                raise YamlError(f"缩进异常: {text!r}")
            key, val = _split_kv(text)
            key = _unquote(key)
            if val is None or val == "":
                self.i += 1
                if self.i < len(self.lines) and self.lines[self.i][0] > indent:
                    d[key] = self._block(self.lines[self.i][0])
                else:
                    d[key] = None
            else:
                d[key] = _scalar(val)
                self.i += 1
        return d

    def _seq(self, indent: int):
        items = []
        while self.i < len(self.lines):
            ind, text = self.lines[self.i]
            if ind < indent or not (text.startswith("- ") or text == "-"):
                break
            if ind > indent:
                raise YamlError(f"序列缩进异常: {text!r}")
            rest = text[1:].strip()
            if rest == "":                          # '-' 后接缩进块
                self.i += 1
                if self.i < len(self.lines) and self.lines[self.i][0] > indent:
                    items.append(self._block(self.lines[self.i][0]))
                else:
                    items.append(None)
            elif rest[0] in "[{":                   # 流式
                items.append(_scalar(rest))
                self.i += 1
            else:
                k, v = _split_kv(rest)
                if v is None:                       # 纯标量项
                    items.append(_scalar(rest))
                    self.i += 1
                else:                               # `- key: value`：行内映射起始
                    item = {}
                    # key 的实际列 = "- " 之后的列
                    key_col = ind + (len(text) - len(rest))
                    item[_unquote(k)] = _scalar(v) if v != "" else self._inline_nested(key_col)
                    self.i += 1
                    # 同一映射的后续键，缩进 = key_col
                    while self.i < len(self.lines) and self.lines[self.i][0] == key_col \
                            and not self.lines[self.i][1].startswith("- "):
                        kk, vv = _split_kv(self.lines[self.i][1])
                        kk = _unquote(kk)
                        if vv is None or vv == "":
                            self.i += 1
                            if self.i < len(self.lines) and self.lines[self.i][0] > key_col:
                                item[kk] = self._block(self.lines[self.i][0])
                            else:
                                item[kk] = None
                        else:
                            item[kk] = _scalar(vv)
                            self.i += 1
                    items.append(item)
        return items

    def _inline_nested(self, key_col: int):
        # `- key:` 后面跟缩进子块（少见），返回该子块
        if self.i + 1 < len(self.lines) and self.lines[self.i + 1][0] > key_col:
            self.i += 1
            return self._block(self.lines[self.i][0])
        return None


def load(text: str):
    """解析 YAML 文本为 Python 对象；失败抛 YamlError。"""
    try:
        return _Reader(text).parse()
    except (IndexError, ValueError) as e:
        raise YamlError(str(e))
