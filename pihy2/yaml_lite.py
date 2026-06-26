"""极简 YAML 读取器——只为解析 Clash/mihomo 订阅里的 proxies 段，零依赖。

支持该场景需要的子集：
  * 块状映射（key: value / key: 后接缩进子结构）
  * 块状序列（- item / - key: value）
  * 流式 {a: b, c: [d, e]} 与 [a, b]
  * 单/双引号标量、布尔/null/整数/浮点、UTF-8（中文节点名）
  * 块标量 | 与 >（尽力而为，避免含证书/多行内容的订阅整体解析失败）
  * 锚点 &name / 别名 *name / 合并键 <<:（常见于聚合配置）
  * 多文档（--- 分隔）：只取第一个文档，避免后文档键覆盖前文档丢节点
不追求完整 YAML 规范；解析失败时调用方应回退到“暂不支持”，不影响其它功能。
"""

from __future__ import annotations

import re


class YamlError(ValueError):
    pass


# 块标量起始记号：| 或 >，可带 chomping/缩进指示（如 |-、>+、|2），且其后无其它内容
_BLOCK_SCALAR_RE = re.compile(r"^[|>][+-]?\d*$")


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
        try:
            val, rest = _parse_flow(v)
            if not rest.strip():
                return val
        except YamlError:
            pass
        # 不是合法流式标量（如恰好以 [ / { 开头的密码、节点名、证书片段）：按普通字符串处理，
        # 避免一个字段的流式解析失败把整篇订阅（document 级 except）的所有节点一起丢掉（ROBUST-1）。
        return v
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
        self.full: list[str] = []     # 与 self.lines 同序对齐：保留缩进的整行（供块标量按相对缩进还原）
        for raw in text.splitlines():
            # 仅把行首缩进里的 tab 折算成空格；行内（尤其是引号字符串里的真实 \t，
            # 如 header/password）原样保留，避免被悄悄替换成 4 个空格造成数据损坏
            body = raw.lstrip(" \t")
            lead = raw[:len(raw) - len(body)].replace("\t", "    ")
            s = _strip_comment(lead + body)
            stripped = s.strip()
            if stripped in ("---", "..."):
                if self.lines:        # 多文档：只解析第一个，避免后文档键覆盖前者丢节点
                    break
                continue
            if not stripped:
                continue
            indent = len(s) - len(s.lstrip(" "))
            self.lines.append((indent, stripped))
            self.full.append(s)
        self.i = 0
        self.anchors: dict[str, object] = {}

    def parse(self):
        if not self.lines:
            return None
        # 整份文档即一个流式标量（{...} / [...]）时，按流式解析；否则按块状结构
        if self.lines[0][1][:1] in "[{":
            return _scalar(self.lines[0][1])
        return self._block(self.lines[0][0])

    def _block(self, indent: int):
        ind, text = self.lines[self.i]
        if text.startswith("- ") or text == "-":
            return self._seq(indent)
        return self._map(indent)

    # 合并键 <<:（把别名指向的映射并入当前 dict，已存在的键不覆盖）
    def _assign(self, d: dict, key: str, value):
        if key == "<<":
            merges = value if isinstance(value, list) else [value]
            for m in merges:
                # `<<: [*a, *b]`（流式别名列表，聚合配置常见）里别名是字面字符串 '*a'，
                # 流式解析不认锚点；在合并时按当前锚点表解析，否则所有被合并的键被静默丢弃（BUG-2）。
                if isinstance(m, str) and m.startswith("*"):
                    m = self.anchors.get(m[1:].strip())
                if isinstance(m, dict):
                    for k, v in m.items():
                        d.setdefault(k, v)
            return
        d[key] = value

    # 标量位置：解析 &anchor 定义 / *alias 引用 / 普通标量
    def _resolve_scalar(self, val: str):
        val = val.strip()
        if val.startswith("&"):
            name, _, rest = val[1:].partition(" ")
            v = _scalar(rest) if rest.strip() else None
            self.anchors[name] = v
            return v
        if val.startswith("*"):
            return self.anchors.get(val[1:].strip())
        return _scalar(val)

    def _block_scalar(self, indent: int, indicator: str = "|") -> str:
        """收集所有缩进大于 indent 的后续行作为块标量字符串（尽力而为）。
        indicator 形如 |、>、|-、>+ 等：> 折叠换行为空格，| 保留换行；'-' 去尾随换行。
        用保留缩进的整行（self.full）并按块内最小缩进统一左移，保留 PEM/多行内容的相对缩进。"""
        rows = []
        while self.i < len(self.lines) and self.lines[self.i][0] > indent:
            rows.append(self.full[self.i])
            self.i += 1
        if not rows:
            return ""
        base = min(len(r) - len(r.lstrip(" ")) for r in rows)
        parts = [r[base:] for r in rows]
        sep = " " if indicator.startswith(">") else "\n"
        text = sep.join(parts)
        if indicator.endswith("-"):     # chomping '-'(strip)：去尾随换行；默认/'+' 保持
            text = text.rstrip("\n")
        return text

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
            self._consume_value(d, key, val, indent)
        return d

    def _child_block_indent(self, col: int):
        """key 行已被消费、self.i 指向下一行时，判断该行是否是本 key 的块状值。

        返回应下钻的缩进列，或 None（无子块，值为 null）。子块有两种合法形态：
          1) 更深缩进的子映射/子序列（indent > col）；
          2) 与 key **同列**的块状序列——`- ` 标记本身提供缩进，YAML 允许
             `proxies:\\n- a\\n- b` 这种零缩进列表（PyYAML 默认导出 / 多数订阅商格式）。
        """
        if self.i >= len(self.lines):
            return None
        nind, ntext = self.lines[self.i]
        if nind > col:
            return nind
        if nind == col and (ntext.startswith("- ") or ntext == "-"):
            return nind
        return None

    def _consume_value(self, container: dict, key: str, val: str | None, col: int):
        """把 `key: val` 的值（含 None/块/块标量/锚点/别名）写入 container[key]。
        调用时 self.i 指向 key 所在行；返回时 self.i 指向下一条待处理行。"""
        if val is None or val == "":
            self.i += 1
            cind = self._child_block_indent(col)
            if cind is not None:
                self._assign(container, key, self._block(cind))
            else:
                self._assign(container, key, None)
        elif _BLOCK_SCALAR_RE.match(val):
            self.i += 1
            self._assign(container, key, self._block_scalar(col, val))
        elif val.startswith("&") and len(val.split()) == 1:
            # 块级锚点：&name 后接缩进子块
            name = val[1:]
            self.i += 1
            cind = self._child_block_indent(col)
            block = self._block(cind) if cind is not None else None
            self.anchors[name] = block
            self._assign(container, key, block)
        else:
            self._assign(container, key, self._resolve_scalar(val))
            self.i += 1

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
            elif rest.startswith("&") and len(rest.split()) == 1:
                # `- &anchor` 后接缩进子映射/子序列（聚合/手写配置常给整条 proxy 起锚点）。
                # 旧逻辑把 '&anchor' 当纯标量、anchors[x]=None，后续缩进行触发“缩进异常”毁掉整篇（BUG-3）。
                name = rest[1:]
                self.i += 1
                if self.i < len(self.lines) and self.lines[self.i][0] > indent:
                    block = self._block(self.lines[self.i][0])
                else:
                    block = None
                self.anchors[name] = block
                items.append(block)
            else:
                k, v = _split_kv(rest)
                if v is None:                       # 纯标量项
                    items.append(self._resolve_scalar(rest))
                    self.i += 1
                else:                               # `- key: value`：行内映射起始
                    item: dict = {}
                    # key 的实际列 = "- " 之后的列
                    key_col = ind + (len(text) - len(rest))
                    kk0 = _unquote(k)
                    if v == "":
                        # 首键无行内值：可能后接更深缩进子块，或与 key 同列的块状序列（零缩进列表）。
                        # 复用 _child_block_indent，与 _consume_value 保持一致——避免漏判同列序列（否则
                        # 整条订阅可能解析失败），也避免吞行。
                        self.i += 1
                        cind = self._child_block_indent(key_col)
                        self._assign(item, kk0, self._block(cind) if cind is not None else None)
                    elif _BLOCK_SCALAR_RE.match(v):
                        self.i += 1
                        self._assign(item, kk0, self._block_scalar(key_col, v))
                    else:
                        self._assign(item, kk0, self._resolve_scalar(v))
                        self.i += 1
                    # 同一映射的后续键，缩进 = key_col
                    while self.i < len(self.lines) and self.lines[self.i][0] == key_col \
                            and not self.lines[self.i][1].startswith("- "):
                        kk, vv = _split_kv(self.lines[self.i][1])
                        kk = _unquote(kk)
                        self._consume_value(item, kk, vv, key_col)
                    items.append(item)
        return items


def load(text: str):
    """解析 YAML 文本为 Python 对象；失败抛 YamlError。"""
    try:
        return _Reader(text).parse()
    except (IndexError, ValueError, RecursionError) as e:
        raise YamlError(str(e))
