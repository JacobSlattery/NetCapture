"""
Wireshark-style filter parser — mirrors frontend/src/lib/filter.ts.

Supports the same grammar so profile filters and user-typed filters are
interpreted identically on both sides.
"""

from __future__ import annotations

_KNOWN_FILTER_FIELDS = {
    'ip.src', 'ip.dst', 'ip.addr',
    'port', 'src.port', 'dst.port',
    'tcp.port', 'udp.port',
    'tcp.srcport', 'tcp.dstport',
    'udp.srcport', 'udp.dstport',
    'proto', 'ip.proto', 'protocol',
    'info', 'frame.info',
    'interpreter',
}

_PORT_FILTER_FIELDS = {
    'port', 'src.port', 'dst.port',
    'tcp.port', 'udp.port',
    'tcp.srcport', 'tcp.dstport',
    'udp.srcport', 'udp.dstport',
}


def _flatten_decoded(v) -> list[str]:
    """Recursively collect all leaf values from a DecodedValue as lowercase strings."""
    if v is None:
        return []
    if isinstance(v, bool):
        return [str(v).lower()]
    if isinstance(v, (int, float)):
        return [str(v)]
    if isinstance(v, str):
        return [v.lower()]
    if isinstance(v, list):
        out: list[str] = []
        for item in v:
            out.extend(_flatten_decoded(item))
        return out
    if isinstance(v, dict):
        out = []
        for item in v.values():
            out.extend(_flatten_decoded(item))
        return out
    return [str(v).lower()]


def _resolve_decoded_path(v, path: list[str]) -> list[str]:
    """Navigate a decoded value along path segments, then flatten the result."""
    if not path:
        return _flatten_decoded(v)
    head, *rest = path
    if isinstance(v, list):
        out: list[str] = []
        for item in v:
            out.extend(_resolve_decoded_path(item, path))
        return out
    if isinstance(v, dict):
        key = next((k for k in v if k.lower() == head), None)
        if key is None:
            return []
        return _resolve_decoded_path(v[key], rest)
    return []


def _filter_tokenize(src: str) -> list[tuple[str, str]]:
    """Return list of (kind, value) tokens."""
    tokens: list[tuple[str, str]] = []
    i = 0
    while i < len(src):
        if src[i].isspace():
            i += 1
            continue
        if src[i] in ('"', "'"):
            q = src[i]; i += 1; s = ''
            while i < len(src) and src[i] != q:
                if src[i] == '\\':
                    i += 1
                s += src[i]; i += 1
            if i >= len(src):
                raise ValueError('Unterminated string literal')
            i += 1
            tokens.append(('word', s))
            continue
        two = src[i:i+2]
        if two == '==': tokens.append(('eq',  '==')); i += 2; continue
        if two == '!=': tokens.append(('neq', '!=')); i += 2; continue
        if two == '&&': tokens.append(('and', '&&')); i += 2; continue
        if two == '||': tokens.append(('or',  '||')); i += 2; continue
        if src[i] == '!': tokens.append(('not', '!')); i += 1; continue
        if src[i] == '(': tokens.append(('lp',  '(')); i += 1; continue
        if src[i] == ')': tokens.append(('rp',  ')')); i += 1; continue
        if src[i].isalnum() or src[i] in '._':
            w = ''
            while i < len(src) and (src[i].isalnum() or src[i] in '._-:/'):
                w += src[i]; i += 1
            lower = w.lower()
            if   lower == 'and':      tokens.append(('and',      w))
            elif lower == 'or':       tokens.append(('or',       w))
            elif lower == 'not':      tokens.append(('not',      w))
            elif lower == 'contains': tokens.append(('contains', w))
            else:                     tokens.append(('word',     w))
            continue
        raise ValueError(f"Unexpected character '{src[i]}' at position {i}")
    return tokens


class _FilterParser:
    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self._tokens = tokens
        self._i      = 0

    def _peek(self) -> tuple[str, str] | None:
        return self._tokens[self._i] if self._i < len(self._tokens) else None

    def _next(self) -> tuple[str, str]:
        t = self._tokens[self._i]; self._i += 1; return t

    def _eat(self, kind: str) -> tuple[str, str]:
        t = self._next()
        if t[0] != kind:
            raise ValueError(f"Expected {kind}, got '{t[1]}'")
        return t

    def parse(self):  # type: ignore[return]
        if not self._tokens:
            raise ValueError('Empty filter')
        e = self._parse_or()
        if self._peek():
            raise ValueError(f"Unexpected '{self._peek()[1]}'")  # type: ignore[index]
        return e

    def _parse_or(self):
        e = self._parse_and()
        while self._peek() and self._peek()[0] == 'or':
            self._next()
            e = ('or', e, self._parse_and())
        return e

    def _parse_and(self):
        e = self._parse_not()
        while self._peek() and self._peek()[0] == 'and':
            self._next()
            e = ('and', e, self._parse_not())
        return e

    def _parse_not(self):
        if self._peek() and self._peek()[0] == 'not':
            self._next()
            return ('not', self._parse_not())
        return self._parse_atom()

    def _parse_atom(self):
        t = self._peek()
        if not t:
            raise ValueError('Expected an expression')
        if t[0] == 'lp':
            self._next()
            e = self._parse_or()
            self._eat('rp')
            return e
        if t[0] == 'word':
            word_tok = self._next()
            field    = word_tok[1].lower()
            op_tok   = self._peek()
            if op_tok and op_tok[0] in ('eq', 'neq', 'contains'):
                if field not in _KNOWN_FILTER_FIELDS and not field.startswith('decoded.'):
                    raise ValueError(f"Unknown field '{word_tok[1]}'")
                self._next()  # consume op
                val_tok = self._peek()
                if not val_tok or val_tok[0] != 'word':
                    raise ValueError(f"Expected a value after '{op_tok[1]}'")
                self._next()  # consume value
                return ('cmp', field, op_tok[1], val_tok[1])
            return ('bare', field)
        raise ValueError(f"Unexpected '{t[1]}'")


def filter_eval(node, pkt: dict) -> bool:
    kind = node[0]
    if kind == 'and':  return filter_eval(node[1], pkt) and filter_eval(node[2], pkt)
    if kind == 'or':   return filter_eval(node[1], pkt) or  filter_eval(node[2], pkt)
    if kind == 'not':  return not filter_eval(node[1], pkt)
    if kind == 'bare': return (pkt.get('protocol') or '').lower() == node[1]
    if kind == 'cmp':
        _, field, op, raw_val = node
        v        = raw_val.lower()
        src_port = str(pkt.get('src_port') or '')
        dst_port = str(pkt.get('dst_port') or '')
        src_ip   = (pkt.get('src_ip')  or '').lower()
        dst_ip   = (pkt.get('dst_ip')  or '').lower()
        proto    = (pkt.get('protocol') or '').lower()
        info     = (pkt.get('info')    or '').lower()

        if   field == 'ip.src':                                    candidates = [src_ip]
        elif field == 'ip.dst':                                    candidates = [dst_ip]
        elif field == 'ip.addr':                                   candidates = [src_ip, dst_ip]
        elif field in ('port', 'tcp.port', 'udp.port'):            candidates = [src_port, dst_port]
        elif field in ('src.port', 'tcp.srcport', 'udp.srcport'):  candidates = [src_port]
        elif field in ('dst.port', 'tcp.dstport', 'udp.dstport'):  candidates = [dst_port]
        elif field in ('proto', 'ip.proto', 'protocol'):           candidates = [proto]
        elif field in ('info', 'frame.info'):                      candidates = [info]
        elif field == 'interpreter':
            decoded    = pkt.get('decoded') or {}
            candidates = [(decoded.get('interpreterName') or '').lower()]
        elif field.startswith('decoded.'):
            key       = field[len('decoded.'):]
            parts     = key.split('.')
            field_key = parts[0]
            nested    = parts[1:]
            decoded   = pkt.get('decoded') or {}
            fields    = decoded.get('fields') or []
            match     = next((f for f in fields if (f.get('key') or '').lower() == field_key), None)
            candidates = _resolve_decoded_path(match['value'], nested) if match is not None else []
        else:
            return False

        is_port = field in _PORT_FILTER_FIELDS
        is_info = field in ('info', 'frame.info')

        if op in ('==', 'contains'):
            if op == 'contains':
                return any(v in c for c in candidates)
            if is_port:
                return any(c == v for c in candidates)
            if is_info:
                return any(v in c for c in candidates)
            return any(c == v for c in candidates)
        if op == '!=':
            if is_port: return all(c != v for c in candidates)
            if is_info: return all(v not in c for c in candidates)
            return all(c != v for c in candidates)
    return False


def filter_uses_decoded(node) -> bool:
    """
    Return True if the filter AST references interpreter or decoded.* fields.

    When True the interpreter must run *before* the filter, so the filter
    cannot be safely applied as a pre-filter in the capture thread (where
    decoded fields have not yet been populated).
    """
    if node is None:
        return False
    kind = node[0]
    if kind in ('and', 'or'):
        return filter_uses_decoded(node[1]) or filter_uses_decoded(node[2])
    if kind == 'not':
        return filter_uses_decoded(node[1])
    if kind == 'cmp':
        field = node[1]
        return field == 'interpreter' or field.startswith('decoded.')
    return False


def parse_filter(filter_str: str):
    """Parse a filter string into an AST node, or return None on error."""
    trimmed = filter_str.strip()
    if not trimmed:
        return None
    try:
        tokens = _filter_tokenize(trimmed)
        return _FilterParser(tokens).parse()
    except ValueError as exc:
        print(f"[filter] parse error — treating as pass-all: {exc}")
        return None
