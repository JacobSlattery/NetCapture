"""
tests/test_filter.py — Unit tests for the Wireshark-style filter parser and evaluator.

Covers tokenizer, parser, evaluator, filter_uses_decoded, and edge cases.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from netcapture._filter import (  # noqa: E402
    _filter_tokenize,
    _flatten_decoded,
    _resolve_decoded_path,
    _FilterParser,
    filter_eval,
    filter_uses_decoded,
    parse_filter,
)


# ── Tokenizer ────────────────────────────────────────────────────────────────

class TestTokenizer:
    def test_simple_eq(self):
        tokens = _filter_tokenize('ip.src == 10.0.0.1')
        assert tokens == [('word', 'ip.src'), ('eq', '=='), ('word', '10.0.0.1')]

    def test_neq(self):
        tokens = _filter_tokenize('port != 80')
        assert tokens == [('word', 'port'), ('neq', '!='), ('word', '80')]

    def test_and_or(self):
        tokens = _filter_tokenize('tcp && port == 80 || udp')
        kinds = [t[0] for t in tokens]
        assert 'and' in kinds
        assert 'or' in kinds

    def test_word_and_or(self):
        tokens = _filter_tokenize('tcp and port == 80 or udp')
        kinds = [t[0] for t in tokens]
        assert kinds.count('and') == 1
        assert kinds.count('or') == 1

    def test_not_operator(self):
        tokens = _filter_tokenize('!tcp')
        assert tokens == [('not', '!'), ('word', 'tcp')]

    def test_word_not(self):
        tokens = _filter_tokenize('not tcp')
        assert tokens == [('not', 'not'), ('word', 'tcp')]

    def test_parens(self):
        tokens = _filter_tokenize('(tcp)')
        assert tokens == [('lp', '('), ('word', 'tcp'), ('rp', ')')]

    def test_contains(self):
        tokens = _filter_tokenize('info contains hello')
        assert tokens == [('word', 'info'), ('contains', 'contains'), ('word', 'hello')]

    def test_quoted_string(self):
        tokens = _filter_tokenize('info == "hello world"')
        assert tokens[2] == ('word', 'hello world')

    def test_single_quoted_string(self):
        tokens = _filter_tokenize("info == 'hello world'")
        assert tokens[2] == ('word', 'hello world')

    def test_escaped_quote(self):
        tokens = _filter_tokenize(r'info == "he said \"hi\""')
        assert tokens[2] == ('word', 'he said "hi"')

    def test_unterminated_string(self):
        with pytest.raises(ValueError, match="Unterminated"):
            _filter_tokenize('info == "oops')

    def test_unexpected_char(self):
        with pytest.raises(ValueError, match="Unexpected character"):
            _filter_tokenize('info == @bad')

    def test_whitespace_only(self):
        assert _filter_tokenize('   ') == []

    def test_colons_not_in_bare_word(self):
        # Bare ':' is not a valid word char — must be quoted
        with pytest.raises(ValueError, match="Unexpected character"):
            _filter_tokenize('ip.src == ::1')

    def test_colon_in_quoted_string(self):
        tokens = _filter_tokenize('ip.src == "::1"')
        assert tokens[2] == ('word', '::1')

    def test_dashes_in_word(self):
        tokens = _filter_tokenize('interpreter == nc-frame')
        assert tokens[2] == ('word', 'nc-frame')


# ── Parser ───────────────────────────────────────────────────────────────────

class TestParser:
    def test_bare_word(self):
        ast = parse_filter('tcp')
        assert ast == ('bare', 'tcp')

    def test_comparison(self):
        ast = parse_filter('ip.src == 10.0.0.1')
        assert ast == ('cmp', 'ip.src', '==', '10.0.0.1')

    def test_neq_comparison(self):
        ast = parse_filter('port != 80')
        assert ast == ('cmp', 'port', '!=', '80')

    def test_contains_comparison(self):
        ast = parse_filter('info contains hello')
        assert ast == ('cmp', 'info', 'contains', 'hello')

    def test_and(self):
        ast = parse_filter('tcp && port == 80')
        assert ast[0] == 'and' # type: ignore

    def test_or(self):
        ast = parse_filter('tcp || udp')
        assert ast[0] == 'or' # type: ignore

    def test_not(self):
        ast = parse_filter('!tcp')
        assert ast == ('not', ('bare', 'tcp'))

    def test_parens(self):
        ast = parse_filter('(tcp || udp) && port == 80')
        assert ast[0] == 'and' # type: ignore
        assert ast[1][0] == 'or' # type: ignore

    def test_nested_not(self):
        ast = parse_filter('!!tcp')
        assert ast == ('not', ('not', ('bare', 'tcp')))

    def test_empty_filter(self):
        assert parse_filter('') is None
        assert parse_filter('   ') is None

    def test_unknown_field_raises(self):
        # parse_filter catches ValueError and returns None
        ast = parse_filter('badfield == value')
        assert ast is None

    def test_decoded_field_allowed(self):
        ast = parse_filter('decoded.temp == 23')
        assert ast == ('cmp', 'decoded.temp', '==', '23')

    def test_extra_tokens_rejected(self):
        ast = parse_filter('tcp udp')
        assert ast is None  # parse error → None

    def test_missing_value_after_op(self):
        ast = parse_filter('port ==')
        assert ast is None


# ── Evaluator ────────────────────────────────────────────────────────────────

class TestFilterEval:
    PKT = {
        "protocol": "TCP",
        "src_ip": "192.168.1.1",
        "dst_ip": "10.0.0.2",
        "src_port": 54321,
        "dst_port": 80,
        "info": "[SYN] 192.168.1.1:54321 → 10.0.0.2:80",
        "decoded": None,
    }

    def test_bare_protocol_match(self):
        ast = parse_filter('tcp')
        assert filter_eval(ast, self.PKT) is True

    def test_bare_protocol_no_match(self):
        ast = parse_filter('udp')
        assert filter_eval(ast, self.PKT) is False

    def test_ip_src(self):
        ast = parse_filter('ip.src == 192.168.1.1')
        assert filter_eval(ast, self.PKT) is True

    def test_ip_dst(self):
        ast = parse_filter('ip.dst == 10.0.0.2')
        assert filter_eval(ast, self.PKT) is True

    def test_ip_addr_matches_either(self):
        ast = parse_filter('ip.addr == 192.168.1.1')
        assert filter_eval(ast, self.PKT) is True
        ast2 = parse_filter('ip.addr == 10.0.0.2')
        assert filter_eval(ast2, self.PKT) is True

    def test_port_matches_either(self):
        ast = parse_filter('port == 80')
        assert filter_eval(ast, self.PKT) is True
        ast2 = parse_filter('port == 54321')
        assert filter_eval(ast2, self.PKT) is True

    def test_src_port(self):
        ast = parse_filter('src.port == 54321')
        assert filter_eval(ast, self.PKT) is True
        ast2 = parse_filter('src.port == 80')
        assert filter_eval(ast2, self.PKT) is False

    def test_dst_port(self):
        ast = parse_filter('dst.port == 80')
        assert filter_eval(ast, self.PKT) is True

    def test_neq(self):
        ast = parse_filter('port != 443')
        assert filter_eval(ast, self.PKT) is True

    def test_neq_matches_one(self):
        # port != 80 — dst_port IS 80, so this should be false
        ast = parse_filter('port != 80')
        assert filter_eval(ast, self.PKT) is False

    def test_contains(self):
        ast = parse_filter('info contains SYN')
        assert filter_eval(ast, self.PKT) is True

    def test_contains_case_insensitive(self):
        ast = parse_filter('info contains syn')
        assert filter_eval(ast, self.PKT) is True

    def test_info_eq_substring(self):
        # info == is treated as "contains" for info fields
        ast = parse_filter('info == syn')
        assert filter_eval(ast, self.PKT) is True

    def test_and(self):
        ast = parse_filter('tcp && port == 80')
        assert filter_eval(ast, self.PKT) is True

    def test_and_false(self):
        ast = parse_filter('udp && port == 80')
        assert filter_eval(ast, self.PKT) is False

    def test_or(self):
        ast = parse_filter('udp || tcp')
        assert filter_eval(ast, self.PKT) is True

    def test_not(self):
        ast = parse_filter('!udp')
        assert filter_eval(ast, self.PKT) is True

    def test_not_true(self):
        ast = parse_filter('!tcp')
        assert filter_eval(ast, self.PKT) is False

    def test_protocol_field(self):
        ast = parse_filter('protocol == tcp')
        assert filter_eval(ast, self.PKT) is True

    def test_proto_field(self):
        ast = parse_filter('proto == tcp')
        assert filter_eval(ast, self.PKT) is True

    def test_unknown_field_returns_false(self):
        # Manually construct AST with unknown field
        node = ('cmp', 'nonexistent', '==', 'value')
        assert filter_eval(node, self.PKT) is False

    def test_missing_ports(self):
        pkt = {**self.PKT, "src_port": None, "dst_port": None}
        ast = parse_filter('port == 80')
        assert filter_eval(ast, pkt) is False

    def test_interpreter_field(self):
        pkt = {
            **self.PKT,
            "decoded": {"interpreterName": "NC-Frame", "fields": []},
        }
        ast = parse_filter('interpreter == nc-frame')
        assert filter_eval(ast, pkt) is True

    def test_decoded_field(self):
        pkt = {
            **self.PKT,
            "decoded": {
                "interpreterName": "NC-Frame",
                "fields": [{"key": "temp", "value": 23.5}],
            },
        }
        ast = parse_filter('decoded.temp == 23.5')
        assert filter_eval(ast, pkt) is True

    def test_decoded_nested_path(self):
        pkt = {
            **self.PKT,
            "decoded": {
                "interpreterName": "X",
                "fields": [{"key": "status", "value": {"code": 200}}],
            },
        }
        ast = parse_filter('decoded.status.code == 200')
        assert filter_eval(ast, pkt) is True


# ── filter_uses_decoded ──────────────────────────────────────────────────────

class TestFilterUsesDecoded:
    def test_none(self):
        assert filter_uses_decoded(None) is False

    def test_bare(self):
        assert filter_uses_decoded(('bare', 'tcp')) is False

    def test_interpreter(self):
        ast = parse_filter('interpreter == nc-frame')
        assert filter_uses_decoded(ast) is True

    def test_decoded_prefix(self):
        ast = parse_filter('decoded.temp == 23')
        assert filter_uses_decoded(ast) is True

    def test_simple_field(self):
        ast = parse_filter('port == 80')
        assert filter_uses_decoded(ast) is False

    def test_nested_and_with_decoded(self):
        ast = parse_filter('tcp && interpreter == nc-frame')
        assert filter_uses_decoded(ast) is True

    def test_not_decoded(self):
        ast = parse_filter('!interpreter == nc-frame')
        # This parses as !(interpreter == nc-frame)
        assert filter_uses_decoded(ast) is True


# ── _flatten_decoded / _resolve_decoded_path ─────────────────────────────────

class TestDecodedHelpers:
    def test_flatten_none(self):
        assert _flatten_decoded(None) == []

    def test_flatten_bool(self):
        assert _flatten_decoded(True) == ['true']

    def test_flatten_int(self):
        assert _flatten_decoded(42) == ['42']

    def test_flatten_float(self):
        assert _flatten_decoded(3.14) == ['3.14']

    def test_flatten_str(self):
        assert _flatten_decoded('Hello') == ['hello']

    def test_flatten_list(self):
        assert _flatten_decoded([1, 'two', 3]) == ['1', 'two', '3']

    def test_flatten_dict(self):
        result = _flatten_decoded({'a': 1, 'b': 'c'})
        assert '1' in result
        assert 'c' in result

    def test_flatten_nested(self):
        result = _flatten_decoded([{'a': [1, 2]}, 3])
        assert result == ['1', '2', '3']

    def test_flatten_unknown_type(self):
        # Falls back to str(v).lower()
        assert _flatten_decoded(object())[0].startswith('<')

    def test_resolve_empty_path(self):
        assert _resolve_decoded_path(42, []) == ['42']

    def test_resolve_dict(self):
        v = {'Code': 200}
        assert _resolve_decoded_path(v, ['code']) == ['200']

    def test_resolve_missing_key(self):
        v = {'Code': 200}
        assert _resolve_decoded_path(v, ['missing']) == []

    def test_resolve_list_broadcasts(self):
        v = [{'a': 1}, {'a': 2}]
        assert _resolve_decoded_path(v, ['a']) == ['1', '2']

    def test_resolve_scalar_with_path(self):
        assert _resolve_decoded_path(42, ['nested']) == []
