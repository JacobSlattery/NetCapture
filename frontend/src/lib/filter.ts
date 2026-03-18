/**
 * Wireshark-style display filter — parser, validator, and evaluator.
 *
 * Grammar:
 *   filter     := or_expr
 *   or_expr    := and_expr (('||' | 'or')  and_expr)*
 *   and_expr   := not_expr (('&&' | 'and') not_expr)*
 *   not_expr   := ('!' | 'not') not_expr | atom
 *   atom       := '(' filter ')' | comparison | bare_word
 *   comparison := field ('==' | '!=' | 'contains') value
 *   bare_word  := word  (shorthand: treated as proto == word)
 *
 * Fields:
 *   ip.src                     source IP  (exact)
 *   ip.dst                     destination IP  (exact)
 *   ip.addr                    source OR destination IP  (exact)
 *   port                       source OR destination port  (exact int)
 *   src.port  / tcp.srcport    source port  (exact int)
 *   dst.port  / tcp.dstport    destination port  (exact int)
 *   proto     / ip.proto       protocol name  (case-insensitive exact)
 *   info      / frame.info     info string  (case-insensitive contains via ==)
 *
 * Operators:
 *   ==        exact match (port: int eq; IP: exact; proto: case-insensitive exact;
 *                          info: case-insensitive substring)
 *   !=        inverse of ==
 *   contains  case-insensitive substring match (all field types)
 *
 * Examples:
 *   ip.src == 192.168.1.1
 *   ip.src == 192.168.1.1 || ip.src == 10.0.0.1
 *   ip.addr == 192.168.1.1 && port == 80
 *   not arp
 *   udp && port == 9001
 *   !(ip.dst == 192.168.1.1) && udp
 *   info contains "handshake"
 *   proto != ICMP
 */

import type { Packet, DecodedValue, AddressBookEntry } from './types'

// ── Address book resolution ────────────────────────────────────────────────────
// Module-level mirror updated via setAddressBook() from captureService.

let _addressBook: AddressBookEntry[] = []

export function setAddressBook(book: AddressBookEntry[]): void {
  _addressBook = book
}

/** Resolve an IP (and optional port) to a name.  Returns the raw IP if not found. */
function resolveAddr(ip: string, port: number | null): string {
  const ipLower = (ip ?? '').toLowerCase()
  if (port != null) {
    const key = `${ipLower}:${port}`
    const hit = _addressBook.find(e => e.address.toLowerCase() === key)
    if (hit) return hit.name.toLowerCase()
  }
  const hit = _addressBook.find(e => e.address.toLowerCase() === ipLower)
  return hit?.name.toLowerCase() ?? ipLower
}

// ── DecodedValue flattening ────────────────────────────────────────────────────
// For primitives returns [String(v)].
// For arrays/dicts recursively collects all leaf strings so that `contains`
// and `==` work intuitively on nested interpreter values.

function flattenDecoded(v: DecodedValue): string[] {
  if (v === null || v === undefined) return []
  if (typeof v === 'string')  return [v.toLowerCase()]
  if (typeof v === 'number')  return [String(v)]
  if (typeof v === 'boolean') return [String(v)]
  if (Array.isArray(v)) return v.flatMap(item => flattenDecoded(item as DecodedValue))
  return Object.values(v as Record<string, DecodedValue>).flatMap(item => flattenDecoded(item))
}

/**
 * Navigate a decoded value along a dot-separated path, then flatten the result.
 * e.g. path ['fw'] on {fw: '1.2.3', board: 'A'} → ['1.2.3']
 * Arrays are searched element-by-element at each step.
 */
function resolveDecodedPath(v: DecodedValue, path: string[]): string[] {
  if (path.length === 0) return flattenDecoded(v)
  const [head, ...rest] = path
  if (Array.isArray(v))
    return v.flatMap(item => resolveDecodedPath(item as DecodedValue, path))
  if (typeof v === 'object' && v !== null) {
    const obj = v as Record<string, DecodedValue>
    const key = Object.keys(obj).find(k => k.toLowerCase() === head)
    if (key === undefined) return []
    return resolveDecodedPath(obj[key], rest)
  }
  return []  // primitive with remaining path segments — no match
}

// ── Token types ───────────────────────────────────────────────────────────────

type TokKind = 'word' | 'eq' | 'neq' | 'contains' | 'and' | 'or' | 'not' | 'lp' | 'rp'
interface Token { kind: TokKind; value: string }

export const KNOWN_FIELDS = new Set([
  'ip.src', 'ip.dst', 'ip.addr',
  'src_name', 'dst_name', 'addr_name',
  'port', 'src.port', 'dst.port',
  'tcp.srcport', 'tcp.dstport',
  'udp.srcport', 'udp.dstport',
  'tcp.port', 'udp.port',
  'proto', 'ip.proto', 'protocol',
  'info', 'frame.info',
  'interpreter',
])

// ── Tokenizer ─────────────────────────────────────────────────────────────────

export function tokenize(src: string): Token[] {
  const out: Token[] = []
  let i = 0
  while (i < src.length) {
    if (/\s/.test(src[i])) { i++; continue }

    // Quoted string
    if (src[i] === '"' || src[i] === "'") {
      const q = src[i++]; let s = ''
      while (i < src.length && src[i] !== q) {
        if (src[i] === '\\') i++
        s += src[i++]
      }
      if (i >= src.length) throw new Error('Unterminated string literal')
      i++
      out.push({ kind: 'word', value: s })
      continue
    }

    const two = src.slice(i, i + 2)
    if (two === '==') { out.push({ kind: 'eq',  value: '==' }); i += 2; continue }
    if (two === '!=') { out.push({ kind: 'neq', value: '!=' }); i += 2; continue }
    if (two === '&&') { out.push({ kind: 'and', value: '&&' }); i += 2; continue }
    if (two === '||') { out.push({ kind: 'or',  value: '||' }); i += 2; continue }

    if (src[i] === '!') { out.push({ kind: 'not', value: '!' }); i++; continue }
    if (src[i] === '(') { out.push({ kind: 'lp',  value: '(' }); i++; continue }
    if (src[i] === ')') { out.push({ kind: 'rp',  value: ')' }); i++; continue }

    if (/[\w.]/.test(src[i])) {
      let w = ''
      while (i < src.length && /[\w.\-:/]/.test(src[i])) w += src[i++]
      const lower = w.toLowerCase()
      if      (lower === 'and')      out.push({ kind: 'and',      value: w })
      else if (lower === 'or')       out.push({ kind: 'or',       value: w })
      else if (lower === 'not')      out.push({ kind: 'not',      value: w })
      else if (lower === 'contains') out.push({ kind: 'contains', value: w })
      else                           out.push({ kind: 'word',     value: w })
      continue
    }

    throw new Error(`Unexpected character '${src[i]}' at position ${i}`)
  }
  return out
}

// ── AST ───────────────────────────────────────────────────────────────────────

type Expr =
  | { kind: 'and';  left: Expr; right: Expr }
  | { kind: 'or';   left: Expr; right: Expr }
  | { kind: 'not';  expr: Expr }
  | { kind: 'cmp';  field: string; op: string; value: string }
  | { kind: 'bare'; value: string }

// ── Parser ────────────────────────────────────────────────────────────────────

class Parser {
  private i = 0
  constructor(private readonly tokens: Token[]) {}

  private peek()  { return this.tokens[this.i]     }
  private next()  { return this.tokens[this.i++]   }
  private eat(k: TokKind): Token {
    const t = this.next()
    if (!t)          throw new Error(`Expected ${k} but reached end of filter`)
    if (t.kind !== k) throw new Error(`Expected ${k}, got '${t.value}'`)
    return t
  }

  parse(): Expr {
    if (!this.tokens.length) throw new Error('Filter is empty')
    const e = this.parseOr()
    if (this.peek()) throw new Error(`Unexpected '${this.peek()!.value}'`)
    return e
  }

  private parseOr(): Expr {
    let e = this.parseAnd()
    while (this.peek()?.kind === 'or') {
      this.next(); e = { kind: 'or', left: e, right: this.parseAnd() }
    }
    return e
  }

  private parseAnd(): Expr {
    let e = this.parseNot()
    while (this.peek()?.kind === 'and') {
      this.next(); e = { kind: 'and', left: e, right: this.parseNot() }
    }
    return e
  }

  private parseNot(): Expr {
    if (this.peek()?.kind === 'not') {
      this.next()
      return { kind: 'not', expr: this.parseNot() }
    }
    return this.parseAtom()
  }

  private parseAtom(): Expr {
    const t = this.peek()
    if (!t) throw new Error('Expected an expression')

    if (t.kind === 'lp') {
      this.next()
      const e = this.parseOr()
      this.eat('rp')
      return e
    }

    if (t.kind === 'word') {
      const wordTok = this.next()!
      const field   = wordTok.value.toLowerCase()
      const op      = this.peek()

      if (op?.kind === 'eq' || op?.kind === 'neq' || op?.kind === 'contains') {
        if (!KNOWN_FIELDS.has(field) && !field.startsWith('decoded.')) {
          throw new Error(`Unknown field '${wordTok.value}'`)
        }
        this.next()   // consume operator
        const valTok = this.peek()
        if (!valTok || valTok.kind !== 'word') {
          throw new Error(`Expected a value after '${op.value}'`)
        }
        this.next()   // consume value
        return { kind: 'cmp', field, op: op.value, value: valTok.value }
      }

      // Bare word — proto shorthand
      return { kind: 'bare', value: field }
    }

    throw new Error(`Unexpected '${t.value}' — expected a field name, protocol, or '('`)
  }
}

// ── Evaluator ─────────────────────────────────────────────────────────────────

const PORT_FIELDS = new Set([
  'port', 'src.port', 'dst.port',
  'tcp.port', 'udp.port',
  'tcp.srcport', 'tcp.dstport',
  'udp.srcport', 'udp.dstport',
])

function evalExpr(e: Expr, p: Packet): boolean {
  switch (e.kind) {
    case 'and':  return evalExpr(e.left, p) && evalExpr(e.right, p)
    case 'or':   return evalExpr(e.left, p) || evalExpr(e.right, p)
    case 'not':  return !evalExpr(e.expr, p)
    case 'bare': return (p.protocol ?? '').toLowerCase() === e.value
    case 'cmp':  return evalCmp(e.field, e.op, e.value, p)
  }
}

function evalCmp(field: string, op: string, rawValue: string, p: Packet): boolean {
  const v       = rawValue.toLowerCase()
  const srcPort = String(p.src_port ?? '')
  const dstPort = String(p.dst_port ?? '')

  // Resolve field to one or more candidate strings
  let candidates: string[]
  switch (field) {
    case 'ip.src':   candidates = [(p.src_ip ?? '').toLowerCase(), resolveAddr(p.src_ip, p.src_port)]; break
    case 'ip.dst':   candidates = [(p.dst_ip ?? '').toLowerCase(), resolveAddr(p.dst_ip, p.dst_port)]; break
    case 'ip.addr':  candidates = [(p.src_ip ?? '').toLowerCase(), (p.dst_ip ?? '').toLowerCase(),
                                    resolveAddr(p.src_ip, p.src_port), resolveAddr(p.dst_ip, p.dst_port)]; break
    case 'src_name': candidates = [resolveAddr(p.src_ip, p.src_port)]; break
    case 'dst_name': candidates = [resolveAddr(p.dst_ip, p.dst_port)]; break
    case 'addr_name': candidates = [resolveAddr(p.src_ip, p.src_port), resolveAddr(p.dst_ip, p.dst_port)]; break
    case 'port': case 'tcp.port': case 'udp.port':          candidates = [srcPort, dstPort]; break
    case 'src.port': case 'tcp.srcport': case 'udp.srcport': candidates = [srcPort]; break
    case 'dst.port': case 'tcp.dstport': case 'udp.dstport': candidates = [dstPort]; break
    case 'proto': case 'ip.proto': case 'protocol':        candidates = [(p.protocol ?? '').toLowerCase()]; break
    case 'info':  case 'frame.info':                        candidates = [(p.info    ?? '').toLowerCase()]; break
    case 'interpreter':                                     candidates = [(p.decoded?.interpreterName ?? '').toLowerCase()]; break
    default: {
      // decoded.<key> — look up in interpreter fields, flatten nested structures
      if (field.startsWith('decoded.')) {
        const [fieldKey, ...nestedPath] = field.slice('decoded.'.length).split('.')
        const f = p.decoded?.fields.find(df => df.key.toLowerCase() === fieldKey)
        candidates = f !== undefined ? resolveDecodedPath(f.value, nestedPath) : []
        break
      }
      return false
    }
  }

  const isPort = PORT_FIELDS.has(field)

  switch (op) {
    case '==':
      // Ports: exact int equality.  IP/proto: exact.  Info: substring (like Wireshark).
      return isPort
        ? candidates.some(c => c === v)
        : field === 'info' || field === 'frame.info'
          ? candidates.some(c => c.includes(v))
          : candidates.some(c => c === v)

    case '!=':
      return isPort
        ? candidates.every(c => c !== v)
        : field === 'info' || field === 'frame.info'
          ? candidates.every(c => !c.includes(v))
          : candidates.every(c => c !== v)

    case 'contains':
      return candidates.some(c => c.includes(v))

    default:
      return false
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

export interface ParseResult {
  valid:  boolean
  error?: string
  _expr?: Expr   // internal — consumed by matchesFilter
}

export function parseFilter(raw: string): ParseResult {
  const trimmed = raw.trim()
  if (!trimmed) return { valid: true }
  try {
    const tokens = tokenize(trimmed)
    const expr   = new Parser(tokens).parse()
    return { valid: true, _expr: expr }
  } catch (err) {
    return { valid: false, error: (err as Error).message }
  }
}

export function matchesFilter(p: Packet, result: ParseResult): boolean {
  if (!result._expr) return true   // empty or invalid → show everything
  return evalExpr(result._expr, p)
}
