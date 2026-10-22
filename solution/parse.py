"""Octra HFHE bounty v2 - public artifact parser (pure python port of pvac_hfhe_cpp@071b0e9).

Provides:
  - range-coder decompression for pk.bin (pvac_compress)
  - pubkey parse (canon_tag, H, ubk, H_digest, omega_B, powg_B)
  - secret.ct bundle parse (layers, c0, edges)
  - public layer aggregate T_l (slot 0) per layer
"""
import struct, hashlib, sys, os, pickle, glob

P = (1 << 127) - 1
MASK63 = (1 << 63) - 1
MASK32 = 0xFFFFFFFF

# ---------------------------------------------------------------- fp arithmetic
def fp(lo, hi):
    """fp_from_words: reduce 128-bit value with top bit folded (p = 2^127-1)."""
    extra = hi >> 63
    hi &= MASK63
    t = lo + extra
    lo = t & ((1 << 64) - 1)
    hi += t >> 64
    # conditional subtract P
    lo2 = (lo - ((1 << 64) - 1)) & ((1 << 64) - 1)
    borrow = 1 if lo < ((1 << 64) - 1) else 0
    hi2 = (hi - MASK63 - borrow) & ((1 << 64) - 1)
    if (hi >> 63) or (hi == MASK63 and lo == ((1 << 64) - 1)):
        return lo2, hi2
    return lo, hi

def f2i(x):  return x[0] | (x[1] << 64)
def i2f(v):
    # NB: must reduce mod P, not mask.  The old
    #     return fp(v & M64, (v >> 64) & MASK63)
    # silently discarded bit 127, and 2^127 == 1 (mod p) -- so every intermediate
    # that carried a borrow (i.e. fsub going negative) lost exactly +1.  That made
    # the public layer aggregate T_l wrong by a small per-layer integer (observed
    # +4..+15), which is precisely the signature of "N lost carries", not of a
    # wrong model.  Reducing first also keeps Python's floor-shift from sneaking a
    # negative high word through & MASK63.
    v %= P
    return (v & ((1 << 64) - 1), (v >> 64) & MASK63)
def fadd(a, b): return i2f(f2i(a) + f2i(b))
def fsub(a, b): return i2f(f2i(a) - f2i(b))
def fmul(a, b): return i2f((f2i(a) * f2i(b)) % P)
def fneg(a):    return i2f((P - f2i(a)) % P)
def finv(a):    return i2f(pow(f2i(a), P - 2, P))
def fpow(a, e): return i2f(pow(f2i(a), e, P))

# ---------------------------------------------------------------- range decoder
class AdaptiveState:
    def __init__(self, n=256):
        self.n = n
        self.ctx = [0] * n
        for i in range(n):
            w = ((i & 1) * 2 + (i & 2) + (i >> 2 & 1) + (i >> 3 & 1)
                 + (i >> 4 & 1) + (i >> 5 & 1) + (i >> 6 & 1) + (i >> 7 & 1) + 3)
            self.ctx[i] = (w << 28) | 6
        self.prev = 0
        self.rate_table = [32768 // (2 * i + 3) for i in range(256)]

    def predict(self, s):
        self.prev = s
        return self.ctx[s] >> 16

    def update(self, bit, limit=255):
        cnt = self.ctx[self.prev] & 255
        p = self.ctx[self.prev] >> 14
        if cnt < limit:
            self.ctx[self.prev] = (self.ctx[self.prev] + 1) & MASK32
            delta = ((((bit << 18) - p) * self.rate_table[cnt]) & MASK32) & 0xFFFFFF00
            self.ctx[self.prev] = (self.ctx[self.prev] + delta) & MASK32

class Predictor:
    def __init__(self):
        self.prev = 0
        self.matrix = AdaptiveState(0x10000)
        self.order = [0x66] * 256

    def predict(self):
        return self.matrix.predict((self.prev << 8) | self.order[self.prev])

    def update(self, bit):
        self.matrix.update(bit, 90)
        s = self.order[self.prev]
        s = (s + s + bit) & 255
        self.order[self.prev] = s
        self.prev = self.prev + self.prev + bit
        if self.prev >= 256:
            self.prev = 0

class RangeDecoder:
    def __init__(self, data, length):
        self.src, self.src_len, self.pos = data, length, 0
        self.lo, self.hi, self.code = 0, MASK32, 0
        for _ in range(4):
            self.code = ((self.code << 8) + self._nb()) & MASK32
        self.pred = Predictor()

    def _nb(self):
        if self.pos < self.src_len:
            b = self.src[self.pos]; self.pos += 1; return b
        return 0

    def decode_bit(self):
        p = self.pred.predict()
        rng = (self.hi - self.lo) & MASK32
        mid = (self.lo + ((rng >> 16) * p) + ((((rng & 0xffff) * p) >> 16))) & MASK32
        if self.code <= mid:
            bit = 1; self.hi = mid
        else:
            bit = 0; self.lo = (mid + 1) & MASK32
        self.pred.update(bit)
        while ((self.lo ^ self.hi) & 0xFF000000) == 0:
            self.lo = (self.lo << 8) & MASK32
            self.hi = ((self.hi << 8) + 255) & MASK32
            self.code = ((self.code << 8) & MASK32) + self._nb()
        return bit

    def decode_byte_or_eof(self):
        if not self.decode_bit():
            return -1
        b = 1
        while b < 256:
            b += b + self.decode_bit()
        return b - 256

def unpack(data):
    if len(data) < 5 or data[0] != 0xEC:
        raise ValueError('bad pvac_compress header')
    orig = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4]
    dec = RangeDecoder(data[5:], len(data) - 5)
    out = bytearray()
    while True:
        b = dec.decode_byte_or_eof()
        if b < 0:
            break
        if len(out) >= orig:
            raise ValueError('output exceeds declared size')
        out.append(b)
    if len(out) != orig:
        raise ValueError('size mismatch %d != %d' % (len(out), orig))
    return bytes(out)

# ---------------------------------------------------------------- byte reader
class R:
    def __init__(self, data, pos=0):
        self.d = data; self.p = pos
    def u8(self):
        v = self.d[self.p]; self.p += 1; return v
    def u16(self):
        v = struct.unpack_from('<H', self.d, self.p)[0]; self.p += 2; return v
    def u32(self):
        v = struct.unpack_from('<I', self.d, self.p)[0]; self.p += 4; return v
    def i32(self):
        return struct.unpack_from('<i', self.d, self.p)[0] if False else self.u32() - (1 << 32) * (self.d[self.p:self.p+4][0] >> 7 and (0 if True else 0))
    def u64(self):
        v = struct.unpack_from('<Q', self.d, self.p)[0]; self.p += 8; return v
    def f64(self):
        v = struct.unpack_from('<d', self.d, self.p)[0]; self.p += 8; return v
    def raw(self, n):
        v = self.d[self.p:self.p + n]; self.p += n; return v

def rd_i32(r):
    v = struct.unpack_from('<i', r.d, r.p)[0]; r.p += 4; return v

# ---------------------------------------------------------------- pubkey
def parse_pubkey_raw(raw):
    r = R(raw)
    magic = r.raw(4)
    assert magic == b'PVAC', magic
    ver = r.u8(); tag = r.u8()
    assert tag == 1, tag
    prm = {}
    prm['B'] = rd_i32(r); prm['m_bits'] = rd_i32(r); prm['n_bits'] = rd_i32(r)
    prm['h_col_wt'] = rd_i32(r); prm['x_col_wt'] = rd_i32(r); prm['err_wt'] = rd_i32(r)
    prm['noise_entropy_bits'] = r.f64(); prm['tuple2_fraction'] = r.f64()
    prm['depth_slope_bits'] = r.f64(); prm['edge_budget'] = r.u64()
    prm['lpn_n'] = rd_i32(r); prm['lpn_t'] = rd_i32(r)
    prm['lpn_tau_num'] = rd_i32(r); prm['lpn_tau_den'] = rd_i32(r)
    canon_tag = r.u64()
    nH = r.u64()
    H = []
    for _ in range(nH):
        nbits = r.u64(); nw = r.u64()
        if nbits % 64:
            assert nw == (nbits + 63) // 64
        H.append((nbits, struct.unpack_from('<%dQ' % nw, r.d, r.p)))
        r.p += 8 * nw
    np_ = r.u64(); perm = list(struct.unpack_from('<%di' % np_, r.d, r.p)); r.p += 4 * np_
    ni = r.u64(); inv = list(struct.unpack_from('<%di' % ni, r.d, r.p)); r.p += 4 * ni
    H_digest = r.raw(32)
    omega_B = (r.u64(), r.u64() & MASK63)
    ng = r.u64()
    powg_B = []
    for _ in range(ng):
        powg_B.append((r.u64(), r.u64() & MASK63))
    assert r.p == len(raw), (r.p, len(raw))
    return dict(prm=prm, canon_tag=canon_tag, H=H, perm=perm, inv=inv,
                H_digest=H_digest, omega_B=omega_B, powg_B=powg_B, raw_len=len(raw))

def load_pubkey(path):
    data = open(path, 'rb').read()
    raw = unpack(data) if data[0] == 0xEC else data
    return parse_pubkey_raw(raw)


# ---------------------------------------------------------------- pk cache
def cache_file(path):
    """Cache path for a parsed pubkey, keyed by that pk file's own bytes.

    Keying on the basename (the earlier scheme) collides as soon as two
    different pubkeys share a filename -- pk.bin at the repository root and
    pk_case.bin in the reference rig, or two rig cases. A stale foreign cache
    then silently yields wrong intermediates, so the digest is part of the name.
    """
    with open(path, 'rb') as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()[:16]
    cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.cache')
    try:
        os.makedirs(cache_dir, exist_ok=True)
    except OSError:
        cache_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(cache_dir, 'pk-%s.parsed.pkl' % digest)


def load_pubkey_cached(path, quiet=False):
    """load_pubkey() behind a digest-keyed pickle cache (a parse costs ~2 min)."""
    cache = cache_file(path)
    try:
        with open(cache, 'rb') as fh:
            pk = pickle.load(fh)
        if not quiet:
            print('NOTE: pubkey parsed from cache %s' % cache)
        return pk
    except (OSError, EOFError, ValueError):
        pass
    if not quiet:
        print('NOTE: parsing %s (pure-python range decoder, slow; cached next run)' % path)
    pk = load_pubkey(path)
    try:
        with open(cache, 'wb') as fh:
            pickle.dump(pk, fh, protocol=4)
    except OSError:
        pass
    return pk

# ---------------------------------------------------------------- ciphertext
SGN_P, SGN_M = 0, 1
RULE_BASE, RULE_PROD = 0, 1

def read_layer(r):
    rule = r.u8()
    L = {'rule': rule}
    if rule == RULE_BASE:
        L['ztag'] = r.u64(); L['nlo'] = r.u64(); L['nhi'] = r.u64()
    else:
        L['pa'] = r.u32(); L['pb'] = r.u32()
    nPC = r.u64()
    L['PC'] = [r.raw(32) for _ in range(nPC)]
    return L

def read_edge(r):
    e = {'layer': r.u32(), 'idx': r.u16(), 'ch': r.u8()}
    nw = r.u64()
    e['w'] = [(r.u64(), r.u64() & MASK63) for _ in range(nw)]
    e['s_nbits'] = r.u64(); nws = r.u64()
    e['s'] = struct.unpack_from('<%dQ' % nws, r.d, r.p); r.p += 8 * nws
    return e

def parse_cipher(blob):
    r = R(blob)
    assert r.raw(4) == b'PVAC'
    ver = r.u8(); tag = r.u8()
    assert tag == 0, tag
    C = {'slots': r.u64()}
    nL = r.u64()
    C['L'] = [read_layer(r) for _ in range(nL)]
    nc = r.u64()
    C['c0'] = [(r.u64(), r.u64() & MASK63) for _ in range(nc)]
    nE = r.u64()
    C['E'] = [read_edge(r) for _ in range(nE)]
    C['raw_len'] = len(blob)
    assert r.p == len(blob), (r.p, len(blob))
    return C

BUNDLE_MAGIC = b'OCTRA-HFHE-BTY02'

def load_bundle(path):
    data = open(path, 'rb').read()
    assert data[:16] == BUNDLE_MAGIC
    pos = 16
    count = struct.unpack_from('<Q', data, pos)[0]; pos += 8
    cts = []
    for _ in range(count):
        n = struct.unpack_from('<Q', data, pos)[0]; pos += 8
        cts.append(parse_cipher(data[pos:pos + n]))
        pos += n
    assert pos == len(data)
    return cts

# ---------------------------------------------------------------- public aggregate
def public_T(pk, C, layer_id, slot=0):
    acc = C['c0'][slot] if (layer_id == 0 and C['c0']) else (0, 0)
    for e in C['E']:
        if e['layer'] != layer_id:
            continue
        term = fmul(e['w'][slot], pk['powg_B'][e['idx']])
        acc = fadd(acc, term) if e['ch'] == SGN_P else fsub(acc, term)
    return acc

def fp_hex(x):
    return '%016x%016x' % (x[1] & MASK63, x[0])

def prune_cache(quiet=False):
    """Delete .cache/pk-*.parsed.pkl entries that do not belong to the current pk.bin.

    The cache is keyed by pk.bin's digest, so a changed pubkey silently accumulates a second
    12.6 MB entry while the old one lingers forever. Three such files (37.7 MB) had built up
    here, two of them stale. Called from main() so a rebuild self-cleans.
    """
    cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.cache')
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pk_path = os.path.join(base, 'pk.bin')
    if not (os.path.isdir(cache_dir) and os.path.exists(pk_path)):
        return []
    with open(pk_path, 'rb') as fh:
        live = hashlib.sha256(fh.read()).hexdigest()[:16]
    removed = []
    for p in glob.glob(os.path.join(cache_dir, 'pk-*.parsed.pkl')):
        if live not in os.path.basename(p):
            size = os.path.getsize(p)
            os.remove(p)
            removed.append((os.path.basename(p), size))
            if not quiet:
                print('pruned stale cache %s (%.1f MiB)' % (os.path.basename(p), size / 2**20))
    return removed


def main():
    # solution/ -> repository root (challenge artifacts live there)
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pk = load_pubkey(os.path.join(base, 'pk.bin'))
    cts = load_bundle(os.path.join(base, 'secret.ct'))
    print('params:', pk['prm'])
    print('canon_tag: %016x' % pk['canon_tag'])
    print('H_digest:', pk['H_digest'].hex())
    print('omega_B:', fp_hex(pk['omega_B']))
    print('n H cols: %d each %d bits' % (len(pk['H']), pk['H'][0][0]))
    print('powg_B[0..3]:', [fp_hex(x) for x in pk['powg_B'][:3]])
    print('ciphertexts: %d' % len(cts))
    for i, C in enumerate(cts):
        base_layers = [j for j, L in enumerate(C['L']) if L['rule'] == RULE_BASE]
        prod = [j for j, L in enumerate(C['L']) if L['rule'] == RULE_PROD]
        per_layer = {}
        for e in C['E']:
            per_layer[e['layer']] = per_layer.get(e['layer'], 0) + 1
        dupe = len(C['E']) - len({(e['layer'], e['idx'], e['ch']) for e in C['E']})
        print('ct%02d slots=%d L=%d base=%s prod=%s E=%d perlayer=%s dup_triples=%d c0len=%d'
              % (i, C['slots'], len(C['L']), base_layers, prod, len(C['E']),
                 [per_layer.get(j, 0) for j in range(len(C['L']))], dupe, len(C['c0'])))
        for j, L in enumerate(C['L']):
            if L['rule'] == RULE_BASE:
                T = public_T(pk, C, j)
                print('   L%d BASE ztag=%d nlo=%016x nhi=%016x PC=%d T=%s'
                      % (j, L['ztag'], L['nlo'], L['nhi'], len(L['PC']), fp_hex(T)))
    # Store the ciphers only. The pubkey -- including the 16 MB H matrix -- is already
    # cached by load_pubkey_cached() under solution/.cache/pk-<sha16>.parsed.pkl, keyed by
    # pk.bin's own digest. Duplicating it here cost 15 MB of duplicate state and left an
    # unkeyed copy that goes stale the moment pk.bin changes.
    cache = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'parsed.pkl')
    with open(cache, 'wb') as fh:
        pickle.dump({'cts': cts}, fh)
    print('saved solution/parsed.pkl (ciphers only; pubkey lives in .cache/, digest-keyed)')
    prune_cache()

if __name__ == '__main__':
    main()
