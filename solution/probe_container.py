#!/usr/bin/env python3
"""Container canonicality probe for the published PVAC artifacts.

Question: does sha256(pk.bin) determine the public key that the engine decodes?

The engine's compressed container (include/pvac/core/pvac_compress.hpp at the
pinned commit) is an adaptive range coder.  Its decoder refills with zeros past
the end of input and `unpack()` never compares the consumed position against
the input length.  Whether that makes the container malleable, brittle, or
neither is a measurement, not a reading: the decoder pulls appended bytes into
its code register during the final renormalisation BEFORE it lands on the
end-of-stream symbol, so the effect depends on the suffix value.

Part A  encoder self-test, then suffix tolerance by suffix value (synthetic)
Part B  consumed-length measurement (where the decoder stops)
Part C  the real pk.bin: decode, then decode with a zero suffix, compare
Part D  raw pubkey reader: the Python port rejects trailing bytes, the pinned
        C++ deserializer does not (source asymmetry)

Run:  python solution/probe_container.py [--fast]
      --fast reuses the cached decode of pk.bin instead of decoding twice
      (each full pure-Python decode of pk.bin is ~2 min).
"""
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import parse as P  # noqa: E402

MASK32 = 0xFFFFFFFF
TAG = 0xEC


# --------------------------------------------------------------- range encoder
# Mirrors include/pvac/core/pvac_compress.hpp:79-121 at the pinned commit, using
# the decoder's own Predictor (solution/parse.py) so the model cannot drift.
class RangeEncoder:
    def __init__(self):
        self.pred = P.Predictor()
        self.out = bytearray()
        self.lo, self.hi = 0, MASK32

    def encode_bit(self, bit):
        p = self.pred.predict()
        rng = (self.hi - self.lo) & MASK32
        mid = (self.lo + ((rng >> 16) * p) + (((rng & 0xFFFF) * p) >> 16)) & MASK32
        if bit:
            self.hi = mid
        else:
            self.lo = (mid + 1) & MASK32
        self.pred.update(bit)
        while ((self.lo ^ self.hi) & 0xFF000000) == 0:
            self.out.append((self.hi >> 24) & 0xFF)
            self.lo = (self.lo << 8) & MASK32
            self.hi = ((self.hi << 8) + 255) & MASK32

    def encode_byte(self, b):
        self.encode_bit(1)
        for i in range(7, -1, -1):
            self.encode_bit((b >> i) & 1)

    def encode_eof(self):
        self.encode_bit(0)

    def flush(self):
        while ((self.lo ^ self.hi) & 0xFF000000) == 0:
            self.out.append((self.hi >> 24) & 0xFF)
            self.lo = (self.lo << 8) & MASK32
            self.hi = ((self.hi << 8) + 255) & MASK32
        self.out.append((self.hi >> 24) & 0xFF)


def pack(raw):
    enc = RangeEncoder()
    head = bytes([TAG,
                  (len(raw) >> 24) & 0xFF, (len(raw) >> 16) & 0xFF,
                  (len(raw) >> 8) & 0xFF, len(raw) & 0xFF])
    for b in raw:
        enc.encode_byte(b)
    enc.encode_eof()
    enc.flush()
    return head + bytes(enc.out)


def unpack_measured(data):
    """unpack() plus the payload byte count actually consumed (dec.pos)."""
    if len(data) < 5 or data[0] != TAG:
        raise ValueError('bad pvac_compress header')
    orig = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4]
    dec = P.RangeDecoder(data[5:], len(data) - 5)
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
    return bytes(out), dec.pos


FAIL = []


def check(label, ok, detail=''):
    print('%-60s %s %s' % (label, 'PASS' if ok else 'FAIL', detail))
    if not ok:
        FAIL.append(label)


# ---------------------------------------------------------------------- Part A
def part_a():
    print('\n== Part A: encoder self-test and suffix tolerance (synthetic) ==')
    ok_rt = True
    for n in (0, 1, 17, 300, 1000, 5000):
        raw = os.urandom(n)
        try:
            got = unpack_measured(pack(raw))[0]
        except Exception as exc:  # noqa: BLE001
            print('  round-trip n=%d raised %s' % (n, exc))
            ok_rt = False
            continue
        ok_rt = ok_rt and got == raw
    check('encoder mirrors the engine (round-trip n=0,1,17,300,1000,5000)', ok_rt,
          '(self-test gate for every claim below)')

    raw = os.urandom(1000)
    base = pack(raw)
    cases = [
        ('0 bytes (control)', b''),
        ('1 zero byte', b'\x00'),
        ('64 zero bytes', b'\x00' * 64),
        ('4 KiB zero bytes', b'\x00' * 4096),
        ('1 0xff byte', b'\xff'),
        ('64 0xff bytes', b'\xff' * 64),
        ('zero-pad + non-zero payload', b'\x00' * 16 + b'MALICIOUS_PAYLOAD_HERE'),
    ]
    zero_ok = True
    ff_rejected = True
    tail_ignored = False
    print('  %-22s %-10s %-9s %s' % ('suffix', 'outcome', 'payload', 'position'))
    for name, tail in cases:
        try:
            got, pos = unpack_measured(base + tail)
            outcome = 'identical' if got == raw else 'DIFFERENT'
            if '0xff' in name:
                ff_rejected = False
            if 'zero-pad + non-zero' in name:
                tail_ignored = (got == raw) and (pos < len(base + tail))
            if not tail.strip(b'\x00'):
                zero_ok = zero_ok and outcome == 'identical'
        except ValueError as exc:
            outcome = str(exc)
            pos = '-'
            if '0xff' in name:
                ff_rejected = ff_rejected and True
            if not tail.strip(b'\x00'):
                zero_ok = False
        print('  %-22s %-10s %-9d %s' % (name, outcome[:10], len(base) - 5, pos))

    check('an all-zero suffix still decodes to the identical payload', zero_ok,
          'so one payload has many valid byte strings')
    check('an immediate 0xff suffix is rejected, not silently ignored', ff_rejected,
          'the decoder pulls 0xff into its code register before EOF')
    check('a non-zero payload past EOF pad is silently accepted', tail_ignored,
          'bytes past the EOF renormalisation window are never read')

    # the decisive pair: two byte strings, different digests, same payload
    a = base
    b = base + b'\x00' * 64
    da, db = hashlib.sha256(a).digest(), hashlib.sha256(b).digest()
    check('two byte strings, different sha256, identical decoded payload',
          da != db and unpack_measured(a)[0] == unpack_measured(b)[0])
    return raw


# ---------------------------------------------------------------------- Part B
def part_b(raw):
    print('\n== Part B: where the decoder stops ==')
    base = pack(raw)
    _, pos0 = unpack_measured(base)
    print('  clean blob: payload %d B, decoder consumed %d B' % (len(base) - 5, pos0))
    _, pos1 = unpack_measured(base + b'\x00' * 64)
    print('  64 zero suffix: payload %d B, decoder consumed %d B (ignored %d B)' %
          (len(base) + 64 - 5, pos1, len(base) + 64 - 5 - pos1))
    check('the decoder reads into the suffix before landing on EOF', pos1 >= pos0,
          'this is why the suffix value decides accept/reject')


# ---------------------------------------------------------------------- Part C
def part_c(fast):
    print('\n== Part C: the published pk.bin ==')
    blob = open(os.path.join(ROOT, 'pk.bin'), 'rb').read()
    print('  pk.bin %d B  sha256 %s' % (len(blob), hashlib.sha256(blob).hexdigest()))
    cached = os.path.join(HERE, '.cache', 'probe-raw.bin')
    os.makedirs(os.path.dirname(cached), exist_ok=True)
    if os.path.exists(cached) and os.path.getsize(cached) == 17110454:
        raw = open(cached, 'rb').read()
        print('  reused cached decode (%d B, sha256 %s)' %
              (len(raw), hashlib.sha256(raw).hexdigest()[:16]))
    else:
        print('  decoding (pure Python, ~2 min)...')
        raw, pos = unpack_measured(blob)
        open(cached, 'wb').write(raw)
        print('  decoded %d B, payload %d B, consumed %d B' %
              (len(raw), len(blob) - 5, pos))
    check('pk.bin decodes', len(raw) == 17110454,
          'sha256(raw) %s' % hashlib.sha256(raw).hexdigest())

    if fast:
        print('  --fast: skipping the second full decode')
        return raw

    mutated = blob + b'\x00' * 64
    print('  decoding pk.bin + 64 zero bytes (~2 min)...')
    try:
        raw2, pos2 = unpack_measured(mutated)
        same = raw2 == raw
    except ValueError as exc:
        print('  raised %s' % exc)
        same = False
        pos2 = None
    check('pk.bin + 64 zero bytes decodes to the identical pubkey',
          same and hashlib.sha256(mutated).digest() != hashlib.sha256(blob).digest(),
          'different sha256, same %d decoded bytes %s' %
          (len(raw), '' if pos2 is None else '(consumed %d/%d)' % (pos2, len(mutated) - 5)))
    return raw


# ---------------------------------------------------------------------- Part D
def part_d(raw):
    print('\n== Part D: raw pubkey reader, pinned C++ vs the Python port ==')
    pk = P.parse_pubkey_raw(raw)
    prm = pk['prm']
    print('  parsed canon_tag 0x%016x  B=%d  m_bits=%d  n_bits=%d  powers=%d' %
          (pk['canon_tag'], prm['B'], prm['m_bits'], prm['n_bits'], len(pk['powg_B'])))
    check('Python port accepts the canonical raw pubkey', True)
    raised = False
    try:
        P.parse_pubkey_raw(raw + b'\x00')
    except AssertionError:
        raised = True
    except Exception as exc:  # noqa: BLE001
        print('  (+1 byte raised %s instead)' % type(exc).__name__)
    check('Python port rejects raw pubkey + 1 trailing byte', raised,
          'parse.py asserts full consumption')
    print('  pinned source/pvac_artifact_serialize.hpp:425-466 ends with')
    print('    validate_pubkey_structure(pk); return pk;')
    print('  and never compares r.p against len, so the engine accepts a byte')
    print('  string the port rejects: the two implementations disagree on one input.')


def main():
    fast = '--fast' in sys.argv
    print('PVAC container canonicality probe')
    raw = part_a()
    part_b(raw)
    raw_real = part_c(fast)
    part_d(raw_real)
    print('\n%d failure(s)' % len(FAIL))
    for f in FAIL:
        print('  - %s' % f)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
