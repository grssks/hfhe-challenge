"""Minimal standard Ristretto255 (RFC 9496) + Edwards25519 arithmetic.

Used to probe the pvac Pedersen commitment generator H and the ciphertext
PC values: if the blinding term vanishes, PC_l * T_l = v_l * G and the
plaintext becomes recoverable.
"""

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493  # group order

D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
ONE_MINUS_D_SQ = (1 - D * D) % P
D_MINUS_ONE_SQ = ((D - 1) * (D - 1)) % P
# RFC 9496 constants for ristretto255 (a = -1)
SQRT_AD_MINUS_ONE = 25063068953384623474111414158702152701244531502492656460079210482610430750235
INVSQRT_A_MINUS_D = 54469307008909316920995813868745141605393597292927456921205312896311721017578


def inv(x):
    return pow(x % P, P - 2, P)


def is_negative(x):
    return (x % P) & 1 == 1


def ct_abs(x):
    x %= P
    return P - x if is_negative(x) else x


def sqrt_ratio_m1(u, v):
    """(was_square, sqrt(u/v)) following RFC 9496."""
    u %= P
    v %= P
    v3 = pow(v, 3, P)
    v7 = pow(v, 7, P)
    r = (u * v3) % P * pow((u * v7) % P, (P - 5) // 8, P) % P
    check = (v * r * r) % P
    correct = check == u % P
    flipped = check == (-u) % P
    flipped_i = check == (-u * SQRT_M1) % P
    if flipped or flipped_i:
        r = (r * SQRT_M1) % P
    r = ct_abs(r)
    return (correct or flipped), r


# ------------------------------------------------------------------ points
# extended coordinates (X : Y : Z : T), a = -1 twisted Edwards
IDENT = (0, 1, 1, 0)

# edwards25519 basepoint
By = 4 * inv(5) % P
Bx = None
_xx = (By * By - 1) * inv(D * By * By + 1) % P
# x = sqrt(xx) with sign chosen: standard Bx
_xx = ((By * By - 1) % P) * inv((D * By * By + 1) % P) % P
Bx = pow(_xx, (P + 3) // 8, P)
if (Bx * Bx - _xx) % P != 0:
    Bx = (Bx * SQRT_M1) % P
assert (Bx * Bx - _xx) % P == 0
if is_negative(Bx):
    Bx = P - Bx
G = (Bx, By, 1, (Bx * By) % P)


def ext_add(Pt, Q):
    X1, Y1, Z1, T1 = Pt
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % P
    B_ = (Y1 + X1) * (Y2 + X2) % P
    C = (T1 * 2 * D) % P * T2 % P
    Dd = (Z1 * 2) % P * Z2 % P
    E = (B_ - A) % P
    F = (Dd - C) % P
    G_ = (Dd + C) % P
    H = (B_ + A) % P
    return ((E * F) % P, (G_ * H) % P, (F * G_) % P, (E * H) % P)


def ext_neg(Pt):
    X, Y, Z, T = Pt
    return ((-X) % P, Y, Z, (-T) % P)


def ext_double(Pt):
    return ext_add(Pt, Pt)


def scalarmul(Pt, k):
    R = IDENT
    Q = Pt
    while k > 0:
        if k & 1:
            R = ext_add(R, Q)
        Q = ext_double(Q)
        k >>= 1
    return R


def scalarmul_g(k):
    return scalarmul(G, k)


def encode(Pt):
    X, Y, Z, T = Pt
    u1 = (Z + Y) * (Z - Y) % P
    u2 = X * Y % P
    _, invs = sqrt_ratio_m1(1, u1 * u2 * u2 % P)
    den1 = invs * u1 % P
    den2 = invs * u2 % P
    z_inv = den1 * den2 % P * T % P
    ix = X * SQRT_M1 % P
    iy = Y * SQRT_M1 % P
    enchanted = den1 * INVSQRT_A_MINUS_D % P
    rotate = is_negative(T * z_inv % P)
    if rotate:
        X, Y = iy, ix
        den_inv = enchanted
    else:
        den_inv = den2
    if is_negative(X * z_inv % P):
        Y = (-Y) % P
    s = ct_abs(den_inv * (Z - Y) % P)
    return s.to_bytes(32, 'little')


def decode(s_bytes):
    if len(s_bytes) != 32:
        return None
    s = int.from_bytes(s_bytes, 'little')
    if s >= P:
        return None
    ss = s * s % P
    u1 = (1 - ss) % P
    u2 = (1 + ss) % P
    u2_sqr = u2 * u2 % P
    v = (-(D * u1 * u1 % P) - u2_sqr) % P
    ok, invs = sqrt_ratio_m1(1, v * u2_sqr % P)
    den_x = invs * u2 % P
    den_y = invs * den_x % P * v % P
    x = ct_abs(2 * s * den_x % P)
    y = u1 * den_y % P
    t = x * y % P
    if (not ok) or is_negative(t) or y == 0:
        return None
    return (x, y, 1, t)


if __name__ == '__main__':
    # self-checks
    assert encode(IDENT) == b'\x00' * 32
    assert decode(encode(IDENT)) is not None
    g_enc = encode(G)
    assert decode(g_enc) is not None
    P1 = decode(g_enc)
    P2 = scalarmul_g(1)
    assert encode(P2) == g_enc
    # 1*G + 2*G == 3*G
    assert encode(ext_add(scalarmul_g(1), scalarmul_g(2))) == encode(scalarmul_g(3))
    assert encode(scalarmul_g(L)) == encode(IDENT)
    print("ristretto self-check OK")
    print("G_enc =", g_enc.hex())
