"""Bounded pure-Python reference primitives for SSPS draft 2 fixtures.

secp256k1, BIP-340, BIP-327 KeySort/KeyAgg, BIP-341 taproot (Bitcoin and
Elements tagged hashes), bech32m, BigSize TLV, fixture JCS, NIP-01 events and
NIP-44 v2. Written for deterministic test vectors with public keys only: not
constant time, not for production use.
"""
import base64
import hashlib
import hmac
import json
import struct

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def point_add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and a[1] != b[1]: return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], p - 2, p) % p
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], p - 2, p) % p
    x = (lam * lam - a[0] - b[0]) % p
    return (x, (lam * (a[0] - x) - a[1]) % p)


def point_mul(pt, k):
    r = None
    for i in range(256):
        if (k >> i) & 1: r = point_add(r, pt)
        pt = point_add(pt, pt)
    return r


def lift_x(x):
    y2 = (pow(x, 3, p) + 7) % p
    y = pow(y2, (p + 1) // 4, p)
    if pow(y, 2, p) != y2: raise ValueError('x not on curve')
    return (x, y if y % 2 == 0 else p - y)


def lift_compressed(b):
    pt = lift_x(int.from_bytes(b[1:], 'big'))
    return pt if (pt[1] % 2 == 0) == (b[0] == 2) else (pt[0], p - pt[1])


def cbytes(pt): return (b'\x02' if pt[1] % 2 == 0 else b'\x03') + pt[0].to_bytes(32, 'big')
def xbytes(pt): return pt[0].to_bytes(32, 'big')
def pubkey(secret): return point_mul(G, secret)
def sha256(b): return hashlib.sha256(b).digest()
def rmd160(b): return hashlib.new('ripemd160', b).digest()


def tagged(tag, msg):
    t = sha256(tag.encode())
    return sha256(t + t + msg)


def schnorr_sign(msg, secret, aux=b'\x00' * 32):
    P = pubkey(secret)
    d = secret if P[1] % 2 == 0 else n - secret
    t = (d ^ int.from_bytes(tagged('BIP0340/aux', aux), 'big')).to_bytes(32, 'big')
    k0 = int.from_bytes(tagged('BIP0340/nonce', t + xbytes(P) + msg), 'big') % n
    R = pubkey(k0)
    k = k0 if R[1] % 2 == 0 else n - k0
    e = int.from_bytes(tagged('BIP0340/challenge', xbytes(R) + xbytes(P) + msg), 'big') % n
    return xbytes(R) + ((k + e * d) % n).to_bytes(32, 'big')


def schnorr_verify(msg, pub32, sig):
    try:
        P = lift_x(int.from_bytes(pub32, 'big'))
    except ValueError:
        return False
    r, s = int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')
    if r >= p or s >= n: return False
    e = int.from_bytes(tagged('BIP0340/challenge', sig[:32] + pub32 + msg), 'big') % n
    R = point_add(pubkey(s), point_mul(P, n - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def key_agg(pubkeys):
    """BIP-327 KeyAgg over pubkeys in the given order (no KeySort); returns the aggregate point."""
    keys = list(pubkeys)
    L = tagged('KeyAgg list', b''.join(keys))
    second = next((k for k in keys[1:] if k != keys[0]), None)
    Q = None
    for k in keys:
        a = 1 if k == second else int.from_bytes(tagged('KeyAgg coefficient', L + k), 'big') % n
        Q = point_add(Q, point_mul(lift_compressed(k), a))
    return Q


RAILS = {'btc': ('TapLeaf', 'TapBranch', 'TapTweak', 0xc0),
         'liquid': ('TapLeaf/elements', 'TapBranch/elements', 'TapTweak/elements', 0xc4)}


def script_num(v):
    out = b''
    while v:
        out += bytes([v & 0xff]); v >>= 8
    if out and out[-1] & 0x80: out += b'\x00'
    return bytes([len(out)]) + out


def htlc(rail, payment_hash, claim_key, refund_key, deadline, publisher='claim'):
    """The SSPS chain lock: claim and refund leaves, MuSig2 internal key.

    `publisher` names the key of the party that published the lock ('claim' or
    'refund'); it goes first in KeyAgg, Boltz's order."""
    leaf_tag, branch_tag, tweak_tag, version = RAILS[rail]
    claim = (b'\x82\x01\x20\x88\xa9\x14' + rmd160(payment_hash) + b'\x88\x20'
             + claim_key[1:] + b'\xac')
    refund = b'\x20' + refund_key[1:] + b'\xad' + script_num(deadline) + b'\xb1'
    leaves = [tagged(leaf_tag, bytes([version, len(s)]) + s) for s in (claim, refund)]
    root = tagged(branch_tag, b''.join(sorted(leaves)))
    order = [claim_key, refund_key] if publisher == 'claim' else [refund_key, claim_key]
    internal = xbytes(key_agg(order))
    t = int.from_bytes(tagged(tweak_tag, internal + root), 'big')
    output = xbytes(point_add(lift_x(int.from_bytes(internal, 'big')), pubkey(t)))
    return {'claim_leaf': claim.hex(), 'refund_leaf': refund.hex(), 'leaf_version': version,
            'merkle_root': root.hex(), 'internal_key': internal.hex(),
            'output_key': output.hex(), 'script_pubkey': '5120' + output.hex()}


CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'


def bech32m(hrp, witver, prog):
    def polymod(values):
        gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            b = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ v
            for i in range(5): chk ^= gen[i] if (b >> i) & 1 else 0
        return chk
    acc, bits, data = 0, 0, [witver]
    for byte in prog:
        acc = (acc << 8) | byte; bits += 8
        while bits >= 5:
            bits -= 5; data.append((acc >> bits) & 31)
    if bits: data.append((acc << (5 - bits)) & 31)
    hrp_exp = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    mod = polymod(hrp_exp + data + [0] * 6) ^ 0x2bc830a3
    return hrp + '1' + ''.join(CHARSET[d] for d in data + [(mod >> 5 * (5 - i)) & 31 for i in range(6)])


def bigsize(i):
    if i < 0xfd: return bytes([i])
    if i <= 0xffff: return b'\xfd' + i.to_bytes(2, 'big')
    if i <= 0xffffffff: return b'\xfe' + i.to_bytes(4, 'big')
    return b'\xff' + i.to_bytes(8, 'big')


def read_bigsize(b, i):
    first = b[i]
    if first < 0xfd: return first, i + 1
    size = {0xfd: 2, 0xfe: 4, 0xff: 8}[first]
    return int.from_bytes(b[i + 1:i + 1 + size], 'big'), i + 1 + size


def jcs(value):
    """RFC 8785 for the bounded values fixtures use: ASCII strings, safe integers."""
    def check(v):
        if isinstance(v, str): assert v.isascii()
        elif isinstance(v, bool) or v is None: pass
        elif isinstance(v, int): assert abs(v) <= 2**53 - 1
        elif isinstance(v, list): [check(x) for x in v]
        elif isinstance(v, dict): [check(k) or check(x) for k, x in v.items()]
        else: raise ValueError('fixture values must be ASCII strings or safe integers')
    check(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def signed_digest(domain, value):
    return sha256(domain + jcs(value))


def nostr_event(secret, kind, tags, content, created_at):
    pub = xbytes(pubkey(secret)).hex()
    ser = json.dumps([0, pub, created_at, kind, tags, content],
                     ensure_ascii=False, separators=(',', ':')).encode()
    eid = sha256(ser)
    return {'id': eid.hex(), 'pubkey': pub, 'created_at': created_at, 'kind': kind,
            'tags': tags, 'content': content, 'sig': schnorr_sign(eid, secret).hex()}


def nostr_verify(event):
    ser = json.dumps([0, event['pubkey'], event['created_at'], event['kind'], event['tags'],
                      event['content']], ensure_ascii=False, separators=(',', ':')).encode()
    eid = sha256(ser)
    return eid.hex() == event['id'] and schnorr_verify(
        eid, bytes.fromhex(event['pubkey']), bytes.fromhex(event['sig']))


# ---------- NIP-44 v2 ----------

def _quarter(s, a, b, c, d):
    m = 0xffffffff
    s[a] = (s[a] + s[b]) & m; s[d] ^= s[a]; s[d] = ((s[d] << 16) | (s[d] >> 16)) & m
    s[c] = (s[c] + s[d]) & m; s[b] ^= s[c]; s[b] = ((s[b] << 12) | (s[b] >> 20)) & m
    s[a] = (s[a] + s[b]) & m; s[d] ^= s[a]; s[d] = ((s[d] << 8) | (s[d] >> 24)) & m
    s[c] = (s[c] + s[d]) & m; s[b] ^= s[c]; s[b] = ((s[b] << 7) | (s[b] >> 25)) & m


def chacha20(key, nonce, data, counter=0):
    """RFC 8439 ChaCha20 (12-byte nonce)."""
    out = bytearray()
    for block in range(0, len(data), 64):
        state = ([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
                 + list(struct.unpack('<8I', key)) + [counter + block // 64]
                 + list(struct.unpack('<3I', nonce)))
        w = state[:]
        for _ in range(10):
            _quarter(w, 0, 4, 8, 12); _quarter(w, 1, 5, 9, 13)
            _quarter(w, 2, 6, 10, 14); _quarter(w, 3, 7, 11, 15)
            _quarter(w, 0, 5, 10, 15); _quarter(w, 1, 6, 11, 12)
            _quarter(w, 2, 7, 8, 13); _quarter(w, 3, 4, 9, 14)
        stream = struct.pack('<16I', *[(w[i] + state[i]) & 0xffffffff for i in range(16)])
        out += bytes(x ^ y for x, y in zip(data[block:block + 64], stream))
    return bytes(out)


def nip44_conversation_key(secret, pub_x_hex):
    shared = point_mul(lift_x(int.from_bytes(bytes.fromhex(pub_x_hex), 'big')), secret)
    return hmac.new(b'nip44-v2', xbytes(shared), hashlib.sha256).digest()


def nip44_message_keys(conversation_key, nonce):
    okm, t, i = b'', b'', 1
    while len(okm) < 76:
        t = hmac.new(conversation_key, t + nonce + bytes([i]), hashlib.sha256).digest()
        okm += t; i += 1
    return okm[:32], okm[32:44], okm[44:76]


def nip44_padded_len(length):
    if length <= 32: return 32
    next_power = 1 << (length - 1).bit_length()
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * ((length - 1) // chunk + 1)


def nip44_encrypt(plaintext, conversation_key, nonce):
    raw = plaintext.encode()
    if not 1 <= len(raw) <= 65535: raise ValueError('plaintext length')
    padded = struct.pack('>H', len(raw)) + raw + b'\x00' * (nip44_padded_len(len(raw)) - len(raw))
    key, cnonce, hkey = nip44_message_keys(conversation_key, nonce)
    ct = chacha20(key, cnonce, padded)
    mac = hmac.new(hkey, nonce + ct, hashlib.sha256).digest()
    return base64.b64encode(b'\x02' + nonce + ct + mac).decode()


def nip44_decrypt(payload, conversation_key):
    data = base64.b64decode(payload)
    if data[0] != 2 or len(data) < 99: raise ValueError('unsupported payload')
    nonce, ct, mac = data[1:33], data[33:-32], data[-32:]
    key, cnonce, hkey = nip44_message_keys(conversation_key, nonce)
    if not hmac.compare_digest(mac, hmac.new(hkey, nonce + ct, hashlib.sha256).digest()):
        raise ValueError('invalid MAC')
    padded = chacha20(key, cnonce, ct)
    length = struct.unpack('>H', padded[:2])[0]
    if not 1 <= length or len(padded) != 2 + nip44_padded_len(length):
        raise ValueError('invalid padding')
    return padded[2:2 + length].decode()
