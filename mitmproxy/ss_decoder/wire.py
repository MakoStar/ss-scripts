# -*- coding: utf-8 -*-
# wire format, crypto and relay logic shared by all entry points
import logging
import zlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# region CN JP KR EN TW
REGION = "CN"

# relay switch, derives key3 automatically
MITM = True

# relay private keys, one-time values, safe to replace
F1_PRIV_HEX = "749f07329dbdefecf03371286ff14a76570fe152b38dd346e65afe5f1dc4642c"
F2_PRIV_HEX = "599b71486de02d56ec3ddf257f7340772f1fa8a43de6542c2cd4b956541eec1d"

# manual key3 when relaying is off
KEY3_HEX = ""

# manual client private key when relaying is off
CLIENT_PRIV_HEX = ""

# key3 injected at runtime via ss-key3 requests
KEY3_LIVE = ""

# decrypt serverlist.html and noticelist.html
STATIC_META = True

GARBLE = {
    "CN": "QW*Wi7fKjLk!T82Qf2nEGZA%nSC!D9qV",
    "JP": "yX5Gt64PVvVH6$qwBXaPJC*LZKoK5mYh",
    "KR": "25hdume9H#*6hHn@d9hSF7tekTwN#JYj",
    "EN": "xNdVF^XTa6T3HCUATMQ@sKMLzAw&%L!3",
    "TW": "N&mfco452ZH5!nE3s&o5uxB57UGPENVo",
}

STATIC_KEYS = {
    "CN": "Xf&FRcsYm48cJ2A@",
    "EN": "ma5Dn2FhC*Xhxy%c",
    "JP": "ZnUFA@S9%4KyoryM",
    "KR": "U9cjHuwGDDx&$drn",
    "TW": "owGYVDmfHrxi^4pm",
}

STATIC_HOSTREGION = {
    "nova-static.yostar.cn": "CN",
    "nova-static.stellasora.global": "EN",
    "nova-static.stellasora.jp": "JP",
    "nova-static.stellasora.kr": "KR",
    "nova-static.stargazer-games.com": "TW",
}

REGION_ORDER = ["CN", "EN", "JP", "KR", "TW"]


class State(object):
    # shared session state
    def __init__(self):
        self.client_pub = None
        self.server_pub = None
        self.derived_key3 = None
        self.ike_cipher = -1
        self.ike_token = None
        self.ike_server_ts = 0
        self.f1_pub = None
        self.f2_pub = None
        self.mitm_cli_pub = None
        self.mitm_srv_pub = None
        self.kcli = None
        self.ksrv = None
        self.relay_cnt = 0
        self.mitm_fail = 0
        self.mitm_warned = False


ST = State()


def hex_bytes(s):
    try:
        return bytes.fromhex(s)
    except Exception:
        return b""


def garble_bytes():
    # ascii garble key of the current region
    g = GARBLE.get(REGION)
    return g.encode("ascii") if g else b""


def read_varint(d, p, end):
    # read one varint, returns value and new position or None
    v, shift = 0, 0
    while p < end and shift < 64:
        b = d[p]
        p += 1
        v |= (b & 0x7F) << shift
        if not b & 0x80:
            return v, p
        shift += 7
    return None


def scan_fields(d, off, ln):
    # scan all fields of one message, returns list of (num, wt, voff, vlen)
    p, end = off, off + ln
    out = []
    while p < end:
        tag = read_varint(d, p, end)
        if tag is None:
            return None
        v, p = tag
        fn, wt = v >> 3, v & 7
        if fn == 0:
            return None
        if wt == 0:
            r = read_varint(d, p, end)
            if r is None:
                return None
            vo, p = p, r[1]
            vl = p - vo
        elif wt == 1:
            if p + 8 > end:
                return None
            vo, vl, p = p, 8, p + 8
        elif wt == 5:
            if p + 4 > end:
                return None
            vo, vl, p = p, 4, p + 4
        elif wt == 2:
            r = read_varint(d, p, end)
            if r is None:
                return None
            vl = r[0]
            if vl > end - r[1]:
                return None
            vo, p = r[1], r[1] + vl
        else:
            return None
        out.append((fn, wt, vo, vl))
    return out or None


def pb_fully_parses(d):
    # a payload is accepted when it scans cleanly as protobuf
    return bool(scan_fields(d, 0, len(d)))


def pb_find(d, want):
    # find the first field value by number over pure protobuf bytes
    if d is None:
        return None
    p, end = 0, len(d)
    while p < end:
        tag = read_varint(d, p, end)
        if tag is None:
            return None
        v, p = tag
        fn, wt = v >> 3, v & 7
        if fn <= 0:
            return None
        if wt == 0:
            r = read_varint(d, p, end)
            if r is None:
                return None
            if fn == want:
                return (0, r[0])
            p = r[1]
        elif wt == 1:
            if p + 8 > end:
                return None
            p += 8
        elif wt == 5:
            if p + 4 > end:
                return None
            p += 4
        elif wt == 2:
            r = read_varint(d, p, end)
            if r is None:
                return None
            fl = r[0]
            if r[1] + fl > end:
                return None
            if fn == want:
                return (2, bytes(d[r[1]:r[1] + fl]))
            p = r[1] + fl
        else:
            return None
    return None


def pb_off(d, start, end, want):
    # find offset and length of one length delimited field
    p = start
    while p < end:
        sp = p
        tag = read_varint(d, p, end)
        if tag is None:
            return None
        v, p = tag
        fn, wt = v >> 3, v & 7
        if fn <= 0:
            return None
        if wt == 0:
            r = read_varint(d, p, end)
            if r is None:
                return None
            p = r[1]
        elif wt == 1:
            if p + 8 > end:
                return None
            p += 8
        elif wt == 5:
            if p + 4 > end:
                return None
            p += 4
        elif wt == 2:
            r = read_varint(d, p, end)
            if r is None:
                return None
            fl = r[0]
            if r[1] + fl > end:
                return None
            if fn == want:
                return (r[1], fl)
            p = r[1] + fl
        else:
            return None
        if p <= sp:
            return None
    return None


def ror1(b):
    return ((b >> 1) | (b << 7)) & 0xFF


def rol1(b):
    return ((b << 1) | (b >> 7)) & 0xFF


def transform(wire, t, garble):
    # one of the four obfuscation variants, t 0 means raw
    d = bytearray(wire)
    if t == 0:
        return bytes(d)
    if not garble:
        return None
    if t in (1, 2):
        for i in range(len(d)):
            if t == 1:
                d[i] = ror1(d[i])
            else:
                d[i] ^= garble[i % len(garble)]
        for i in range(len(d)):
            if t == 1:
                d[i] ^= garble[i % len(garble)]
            else:
                d[i] = ror1(d[i])
        return bytes(d)
    lb = len(wire) & 0xFF
    for i in range(len(d)):
        d[i] ^= lb
        d[i] = ror1(d[i]) if t == 3 else rol1(d[i])
        d[i] ^= garble[i % len(garble)]
    return bytes(d)


def obscure_req(d, g):
    # inverse of transform t 1
    for i in range(len(d)):
        d[i] ^= g[i % len(g)]
        d[i] = rol1(d[i])


def obscure_resp(d, g):
    # inverse of transform t 3
    lb = len(d) & 0xFF
    for i in range(len(d)):
        d[i] ^= g[i % len(g)]
        d[i] = rol1(d[i])
        d[i] ^= lb


def obscure_req2(d, g):
    # inverse of transform t 2
    for i in range(len(d)):
        d[i] = rol1(d[i])
        d[i] ^= g[i % len(g)]


def obscure_resp2(d, g):
    # inverse of transform t 4
    lb = len(d) & 0xFF
    for i in range(len(d)):
        d[i] ^= g[i % len(g)]
        d[i] = ror1(d[i])
        d[i] ^= lb


def aead_dec(key, nonce, ct, tag, aad, fn):
    # fn 1 is chacha20-poly1305, anything else is aes-gcm
    try:
        if fn == 1:
            return ChaCha20Poly1305(key).decrypt(nonce, bytes(ct) + bytes(tag), aad or b"")
        return AESGCM(key).decrypt(nonce, bytes(ct) + bytes(tag), aad or b"")
    except Exception:
        return None


def aead_enc(key, nonce, pt, aad, fn):
    try:
        if fn == 1:
            return ChaCha20Poly1305(key).encrypt(nonce, bytes(pt), aad or b"")
        return AESGCM(key).encrypt(nonce, bytes(pt), aad or b"")
    except Exception:
        return None


def try_aead(buf, key, fn, aad_nonce):
    # decrypt nonce prefixed aead framed data
    if buf is None or key is None or len(buf) < 12 + 16 + 2:
        return None
    nonce = buf[:12]
    ct = buf[12:-16]
    tag = buf[-16:]
    aad = nonce if aad_nonce else b""
    return aead_dec(key, nonce, ct, tag, aad, fn)


def cal_info(cli_pub, srv_pub):
    # derive the hkdf info from both public keys
    out = bytearray(len(cli_pub))
    for i in range(len(cli_pub)):
        s = srv_pub[i % len(srv_pub)]
        t = ((s * 2) & 0xFF) if cli_pub[i] > s else (s >> 1)
        out[i] = cli_pub[i] ^ t
    return bytes(out)


def hkdf32(ikm, salt, info):
    # hkdf sha256 to 32 bytes
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes(salt), info=bytes(info)).derive(bytes(ikm))


def ecdh_x(priv32, peer_pub65):
    # shared secret x coordinate of p256 ecdh
    try:
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(peer_pub65))
        priv = ec.derive_private_key(int.from_bytes(bytes(priv32), "big"), ec.SECP256R1())
        return priv.exchange(ec.ECDH(), peer)
    except Exception:
        return None


def pub_of_priv(priv32):
    # uncompressed 65 byte public key of a private key
    try:
        k = ec.derive_private_key(int.from_bytes(bytes(priv32), "big"), ec.SECP256R1())
        return k.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    except Exception:
        return None


def k3(priv32, peer_pub65, cli_pub65, srv_pub65):
    # derive key3 the same way the client does
    if priv32 is None or len(priv32) != 32:
        return None
    if peer_pub65 is None or len(peer_pub65) != 65:
        return None
    if cli_pub65 is None or len(cli_pub65) != 65:
        return None
    if srv_pub65 is None or len(srv_pub65) != 65:
        return None
    sh = ecdh_x(priv32, peer_pub65)
    if sh is None:
        return None
    try:
        return hkdf32(sh, srv_pub65, cal_info(cli_pub65, srv_pub65))
    except Exception:
        return None


def try_derive_key3():
    # derive key3 from manual client private key
    if ST.derived_key3 is not None:
        return True
    priv = hex_bytes(CLIENT_PRIV_HEX)
    if len(priv) != 32 or ST.client_pub is None or ST.server_pub is None:
        return False
    sh = ecdh_x(priv, ST.server_pub)
    if sh is None:
        return False
    try:
        ST.derived_key3 = hkdf32(sh, ST.server_pub, cal_info(ST.client_pub, ST.server_pub))
        return True
    except Exception:
        return False


def ike_capture(body, is_req):
    # cache public keys and cipher from ike packets
    if is_req:
        r = pb_find(body, 3)
        if r and r[0] == 2 and len(r[1]) > 0:
            replaced = (ST.f1_pub is not None and r[1] == ST.f1_pub and ST.mitm_cli_pub is not None)
            if not replaced:
                ST.client_pub = r[1]
        return
    r = pb_find(body, 1)
    if r and r[0] == 2:
        try:
            ST.ike_token = r[1].decode("utf-8", "replace")
        except Exception:
            pass
    r = pb_find(body, 2)
    if r and r[0] == 0:
        ST.ike_cipher = int(r[1])
    r = pb_find(body, 3)
    if r and r[0] == 0:
        ST.ike_server_ts = int(r[1])
    r = pb_find(body, 4)
    if r and r[0] == 2 and len(r[1]) > 0:
        replaced = (ST.f2_pub is not None and r[1] == ST.f2_pub and ST.mitm_srv_pub is not None)
        if not replaced:
            ST.server_pub = r[1]
    try_derive_key3()


def mitm_init():
    # compute f1 and f2 public keys once
    if ST.f1_pub is not None and ST.f2_pub is not None:
        return True
    p1 = hex_bytes(F1_PRIV_HEX)
    p2 = hex_bytes(F2_PRIV_HEX)
    if len(p1) != 32 or len(p2) != 32:
        return False
    ST.f1_pub = pub_of_priv(p1)
    ST.f2_pub = pub_of_priv(p2)
    return ST.f1_pub is not None and ST.f2_pub is not None


def mitm_ike(wire, g, is_req):
    # rewrite the ephemeral public key inside an ike packet
    if wire is None or len(wire) < 30:
        return None, 0, None, None

    pt = nonce = None
    fn, tr = -1, 0
    aad_nonce = True

    for cur in (3, 1, 4, 2):
        if pt is not None:
            break
        d = transform(wire, cur, g)
        if d is None or len(d) < 30:
            continue
        n = d[:12]
        cl = len(d) - 12 - 16
        if cl < 2:
            continue
        ct, tag = d[12:12 + cl], d[-16:]
        for ai in range(2):
            aad = n if ai == 0 else b""
            for f in range(2):
                cand = (1 if f == 0 else 0) if ST.ike_cipher == 1 else (0 if f == 0 else 1)
                r = aead_dec(g, n, ct, tag, aad, cand)
                if r is not None and len(r) >= 5 and int.from_bytes(r[:2], "big") == (1 if is_req else 2):
                    pt, fn, tr, nonce, aad_nonce = r, cand, cur, n, (ai == 0)
                    break
    if pt is None:
        return None, 0, None, None
    pt = bytearray(pt)

    msg_id = int.from_bytes(pt[:2], "big")
    want = 3 if is_req else 4
    loc = pb_off(pt, 2, len(pt), want)
    if loc is None or loc[1] != 65 or pt[loc[0]] != 0x04:
        return None, 0, None, None

    off = loc[0]
    real_pub = bytes(pt[off:off + 65])
    mine = ST.f1_pub if is_req else ST.f2_pub
    if mine is None or len(mine) != 65:
        return None, 0, None, None
    pt[off:off + 65] = mine

    body = aead_enc(g, nonce, pt, nonce if aad_nonce else b"", fn)
    if body is None or len(body) != cl + 16:
        return None, 0, None, None

    w2 = bytearray(nonce + body)
    if tr == 1:
        obscure_req(w2, g)
    elif tr == 2:
        obscure_req2(w2, g)
    elif tr == 3:
        obscure_resp(w2, g)
    else:
        obscure_resp2(w2, g)

    note = ("clientPubKey" if is_req else "serverPubKey") + " replaced, fn=" \
        + ("chacha" if fn == 1 else "aes-gcm") + " aad=" + ("nonce" if aad_nonce else "none") \
        + " t=" + str(tr)
    return bytes(w2), msg_id, real_pub, note


def mitm_relay(wire, is_req, g):
    # decrypt a business packet and re-encrypt it with the other side key
    if ST.kcli is None or ST.ksrv is None:
        return None
    if wire is None or len(wire) < 30:
        return None

    key_in = ST.kcli if is_req else ST.ksrv
    key_out = ST.ksrv if is_req else ST.kcli

    for t in (0, 3, 1, 4, 2):
        d = transform(wire, t, g)
        if d is None or len(d) < 30:
            continue
        nonce = d[:12]
        cl = len(d) - 12 - 16
        if cl < 2:
            continue
        ct, tag = d[12:12 + cl], d[-16:]
        for ai in range(2):
            aad = nonce if ai == 0 else b""
            for f in range(2):
                fn = (1 if f == 0 else 0) if ST.ike_cipher == 1 else (0 if f == 0 else 1)
                pt = aead_dec(key_in, nonce, ct, tag, aad, fn)
                if pt is None:
                    continue
                body = aead_enc(key_out, nonce, pt, aad, fn)
                if body is None or len(body) != cl + 16:
                    return None
                r = bytearray(nonce + body)
                if t == 1:
                    obscure_req(r, g)
                elif t == 2:
                    obscure_req2(r, g)
                elif t == 3:
                    obscure_resp(r, g)
                elif t == 4:
                    obscure_resp2(r, g)
                ST.relay_cnt += 1
                return bytes(r)
    return None


def decode(wire, is_req):
    # decrypt one packet and split msgId from body, returns dict or None
    if wire is None or len(wire) < 30:
        return None

    garble = garble_bytes()
    hexsrc = KEY3_LIVE if len(KEY3_LIVE) == 64 else KEY3_HEX
    key3 = hex_bytes(hexsrc) if hexsrc else None
    if key3 is not None and len(key3) != 32:
        key3 = None
    if key3 is None and not garble and ST.kcli is None:
        return None

    keys, knm = [], []
    if key3 is not None:
        keys.append(key3)
        knm.append("key3@" if len(KEY3_LIVE) == 64 else "key3")
    try_derive_key3()
    if ST.derived_key3 is not None:
        keys.append(ST.derived_key3)
        knm.append("key3*")
    if ST.kcli is not None:
        keys.append(ST.kcli)
        knm.append("k3C")
    if ST.ksrv is not None:
        keys.append(ST.ksrv)
        knm.append("k3S")
    if garble:
        keys.append(garble)
        knm.append("garble")

    fn_order = (1, 0) if ST.ike_cipher == 1 else (0, 1)
    order = (0, 3, 4, 1, 2)
    tname = {0: "raw", 1: "req.ror", 2: "req.alt", 3: "resp.ror", 4: "resp.alt"}

    for t in order:
        d = transform(wire, t, garble)
        if d is None:
            continue
        for ki in range(len(keys)):
            key = keys[ki]
            if not key:
                continue
            for fn in fn_order:
                for ai in range(2):
                    pt = try_aead(d, key, fn, ai == 0)
                    if pt is None or len(pt) < 2:
                        continue
                    if is_req:
                        if int.from_bytes(pt[:2], "big") == 1:
                            mid, body_off = 1, 2
                        elif len(pt) >= 12:
                            mid, body_off = int.from_bytes(pt[10:12], "big"), 12
                        else:
                            continue
                    else:
                        mid, body_off = int.from_bytes(pt[:2], "big"), 2
                    if mid <= 0:
                        continue
                    return {
                        "msgId": mid,
                        "body": pt[body_off:],
                        "plain": pt,
                        "info": "t=%s key=%s fn=%s aad=%s" % (
                            tname[t], knm[ki], "chacha" if fn == 1 else "aes-gcm",
                            "nonce" if ai == 0 else "none"),
                        "key": key,
                        "keyName": knm[ki],
                        "nonce": d[:12],
                    }
    return None


def looks_plain(b):
    # plaintext text body check
    if b is None or len(b) < 64:
        return False
    if b[0] not in (0x24, 0x7B, 0x5B, 0x3C, 0x22, 0x2F):
        return False
    n = min(len(b), 4096)
    txt = sum(1 for c in b[:n] if c in (9, 10, 13) or 32 <= c < 127)
    return txt * 10 >= n * 9


def try_inflate(d):
    # gunzip or zlib inflate
    for wbits in (16 + zlib.MAX_WBITS, zlib.MAX_WBITS):
        try:
            return zlib.decompress(d, wbits)
        except Exception:
            pass
    return None


def looks_zlib(d):
    return len(d) > 2 and d[0] == 0x78 and ((d[0] << 8) | d[1]) % 31 == 0


def aes_cbc_dec(key, iv, ct):
    # aes 128 cbc with pkcs7 padding
    try:
        dec = Cipher(algorithms.AES(bytes(key)), modes.CBC(bytes(iv))).decryptor()
        pt = dec.update(bytes(ct)) + dec.finalize()
        if not pt or len(pt) % 16:
            return None
        n = pt[-1]
        if n < 1 or n > 16 or pt[-n:] != bytes([n]) * n:
            return None
        return pt[:-n]
    except Exception:
        return None


def static_plain(wire, region):
    # decrypt a serverlist or noticelist payload
    if wire is None or len(wire) < 32:
        return None
    wire = bytes(wire)

    un = try_inflate(wire)
    if un is not None:
        wire = un
    if len(wire) < 32:
        return None

    iv, ct = wire[:16], wire[16:]

    for r in [region] + [x for x in REGION_ORDER if x != region]:
        key = STATIC_KEYS.get(r)
        if not key:
            continue
        pt = aes_cbc_dec(key.encode("ascii"), iv, ct)
        if pt is not None and pb_fully_parses(pt):
            return pt
    return None


def boot():
    # warm up relay keys
    if MITM:
        mitm_init()
