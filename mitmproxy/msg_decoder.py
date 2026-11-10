# -*- coding: utf-8 -*-
# StellaSora mitmproxy decode and relay script
# usage mitmdump -s msg_decoder.py
# msgId table and schema are parsed from ../fiddler/msg_decoder.cs so both stay in sync
import logging
import os
import re
import zlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

try:
    from mitmproxy import http
except ImportError:
    http = None

HERE = os.path.dirname(os.path.abspath(__file__))

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

# decode body to JSON in the event log
LOG_JSON = False

# max json chars to log
LOG_JSON_MAX = 8000

# write each decoded body as a file when set
DUMP_DIR = ""

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

GUESS_SKIP = {
    "Nil", "Error", "Any", "Empty", "Ping", "Pong",
    "UI32", "I32", "UI64", "I64", "S32", "S64", "StringV", "Bytes", "BytesV", "Boolean",
    "ServerListMeta", "ServerAgent", "Rule", "NoticeList", "NoticeType", "NoticeItem",
}

# msgId to name map
MAP = {}

# message name to field spec
SCHEMA = {}

# per message field numbers and codes for guessing
GNUM = {}
GCODE = {}
GCACHE = {}


def load_tables():
    # parse SS_MAP_STR and SS_SCHEMA_STR out of the fiddler script
    path = os.environ.get("SS_TABLES") or os.path.join(HERE, "..", "fiddler", "msg_decoder.cs")
    src = open(path, encoding="utf-8").read()

    def extract(name):
        i = src.index("static string %s =" % name)
        j = src.index(";", i)
        lits = re.findall(r'"((?:[^"\\]|\\.)*)"', src[i:j])
        out = []
        for s in lits:
            s = s.replace("\\\\", "\x00").replace("\\n", "\n").replace('\\"', '"').replace("\x00", "\\")
            out.append(s)
        return "".join(out)

    for entry in extract("SS_MAP_STR").split("|"):
        if ":" not in entry:
            continue
        sid, name = entry.split(":", 1)
        try:
            MAP[int(sid)] = name
        except ValueError:
            pass

    text = extract("SS_SCHEMA_STR") + "\n" + extract("SS_SCHEMA_META")
    for line in text.split("\n"):
        if "|" not in line:
            continue
        name, spec = line.split("|", 1)
        SCHEMA[name] = spec

    for name, spec in SCHEMA.items():
        nums = []
        codes = []
        for part in spec.split(","):
            c1 = part.find(":")
            if c1 <= 0:
                continue
            c2 = part.find(":", c1 + 1)
            try:
                nums.append(int(part[:c1]))
            except ValueError:
                continue
            codes.append(part[c2 + 1:] if c2 > c1 else None)
        GNUM[name] = nums
        GCODE[name] = codes


def msg_name(mid):
    # resolve msgId to a readable name
    return MAP.get(mid, "0x%04X" % mid)


def schema_field(spec, num):
    # look up name, sub type and type code by field number
    if not spec:
        return None, None, None
    for part in spec.split(","):
        c1 = part.find(":")
        if c1 <= 0:
            continue
        try:
            if int(part[:c1]) != num:
                continue
        except ValueError:
            continue
        rest = part[c1 + 1:]
        c2 = -1
        for i, ch in enumerate(rest):
            if ch == ">" or ch == ":":
                c2 = i
                break
        name = rest if c2 < 0 else rest[:c2]
        tail = rest[c2:]
        if not tail:
            return name, None, None
        if tail[0] == ":":
            a = tail[1:]
            k = 1 if a.startswith("r") else 0
            if a[k:k + 1] == ">":
                return name, a[k + 1:], ("rm" if k else None)
            return name, None, a[k:]
        return name, tail[1:], None
    return None, None, None


def code_base(code):
    # base type char of a type code
    if not code:
        return "?"
    if code[0] == "r" and len(code) >= 2:
        return code[1]
    return code[0]


def code_is_repeated(code):
    return code is not None and len(code) >= 2 and code[0] == "r"


def code_match(code, wt):
    # check a type code against a protobuf wire type
    if not code:
        return False
    c = code[1] if code[0] == "r" and len(code) >= 2 else code[0]
    if c == ">" or c == "m":
        return wt == 2
    if wt == 0:
        return c == "i" or c == "l" or c == "u"
    if wt == 1:
        return c == "d"
    if wt == 5:
        return c == "f"
    return c == "s" or c == "b"


def packed_vals(d, off, ln, base_type):
    # decode a packed repeated scalar field
    p, end = off, off + ln
    vals = []
    while p < end:
        if base_type in ("i", "l", "u"):
            v, shift, done = 0, 0, False
            while p < end and shift < 64:
                b = d[p]
                p += 1
                v |= (b & 0x7F) << shift
                if not b & 0x80:
                    done = True
                    break
                shift += 7
            if not done:
                return None
        elif base_type == "f":
            if p + 4 > end:
                return None
            v = int.from_bytes(d[p:p + 4], "little")
            p += 4
        elif base_type == "d":
            if p + 8 > end:
                return None
            v = int.from_bytes(d[p:p + 8], "little")
            p += 8
        else:
            return None
        vals.append(v)
    return vals


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
        mark = p
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
        if p <= mark:
            return None
    return out or None


def pb_find(d, want):
    # find the first field value by number, returns (wt, int val) or (2, bytes)
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
        self.seq = 0
        self.last_resolved = None
        self.pending_cli_pub = None


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


def json_hex_out(d, off, ln):
    # hex string for binary fields, long ones are truncated
    show = min(ln, 128)
    s = d[off:off + show].hex()
    if ln > show:
        s += "…(%dB)" % ln
    return '"%s"' % s


def json_esc(s):
    # escape a string for json output
    out = []
    for c in s:
        v = ord(c)
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif c == "\n":
            out.append("\\n")
        elif c == "\r":
            out.append("\\r")
        elif c == "\t":
            out.append("\\t")
        elif v < 0x20 or v == 0x7F:
            out.append("\\u00%x%x" % ((v >> 4) & 0xF, v & 0xF))
        else:
            out.append(c)
    return "".join(out)


def is_printable(b):
    # readable utf8 text check
    if not b:
        return False
    for c in b:
        if c in (9, 10, 13):
            continue
        if 32 <= c < 127 or c >= 0x80:
            continue
        return False
    try:
        bytes(b).decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def signed(v, bits):
    # wrap an unsigned value to the given bit width
    m = 1 << bits
    v &= m - 1
    return v - m if v >= (m >> 1) else v


def json_val(d, wt, vo, vl, sub, code, depth, owner_type):
    # render one field value
    if sub is not None and wt == 2:
        if sub == "Any":
            return json_any(d, vo, vl, depth)
        r = json_msg(d, vo, vl, depth + 1, sub)
        if r is not None:
            return r

    if wt == 2 and sub is None and code is None:
        r = json_msg(d, vo, vl, depth + 1, None)
        if r is not None:
            return r

    if wt == 0:
        v = 0
        for i in range(min(vl, 10)):
            v |= (d[vo + i] & 0x7F) << (7 * i)
        bt = code_base(code)
        if bt == "i":
            return str(signed(v, 32))
        if bt == "l":
            return str(signed(v, 64))
        if v > (1 << 63) - 1:
            return str(signed(v, 64))
        return str(v)

    if wt in (1, 5):
        v = int.from_bytes(d[vo:vo + vl], "little")
        return str(v)

    bt = code_base(code)

    if code_is_repeated(code) and bt in ("i", "l", "u", "f", "d"):
        vals = packed_vals(d, vo, vl, bt)
        if vals:
            out = []
            for v in vals:
                if bt == "i":
                    out.append(str(signed(v, 32)))
                elif bt == "l":
                    out.append(str(signed(v, 64)))
                else:
                    out.append(str(v))
            return "[" + ",".join(out) + "]"

    if bt == "s":
        try:
            return '"' + json_esc(d[vo:vo + vl].decode("utf-8")) + '"'
        except UnicodeDecodeError:
            return json_hex_out(d, vo, vl)

    if bt == "b":
        return json_hex_out(d, vo, vl)

    val = d[vo:vo + vl]
    if is_printable(val):
        return '"' + json_esc(val.decode("utf-8", "replace")) + '"'
    return json_hex_out(d, vo, vl)


def json_any(d, off, ln, depth):
    # expand a google.protobuf.Any value
    url = None
    voff, vln = -1, 0
    fields = scan_fields(d, off, ln)
    if fields:
        for fn, wt, fo, fl in fields:
            if wt != 2:
                continue
            if fn == 1:
                url = d[fo:fo + fl].decode("utf-8", "replace")
            elif fn == 2:
                voff, vln = fo, fl

    tname = None
    if url:
        tname = url.rsplit("/", 1)[-1]
        tname = tname.rsplit(".", 1)[-1]

    out = "{"
    if url is not None:
        out += '"@type":"' + json_esc(url) + '"'

    if voff >= 0 and vln > 0 and depth < 12:
        tmp = None
        if tname:
            tmp = json_msg(d, voff, vln, depth + 1, tname)
        if tmp is None:
            tmp = json_msg(d, voff, vln, depth + 1, None)
        if url is not None:
            out += ","
        if tmp is not None:
            out += '"value":' + tmp
        else:
            out += '"value":' + json_hex_out(d, voff, vln)
    return out + "}"


def json_next(d, off, ln, depth, owner_type):
    # expand a NextPackage continuation value
    skip = -1
    for k in range(3):
        if ln - k < 2:
            continue
        if scan_fields(d, off + k, ln - k):
            skip = k
            break
    if skip < 0:
        return json_hex_out(d, off, ln)

    tmp = None
    if owner_type and depth < 10:
        tmp = json_msg(d, off + skip, ln - skip, depth + 1, owner_type)
    if tmp is None:
        tmp = json_msg(d, off + skip, ln - skip, depth + 1, None)
    return tmp if tmp is not None else json_hex_out(d, off, ln)


def guess_skip(n):
    # placeholder messages never take part in guessing
    return n is None or n in GUESS_SKIP


def miss_count(spec, fns):
    # count field numbers missing from a spec
    if spec is None:
        return len(fns)
    miss = 0
    for fn in fns:
        if schema_field(spec, fn)[0] is None:
            miss += 1
    return miss


def guess_score(type_name, d, off, ln, depth):
    # recursive compatibility score, -1 means clearly wrong
    if depth > 3:
        return 0
    spec = SCHEMA.get(type_name) if type_name else None
    if spec is None:
        return -1
    fields = scan_fields(d, off, ln)
    if not fields:
        return -1
    score = 0
    for fn, wt, fo, fl in fields:
        nm, sub, cd = schema_field(spec, fn)
        if nm is None:
            score -= 1
            continue
        if sub is not None:
            if wt != 2:
                return -1
        elif not code_match(cd, wt):
            return -1
        if sub is None and cd is not None and cd[0] == "s" and wt == 2:
            try:
                d[fo:fo + fl].decode("utf-8")
            except UnicodeDecodeError:
                return -1
        score += 2
        if wt == 2 and sub is not None and sub != "Any" and fl > 1:
            s2 = guess_score(sub, d, fo, fl, depth + 1)
            if s2 < 0:
                return -1
            score += s2
    return score


def schema_guess(d, off, ln, fns, wts):
    # guess a message type from field numbers and wire types
    un, uw = [], []
    for i in range(len(fns)):
        if fns[i] not in un:
            un.append(fns[i])
            uw.append(wts[i])

    sig = ",".join("%d_%d" % (a, b) for a, b in zip(un, uw)) + "#" + str(ln)
    if sig in GCACHE:
        return GCACHE[sig] or None

    best, best_score, best_cnt = None, -1, 0
    for mn in GNUM:
        if guess_skip(mn):
            continue
        nums = GNUM[mn]
        if len(nums) < len(un) or len(nums) - len(un) > 2:
            continue
        codes = GCODE[mn]
        ok = True
        for i in range(len(un)):
            j = -1
            for k in range(len(nums)):
                if nums[k] == un[i]:
                    j = k
                    break
            if j < 0 or not code_match(codes[j], uw[i]):
                ok = False
                break
        if not ok:
            continue
        sc = guess_score(mn, d, off, ln, 0)
        if sc < 0:
            continue
        if sc > best_score:
            best_score, best_cnt, best = sc, 1, mn
        elif sc == best_score:
            best_cnt += 1

    if best_cnt != 1:
        best = None
    GCACHE[sig] = best or ""
    return best


def json_msg(d, off, ln, depth, type_name):
    # render one protobuf message as json, returns None when it does not parse
    if depth > 12:
        return None
    spec = SCHEMA.get(type_name) if type_name else None
    fields = scan_fields(d, off, ln)
    if not fields:
        return None

    fns = [f[0] for f in fields]
    wts = [f[1] for f in fields]

    if fields and (spec is None or guess_skip(type_name)):
        miss = miss_count(spec, fns)
        if miss > 0:
            g = schema_guess(d, off, ln, fns, wts)
            if g is not None:
                gs = SCHEMA.get(g)
                if gs is not None and miss_count(gs, fns) < miss:
                    spec = gs
                    type_name = g
                    if depth == 0:
                        ST.last_resolved = g

    order, subs, codes, grp = [], {}, {}, {}
    for i, (fn, wt, fo, fl) in enumerate(fields):
        nm, sub, cd = schema_field(spec, fn) if spec else (None, None, None)
        key = nm if nm is not None else str(fn)
        if key not in grp:
            grp[key] = []
            order.append(key)
            subs[key] = sub
            codes[key] = cd
        grp[key].append(i)

    parts = []
    for key in order:
        sub, cd, g = subs[key], codes[key], grp[key]
        force_arr = (cd is not None and len(cd) >= 2 and cd[0] == "r" and cd[1] in ("m", "s", "b"))

        def render(idx):
            fn, wt, fo, fl = fields[idx]
            if fn == 2047 and wt == 2:
                return json_next(d, fo, fl, depth, type_name)
            return json_val(d, wt, fo, fl, sub, cd, depth, type_name)

        if len(g) == 1 and not force_arr:
            parts.append('"%s":%s' % (json_esc(key), render(g[0])))
        else:
            parts.append('"%s":[%s]' % (json_esc(key), ",".join(render(i) for i in g)))

    if not order:
        return "{}"
    return "{" + ",".join(parts) + "}"


def json_body(body, type_name):
    # render a full message body
    if not body:
        return None
    ST.last_resolved = None
    return json_msg(body, 0, len(body), 0, type_name)


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


def pb_fully_parses(d):
    # a payload is accepted when it scans cleanly as protobuf
    return bool(scan_fields(d, 0, len(d)))


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


def looks_plain(b):
    # plaintext text body check
    if b is None or len(b) < 64:
        return False
    if b[0] not in (0x24, 0x7B, 0x5B, 0x3C, 0x22, 0x2F):
        return False
    n = min(len(b), 4096)
    txt = sum(1 for c in b[:n] if c in (9, 10, 13) or 32 <= c < 127)
    return txt * 10 >= n * 9


def try_feed_key3(flow):
    # accept a key3 pushed via a marker request
    host = (flow.request.host or "").lower()
    path = (flow.request.path or "").lower()
    if "ss-key3" not in host and "__ss_k3" not in path:
        return False
    b = flow.request.raw_content or b""
    hexs = "".join(chr(c) for c in b if c not in (32, 9, 10, 13))
    ok = len(hexs) == 64
    if ok:
        globals()["KEY3_LIVE"] = hexs
    logging.info("SS key3 inject " + ("ok" if ok else "failed, body len = %d" % len(hexs)))
    return True


def static_kind(flow):
    # static resource type by request path
    path = (flow.request.path or "").lower()
    if "serverlist.html" in path:
        return "ServerListMeta"
    if "noticelist.html" in path:
        return "NoticeList"
    return None


def is_static(flow):
    # static resource session check
    if static_kind(flow) is None:
        return False
    host = (flow.request.host or "").lower()
    return "static" in host or host in STATIC_HOSTREGION


def static_region(flow):
    # region of a static resource session
    host = (flow.request.host or "").lower()
    return STATIC_HOSTREGION.get(host, REGION)


def is_game_session(flow):
    # game protocol session check
    host = (flow.request.host or "").lower()
    path = (flow.request.path or "").lower()
    if "static" in host or "cdn" in host or "assets" in host:
        return False
    host_ok = ("yostar" in host or "stellasora" in host or "stargazer" in host
               or "jvav" in host or "nova." in host)
    path_ok = "agent-zone" in path
    if not host_ok and not path_ok:
        return False
    req = flow.request.raw_content
    rsp = flow.response.raw_content if flow.response is not None else None
    b = req if req is not None and len(req) >= 30 else rsp
    if b is None or len(b) < 30:
        return False
    if b[0] == 0x1F and b[1] == 0x8B:
        return False
    if b[0] == 0x7B and b[1] in (0x22, 0x0A):
        return False
    if b[0] == 0x3C:
        return False
    return True


def line_info(dec, is_req):
    # one info line for a decoded packet
    nm = msg_name(dec["msgId"])
    s = ("REQ " if is_req else "RESP") + " msgId=%d (%s)" % (dec["msgId"], nm)
    if ST.last_resolved and ST.last_resolved != nm:
        s += " type=" + ST.last_resolved
    if dec.get("nonce"):
        s += " nonce=" + dec["nonce"].hex()
    if dec.get("key"):
        s += " key3=" + dec["key"].hex()
        if dec.get("keyName"):
            s += " [" + dec["keyName"] + "]"
    return s


def dump_body(dec, is_req, flow, type_name):
    # log or write the decoded json body
    body = dec["body"]
    text = "{}" if not body else json_body(body, type_name)
    if text is None:
        return
    tag = "REQ" if is_req else "RESP"
    if DUMP_DIR:
        ST.seq += 1
        try:
            os.makedirs(DUMP_DIR, exist_ok=True)
            fn = os.path.join(DUMP_DIR, "%05d-%s-%d.json" % (ST.seq, tag, dec["msgId"]))
            with open(fn, "w", encoding="utf-8") as f:
                f.write(text)
        except OSError:
            pass
    if LOG_JSON:
        show = text[:LOG_JSON_MAX]
        if len(text) > LOG_JSON_MAX:
            show += "…(%d chars)" % len(text)
        logging.info("%s %s body %s" % (tag, dec["msgId"], show))


class SSDecoder(object):
    # mitmproxy addon entry
    def request(self, flow):
        try:
            self._handle(flow, True)
        except Exception:
            logging.exception("SS request hook failed")

    def response(self, flow):
        try:
            if STATIC_META and is_static(flow):
                self._write_static(flow)
                return
            self._handle(flow, False)
        except Exception:
            logging.exception("SS response hook failed")

    def _write_static(self, flow):
        # replace a static resource body with its plaintext or json
        logging.info("SS static %s" % static_kind(flow))
        if flow.response is None:
            return
        wire = flow.response.raw_content
        if wire is None or len(wire) < 32:
            return
        body = static_plain(wire, static_region(flow))
        if body is None:
            logging.info("SS static decrypt failed")
            return
        js = json_body(body, static_kind(flow))
        payload = js.encode("utf-8") if js is not None else body
        flow.response.content = payload
        flow.response.headers["content-length"] = str(len(flow.response.raw_content))
        if js is not None and DUMP_DIR:
            ST.seq += 1
            try:
                os.makedirs(DUMP_DIR, exist_ok=True)
                fn = os.path.join(DUMP_DIR, "%05d-%s.json" % (ST.seq, static_kind(flow)))
                with open(fn, "w", encoding="utf-8") as f:
                    f.write(js)
            except OSError:
                pass

    def _mitm_step(self, flow, is_req, wire):
        # relay entry, rewrites ike and re-encrypts business packets
        if not mitm_init():
            logging.warning("SS MITM disabled, invalid F1/F2 private key")
            return None
        g = garble_bytes()
        if not g:
            logging.warning("SS MITM disabled, no garble key for region " + REGION)
            return None

        out = None
        if ST.kcli is not None and ST.ksrv is not None:
            out = mitm_relay(wire, is_req, g)
            if out is not None:
                logging.info("SS MITM relayed %s, total %d packets"
                             % ("client to server" if is_req else "server to client", ST.relay_cnt))

        if out is None:
            if not is_req and ST.mitm_cli_pub is None:
                logging.debug("SS MITM skip IKE response, matching request not seen")
                return None
            out, mid, real_pub, note = mitm_ike(wire, g, is_req)
            if out is None:
                if ST.kcli is None and not ST.mitm_warned:
                    ST.mitm_warned = True
                    logging.warning("SS MITM not taken over, handshake already done before mitmproxy start, "
                                    "restart the game so the handshake happens with mitmproxy ready")
                return None

            if is_req:
                ST.pending_cli_pub = real_pub
                logging.info("SS MITM " + note)
                logging.info("SS MITM real clientPub = %s" % real_pub.hex())
                logging.info("SS MITM replaced with F1_pub = %s" % ST.f1_pub.hex())
            else:
                ST.mitm_srv_pub = real_pub
                logging.info("SS MITM " + note)
                logging.info("SS MITM real serverPub = %s" % real_pub.hex())
                logging.info("SS MITM replaced with F2_pub = %s" % ST.f2_pub.hex())
                p1 = hex_bytes(F1_PRIV_HEX)
                p2 = hex_bytes(F2_PRIV_HEX)
                if ST.mitm_cli_pub is not None and len(ST.mitm_cli_pub) == 65 and len(real_pub) == 65:
                    ST.kcli = k3(p2, ST.mitm_cli_pub, ST.mitm_cli_pub, ST.f2_pub)
                    ST.ksrv = k3(p1, real_pub, ST.f1_pub, real_pub)
                if ST.kcli is not None and ST.ksrv is not None:
                    logging.info("SS MITM key3 client side = %s" % ST.kcli.hex())
                    logging.info("SS MITM key3 server side = %s" % ST.ksrv.hex())
                    logging.info("SS MITM relay ready, packets decrypted and re-encrypted")
                else:
                    logging.warning("SS MITM key3 failed, IKE request must be captured too")
                    ST.mitm_fail += 1

        try:
            if is_req:
                flow.request.raw_content = out
            else:
                flow.response.raw_content = out
        except Exception:
            ST.mitm_fail += 1
            if not is_req:
                ST.kcli = None
                ST.ksrv = None
            logging.warning("SS MITM write back failed, packet passed through")
            return None

        if is_req and getattr(ST, "pending_cli_pub", None) is not None:
            ST.mitm_cli_pub = ST.pending_cli_pub
            ST.pending_cli_pub = None
        return out

    def _handle(self, flow, is_req):
        # common flow for both directions
        if is_req and try_feed_key3(flow):
            return

        if not is_game_session(flow):
            return

        wire = flow.request.raw_content if is_req else flow.response.raw_content
        if wire is None or len(wire) < 30:
            return
        if looks_plain(wire):
            return

        orig = wire
        if MITM:
            self._mitm_step(flow, is_req, wire)

        dec = decode(orig, is_req)
        if dec is None:
            if not is_req and flow.response is not None:
                logging.info("SS RESP decode failed len=%d host=%s"
                             % (len(wire), (flow.request.host or "").lower()))
            return

        if is_req and dec["msgId"] == 1:
            ike_capture(dec["body"], True)
        elif not is_req and dec["msgId"] == 2:
            ike_capture(dec["body"], False)

        logging.info(line_info(dec, is_req))
        logging.debug("SS %s %s" % ("REQ" if is_req else "RESP", dec["info"]))
        dump_body(dec, is_req, flow, msg_name(dec["msgId"]))


def boot():
    # warm up tables and relay keys
    load_tables()
    if MITM:
        mitm_init()


boot()

if http is not None:
    addons = [SSDecoder()]
