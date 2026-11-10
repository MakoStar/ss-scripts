# -*- coding: utf-8 -*-
# parse decoded bodies with the generated pb2 module and render json
import base64
import json

from google.protobuf.json_format import MessageToDict

from . import proto_pb2
from . import PB_pb2
from .msgid import MSG_ID

# max recursion for Any and NextPackage expansion
MAX_DEPTH = 8

# root scopes, proto is a top level message, Pb is the package of PB_pb2
ROOTS = {
    "proto": getattr(proto_pb2, "proto", None),
    "Pb": PB_pb2,
}


def resolve(full):
    # resolve proto.PlayerInfo or Pb.ServerListMeta to the message class
    if not full:
        return None
    name = full
    root = None
    if "." in full:
        head, rest = full.split(".", 1)
        root = ROOTS.get(head)
        if root is not None:
            name = rest
    for cur in ([root] if root is not None else list(ROOTS.values())):
        obj = cur
        ok = obj is not None
        for part in name.split("."):
            obj = getattr(obj, part, None) if obj is not None else None
            if obj is None:
                ok = False
                break
        if ok:
            return obj
    return None


def msg_name(mid):
    # short message name of a msgId
    full = MSG_ID.get(mid)
    return full.rsplit(".", 1)[-1] if full else "0x%04X" % mid


def parse(msg_id, body):
    # parse a decoded body into a message instance, None when unknown
    if not body:
        return None
    cls = resolve(MSG_ID.get(msg_id, ""))
    if cls is None:
        return None
    m = cls()
    try:
        m.ParseFromString(bytes(body))
    except Exception:
        return None
    return m


def to_json(msg):
    # message instance to pretty json text with Any and NextPackage expanded
    d = MessageToDict(msg, preserving_proto_field_name=True)
    return json.dumps(post(d, msg.DESCRIPTOR.name, 0), ensure_ascii=False, indent=2)


def post(obj, owner, depth):
    # expand Any values and NextPackage continuation bytes
    if depth > MAX_DEPTH:
        return obj
    if isinstance(obj, list):
        return [post(x, owner, depth) for x in obj]
    if not isinstance(obj, dict):
        return obj

    # google.protobuf.Any, both fields must be present
    tu = obj.get("type_url")
    val = obj.get("value")
    if isinstance(tu, str) and "value" in obj:
        cls = resolve(tu.rsplit("/", 1)[-1])
        if cls is not None and isinstance(val, str) and val:
            try:
                m = cls()
                m.ParseFromString(base64.b64decode(val))
                out = {"@type": tu}
                out.update(post(MessageToDict(m, preserving_proto_field_name=True),
                                cls.DESCRIPTOR.name, depth + 1))
                for k, v in obj.items():
                    if k not in ("type_url", "value"):
                        out[k] = post(v, owner, depth + 1)
                return out
            except Exception:
                pass

    # NextPackage bytes hold the next message of the same type
    np = obj.get("NextPackage")
    if isinstance(np, str) and np and owner is not None:
        cls = resolve(owner)
        if cls is not None:
            try:
                raw = base64.b64decode(np)
            except Exception:
                raw = b""
            for skip in (0, 1, 2):
                if len(raw) - skip < 2:
                    continue
                m = cls()
                try:
                    m.ParseFromString(raw[skip:])
                except Exception:
                    continue
                out = post(MessageToDict(m, preserving_proto_field_name=True), owner, depth + 1)
                for k, v in obj.items():
                    if k != "NextPackage":
                        out[k] = post(v, owner, depth + 1)
                return out

    return {k: post(v, owner, depth + 1) for k, v in obj.items()}


def raw_json(cls, raw):
    # parse raw protobuf bytes of a known class and return pretty json text
    m = cls()
    try:
        m.ParseFromString(bytes(raw))
    except Exception:
        return None
    d = MessageToDict(m, preserving_proto_field_name=True)
    return json.dumps(post(d, cls.DESCRIPTOR.name, 0), ensure_ascii=False, indent=2)


def body_json(msg_id, body):
    # decoded body to json text, None when the msgId is unknown
    m = parse(msg_id, body)
    if m is None:
        return None
    return to_json(m)
