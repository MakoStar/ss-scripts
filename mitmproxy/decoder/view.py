# -*- coding: utf-8 -*-
# body panel contentview that renders decrypted game packets as json
import json

from mitmproxy import contentviews

from . import pb
from . import wire


class SSJsonView(object):
    # body panel view for decrypted game packets and static resources
    name = "SS JSON"
    syntax_highlight = "javascript"

    def _direction(self, metadata):
        # request or response direction from the flow
        f = getattr(metadata, "flow", None)
        msg = getattr(metadata, "http_message", None)
        if f is not None and msg is not None and getattr(f, "response", None) is not None:
            if msg is f.response:
                return False
            if msg is f.request:
                return True
        return None

    def _host(self, metadata):
        # lowercase request host of the flow
        f = getattr(metadata, "flow", None)
        req = getattr(f, "request", None) if f is not None else None
        return (req.host or "").lower() if req is not None else None

    def _is_capture(self, metadata):
        # one of the configured capture domains
        host = self._host(metadata)
        if not host:
            return False
        for d in wire.CAPTURE_DOMAINS:
            if host == d or host.endswith("." + d):
                return True
        return False

    def _is_static(self, metadata):
        # static resource flow
        host = self._host(metadata) or ""
        if "static" not in host:
            return False
        f = getattr(metadata, "flow", None)
        path = (f.request.path or "").lower() if f is not None else ""
        return "serverlist.html" in path or "noticelist.html" in path

    def render_priority(self, data, metadata):
        # auto select encrypted bodies of capture domains
        if data is None or len(data) < 30:
            return -1
        if self._is_static(metadata):
            return 2
        if not self._is_capture(metadata):
            return -1
        head = data[:64]
        printable = sum(1 for c in head if 32 <= c < 127 or c in (9, 10, 13))
        if printable * 2 >= len(head):
            return -1
        return 2

    def _static_text(self, data, metadata):
        # decrypt a serverlist or noticelist body
        f = metadata.flow
        path = (f.request.path or "").lower()
        kind = "Pb.ServerListMeta" if "serverlist.html" in path else "Pb.NoticeList"
        host = (f.request.host or "").lower()
        region = wire.STATIC_HOSTREGION.get(host, wire.REGION)
        body = wire.static_plain(data, region)
        if body is None:
            return "static %s decrypt failed (region %s)" % (kind, region)
        cls = pb.resolve(kind)
        js = pb.raw_json(cls, body) if cls is not None else None
        if js is None:
            return "static %s\nplain hex:\n%s" % (kind, body[:256].hex())
        return "static %s (%s)\n%s" % (kind, region, js)

    def _ike_text(self, body, is_req):
        # decoded handshake fields
        parts = []
        if is_req:
            r = wire.pb_find(body, 3)
            if r and r[0] == 2:
                parts.append("clientPub=" + r[1].hex())
        else:
            r = wire.pb_find(body, 1)
            if r and r[0] == 2:
                parts.append("token=" + r[1].decode("utf-8", "replace"))
            r = wire.pb_find(body, 2)
            if r and r[0] == 0:
                parts.append("cipher=" + ("chacha" if int(r[1]) == 1 else "aes-gcm"))
            r = wire.pb_find(body, 3)
            if r and r[0] == 0:
                parts.append("serverTs=%d" % int(r[1]))
            r = wire.pb_find(body, 4)
            if r and r[0] == 2:
                parts.append("serverPub=" + r[1].hex())
        return "\n".join(parts)

    def _render(self, dec):
        # one decoded packet to display text
        mid = dec["msgId"]
        head = "msgId=%d (%s) %s" % (mid, pb.msg_name(mid), dec["info"])

        if mid in (1, 2):
            t = self._ike_text(dec["body"], mid == 1)
            return head + ("\n" + t if t else "\nIKE handshake")

        if not dec["body"]:
            return head + "\n{}"

        js = pb.body_json(mid, dec["body"])
        if js is None:
            return head + "\nbody not in proto table, hex:\n" + dec["body"][:256].hex()

        try:
            js = json.dumps(json.loads(js), ensure_ascii=False, indent=2)
        except Exception:
            pass
        return head + "\n" + js

    def prettify(self, data, metadata):
        # decrypt one packet and render, both directions when unknown
        if data is None or len(data) < 30:
            raise ValueError("not a game packet")

        if self._is_static(metadata):
            return self._static_text(data, metadata)

        d = self._direction(metadata)
        dirs = [d] if d is not None else (False, True)
        results = []
        for is_req in dirs:
            dec = wire.decode(data, is_req)
            if dec is not None:
                results.append(dec)

        if not results:
            raise ValueError("decode failed, key3 not ready or not a game packet")

        # prefer the result whose msgId is a known message,
        # fixes wrong hits of the weak request side msgId check
        for dec in results:
            if dec["msgId"] in (1, 2) or dec["msgId"] in pb.MSG_ID:
                return self._render(dec)
        return self._render(results[0])


def register():
    # called from the addon load hook so the ui picks up the view
    contentviews.add(SSJsonView())
