# -*- coding: utf-8 -*-
# body panel contentview that renders decrypted game packets as json
import json

from mitmproxy import contentviews

from . import pb
from . import wire


class SSJsonView(object):
    # body panel view for decrypted game packets
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

    def _is_game(self, metadata):
        # game protocol flow check by host and path
        f = getattr(metadata, "flow", None)
        req = getattr(f, "request", None) if f is not None else None
        if req is None:
            return False
        host = (req.host or "").lower()
        if "static" in host or "cdn" in host or "assets" in host:
            return False
        path = (req.path or "").lower()
        return ("yostar" in host or "stellasora" in host or "stargazer" in host
                or "jvav" in host or "nova." in host or "agent-zone" in path)

    def render_priority(self, data, metadata):
        # auto select only binary bodies of game flows
        if not self._is_game(metadata) or data is None or len(data) < 30:
            return -1
        head = data[:64]
        printable = sum(1 for c in head if 32 <= c < 127 or c in (9, 10, 13))
        if printable * 2 >= len(head):
            return -1
        return 2

    def prettify(self, data, metadata):
        # decrypt one packet and render the json body
        if data is None or len(data) < 30:
            raise ValueError("not a game packet")

        d = self._direction(metadata)
        dec = None
        # response direction first, its msgId check is the strong one
        for is_req in ([d] if d is not None else (False, True)):
            dec = wire.decode(data, is_req)
            if dec is not None:
                break
        if dec is None:
            raise ValueError("decode failed, key3 not ready or not a game packet")

        mid = dec["msgId"]
        head = "msgId=%d (%s) %s" % (mid, pb.msg_name(mid), dec["info"])

        if mid == 1 or mid == 2:
            return head + "\nIKE handshake, pub keys captured"

        js = pb.body_json(mid, dec["body"])
        if js is None:
            return head + "\nbody not in proto table, hex:\n" + dec["body"][:256].hex()

        try:
            js = json.dumps(json.loads(js), ensure_ascii=False, indent=2)
        except Exception:
            pass
        return head + "\n" + js


contentviews.add(SSJsonView())
