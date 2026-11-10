# -*- coding: utf-8 -*-
# mitmweb addon entry
import logging

from . import wire
from . import pb


class SSDecoder(object):
    # hooks for mitmproxy, run mitmweb --scripts addon.py
    def request(self, flow):
        try:
            self._handle(flow, True)
        except Exception:
            logging.exception("SS request hook failed")

    def response(self, flow):
        try:
            if wire.STATIC_META and self._is_static(flow):
                self._log_static(flow)
                return
            self._handle(flow, False)
        except Exception:
            logging.exception("SS response hook failed")

    def _is_static(self, flow):
        # static resource session check
        kind = self._static_kind(flow)
        if kind is None:
            return False
        host = (flow.request.host or "").lower()
        return "static" in host or host in wire.STATIC_HOSTREGION

    def _static_kind(self, flow):
        # static resource type by request path
        path = (flow.request.path or "").lower()
        if "serverlist.html" in path:
            return "Pb.ServerListMeta"
        if "noticelist.html" in path:
            return "Pb.NoticeList"
        return None

    def _static_region(self, flow):
        # region of a static resource session
        host = (flow.request.host or "").lower()
        return wire.STATIC_HOSTREGION.get(host, wire.REGION)

    def _log_static(self, flow):
        # decrypt a static resource body and show the json, body stays untouched
        kind = self._static_kind(flow)
        logging.info("SS static %s" % kind)
        if flow.response is None:
            return
        wire_body = flow.response.raw_content
        if wire_body is None or len(wire_body) < 32:
            return
        body = wire.static_plain(wire_body, self._static_region(flow))
        if body is None:
            logging.info("SS static decrypt failed")
            return
        cls = pb.resolve(kind)
        js = pb.raw_json(cls, body) if cls is not None else None
        if js is None:
            logging.info("SS static %s plain hex %s" % (kind, body[:256].hex()))
            return
        show = js[:4000] + ("…(%d chars)" % len(js) if len(js) > 4000 else "")
        self._mark(flow, "static %s %s" % (kind, show))
        logging.info("SS static %s body %s" % (kind, show))

    def _is_game(self, flow):
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

    def _feed_key3(self, flow):
        # accept a key3 pushed via a marker request
        host = (flow.request.host or "").lower()
        path = (flow.request.path or "").lower()
        if "ss-key3" not in host and "__ss_k3" not in path:
            return False
        b = flow.request.raw_content or b""
        hexs = "".join(chr(c) for c in b if c not in (32, 9, 10, 13))
        ok = len(hexs) == 64
        if ok:
            wire.KEY3_LIVE = hexs
        logging.info("SS key3 inject " + ("ok" if ok else "failed, body len = %d" % len(hexs)))
        self._mark(flow, "key3 inject " + ("ok" if ok else "failed"))
        return True

    def _mark(self, flow, text):
        # attach a comment to the flow for the mitmweb ui
        try:
            flow.comment = text
            flow.marked = True
        except Exception:
            pass

    def _mitm_step(self, flow, is_req, wire_body):
        # relay entry, rewrites ike and re-encrypts business packets
        if not wire.mitm_init():
            logging.warning("SS MITM disabled, invalid F1/F2 private key")
            return None
        g = wire.garble_bytes()
        if not g:
            logging.warning("SS MITM disabled, no garble key for region " + wire.REGION)
            return None

        out = None
        if wire.ST.kcli is not None and wire.ST.ksrv is not None:
            out = wire.mitm_relay(wire_body, is_req, g)
            if out is not None:
                logging.info("SS MITM relayed %s, total %d packets"
                             % ("client to server" if is_req else "server to client",
                                wire.ST.relay_cnt))

        if out is None:
            if not is_req and wire.ST.mitm_cli_pub is None:
                logging.debug("SS MITM skip IKE response, matching request not seen")
                return None
            out, mid, real_pub, note = wire.mitm_ike(wire_body, g, is_req)
            if out is None:
                if wire.ST.kcli is None and not wire.ST.mitm_warned:
                    wire.ST.mitm_warned = True
                    logging.warning("SS MITM not taken over, handshake already done before mitmproxy start, "
                                    "restart the game so the handshake happens with mitmproxy ready")
                return None

            logging.info("SS MITM " + note)
            logging.info("SS MITM real %s = %s"
                         % ("clientPub" if is_req else "serverPub", real_pub.hex()))
            if is_req:
                wire.ST.pending_cli_pub = real_pub
            else:
                wire.ST.mitm_srv_pub = real_pub
                p1 = wire.hex_bytes(wire.F1_PRIV_HEX)
                p2 = wire.hex_bytes(wire.F2_PRIV_HEX)
                if wire.ST.mitm_cli_pub is not None and len(wire.ST.mitm_cli_pub) == 65 and len(real_pub) == 65:
                    wire.ST.kcli = wire.k3(p2, wire.ST.mitm_cli_pub, wire.ST.mitm_cli_pub, wire.ST.f2_pub)
                    wire.ST.ksrv = wire.k3(p1, real_pub, wire.ST.f1_pub, real_pub)
                if wire.ST.kcli is not None and wire.ST.ksrv is not None:
                    logging.info("SS MITM key3 client side = %s" % wire.ST.kcli.hex())
                    logging.info("SS MITM key3 server side = %s" % wire.ST.ksrv.hex())
                    logging.info("SS MITM relay ready, packets decrypted and re-encrypted")
                else:
                    logging.warning("SS MITM key3 failed, IKE request must be captured too")
                    wire.ST.mitm_fail += 1

        try:
            if is_req:
                flow.request.raw_content = out
            else:
                flow.response.raw_content = out
        except Exception:
            wire.ST.mitm_fail += 1
            if not is_req:
                wire.ST.kcli = None
                wire.ST.ksrv = None
            logging.warning("SS MITM write back failed, packet passed through")
            return None

        if is_req and getattr(wire.ST, "pending_cli_pub", None) is not None:
            wire.ST.mitm_cli_pub = wire.ST.pending_cli_pub
            wire.ST.pending_cli_pub = None
        return out

    def _handle(self, flow, is_req):
        # common flow for both directions
        if is_req and self._feed_key3(flow):
            return

        if not self._is_game(flow):
            return

        wire_body = flow.request.raw_content if is_req else flow.response.raw_content
        if wire_body is None or len(wire_body) < 30:
            return
        if wire.looks_plain(wire_body):
            return

        orig = wire_body
        if wire.MITM:
            self._mitm_step(flow, is_req, wire_body)

        dec = wire.decode(orig, is_req)
        if dec is None:
            logging.info("SS %s decode failed len=%d host=%s"
                         % ("REQ" if is_req else "RESP", len(wire_body),
                            (flow.request.host or "").lower()))
            return

        if is_req and dec["msgId"] == 1:
            wire.ike_capture(dec["body"], True)
        elif not is_req and dec["msgId"] == 2:
            wire.ike_capture(dec["body"], False)

        name = pb.msg_name(dec["msgId"])
        line = "%s msgId=%d (%s) nonce=%s key3=%s [%s]" % (
            "REQ" if is_req else "RESP", dec["msgId"], name,
            dec["nonce"].hex(), dec["key"].hex(), dec["keyName"])
        js = pb.body_json(dec["msgId"], dec["body"])
        if js is not None:
            self._mark(flow, line)
            logging.info(line)
            logging.info("%s body %s" % ("REQ" if is_req else "RESP",
                                         js[:4000] + ("…(%d chars)" % len(js) if len(js) > 4000 else "")))
        else:
            self._mark(flow, line + "  body=" + dec["body"][:64].hex())
            logging.info(line + "  body=" + dec["body"][:128].hex())
