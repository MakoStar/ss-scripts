# -*- coding: utf-8 -*-
# generate ss_decoder/msgid.py from NetMsgId.lua
# usage python gen_msgid.py [--lua path] [--out path]
import argparse
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))

# table entry [1002] = "proto.PlayerInfo"
RE_ENTRY = re.compile(r'\[(-?\d+)\]\s*=\s*"([\w.]+)"')


def read_map(path):
    # read all id to message name pairs
    src = open(path, encoding="utf-8").read()
    pairs = RE_ENTRY.findall(src)
    if not pairs:
        raise SystemExit("no entry in " + path)
    seen = {}
    for sid, name in pairs:
        i = int(sid)
        if i not in seen:
            seen[i] = name
    return seen


def render(seen):
    # render as a python dict, message names keep their proto. prefix
    lines = ["# generated from NetMsgId.lua, do not edit", "MSG_ID = {"]
    for i in sorted(seen):
        lines.append('    %d: "%s",' % (i, seen[i]))
    lines.append("}")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lua", default=os.path.join(HERE, "NetMsgId.lua"))
    ap.add_argument("--out", default=os.path.join(HERE, "ss_decoder", "msgid.py"))
    a = ap.parse_args()

    seen = read_map(a.lua)
    text = render(seen)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    open(a.out, "w", encoding="utf-8", newline="\n").write(text)
    print("entries:", len(seen))
    print("written:", a.out)


if __name__ == "__main__":
    main()
