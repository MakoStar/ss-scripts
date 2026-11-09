# -*- coding: utf-8 -*-
# 从 NetMsgId.lua 生成 msgId 名称表，写回 msg_decoder.cs 的 SS_MAP_STR
# 用法 python gen_map.py [--lua 路径] [--cs 路径] [--write]
import argparse
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))

# 匹配表项 [1001] = "proto.LoginReq"
RE_ENTRY = re.compile(r'\[(-?\d+)\]\s*=\s*"proto\.([\w.]+)"')

# 每段 C# 字符串的最大长度
CHUNK = 400


def read_map(path):
    # 读出所有 id 到名字的映射
    src = open(path, encoding="utf-8").read()
    pairs = RE_ENTRY.findall(src)
    if not pairs:
        raise SystemExit("no entry in " + path)
    # 同一个 id 只保留第一次出现
    seen = {}
    for sid, name in pairs:
        i = int(sid)
        if i not in seen:
            seen[i] = name
    return seen


def build_body(seen):
    # 拼成 1001:LoginReq|1002:PlayerInfo 形式
    return "|".join("%d:%s" % (i, seen[i]) for i in sorted(seen))


def write_cs(path, body):
    # 按固定长度切段，段间用 + 连接
    chunks = [body[p:p + CHUNK] for p in range(0, len(body), CHUNK)]
    lit = []
    for i, c in enumerate(chunks):
        esc = c.replace("\\", "\\\\").replace('"', '\\"')
        lit.append('    "%s"%s' % (esc, "" if i == len(chunks) - 1 else " +"))
    block = "static string SS_MAP_STR =\n" + "\n".join(lit) + ";\n"

    # 只替换 SS_MAP_STR 与 SS_SCHEMA_STR 之间的部分
    cs = open(path, encoding="utf-8").read()
    start = cs.find("static string SS_MAP_STR =")
    end = cs.find("static string SS_SCHEMA_STR =")
    if start < 0 or end < 0 or end < start:
        raise SystemExit("SS_MAP_STR block not found in " + path)
    cs = cs[:start] + block + "\n" + cs[end:]
    open(path, "w", encoding="utf-8", newline="\n").write(cs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lua", default=os.path.join(HERE, "NetMsgId.lua"))
    ap.add_argument("--cs", default=os.path.join(HERE, "msg_decoder.cs"))
    ap.add_argument("--write", action="store_true")
    a = ap.parse_args()

    seen = read_map(a.lua)
    body = build_body(seen)
    print("entries:", len(seen), "bytes:", len(body))

    if a.write:
        write_cs(a.cs, body)
        print("written:", a.cs)


if __name__ == "__main__":
    main()
