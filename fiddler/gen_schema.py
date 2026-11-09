# -*- coding: utf-8 -*-
# 从 proto.proto 生成字段表，写回 msg_decoder.cs 的 SS_SCHEMA_STR
# 用法 python gen_schema.py [--proto 路径] [--cs 路径] [--write]
#
# 行格式 1:Id:i,2:Items>Item,3:Ids:ri
# 类型码 i int  l int64  u uint bool enum  f float  d double  s string  b bytes
#        >X message，前缀 r 表示 repeated
import argparse
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))

# 标量类型到类型码
SCALAR = {
    "int32": "i", "sint32": "i", "sfixed32": "i",
    "int64": "l", "sint64": "l", "sfixed64": "l",
    "uint32": "u", "uint64": "u", "bool": "u",
    "fixed32": "f", "float": "f",
    "fixed64": "d", "double": "d",
    "string": "s", "bytes": "b",
}

RE_MSG = re.compile(r"^message\s+(\w+)\s*\{")
RE_ENUM = re.compile(r"^enum\s+(\w+)\s*\{")
RE_ONEOF = re.compile(r"^oneof\s+(\w+)\s*\{")
RE_FIELD = re.compile(
    r"^(?:(optional|repeated|required)\s+)?([\w.]+)\s+(\w+)\s*=\s*(\d+)\s*(?:\[[^\]]*\])?\s*;")

# 每段 C# 字符串的最大长度
CHUNK = 400


def scan_enums(lines):
    # 先收集所有 enum 短名，避免引用到后面才定义的 enum 被当成 message
    names = set()
    for line in lines:
        s = line.strip()
        m = RE_ENUM.match(s)
        if m:
            names.add(m.group(1))
    return names


def parse(lines, enums):
    # 逐行解析 message 与字段，返回全名到字段列表
    fields = {}
    order = []
    stack = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("//"):
            continue

        m = RE_MSG.match(s)
        if m:
            parent = stack[-1][1] + "." if stack and stack[-1][0] == "m" else ""
            full = parent + m.group(1)
            stack.append(("m", full))
            if full not in fields:
                fields[full] = []
                order.append(full)
            continue

        if RE_ENUM.match(s):
            stack.append(("e", ""))
            continue

        if RE_ONEOF.match(s):
            stack.append(("o", ""))
            continue

        if s.startswith("}"):
            if stack:
                stack.pop()
            continue

        m = RE_FIELD.match(s)
        if not m:
            continue

        # 字段归属最近一层 message，oneof 内的归属它外层的 message
        owner = -1
        for k in range(len(stack) - 1, -1, -1):
            if stack[k][0] == "m":
                owner = k
                break
            if stack[k][0] == "o":
                continue
        if owner < 0:
            continue

        rep, typ, name, num = m.group(1), m.group(2), m.group(3), int(m.group(4))
        short = typ.split(".")[-1]
        if typ in SCALAR:
            code = SCALAR[typ]
        elif short == "Any":
            code = ">Any"
        elif typ in enums or short in enums:
            code = "u"
        else:
            code = ">" + short
        if rep == "repeated":
            code = "r" + code

        fields[stack[owner][1]].append((num, name, code))
    return fields, order


def spec_of(items):
    # 把一条 message 的字段拼成一行
    if not items:
        return None
    return ",".join("%d:%s:%s" % (n, nm, c) for n, nm, c in sorted(items, key=lambda x: x[0]))


def build_lines(fields, order):
    # 短名索引，同名消息取字段最多的一条
    best = {}
    for full in order:
        spec = spec_of(fields.get(full))
        if not spec:
            continue
        short = full.split(".")[-1]
        if short not in best or len(spec) > len(best[short]):
            best[short] = spec
    return ["%s|%s" % (k, best[k]) for k in best]


def write_cs(path, lines):
    # 按固定长度切段，段间用 + 连接
    body = "\n".join(lines)
    chunks = [body[p:p + CHUNK] for p in range(0, len(body), CHUNK)]
    lit = []
    for i, c in enumerate(chunks):
        esc = c.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        lit.append('    "%s"%s' % (esc, "" if i == len(chunks) - 1 else " +"))
    block = "static string SS_SCHEMA_STR =\n" + "\n".join(lit) + ";\n"

    # 只替换 SS_SCHEMA_STR 与 SS_NAMES 之间的部分
    cs = open(path, encoding="utf-8").read()
    start = cs.find("static string SS_SCHEMA_STR =")
    end = cs.find("static System.Collections.Generic.Dictionary<int, string> SS_NAMES")
    if start < 0 or end < 0 or end < start:
        raise SystemExit("SS_SCHEMA_STR block not found in " + path)
    cs = cs[:start] + block + "\n" + cs[end:]
    open(path, "w", encoding="utf-8", newline="\n").write(cs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proto", default=os.path.join(HERE, "proto.proto"))
    ap.add_argument("--cs", default=os.path.join(HERE, "msg_decoder.cs"))
    ap.add_argument("--write", action="store_true")
    a = ap.parse_args()

    lines = open(a.proto, encoding="utf-8").read().split("\n")
    enums = scan_enums(lines)
    fields, order = parse(lines, enums)
    out = build_lines(fields, order)
    print("messages:", len(out))

    if a.write:
        write_cs(a.cs, out)
        print("written:", a.cs)


if __name__ == "__main__":
    main()
