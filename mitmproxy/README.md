# mitmproxy

ss 的 mitmweb 解码脚本：自动解密游戏报文，Body 面板直接显示明文 JSON，Comment 显示 msgId nonce key3。

## 启动

```bash
uv sync
uv run mitmweb --scripts addon.py -p 8888
```

浏览器打开 http://127.0.0.1:8099，证书与 Windows 系统代理在启动时自动配置，退出时自动还原。

## 使用

1. 关闭游戏加速器
2. 启动 mitmweb 后再启动游戏（握手必须被接管）
3. 事件日志出现 `relay ready` 后，Body 面板自动显示解密明文（视图 SS JSON），Comment 是 `REQ/RESP msgId=... nonce=... key3=... [k3C/k3S]`

手机或模拟器抓包加 `--listen-host 0.0.0.0`，代理指向本机 IP 和 8888 端口。

## 配置

`decoder/wire.py` 顶部：

- `REGION` 区服 CN JP KR EN TW
- `MITM` 中转开关，关闭后需手填 `KEY3_HEX`
- `CAPTURE_DOMAINS` 抓包域名列表，流列表只显示这些域名
- `F1_PRIV_HEX` / `F2_PRIV_HEX` 中转私钥，一次性值可自行替换

## 更新 pb 表

GitHub Action（mitmproxy.yml）手动触发，自动拉取上游 proto 和 msgId 表生成 `decoder/proto_pb2.py`、`decoder/PB_pb2.py`、`decoder/msgid.py` 并提交。

本地手动生成：

```bash
pb2proto -i proto.pb -o proto.proto
uv run python -m grpc_tools.protoc -I . --python_out=decoder proto.proto
uv run python gen_msgid.py --lua NetMsgId.lua
```
