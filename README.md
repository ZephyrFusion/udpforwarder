# udp forwarder

把位于 NAT 之后的 client 背后的一个 UDP 端口，映射到有公网地址的 server 上。

```
互联网客户端 --udp--> server:data_port --(加密控制通道)--> client --udp--> 127.0.0.1:local_service_port
```

- 纯 C + epoll，libsodium 提供 HMAC-SHA256 与 KDF，静态链接（musl + 静态 libsodium）。
- 只支持 IPv4，只支持单个 client。
- 配置文件为 ini。

## 编译

```sh
make                    # 首次会先下载并编译 libsodium 静态库（需 musl-tools 与网络）
make test               # 端到端测试（全部在 127.0.0.1 上跑，无需 root）
```

产物是单个静态二进制 `udpforwarder`，可直接 scp 到目标机器运行。

## 运行

```sh
# server（公网机器）
./udpforwarder server -c examples/server.ini

# client（NAT 之后的机器）
./udpforwarder client -c examples/client.ini
```

默认配置路径分别为 `/etc/udpforwarder/server.ini` 与 `/etc/udpforwarder/client.ini`。

### server 配置

| 键 | 说明 | 默认 |
| --- | --- | --- |
| `server.bind` | 监听地址，`0.0.0.0` 表示所有网卡 | `0.0.0.0` |
| `server.control_port` | 控制端口（握手/心跳/回程数据） | 必填 |
| `server.data_port` | 数据端口（互联网业务流量） | 必填 |
| `server.client_idle_timeout` | 多久（秒）没收到握手就清除 client 控制地址 | 180 |
| `key.psk` | 预共享密钥，见下 | 必填 |

### client 配置

| 键 | 说明 | 默认 |
| --- | --- | --- |
| `client.server_host` | server 的 IPv4 地址 | 必填 |
| `client.server_control_port` | server 控制端口 | 必填 |
| `client.local_service_host` | 本地服务地址 | `127.0.0.1` |
| `client.local_service_port` | 本地服务端口 | 必填 |
| `client.heartbeat_interval` | 心跳（握手）间隔，秒 | 30 |
| `client.mapping_idle_timeout` | 映射空闲多久后清除，秒 | 120 |
| `client.max_mappings` | 映射表上限 | 1024 |

`key.psk` 两种写法：64 个 hex 字符（推荐，`openssl rand -hex 32`）按 32 字节原始密钥处理；
否则按口令处理（至少 16 字符），经 blake2b 拉长成 32 字节。两端必须一致。

### 密钥派生

```
master = hex_decode(psk)            或  blake2b(psk)             # 口令时
key    = crypto_kdf_derive_from_key(32, id=1, context="udpfwd01", master)
```

`key` 就是握手与 ACK 的 HMAC-SHA256 key。

## 协议

控制端口上的每个报文第一个字节是类型。时间戳为 8 字节大端 Unix 秒，MAC 为
HMAC-SHA256 的 32 字节原文。

| 报文 | 方向 | 格式 |
| --- | --- | --- |
| 握手 | client → server | `0x00 \| ts(8) \| hmac(ts)(32)`，共 41 字节 |
| 握手应答 | server → client | `0x02 \| 我方ts(8) \| server ts(8) \| hmac(两ts)(32)`，共 49 字节 |
| 数据 | 双向 | `0x01 \| ipv4(4) \| port(2) \| payload` |

流程：

1. client 启动后立即握手，之后每 `heartbeat_interval`（默认 30 秒）握手一次作为心跳。
2. server 校验 MAC 与时间戳（与本机时间相差不超过 60 秒），通过后把该 UDP 来源地址记为
   client 的控制地址，并回复 `0x02` 的 ACK（回显 client 的 ts，带上自己的 ts）。
3. client 校验 ACK 的 MAC、server 时间戳窗口，以及回显的 ts 是否是自己最近发出的，
   通过后认为链路可用。连续 3 个心跳周期收不到 ACK 则判定链路中断，开始重连式握手。
4. 互联网客户端把报文发到 `data_port`，server 加上来源 `ipv4+port` 头后发给 client 控制地址。
5. client 为每个来源 `ipv4+port` 分配一个 `127.0.0.1` 上的临时端口，与该来源一对一通信，
   收到本地服务的回包后加上同样的头，用 `0x01` 发回 server 控制端口。
6. server 去掉头，把 payload 从 `data_port` 发给对应的互联网客户端。
7. `mapping_idle_timeout`（默认 120 秒）内没有流量的映射会被关闭清理。

下行数据报文带 `0x01` 类型字节是为了和 ACK（`0x02`）在同一个控制端口上无歧义地区分开。

### 重放保护

server 只接受时间戳比"上一次通过的握手时间戳"更大的握手；因此把抓到的握手报文原样重放
（包括换个源地址重放）不会拿到 ACK。副作用：如果攻击者发来一个时间戳很超前的合法握手，
真正的 client 在追上该时间戳之前的心跳会被拒绝（最长 60 秒），之后自愈。

### 安全边界

- 控制通道的完整性与握手认证靠 HMAC，但数据 payload 本身不加密（设计目标只是端口转发，
  不是 VPN）。需要加密请叠加在应用层或改协议。
- 数据端口对互联网开放，任何能发包到 `data_port` 的人都能借道访问 client 背后的本地服务，
  请配合防火墙/本地服务的访问控制使用。

## 已知限制

- 只有单个 client，两份配置（server 与 client）是配对的。
- client 的 NAT 出口端口变化后，要等下一次心跳（默认 ≤30 秒）server 才会更新目标地址，
  这段时间内下行报文会打到旧端口而丢失。
- 只有 IPv4。

## 目录结构

```
src/main.c     命令行入口
src/common.*   时间、日志、限速日志
src/ini.*      ini 解析
src/proto.*    报文格式、KDF、HMAC
src/server.c   server：控制端口 + 数据端口
src/client.c   client：映射表 + 本地服务收发
tests/test_forward.py  端到端测试
examples/*.ini 示例配置
```
