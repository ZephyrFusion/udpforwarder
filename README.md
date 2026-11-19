# !! AI SLOP - DO NOT TRUST THIS CODE !!

```
    ###  #####     #### #      ###  ####
   #   #   #      #     #     #   # #   #
   #####   #       ###  #     #   # ####
   #   #   #          # #     #   # #
   #   # #####    ####  #####  ###  #
```

**WARNING: this repository is AI-generated slop.**

Code, tests, comments and docs were all written by an AI and have not been reviewed
by a human. It may contain bugs, security holes and plain bad design. Do not run it in
production, and do not put real traffic or sensitive data through it.

Passing `make test` does not mean the code is correct. Read every line with suspicion.

---

# udp forwarder

Maps one UDP port behind a NATed client onto a server that has a public address.

```
internet client --udp--> server:data_port --(authenticated control channel)--> client --udp--> 127.0.0.1:local_service_port
```

- Plain C + epoll; libsodium provides HMAC-SHA256 and the KDF; statically linked
  (musl + static libsodium).
- IPv4 only, single client only.
- Configuration files are ini.

## Build

```sh
make                    # downloads and builds the static libsodium on first run
                        # (needs musl-tools and network access)
make test               # end-to-end tests, all on 127.0.0.1, no root needed
```

The result is a single static binary `udpforwarder`; just scp it to the target machine.

## Run

```sh
# server (the machine with the public address)
./udpforwarder server -c examples/server.ini

# client (the machine behind NAT)
./udpforwarder client -c examples/client.ini
```

The default config paths are `/etc/udpforwarder/server.ini` and
`/etc/udpforwarder/client.ini`.

### server config

| Key | Meaning | Default |
| --- | --- | --- |
| `server.bind` | listen address, `0.0.0.0` means all interfaces | `0.0.0.0` |
| `server.control_port` | control port (handshake/heartbeat/return traffic) | required |
| `server.data_port` | data port (internet traffic) | required |
| `server.client_idle_timeout` | forget the client control address after this many seconds without a handshake | 180 |
| `key.psk` | pre-shared key, see below | required |

### client config

| Key | Meaning | Default |
| --- | --- | --- |
| `client.server_host` | IPv4 address of the server | required |
| `client.server_control_port` | server control port | required |
| `client.local_service_host` | local service address | `127.0.0.1` |
| `client.local_service_port` | local service port | required |
| `client.heartbeat_interval` | heartbeat (handshake) interval in seconds | 30 |
| `client.mapping_idle_timeout` | drop a mapping after this many idle seconds | 120 |
| `client.max_mappings` | upper bound of the mapping table | 1024 |

`key.psk` accepts two forms: 64 hex characters (recommended, `openssl rand -hex 32`) are
used as a 32-byte raw key; anything else is treated as a passphrase (at least 16
characters) and stretched to 32 bytes with blake2b. Both ends must match.

### Key derivation

```
master = hex_decode(psk)            or  blake2b(psk)            # passphrase case
key    = crypto_kdf_derive_from_key(32, id=1, context="udpfwd01", master)
```

`key` is the HMAC-SHA256 key used for handshakes and ACKs.

## Protocol

The first byte of every message on the control port is a type. Timestamps are 8-byte
big-endian Unix seconds, MACs are the raw 32 bytes of HMAC-SHA256.

| Message | Direction | Format |
| --- | --- | --- |
| handshake | client -> server | `0x00 \| ts(8) \| hmac(ts)(32)`, 41 bytes |
| handshake reply | server -> client | `0x02 \| our ts(8) \| server ts(8) \| hmac(both ts)(32)`, 49 bytes |
| data | both ways | `0x01 \| ipv4(4) \| port(2) \| payload` |

Flow:

1. The client handshakes right after start-up, then once every `heartbeat_interval`
   (30 seconds by default) as a heartbeat.
2. The server checks the MAC and the timestamp (at most 60 seconds away from its own
   clock), records that UDP source address as the client control address and replies
   with a `0x02` ACK (echoing the client ts, carrying its own ts).
3. The client checks the ACK's MAC, the server timestamp window, and that the echoed ts
   is one it recently sent; only then is the link considered up. Three heartbeat periods
   without an ACK are treated as a broken link and trigger a reconnecting handshake.
4. An internet client sends a datagram to `data_port`; the server prefixes it with the
   source `ipv4+port` header and sends it to the client control address.
5. The client allocates an ephemeral port on `127.0.0.1` for every source `ipv4+port`
   and talks to that source one-to-one; replies from the local service get the same
   header and go back to the server control port as `0x01`.
6. The server strips the header and sends the payload from `data_port` to the matching
   internet client.
7. Mappings without traffic for `mapping_idle_timeout` (120 seconds by default) are
   closed and cleaned up.

Downstream data messages carry the `0x01` type byte so they can be told apart from ACKs
(`0x02`) without ambiguity on the same control port.

### Replay protection

The server only accepts a handshake whose timestamp is greater than the timestamp of the
last accepted handshake; replaying a captured handshake verbatim (including from a
different source address) therefore never yields an ACK. Side effect: if an attacker
sends a valid handshake with a far-future timestamp, the real client's heartbeats are
rejected (for at most 60 seconds) until they catch up, after which it heals itself.

### Security boundaries

- The control channel's integrity and the handshake authentication rely on HMAC, but the
  data payload itself is not encrypted (the design goal is port forwarding, not a VPN).
  If you need encryption, layer it on top or change the protocol.
- The data port is open to the internet, so anyone who can send packets to `data_port`
  can reach the local service behind the client. Use it together with a firewall and the
  local service's own access control.

## Known limitations

- Only a single client; the server and client configs are a matched pair.
- When the client's NAT port changes, the server only learns the new target address on
  the next heartbeat (at most 30 seconds by default); downstream datagrams sent in the
  meantime hit the old port and are lost.
- IPv4 only.

## Layout

```
src/main.c     command line entry point
src/common.*   clocks, logging, rate-limited logging
src/ini.*      ini parser
src/proto.*    message formats, KDF, HMAC
src/server.c   server: control port + data port
src/client.c   client: mapping table + local service I/O
tests/test_forward.py  end-to-end tests
examples/*.ini example configs
```
