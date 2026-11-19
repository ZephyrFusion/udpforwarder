/* 转发协议：控制报文格式、48bit ipv4+port 头、psk -> hmac key 的 kdf */
#ifndef UFW_PROTO_H
#define UFW_PROTO_H

#include <sodium.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

/* 数据头：32bit ipv4 地址 + 16bit 端口，共 48bit，网络字节序 */
#define FWD_HDR_LEN 6

/* 控制端口上的报文类型（第一个字节） */
#define FWD_TYPE_HELLO 0x00 /* client -> server: 0x00 | ts(8) | hmac(32) */
#define FWD_TYPE_DATA 0x01  /* 双向: 0x01 | hdr(6) | payload */
#define FWD_TYPE_ACK 0x02   /* server -> client: 0x02 | cts(8) | sts(8) | hmac(32) */

#define FWD_TS_LEN 8
#define FWD_KEY_LEN 32
#define FWD_MAC_LEN crypto_auth_hmacsha256_BYTES
#define FWD_HELLO_LEN (1 + FWD_TS_LEN + FWD_MAC_LEN)
#define FWD_ACK_LEN (1 + 2 * FWD_TS_LEN + FWD_MAC_LEN)

/* 握手时间戳允许的最大偏差（秒） */
#define FWD_TS_MAX_SKEW 60

struct fwd_addr {
    uint32_t ip; /* 主机字节序 */
    uint16_t port; /* 主机字节序 */
};

void fwd_hdr_pack(uint8_t out[FWD_HDR_LEN], const struct fwd_addr *a);
void fwd_hdr_unpack(const uint8_t in[FWD_HDR_LEN], struct fwd_addr *a);

int fwd_addr_eq(const struct fwd_addr *a, const struct fwd_addr *b);
/* 把地址转成 "a.b.c.d:port" 形式，buf 至少 24 字节 */
const char *fwd_addr_str(const struct fwd_addr *a, char *buf, size_t buflen);

void fwd_addr_from_sockaddr(struct fwd_addr *a, const struct sockaddr_in *sin);

/* 由 pre shared key 推导 hmac key。psk 为 64 个 hex 字符时按 32 字节二进制处理，
 * 否则按口令处理（blake2b 拉长到 32 字节）。成功返回 0。 */
int fwd_key_from_psk(const char *psk, unsigned char key[FWD_KEY_LEN], char *err,
                     size_t errlen);

/* 组一个握手报文，返回报文长度（FWD_HELLO_LEN） */
size_t fwd_hello_build(const unsigned char key[FWD_KEY_LEN], uint64_t ts,
                       uint8_t out[FWD_HELLO_LEN]);

/* 校验握手报文。返回 0 表示通过；-1 格式/MAC 错误；-2 时间戳超出窗口 */
int fwd_hello_verify(const unsigned char key[FWD_KEY_LEN], const uint8_t *pkt, size_t len,
                     uint64_t now, uint64_t *ts_out);

/* 组握手应答：client_ts 原样回显，server_ts 为 server 当前时间 */
size_t fwd_ack_build(const unsigned char key[FWD_KEY_LEN], uint64_t client_ts,
                     uint64_t server_ts, uint8_t out[FWD_ACK_LEN]);

/* 校验握手应答。返回 0 表示通过；-1 格式/MAC 错误；-2 server 时间戳超出窗口。
 * client_ts_out 用于 client 确认这是对自己最近一次握手的应答。 */
int fwd_ack_verify(const unsigned char key[FWD_KEY_LEN], const uint8_t *pkt, size_t len,
                   uint64_t now, uint64_t *client_ts_out, uint64_t *server_ts_out);

#endif /* UFW_PROTO_H */
