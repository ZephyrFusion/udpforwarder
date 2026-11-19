#include "proto.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

/* kdf 的上下文串，长度必须是 crypto_kdf_CONTEXTBYTES(8) */
static const char KDF_CONTEXT[8] = {'u', 'd', 'p', 'f', 'w', 'd', '0', '1'};
#define KDF_SUBKEY_ID 1ULL

static int is_hex32(const char *s)
{
    if (strlen(s) != FWD_KEY_LEN * 2)
        return 0;
    for (const char *p = s; *p; p++)
        if (!isxdigit((unsigned char)*p))
            return 0;
    return 1;
}

static int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen)
{
    for (size_t i = 0; i < outlen; i++) {
        unsigned int v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1)
            return -1;
        out[i] = (unsigned char)v;
    }
    return 0;
}

int fwd_key_from_psk(const char *psk, unsigned char key[FWD_KEY_LEN], char *err,
                     size_t errlen)
{
    unsigned char master[FWD_KEY_LEN];

    if (!psk || *psk == '\0') {
        snprintf(err, errlen, "缺少 psk");
        return -1;
    }

    if (is_hex32(psk)) {
        if (hex_to_bytes(psk, master, sizeof(master)) != 0) {
            snprintf(err, errlen, "psk 的 hex 解码失败");
            return -1;
        }
    } else {
        if (strlen(psk) < 16) {
            snprintf(err, errlen, "psk 太短（口令至少 16 字符，或用 64 个 hex 字符）");
            return -1;
        }
        if (crypto_generichash(master, sizeof(master), (const unsigned char *)psk,
                               strlen(psk), NULL, 0) != 0) {
            snprintf(err, errlen, "psk 摘要失败");
            return -1;
        }
    }

    if (crypto_kdf_derive_from_key(key, FWD_KEY_LEN, KDF_SUBKEY_ID, KDF_CONTEXT, master) != 0) {
        snprintf(err, errlen, "kdf 派生失败");
        return -1;
    }
    sodium_memzero(master, sizeof(master));
    return 0;
}

void fwd_hdr_pack(uint8_t out[FWD_HDR_LEN], const struct fwd_addr *a)
{
    out[0] = (uint8_t)(a->ip >> 24);
    out[1] = (uint8_t)(a->ip >> 16);
    out[2] = (uint8_t)(a->ip >> 8);
    out[3] = (uint8_t)(a->ip);
    out[4] = (uint8_t)(a->port >> 8);
    out[5] = (uint8_t)(a->port);
}

void fwd_hdr_unpack(const uint8_t in[FWD_HDR_LEN], struct fwd_addr *a)
{
    a->ip = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) |
            (uint32_t)in[3];
    a->port = (uint16_t)(((uint16_t)in[4] << 8) | (uint16_t)in[5]);
}

int fwd_addr_eq(const struct fwd_addr *a, const struct fwd_addr *b)
{
    return a->ip == b->ip && a->port == b->port;
}

const char *fwd_addr_str(const struct fwd_addr *a, char *buf, size_t buflen)
{
    snprintf(buf, buflen, "%u.%u.%u.%u:%u", (a->ip >> 24) & 0xff, (a->ip >> 16) & 0xff,
             (a->ip >> 8) & 0xff, a->ip & 0xff, (unsigned)a->port);
    return buf;
}

void fwd_addr_from_sockaddr(struct fwd_addr *a, const struct sockaddr_in *sin)
{
    a->ip = ntohl(sin->sin_addr.s_addr);
    a->port = ntohs(sin->sin_port);
}

static void put_be64(uint8_t *out, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        out[i] = (uint8_t)(v >> (56 - 8 * i));
}

static uint64_t get_be64(const uint8_t *in)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | in[i];
    return v;
}

size_t fwd_hello_build(const unsigned char key[FWD_KEY_LEN], uint64_t ts,
                       uint8_t out[FWD_HELLO_LEN])
{
    out[0] = FWD_TYPE_HELLO;
    put_be64(out + 1, ts);
    crypto_auth_hmacsha256(out + 1 + FWD_TS_LEN, out + 1, FWD_TS_LEN, key);
    return FWD_HELLO_LEN;
}

int fwd_hello_verify(const unsigned char key[FWD_KEY_LEN], const uint8_t *pkt, size_t len,
                     uint64_t now, uint64_t *ts_out)
{
    uint8_t mac[FWD_MAC_LEN];
    uint64_t ts;
    uint64_t diff;

    if (len != FWD_HELLO_LEN || pkt[0] != FWD_TYPE_HELLO)
        return -1;

    crypto_auth_hmacsha256(mac, pkt + 1, FWD_TS_LEN, key);
    if (sodium_memcmp(mac, pkt + 1 + FWD_TS_LEN, FWD_MAC_LEN) != 0)
        return -1;

    ts = get_be64(pkt + 1);
    diff = ts > now ? ts - now : now - ts;
    if (diff > FWD_TS_MAX_SKEW)
        return -2;

    if (ts_out)
        *ts_out = ts;
    return 0;
}

size_t fwd_ack_build(const unsigned char key[FWD_KEY_LEN], uint64_t client_ts,
                     uint64_t server_ts, uint8_t out[FWD_ACK_LEN])
{
    uint8_t body[2 * FWD_TS_LEN];

    out[0] = FWD_TYPE_ACK;
    put_be64(body, client_ts);
    put_be64(body + FWD_TS_LEN, server_ts);
    memcpy(out + 1, body, sizeof(body));
    crypto_auth_hmacsha256(out + 1 + sizeof(body), body, sizeof(body), key);
    return FWD_ACK_LEN;
}

int fwd_ack_verify(const unsigned char key[FWD_KEY_LEN], const uint8_t *pkt, size_t len,
                   uint64_t now, uint64_t *client_ts_out, uint64_t *server_ts_out)
{
    uint8_t mac[FWD_MAC_LEN];
    uint64_t cts, sts, diff;
    size_t body_len = 2 * FWD_TS_LEN;

    if (len != FWD_ACK_LEN || pkt[0] != FWD_TYPE_ACK)
        return -1;

    crypto_auth_hmacsha256(mac, pkt + 1, body_len, key);
    if (sodium_memcmp(mac, pkt + 1 + body_len, FWD_MAC_LEN) != 0)
        return -1;

    cts = get_be64(pkt + 1);
    sts = get_be64(pkt + 1 + FWD_TS_LEN);
    diff = sts > now ? sts - now : now - sts;
    if (diff > FWD_TS_MAX_SKEW)
        return -2;

    if (client_ts_out)
        *client_ts_out = cts;
    if (server_ts_out)
        *server_ts_out = sts;
    return 0;
}
