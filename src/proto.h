/* Forwarding protocol: control message formats, the 48-bit ipv4+port header,
 * and the psk -> hmac key KDF. */
#ifndef UFW_PROTO_H
#define UFW_PROTO_H

#include <sodium.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

/* Data header: 32-bit IPv4 address + 16-bit port, 48 bits total, network order. */
#define FWD_HDR_LEN 6

/* Message types on the control port (first byte). */
#define FWD_TYPE_HELLO 0x00 /* client -> server: 0x00 | ts(8) | hmac(32) */
#define FWD_TYPE_DATA 0x01  /* both directions: 0x01 | hdr(6) | payload */
#define FWD_TYPE_ACK 0x02   /* server -> client: 0x02 | cts(8) | sts(8) | hmac(32) */

#define FWD_TS_LEN 8
#define FWD_KEY_LEN 32
#define FWD_MAC_LEN crypto_auth_hmacsha256_BYTES
#define FWD_HELLO_LEN (1 + FWD_TS_LEN + FWD_MAC_LEN)
#define FWD_ACK_LEN (1 + 2 * FWD_TS_LEN + FWD_MAC_LEN)

/* Max allowed skew of handshake timestamps, in seconds. */
#define FWD_TS_MAX_SKEW 60

struct fwd_addr {
    uint32_t ip;   /* host byte order */
    uint16_t port; /* host byte order */
};

void fwd_hdr_pack(uint8_t out[FWD_HDR_LEN], const struct fwd_addr *a);
void fwd_hdr_unpack(const uint8_t in[FWD_HDR_LEN], struct fwd_addr *a);

int fwd_addr_eq(const struct fwd_addr *a, const struct fwd_addr *b);
/* Formats the address as "a.b.c.d:port"; buf must hold at least 24 bytes. */
const char *fwd_addr_str(const struct fwd_addr *a, char *buf, size_t buflen);

void fwd_addr_from_sockaddr(struct fwd_addr *a, const struct sockaddr_in *sin);

/* Derives the hmac key from the pre-shared key. A psk of 64 hex characters is
 * treated as 32 raw bytes; anything else is treated as a passphrase and stretched
 * to 32 bytes with blake2b. Returns 0 on success. */
int fwd_key_from_psk(const char *psk, unsigned char key[FWD_KEY_LEN], char *err,
                     size_t errlen);

/* Builds a handshake message and returns its length (FWD_HELLO_LEN). */
size_t fwd_hello_build(const unsigned char key[FWD_KEY_LEN], uint64_t ts,
                       uint8_t out[FWD_HELLO_LEN]);

/* Verifies a handshake message. Returns 0 on success, -1 on malformed/MAC error,
 * -2 if the timestamp is outside the allowed window. */
int fwd_hello_verify(const unsigned char key[FWD_KEY_LEN], const uint8_t *pkt, size_t len,
                     uint64_t now, uint64_t *ts_out);

/* Builds the handshake reply: client_ts is echoed back, server_ts is the current
 * server time. */
size_t fwd_ack_build(const unsigned char key[FWD_KEY_LEN], uint64_t client_ts,
                     uint64_t server_ts, uint8_t out[FWD_ACK_LEN]);

/* Verifies the handshake reply. Returns 0 on success, -1 on malformed/MAC error,
 * -2 if the server timestamp is outside the window. client_ts_out lets the client
 * confirm this is a reply to its own latest handshake. */
int fwd_ack_verify(const unsigned char key[FWD_KEY_LEN], const uint8_t *pkt, size_t len,
                   uint64_t now, uint64_t *client_ts_out, uint64_t *server_ts_out);

#endif /* UFW_PROTO_H */
