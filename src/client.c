/* Client side: sends payloads forwarded by the server to the local UDP service
 * through an ephemeral port on 127.0.0.1. */
#include "client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"
#include "ini.h"
#include "proto.h"

#define EP_NAME "client"
#define MAX_MAPPINGS 4096

/* One mapping: an ephemeral 127.0.0.1 port <-> an internet-side ipv4+port. */
struct mapping {
    int fd;
    uint16_t lport;
    struct fwd_addr remote;
    uint64_t last_ms;
};

struct client {
    int epfd;
    int ctl_fd; /* socket used to talk to the server control port */
    unsigned char key[FWD_KEY_LEN];

    struct sockaddr_in server_addr;
    struct sockaddr_in svc_addr;

    uint64_t hello_interval_ms;
    uint64_t next_hello_ms;
    uint64_t idle_ms;

    /* Timestamps of the latest handshakes, used to match ACKs from the server. */
    uint64_t recent_ts[8];
    int recent_pos;
    int recent_cnt;

    int connected; /* a valid ACK has been received */
    uint64_t last_ack_ms;

    struct mapping *maps;
    int ncap;
    int nmaps;

    struct ufw_ratelog rl_ctl;
    struct ufw_ratelog rl_local;
    struct ufw_ratelog rl_unacked;

    uint8_t *rx;
    uint8_t *tx;
};

static int parse_ipport_pair(const char *host_str, const char *port_str, struct sockaddr_in *out,
                             const char *what)
{
    unsigned long port;

    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    if (!host_str || inet_pton(AF_INET, host_str, &out->sin_addr) != 1) {
        log_error("[" EP_NAME "] %s address is invalid: %s (only ipv4 dotted decimal is "
                  "supported)", what, host_str ? host_str : "(empty)");
        return -1;
    }
    if (!port_str) {
        log_error("[" EP_NAME "] missing port for %s", what);
        return -1;
    }
    errno = 0;
    {
        char *end = NULL;
        port = strtoul(port_str, &end, 10);
        if (errno != 0 || end == port_str || *end != '\0' || port < 1 || port > 65535) {
            log_error("[" EP_NAME "] %s port is invalid: %s", what, port_str);
            return -1;
        }
    }
    out->sin_port = htons((uint16_t)port);
    return 0;
}

/* ---------- mapping table ---------- */

static struct mapping *map_by_remote(struct client *c, const struct fwd_addr *remote)
{
    for (int i = 0; i < c->nmaps; i++)
        if (fwd_addr_eq(&c->maps[i].remote, remote))
            return &c->maps[i];
    return NULL;
}

static struct mapping *map_by_fd(struct client *c, int fd)
{
    for (int i = 0; i < c->nmaps; i++)
        if (c->maps[i].fd == fd)
            return &c->maps[i];
    return NULL;
}

static void map_destroy(struct client *c, struct mapping *m)
{
    char buf[24];
    int idx = (int)(m - c->maps);

    epoll_ctl(c->epfd, EPOLL_CTL_DEL, m->fd, NULL);
    close(m->fd);
    log_info("[" EP_NAME "] released mapping 127.0.0.1:%u <-> %s", (unsigned)m->lport,
             fwd_addr_str(&m->remote, buf, sizeof(buf)));
    c->maps[idx] = c->maps[c->nmaps - 1];
    c->nmaps--;
}

/* When full, evict the least recently active mapping. */
static int map_make_room(struct client *c)
{
    struct mapping *oldest = NULL;

    if (c->nmaps < c->ncap)
        return 0;
    for (int i = 0; i < c->nmaps; i++)
        if (!oldest || c->maps[i].last_ms < oldest->last_ms)
            oldest = &c->maps[i];
    if (!oldest) {
        ufw_ratelog_emit(&c->rl_local, "WARN",
                         "[" EP_NAME "] mapping table is full, dropping the new client");
        return -1;
    }
    log_warn("[" EP_NAME "] mapping table is full (%d entries), evicting the least recently "
             "active mapping", c->ncap);
    map_destroy(c, oldest);
    return 0;
}

static struct mapping *map_create(struct client *c, const struct fwd_addr *remote)
{
    struct sockaddr_in local;
    struct epoll_event ev;
    struct mapping *m;
    int fd;

    if (map_make_room(c) != 0)
        return NULL;

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        ufw_ratelog_emit(&c->rl_local, "ERROR", "[" EP_NAME "] socket: %s", strerror(errno));
        return NULL;
    }

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    local.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        ufw_ratelog_emit(&c->rl_local, "ERROR", "[" EP_NAME "] bind 127.0.0.1:0 failed: %s",
                         strerror(errno));
        close(fd);
        return NULL;
    }
    /* talk to the configured local service only; this also filters stray packets */
    if (connect(fd, (struct sockaddr *)&c->svc_addr, sizeof(c->svc_addr)) < 0) {
        ufw_ratelog_emit(&c->rl_local, "ERROR",
                         "[" EP_NAME "] connect to the local service failed: %s", strerror(errno));
        close(fd);
        return NULL;
    }

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    if (epoll_ctl(c->epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        ufw_ratelog_emit(&c->rl_local, "ERROR", "[" EP_NAME "] epoll_ctl: %s", strerror(errno));
        close(fd);
        return NULL;
    }

    {
        socklen_t slen = sizeof(local);
        if (getsockname(fd, (struct sockaddr *)&local, &slen) < 0)
            local.sin_port = 0;
    }

    m = &c->maps[c->nmaps++];
    m->fd = fd;
    m->lport = ntohs(local.sin_port);
    m->remote = *remote;
    m->last_ms = ufw_mono_ms();

    {
        char buf[24];
        log_info("[" EP_NAME "] new mapping 127.0.0.1:%u <-> %s", (unsigned)m->lport,
                 fwd_addr_str(&m->remote, buf, sizeof(buf)));
    }
    return m;
}

static void sweep_mappings(struct client *c)
{
    uint64_t now = ufw_mono_ms();

    for (int i = c->nmaps - 1; i >= 0; i--) {
        struct mapping *m = &c->maps[i];
        if (now - m->last_ms > c->idle_ms)
            map_destroy(c, m);
    }
}

/* ---------- handshake ---------- */

static void send_hello(struct client *c)
{
    uint8_t pkt[FWD_HELLO_LEN];
    uint64_t ts = ufw_realtime_s();

    fwd_hello_build(c->key, ts, pkt);
    c->recent_ts[c->recent_pos] = ts;
    c->recent_pos = (c->recent_pos + 1) % (int)(sizeof(c->recent_ts) / sizeof(c->recent_ts[0]));
    if (c->recent_cnt < (int)(sizeof(c->recent_ts) / sizeof(c->recent_ts[0])))
        c->recent_cnt++;

    if (send(c->ctl_fd, pkt, sizeof(pkt), 0) < 0)
        ufw_ratelog_emit(&c->rl_ctl, "WARN", "[" EP_NAME "] failed to send handshake: %s",
                         strerror(errno));
}

static int ts_recently_sent(const struct client *c, uint64_t ts)
{
    for (int i = 0; i < c->recent_cnt; i++)
        if (c->recent_ts[i] == ts)
            return 1;
    return 0;
}

/* Server reply to a handshake. */
static void handle_ack(struct client *c, const uint8_t *pkt, size_t len)
{
    uint64_t cts = 0;
    uint64_t sts = 0;
    int rc = fwd_ack_verify(c->key, pkt, len, ufw_realtime_s(), &cts, &sts);

    if (rc == -2) {
        ufw_ratelog_emit(&c->rl_ctl, "WARN",
                         "[" EP_NAME "] handshake ACK server timestamp is off by more than "
                         "±%d seconds (clock skew between the two ends?)",
                         FWD_TS_MAX_SKEW);
        return;
    }
    if (rc != 0) {
        ufw_ratelog_emit(&c->rl_ctl, "WARN",
                         "[" EP_NAME "] handshake ACK verification failed, ignoring "
                         "(psk mismatch or forged packet)");
        return;
    }
    if (!ts_recently_sent(c, cts)) {
        ufw_ratelog_emit(&c->rl_ctl, "WARN",
                         "[" EP_NAME "] handshake ACK echoed timestamp does not match our "
                         "handshake, ignoring");
        return;
    }

    c->last_ack_ms = ufw_mono_ms();
    if (!c->connected) {
        c->connected = 1;
        log_info("[" EP_NAME "] handshake with server succeeded (ACK received), link is up");
    }
}

/* ---------- control socket: data forwarded by the server ---------- */

static void on_ctl_readable(struct client *c)
{
    for (;;) {
        ssize_t n = recv(c->ctl_fd, c->rx, UFW_MAX_PKT, 0);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            if (errno == EINTR)
                continue;
            /* Usually the server is not up yet or the port is unreachable; ICMP
             * errors surface on a connected socket. */
            ufw_ratelog_emit(&c->rl_ctl, "WARN", "[" EP_NAME "] control socket receive failed: %s",
                             strerror(errno));
            return;
        }
        if (n < 1)
            continue;

        if (c->rx[0] == FWD_TYPE_ACK) {
            handle_ack(c, c->rx, (size_t)n);
            continue;
        }
        if (c->rx[0] != FWD_TYPE_DATA) {
            ufw_ratelog_emit(&c->rl_ctl, "WARN",
                             "[" EP_NAME "] unknown message type %u on control port", c->rx[0]);
            continue;
        }
        if ((size_t)n < 1 + FWD_HDR_LEN) {
            ufw_ratelog_emit(&c->rl_ctl, "WARN",
                             "[" EP_NAME "] dropping short downstream packet (%zd bytes)", n);
            continue;
        }

        {
            struct fwd_addr remote;
            struct mapping *m;
            size_t payload_len = (size_t)n - 1 - FWD_HDR_LEN;

            fwd_hdr_unpack(c->rx + 1, &remote);
            m = map_by_remote(c, &remote);
            if (!m) {
                m = map_create(c, &remote);
                if (!m)
                    continue;
            }
            m->last_ms = ufw_mono_ms();
            if (send(m->fd, c->rx + 1 + FWD_HDR_LEN, payload_len, 0) < 0)
                ufw_ratelog_emit(&c->rl_local, "WARN",
                                 "[" EP_NAME "] failed to send to the local service: %s",
                                 strerror(errno));
        }
    }
}

/* ---------- local service socket: return traffic ---------- */

static void on_local_readable(struct client *c, int fd)
{
    for (;;) {
        struct mapping *m = map_by_fd(c, fd);
        ssize_t n;

        if (!m)
            return;
        n = recv(fd, c->rx, UFW_MAX_PKT, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            if (errno == EINTR)
                continue;
            /* With nobody listening on the local service, a connected socket gets
             * ECONNREFUSED; just drop the mapping. */
            if (errno == ECONNREFUSED) {
                ufw_ratelog_emit(&c->rl_local, "WARN",
                                 "[" EP_NAME "] the local service refused the connection, "
                                 "releasing mapping");
                map_destroy(c, m);
                return;
            }
            ufw_ratelog_emit(&c->rl_local, "WARN", "[" EP_NAME "] local socket receive failed: %s",
                             strerror(errno));
            return;
        }

        c->tx[0] = FWD_TYPE_DATA;
        fwd_hdr_pack(c->tx + 1, &m->remote);
        if (n > 0)
            memcpy(c->tx + 1 + FWD_HDR_LEN, c->rx, (size_t)n);
        if (send(c->ctl_fd, c->tx, 1 + FWD_HDR_LEN + (size_t)n, 0) < 0)
            ufw_ratelog_emit(&c->rl_ctl, "WARN", "[" EP_NAME "] failed to send to server: %s",
                             strerror(errno));
        m->last_ms = ufw_mono_ms();
    }
}

int client_main(const char *cfg_path)
{
    struct client c;
    struct epoll_event ev;
    struct epoll_event *evs = NULL;
    char err[512];
    ini_t *ini;
    unsigned long ctl_port, hello_sec, idle_sec, max_maps;
    const char *server_host, *svc_host;
    const char *psk;
    int rc = 1;

    memset(&c, 0, sizeof(c));
    c.ctl_fd = -1;
    c.epfd = -1;

    ini = ini_load(cfg_path, err, sizeof(err));
    if (!ini) {
        log_error("[" EP_NAME "] %s", err);
        return 1;
    }

    server_host = ini_get(ini, "client", "server_host");
    if (ini_get_uint(ini, "client", "server_control_port", 0, 1, 65535, &ctl_port) != 0 ||
        ctl_port == 0) {
        log_error("[" EP_NAME "] client.server_control_port is missing or not within 1-65535");
        goto out;
    }
    if (!server_host) {
        log_error("[" EP_NAME "] client.server_host is missing");
        goto out;
    }
    if (parse_ipport_pair(server_host, ini_get(ini, "client", "server_control_port"),
                          &c.server_addr, "server_host") != 0)
        goto out;

    svc_host = ini_get(ini, "client", "local_service_host");
    if (!svc_host)
        svc_host = "127.0.0.1";
    {
        const char *svc_port_str = ini_get(ini, "client", "local_service_port");
        if (!svc_port_str) {
            log_error("[" EP_NAME "] client.local_service_port is missing");
            goto out;
        }
        if (parse_ipport_pair(svc_host, svc_port_str, &c.svc_addr, "local_service") != 0)
            goto out;
    }

    if (ini_get_uint(ini, "client", "heartbeat_interval", 30, 1, 3600, &hello_sec) != 0) {
        log_error("[" EP_NAME "] heartbeat_interval is invalid (1-3600 seconds)");
        goto out;
    }
    if (ini_get_uint(ini, "client", "mapping_idle_timeout", 120, 1, 86400, &idle_sec) != 0) {
        log_error("[" EP_NAME "] mapping_idle_timeout is invalid");
        goto out;
    }
    if (ini_get_uint(ini, "client", "max_mappings", 1024, 1, MAX_MAPPINGS, &max_maps) != 0) {
        log_error("[" EP_NAME "] max_mappings is invalid (1-%d)", MAX_MAPPINGS);
        goto out;
    }
    psk = ini_get(ini, "key", "psk");
    if (!psk)
        psk = ini_get(ini, "client", "psk");
    if (fwd_key_from_psk(psk, c.key, err, sizeof(err)) != 0) {
        log_error("[" EP_NAME "] %s", err);
        goto out;
    }

    c.hello_interval_ms = (uint64_t)hello_sec * 1000;
    c.idle_ms = (uint64_t)idle_sec * 1000;
    c.ncap = (int)max_maps;
    c.maps = calloc((size_t)c.ncap, sizeof(*c.maps));
    evs = calloc((size_t)c.ncap + 2, sizeof(*evs));
    c.rx = malloc(UFW_MAX_PKT);
    c.tx = malloc(UFW_MAX_PKT + 1 + FWD_HDR_LEN);
    if (!c.maps || !evs || !c.rx || !c.tx) {
        log_error("[" EP_NAME "] out of memory");
        goto out;
    }
    ufw_ratelog_reset(&c.rl_ctl);
    ufw_ratelog_reset(&c.rl_local);
    ufw_ratelog_reset(&c.rl_unacked);
    c.last_ack_ms = ufw_mono_ms();

    c.epfd = epoll_create1(EPOLL_CLOEXEC);
    if (c.epfd < 0) {
        log_error("[" EP_NAME "] epoll_create1: %s", strerror(errno));
        goto out;
    }

    c.ctl_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (c.ctl_fd < 0) {
        log_error("[" EP_NAME "] socket: %s", strerror(errno));
        goto out;
    }
    /* let the kernel pick the source port; after connect only packets from the
     * server control port are accepted */
    if (connect(c.ctl_fd, (struct sockaddr *)&c.server_addr, sizeof(c.server_addr)) < 0) {
        log_error("[" EP_NAME "] connect to server failed: %s", strerror(errno));
        goto out;
    }

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = c.ctl_fd;
    if (epoll_ctl(c.epfd, EPOLL_CTL_ADD, c.ctl_fd, &ev) < 0) {
        log_error("[" EP_NAME "] epoll_ctl: %s", strerror(errno));
        goto out;
    }

    {
        char sbuf[INET_ADDRSTRLEN] = {0};
        char vbuf[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &c.server_addr.sin_addr, sbuf, sizeof(sbuf));
        inet_ntop(AF_INET, &c.svc_addr.sin_addr, vbuf, sizeof(vbuf));
        log_info("[" EP_NAME "] server control port %s:%u, local service %s:%u, "
                 "heartbeat interval %lu seconds, mapping idle timeout %lu seconds",
                 sbuf, ntohs(c.server_addr.sin_port), vbuf, ntohs(c.svc_addr.sin_port), hello_sec,
                 idle_sec);
    }

    c.next_hello_ms = 0;
    for (;;) {
        uint64_t now = ufw_mono_ms();
        int64_t wait_ms = 1000;
        int n;

        if (now >= c.next_hello_ms) {
            send_hello(&c);
            c.next_hello_ms = now + c.hello_interval_ms;
        }
        /* No ACK for two heartbeat periods: warn that the link looks down. */
        if (now - c.last_ack_ms > 2 * c.hello_interval_ms)
            ufw_ratelog_emit(&c.rl_unacked, "WARN",
                             "[" EP_NAME "] heartbeat sent but no ACK received from the server"
                             "(server not running, port unreachable or psk mismatch?)");
        if (c.connected && now - c.last_ack_ms > 3 * c.hello_interval_ms) {
            c.connected = 0;
            log_warn("[" EP_NAME "] heartbeat timed out, the link to the server is down");
        }
        {
            int64_t until_hello = (int64_t)(c.next_hello_ms - ufw_mono_ms());
            if (until_hello < wait_ms)
                wait_ms = until_hello;
        }
        if (wait_ms < 1)
            wait_ms = 1;

        n = epoll_wait(c.epfd, evs, c.ncap + 2, (int)wait_ms);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            log_error("[" EP_NAME "] epoll_wait: %s", strerror(errno));
            break;
        }
        for (int i = 0; i < n; i++) {
            if (evs[i].data.fd == c.ctl_fd)
                on_ctl_readable(&c);
            else
                on_local_readable(&c, evs[i].data.fd);
        }
        sweep_mappings(&c);
    }
    rc = 0;

out:
    for (int i = 0; i < c.nmaps; i++)
        if (c.maps[i].fd >= 0)
            close(c.maps[i].fd);
    free(c.maps);
    free(evs);
    free(c.rx);
    free(c.tx);
    if (c.epfd >= 0)
        close(c.epfd);
    if (c.ctl_fd >= 0)
        close(c.ctl_fd);
    ini_free(ini);
    return rc;
}
