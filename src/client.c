/* client 端：把 server 转发过来的 payload 用 127.0.0.1 上的临时端口发给本地 UDP 服务 */
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

/* 一个映射：本地 127.0.0.1 的临时端口 <-> 互联网侧的 ipv4+port */
struct mapping {
    int fd;
    uint16_t lport;
    struct fwd_addr remote;
    uint64_t last_ms;
};

struct client {
    int epfd;
    int ctl_fd; /* 与 server 控制端口通信的 socket */
    unsigned char key[FWD_KEY_LEN];

    struct sockaddr_in server_addr;
    struct sockaddr_in svc_addr;

    uint64_t hello_interval_ms;
    uint64_t next_hello_ms;
    uint64_t idle_ms;

    /* 最近几次握手的上行时间戳，用来匹配 server 回的 ACK */
    uint64_t recent_ts[8];
    int recent_pos;
    int recent_cnt;

    int connected; /* 收到过有效 ACK */
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
        log_error("[" EP_NAME "] %s 的地址不合法: %s（只支持 ipv4 点分十进制）", what,
                  host_str ? host_str : "(空)");
        return -1;
    }
    if (!port_str) {
        log_error("[" EP_NAME "] 缺少 %s 的端口", what);
        return -1;
    }
    errno = 0;
    {
        char *end = NULL;
        port = strtoul(port_str, &end, 10);
        if (errno != 0 || end == port_str || *end != '\0' || port < 1 || port > 65535) {
            log_error("[" EP_NAME "] %s 的端口不合法: %s", what, port_str);
            return -1;
        }
    }
    out->sin_port = htons((uint16_t)port);
    return 0;
}

/* ---------- 映射表 ---------- */

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
    log_info("[" EP_NAME "] 释放映射 127.0.0.1:%u <-> %s", (unsigned)m->lport,
             fwd_addr_str(&m->remote, buf, sizeof(buf)));
    c->maps[idx] = c->maps[c->nmaps - 1];
    c->nmaps--;
}

/* 满了就淘汰最久不活跃的那个 */
static int map_make_room(struct client *c)
{
    struct mapping *oldest = NULL;

    if (c->nmaps < c->ncap)
        return 0;
    for (int i = 0; i < c->nmaps; i++)
        if (!oldest || c->maps[i].last_ms < oldest->last_ms)
            oldest = &c->maps[i];
    if (!oldest) {
        ufw_ratelog_emit(&c->rl_local, "WARN", "[" EP_NAME "] 映射表已满，丢弃新客户端");
        return -1;
    }
    log_warn("[" EP_NAME "] 映射表已满（%d 个），淘汰最久不活跃的映射", c->ncap);
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
        ufw_ratelog_emit(&c->rl_local, "ERROR", "[" EP_NAME "] bind 127.0.0.1:0 失败: %s",
                         strerror(errno));
        close(fd);
        return NULL;
    }
    /* 只跟配置的本地服务通信，顺带过滤掉杂包 */
    if (connect(fd, (struct sockaddr *)&c->svc_addr, sizeof(c->svc_addr)) < 0) {
        ufw_ratelog_emit(&c->rl_local, "ERROR", "[" EP_NAME "] connect 本地服务失败: %s",
                         strerror(errno));
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
        log_info("[" EP_NAME "] 新映射 127.0.0.1:%u <-> %s", (unsigned)m->lport,
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

/* ---------- 握手 ---------- */

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
        ufw_ratelog_emit(&c->rl_ctl, "WARN", "[" EP_NAME "] 发送握手失败: %s", strerror(errno));
}

static int ts_recently_sent(const struct client *c, uint64_t ts)
{
    for (int i = 0; i < c->recent_cnt; i++)
        if (c->recent_ts[i] == ts)
            return 1;
    return 0;
}

/* server 对握手的应答 */
static void handle_ack(struct client *c, const uint8_t *pkt, size_t len)
{
    uint64_t cts = 0;
    uint64_t sts = 0;
    int rc = fwd_ack_verify(c->key, pkt, len, ufw_realtime_s(), &cts, &sts);

    if (rc == -2) {
        ufw_ratelog_emit(&c->rl_ctl, "WARN",
                         "[" EP_NAME "] 握手 ACK 的 server 时间戳超出 ±%d 秒（两端时钟不一致？）",
                         FWD_TS_MAX_SKEW);
        return;
    }
    if (rc != 0) {
        ufw_ratelog_emit(&c->rl_ctl, "WARN",
                         "[" EP_NAME "] 握手 ACK 校验失败，忽略（psk 不一致或伪造报文）");
        return;
    }
    if (!ts_recently_sent(c, cts)) {
        ufw_ratelog_emit(&c->rl_ctl, "WARN",
                         "[" EP_NAME "] 握手 ACK 回显的时间戳与我方握手的都对不上，忽略");
        return;
    }

    c->last_ack_ms = ufw_mono_ms();
    if (!c->connected) {
        c->connected = 1;
        log_info("[" EP_NAME "] 与 server 握手成功（ACK 已收到），链路可用");
    }
}

/* ---------- 控制 socket：server 转发来的数据 ---------- */

static void on_ctl_readable(struct client *c)
{
    for (;;) {
        ssize_t n = recv(c->ctl_fd, c->rx, UFW_MAX_PKT, 0);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            if (errno == EINTR)
                continue;
            /* 常见于 server 还没起来/端口不通，ICMP 错误会透传到 connected socket */
            ufw_ratelog_emit(&c->rl_ctl, "WARN", "[" EP_NAME "] 控制 socket 收包失败: %s",
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
            ufw_ratelog_emit(&c->rl_ctl, "WARN", "[" EP_NAME "] 控制端口收到未知类型 %u",
                             c->rx[0]);
            continue;
        }
        if ((size_t)n < 1 + FWD_HDR_LEN) {
            ufw_ratelog_emit(&c->rl_ctl, "WARN", "[" EP_NAME "] 丢弃过短的下行报文（%zd 字节）",
                             n);
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
                ufw_ratelog_emit(&c->rl_local, "WARN", "[" EP_NAME "] 发给本地服务失败: %s",
                                 strerror(errno));
        }
    }
}

/* ---------- 本地服务 socket：回程数据 ---------- */

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
            /* 本地服务没监听时 connected socket 会拿到 ECONNREFUSED，直接释放映射 */
            if (errno == ECONNREFUSED) {
                ufw_ratelog_emit(&c->rl_local, "WARN",
                                 "[" EP_NAME "] 本地服务拒绝连接，释放映射");
                map_destroy(c, m);
                return;
            }
            ufw_ratelog_emit(&c->rl_local, "WARN", "[" EP_NAME "] 本地 socket 收包失败: %s",
                             strerror(errno));
            return;
        }

        c->tx[0] = FWD_TYPE_DATA;
        fwd_hdr_pack(c->tx + 1, &m->remote);
        if (n > 0)
            memcpy(c->tx + 1 + FWD_HDR_LEN, c->rx, (size_t)n);
        if (send(c->ctl_fd, c->tx, 1 + FWD_HDR_LEN + (size_t)n, 0) < 0)
            ufw_ratelog_emit(&c->rl_ctl, "WARN", "[" EP_NAME "] 发给 server 失败: %s",
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
        log_error("[" EP_NAME "] client.server_control_port 缺失或不在 1-65535 之间");
        goto out;
    }
    if (!server_host) {
        log_error("[" EP_NAME "] 缺少 client.server_host");
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
            log_error("[" EP_NAME "] 缺少 client.local_service_port");
            goto out;
        }
        if (parse_ipport_pair(svc_host, svc_port_str, &c.svc_addr, "local_service") != 0)
            goto out;
    }

    if (ini_get_uint(ini, "client", "heartbeat_interval", 30, 1, 3600, &hello_sec) != 0) {
        log_error("[" EP_NAME "] heartbeat_interval 不合法（1-3600 秒）");
        goto out;
    }
    if (ini_get_uint(ini, "client", "mapping_idle_timeout", 120, 1, 86400, &idle_sec) != 0) {
        log_error("[" EP_NAME "] mapping_idle_timeout 不合法");
        goto out;
    }
    if (ini_get_uint(ini, "client", "max_mappings", 1024, 1, MAX_MAPPINGS, &max_maps) != 0) {
        log_error("[" EP_NAME "] max_mappings 不合法（1-%d）", MAX_MAPPINGS);
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
        log_error("[" EP_NAME "] 内存不足");
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
    /* 交给内核选源端口；connect 之后只收 server 控制端口的报文 */
    if (connect(c.ctl_fd, (struct sockaddr *)&c.server_addr, sizeof(c.server_addr)) < 0) {
        log_error("[" EP_NAME "] connect server 失败: %s", strerror(errno));
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
        log_info("[" EP_NAME "] server 控制端口 %s:%u，本地服务 %s:%u，心跳间隔 %lu 秒，"
                 "映射空闲超时 %lu 秒",
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
        /* 连续 2 个心跳周期都没 ACK：提示链路不通 */
        if (now - c.last_ack_ms > 2 * c.hello_interval_ms)
            ufw_ratelog_emit(&c.rl_unacked, "WARN",
                             "[" EP_NAME "] 已发出心跳但没收到 server 的 ACK"
                             "（server 未启动、端口不通或 psk 不一致？）");
        if (c.connected && now - c.last_ack_ms > 3 * c.hello_interval_ms) {
            c.connected = 0;
            log_warn("[" EP_NAME "] 心跳超时，与 server 的链路中断");
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
