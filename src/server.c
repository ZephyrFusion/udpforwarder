/* server 端：控制端口接收 client 的握手与回程数据，数据端口对互联网收发 */
#include "server.h"

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

#define EP_NAME "server"

struct server {
    int epfd;
    int ctl_fd;
    int data_fd;

    unsigned char key[FWD_KEY_LEN];

    struct sockaddr_in client; /* client 的控制端口地址，由握手学习得到 */
    int have_client;
    uint64_t client_seen_ms; /* 最近一次有效握手的单调时间 */
    uint64_t client_last_ts; /* 最近一次接受的握手时间戳，用于反重放 */
    uint64_t client_idle_ms;

    struct ufw_ratelog rl_data_noclient;
    struct ufw_ratelog rl_bad_hello;
    struct ufw_ratelog rl_bad_data;

    uint8_t ack[FWD_ACK_LEN];

    uint8_t *rx;
    uint8_t *tx;
};

static int udp_bind(const char *bind_addr, unsigned long port)
{
    struct sockaddr_in sin;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        log_error("[" EP_NAME "] socket: %s", strerror(errno));
        return -1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t)port);
    if (!bind_addr || strcmp(bind_addr, "0.0.0.0") == 0) {
        sin.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, bind_addr, &sin.sin_addr) != 1) {
        log_error("[" EP_NAME "] bind 地址不合法: %s", bind_addr);
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        log_error("[" EP_NAME "] bind %s:%lu 失败: %s", bind_addr ? bind_addr : "0.0.0.0",
                  port, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int ep_add(int epfd, int fd, const char *name)
{
    struct epoll_event ev;

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        log_error("[" EP_NAME "] epoll_ctl(%s): %s", name, strerror(errno));
        return -1;
    }
    return 0;
}

static void send_to_client(struct server *s, const uint8_t *buf, size_t len)
{
    if (!s->have_client)
        return;
    if (sendto(s->ctl_fd, buf, len, 0, (struct sockaddr *)&s->client, sizeof(s->client)) < 0)
        ufw_ratelog_emit(&s->rl_bad_data, "WARN", "[" EP_NAME "] 发给 client 失败: %s",
                         strerror(errno));
}

/* 数据端口：互联网客户端 -> client 控制端口 */
static void on_data_readable(struct server *s)
{
    uint8_t hdr[FWD_HDR_LEN];

    for (;;) {
        struct sockaddr_in src;
        socklen_t slen = sizeof(src);
        struct fwd_addr from;
        ssize_t n;

        n = recvfrom(s->data_fd, s->rx, UFW_MAX_PKT, 0, (struct sockaddr *)&src, &slen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            if (errno == EINTR)
                continue;
            log_error("[" EP_NAME "] 数据端口 recvfrom: %s", strerror(errno));
            return;
        }

        if (!s->have_client) {
            ufw_ratelog_emit(&s->rl_data_noclient, "WARN",
                             "[" EP_NAME "] 还没收到 client 握手，丢弃数据报文");
            continue;
        }

        fwd_addr_from_sockaddr(&from, &src);
        fwd_hdr_pack(hdr, &from);
        s->tx[0] = FWD_TYPE_DATA;
        memcpy(s->tx + 1, hdr, FWD_HDR_LEN);
        if (n > 0)
            memcpy(s->tx + 1 + FWD_HDR_LEN, s->rx, (size_t)n);
        send_to_client(s, s->tx, 1 + FWD_HDR_LEN + (size_t)n);
    }
}

static int same_sockaddr(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
    return a->sin_addr.s_addr == b->sin_addr.s_addr && a->sin_port == b->sin_port;
}

/* 控制端口：握手 0x00 与 client 回程数据 0x01 */
static void on_ctl_readable(struct server *s)
{
    for (;;) {
        struct sockaddr_in src;
        socklen_t slen = sizeof(src);
        ssize_t n;

        n = recvfrom(s->ctl_fd, s->rx, UFW_MAX_PKT, 0, (struct sockaddr *)&src, &slen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            if (errno == EINTR)
                continue;
            log_error("[" EP_NAME "] 控制端口 recvfrom: %s", strerror(errno));
            return;
        }
        if (n < 1)
            continue;

        if (s->rx[0] == FWD_TYPE_HELLO) {
            uint64_t ts = 0;
            int rc = fwd_hello_verify(s->key, s->rx, (size_t)n, ufw_realtime_s(), &ts);

            if (rc == -2) {
                ufw_ratelog_emit(&s->rl_bad_hello, "WARN",
                                 "[" EP_NAME "] 握手时间戳超出 ±%d 秒，忽略",
                                 FWD_TS_MAX_SKEW);
                continue;
            }
            if (rc != 0) {
                ufw_ratelog_emit(&s->rl_bad_hello, "WARN",
                                 "[" EP_NAME "] 握手 MAC 校验失败，忽略（psk 不一致？）");
                continue;
            }
            /* 反重放：来源地址变了就要求时间戳严格递增 */
            if (!(s->have_client && same_sockaddr(&src, &s->client)) && ts <= s->client_last_ts) {
                ufw_ratelog_emit(&s->rl_bad_hello, "WARN",
                                 "[" EP_NAME "] 握手时间戳重复（重放？），忽略");
                continue;
            }

            if (!s->have_client || !same_sockaddr(&src, &s->client)) {
                char buf[INET_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET, &src.sin_addr, buf, sizeof(buf));
                log_info("[" EP_NAME "] client 控制地址更新为 %s:%u，已回应握手 ACK", buf,
                         ntohs(src.sin_port));
            }
            s->client = src;
            s->have_client = 1;
            s->client_seen_ms = ufw_mono_ms();
            if (ts > s->client_last_ts)
                s->client_last_ts = ts;
            /* 回 ACK：回显 client 时间戳，并带上 server 自己的时间戳 */
            fwd_ack_build(s->key, ts, ufw_realtime_s(), s->ack);
            if (sendto(s->ctl_fd, s->ack, sizeof(s->ack), 0, (struct sockaddr *)&src,
                       sizeof(src)) < 0)
                ufw_ratelog_emit(&s->rl_bad_hello, "WARN",
                                 "[" EP_NAME "] 发送握手 ACK 失败: %s", strerror(errno));
            continue;
        }

        if (s->rx[0] == FWD_TYPE_DATA) {
            struct fwd_addr to;
            ssize_t payload_len = n - 1 - FWD_HDR_LEN;

            if (!s->have_client || !same_sockaddr(&src, &s->client)) {
                ufw_ratelog_emit(&s->rl_bad_data, "WARN",
                                 "[" EP_NAME "] 丢弃来自未认证地址的转发数据");
                continue;
            }
            if (payload_len < 0) {
                ufw_ratelog_emit(&s->rl_bad_data, "WARN",
                                 "[" EP_NAME "] 丢弃过短的转发数据报文");
                continue;
            }
            fwd_hdr_unpack(s->rx + 1, &to);
            {
                struct sockaddr_in dst;

                memset(&dst, 0, sizeof(dst));
                dst.sin_family = AF_INET;
                dst.sin_addr.s_addr = htonl(to.ip);
                dst.sin_port = htons(to.port);
                if (sendto(s->data_fd, s->rx + 1 + FWD_HDR_LEN, (size_t)payload_len, 0,
                           (struct sockaddr *)&dst, sizeof(dst)) < 0)
                    ufw_ratelog_emit(&s->rl_bad_data, "WARN",
                                     "[" EP_NAME "] 数据端口回包失败: %s", strerror(errno));
            }
            continue;
        }

        ufw_ratelog_emit(&s->rl_bad_data, "WARN", "[" EP_NAME "] 控制端口收到未知类型 %u",
                         s->rx[0]);
    }
}

static void sweep_client(struct server *s)
{
    if (!s->have_client)
        return;
    if (ufw_mono_ms() - s->client_seen_ms > s->client_idle_ms) {
        s->have_client = 0;
        log_info("[" EP_NAME "] client 超过 %llu 秒没有握手，清除其控制地址",
                 (unsigned long long)(s->client_idle_ms / 1000));
    }
}

int server_main(const char *cfg_path)
{
    struct server s;
    struct epoll_event evs[8];
    char err[512];
    ini_t *ini;
    const char *bind_addr;
    const char *psk;
    unsigned long control_port, data_port, idle_sec;
    int rc = 1;

    memset(&s, 0, sizeof(s));
    s.ctl_fd = s.data_fd = -1;
    s.epfd = -1;

    ini = ini_load(cfg_path, err, sizeof(err));
    if (!ini) {
        log_error("[" EP_NAME "] %s", err);
        return 1;
    }

    if (ini_get_uint(ini, "server", "control_port", 0, 1, 65535, &control_port) != 0 ||
        control_port == 0) {
        log_error("[" EP_NAME "] server.control_port 缺失或不在 1-65535 之间");
        goto out;
    }
    if (ini_get_uint(ini, "server", "data_port", 0, 1, 65535, &data_port) != 0 ||
        data_port == 0) {
        log_error("[" EP_NAME "] server.data_port 缺失或不在 1-65535 之间");
        goto out;
    }
    if (ini_get_uint(ini, "server", "client_idle_timeout", 180, 10, 86400, &idle_sec) != 0) {
        log_error("[" EP_NAME "] client_idle_timeout 不合法");
        goto out;
    }
    bind_addr = ini_get(ini, "server", "bind");
    psk = ini_get(ini, "key", "psk");
    if (!psk)
        psk = ini_get(ini, "server", "psk");

    if (fwd_key_from_psk(psk, s.key, err, sizeof(err)) != 0) {
        log_error("[" EP_NAME "] %s", err);
        goto out;
    }
    s.client_idle_ms = (uint64_t)idle_sec * 1000;

    s.ctl_fd = udp_bind(bind_addr, control_port);
    if (s.ctl_fd < 0)
        goto out;
    s.data_fd = udp_bind(bind_addr, data_port);
    if (s.data_fd < 0)
        goto out;

    s.epfd = epoll_create1(EPOLL_CLOEXEC);
    if (s.epfd < 0) {
        log_error("[" EP_NAME "] epoll_create1: %s", strerror(errno));
        goto out;
    }
    if (ep_add(s.epfd, s.ctl_fd, "ctl") != 0 || ep_add(s.epfd, s.data_fd, "data") != 0)
        goto out;

    s.rx = malloc(UFW_MAX_PKT);
    s.tx = malloc(UFW_MAX_PKT + 1 + FWD_HDR_LEN);
    if (!s.rx || !s.tx) {
        log_error("[" EP_NAME "] 内存不足");
        goto out;
    }
    ufw_ratelog_reset(&s.rl_data_noclient);
    ufw_ratelog_reset(&s.rl_bad_hello);
    ufw_ratelog_reset(&s.rl_bad_data);

    log_info("[" EP_NAME "] 监听 %s 控制端口 %lu / 数据端口 %lu", bind_addr ? bind_addr : "*",
             control_port, data_port);

    for (;;) {
        int n = epoll_wait(s.epfd, evs, (int)(sizeof(evs) / sizeof(evs[0])), 1000);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            log_error("[" EP_NAME "] epoll_wait: %s", strerror(errno));
            break;
        }
        for (int i = 0; i < n; i++) {
            if (evs[i].data.fd == s.ctl_fd)
                on_ctl_readable(&s);
            else if (evs[i].data.fd == s.data_fd)
                on_data_readable(&s);
        }
        sweep_client(&s);
    }
    rc = 0;

out:
    free(s.rx);
    free(s.tx);
    if (s.epfd >= 0)
        close(s.epfd);
    if (s.ctl_fd >= 0)
        close(s.ctl_fd);
    if (s.data_fd >= 0)
        close(s.data_fd);
    ini_free(ini);
    return rc;
}
