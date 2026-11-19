/* 通用小工具：时间、日志、socket 设置 */
#ifndef UFW_COMMON_H
#define UFW_COMMON_H

#include <stdint.h>
#include <stddef.h>

#define UFW_VERSION "1.0.0"

/* 单个 UDP 报文的最大长度（IPv4 UDP payload 上限） */
#define UFW_MAX_PKT 65535

/* 单调时钟，毫秒，用于超时/活跃时间 */
uint64_t ufw_mono_ms(void);

/* 墙上时钟，秒，用于控制协议的握手时间戳 */
uint64_t ufw_realtime_s(void);

void ufw_log(const char *level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define log_info(...)  ufw_log("INFO", __VA_ARGS__)
#define log_warn(...)  ufw_log("WARN", __VA_ARGS__)
#define log_error(...) ufw_log("ERROR", __VA_ARGS__)

int ufw_set_nonblock(int fd);

/* 限速日志：同一条日志最多每 interval_ms 输出一次，并带上被压缩的条数 */
struct ufw_ratelog {
    uint64_t next_ms;
    uint64_t count;
};

void ufw_ratelog_reset(struct ufw_ratelog *rl);
void ufw_ratelog_emit(struct ufw_ratelog *rl, const char *level, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

#endif /* UFW_COMMON_H */
