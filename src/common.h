/* Small shared helpers: clocks, logging, socket setup. */
#ifndef UFW_COMMON_H
#define UFW_COMMON_H

#include <stdint.h>
#include <stddef.h>

#define UFW_VERSION "1.0.0"

/* Max size of a single UDP datagram (IPv4 UDP payload limit). */
#define UFW_MAX_PKT 65535

/* Monotonic clock in milliseconds, used for timeouts and activity tracking. */
uint64_t ufw_mono_ms(void);

/* Wall clock in seconds, used for handshake timestamps of the control protocol. */
uint64_t ufw_realtime_s(void);

void ufw_log(const char *level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define log_info(...)  ufw_log("INFO", __VA_ARGS__)
#define log_warn(...)  ufw_log("WARN", __VA_ARGS__)
#define log_error(...) ufw_log("ERROR", __VA_ARGS__)

int ufw_set_nonblock(int fd);

/* Rate-limited logging: a given message is emitted at most once per interval_ms,
 * with the number of suppressed occurrences appended. */
struct ufw_ratelog {
    uint64_t next_ms;
    uint64_t count;
};

void ufw_ratelog_reset(struct ufw_ratelog *rl);
void ufw_ratelog_emit(struct ufw_ratelog *rl, const char *level, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

#endif /* UFW_COMMON_H */
