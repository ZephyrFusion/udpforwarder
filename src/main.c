/* udp forwarder entry point: udpforwarder server|client -c config-file */
#include <sodium.h>
#include <stdio.h>
#include <string.h>

#include "client.h"
#include "common.h"
#include "server.h"

static void usage(const char *prog)
{
    fprintf(stderr,
            "udp forwarder %s\n"
            "usage:\n"
            "  %s server [-c config-file]   defaults to /etc/udpforwarder/server.ini\n"
            "  %s client [-c config-file]   defaults to /etc/udpforwarder/client.ini\n",
            UFW_VERSION, prog, prog);
}

int main(int argc, char **argv)
{
    const char *mode;
    const char *cfg = NULL;
    char defcfg[256];

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    mode = argv[1];
    if (strcmp(mode, "-h") == 0 || strcmp(mode, "--help") == 0 || strcmp(mode, "help") == 0) {
        usage(argv[0]);
        return 0;
    }
    if (strcmp(mode, "server") != 0 && strcmp(mode, "client") != 0) {
        fprintf(stderr, "unknown mode: %s\n", mode);
        usage(argv[0]);
        return 2;
    }

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s requires an argument\n", argv[i]);
                return 2;
            }
            cfg = argv[++i];
        } else if (strncmp(argv[i], "--config=", 9) == 0) {
            cfg = argv[i] + 9;
        } else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }
    if (!cfg) {
        snprintf(defcfg, sizeof(defcfg), "/etc/udpforwarder/%s.ini", mode);
        cfg = defcfg;
    }

    if (sodium_init() < 0) {
        log_error("libsodium initialization failed");
        return 1;
    }

    if (strcmp(mode, "server") == 0)
        return server_main(cfg);
    return client_main(cfg);
}
