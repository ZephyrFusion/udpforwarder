# 静态链接（musl + libsodium 静态库）的 udp forwarder
ifeq ($(origin CC),default)
CC := musl-gcc
endif
SODIUM_DIR := third_party/libsodium-musl
CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra -Wshadow -Wstrict-prototypes -Wmissing-prototypes
CFLAGS += -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -I$(SODIUM_DIR)/include
LDFLAGS += -static -L$(SODIUM_DIR)/lib
LDLIBS += -lsodium -pthread

SRCS := src/main.c src/common.c src/ini.c src/proto.c src/server.c src/client.c
OBJS := $(SRCS:.c=.o)
BIN := udpforwarder

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJS): | $(SODIUM_DIR)/lib/libsodium.a

$(SODIUM_DIR)/lib/libsodium.a:
	./third_party/build_libsodium.sh

test: $(BIN)
	python3 tests/test_forward.py

clean:
	rm -f $(OBJS) $(BIN)

distclean: clean
	rm -rf third_party/libsodium-musl

.PHONY: all test clean distclean
