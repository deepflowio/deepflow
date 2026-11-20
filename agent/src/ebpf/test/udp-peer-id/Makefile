CC ?= gcc
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror

TARGETS := udp_peer_client udp_peer_server

.PHONY: all clean

all: $(TARGETS)

udp_peer_client: udp_peer_client.c
	$(CC) $(CFLAGS) $< -o $@

udp_peer_server: udp_peer_server.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGETS)
