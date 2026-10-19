#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_BIND_IP "127.0.0.1"
#define DEFAULT_PORT 53053
#define MESSAGE_COUNT 2
#define BUFFER_SIZE 512

struct received_message {
	uint8_t data[BUFFER_SIZE];
	ssize_t len;
	struct sockaddr_in peer;
	socklen_t peer_len;
};

static void die(const char *message)
{
	perror(message);
	exit(EXIT_FAILURE);
}

static uint16_t parse_port(const char *text)
{
	char *end = NULL;
	long value = strtol(text, &end, 10);

	if (end == text || *end != '\0' || value <= 0 || value > 65535) {
		fprintf(stderr, "invalid port: %s\n", text);
		exit(EXIT_FAILURE);
	}
	return (uint16_t)value;
}

static void format_peer(const struct sockaddr_in *peer, char *ip, size_t ip_len)
{
	if (inet_ntop(AF_INET, &peer->sin_addr, ip, ip_len) == NULL)
		die("inet_ntop");
}

int main(int argc, char **argv)
{
	const char *bind_ip = argc > 1 ? argv[1] : DEFAULT_BIND_IP;
	uint16_t port = argc > 2 ? parse_port(argv[2]) : DEFAULT_PORT;
	struct sockaddr_in local = {0};
	struct received_message messages[MESSAGE_COUNT];
	int fd;
	int one = 1;

	memset(messages, 0, sizeof(messages));
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		die("socket");
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
		die("setsockopt");

	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	if (inet_pton(AF_INET, bind_ip, &local.sin_addr) != 1) {
		fprintf(stderr, "invalid bind address: %s\n", bind_ip);
		return EXIT_FAILURE;
	}
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0)
		die("bind");

	printf("server fd=%d listening on %s:%u\n", fd, bind_ip, port);
	fflush(stdout);

	for (int i = 0; i < MESSAGE_COUNT; i++) {
		char peer_ip[INET_ADDRSTRLEN];

		messages[i].peer_len = sizeof(messages[i].peer);
		messages[i].len = recvfrom(fd, messages[i].data,
					    sizeof(messages[i].data), 0,
					    (struct sockaddr *)&messages[i].peer,
					    &messages[i].peer_len);
		if (messages[i].len < 0)
			die("recvfrom");
		if (messages[i].len < 12) {
			fprintf(stderr, "DNS message is too short: %zd\n",
				messages[i].len);
			return EXIT_FAILURE;
		}
		format_peer(&messages[i].peer, peer_ip, sizeof(peer_ip));
		printf("received id=0x%02x%02x from %s:%u on fd=%d\n",
		       messages[i].data[0], messages[i].data[1], peer_ip,
		       ntohs(messages[i].peer.sin_port), fd);
	}

	/* Reply to B before A to exercise interleaved peer ordering. */
	for (int i = MESSAGE_COUNT - 1; i >= 0; i--) {
		char peer_ip[INET_ADDRSTRLEN];
		ssize_t sent;

		messages[i].data[2] = 0x81;
		messages[i].data[3] = 0x80;
		sent = sendto(fd, messages[i].data, (size_t)messages[i].len, 0,
			      (struct sockaddr *)&messages[i].peer,
			      messages[i].peer_len);
		if (sent != messages[i].len)
			die("sendto");
		format_peer(&messages[i].peer, peer_ip, sizeof(peer_ip));
		printf("replied id=0x%02x%02x to %s:%u on fd=%d\n",
		       messages[i].data[0], messages[i].data[1], peer_ip,
		       ntohs(messages[i].peer.sin_port), fd);
	}

	if (close(fd) < 0)
		die("close");
	return EXIT_SUCCESS;
}
