#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_SERVER_IP "127.0.0.1"
#define DEFAULT_PORT 53053
#define CLIENT_COUNT 2

static const uint8_t dns_query_template[] = {
	0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 'a',  0x04, 't',
	'e',  's',  't',  0x00, 0x00, 0x01, 0x00, 0x01,
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

static int create_client(const char *local_ip)
{
	struct sockaddr_in local = {0};
	struct sockaddr_in actual = {0};
	socklen_t actual_len = sizeof(actual);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		die("socket");
	local.sin_family = AF_INET;
	if (inet_pton(AF_INET, local_ip, &local.sin_addr) != 1) {
		fprintf(stderr, "invalid local address: %s\n", local_ip);
		exit(EXIT_FAILURE);
	}
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0)
		die("bind");
	if (getsockname(fd, (struct sockaddr *)&actual, &actual_len) < 0)
		die("getsockname");
	printf("client fd=%d bound to %s:%u\n", fd, local_ip,
	       ntohs(actual.sin_port));
	return fd;
}

static void send_query(int fd, const struct sockaddr_in *server, uint16_t id)
{
	uint8_t query[sizeof(dns_query_template)];
	ssize_t sent;

	memcpy(query, dns_query_template, sizeof(query));
	query[0] = (uint8_t)(id >> 8);
	query[1] = (uint8_t)id;
	sent = sendto(fd, query, sizeof(query), 0,
		      (const struct sockaddr *)server, sizeof(*server));
	if (sent != (ssize_t)sizeof(query))
		die("sendto");
	printf("sent id=0x%04x on fd=%d\n", id, fd);
}

static void receive_response(int fd, uint16_t expected_id)
{
	char peer_ip[INET_ADDRSTRLEN];
	uint8_t response[512];
	struct sockaddr_in peer = {0};
	socklen_t peer_len = sizeof(peer);
	ssize_t received =
	    recvfrom(fd, response, sizeof(response), 0,
		     (struct sockaddr *)&peer, &peer_len);
	uint16_t id;

	if (received < 0)
		die("recvfrom");
	if (peer.sin_family != AF_INET) {
		fprintf(stderr, "unexpected response address family: %u\n",
			(unsigned int)peer.sin_family);
		exit(EXIT_FAILURE);
	}
	if (inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip)) == NULL)
		die("inet_ntop");
	if (received < 12) {
		fprintf(stderr, "DNS response is too short: %zd\n", received);
		exit(EXIT_FAILURE);
	}
	id = (uint16_t)((uint16_t)response[0] << 8 | response[1]);
	if (id != expected_id || (response[2] & 0x80) == 0) {
		fprintf(stderr, "unexpected DNS response id=0x%04x\n", id);
		exit(EXIT_FAILURE);
	}
	printf("received response id=0x%04x from %s:%u on fd=%d\n", id,
	       peer_ip, ntohs(peer.sin_port), fd);
}

int main(int argc, char **argv)
{
	const char *server_ip = argc > 1 ? argv[1] : DEFAULT_SERVER_IP;
	uint16_t port = argc > 2 ? parse_port(argv[2]) : DEFAULT_PORT;
	const char *local_ips[CLIENT_COUNT] = {"127.0.0.2", "127.0.0.3"};
	const uint16_t ids[CLIENT_COUNT] = {0x1111, 0x2222};
	struct sockaddr_in server = {0};
	int fds[CLIENT_COUNT];

	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	if (inet_pton(AF_INET, server_ip, &server.sin_addr) != 1) {
		fprintf(stderr, "invalid server address: %s\n", server_ip);
		return EXIT_FAILURE;
	}

	for (int i = 0; i < CLIENT_COUNT; i++)
		fds[i] = create_client(local_ips[i]);
	for (int i = 0; i < CLIENT_COUNT; i++)
		send_query(fds[i], &server, ids[i]);

	/* The server deliberately replies to B before A. */
	receive_response(fds[1], ids[1]);
	receive_response(fds[0], ids[0]);

	for (int i = 0; i < CLIENT_COUNT; i++) {
		if (close(fds[i]) < 0)
			die("close");
	}
	return EXIT_SUCCESS;
}
