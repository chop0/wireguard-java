#include <sys/ioctl.h>

#include <string.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <unistd.h>
#include <fcntl.h>

#include <net/if.h>

#include "posix_raw.h"


uint8_t const packet[] =  "\x45\x00\x00\x29\x00\x00\x40\x00\x40\x11\x3c\xc2\x7f\x00\x00\x01\x7f\x00\x00\x01\x04\xd3\x04\xd2\x00\x15\xb6\xd0\x48\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x21";

int open_tun(char *name, int nameLength) {
	int fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	int err = ioctl(fd, TUNSETIFF, &ifr);
	if (err < 0) {
		close(fd);
		return -1;
	}

	strncpy(name, ifr.ifr_name, nameLength);

	return fd;
}

int main() {
	char tun_name[IFNAMSIZ] = {0};

	int tunnel_fd = open_tun(tun_name, sizeof(tun_name));
	if (tunnel_fd < 0) {
		perror("open_tun");
		exit(1);
	}

	printf("Opened tunnel %s\n", tun_name);
	uint8_t buffer[2048];

	while (true) {
		int n = read(tunnel_fd, buffer, sizeof(buffer));

		if (n < 0) {
			perror("read");
			exit(1);
		}

		printf("Read %d bytes\n", n);
		for (int i = 0; i < n; i++) {
			printf("%02x ", buffer[i]);
		}
			printf("\n");
	}

	close(tunnel_fd);
}