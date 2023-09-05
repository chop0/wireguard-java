#include <unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

#include <netinet/ip.h>
#include <net/if.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "posix_raw.h"

int open_raw_socket(void) {
 	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
		return -1;
	}

    int ip_hdrincl = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &ip_hdrincl, sizeof(ip_hdrincl)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

#ifdef __linux__
int open_tun(char *name, int nameLength) {
	int fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN;
	int err = ioctl(fd, TUNSETIFF, &ifr);
	if (err < 0) {
		close(fd);
		return -1;
	}

	strncpy(name, ifr.ifr_name, nameLength);

	return fd;
}

#elif defined(__APPLE__)
static uint32_t get_control_id(char const *name) {
	int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (fd < 0) {
		return -1;
	}

	struct ctl_info info;
	memset(&info, 0, sizeof(info));
	strncpy(info.ctl_name, name, sizeof(info.ctl_name));
	int err = ioctl(fd, CTLIOCGINFO, &info);
	if (err < 0) {
		close(fd);
		return -1;
	}

	close(fd);
	return info.ctl_id;
}

static int get_utun_ctl_addr(struct sockaddr_ctl *addr) {
	int const ctl_id = get_control_id("com.apple.net.utun_control");
	if (ctl_id < 0) {
		return -1;
	}

	memset(addr, 0, sizeof(*addr));

	addr->sc_len = sizeof(addr);
	addr->sc_family = AF_SYSTEM;
	addr->ss_sysaddr = AF_SYS_CONTROL;
	addr->sc_id = ctl_id;

	return 0;
}

int open_tun(char *name, int nameLength) {
	int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (fd < 0) {
		return -1;
	}

	struct sockaddr_ctl addr;
	if (get_utun_ctl_addr(&addr) < 0) {
		return -1;
	}

	for (int i = 0; i < 255; ++i) {
		addr.sc_unit = i + 1;
		int err = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
		if (err < 0) {
			continue;
		}

       	snprintf(name, nameLength, "utun%d", i);
       	return fd;
	}

	close(fd);
	return -1;
}
#else
#error "Unsupported platform"
#endif

int mtu(char const* name, int nameLength) {
	struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    if (nameLength > sizeof(ifr.ifr_name)) {
		return -1;
	}

	strncpy(ifr.ifr_name, name, nameLength);

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		return -1;
	}


	int result = ioctl(sockfd, SIOCGIFMTU, &ifr);
	if (result < 0) {
		close(sockfd);
		return -1;
	}

	close(sockfd);
	return ifr.ifr_mtu;
}

int set_mtu(char const* name, int nameLength, int mtu) {
	struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    if (nameLength > sizeof(ifr.ifr_name)) {
		return -1;
	}

	strncpy(ifr.ifr_name, name, nameLength);
	ifr.ifr_mtu = mtu;

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		return -1;
	}


	int result = ioctl(sockfd, SIOCSIFMTU, &ifr);
	close(sockfd);

	return result;
}