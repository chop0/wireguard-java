#include <unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#ifdef __APPLE__
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

#elif defined(__linux__)
#include <fcntl.h>
#include <linux/if_tun.h>

#endif

#include <netinet/ip.h>
#include <net/if.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "posix_raw.h"

#ifdef __linux__
static int tun_alloc_mq(char *dev, int queues, int *fds)
  {
      struct ifreq ifr;
      int fd, err, i;

      if (!dev)
          return -1;

      memset(&ifr, 0, sizeof(ifr));
      /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
       *        IFF_TAP   - TAP device
       *
       *        IFF_NO_PI - Do not provide packet information
       *        IFF_MULTI_QUEUE - Create a queue of multiqueue device
       */
      ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
      strcpy(ifr.ifr_name, dev);

      for (i = 0; i < queues; i++) {
          if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
             goto err;
          err = ioctl(fd, TUNSETIFF, (void *)&ifr);
          if (err) {
             close(fd);
             goto err;
          }
          fds[i] = fd;
      }

      return 0;
  err:
      for (--i; i >= 0; i--)
          close(fds[i]);
      return err;
  }

int open_tun(char *name, int nameLength, int *multiqueueCount, int *multiqueues) {
	int fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
	int err = ioctl(fd, TUNSETIFF, &ifr);
	if (err < 0) {
		close(fd);
		return -1;
	}

	strncpy(name, ifr.ifr_name, nameLength);

	if (tun_alloc_mq(ifr.ifr_name, *multiqueueCount, multiqueues) < 0) {
		perror("tun_alloc_mq");
		*multiqueueCount = 0;
	}

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

int open_tun(char *name, int nameLength, int *multiqueueCount, int *multiqueues) {
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
       	*multiqueueCount = 0;
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

int wg_readv(int fd, struct iovec *iov, int iovcnt) {
	return readv(fd, iov, iovcnt);
}

int wg_writev(int fd, struct iovec *iov, int iovcnt) {
	return writev(fd, iov, iovcnt);
}

int wg_close(int fd) {
	return close(fd);
}