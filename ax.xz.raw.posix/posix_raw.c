#include <jni.h>

#include <unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

#include <netinet/ip.h>
#include <net/if.h>

#include <errno.h>
#include <string.h>

#include "jni_utils.h"

static jobject createFdObject(JNIEnv *env, int fd) {
    jclass sharedSecretsCls = FIND_CLASS(env, "jdk/internal/access/SharedSecrets");
    jclass javaIOFileDescriptorAccessCls = FIND_CLASS(env, "jdk/internal/access/JavaIOFileDescriptorAccess");
    jclass fileDescriptorCls = FIND_CLASS(env, "java/io/FileDescriptor");

    jmethodID getJavaIOFileDescriptorAccess = GET_STATIC_METHOD_ID(env, sharedSecretsCls, "getJavaIOFileDescriptorAccess", "()Ljdk/internal/access/JavaIOFileDescriptorAccess;");
    jmethodID fileDescriptorAccessSet = GET_METHOD_ID(env, javaIOFileDescriptorAccessCls, "set", "(Ljava/io/FileDescriptor;I)V");
    jmethodID fileDescriptorRegisterCleanup = GET_METHOD_ID(env, javaIOFileDescriptorAccessCls, "registerCleanup", "(Ljava/io/FileDescriptor;)V");
    jmethodID fdConstructor = GET_METHOD_ID(env, fileDescriptorCls, "<init>", "()V");

    jobject fileDescriptorAccess = (*env)->CallStaticObjectMethod(env, sharedSecretsCls, getJavaIOFileDescriptorAccess);
    jobject fdObj = (*env)->NewObject(env, fileDescriptorCls, fdConstructor);
    (*env)->CallVoidMethod(env, fileDescriptorAccess, fileDescriptorAccessSet, fdObj, fd);
    (*env)->CallVoidMethod(env, fileDescriptorAccess, fileDescriptorRegisterCleanup, fdObj);

    return fdObj;
}

// 	public native RawSocket open() throws IOException;
JNIEXPORT jobject JNICALL Java_ax_xz_raw_posix_POSIXRawSocketProvider_open(JNIEnv *env, jclass cls) {
    int fd = IO_TRY(env, socket(AF_INET, SOCK_RAW, IPPROTO_RAW));

    int ip_hdrincl = 1;
    IO_TRY(env, setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &ip_hdrincl, sizeof(ip_hdrincl)));

    jobject fdObject = createFdObject(env, fd);

    jclass rawSocketCls = FIND_CLASS(env, "ax/xz/raw/posix/POSIXRawSocket");
    jmethodID rawSocketConstructor = GET_METHOD_ID(env, rawSocketCls, "<init>", "(Ljava/io/FileDescriptor;)V");
    return (*env)->NewObject(env, rawSocketCls, rawSocketConstructor, fdObject);
}

#ifdef __linux__
static jobject open_tun(JNIEnv* env) {
	int fd = IO_TRY(env, open("/dev/net/tun", O_RDWR));
	if (fd < 0) {
		return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN;
	int err = IO_TRY(env, ioctl(fd, TUNSETIFF, &ifr));
	if (err < 0) {
		close(fd);
		return -1;
	}
	jclass posixTunCls = FIND_CLASS(env, "ax/xz/raw/posix/POSIXTun");
    jmethodID posixTunConstructor = GET_METHOD_ID(env, posixTunCls, "<init>", "(Ljava/io/FileDescriptor;Ljava/lang/String;)V");

    jstring name = (*env)->NewStringUTF(env, ifr.ifr_name);
    return (*env)->NewObject(env, posixTunCls, posixTunConstructor, fdObj, name);
}

#elif defined(__APPLE__)
static int get_control_id(char const *name) {
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

	return info.ctl_id;
}

static jobject open_tun(JNIEnv* env) {
	int const ctl_id = IO_TRY(env, get_control_id("com.apple.net.utun_control"));
	if (ctl_id < 0) {
		return NULL;
	}

	struct sockaddr_ctl addr;
	memset(&addr, 0, sizeof(addr));

	addr.sc_len = sizeof(addr);
	addr.sc_family = AF_SYSTEM;
	addr.ss_sysaddr = AF_SYS_CONTROL;
	addr.sc_id = ctl_id;

	int fd = IO_TRY(env, socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL));
	if (fd < 0) {
		return NULL;
	}

	for (int i = 0; i < 255; ++i) {
		addr.sc_unit = i + 1;
		int err = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
		if (err < 0) {
			continue;
		}

		jclass posixTunCls = FIND_CLASS(env, "ax/xz/raw/posix/POSIXTun");
        jmethodID posixTunConstructor = GET_METHOD_ID(env, posixTunCls, "<init>", "(Ljava/io/FileDescriptor;Ljava/lang/String;)V");

        // name is concatenation of "utun" and unit number - 1
       	char name[IFNAMSIZ];
       	snprintf(name, sizeof(name), "utun%d", i);
       	jstring nameStr = (*env)->NewStringUTF(env, name);

		jobject fdObj = createFdObject(env, fd);
       	return (*env)->NewObject(env, posixTunCls, posixTunConstructor, fdObj, nameStr);
	}

	close(fd);
	return NULL;
}
#else
#error "Unsupported platform"
#endif

// public native Tun open() throws IOException;
JNIEXPORT jobject JNICALL Java_ax_xz_raw_posix_POSIXTunProvider_open(JNIEnv *env, jclass clazz) {
	// open tun device
	return open_tun(env);
}

static void getIfr(JNIEnv *env, jobject tunObj, struct ifreq *ifr) {
	jclass tunCls = FIND_CLASS(env, "ax/xz/raw/posix/POSIXTun");
	jmethodID name = GET_METHOD_ID(env, tunCls, "name", "()Ljava/lang/String;");
	jstring nameStr = (*env)->CallObjectMethod(env, tunObj, name);

	const char *nameCStr = (*env)->GetStringUTFChars(env, nameStr, NULL);
	strncpy(ifr->ifr_name, nameCStr, strlen(nameCStr));
	(*env)->ReleaseStringUTFChars(env, nameStr, nameCStr);
}

JNIEXPORT void JNICALL Java_ax_xz_raw_posix_POSIXTun_setMTU(JNIEnv *env, jobject tunObj, jint mtu) {
	struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    getIfr(env, tunObj, &ifr);
    ifr.ifr_mtu = mtu;

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	IO_TRY(env, ioctl(sockfd, SIOCSIFMTU, &ifr));
	close(sockfd);
}

JNIEXPORT int JNICALL Java_ax_xz_raw_posix_POSIXTun_mtu(JNIEnv *env, jobject tunObj) {
	struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    getIfr(env, tunObj, &ifr);

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	IO_TRY(env, ioctl(sockfd, SIOCGIFMTU, &ifr));
	close(sockfd);

	return ifr.ifr_mtu;
}